using System.Security.Cryptography;
using System.Text;
using Bam.Encryption;
using Bam.Logging;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Profile;
using Bam.Protocol.Profile;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Proves a lost-device key-set rotation (bam.protocol#85, option 2): a surviving passkey of the
/// same person moves the key set once a recovery it proved has waited out
/// <see cref="PasskeyOptions.RecoveryDelay"/> without being canceled.
/// <para>
/// It anchors a key set only when that key set's own handle has a due, open
/// <see cref="PendingKeySetRecoveryData"/> recorded against exactly that key set (its
/// <see cref="KeySetRotationPayload.AnchorSha256"/>).  A key set with no due recovery, another
/// handle's key set, and any proposed key set are not anchored, so this proof never widens who can
/// rotate a key set that has no waiting recovery.  Which key sets can get a recovery is decided by
/// <see cref="KeySetRecovery.Begin"/>: only one a passkey of the person holds, or one holding exactly
/// the key of a passkey the person removed.  An admin rebind or a device key is never recoverable.
/// </para>
/// <para>
/// The recovery store is trusted for what was proved and when; the proof still holds the stored
/// effective time to at least the begin time plus <see cref="PasskeyOptions.RecoveryDelay"/>.
/// </para>
/// <para>
/// The proof bytes are the heir's assertion exactly as <see cref="KeySetRecovery"/> stored it.  The
/// proof checks they are that recovery's assertion, that the proposed key set is exactly the heir's
/// key, that the heir is still the person's accepted passkey with the key it had at begin, and that
/// the assertion's signature, origin and challenge (SHA-256 of
/// <see cref="KeySetRotationPayload.ComposeFor"/>(current, proposed)) still verify, user-verified.
/// The sign counter is not judged again: it was checked and recorded when the recovery was
/// proved, and the heir has signed in since.  Failure messages never carry the assertion or a key.
/// </para>
/// </summary>
public sealed class PasskeyRecoveryRotationProof : IKeySetRotationProof
{
    /// <summary>The name recorded when this proof authorizes a rotation (<c>RevokedBy = rotation:passkey-recovery</c>).</summary>
    public const string ProofName = "passkey-recovery";

    private readonly Func<IKeySetRecoveryRepository> _recoveries;
    private readonly Func<IPasskeyCredentialRepository> _credentials;
    private readonly Func<PasskeyAssertionVerifier> _verifier;
    private readonly Func<TimeProvider> _clock;
    private readonly Func<PasskeyOptions> _options;

    /// <summary>Initializes the proof over fixed collaborators.</summary>
    /// <param name="recoveries">Recovery custody.</param>
    /// <param name="credentials">Passkey custody.</param>
    /// <param name="verifier">Verifies the stored assertion; it never records a sign counter.</param>
    /// <param name="clock">The clock recoveries are judged due by; the same one <see cref="KeySetRecovery"/> uses.</param>
    /// <param name="options">The relying-party policy; its <see cref="PasskeyOptions.RecoveryDelay"/> is the least a recovery waits.</param>
    public PasskeyRecoveryRotationProof(IKeySetRecoveryRepository recoveries, IPasskeyCredentialRepository credentials, PasskeyAssertionVerifier verifier, TimeProvider clock, PasskeyOptions options)
        : this(Fixed(recoveries), Fixed(credentials), Fixed(verifier), Fixed(clock), Fixed(options))
    {
    }

    /// <summary>
    /// Initializes the proof over collaborators resolved on each use, so a host that binds its own
    /// recovery custody or clock after registering the proof still has the proof and
    /// <see cref="KeySetRecovery"/> read the same ones.
    /// </summary>
    /// <param name="recoveries">Resolves recovery custody.</param>
    /// <param name="credentials">Resolves passkey custody.</param>
    /// <param name="verifier">Resolves the assertion verifier.</param>
    /// <param name="clock">Resolves the clock.</param>
    /// <param name="options">Resolves the relying-party policy.</param>
    public PasskeyRecoveryRotationProof(Func<IKeySetRecoveryRepository> recoveries, Func<IPasskeyCredentialRepository> credentials, Func<PasskeyAssertionVerifier> verifier,
        Func<TimeProvider> clock, Func<PasskeyOptions> options)
    {
        ArgumentNullException.ThrowIfNull(recoveries);
        ArgumentNullException.ThrowIfNull(credentials);
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(options);
        _recoveries = recoveries;
        _credentials = credentials;
        _verifier = verifier;
        _clock = clock;
        _options = options;
    }

    /// <inheritdoc />
    public string Name => ProofName;

    /// <inheritdoc />
    public bool Anchors(PublicKeySetData current)
    {
        // Never throws: Anchors is asked outside the registrar's try block.
        try
        {
            return DueRecovery(current) is not null;
        }
        catch (Exception e)
        {
            Log.Warn("Passkey recovery proof could not read the recoveries of {0}: {1}", PasskeyText.Printable(current?.KeySetHandle), PasskeyText.Printable(e.Message, PasskeyVerification.MaxDetailLength));
            return false;
        }
    }

    /// <inheritdoc />
    public ISignatureVerification Verify(PublicKeySetData current, PublicKeySetData proposed, byte[] proof)
    {
        if (current is null || proposed is null || !string.Equals(current.KeySetHandle, proposed.KeySetHandle, StringComparison.Ordinal))
        {
            return Failed("The rotation does not stay on one handle.");
        }
        PendingKeySetRecoveryData? recovery = DueRecovery(current);
        if (recovery is null)
        {
            return Failed("No due recovery was recorded against the current key set.");
        }
        byte[] stored = Encoding.UTF8.GetBytes(recovery.AssertionJson);
        if (proof is null || !CryptographicOperations.FixedTimeEquals(stored, proof))
        {
            return Failed("The proof is not the due recovery's assertion.");
        }
        PasskeyCredentialData? heir = _credentials().FindByCredentialId(recovery.HeirCredentialId);
        if (heir is null || heir.Pending || !string.Equals(heir.PersonHandle, current.KeySetHandle, StringComparison.Ordinal)
            || !string.Equals(PublicKeyFingerprint.Of(heir.PublicKeyPem), recovery.HeirKeyFingerprint, StringComparison.Ordinal))
        {
            return Failed("The heir is no longer the person's passkey with the key it had when the recovery began.");
        }
        if (!PasskeyKeySet.IsHeldBy(proposed, heir))
        {
            return Failed("The proposed key set is not exactly the heir's key.");
        }
        PasskeyAssertionResponse response;
        try
        {
            response = PasskeyAssertionResponse.FromJson(stored);
        }
        catch (PasskeyFormatException)
        {
            return Failed("The stored assertion is not a passkey assertion.");
        }
        // A copy with no counter: the counter was judged when the recovery was proved.
        PasskeyCredentialData counterless = new PasskeyCredentialData
        {
            PersonHandle = heir.PersonHandle,
            CredentialId = heir.CredentialId,
            UserHandle = heir.UserHandle,
            PublicKeyPem = heir.PublicKeyPem,
            Algorithm = heir.Algorithm,
            SignCount = 0
        };
        PasskeyVerification verification = _verifier().Verify(response, PasskeyKeySetRotationProof.Challenge(current, proposed), counterless);
        if (!verification.Success || verification.AuthenticatorData is null)
        {
            return Failed("The stored assertion did not verify: " + verification.Failure);
        }
        if (!verification.AuthenticatorData.UserVerified)
        {
            return Failed("The stored assertion was not user-verified.");
        }
        return new SignatureVerification
        {
            Success = true,
            Message = string.Empty,
            IssuerPublicKey = null!,
            Signature = new Signature { SignatureBytes = Array.Empty<byte>(), Data = string.Empty, Algorithm = heir.Algorithm.ToString(System.Globalization.CultureInfo.InvariantCulture) }
        };
    }

    // The open recovery of the key set's own handle that is due and was begun from exactly this key
    // set.  A storage fault throws, so Verify reports a fault rather than a refusal (Anchors catches
    // it).  More than one open recovery anchors nothing: within a process there is never more than
    // one, and across processes the banner, the cancel and the proof must act on the same row.  The
    // stored effective time is held to the begin time plus the delay, so a row edited at rest with an
    // earlier one doesn't skip the wait.
    private PendingKeySetRecoveryData? DueRecovery(PublicKeySetData? keySet)
    {
        if (keySet is null || string.IsNullOrWhiteSpace(keySet.KeySetHandle))
        {
            return null;
        }
        if (string.IsNullOrEmpty(keySet.PublicRsaKey) && string.IsNullOrEmpty(keySet.PublicEccKey))
        {
            return null;
        }
        List<PendingKeySetRecoveryData> open = _recoveries().FindByHandle(keySet.KeySetHandle).Where(recovery => recovery.IsOpen()).ToList();
        if (open.Count != 1)
        {
            return null;
        }
        PendingKeySetRecoveryData only = open[0];
        string anchor = KeySetRotationPayload.AnchorSha256(keySet);
        DateTime now = _clock().GetUtcNow().UtcDateTime;
        DateTime earliest = only.BeganUtc.Add(_options().RecoveryDelay);
        bool due = only.EffectiveUtc >= earliest && only.EffectiveUtc <= now;
        return due && string.Equals(only.Anchor, anchor, StringComparison.Ordinal) ? only : null;
    }

    private static Func<T> Fixed<T>(T value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return () => value;
    }

    private static SignatureVerification Failed(string message)
    {
        return new SignatureVerification { Success = false, Message = message, IssuerPublicKey = null!, Signature = null! };
    }
}
