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
/// rotate a key set that has no waiting recovery.
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

    private readonly IKeySetRecoveryRepository _recoveries;
    private readonly IPasskeyCredentialRepository _credentials;
    private readonly PasskeyAssertionVerifier _verifier;
    private readonly TimeProvider _clock;

    /// <summary>Initializes the proof.</summary>
    /// <param name="recoveries">Recovery custody.</param>
    /// <param name="credentials">Passkey custody.</param>
    /// <param name="verifier">Verifies the stored assertion; it never records a sign counter.</param>
    /// <param name="clock">The clock recoveries are judged due by; the same one <see cref="KeySetRecovery"/> uses.</param>
    public PasskeyRecoveryRotationProof(IKeySetRecoveryRepository recoveries, IPasskeyCredentialRepository credentials, PasskeyAssertionVerifier verifier, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(recoveries);
        ArgumentNullException.ThrowIfNull(credentials);
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(clock);
        _recoveries = recoveries;
        _credentials = credentials;
        _verifier = verifier;
        _clock = clock;
    }

    /// <inheritdoc />
    public string Name => ProofName;

    /// <inheritdoc />
    public bool Anchors(PublicKeySetData current)
    {
        return DueRecovery(current) is not null;
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
        PasskeyCredentialData? heir = _credentials.FindByCredentialId(recovery.HeirCredentialId);
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
        PasskeyVerification verification = _verifier.Verify(response, PasskeyKeySetRotationProof.Challenge(current, proposed), counterless);
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
    // set.  Never throws: Anchors is asked outside the registrar's try block.
    private PendingKeySetRecoveryData? DueRecovery(PublicKeySetData? keySet)
    {
        if (keySet is null || string.IsNullOrWhiteSpace(keySet.KeySetHandle))
        {
            return null;
        }
        try
        {
            if (string.IsNullOrEmpty(keySet.PublicRsaKey) && string.IsNullOrEmpty(keySet.PublicEccKey))
            {
                return null;
            }
            string anchor = KeySetRotationPayload.AnchorSha256(keySet);
            DateTime now = _clock.GetUtcNow().UtcDateTime;
            return _recoveries.FindByHandle(keySet.KeySetHandle)
                .FirstOrDefault(recovery => recovery.IsOpen() && recovery.EffectiveUtc <= now
                    && string.Equals(recovery.Anchor, anchor, StringComparison.Ordinal));
        }
        catch (Exception e)
        {
            Log.Warn("Passkey recovery proof could not read the recoveries of {0}: {1}", PasskeyText.Printable(keySet.KeySetHandle), PasskeyText.Printable(e.Message, PasskeyVerification.MaxDetailLength));
            return null;
        }
    }

    private static SignatureVerification Failed(string message)
    {
        return new SignatureVerification { Success = false, Message = message, IssuerPublicKey = null!, Signature = null! };
    }
}
