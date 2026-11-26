using System.Security.Cryptography;
using System.Text;
using Bam.Encryption;
using Bam.Logging;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Profile;
using Bam.Protocol.Profile;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// <see cref="IKeySetRecovery"/> over passkey custody, recovery custody, the key-set registrar
/// and the host's rotation proofs (bam.protocol#85, option 2).
/// <list type="number">
/// <item><see cref="Begin"/> checks the rule (a key set no surviving passkey holds, or the lost
/// passkey named in <c>removes</c>; an heir old enough; nothing already waiting), records which key
/// set it began from, and returns options that allow only the heir, user verification required,
/// over <see cref="PasskeyKeySetRotationProof.Challenge"/> of the rotation to the heir.</item>
/// <item><see cref="Complete"/> takes the begin (once), checks nothing moved, verifies the heir's
/// assertion (recording its sign counter), stores the recovery as waiting until
/// <see cref="PasskeyOptions.RecoveryDelay"/> has passed, and takes the <c>removes</c> passkey out
/// of sign-in now.</item>
/// <item><see cref="Settle"/>, on a later request after the delay, rotates the key set through
/// <see cref="IPublicKeySetRegistrar.Rotate"/> with the stored assertion, which only
/// <see cref="PasskeyRecoveryRotationProof"/> accepts, so the registrar's proof chain decides and
/// tombstones the lost key.</item>
/// </list>
/// Complete, cancel and settle run under the inventory's removal lock, which removals and
/// handovers take too.
/// </summary>
public sealed class KeySetRecovery : IKeySetRecovery
{
    private const string RecoveryPrefix = "passkey-recovery:";

    private readonly IPasskeyCredentialRepository _credentials;
    private readonly IKeySetRecoveryRepository _recoveries;
    private readonly IPublicKeySetRegistrar _registrar;
    private readonly KeySetRotationProofs? _proofs;
    private readonly IConfirmationChallengeRepository _challenges;
    private readonly Func<PasskeyCeremony> _ceremony;
    private readonly PasskeyOptions _options;
    private readonly TimeProvider _clock;

    /// <summary>Initializes the recovery over its collaborators.</summary>
    /// <param name="credentials">Passkey custody.</param>
    /// <param name="recoveries">Recovery custody.</param>
    /// <param name="registrar">The key-set registrar.</param>
    /// <param name="proofs">The host's trusted rotation proofs, or null when it has none; recovery is available only when they include <see cref="PasskeyRecoveryRotationProof"/> and <see cref="PasskeyKeySetRotationProof"/>.</param>
    /// <param name="challenges">Challenge custody; the begin state is kept there, one row per recovery.</param>
    /// <param name="ceremony">Resolves the ceremony whose <c>Assert</c> verifies the heir's assertion and records its counter.</param>
    /// <param name="options">The relying-party policy, with the recovery limits.</param>
    /// <param name="clock">The clock the age gate and the delay are measured with; the recovery proof must use the same one.</param>
    public KeySetRecovery(IPasskeyCredentialRepository credentials, IKeySetRecoveryRepository recoveries, IPublicKeySetRegistrar registrar, KeySetRotationProofs? proofs,
        IConfirmationChallengeRepository challenges, Func<PasskeyCeremony> ceremony, PasskeyOptions options, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(credentials);
        ArgumentNullException.ThrowIfNull(recoveries);
        ArgumentNullException.ThrowIfNull(registrar);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(ceremony);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(clock);
        _credentials = credentials;
        _recoveries = recoveries;
        _registrar = registrar;
        _proofs = proofs;
        _challenges = challenges;
        _ceremony = ceremony;
        _options = options;
        _clock = clock;
    }

    /// <inheritdoc />
    public bool IsAvailable => _proofs is not null
        && _proofs.All.Any(proof => proof is PasskeyRecoveryRotationProof)
        && _proofs.All.Any(proof => proof is PasskeyKeySetRotationProof);

    private DateTime Now => _clock.GetUtcNow().UtcDateTime;

    /// <inheritdoc />
    public bool IsRecoverable(string personHandle)
    {
        if (!IsAvailable || string.IsNullOrWhiteSpace(personHandle))
        {
            return false;
        }
        PublicKeySetData? current = _registrar.Resolve(personHandle);
        return current is not null && Holder(personHandle, current) is null && WasRemovedPasskeyKeySet(personHandle, current) && Pending(personHandle) is null;
    }

    /// <inheritdoc />
    public KeySetRecoveryStart Begin(string personHandle, string? removesCredentialId, string? heirCredentialId, string? sessionCredentialId)
    {
        if (string.IsNullOrWhiteSpace(personHandle))
        {
            return Refused(KeySetRecoveryRefusal.NotFound);
        }
        PasskeyCredentialData? removes = null;
        if (!string.IsNullOrWhiteSpace(removesCredentialId))
        {
            removes = Owned(personHandle, removesCredentialId);
            if (removes is null)
            {
                return Refused(KeySetRecoveryRefusal.NotFound);
            }
        }
        PublicKeySetData? current = _registrar.Resolve(personHandle);
        if (current is null)
        {
            return Refused(KeySetRecoveryRefusal.NoKeySet);
        }
        if (removes is not null && !PasskeyKeySet.IsHeldBy(current, removes))
        {
            return Refused(KeySetRecoveryRefusal.NotKeySet);
        }
        if (removes is null && Holder(personHandle, current) is not null)
        {
            return Refused(KeySetRecoveryRefusal.RemovesRequired);
        }
        if (removes is null && !WasRemovedPasskeyKeySet(personHandle, current))
        {
            // No passkey holds it and none of the person's removed passkeys did: an admin rebind or
            // a device key.  Recovery moves only a key set a passkey of the person held.
            return Refused(KeySetRecoveryRefusal.NoKeySet);
        }
        if (!IsAvailable)
        {
            return Refused(KeySetRecoveryRefusal.RotationUnavailable);
        }
        if (Pending(personHandle) is not null)
        {
            return Refused(KeySetRecoveryRefusal.RecoveryPending);
        }
        string? heirId = string.IsNullOrWhiteSpace(heirCredentialId) ? sessionCredentialId : heirCredentialId;
        PasskeyCredentialData? heir = string.IsNullOrWhiteSpace(heirId) ? null : Owned(personHandle, heirId);
        if (heir is null || (removes is not null && string.Equals(heir.CredentialId, removes.CredentialId, StringComparison.Ordinal))
            || PasskeyKeySet.IsHeldBy(current, heir) || !Bam.Encryption.Cose.CoseAlgorithms.IsSupported(heir.Algorithm))
        {
            return Refused(KeySetRecoveryRefusal.InvalidHeir);
        }
        DateTime eligibleUtc = heir.CreatedUtc.Add(_options.RecoveryCredentialAge);
        if (Now < eligibleUtc)
        {
            Log.Info("Key-set recovery for {0} refused: heir passkey {1} is too new (eligible {2})", PasskeyText.Printable(personHandle), PasskeyText.Printable(heir.CredentialId), eligibleUtc.ToString("o", System.Globalization.CultureInfo.InvariantCulture));
            return new KeySetRecoveryStart { Refusal = KeySetRecoveryRefusal.HeirTooNew, EligibleUtc = eligibleUtc };
        }

        string recoveryId = Base64UrlEncoder.Default.Encode(RandomBytes(16));
        BeginState state = new BeginState
        {
            Handle = personHandle,
            Removes = removes?.CredentialId,
            Heir = heir.CredentialId,
            Anchor = KeySetRotationPayload.AnchorSha256(current)
        };
        byte[] challenge = PasskeyKeySetRotationProof.Challenge(current, PasskeyKeySet.From(heir));
        _challenges.Save(new ConfirmationChallenge
        {
            PersonHandle = RecoveryPrefix + recoveryId,
            ChallengeBytes = Encoding.UTF8.GetBytes(PasskeyJson.Serialize(state)),
            ExpiresUtc = DateTime.UtcNow.Add(_options.ChallengeLifetime)
        });
        Log.Info("Key-set recovery begun for {0}: heir passkey {1}{2}", PasskeyText.Printable(personHandle), PasskeyText.Printable(heir.CredentialId),
            removes is null ? string.Empty : ", removing " + PasskeyText.Printable(removes.CredentialId));
        List<string> transports = heir.TransportList();
        return new KeySetRecoveryStart
        {
            Refusal = KeySetRecoveryRefusal.None,
            RecoveryId = recoveryId,
            HeirCredentialId = heir.CredentialId,
            Options = new PasskeyRequestOptions
            {
                Challenge = Base64UrlEncoder.Default.Encode(challenge),
                RpId = _options.RpId,
                Timeout = (long)_options.Timeout.TotalMilliseconds,
                AllowCredentials = new List<PasskeyCredentialDescriptor> { new PasskeyCredentialDescriptor { Id = heir.CredentialId, Transports = transports.Count == 0 ? null : transports } },
                // The rule needs a user-verified heir whatever the host's sign-in policy is.
                UserVerification = "required",
                CeremonyId = recoveryId
            }
        };
    }

    /// <inheritdoc />
    public KeySetRecoveryResult Complete(string personHandle, string? recoveryId, byte[]? assertionJson)
    {
        if (string.IsNullOrWhiteSpace(personHandle) || string.IsNullOrWhiteSpace(recoveryId))
        {
            return Failed(personHandle, KeySetRecoveryRefusal.RecoveryExpired, "no recovery id.");
        }
        // Taken whatever happens next: a recovery id works once.
        ConfirmationChallenge? row = _challenges.Take(RecoveryPrefix + recoveryId);
        BeginState? state = Read(row);
        if (row is null || state is null || DateTime.UtcNow > row.ExpiresUtc || !string.Equals(state.Handle, personHandle, StringComparison.Ordinal))
        {
            return Failed(personHandle, KeySetRecoveryRefusal.RecoveryExpired, "the recovery id is unknown, used, expired or another person's.");
        }

        lock (PasskeyInventory.RemovalLock)
        {
            PublicKeySetData? current = _registrar.Resolve(personHandle);
            if (current is null || !string.Equals(KeySetRotationPayload.AnchorSha256(current), state.Anchor, StringComparison.Ordinal))
            {
                return Failed(personHandle, KeySetRecoveryRefusal.KeySetChanged, "the key set changed since the recovery began.");
            }
            PasskeyCredentialData? removes = null;
            if (state.Removes is not null)
            {
                removes = Owned(personHandle, state.Removes);
                if (removes is null || !PasskeyKeySet.IsHeldBy(current, removes))
                {
                    return Failed(personHandle, KeySetRecoveryRefusal.KeySetChanged, "the passkey holding the key set changed since the recovery began.");
                }
            }
            else if (Holder(personHandle, current) is not null || !WasRemovedPasskeyKeySet(personHandle, current))
            {
                return Failed(personHandle, KeySetRecoveryRefusal.KeySetChanged, "a passkey holds the key set again since the recovery began.");
            }
            PasskeyCredentialData? heir = Owned(personHandle, state.Heir);
            if (heir is null)
            {
                return Failed(personHandle, KeySetRecoveryRefusal.HeirGone, "the heir was removed since the recovery began.");
            }
            if (Pending(personHandle) is not null)
            {
                return Failed(personHandle, KeySetRecoveryRefusal.RecoveryPending, "another recovery was proved since this one began.");
            }
            if (assertionJson is null || assertionJson.Length == 0)
            {
                return Failed(personHandle, KeySetRecoveryRefusal.ProofRefused, "no assertion.");
            }
            PasskeyAssertionResponse response;
            try
            {
                response = PasskeyAssertionResponse.FromJson(assertionJson);
            }
            catch (PasskeyFormatException)
            {
                return Failed(personHandle, KeySetRecoveryRefusal.ProofRefused, "the assertion is not a passkey assertion.");
            }
            if (!string.Equals(response.Id, heir.CredentialId, StringComparison.Ordinal))
            {
                return Failed(personHandle, KeySetRecoveryRefusal.ProofRefused, "the assertion is not by the heir.");
            }
            PasskeySignInResult verified = _ceremony().Assert(response, PasskeyKeySetRotationProof.Challenge(current, PasskeyKeySet.From(heir)), heir);
            if (!verified.Success)
            {
                return Failed(personHandle, KeySetRecoveryRefusal.ProofRefused, "the heir's assertion did not verify: " + verified.Failure);
            }
            if (!verified.UserVerified)
            {
                return Failed(personHandle, KeySetRecoveryRefusal.ProofRefused, "the heir's assertion was not user-verified.");
            }
            // The challenge is the rotation itself, not a server nonce, and a synced passkey's counter
            // stays at 0, so an earlier recovery's assertion verifies again.  Refusing one any earlier
            // recovery of the person stored keeps a cancel final.
            string assertionText = Encoding.UTF8.GetString(assertionJson);
            if (_recoveries.FindByHandle(personHandle).Any(earlier => string.Equals(earlier.AssertionJson, assertionText, StringComparison.Ordinal)))
            {
                return Failed(personHandle, KeySetRecoveryRefusal.ProofRefused, "the heir's assertion was already used by an earlier recovery.");
            }

            DateTime began = Now;
            PendingKeySetRecoveryData recovery = new PendingKeySetRecoveryData
            {
                PersonHandle = personHandle,
                RecoveryId = recoveryId,
                RemovedCredentialId = removes?.CredentialId,
                RemovedKeyFingerprint = removes is null ? null : PublicKeyFingerprint.Of(removes.PublicKeyPem),
                HeirCredentialId = heir.CredentialId,
                HeirKeyFingerprint = PublicKeyFingerprint.Of(heir.PublicKeyPem) ?? string.Empty,
                Anchor = state.Anchor,
                AssertionJson = assertionText,
                BeganUtc = began,
                EffectiveUtc = began.Add(_options.RecoveryDelay)
            };
            _recoveries.Save(recovery);
            // The lost passkey leaves sign-in now (option A); only the key-set move waits.  Its
            // sessions end on their next request, when the session check finds no credential.
            if (removes is not null)
            {
                // Recorded so that, if this recovery is canceled, a later one can still move the key
                // set the removed passkey held.
                PasskeyInventory.RecordRemovedKey(_recoveries, removes);
                _credentials.Remove(personHandle, removes.CredentialId);
            }
            Log.Warn("Key-set recovery {0} for {1} proved by passkey {2}: the key set moves at {3} unless canceled{4}", PasskeyText.Printable(recoveryId), PasskeyText.Printable(personHandle),
                PasskeyText.Printable(heir.CredentialId), recovery.EffectiveUtc.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
                removes is null ? string.Empty : "; passkey " + PasskeyText.Printable(removes.CredentialId) + " was removed");
            return new KeySetRecoveryResult
            {
                Refusal = KeySetRecoveryRefusal.None,
                RecoveryId = recoveryId,
                RemovedCredentialId = removes?.CredentialId,
                HeirCredentialId = heir.CredentialId,
                EffectiveUtc = recovery.EffectiveUtc
            };
        }
    }

    /// <inheritdoc />
    public bool Cancel(string personHandle, string recoveryId, string? sessionCredentialId)
    {
        if (string.IsNullOrWhiteSpace(personHandle) || string.IsNullOrWhiteSpace(recoveryId))
        {
            return false;
        }
        lock (PasskeyInventory.RemovalLock)
        {
            PendingKeySetRecoveryData? recovery = _recoveries.Find(personHandle, recoveryId);
            if (recovery is null || !recovery.IsOpen())
            {
                return false;
            }
            End(recovery, KeySetRecoveryEnd.Canceled, sessionCredentialId);
            Log.Warn("Key-set recovery {0} for {1} canceled by the session of passkey {2}", PasskeyText.Printable(recoveryId), PasskeyText.Printable(personHandle), PasskeyText.Printable(sessionCredentialId ?? "(unknown)"));
            return true;
        }
    }

    /// <inheritdoc />
    public PendingKeySetRecoveryData? Pending(string personHandle)
    {
        if (string.IsNullOrWhiteSpace(personHandle))
        {
            return null;
        }
        lock (PasskeyInventory.RemovalLock)
        {
            PendingKeySetRecoveryData? recovery = _recoveries.FindByHandle(personHandle).LastOrDefault(row => row.IsOpen());
            if (recovery is null)
            {
                return null;
            }
            if (Owned(personHandle, recovery.HeirCredentialId) is null)
            {
                End(recovery, KeySetRecoveryEnd.HeirGone, null);
                Log.Warn("Key-set recovery {0} for {1} canceled: its heir passkey {2} was removed", PasskeyText.Printable(recovery.RecoveryId), PasskeyText.Printable(personHandle), PasskeyText.Printable(recovery.HeirCredentialId));
                return null;
            }
            return recovery;
        }
    }

    /// <inheritdoc />
    public KeySetRecoverySettlement Settle(string personHandle)
    {
        try
        {
            return SettleOrThrow(personHandle);
        }
        catch (Exception e)
        {
            Log.Warn("Key-set recovery for {0} could not settle now ({1}); the next request tries again", PasskeyText.Printable(personHandle), PasskeyText.Printable(e.Message, PasskeyVerification.MaxDetailLength));
            return KeySetRecoverySettlement.Deferred;
        }
    }

    private KeySetRecoverySettlement SettleOrThrow(string personHandle)
    {
        if (!IsAvailable)
        {
            return KeySetRecoverySettlement.NothingPending;
        }
        lock (PasskeyInventory.RemovalLock)
        {
            PendingKeySetRecoveryData? recovery = Pending(personHandle);
            if (recovery is null)
            {
                return KeySetRecoverySettlement.NothingPending;
            }
            // Held to the delay from the begin time too, as the proof holds it, so a row whose
            // effective time was moved earlier at rest just waits rather than being refused.
            if (Now < recovery.EffectiveUtc || Now < recovery.BeganUtc.Add(_options.RecoveryDelay))
            {
                return KeySetRecoverySettlement.NotDue;
            }
            PasskeyCredentialData heir = Owned(personHandle, recovery.HeirCredentialId)!;
            PublicKeySetData? current = _registrar.Resolve(personHandle);
            if (current is not null && PasskeyKeySet.IsHeldBy(current, heir))
            {
                // The key set is already the heir's: an earlier settle moved it and then failed to
                // record that.  Record it now rather than end the recovery as changed.
                return Completed(recovery, heir);
            }
            if (current is null || !string.Equals(KeySetRotationPayload.AnchorSha256(current), recovery.Anchor, StringComparison.Ordinal))
            {
                End(recovery, KeySetRecoveryEnd.KeySetChanged, null);
                Log.Warn("Key-set recovery {0} for {1} ended: the key set moved some other way before it was due", PasskeyText.Printable(recovery.RecoveryId), PasskeyText.Printable(personHandle));
                return KeySetRecoverySettlement.Ended;
            }
            PublicKeySetData proposed = PasskeyKeySet.From(heir);
            byte[] proof = Encoding.UTF8.GetBytes(recovery.AssertionJson);
            // Asked first, outside the registrar, so a fault can be told from a refusal: a proof that
            // throws (a store timeout, say) leaves the recovery waiting through Settle's catch, and only
            // a clean refusal ends it.  The registrar counts a throwing proof as a refusal.
            ISignatureVerification verification = RecoveryProof().Verify(current, proposed, proof);
            if (!verification.Success)
            {
                return Refused(recovery, personHandle, verification.Message);
            }
            try
            {
                _registrar.Rotate(proposed, proof);
            }
            catch (KeySetRotationTooSoonException)
            {
                // The handle rotated recently (bam.protocol#89): stay waiting and try on a later request.
                Log.Info("Key-set recovery {0} for {1} is due but the handle rotated too recently; it waits", PasskeyText.Printable(recovery.RecoveryId), PasskeyText.Printable(personHandle));
                return KeySetRecoverySettlement.Deferred;
            }
            catch (InvalidKeySetRotationException e)
            {
                // The proof verified a moment ago, so the registrar's own verification failing (or
                // throwing) is a fault, not a decision: stay waiting.  The recovery can still be canceled.
                Log.Warn("Key-set recovery {0} for {1} is due but the registrar could not verify it now ({2}); it waits", PasskeyText.Printable(recovery.RecoveryId), PasskeyText.Printable(personHandle), PasskeyText.Printable(e.Message, PasskeyVerification.MaxDetailLength));
                return KeySetRecoverySettlement.Deferred;
            }
            catch (KeySetRegistrationException e)
            {
                // The heir's key is blocklisted or claimed by another handle: retrying won't change
                // it, so the recovery ends and the key set stays.
                return Refused(recovery, personHandle, e.Message);
            }
            return Completed(recovery, heir);
        }
    }

    // The key set has moved.  Mark the recovery done first: the proof no longer anchors a completed
    // recovery, so nothing can replay it.
    private KeySetRecoverySettlement Completed(PendingKeySetRecoveryData recovery, PasskeyCredentialData heir)
    {
        recovery.CompletedUtc = Now;
        _recoveries.Update(recovery);
        _credentials.SetRegisteredKeySet(recovery.PersonHandle, heir.CredentialId, true);
        Log.Warn("Key-set recovery {0} for {1} done: the key set moved to passkey {2}", PasskeyText.Printable(recovery.RecoveryId), PasskeyText.Printable(recovery.PersonHandle), PasskeyText.Printable(heir.CredentialId));
        return KeySetRecoverySettlement.Settled;
    }

    private KeySetRecoverySettlement Refused(PendingKeySetRecoveryData recovery, string personHandle, string? reason)
    {
        End(recovery, KeySetRecoveryEnd.Refused, null);
        Log.Warn("Key-set recovery {0} for {1} ended: the rotation was refused ({2})", PasskeyText.Printable(recovery.RecoveryId), PasskeyText.Printable(personHandle), PasskeyText.Printable(reason ?? string.Empty, PasskeyVerification.MaxDetailLength));
        return KeySetRecoverySettlement.Ended;
    }

    private PasskeyRecoveryRotationProof RecoveryProof()
    {
        // IsAvailable was checked first, so the proof is there.
        return _proofs!.All.OfType<PasskeyRecoveryRotationProof>().First();
    }

    // Whether the key set holds exactly one key, and a passkey of the person with that key was
    // removed: the key set a recovery naming no removes may move.
    private bool WasRemovedPasskeyKeySet(string personHandle, PublicKeySetData current)
    {
        bool hasRsa = !string.IsNullOrEmpty(current.PublicRsaKey);
        bool hasEcc = !string.IsNullOrEmpty(current.PublicEccKey);
        if (hasRsa == hasEcc)
        {
            return false;
        }
        string? fingerprint = PublicKeyFingerprint.Of(hasRsa ? current.PublicRsaKey : current.PublicEccKey);
        return fingerprint is not null && _recoveries.WasRemovedPasskeyKey(personHandle, fingerprint);
    }

    private void End(PendingKeySetRecoveryData recovery, string reason, string? byCredentialId)
    {
        recovery.CanceledUtc = Now;
        recovery.CancelReason = reason;
        recovery.CanceledByCredentialId = byCredentialId;
        _recoveries.Update(recovery);
    }

    // The accepted passkey of the person whose key is exactly the key set, if any.
    private PasskeyCredentialData? Holder(string personHandle, PublicKeySetData current)
    {
        return _credentials.FindByHandle(personHandle).FirstOrDefault(credential => !credential.Pending && PasskeyKeySet.IsHeldBy(current, credential));
    }

    private PasskeyCredentialData? Owned(string personHandle, string? credentialId)
    {
        if (string.IsNullOrWhiteSpace(personHandle) || string.IsNullOrWhiteSpace(credentialId))
        {
            return null;
        }
        PasskeyCredentialData? credential = _credentials.FindByCredentialId(credentialId);
        return credential is not null && !credential.Pending && string.Equals(credential.PersonHandle, personHandle, StringComparison.Ordinal) ? credential : null;
    }

    private static BeginState? Read(ConfirmationChallenge? row)
    {
        if (row?.ChallengeBytes is null || row.ChallengeBytes.Length == 0)
        {
            return null;
        }
        try
        {
            BeginState state = PasskeyJson.Deserialize<BeginState>(row.ChallengeBytes);
            bool complete = !string.IsNullOrEmpty(state.Handle) && !string.IsNullOrEmpty(state.Heir) && !string.IsNullOrEmpty(state.Anchor);
            return complete ? state : null;
        }
        catch (PasskeyFormatException)
        {
            return null;
        }
    }

    private static byte[] RandomBytes(int count)
    {
        byte[] bytes = new byte[count];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }

    private static KeySetRecoveryStart Refused(KeySetRecoveryRefusal refusal)
    {
        return new KeySetRecoveryStart { Refusal = refusal };
    }

    private static KeySetRecoveryResult Failed(string? personHandle, KeySetRecoveryRefusal refusal, string detail)
    {
        Log.Warn("Key-set recovery for {0} refused: {1} ({2})", PasskeyText.Printable(personHandle), refusal, PasskeyText.Printable(detail, PasskeyVerification.MaxDetailLength));
        return new KeySetRecoveryResult { Refusal = refusal };
    }

    /// <summary>What a begun recovery recorded: who, which passkeys, and which key set it began from.</summary>
    internal sealed class BeginState
    {
        public string Handle { get; set; } = string.Empty;

        /// <summary>The lost key-set passkey to remove, or null when it was already gone.</summary>
        public string? Removes { get; set; }

        public string Heir { get; set; } = string.Empty;

        /// <summary>The SHA-256 of the key the key set was anchored on at begin (<see cref="KeySetRotationPayload.AnchorSha256"/>).</summary>
        public string Anchor { get; set; } = string.Empty;
    }
}
