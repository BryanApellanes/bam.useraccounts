using System.Security.Cryptography;
using Bam.Logging;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Profile;
using Bam.Protocol.Profile;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// <see cref="IKeySetHandover"/> over passkey custody, the key-set registrar and the host's
/// rotation proofs.  The handover is two requests:
/// <list type="number">
/// <item><see cref="Begin"/> checks the passkey being removed holds the key set and the heir is
/// another accepted passkey of the person, records which key set it began from, and returns
/// assertion options that allow only the passkey being removed, over
/// <see cref="PasskeyKeySetRotationProof.Challenge"/> of the rotation to the heir.</item>
/// <item><see cref="Complete"/> takes the handover (once), checks nothing moved, rotates the key
/// set with the assertion through <see cref="IPublicKeySetRegistrar.Rotate"/> (so the registrar's
/// proof chain verifies it and tombstones the old key), then marks the heir as the key set and
/// removes the old passkey.</item>
/// </list>
/// The rotation comes before the removal on purpose: a fault between them leaves the old passkey
/// signing in but no longer the key set, and a retry of the removal is then a plain removal.
/// Completion runs under the inventory's removal lock, and a removal decides whether it needs a
/// handover under the same lock, so removing the heir while a handover completes is asked for a
/// handover rather than removing the passkey that has just become the key set.
/// </summary>
public sealed class KeySetHandover : IKeySetHandover
{
    private const string HandoverPrefix = "passkey-handover:";

    private readonly IPasskeyCredentialRepository _credentials;
    private readonly IPublicKeySetRegistrar _registrar;
    private readonly KeySetRotationProofs? _proofs;
    private readonly IConfirmationChallengeRepository _challenges;
    private readonly PasskeyOptions _options;

    /// <summary>Initializes the handover over its collaborators.</summary>
    /// <param name="credentials">Passkey custody.</param>
    /// <param name="registrar">The key-set registrar.</param>
    /// <param name="proofs">The host's trusted rotation proofs, or null when the host has none; the handover is available only when they include a <see cref="PasskeyKeySetRotationProof"/>.</param>
    /// <param name="challenges">Challenge custody; the handover state is kept there, one row per handover.</param>
    /// <param name="options">The relying-party policy.</param>
    public KeySetHandover(IPasskeyCredentialRepository credentials, IPublicKeySetRegistrar registrar, KeySetRotationProofs? proofs, IConfirmationChallengeRepository challenges, PasskeyOptions options)
    {
        ArgumentNullException.ThrowIfNull(credentials);
        ArgumentNullException.ThrowIfNull(registrar);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(options);
        _credentials = credentials;
        _registrar = registrar;
        _proofs = proofs;
        _challenges = challenges;
        _options = options;
    }

    /// <inheritdoc />
    public bool IsAvailable => _proofs is not null && _proofs.All.Any(proof => proof is PasskeyKeySetRotationProof);

    /// <inheritdoc />
    public bool IsRequiredFor(PasskeyCredentialData credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        return IsAvailable && !credential.Pending && PasskeyKeySet.IsHeldBy(_registrar.Resolve(credential.PersonHandle), credential);
    }

    /// <inheritdoc />
    public KeySetHandoverStart Begin(string personHandle, string credentialId, string? heirCredentialId, string? sessionCredentialId)
    {
        PasskeyCredentialData? removes = Owned(personHandle, credentialId);
        if (removes is null)
        {
            return Refused(KeySetHandoverRefusal.NotFound);
        }
        if (Active(personHandle).Count <= 1)
        {
            return Refused(KeySetHandoverRefusal.LastCredential);
        }
        PublicKeySetData? current = _registrar.Resolve(personHandle);
        if (!PasskeyKeySet.IsHeldBy(current, removes))
        {
            return Refused(KeySetHandoverRefusal.NotKeySet);
        }
        if (!IsAvailable)
        {
            return Refused(KeySetHandoverRefusal.RotationUnavailable);
        }
        string? heirId = string.IsNullOrWhiteSpace(heirCredentialId) ? sessionCredentialId : heirCredentialId;
        PasskeyCredentialData? heir = string.IsNullOrWhiteSpace(heirId) ? null : Owned(personHandle, heirId);
        if (heir is null || string.Equals(heir.CredentialId, removes.CredentialId, StringComparison.Ordinal) || !CoseAlgorithmSupported(heir))
        {
            return Refused(KeySetHandoverRefusal.InvalidHeir);
        }

        string handoverId = Base64UrlEncoder.Default.Encode(RandomBytes(16));
        HandoverState state = new HandoverState
        {
            Handle = personHandle,
            Removes = removes.CredentialId,
            Heir = heir.CredentialId,
            Anchor = KeySetRotationPayload.AnchorSha256(current!)
        };
        byte[] challenge = PasskeyKeySetRotationProof.Challenge(current!, PasskeyKeySet.From(heir));
        _challenges.Save(new ConfirmationChallenge
        {
            PersonHandle = HandoverPrefix + handoverId,
            ChallengeBytes = System.Text.Encoding.UTF8.GetBytes(PasskeyJson.Serialize(state)),
            ExpiresUtc = DateTime.UtcNow.Add(_options.ChallengeLifetime)
        });
        Log.Info("Key-set handover begun for {0}: from passkey {1} to {2}", PasskeyText.Printable(personHandle), PasskeyText.Printable(removes.CredentialId), PasskeyText.Printable(heir.CredentialId));
        List<string> transports = removes.TransportList();
        return new KeySetHandoverStart
        {
            Refusal = KeySetHandoverRefusal.None,
            HandoverId = handoverId,
            HeirCredentialId = heir.CredentialId,
            Options = new PasskeyRequestOptions
            {
                Challenge = Base64UrlEncoder.Default.Encode(challenge),
                RpId = _options.RpId,
                Timeout = (long)_options.Timeout.TotalMilliseconds,
                AllowCredentials = new List<PasskeyCredentialDescriptor> { new PasskeyCredentialDescriptor { Id = removes.CredentialId, Transports = transports.Count == 0 ? null : transports } },
                UserVerification = _options.UserVerification,
                CeremonyId = handoverId
            }
        };
    }

    /// <inheritdoc />
    public KeySetHandoverResult Complete(string personHandle, string? handoverId, byte[]? assertionJson)
    {
        if (string.IsNullOrWhiteSpace(personHandle) || string.IsNullOrWhiteSpace(handoverId))
        {
            return Failed(personHandle, KeySetHandoverRefusal.HandoverExpired, "no handover id.");
        }
        // Taken whatever happens next: a handover id works once.
        ConfirmationChallenge? row = _challenges.Take(HandoverPrefix + handoverId);
        HandoverState? state = Read(row);
        if (row is null || state is null || DateTime.UtcNow > row.ExpiresUtc || !string.Equals(state.Handle, personHandle, StringComparison.Ordinal))
        {
            return Failed(personHandle, KeySetHandoverRefusal.HandoverExpired, "the handover id is unknown, used, expired or another person's.");
        }

        lock (PasskeyInventory.RemovalLock)
        {
            PasskeyCredentialData? removes = Owned(personHandle, state.Removes);
            PublicKeySetData? current = _registrar.Resolve(personHandle);
            if (removes is null || current is null || !PasskeyKeySet.IsHeldBy(current, removes)
                || !string.Equals(KeySetRotationPayload.AnchorSha256(current), state.Anchor, StringComparison.Ordinal))
            {
                return Failed(personHandle, KeySetHandoverRefusal.KeySetChanged, "the key set or the passkey holding it changed since the handover began.");
            }
            PasskeyCredentialData? heir = Owned(personHandle, state.Heir);
            if (heir is null)
            {
                return Failed(personHandle, KeySetHandoverRefusal.HeirGone, "the heir was removed since the handover began.");
            }
            if (assertionJson is null || assertionJson.Length == 0)
            {
                return Failed(personHandle, KeySetHandoverRefusal.ProofRefused, "no assertion.");
            }

            try
            {
                _registrar.Rotate(PasskeyKeySet.From(heir), assertionJson);
            }
            catch (KeySetRegistrationException e)
            {
                // A policy refusal: the registrar changed nothing.  Its message names the handle
                // and the reason, never the proof bytes.
                return Failed(personHandle, KeySetHandoverRefusal.ProofRefused, e.Message);
            }
            catch (ArgumentException e)
            {
                return Failed(personHandle, KeySetHandoverRefusal.ProofRefused, e.Message);
            }

            // The key set has moved.  Nothing below may undo that: a fault here leaves the old
            // passkey signing in but no longer the key set, and its removal is then plain.
            _credentials.SetRegisteredKeySet(personHandle, heir.CredentialId, true);
            _credentials.Remove(personHandle, removes.CredentialId);
            Log.Info("Key-set handover for {0} done: the key set moved from passkey {1} to {2}, and {1} was removed", PasskeyText.Printable(personHandle), PasskeyText.Printable(removes.CredentialId), PasskeyText.Printable(heir.CredentialId));
            return new KeySetHandoverResult
            {
                Refusal = KeySetHandoverRefusal.None,
                RemovedCredentialId = removes.CredentialId,
                HeirCredentialId = heir.CredentialId
            };
        }
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

    private List<PasskeyCredentialData> Active(string personHandle)
    {
        return _credentials.FindByHandle(personHandle).Where(credential => !credential.Pending).ToList();
    }

    private static bool CoseAlgorithmSupported(PasskeyCredentialData credential)
    {
        return Bam.Encryption.Cose.CoseAlgorithms.IsSupported(credential.Algorithm);
    }

    private static HandoverState? Read(ConfirmationChallenge? row)
    {
        if (row?.ChallengeBytes is null || row.ChallengeBytes.Length == 0)
        {
            return null;
        }
        try
        {
            HandoverState state = PasskeyJson.Deserialize<HandoverState>(row.ChallengeBytes);
            bool complete = !string.IsNullOrEmpty(state.Handle) && !string.IsNullOrEmpty(state.Removes) && !string.IsNullOrEmpty(state.Heir) && !string.IsNullOrEmpty(state.Anchor);
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

    private static KeySetHandoverStart Refused(KeySetHandoverRefusal refusal)
    {
        return new KeySetHandoverStart { Refusal = refusal };
    }

    private static KeySetHandoverResult Failed(string? personHandle, KeySetHandoverRefusal refusal, string detail)
    {
        Log.Warn("Key-set handover for {0} refused: {1} ({2})", PasskeyText.Printable(personHandle), refusal, PasskeyText.Printable(detail, PasskeyVerification.MaxDetailLength));
        return new KeySetHandoverResult { Refusal = refusal };
    }

    /// <summary>What a begun handover recorded: who, which passkeys, and which key set it began from.</summary>
    internal sealed class HandoverState
    {
        public string Handle { get; set; } = string.Empty;

        public string Removes { get; set; } = string.Empty;

        public string Heir { get; set; } = string.Empty;

        /// <summary>The SHA-256 of the key the key set was anchored on at begin (<see cref="KeySetRotationPayload.AnchorSha256"/>).</summary>
        public string Anchor { get; set; } = string.Empty;
    }
}
