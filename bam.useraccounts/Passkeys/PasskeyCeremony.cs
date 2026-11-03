using System.Security.Cryptography;
using Bam.Encryption.Cose;
using Bam.Logging;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Profile;
using Bam.Protocol.Profile;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Runs the registration and assertion ceremonies over the framework's challenge custody
/// (<see cref="IConfirmationChallengeRepository"/>), passkey credential custody
/// (<see cref="IPasskeyCredentialRepository"/>) and key-set registration
/// (<see cref="IPublicKeySetRegistrar"/>).  Challenges are keyed into the challenge repository
/// under prefixed handles so passkey ceremonies never collide with device-key confirmation
/// challenges for the same person.  Every failure is logged at warning level with its
/// <see cref="PasskeyVerificationFailure"/> and detail; the result carries one generic message
/// so an unauthenticated caller learns nothing about which check failed.
/// </summary>
public sealed class PasskeyCeremony : IPasskeyCeremony
{
    /// <summary>The one message every failed registration or assertion returns.</summary>
    public const string VerificationFailedMessage = "Passkey verification failed";

    private const string RegistrationPrefix = "passkey-registration:";
    private const string UserHandlePrefix = "passkey-user-handle:";
    private const string AssertionPrefix = "passkey-assertion:";

    private readonly PasskeyOptions _options;
    private readonly IConfirmationChallengeRepository _challenges;
    private readonly IPasskeyCredentialRepository _credentials;
    private readonly PasskeyRegistrationVerifier _registrationVerifier;
    private readonly PasskeyAssertionVerifier _assertionVerifier;
    private readonly IPublicKeySetRegistrar _registrar;

    /// <summary>Initializes the ceremony over its custody and verification collaborators.</summary>
    public PasskeyCeremony(
        PasskeyOptions options,
        IConfirmationChallengeRepository challenges,
        IPasskeyCredentialRepository credentials,
        PasskeyRegistrationVerifier registrationVerifier,
        PasskeyAssertionVerifier assertionVerifier,
        IPublicKeySetRegistrar registrar)
    {
        _options = options;
        _challenges = challenges;
        _credentials = credentials;
        _registrationVerifier = registrationVerifier;
        _assertionVerifier = assertionVerifier;
        _registrar = registrar;
    }

    /// <inheritdoc />
    public PasskeyCreationOptions BeginRegistration(string personHandle, string displayName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(personHandle);
        IReadOnlyList<PasskeyCredentialData> existing = _credentials.FindByHandle(personHandle);
        byte[] userHandle = existing.Count > 0
            ? Base64UrlEncoder.Default.Decode(existing[0].UserHandle)
            : RandomBytes(32);
        byte[] challenge = RandomBytes(32);
        DateTime expiresUtc = DateTime.UtcNow.Add(_options.ChallengeLifetime);
        _challenges.Save(new ConfirmationChallenge { PersonHandle = RegistrationPrefix + personHandle, ChallengeBytes = challenge, ExpiresUtc = expiresUtc });
        _challenges.Save(new ConfirmationChallenge { PersonHandle = UserHandlePrefix + personHandle, ChallengeBytes = userHandle, ExpiresUtc = expiresUtc });

        return new PasskeyCreationOptions
        {
            Rp = new PasskeyRelyingParty { Id = _options.RpId, Name = _options.RpName },
            User = new PasskeyUser
            {
                Id = Base64UrlEncoder.Default.Encode(userHandle),
                Name = personHandle,
                DisplayName = string.IsNullOrWhiteSpace(displayName) ? personHandle : displayName
            },
            Challenge = Base64UrlEncoder.Default.Encode(challenge),
            PubKeyCredParams = _options.Algorithms.Select(algorithm => new PasskeyCredentialParameter { Alg = (long)algorithm }).ToList(),
            Timeout = (long)_options.Timeout.TotalMilliseconds,
            Attestation = "none",
            AuthenticatorSelection = new PasskeyAuthenticatorSelection { ResidentKey = _options.ResidentKey, UserVerification = _options.UserVerification },
            ExcludeCredentials = existing.Select(Describe).ToList()
        };
    }

    /// <inheritdoc />
    public PasskeyRegistrationResult CompleteRegistration(string personHandle, PasskeyRegistrationResponse? response)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(personHandle);
        ConfirmationChallenge? challenge = _challenges.Take(RegistrationPrefix + personHandle);
        ConfirmationChallenge? userHandle = _challenges.Take(UserHandlePrefix + personHandle);
        if (challenge is null || userHandle is null)
        {
            return RegistrationFailed(personHandle, PasskeyVerificationFailure.NoPendingChallenge, "no registration is pending for the handle.");
        }
        if (DateTime.UtcNow > challenge.ExpiresUtc)
        {
            return RegistrationFailed(personHandle, PasskeyVerificationFailure.ChallengeExpired, "the registration challenge has expired.");
        }

        PasskeyVerification verification = _registrationVerifier.Verify(response, challenge.ChallengeBytes);
        if (!verification.Success || verification.Credential is null)
        {
            return RegistrationFailed(personHandle, verification.Failure, verification.Detail);
        }
        ParsedPasskeyCredential credential = verification.Credential;
        if (_credentials.FindByCredentialId(credential.CredentialId) is not null)
        {
            return RegistrationFailed(personHandle, PasskeyVerificationFailure.CredentialAlreadyRegistered, "the credential id is already registered.");
        }

        string pem = credential.PublicKey.Pem;
        bool first = _credentials.FindByHandle(personHandle).Count == 0;
        bool keySetRegistered = false;
        if (first)
        {
            PublicKeySetData keySet = new PublicKeySetData { KeySetHandle = personHandle };
            if (CoseAlgorithms.KeyType(credential.Algorithm) == CoseAlgorithms.KeyTypeRsa)
            {
                keySet.PublicRsaKey = pem;
            }
            else
            {
                keySet.PublicEccKey = pem;
            }
            try
            {
                _registrar.Register(keySet);
                keySetRegistered = true;
            }
            catch (PublicKeySetConflictException)
            {
                // The handle already has a key set from another path (device key); the passkey
                // is stored as an additional credential and the existing key set stands.
                keySetRegistered = false;
            }
            catch (PublicKeySetKeyMaterialConflictException e)
            {
                return RegistrationFailed(personHandle, PasskeyVerificationFailure.CredentialAlreadyRegistered, e.Message);
            }
            catch (RevokedKeyMaterialException e)
            {
                return RegistrationFailed(personHandle, PasskeyVerificationFailure.CredentialAlreadyRegistered, e.Message);
            }
            catch (InvalidPublicKeySetException e)
            {
                return RegistrationFailed(personHandle, PasskeyVerificationFailure.InvalidCredentialKey, e.Message);
            }
        }

        DateTime nowUtc = DateTime.UtcNow;
        PasskeyCredentialData stored = new PasskeyCredentialData
        {
            PersonHandle = personHandle,
            CredentialId = credential.CredentialId,
            UserHandle = Base64UrlEncoder.Default.Encode(userHandle.ChallengeBytes),
            PublicKeyPem = pem,
            Algorithm = (long)credential.Algorithm,
            SignCount = credential.SignCount,
            Aaguid = Convert.ToHexString(credential.Aaguid).ToLowerInvariant(),
            Transports = string.Join(",", credential.Transports),
            BackupEligible = credential.Flags.HasFlag(AuthenticatorFlags.BackupEligible),
            BackedUp = credential.Flags.HasFlag(AuthenticatorFlags.BackedUp),
            CreatedUtc = nowUtc,
            IsRegisteredKeySet = keySetRegistered
        };
        _credentials.Save(stored);

        return new PasskeyRegistrationResult
        {
            Success = true,
            Failure = PasskeyVerificationFailure.None,
            CredentialId = credential.CredentialId,
            KeySetRegistered = keySetRegistered,
            KeyFingerprint = PublicKeyFingerprint.Of(pem),
            Message = keySetRegistered ? "Passkey registered as the account key set" : "Passkey registered",
            Data = stored
        };
    }

    /// <inheritdoc />
    public PasskeyRequestOptions BeginAssertion(string? personHandle)
    {
        byte[] challenge = RandomBytes(32);
        string ceremonyId = Base64UrlEncoder.Default.Encode(RandomBytes(16));
        _challenges.Save(new ConfirmationChallenge
        {
            PersonHandle = AssertionPrefix + ceremonyId,
            ChallengeBytes = challenge,
            ExpiresUtc = DateTime.UtcNow.Add(_options.ChallengeLifetime)
        });
        List<PasskeyCredentialDescriptor> allow = string.IsNullOrWhiteSpace(personHandle)
            ? new List<PasskeyCredentialDescriptor>()
            : _credentials.FindByHandle(personHandle).Select(Describe).ToList();
        return BuildRequestOptions(challenge, allow, ceremonyId);
    }

    /// <inheritdoc />
    public PasskeySignInResult CompleteAssertion(PasskeyAssertionResponse? response)
    {
        if (response is null || string.IsNullOrEmpty(response.CeremonyId) || string.IsNullOrEmpty(response.Id))
        {
            return SignInFailed(null, PasskeyVerificationFailure.NoPendingChallenge, "the assertion names no ceremony or credential.");
        }
        ConfirmationChallenge? challenge = _challenges.Take(AssertionPrefix + response.CeremonyId);
        if (challenge is null)
        {
            return SignInFailed(response.Id, PasskeyVerificationFailure.NoPendingChallenge, "no assertion is pending for the ceremony id.");
        }
        if (DateTime.UtcNow > challenge.ExpiresUtc)
        {
            return SignInFailed(response.Id, PasskeyVerificationFailure.ChallengeExpired, "the assertion challenge has expired.");
        }
        PasskeyCredentialData? credential = _credentials.FindByCredentialId(response.Id);
        if (credential is null)
        {
            return SignInFailed(response.Id, PasskeyVerificationFailure.UnknownCredential, "no credential is registered under the response id.");
        }
        return Assert(response, challenge.ChallengeBytes, credential);
    }

    /// <inheritdoc />
    public PasskeyRequestOptions ToRequestOptions(ConfirmationChallenge challenge)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        List<PasskeyCredentialDescriptor> allow = _credentials.FindByHandle(challenge.PersonHandle).Select(Describe).ToList();
        return BuildRequestOptions(challenge.ChallengeBytes, allow, null);
    }

    /// <summary>
    /// Verifies an assertion against known challenge bytes and a stored credential, records the
    /// sign counter on success and flags the credential on a counter regression.  Shared by
    /// <see cref="CompleteAssertion"/> and the <see cref="IAccountConfirmation"/> adapter.
    /// </summary>
    internal PasskeySignInResult Assert(PasskeyAssertionResponse response, byte[] challengeBytes, PasskeyCredentialData credential)
    {
        PasskeyVerification verification = _assertionVerifier.Verify(response, challengeBytes, credential);
        if (!verification.Success || verification.AuthenticatorData is null)
        {
            if (verification.Failure == PasskeyVerificationFailure.SignCountRegressed)
            {
                _credentials.FlagSignCountRegression(credential.CredentialId);
            }
            return SignInFailed(credential.CredentialId, verification.Failure, verification.Detail);
        }
        _credentials.RecordUse(credential.CredentialId, verification.AuthenticatorData.SignCount, DateTime.UtcNow);
        return new PasskeySignInResult
        {
            Success = true,
            Failure = PasskeyVerificationFailure.None,
            PersonHandle = credential.PersonHandle,
            CredentialId = credential.CredentialId,
            KeyFingerprint = PublicKeyFingerprint.Of(credential.PublicKeyPem),
            UserVerified = verification.AuthenticatorData.UserVerified,
            Message = "Signed in with passkey",
            Data = credential
        };
    }

    private PasskeyRequestOptions BuildRequestOptions(byte[] challenge, List<PasskeyCredentialDescriptor> allow, string? ceremonyId)
    {
        return new PasskeyRequestOptions
        {
            Challenge = Base64UrlEncoder.Default.Encode(challenge),
            RpId = _options.RpId,
            Timeout = (long)_options.Timeout.TotalMilliseconds,
            AllowCredentials = allow,
            UserVerification = _options.UserVerification,
            CeremonyId = ceremonyId
        };
    }

    private static PasskeyCredentialDescriptor Describe(PasskeyCredentialData credential)
    {
        List<string> transports = credential.TransportList();
        return new PasskeyCredentialDescriptor { Id = credential.CredentialId, Transports = transports.Count == 0 ? null : transports };
    }

    private static byte[] RandomBytes(int count)
    {
        byte[] bytes = new byte[count];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }

    private static PasskeyRegistrationResult RegistrationFailed(string personHandle, PasskeyVerificationFailure failure, string? detail)
    {
        Log.Warn("Passkey registration for {0} failed: {1} ({2})", personHandle, failure, detail ?? string.Empty);
        return new PasskeyRegistrationResult { Success = false, Failure = failure, Message = VerificationFailedMessage };
    }

    private static PasskeySignInResult SignInFailed(string? credentialId, PasskeyVerificationFailure failure, string? detail)
    {
        Log.Warn("Passkey assertion for credential {0} failed: {1} ({2})", credentialId ?? "(none)", failure, detail ?? string.Empty);
        return new PasskeySignInResult { Success = false, Failure = failure, Message = VerificationFailedMessage };
    }
}
