using System.Security.Cryptography;
using System.Text;
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
/// challenges for the same person, and the sign-up, additional-registration and assertion
/// ceremonies never collide with each other.  Every ceremony that needs two rows (a challenge
/// and a user handle, or a challenge and a handle binding) fails closed when either row is
/// missing at completion.  Every failure is logged at warning level with its
/// <see cref="PasskeyVerificationFailure"/> and detail; the result carries one generic message
/// so an unauthenticated caller learns nothing about which check failed.
/// <para>
/// Two registration paths exist.  <see cref="BeginRegistration"/> / <see cref="CompleteRegistration"/>
/// is sign-up: it may be exposed to anonymous callers and claims a handle for its first passkey
/// through the registrar's first-registration-wins policy, refusing a handle that already has a
/// passkey or a key set.  <see cref="BeginAdditionalRegistration"/> / <see cref="CompleteAdditionalRegistration"/>
/// adds a passkey to an existing person and must only be reached by a caller the host has already
/// authenticated as that person.
/// </para>
/// </summary>
public sealed class PasskeyCeremony : IPasskeyCeremony
{
    /// <summary>The one message every failed registration or assertion returns.</summary>
    public const string VerificationFailedMessage = "Passkey verification failed";

    private const string RegistrationPrefix = "passkey-registration:";
    private const string UserHandlePrefix = "passkey-user-handle:";
    private const string AdditionalPrefix = "passkey-additional:";
    private const string AdditionalUserHandlePrefix = "passkey-additional-user-handle:";
    private const string AssertionPrefix = "passkey-assertion:";
    private const string AssertionHandlePrefix = "passkey-assertion-handle:";

    // The first byte of an assertion's handle binding row.  A marker byte instead of an empty
    // row for the discoverable case, so no backend that stores an empty value as null can turn
    // "discoverable" into "row lost".
    private const byte DiscoverableBinding = 0x00;
    private const byte HandleBinding = 0x01;

    /// <summary>
    /// How long a credential row may stay pending (saved, not yet activated) before the next
    /// registration for its handle or credential id settles it: activated when the registrar
    /// holds its key as the handle's key set, removed otherwise.  A pending row is never usable;
    /// one older than this was left by a process that stopped, or a store that faulted, between
    /// the save and the activation.
    /// </summary>
    public static readonly TimeSpan PendingCredentialGrace = TimeSpan.FromMinutes(5);

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
        // Sign-up never reads the handle's credentials: an anonymous caller must not learn
        // whether the handle exists, which credential ids it has or its stable user handle.
        return Begin(personHandle, displayName, new List<PasskeyCredentialData>(), additional: false);
    }

    /// <inheritdoc />
    public PasskeyCreationOptions BeginAdditionalRegistration(string personHandle, string displayName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(personHandle);
        return Begin(personHandle, displayName, ActiveByHandle(personHandle), additional: true);
    }

    /// <inheritdoc />
    public PasskeyRegistrationResult CompleteRegistration(string personHandle, PasskeyRegistrationResponse? response)
    {
        return Complete(personHandle, response, additional: false);
    }

    /// <inheritdoc />
    public PasskeyRegistrationResult CompleteAdditionalRegistration(string personHandle, PasskeyRegistrationResponse? response)
    {
        return Complete(personHandle, response, additional: true);
    }

    /// <inheritdoc />
    public PasskeyRequestOptions BeginAssertion(string? personHandle)
    {
        byte[] challenge = RandomBytes(32);
        string ceremonyId = Base64UrlEncoder.Default.Encode(RandomBytes(16));
        DateTime expiresUtc = DateTime.UtcNow.Add(_options.ChallengeLifetime);
        _challenges.Save(new ConfirmationChallenge { PersonHandle = AssertionPrefix + ceremonyId, ChallengeBytes = challenge, ExpiresUtc = expiresUtc });
        // The handle binding row is always written (WebAuthn 7.2 step 6): a marker byte, then the
        // handle's UTF-8 bytes for a handle-scoped ceremony.  Completion refuses a credential
        // that belongs to anyone else, and fails closed when the row is gone or unreadable, so a
        // binding can never be lost without the ceremony being lost with it.
        bool scoped = !string.IsNullOrWhiteSpace(personHandle);
        byte[] binding = scoped
            ? new byte[] { HandleBinding }.Concat(Encoding.UTF8.GetBytes(personHandle!)).ToArray()
            : new byte[] { DiscoverableBinding };
        _challenges.Save(new ConfirmationChallenge { PersonHandle = AssertionHandlePrefix + ceremonyId, ChallengeBytes = binding, ExpiresUtc = expiresUtc });
        List<PasskeyCredentialDescriptor> allow = scoped
            ? ActiveByHandle(personHandle!).Select(Describe).ToList()
            : new List<PasskeyCredentialDescriptor>();
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
        ConfirmationChallenge? scopedHandle = _challenges.Take(AssertionHandlePrefix + response.CeremonyId);
        if (challenge is null)
        {
            return SignInFailed(response.Id, PasskeyVerificationFailure.NoPendingChallenge, "no assertion is pending for the ceremony id.");
        }
        if (scopedHandle is null || !TryReadBinding(scopedHandle.ChallengeBytes, out string? boundHandle))
        {
            return SignInFailed(response.Id, PasskeyVerificationFailure.NoPendingChallenge, "the ceremony's handle binding is missing.");
        }
        if (DateTime.UtcNow > challenge.ExpiresUtc)
        {
            return SignInFailed(response.Id, PasskeyVerificationFailure.ChallengeExpired, "the assertion challenge has expired.");
        }
        PasskeyCredentialData? credential = _credentials.FindByCredentialId(response.Id);
        if (credential is null || credential.Pending)
        {
            // A pending row's key has not been accepted by the registrar: it is not a credential yet.
            return SignInFailed(response.Id, PasskeyVerificationFailure.UnknownCredential, "no credential is registered under the response id.");
        }
        if (boundHandle is not null && !string.Equals(boundHandle, credential.PersonHandle, StringComparison.Ordinal))
        {
            return SignInFailed(response.Id, PasskeyVerificationFailure.UnknownCredential, "the credential does not belong to the handle the ceremony was begun for.");
        }
        return Assert(response, challenge.ChallengeBytes, credential);
    }

    /// <inheritdoc />
    public PasskeyRequestOptions ToRequestOptions(ConfirmationChallenge challenge)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        List<PasskeyCredentialDescriptor> allow = ActiveByHandle(challenge.PersonHandle).Select(Describe).ToList();
        return BuildRequestOptions(challenge.ChallengeBytes, allow, null);
    }

    /// <summary>
    /// Verifies an assertion against known challenge bytes and a stored credential, records the
    /// sign counter on success and flags the credential on a counter regression.  Shared by
    /// <see cref="CompleteAssertion"/> and the <see cref="IAccountConfirmation"/> adapter.
    /// </summary>
    internal PasskeySignInResult Assert(PasskeyAssertionResponse response, byte[] challengeBytes, PasskeyCredentialData credential)
    {
        if (credential.Pending)
        {
            return SignInFailed(response.Id, PasskeyVerificationFailure.UnknownCredential, "the credential is pending registration.");
        }
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

    private PasskeyCreationOptions Begin(string personHandle, string displayName, IReadOnlyList<PasskeyCredentialData> existing, bool additional)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(personHandle);
        byte[] userHandle = existing.Count > 0
            ? Base64UrlEncoder.Default.Decode(existing[0].UserHandle)
            : RandomBytes(32);
        byte[] challenge = RandomBytes(32);
        DateTime expiresUtc = DateTime.UtcNow.Add(_options.ChallengeLifetime);
        // Sign-up and additional registration keep separate rows: an anonymous sign-up attempt
        // for a handle can never clobber the pending ceremony of the authenticated person.
        string challengePrefix = additional ? AdditionalPrefix : RegistrationPrefix;
        string userHandlePrefix = additional ? AdditionalUserHandlePrefix : UserHandlePrefix;
        _challenges.Save(new ConfirmationChallenge { PersonHandle = challengePrefix + personHandle, ChallengeBytes = challenge, ExpiresUtc = expiresUtc });
        _challenges.Save(new ConfirmationChallenge { PersonHandle = userHandlePrefix + personHandle, ChallengeBytes = userHandle, ExpiresUtc = expiresUtc });

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

    private PasskeyRegistrationResult Complete(string personHandle, PasskeyRegistrationResponse? response, bool additional)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(personHandle);
        ConfirmationChallenge? challenge = _challenges.Take((additional ? AdditionalPrefix : RegistrationPrefix) + personHandle);
        ConfirmationChallenge? userHandle = _challenges.Take((additional ? AdditionalUserHandlePrefix : UserHandlePrefix) + personHandle);
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
        SettleStalePending(personHandle, credential.CredentialId);
        if (_credentials.FindByCredentialId(credential.CredentialId) is not null)
        {
            return RegistrationFailed(personHandle, PasskeyVerificationFailure.CredentialAlreadyRegistered, "the credential id is already registered.");
        }

        IReadOnlyList<PasskeyCredentialData> held = _credentials.FindByHandle(personHandle);
        if (!additional && held.Count > 0)
        {
            // Sign-up may not attach a passkey to a person who already has one: that would let an
            // anonymous caller become that person.  Adding a passkey is the authenticated path.
            // A pending row counts: another sign-up for the handle is in flight.
            return RegistrationFailed(personHandle, PasskeyVerificationFailure.HandleAlreadyRegistered, "the handle already has a passkey; additional passkeys are registered through the authenticated path.");
        }

        // Only accepted credentials describe the person: a pending row may be someone else's
        // in-flight sign-up attempt for this handle.
        List<PasskeyCredentialData> existing = held.Where(row => !row.Pending).ToList();
        string pem = credential.PublicKey.Pem;
        string storedUserHandle = existing.Count > 0 ? existing[0].UserHandle : Base64UrlEncoder.Default.Encode(userHandle.ChallengeBytes);
        bool first = existing.Count == 0;
        PasskeyCredentialData stored = BuildCredential(personHandle, credential, pem, storedUserHandle, isRegisteredKeySet: first);
        // Save first so the registrar never accepts a key no credential row carries.  The row
        // is saved pending whenever the registrar still has to accept its key: a pending row
        // cannot sign in or confirm an account, so nothing is usable under the handle until the
        // registrar has answered.  It is removed when the registrar refuses the material, and
        // kept (pending, to be settled later) when anything faults after the registrar accepted.
        // Custody refuses a credential id that already has a row, so a registration that raced
        // past the check above stores nothing and touches nobody else's row.
        stored.Pending = first;
        if (!TrySave(stored))
        {
            return RegistrationFailed(personHandle, PasskeyVerificationFailure.CredentialAlreadyRegistered, "the credential id was registered while this registration was completing.");
        }

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
            catch (PublicKeySetConflictException e)
            {
                if (!additional)
                {
                    // The handle already belongs to someone (a device-key key set): sign-up
                    // must not attach a credential to it.
                    _credentials.Remove(personHandle, credential.CredentialId);
                    return RegistrationFailed(personHandle, PasskeyVerificationFailure.HandleAlreadyRegistered, e.Message);
                }
                // An authenticated person with a device-key key set adds their first passkey:
                // the existing key set stands and the passkey is an additional credential.
                _credentials.Remove(personHandle, credential.CredentialId);
                stored = BuildCredential(personHandle, credential, pem, storedUserHandle, isRegisteredKeySet: false);
                if (!TrySave(stored))
                {
                    return RegistrationFailed(personHandle, PasskeyVerificationFailure.CredentialAlreadyRegistered, "the credential id was registered while this registration was completing.");
                }
            }
            catch (PublicKeySetKeyMaterialConflictException e)
            {
                _credentials.Remove(personHandle, credential.CredentialId);
                return RegistrationFailed(personHandle, PasskeyVerificationFailure.CredentialAlreadyRegistered, e.Message);
            }
            catch (RevokedKeyMaterialException e)
            {
                _credentials.Remove(personHandle, credential.CredentialId);
                return RegistrationFailed(personHandle, PasskeyVerificationFailure.CredentialAlreadyRegistered, e.Message);
            }
            catch (InvalidPublicKeySetException e)
            {
                _credentials.Remove(personHandle, credential.CredentialId);
                return RegistrationFailed(personHandle, PasskeyVerificationFailure.InvalidCredentialKey, e.Message);
            }
            catch (KeySetRegistrationException e)
            {
                // Any other registrar policy refusal (an unauthorized successor of a revoked
                // handle, or a refusal added to the registrar later): the handle is not claimable
                // by this key, and the saved row must not outlive the refusal.
                _credentials.Remove(personHandle, credential.CredentialId);
                return RegistrationFailed(personHandle, PasskeyVerificationFailure.HandleAlreadyRegistered, e.Message);
            }
            catch (Exception)
            {
                // A fault, not a policy answer, and not proof of a refusal either: the registrar
                // may have stored the key set before it faulted.  So the registrar is asked.
                // Only when it answers that it does not hold this key is the row removed.  When
                // it holds the key, or cannot be asked, the row stays pending (inert) and a later
                // registration for the handle settles it.  Whatever happens here, the registrar's
                // fault is the one reported.
                try
                {
                    if (IsRegisteredKeySetOf(stored))
                    {
                        Log.Warn("Passkey registration for {0}: the registrar faulted but holds the key of credential {1}; the row is kept pending", PasskeyText.Printable(personHandle), PasskeyText.Printable(credential.CredentialId));
                    }
                    else
                    {
                        _credentials.Remove(personHandle, credential.CredentialId);
                    }
                }
                catch (Exception cleanupFault)
                {
                    Log.Warn("Passkey registration for {0}: the pending credential {1} is left as it is after a registrar fault ({2})", PasskeyText.Printable(personHandle), PasskeyText.Printable(credential.CredentialId), PasskeyText.Printable(cleanupFault.Message, PasskeyVerification.MaxDetailLength));
                }
                throw;
            }
        }

        // Activation is outside the registrar's try block on purpose: once the registrar has
        // accepted the key, nothing here may remove the row.  A fault below leaves it pending,
        // and the next registration for the handle activates it (SettleStalePending).
        if (keySetRegistered && !Activate(stored))
        {
            return RegistrationFailed(personHandle, PasskeyVerificationFailure.CredentialAlreadyRegistered, "the accepted credential could not be activated: its row is gone and its credential id is held by another row.");
        }

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

    /// <summary>
    /// Makes the credential this registration saved usable once the registrar has accepted its
    /// key.  The row is addressed by person and credential id, so only this registration's row
    /// can be activated.  If the pending row is gone (removed as stale while the registrar was
    /// answering), it is saved again as an accepted credential.
    /// </summary>
    /// <returns>False when the row is gone and cannot be saved again because another row now holds its credential id.</returns>
    private bool Activate(PasskeyCredentialData stored)
    {
        if (_credentials.Activate(stored.PersonHandle, stored.CredentialId))
        {
            stored.Pending = false;
            return true;
        }
        stored.Pending = false;
        return TrySave(stored);
    }

    private bool TrySave(PasskeyCredentialData credential)
    {
        try
        {
            _credentials.Save(credential);
            return true;
        }
        catch (PasskeyCredentialConflictException)
        {
            return false;
        }
    }

    private List<PasskeyCredentialData> ActiveByHandle(string personHandle)
    {
        return _credentials.FindByHandle(personHandle).Where(row => !row.Pending).ToList();
    }

    /// <summary>
    /// Settles pending rows older than <see cref="PendingCredentialGrace"/> under the handle or
    /// the credential id: leftovers of a process that stopped, or a store that faulted, between
    /// the save and the activation.  The registrar decides which way.  A row whose key the
    /// registrar holds as its handle's key set was accepted, so it is activated (removing it
    /// would lose the handle: the registrar refuses every later key for it).  A row whose key
    /// the registrar does not hold was never accepted, so it is removed (keeping it would hold
    /// the handle forever).  When the registrar cannot be asked, the row is left for next time.
    /// </summary>
    private void SettleStalePending(string personHandle, string credentialId)
    {
        DateTime cutoff = DateTime.UtcNow.Subtract(PendingCredentialGrace);
        List<PasskeyCredentialData> candidates = _credentials.FindByHandle(personHandle).ToList();
        PasskeyCredentialData? sameId = _credentials.FindByCredentialId(credentialId);
        if (sameId is not null && !candidates.Any(row => string.Equals(row.CredentialId, sameId.CredentialId, StringComparison.Ordinal)))
        {
            candidates.Add(sameId);
        }
        foreach (PasskeyCredentialData row in candidates.Where(row => row.Pending && row.CreatedUtc < cutoff))
        {
            bool accepted;
            try
            {
                accepted = IsRegisteredKeySetOf(row);
            }
            catch (Exception e)
            {
                Log.Warn("Stale pending passkey credential {0} of {1} left as it is: the registrar could not be asked ({2})", PasskeyText.Printable(row.CredentialId), PasskeyText.Printable(row.PersonHandle), PasskeyText.Printable(e.Message, PasskeyVerification.MaxDetailLength));
                continue;
            }
            if (accepted)
            {
                Log.Warn("Activating stale pending passkey credential {0} of {1} (saved {2}): the registrar holds its key as the handle's key set", PasskeyText.Printable(row.CredentialId), PasskeyText.Printable(row.PersonHandle), row.CreatedUtc.ToString("o", System.Globalization.CultureInfo.InvariantCulture));
                _credentials.Activate(row.PersonHandle, row.CredentialId);
            }
            else
            {
                Log.Warn("Removing stale pending passkey credential {0} of {1} (saved {2}, never accepted by the registrar)", PasskeyText.Printable(row.CredentialId), PasskeyText.Printable(row.PersonHandle), row.CreatedUtc.ToString("o", System.Globalization.CultureInfo.InvariantCulture));
                _credentials.Remove(row.PersonHandle, row.CredentialId);
            }
        }
    }

    /// <summary>
    /// Whether the registrar holds the row's key as the key set of the row's handle.  Keys are
    /// compared by canonical fingerprint, never by PEM text.
    /// </summary>
    private bool IsRegisteredKeySetOf(PasskeyCredentialData row)
    {
        if (!row.IsRegisteredKeySet)
        {
            return false;
        }
        PublicKeySetData? keySet = _registrar.Resolve(row.PersonHandle);
        string? rowKey = PublicKeyFingerprint.Of(row.PublicKeyPem);
        if (keySet is null || rowKey is null)
        {
            return false;
        }
        string? registeredRsa = string.IsNullOrEmpty(keySet.PublicRsaKey) ? null : PublicKeyFingerprint.Of(keySet.PublicRsaKey);
        string? registeredEcc = string.IsNullOrEmpty(keySet.PublicEccKey) ? null : PublicKeyFingerprint.Of(keySet.PublicEccKey);
        return string.Equals(rowKey, registeredRsa, StringComparison.Ordinal) || string.Equals(rowKey, registeredEcc, StringComparison.Ordinal);
    }

    private static bool TryReadBinding(byte[]? binding, out string? boundHandle)
    {
        boundHandle = null;
        if (binding is null || binding.Length == 0)
        {
            return false;
        }
        if (binding[0] == DiscoverableBinding)
        {
            return binding.Length == 1;
        }
        if (binding[0] != HandleBinding || binding.Length == 1)
        {
            return false;
        }
        boundHandle = Encoding.UTF8.GetString(binding, 1, binding.Length - 1);
        return true;
    }

    private static PasskeyCredentialData BuildCredential(string personHandle, ParsedPasskeyCredential credential, string pem, string userHandle, bool isRegisteredKeySet)
    {
        return new PasskeyCredentialData
        {
            PersonHandle = personHandle,
            CredentialId = credential.CredentialId,
            UserHandle = userHandle,
            PublicKeyPem = pem,
            Algorithm = (long)credential.Algorithm,
            SignCount = credential.SignCount,
            Aaguid = Convert.ToHexString(credential.Aaguid).ToLowerInvariant(),
            Transports = string.Join(",", credential.Transports),
            BackupEligible = credential.Flags.HasFlag(AuthenticatorFlags.BackupEligible),
            BackedUp = credential.Flags.HasFlag(AuthenticatorFlags.BackedUp),
            CreatedUtc = DateTime.UtcNow,
            IsRegisteredKeySet = isRegisteredKeySet
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
        // The handle and, through the detail, the client's own bytes are caller-chosen: one bounded line each.
        // A detail from PasskeyVerification.Fail is already printable and may end in a truncation note, so the
        // cap here leaves room for it; a raw detail (a registrar exception message) is cut here for the first time.
        Log.Warn("Passkey registration for {0} failed: {1} ({2})", PasskeyText.Printable(personHandle), failure, PasskeyText.Printable(detail ?? string.Empty, PasskeyVerification.MaxLoggedDetailLength));
        return new PasskeyRegistrationResult { Success = false, Failure = failure, Message = VerificationFailedMessage };
    }

    private static PasskeySignInResult SignInFailed(string? credentialId, PasskeyVerificationFailure failure, string? detail)
    {
        // The credential id comes straight from the response when no stored credential matched it.
        Log.Warn("Passkey assertion for credential {0} failed: {1} ({2})", PasskeyText.Printable(credentialId), failure, PasskeyText.Printable(detail ?? string.Empty, PasskeyVerification.MaxLoggedDetailLength));
        return new PasskeySignInResult { Success = false, Failure = failure, Message = VerificationFailedMessage };
    }
}
