using Bam.Logging;
using Bam.Protocol.Data;
using Bam.Protocol.Profile.Registration;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// <see cref="IPasskeySignUp"/> over the passkey ceremony and the account service.  The order
/// is deliberate: the ceremony runs first because it is what enforces handle uniqueness
/// (<c>ProfileManager.RegisterPersonProfile</c> does not), then the profile is written, then the
/// host's steps run.  A profile fault after the passkey has claimed the handle is logged and
/// reported, never thrown: the person can sign in and <see cref="CompleteProfile"/> finishes the job.
/// Every refusal is logged at warning level with its <see cref="SignUpRefusal"/> and the handle;
/// invite codes and credential material are never logged.
/// </summary>
public sealed class PasskeySignUp : IPasskeySignUp
{
    /// <summary>The message for refusals whose reason must not reach an anonymous caller.</summary>
    public const string SignUpFailedMessage = "Sign-up could not be completed";

    // A handle is at most 64 characters once accepted; a refused one is logged cut to this length.
    private const int PrintableHandleLength = 40;

    private readonly IPasskeyCeremony _ceremony;
    private readonly IUserAccountService _accounts;
    private readonly IPasskeyCredentialRepository _credentials;
    private readonly IProfileRepository _profiles;
    private readonly SignUpPolicy _policy;
    private readonly PostSignUpSteps _steps;

    /// <summary>Initializes the sign-up sequence.</summary>
    /// <param name="ceremony">The passkey ceremony; claims the handle.</param>
    /// <param name="accounts">Writes the person profile.</param>
    /// <param name="credentials">Passkey custody, read for availability.</param>
    /// <param name="profiles">Person lookup, so a person without a passkey also counts as taken.</param>
    /// <param name="policy">The host's sign-up policy.</param>
    /// <param name="steps">The host's post-sign-up steps.</param>
    public PasskeySignUp(IPasskeyCeremony ceremony, IUserAccountService accounts, IPasskeyCredentialRepository credentials, IProfileRepository profiles, SignUpPolicy policy, PostSignUpSteps steps)
    {
        _ceremony = ceremony;
        _accounts = accounts;
        _credentials = credentials;
        _profiles = profiles;
        _policy = policy;
        _steps = steps;
    }

    /// <inheritdoc />
    public PasskeySignUpBeginResult Begin(PasskeySignUpRequest? request)
    {
        string handle = SignUpPolicy.NormalizeHandle(request?.Handle);
        SignUpRefusal refusal = Check(request, handle);
        if (refusal == SignUpRefusal.None && _policy.AllowHandleAvailabilityCheck && IsTaken(handle))
        {
            refusal = SignUpRefusal.HandleTaken;
        }
        if (refusal != SignUpRefusal.None)
        {
            Log.Warn("Passkey sign-up for {0} refused at begin: {1}", PasskeyText.Printable(handle, PrintableHandleLength), refusal);
            return new PasskeySignUpBeginResult { Success = false, Refusal = refusal, Message = MessageFor(refusal) };
        }

        PasskeyCreationOptions options = _ceremony.BeginRegistration(handle, DisplayNameOf(request, handle));
        return new PasskeySignUpBeginResult { Success = true, PersonHandle = handle, Options = options, Message = string.Empty };
    }

    /// <inheritdoc />
    public PasskeySignUpResult Complete(PasskeySignUpRequest? request, PasskeyRegistrationResponse? response)
    {
        string handle = SignUpPolicy.NormalizeHandle(request?.Handle);
        SignUpRefusal refusal = Check(request, handle);
        if (refusal == SignUpRefusal.None && PersonExists(handle))
        {
            // The ceremony refuses a handle that has a key set or a passkey; a person row with
            // neither (legacy data) would otherwise be claimed and duplicated.
            refusal = SignUpRefusal.HandleTaken;
        }
        if (refusal != SignUpRefusal.None)
        {
            Log.Warn("Passkey sign-up for {0} refused at completion: {1}", PasskeyText.Printable(handle, PrintableHandleLength), refusal);
            return new PasskeySignUpResult { Success = false, Refusal = refusal, Message = MessageFor(refusal) };
        }

        PasskeyRegistrationResult registration = _ceremony.CompleteRegistration(handle, response);
        if (!registration.Success)
        {
            Log.Warn("Passkey sign-up for {0} refused at completion: {1} ({2})", PasskeyText.Printable(handle, PrintableHandleLength), SignUpRefusal.CeremonyFailed, registration.Failure);
            return new PasskeySignUpResult { Success = false, Refusal = SignUpRefusal.CeremonyFailed, Message = SignUpFailedMessage };
        }

        string displayName = DisplayNameOf(request, handle);
        string? email = string.IsNullOrWhiteSpace(request?.Email) ? null : request.Email.Trim();
        bool profileCreated = CreateProfile(handle, displayName, email);
        SignedUpPerson person = new SignedUpPerson
        {
            PersonHandle = handle,
            DisplayName = displayName,
            Email = email,
            KeyFingerprint = registration.KeyFingerprint,
            ProfileCreated = profileCreated
        };
        string? nextUrl = RunSteps(person);
        Log.Info("Passkey sign-up completed for {0} (key {1}, profile created: {2})", PasskeyText.Printable(handle, PrintableHandleLength), registration.KeyFingerprint ?? string.Empty, profileCreated);
        return new PasskeySignUpResult
        {
            Success = true,
            Refusal = profileCreated ? SignUpRefusal.None : SignUpRefusal.ProfileFailed,
            Message = string.Empty,
            PersonHandle = handle,
            DisplayName = displayName,
            CredentialId = registration.CredentialId,
            KeyFingerprint = registration.KeyFingerprint,
            ProfileCreated = profileCreated,
            NextUrl = nextUrl
        };
    }

    /// <inheritdoc />
    public HandleAvailability CheckHandle(string? handle)
    {
        string normalized = SignUpPolicy.NormalizeHandle(handle);
        if (!_policy.AllowHandleAvailabilityCheck)
        {
            return new HandleAvailability { Handle = normalized, Available = true, Reason = HandleAvailabilityReason.NotChecked };
        }
        if (!_policy.IsHandleAcceptable(normalized))
        {
            return new HandleAvailability { Handle = normalized, Available = false, Reason = HandleAvailabilityReason.Invalid };
        }
        bool taken = IsTaken(normalized);
        return new HandleAvailability { Handle = normalized, Available = !taken, Reason = taken ? HandleAvailabilityReason.Taken : HandleAvailabilityReason.Available };
    }

    /// <inheritdoc />
    public bool HasProfile(string personHandle)
    {
        string handle = SignUpPolicy.NormalizeHandle(personHandle);
        return handle.Length > 0 && PersonExists(handle);
    }

    /// <inheritdoc />
    public ProfileCompletion CompleteProfile(string personHandle, string? displayName, string? email)
    {
        string handle = SignUpPolicy.NormalizeHandle(personHandle);
        if (handle.Length == 0 || !_credentials.FindByHandle(handle).Any(credential => !credential.Pending))
        {
            Log.Warn("Profile completion for {0} refused: the handle has no passkey", PasskeyText.Printable(handle, PrintableHandleLength));
            return ProfileCompletion.NoPasskey;
        }
        if (PersonExists(handle))
        {
            return ProfileCompletion.AlreadyExists;
        }
        string? address = string.IsNullOrWhiteSpace(email) ? null : email.Trim();
        if ((_policy.RequireEmail || address is not null) && !SignUpPolicy.IsPlausibleEmail(address))
        {
            return ProfileCompletion.InvalidEmail;
        }
        string name = string.IsNullOrWhiteSpace(displayName) ? handle : Truncate(displayName.Trim());
        return CreateProfile(handle, name, address) ? ProfileCompletion.Created : ProfileCompletion.Failed;
    }

    private SignUpRefusal Check(PasskeySignUpRequest? request, string handle)
    {
        if (request is null)
        {
            return SignUpRefusal.InvalidHandle;
        }
        if (!_policy.OpenSignUp)
        {
            if (_policy.InviteCodes.Count == 0)
            {
                return SignUpRefusal.SignUpClosed;
            }
            if (!_policy.AcceptsInvite(request.InviteCode))
            {
                return SignUpRefusal.InviteRequired;
            }
        }
        if (!_policy.IsHandleAcceptable(handle))
        {
            return SignUpRefusal.InvalidHandle;
        }
        bool emailGiven = !string.IsNullOrWhiteSpace(request.Email);
        if ((_policy.RequireEmail || emailGiven) && !SignUpPolicy.IsPlausibleEmail(request.Email?.Trim()))
        {
            return SignUpRefusal.EmailRequired;
        }
        return SignUpRefusal.None;
    }

    private bool IsTaken(string handle)
    {
        return _credentials.FindByHandle(handle).Count > 0 || PersonExists(handle);
    }

    private bool PersonExists(string handle)
    {
        return _profiles.FindPersonByHandle(handle) is not null;
    }

    private bool CreateProfile(string handle, string displayName, string? email)
    {
        try
        {
            string[] tokens = displayName.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            string firstName = tokens.Length > 0 ? tokens[0] : handle;
            // A single-word name is repeated as the last name: DefaultRegistrationValidator
            // requires both, and the profile's Name is set to the display name just below.
            string lastName = tokens.Length > 1 ? string.Join(' ', tokens.Skip(1)) : firstName;
            PersonRegistrationData data = new PersonRegistrationData
            {
                Handle = handle,
                FirstName = firstName,
                LastName = lastName,
                Email = email!
            };
            RegistrationResult registered = _accounts.RegisterPerson(data);
            if (!registered.Success)
            {
                Log.Warn("Passkey sign-up for {0}: the passkey claimed the handle but the profile was refused ({1})", PasskeyText.Printable(handle, PrintableHandleLength), PasskeyText.Printable(registered.Message));
                return false;
            }
            string? profileHandle = registered.Profile?.ProfileHandle;
            if (!string.IsNullOrEmpty(profileHandle) && !string.Equals(registered.Profile?.Name, displayName, StringComparison.Ordinal))
            {
                _accounts.UpdateProfile(profileHandle, profile => profile.Name = displayName);
            }
            return true;
        }
        catch (Exception e)
        {
            Log.Warn("Passkey sign-up for {0}: the passkey claimed the handle but the profile write faulted ({1}: {2})", PasskeyText.Printable(handle, PrintableHandleLength), e.GetType().Name, PasskeyText.Printable(e.Message));
            return false;
        }
    }

    private string? RunSteps(SignedUpPerson person)
    {
        string? nextUrl = null;
        foreach (Func<IPostSignUpStep> resolve in _steps.Snapshot())
        {
            try
            {
                PostSignUpOutcome? outcome = resolve().Run(person);
                if (nextUrl is null && !string.IsNullOrWhiteSpace(outcome?.NextUrl))
                {
                    nextUrl = outcome.NextUrl;
                }
            }
            catch (Exception e)
            {
                Log.Warn("Post-sign-up step for {0} faulted and was skipped ({1}: {2})", PasskeyText.Printable(person.PersonHandle, PrintableHandleLength), e.GetType().Name, PasskeyText.Printable(e.Message));
            }
        }
        return nextUrl;
    }

    private static string DisplayNameOf(PasskeySignUpRequest? request, string handle)
    {
        return string.IsNullOrWhiteSpace(request?.DisplayName) ? handle : Truncate(request.DisplayName.Trim());
    }

    private static string Truncate(string displayName)
    {
        return displayName.Length <= SignUpPolicy.MaxDisplayNameLength ? displayName : displayName.Substring(0, SignUpPolicy.MaxDisplayNameLength).TrimEnd();
    }

    private string MessageFor(SignUpRefusal refusal)
    {
        switch (refusal)
        {
            case SignUpRefusal.SignUpClosed:
                return "Sign-up is closed";
            case SignUpRefusal.InviteRequired:
                return "A valid invite code is required";
            case SignUpRefusal.InvalidHandle:
                return "That handle cannot be used";
            case SignUpRefusal.EmailRequired:
                return "A valid email address is required";
            case SignUpRefusal.HandleTaken:
                return _policy.AllowHandleAvailabilityCheck ? "That handle is taken" : SignUpFailedMessage;
            default:
                return SignUpFailedMessage;
        }
    }
}
