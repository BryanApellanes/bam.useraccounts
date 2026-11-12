using Bam.Encryption;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Profile;
using Bam.Protocol.Profile.Registration;
using Bam.UserAccounts.Passkeys;
using NSubstitute;

namespace Bam.UserAccounts.Tests.TestClasses;

/// <summary>
/// A composed <see cref="PasskeySignUp"/> over a real passkey ceremony (<see cref="PasskeyFixture"/>)
/// and recording stand-ins for the account service and the profile repository.
/// </summary>
public sealed class SignUpFixture
{
    public SignUpFixture(SignUpPolicy? policy = null)
    {
        Policy = policy ?? new SignUpPolicy();
        Passkeys = new PasskeyFixture();
        Steps = new PostSignUpSteps();
        Accounts = Substitute.For<IUserAccountService>();
        Accounts.RegisterPerson(Arg.Any<PersonRegistrationData>()).Returns(callInfo =>
        {
            PersonRegistrationData data = callInfo.Arg<PersonRegistrationData>();
            RegisterAttempts++;
            if (RegisterPersonThrows is not null)
            {
                throw RegisterPersonThrows;
            }
            if (RegisterPersonRefuses)
            {
                return new RegistrationResult { Success = false, Message = "refused by the validator" };
            }
            lock (RegisteredPersons)
            {
                RegisteredPersons.Add(data);
                Persons.Add(data.Handle);
            }
            IProfile profile = Substitute.For<IProfile>();
            profile.ProfileHandle.Returns("profile-" + data.Handle);
            profile.PersonHandle.Returns(data.Handle);
            profile.Name.Returns(data.FirstName + " " + data.LastName);
            return new RegistrationResult { Success = true, Profile = profile };
        });
        Accounts.UpdateProfile(Arg.Any<string>(), Arg.Any<Action<ProfileData>>()).Returns(callInfo =>
        {
            ProfileData profile = new ProfileData();
            callInfo.Arg<Action<ProfileData>>()(profile);
            ProfileNames[callInfo.Arg<string>()] = profile.Name;
            return profile;
        });
        Profiles = Substitute.For<IProfileRepository>();
        Profiles.FindPersonByHandle(Arg.Any<string>()).Returns(callInfo =>
        {
            bool found;
            lock (RegisteredPersons)
            {
                found = Persons.Contains(callInfo.Arg<string>());
            }
            // A rendezvous after the read lets a test hold two lookups until both have read.
            FindPersonRendezvous?.SignalAndWait(RendezvousTimeout);
            return found ? new PersonData { Handle = callInfo.Arg<string>() } : null!;
        });
        SignUp = new PasskeySignUp(Passkeys.Ceremony, Accounts, Passkeys.Credentials, Profiles, Policy, Steps);
    }

    public SignUpPolicy Policy { get; }
    public PasskeyFixture Passkeys { get; }
    public PostSignUpSteps Steps { get; }
    public IUserAccountService Accounts { get; }
    public IProfileRepository Profiles { get; }
    public PasskeySignUp SignUp { get; }

    /// <summary>Handles the profile repository reports a person for.</summary>
    public HashSet<string> Persons { get; } = new HashSet<string>(StringComparer.Ordinal);

    /// <summary>Every registration the account service accepted.</summary>
    public List<PersonRegistrationData> RegisteredPersons { get; } = new List<PersonRegistrationData>();

    /// <summary>Profile names set through <c>UpdateProfile</c>, by profile handle.</summary>
    public Dictionary<string, string> ProfileNames { get; } = new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>When set, every person lookup waits here (up to <see cref="RendezvousTimeout"/>) after reading.</summary>
    public Barrier? FindPersonRendezvous { get; set; }

    public TimeSpan RendezvousTimeout { get; set; } = TimeSpan.FromMilliseconds(500);

    public int RegisterAttempts { get; private set; }
    public Exception? RegisterPersonThrows { get; set; }
    public bool RegisterPersonRefuses { get; set; }

    /// <summary>Runs Begin then Complete with the authenticator, the way the browser module does.</summary>
    public PasskeySignUpResult Run(PasskeySignUpRequest request, SyntheticAuthenticator authenticator)
    {
        PasskeySignUpBeginResult begun = SignUp.Begin(request);
        if (!begun.Success || begun.Options is null)
        {
            return new PasskeySignUpResult { Success = false, Refusal = begun.Refusal, Message = begun.Message };
        }
        byte[] challenge = Base64UrlEncoder.Default.Decode(begun.Options.Challenge);
        return SignUp.Complete(request, authenticator.Register(challenge));
    }

    /// <summary>Whether a registration challenge is pending for the handle (consumes it).</summary>
    public bool HasPendingRegistration(string handle)
    {
        return Passkeys.Challenges.Take("passkey-registration:" + handle) is not null;
    }
}
