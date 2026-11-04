using Bam.Encryption;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Profile;
using Bam.UserAccounts.Passkeys;
using NSubstitute;

namespace Bam.UserAccounts.Tests.TestClasses;

/// <summary>
/// A composed passkey ceremony over in-memory custody and a recording key-set registrar, plus
/// the knobs the ceremony and adapter tests turn.
/// </summary>
public sealed class PasskeyFixture
{
    public const string Handle = "person-abc";

    public PasskeyFixture(PasskeyOptions? options = null)
    {
        Options = options ?? DefaultOptions();
        Challenges = new InMemoryConfirmationChallengeRepository();
        Credentials = new InMemoryPasskeyCredentialRepository();
        Registrar = Substitute.For<IPublicKeySetRegistrar>();
        Registrar.Register(Arg.Any<PublicKeySetData>()).Returns(callInfo =>
        {
            PublicKeySetData keySet = callInfo.Arg<PublicKeySetData>();
            Registered.Add(keySet);
            if (RegistrarThrows is not null)
            {
                throw RegistrarThrows;
            }
            return keySet;
        });
        SignatureVerifier = new DetachedSignatureVerifier();
        Ceremony = new PasskeyCeremony(
            Options,
            Challenges,
            Credentials,
            new PasskeyRegistrationVerifier(Options),
            new PasskeyAssertionVerifier(Options, SignatureVerifier),
            Registrar);
    }

    public PasskeyOptions Options { get; }
    public InMemoryConfirmationChallengeRepository Challenges { get; }
    public InMemoryPasskeyCredentialRepository Credentials { get; }
    public IPublicKeySetRegistrar Registrar { get; }
    public List<PublicKeySetData> Registered { get; } = new List<PublicKeySetData>();
    public Exception? RegistrarThrows { get; set; }
    public DetachedSignatureVerifier SignatureVerifier { get; }
    public PasskeyCeremony Ceremony { get; }

    public static PasskeyOptions DefaultOptions(bool requireUserVerification = false)
    {
        return new PasskeyOptions
        {
            RpId = "lumberjack.live",
            RpName = "Lumberjack",
            AllowedOrigins = new List<string> { "https://lumberjack.live" },
            RequireUserVerification = requireUserVerification
        };
    }

    /// <summary>Runs a full registration for the handle with the authenticator and returns the result.</summary>
    public PasskeyRegistrationResult Register(SyntheticAuthenticator authenticator, string handle = Handle)
    {
        PasskeyCreationOptions creation = Ceremony.BeginRegistration(handle, "Jane Doe");
        byte[] challenge = Base64UrlEncoder.Default.Decode(creation.Challenge);
        return Ceremony.CompleteRegistration(handle, authenticator.Register(challenge));
    }

    /// <summary>Runs the authenticated add-a-passkey path for the handle and returns the result.</summary>
    public PasskeyRegistrationResult RegisterAdditional(SyntheticAuthenticator authenticator, string handle = Handle)
    {
        PasskeyCreationOptions creation = Ceremony.BeginAdditionalRegistration(handle, "Jane Doe");
        byte[] challenge = Base64UrlEncoder.Default.Decode(creation.Challenge);
        return Ceremony.CompleteAdditionalRegistration(handle, authenticator.Register(challenge));
    }

    /// <summary>Runs a full assertion for the handle with the authenticator and returns the result.</summary>
    public PasskeySignInResult SignIn(SyntheticAuthenticator authenticator, string? handle = Handle, string? userHandle = null)
    {
        PasskeyRequestOptions request = Ceremony.BeginAssertion(handle);
        byte[] challenge = Base64UrlEncoder.Default.Decode(request.Challenge);
        return Ceremony.CompleteAssertion(authenticator.Assert(challenge, request.CeremonyId, userHandle));
    }
}
