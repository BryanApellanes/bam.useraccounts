using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Protocol;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Common;
using Bam.Protocol.Data.Profile;
using Bam.Test;
using Bam.UserAccounts;
using NSubstitute;
using Org.BouncyCastle.X509;

namespace Bam.UserAccounts.Tests.Unit;

[UnitTestMenu("DeviceKeyAccountConfirmation Should", Selector = "dkac")]
public class DeviceKeyAccountConfirmationShould : UnitTestMenuContainer
{
    private const string Handle = "person-abc";
    private static readonly RsaPublicPrivateKeyPair KeyPair = new RsaPublicPrivateKeyPair();
    private static readonly RsaPublicPrivateKeyPair WrongKeyPair = new RsaPublicPrivateKeyPair();

    public DeviceKeyAccountConfirmationShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    private static byte[] SignChallenge(ConfirmationChallenge challenge, RsaPublicPrivateKeyPair keyPair)
    {
        RsaPrivateKey privateKey = new RsaPrivateKey(keyPair.GetAsymmetricCipherKeyPair().Private);
        return privateKey.Sign(challenge.ChallengeBytes).SignatureBytes;
    }

    private static void SetupDefaults(TestCaseRegistry reg)
    {
        SetupWith(reg, new InMemoryConfirmationChallengeRepository());
    }

    private static void SetupWith(TestCaseRegistry reg, IConfirmationChallengeRepository challengeRepository)
    {
        ICertificateManager certificateManager = Substitute.For<ICertificateManager>();
        IProfileRepository profileRepository = Substitute.For<IProfileRepository>();

        profileRepository.FindPublicKeySetByHandle(Handle).Returns(new PublicKeySetData
        {
            KeySetHandle = Handle,
            PublicRsaKey = KeyPair.PublicKeyPem
        });
        profileRepository.FindProfileByHandle(Handle).Returns(new ProfileData
        {
            PersonHandle = Handle,
            Name = "Jane Doe"
        });

        X509Certificate mockCert = Substitute.For<X509Certificate>();
        certificateManager.CreateSignedCertificate(Arg.Any<IActor>()).Returns(mockCert);

        reg.For<ICertificateManager>().Use(certificateManager);
        reg.For<IProfileRepository>().Use(profileRepository);
        reg.For<IConfirmationChallengeRepository>().Use(challengeRepository);

        reg.For<IAccountConfirmation>().Use(new DeviceKeyAccountConfirmation(
            certificateManager,
            profileRepository,
            new RsaChallengeSignatureVerifier(new RsaSignatureProvider()),
            challengeRepository));
    }

    [UnitTest]
    public void CreateChallengeWithCorrectHandle()
    {
        After.Setup(SetupDefaults)
        .When<IAccountConfirmation>("creates a challenge for a person", (confirmation) =>
        {
            return confirmation.CreateChallenge(Handle);
        })
        .TheTest
        .ShouldPass<ConfirmationChallenge>((because, _, challenge) =>
        {
            because.ItsTrue("has correct person handle", challenge.PersonHandle == Handle);
            because.ItsTrue("has 32 challenge bytes", challenge.ChallengeBytes != null && challenge.ChallengeBytes.Length == 32);
            because.ItsTrue("expires in the future", challenge.ExpiresUtc > DateTime.UtcNow);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void CreateUniqueChallengesPerCall()
    {
        After.Setup(SetupDefaults)
        .When<IAccountConfirmation>("creates two challenges", (confirmation) =>
        {
            ConfirmationChallenge first = confirmation.CreateChallenge(Handle);
            ConfirmationChallenge second = confirmation.CreateChallenge(Handle);
            return new ChallengePairOutcome(first, second);
        })
        .TheTest
        .ShouldPass<ChallengePairOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("challenges have different bytes",
                !outcome.First.ChallengeBytes.SequenceEqual(outcome.Second.ChallengeBytes));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void FailVerificationWithNoPendingChallenge()
    {
        After.Setup(SetupDefaults)
        .When<IAccountConfirmation>("verifies without a pending challenge", (confirmation) =>
        {
            return confirmation.VerifySignedChallenge(Handle, new byte[] { 1, 2, 3 });
        })
        .TheTest
        .ShouldPass<ConfirmationResult>((because, _, result) =>
        {
            because.ItsTrue("is not confirmed", !result.Confirmed);
            because.ItsTrue("is not successful", !result.Success);
            because.ItsTrue("has message about no pending challenge", result.Message.Contains("No pending challenge"));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ConfirmWithValidSignatureAndIssueCertificate()
    {
        After.Setup(SetupDefaults)
        .When<IAccountConfirmation>("verifies a correctly signed challenge", (confirmation) =>
        {
            ConfirmationChallenge challenge = confirmation.CreateChallenge(Handle);
            return confirmation.VerifySignedChallenge(Handle, SignChallenge(challenge, KeyPair));
        })
        .TheTest
        .ShouldPass<ConfirmationResult>((because, _, result) =>
        {
            because.ItsTrue("is confirmed", result.Confirmed);
            because.ItsTrue("is successful", result.Success);
            because.ItsTrue("has a certificate", result.Certificate != null);
            because.ItsTrue("has success message", result.Message.Contains("confirmed"));

            ICertificateManager certificateManager = because.TestCaseRegistry.Get<ICertificateManager>();
            certificateManager.Received(1).CreateSignedCertificate(Arg.Any<IActor>());
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectGarbageSignature()
    {
        After.Setup(SetupDefaults)
        .When<IAccountConfirmation>("verifies garbage signature bytes", (confirmation) =>
        {
            confirmation.CreateChallenge(Handle);
            return confirmation.VerifySignedChallenge(Handle, new byte[] { 1, 2, 3 });
        })
        .TheTest
        .ShouldPass<ConfirmationResult>((because, _, result) =>
        {
            because.ItsTrue("is not confirmed", !result.Confirmed);
            because.ItsTrue("is not successful", !result.Success);
            because.ItsTrue("names the signature as the failure", result.Message.Contains("Signature invalid"));

            ICertificateManager certificateManager = because.TestCaseRegistry.Get<ICertificateManager>();
            certificateManager.DidNotReceive().CreateSignedCertificate(Arg.Any<IActor>());
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectSignatureFromWrongKey()
    {
        After.Setup(SetupDefaults)
        .When<IAccountConfirmation>("verifies a challenge signed with a different key", (confirmation) =>
        {
            ConfirmationChallenge challenge = confirmation.CreateChallenge(Handle);
            return confirmation.VerifySignedChallenge(Handle, SignChallenge(challenge, WrongKeyPair));
        })
        .TheTest
        .ShouldPass<ConfirmationResult>((because, _, result) =>
        {
            because.ItsTrue("is not confirmed", !result.Confirmed);
            because.ItsTrue("names the signature as the failure", result.Message.Contains("Signature invalid"));

            ICertificateManager certificateManager = because.TestCaseRegistry.Get<ICertificateManager>();
            certificateManager.DidNotReceive().CreateSignedCertificate(Arg.Any<IActor>());
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectExpiredChallenge()
    {
        InMemoryConfirmationChallengeRepository challengeRepository = new InMemoryConfirmationChallengeRepository();
        ConfirmationChallenge expired = new ConfirmationChallenge
        {
            PersonHandle = Handle,
            ChallengeBytes = new byte[] { 4, 5, 6, 7 },
            ExpiresUtc = DateTime.UtcNow.AddMinutes(-1)
        };
        challengeRepository.Save(expired);

        After.Setup(reg => SetupWith(reg, challengeRepository))
        .When<IAccountConfirmation>("verifies an expired challenge with a valid signature", (confirmation) =>
        {
            return confirmation.VerifySignedChallenge(Handle, SignChallenge(expired, KeyPair));
        })
        .TheTest
        .ShouldPass<ConfirmationResult>((because, _, result) =>
        {
            because.ItsTrue("is not confirmed", !result.Confirmed);
            because.ItsTrue("has message about expiry", result.Message.Contains("expired"));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ConsumeChallengeAfterVerification()
    {
        After.Setup(SetupDefaults)
        .When<IAccountConfirmation>("verifies the same challenge twice", (confirmation) =>
        {
            ConfirmationChallenge challenge = confirmation.CreateChallenge(Handle);
            byte[] signedChallenge = SignChallenge(challenge, KeyPair);
            ConfirmationResult first = confirmation.VerifySignedChallenge(Handle, signedChallenge);
            ConfirmationResult second = confirmation.VerifySignedChallenge(Handle, signedChallenge);
            return new VerificationPairOutcome(first, second);
        })
        .TheTest
        .ShouldPass<VerificationPairOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("first verification is confirmed", outcome.First.Confirmed);
            because.ItsTrue("second verification fails", !outcome.Second.Confirmed);
            because.ItsTrue("second has message about no pending challenge", outcome.Second.Message.Contains("No pending challenge"));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ConsumeChallengeOnFailedVerification()
    {
        After.Setup(SetupDefaults)
        .When<IAccountConfirmation>("retries with the correct signature after a garbage attempt", (confirmation) =>
        {
            ConfirmationChallenge challenge = confirmation.CreateChallenge(Handle);
            byte[] validSignature = SignChallenge(challenge, KeyPair);
            ConfirmationResult first = confirmation.VerifySignedChallenge(Handle, new byte[] { 1, 2, 3 });
            ConfirmationResult second = confirmation.VerifySignedChallenge(Handle, validSignature);
            return new VerificationPairOutcome(first, second);
        })
        .TheTest
        .ShouldPass<VerificationPairOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("garbage attempt fails", !outcome.First.Confirmed);
            because.ItsTrue("correct signature after failure also fails - challenge was consumed", !outcome.Second.Confirmed);
            because.ItsTrue("second has message about no pending challenge", outcome.Second.Message.Contains("No pending challenge"));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectWhenNoKeySetRegistered()
    {
        After.Setup(reg =>
        {
            SetupDefaults(reg);
            IProfileRepository profileRepository = reg.Get<IProfileRepository>();
            profileRepository.FindPublicKeySetByHandle("unknown-person").Returns((PublicKeySetData)null!);
        })
        .When<IAccountConfirmation>("verifies for a handle with no key set", (confirmation) =>
        {
            ConfirmationChallenge challenge = confirmation.CreateChallenge("unknown-person");
            return confirmation.VerifySignedChallenge("unknown-person", SignChallenge(challenge, KeyPair));
        })
        .TheTest
        .ShouldPass<ConfirmationResult>((because, _, result) =>
        {
            because.ItsTrue("is not confirmed", !result.Confirmed);
            because.ItsTrue("has message about missing signing key", result.Message.Contains("No registered signing key"));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ConfirmWithHandleAsNameWhenProfileAbsent()
    {
        After.Setup(reg =>
        {
            SetupDefaults(reg);
            IProfileRepository profileRepository = reg.Get<IProfileRepository>();
            profileRepository.FindProfileByHandle(Handle).Returns((ProfileData)null!);
            profileRepository.FindProfileByPersonHandle(Handle).Returns((ProfileData)null!);
        })
        .When<IAccountConfirmation>("verifies with a valid signature but no profile record", (confirmation) =>
        {
            ConfirmationChallenge challenge = confirmation.CreateChallenge(Handle);
            return confirmation.VerifySignedChallenge(Handle, SignChallenge(challenge, KeyPair));
        })
        .TheTest
        .ShouldPass<ConfirmationResult>((because, _, result) =>
        {
            because.ItsTrue("is confirmed - the key set is the identity anchor", result.Confirmed);

            ICertificateManager certificateManager = because.TestCaseRegistry.Get<ICertificateManager>();
            certificateManager.Received(1).CreateSignedCertificate(Arg.Is<IActor>(actor => actor.Name == Handle));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private sealed record ChallengePairOutcome(ConfirmationChallenge First, ConfirmationChallenge Second);

    private sealed record VerificationPairOutcome(ConfirmationResult First, ConfirmationResult Second);
}
