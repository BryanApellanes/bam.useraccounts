using Bam.DependencyInjection;
using Bam.Protocol;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Common;
using Bam.Protocol.Profile;
using Bam.Test;
using Bam.UserAccounts;
using NSubstitute;
using Org.BouncyCastle.X509;

namespace Bam.UserAccounts.Tests.Unit;

[UnitTestMenu("DeviceKeyAccountConfirmation Should", Selector = "dkac")]
public class DeviceKeyAccountConfirmationShould : UnitTestMenuContainer
{
    public DeviceKeyAccountConfirmationShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    private static void SetupDefaults(TestCaseRegistry reg)
    {
        var certificateManager = Substitute.For<ICertificateManager>();
        var keyManager = Substitute.For<IKeyManager>();
        var profileManager = Substitute.For<IProfileManager>();

        var mockProfile = Substitute.For<IProfile>();
        mockProfile.PersonHandle.Returns("person-abc");
        mockProfile.Name.Returns("Jane Doe");

        profileManager.FindProfileByHandle("person-abc").Returns(mockProfile);
        profileManager.FindProfileByPublicKey(Arg.Any<string>()).Returns(mockProfile);

        var mockCert = Substitute.For<X509Certificate>();
        certificateManager.CreateSignedCertificate(Arg.Any<IActor>()).Returns(mockCert);

        reg.For<ICertificateManager>().Use(certificateManager);
        reg.For<IKeyManager>().Use(keyManager);
        reg.For<IProfileManager>().Use(profileManager);

        reg.For<IAccountConfirmation>().Use(new DeviceKeyAccountConfirmation(
            certificateManager, keyManager, profileManager));
    }

    [UnitTest]
    public void CreateChallengeWithCorrectHandle()
    {
        After.Setup(SetupDefaults)
        .When<IAccountConfirmation>("creates a challenge for a person", (confirmation) =>
        {
            return confirmation.CreateChallenge("person-abc");
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheObjectUnderTest
                .IsNotNull()
                .IsObjectOfType<DeviceKeyAccountConfirmation>();

            because.TheResult
                .IsNotNull()
                .As<ConfirmationChallenge>("has correct person handle", c => c!.PersonHandle == "person-abc")
                .As<ConfirmationChallenge>("has challenge bytes", c => c!.ChallengeBytes != null && c.ChallengeBytes.Length == 32)
                .As<ConfirmationChallenge>("expires in the future", c => c!.ExpiresUtc > DateTime.UtcNow);
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
            var challenge1 = confirmation.CreateChallenge("person-abc");
            var challenge2 = confirmation.CreateChallenge("person-abc");
            return new { Challenge1 = challenge1, Challenge2 = challenge2 };
        })
        .TheTest
        .ShouldPass(because =>
        {
            dynamic result = because.TheResult.As<dynamic>();
            ConfirmationChallenge c1 = result.Challenge1;
            ConfirmationChallenge c2 = result.Challenge2;

            because.ItsTrue("challenges have different bytes",
                !c1.ChallengeBytes.SequenceEqual(c2.ChallengeBytes));
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
            return confirmation.VerifySignedChallenge("person-abc", new byte[] { 1, 2, 3 });
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<ConfirmationResult>("is not confirmed", r => !r!.Confirmed)
                .As<ConfirmationResult>("is not successful", r => !r!.Success)
                .As<ConfirmationResult>("has message about no pending challenge", r => r!.Message.Contains("No pending challenge"));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void IssueCertificateOnSuccessfulVerification()
    {
        After.Setup(SetupDefaults)
        .When<IAccountConfirmation>("creates challenge then verifies", (confirmation) =>
        {
            confirmation.CreateChallenge("person-abc");
            return confirmation.VerifySignedChallenge("person-abc", new byte[] { 1, 2, 3 });
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<ConfirmationResult>("is confirmed", r => r!.Confirmed)
                .As<ConfirmationResult>("is successful", r => r!.Success)
                .As<ConfirmationResult>("has a certificate", r => r!.Certificate != null)
                .As<ConfirmationResult>("has success message", r => r!.Message.Contains("confirmed"));

            var certManager = because.TestCaseRegistry.Get<ICertificateManager>();
            certManager.Received(1).CreateSignedCertificate(Arg.Any<IActor>());
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
            confirmation.CreateChallenge("person-abc");
            confirmation.VerifySignedChallenge("person-abc", new byte[] { 1, 2, 3 });
            return confirmation.VerifySignedChallenge("person-abc", new byte[] { 1, 2, 3 });
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<ConfirmationResult>("second verification fails", r => !r!.Confirmed)
                .As<ConfirmationResult>("has message about no pending challenge", r => r!.Message.Contains("No pending challenge"));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void FailVerificationForUnknownProfile()
    {
        After.Setup(reg =>
        {
            SetupDefaults(reg);
            var profileManager = reg.Get<IProfileManager>();
            profileManager.FindProfileByHandle("unknown-person").Returns((IProfile)null!);
        })
        .When<IAccountConfirmation>("verifies for unknown person", (confirmation) =>
        {
            confirmation.CreateChallenge("unknown-person");
            return confirmation.VerifySignedChallenge("unknown-person", new byte[] { 1, 2, 3 });
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult
                .IsNotNull()
                .As<ConfirmationResult>("is not confirmed", r => !r!.Confirmed)
                .As<ConfirmationResult>("has message about profile not found", r => r!.Message.Contains("Profile not found"));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}
