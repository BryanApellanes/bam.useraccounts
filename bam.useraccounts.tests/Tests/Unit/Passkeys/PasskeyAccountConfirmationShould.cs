using System.Text;
using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Protocol;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Common;
using Bam.Protocol.Data.Profile;
using Bam.Test;
using Bam.UserAccounts.Passkeys;
using Bam.UserAccounts.Tests.TestClasses;
using NSubstitute;
using Org.BouncyCastle.X509;

namespace Bam.UserAccounts.Tests.Unit.Passkeys;

[UnitTestMenu("PasskeyAccountConfirmation Should", Selector = "pkac")]
public class PasskeyAccountConfirmationShould : UnitTestMenuContainer
{
    public PasskeyAccountConfirmationShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    /// <summary>Everything a confirmation test needs: a fixture with one registered passkey, a profile repository that serves its key set, and the adapter.</summary>
    private sealed class Harness
    {
        public Harness()
        {
            Fixture = new PasskeyFixture();
            Authenticator = new SyntheticAuthenticator();
            Fixture.Register(Authenticator);
            KeySet = Fixture.Registered[0];
            Profiles = Substitute.For<IProfileRepository>();
            Profiles.FindPublicKeySetByHandle(PasskeyFixture.Handle).Returns(callInfo => ServedKeySet);
            Profiles.FindProfileByHandle(PasskeyFixture.Handle).Returns(new ProfileData { PersonHandle = PasskeyFixture.Handle, Name = "Jane Doe" });
            Certificates = Substitute.For<ICertificateManager>();
            Certificates.CreateSignedCertificate(Arg.Any<IActor>()).Returns(callInfo =>
            {
                IssuedFor.Add(callInfo.Arg<IActor>());
                return Substitute.For<X509Certificate>();
            });
            Confirmation = new PasskeyAccountConfirmation(
                Fixture.Options,
                Certificates,
                Profiles,
                new PasskeyChallengeSignatureVerifier(Fixture.Ceremony, Fixture.Credentials),
                Fixture.Challenges);
        }

        public PasskeyFixture Fixture { get; }
        public SyntheticAuthenticator Authenticator { get; }
        public PublicKeySetData KeySet { get; }
        public PublicKeySetData? ServedKeySet { get; set; }
        public IProfileRepository Profiles { get; }
        public ICertificateManager Certificates { get; }
        public List<IActor> IssuedFor { get; } = new List<IActor>();
        public PasskeyAccountConfirmation Confirmation { get; }

        public byte[] Answer(ConfirmationChallenge challenge, SyntheticAuthenticator? authenticator = null)
        {
            return (authenticator ?? Authenticator).Assert(challenge.ChallengeBytes).ToJsonBytes();
        }
    }

    [UnitTest]
    public void ConfirmWithAPasskeyAssertion()
    {
        After.Setup(reg => reg.Set(new Harness()))
        .When<Harness>("creates a challenge and answers it with the registered passkey", (harness, reg) =>
        {
            harness.ServedKeySet = harness.KeySet;
            DateTime before = DateTime.UtcNow;
            ConfirmationChallenge challenge = harness.Confirmation.CreateChallenge(PasskeyFixture.Handle);
            PasskeyRequestOptions request = harness.Fixture.Ceremony.ToRequestOptions(challenge);
            harness.Authenticator.SignCount = 4;
            ConfirmationResult result = harness.Confirmation.VerifySignedChallenge(PasskeyFixture.Handle, harness.Answer(challenge));
            ConfirmationResult again = harness.Confirmation.VerifySignedChallenge(PasskeyFixture.Handle, harness.Answer(challenge));
            long signCount = harness.Fixture.Credentials.FindByCredentialId(harness.Authenticator.CredentialIdBase64Url)!.SignCount;
            return new ConfirmOutcome(before, challenge, request, result, again, harness.IssuedFor, signCount);
        })
        .TheTest
        .ShouldPass<ConfirmOutcome>((because, outcome) =>
        {
            because.ItsTrue("challenge expires after the configured lifetime", outcome.Challenge.ExpiresUtc >= outcome.Before.AddMinutes(5).AddSeconds(-1) && outcome.Challenge.ExpiresUtc <= DateTime.UtcNow.AddMinutes(5).AddSeconds(1));
            because.ItsTrue("request options carry the challenge bytes", outcome.Request.Challenge == Base64UrlEncoder.Default.Encode(outcome.Challenge.ChallengeBytes));
            because.ItsTrue("account is confirmed", outcome.Result.Confirmed && outcome.Result.Success, outcome.Result.Message);
            because.ItsTrue("a certificate is issued", outcome.Result.Certificate is not null);
            because.ItsTrue("certificate is issued to the person by handle and profile name", outcome.IssuedFor.Count == 1 && outcome.IssuedFor[0].Handle == PasskeyFixture.Handle && outcome.IssuedFor[0].Name == "Jane Doe");
            because.ItsTrue("message says passkey", outcome.Result.Message == "Account confirmed via passkey");
            because.ItsTrue("sign count is recorded through the adapter", outcome.SignCount == 4);
            because.ItsTrue("challenge is single-use", !outcome.Again.Confirmed && outcome.Again.Message.Contains("No pending challenge"));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseEveryBrokenConfirmation()
    {
        After.Setup(reg => reg.Set(new Harness()))
        .When<Harness>("runs each failing confirmation", (harness, reg) =>
        {
            harness.ServedKeySet = harness.KeySet;
            ConfirmationResult noPending = harness.Confirmation.VerifySignedChallenge(PasskeyFixture.Handle, new byte[] { 1, 2, 3 });

            ConfirmationChallenge garbageChallenge = harness.Confirmation.CreateChallenge(PasskeyFixture.Handle);
            ConfirmationResult garbage = harness.Confirmation.VerifySignedChallenge(PasskeyFixture.Handle, Encoding.UTF8.GetBytes("{not json"));

            SyntheticAuthenticator stranger = new SyntheticAuthenticator();
            harness.Fixture.Register(stranger, "other-person");
            ConfirmationChallenge strangerChallenge = harness.Confirmation.CreateChallenge(PasskeyFixture.Handle);
            ConfirmationResult otherPersonsCredential = harness.Confirmation.VerifySignedChallenge(PasskeyFixture.Handle, harness.Answer(strangerChallenge, stranger));

            ConfirmationChallenge wrongChallenge = harness.Confirmation.CreateChallenge(PasskeyFixture.Handle);
            ConfirmationChallenge stale = new ConfirmationChallenge { PersonHandle = PasskeyFixture.Handle, ChallengeBytes = SyntheticAuthenticator.RandomBytes(32), ExpiresUtc = wrongChallenge.ExpiresUtc };
            ConfirmationResult wrongBytes = harness.Confirmation.VerifySignedChallenge(PasskeyFixture.Handle, harness.Answer(stale));

            harness.ServedKeySet = null;
            ConfirmationChallenge noKeySetChallenge = harness.Confirmation.CreateChallenge(PasskeyFixture.Handle);
            ConfirmationResult noKeySet = harness.Confirmation.VerifySignedChallenge(PasskeyFixture.Handle, harness.Answer(noKeySetChallenge));

            harness.ServedKeySet = new PublicKeySetData { KeySetHandle = PasskeyFixture.Handle, PublicEccKey = new SyntheticAuthenticator().PublicKeyPem };
            ConfirmationChallenge foreignKeySetChallenge = harness.Confirmation.CreateChallenge(PasskeyFixture.Handle);
            ConfirmationResult foreignKeySet = harness.Confirmation.VerifySignedChallenge(PasskeyFixture.Handle, harness.Answer(foreignKeySetChallenge));

            harness.ServedKeySet = harness.KeySet;
            SyntheticAuthenticator second = new SyntheticAuthenticator();
            harness.Fixture.RegisterAdditional(second);
            second.SignCount = 2;
            ConfirmationChallenge secondChallenge = harness.Confirmation.CreateChallenge(PasskeyFixture.Handle);
            ConfirmationResult secondCredential = harness.Confirmation.VerifySignedChallenge(PasskeyFixture.Handle, harness.Answer(secondChallenge, second));

            return new RefusalOutcome(noPending, garbage, otherPersonsCredential, wrongBytes, noKeySet, foreignKeySet, secondCredential);
        })
        .TheTest
        .ShouldPass<RefusalOutcome>((because, outcome) =>
        {
            because.ItsTrue("no pending challenge is reported as such", !outcome.NoPending.Confirmed && outcome.NoPending.Message.Contains("No pending challenge"));
            because.ItsTrue("garbage bytes fail generically", !outcome.Garbage.Confirmed && outcome.Garbage.Message == DeviceKeyAccountConfirmation.VerificationFailedMessage);
            because.ItsTrue("another person's credential fails generically", !outcome.OtherPersonsCredential.Confirmed && outcome.OtherPersonsCredential.Message == DeviceKeyAccountConfirmation.VerificationFailedMessage);
            because.ItsTrue("assertion over other bytes fails generically", !outcome.WrongBytes.Confirmed && outcome.WrongBytes.Message == DeviceKeyAccountConfirmation.VerificationFailedMessage);
            because.ItsTrue("missing key set fails generically", !outcome.NoKeySet.Confirmed && outcome.NoKeySet.Message == DeviceKeyAccountConfirmation.VerificationFailedMessage);
            because.ItsTrue("key-set credential whose key is not the registered key set fails", !outcome.ForeignKeySet.Confirmed);
            because.ItsTrue("a second credential added through the authenticated path confirms", outcome.SecondCredential.Confirmed, outcome.SecondCredential.Message);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private sealed record ConfirmOutcome(DateTime Before, ConfirmationChallenge Challenge, PasskeyRequestOptions Request, ConfirmationResult Result, ConfirmationResult Again, List<IActor> IssuedFor, long SignCount);
    private sealed record RefusalOutcome(ConfirmationResult NoPending, ConfirmationResult Garbage, ConfirmationResult OtherPersonsCredential, ConfirmationResult WrongBytes, ConfirmationResult NoKeySet, ConfirmationResult ForeignKeySet, ConfirmationResult SecondCredential);
}
