using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Test;
using Bam.UserAccounts;

namespace Bam.UserAccounts.Tests.Unit;

[UnitTestMenu("RsaChallengeSignatureVerifier Should", Selector = "rcsv")]
public class RsaChallengeSignatureVerifierShould : UnitTestMenuContainer
{
    private static readonly RsaPublicPrivateKeyPair KeyPair = new RsaPublicPrivateKeyPair();
    private static readonly RsaPublicPrivateKeyPair WrongKeyPair = new RsaPublicPrivateKeyPair();

    public RsaChallengeSignatureVerifierShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    private static void SetupDefaults(TestCaseRegistry reg)
    {
        reg.For<IChallengeSignatureVerifier>().Use(new RsaChallengeSignatureVerifier(new RsaSignatureProvider()));
    }

    private static ConfirmationChallenge NewChallenge()
    {
        return new ConfirmationChallenge
        {
            PersonHandle = "person-abc",
            ChallengeBytes = new byte[] { 10, 20, 30, 40, 50, 60, 70, 80 },
            ExpiresUtc = DateTime.UtcNow.AddMinutes(10)
        };
    }

    private static byte[] Sign(ConfirmationChallenge challenge, RsaPublicPrivateKeyPair keyPair)
    {
        RsaPrivateKey privateKey = new RsaPrivateKey(keyPair.GetAsymmetricCipherKeyPair().Private);
        return privateKey.Sign(challenge.ChallengeBytes).SignatureBytes;
    }

    [UnitTest]
    public void AcceptSignatureFromMatchingKey()
    {
        After.Setup(SetupDefaults)
        .When<IChallengeSignatureVerifier>("verifies a signature made with the matching key", (verifier) =>
        {
            ConfirmationChallenge challenge = NewChallenge();
            return verifier.Verify(challenge, Sign(challenge, KeyPair), KeyPair.GetRsaPublicKey());
        })
        .TheTest
        .ShouldPass<ISignatureVerification>((because, _, verification) =>
        {
            because.ItsTrue("verification succeeds", verification.Success);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectSignatureFromWrongKey()
    {
        After.Setup(SetupDefaults)
        .When<IChallengeSignatureVerifier>("verifies a signature made with a different key", (verifier) =>
        {
            ConfirmationChallenge challenge = NewChallenge();
            return verifier.Verify(challenge, Sign(challenge, WrongKeyPair), KeyPair.GetRsaPublicKey());
        })
        .TheTest
        .ShouldPass<ISignatureVerification>((because, _, verification) =>
        {
            because.ItsTrue("verification fails", !verification.Success);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectGarbageBytes()
    {
        After.Setup(SetupDefaults)
        .When<IChallengeSignatureVerifier>("verifies garbage signature bytes", (verifier) =>
        {
            return verifier.Verify(NewChallenge(), new byte[] { 1, 2, 3 }, KeyPair.GetRsaPublicKey());
        })
        .TheTest
        .ShouldPass<ISignatureVerification>((because, _, verification) =>
        {
            because.ItsTrue("verification fails", !verification.Success);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectSignatureOverDifferentChallenge()
    {
        After.Setup(SetupDefaults)
        .When<IChallengeSignatureVerifier>("verifies a valid signature over different challenge bytes", (verifier) =>
        {
            ConfirmationChallenge signedChallenge = NewChallenge();
            ConfirmationChallenge presentedChallenge = new ConfirmationChallenge
            {
                PersonHandle = signedChallenge.PersonHandle,
                ChallengeBytes = new byte[] { 99, 98, 97, 96 },
                ExpiresUtc = signedChallenge.ExpiresUtc
            };
            return verifier.Verify(presentedChallenge, Sign(signedChallenge, KeyPair), KeyPair.GetRsaPublicKey());
        })
        .TheTest
        .ShouldPass<ISignatureVerification>((because, _, verification) =>
        {
            because.ItsTrue("verification fails - the signature does not cover the presented challenge", !verification.Success);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}
