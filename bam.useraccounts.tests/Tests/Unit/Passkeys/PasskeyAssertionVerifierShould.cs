using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Encryption.Cose;
using Bam.Test;
using Bam.UserAccounts.Passkeys;
using Bam.UserAccounts.Tests.TestClasses;

namespace Bam.UserAccounts.Tests.Unit.Passkeys;

[UnitTestMenu("PasskeyAssertionVerifier Should", Selector = "pav")]
public class PasskeyAssertionVerifierShould : UnitTestMenuContainer
{
    private const string UserHandle = "dXNlci1oYW5kbGU";

    public PasskeyAssertionVerifierShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    [UnitTest]
    public void AcceptAnEs256Assertion()
    {
        After.Setup(reg => reg.Set(new SyntheticAuthenticator()))
        .When<SyntheticAuthenticator>("verifies a correctly signed ES256 assertion", (authenticator, reg) =>
        {
            authenticator.SignCount = 5;
            byte[] challenge = SyntheticAuthenticator.RandomBytes(32);
            PasskeyCredentialData stored = Stored(authenticator, signCount: 2);
            PasskeyVerification verification = Verifier().Verify(authenticator.Assert(challenge, userHandle: UserHandle), challenge, stored);
            return verification;
        })
        .TheTest
        .ShouldPass<PasskeyVerification>((because, verification) =>
        {
            because.ItsTrue("verification succeeds", verification.Success, verification.Detail);
            because.ItsTrue("authenticator data is returned", verification.AuthenticatorData is not null);
            because.ItsTrue("sign count is the authenticator's", verification.AuthenticatorData!.SignCount == 5);
            because.ItsTrue("user verified flag is read", verification.AuthenticatorData.UserVerified);
            because.ItsTrue("no credential is parsed on assertion", verification.Credential is null);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void AcceptAnRs256Assertion()
    {
        After.Setup(reg => reg.Set(new SyntheticAuthenticator(CoseAlgorithm.RS256)))
        .When<SyntheticAuthenticator>("verifies a correctly signed RS256 assertion", (authenticator, reg) =>
        {
            byte[] challenge = SyntheticAuthenticator.RandomBytes(32);
            return Verifier().Verify(authenticator.Assert(challenge), challenge, Stored(authenticator, signCount: 0));
        })
        .TheTest
        .ShouldPass<PasskeyVerification>((because, verification) =>
        {
            because.ItsTrue("verification succeeds", verification.Success, verification.Detail);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectEveryBrokenAssertion()
    {
        After.Setup(reg => reg.Set(new SyntheticAuthenticator()))
        .When<SyntheticAuthenticator>("verifies each broken assertion", (authenticator, reg) =>
        {
            PasskeyAssertionVerifier verifier = Verifier();
            byte[] challenge = SyntheticAuthenticator.RandomBytes(32);
            byte[] otherChallenge = SyntheticAuthenticator.RandomBytes(32);
            authenticator.SignCount = 10;
            PasskeyCredentialData stored = Stored(authenticator, signCount: 5);
            PasskeyAssertionResponse good = authenticator.Assert(challenge, userHandle: UserHandle);
            SyntheticAuthenticator other = new SyntheticAuthenticator();
            other.SignCount = 11;

            byte[] tampered = Base64UrlEncoder.Default.Decode(good.Response.Signature);
            tampered[^1] ^= 0x01;

            PasskeyVerificationFailure nullResponse = verifier.Verify(null, challenge, stored).Failure;
            PasskeyVerificationFailure tamperedSignature = verifier.Verify(good with { Response = good.Response with { Signature = Base64UrlEncoder.Default.Encode(tampered) } }, challenge, stored).Failure;
            PasskeyVerificationFailure otherKey = verifier.Verify(other.Assert(challenge, id: authenticator.CredentialIdBase64Url), challenge, stored).Failure;
            PasskeyVerificationFailure foreignId = verifier.Verify(other.Assert(challenge), challenge, stored).Failure;
            PasskeyVerificationFailure userHandleMismatch = verifier.Verify(authenticator.Assert(challenge, userHandle: "b3RoZXI"), challenge, stored).Failure;
            PasskeyVerificationFailure wrongType = verifier.Verify(authenticator.Assert(challenge, clientData: authenticator.ClientDataJson(ClientData.TypeCreate, challenge)), challenge, stored).Failure;
            PasskeyVerificationFailure challengeMismatch = verifier.Verify(authenticator.Assert(otherChallenge), challenge, stored).Failure;
            PasskeyVerificationFailure origin = verifier.Verify(authenticator.Assert(challenge, origin: "https://evil.example"), challenge, stored).Failure;
            PasskeyVerificationFailure rpId = verifier.Verify(authenticator.Assert(challenge, rpId: "evil.example"), challenge, stored).Failure;
            PasskeyVerificationFailure badAuthData = verifier.Verify(good with { Response = good.Response with { AuthenticatorData = "AAAA" } }, challenge, stored).Failure;
            PasskeyVerificationFailure emptySignature = verifier.Verify(good with { Response = good.Response with { Signature = "" } }, challenge, stored).Failure;

            authenticator.SignCount = 5;
            PasskeyVerificationFailure sameCount = verifier.Verify(authenticator.Assert(challenge), challenge, stored).Failure;
            authenticator.SignCount = 4;
            PasskeyVerificationFailure lowerCount = verifier.Verify(authenticator.Assert(challenge), challenge, stored).Failure;
            authenticator.SignCount = 0;
            PasskeyVerificationFailure zeroWithZeroStored = verifier.Verify(authenticator.Assert(challenge), challenge, Stored(authenticator, signCount: 0)).Failure;
            authenticator.SignCount = 10;

            PasskeyCredentialData unsupportedStored = Stored(authenticator, signCount: 0);
            unsupportedStored.Algorithm = 99;
            PasskeyVerificationFailure unsupportedAlgorithm = verifier.Verify(authenticator.Assert(challenge), challenge, unsupportedStored).Failure;
            PasskeyCredentialData badKeyStored = Stored(authenticator, signCount: 0);
            badKeyStored.PublicKeyPem = "not a pem";
            PasskeyVerificationFailure badStoredKey = verifier.Verify(authenticator.Assert(challenge), challenge, badKeyStored).Failure;

            string challengeText = Base64UrlEncoder.Default.Encode(challenge);
            byte[] objectType = System.Text.Encoding.UTF8.GetBytes("{\"type\":{},\"challenge\":\"" + challengeText + "\",\"origin\":\"https://lumberjack.live\"}");
            byte[] arrayChallenge = System.Text.Encoding.UTF8.GetBytes("{\"type\":\"webauthn.get\",\"challenge\":[\"a\"],\"origin\":\"https://lumberjack.live\"}");
            byte[] stringCrossOrigin = System.Text.Encoding.UTF8.GetBytes("{\"type\":\"webauthn.get\",\"challenge\":\"" + challengeText + "\",\"origin\":\"https://lumberjack.live\",\"crossOrigin\":\"yes\"}");
            PasskeyVerificationFailure objectTypeFailure = verifier.Verify(authenticator.Assert(challenge, clientData: objectType), challenge, stored).Failure;
            PasskeyVerificationFailure arrayChallengeFailure = verifier.Verify(authenticator.Assert(challenge, clientData: arrayChallenge), challenge, stored).Failure;
            PasskeyVerificationFailure stringCrossOriginFailure = verifier.Verify(authenticator.Assert(challenge, clientData: stringCrossOrigin), challenge, stored).Failure;

            authenticator.UserVerified = false;
            PasskeyVerificationFailure uvRequired = new PasskeyAssertionVerifier(PasskeyFixture.DefaultOptions(requireUserVerification: true), new DetachedSignatureVerifier())
                .Verify(authenticator.Assert(challenge), challenge, stored).Failure;
            authenticator.UserVerified = true;

            return new RejectionOutcome(nullResponse, tamperedSignature, otherKey, foreignId, userHandleMismatch, wrongType, challengeMismatch, origin, rpId,
                badAuthData, emptySignature, sameCount, lowerCount, zeroWithZeroStored, unsupportedAlgorithm, badStoredKey, uvRequired,
                objectTypeFailure, arrayChallengeFailure, stringCrossOriginFailure);
        })
        .TheTest
        .ShouldPass<RejectionOutcome>((because, outcome) =>
        {
            because.ItsTrue("null response is malformed", outcome.NullResponse == PasskeyVerificationFailure.MalformedClientData);
            because.ItsTrue("tampered signature is invalid", outcome.TamperedSignature == PasskeyVerificationFailure.InvalidSignature);
            because.ItsTrue("signature by another key is invalid", outcome.OtherKey == PasskeyVerificationFailure.InvalidSignature);
            because.ItsTrue("response for another credential id is unknown", outcome.ForeignId == PasskeyVerificationFailure.UnknownCredential);
            because.ItsTrue("user handle not matching the credential is refused", outcome.UserHandleMismatch == PasskeyVerificationFailure.UnknownCredential);
            because.ItsTrue("webauthn.create client data is the wrong type", outcome.WrongType == PasskeyVerificationFailure.WrongType);
            because.ItsTrue("another challenge is a mismatch", outcome.ChallengeMismatch == PasskeyVerificationFailure.ChallengeMismatch);
            because.ItsTrue("unlisted origin is refused", outcome.Origin == PasskeyVerificationFailure.OriginNotAllowed);
            because.ItsTrue("another rp id is refused", outcome.RpId == PasskeyVerificationFailure.RpIdMismatch);
            because.ItsTrue("short authenticator data is malformed", outcome.BadAuthData == PasskeyVerificationFailure.MalformedAuthenticatorData);
            because.ItsTrue("empty signature is invalid", outcome.EmptySignature == PasskeyVerificationFailure.InvalidSignature);
            because.ItsTrue("sign count equal to stored is a regression", outcome.SameCount == PasskeyVerificationFailure.SignCountRegressed);
            because.ItsTrue("sign count below stored is a regression", outcome.LowerCount == PasskeyVerificationFailure.SignCountRegressed);
            because.ItsTrue("zero counter with zero stored is accepted", outcome.ZeroWithZeroStored == PasskeyVerificationFailure.None);
            because.ItsTrue("unsupported stored algorithm is refused", outcome.UnsupportedAlgorithm == PasskeyVerificationFailure.UnsupportedAlgorithm);
            because.ItsTrue("unparseable stored key is refused", outcome.BadStoredKey == PasskeyVerificationFailure.InvalidCredentialKey);
            because.ItsTrue("user not verified is refused when required", outcome.UvRequired == PasskeyVerificationFailure.UserNotVerified);
            because.ItsTrue("client data whose type is an object is malformed, not an exception", outcome.ObjectType == PasskeyVerificationFailure.MalformedClientData);
            because.ItsTrue("client data whose challenge is an array is malformed, not an exception", outcome.ArrayChallenge == PasskeyVerificationFailure.MalformedClientData);
            because.ItsTrue("client data whose crossOrigin is a string is malformed, not an exception", outcome.StringCrossOrigin == PasskeyVerificationFailure.MalformedClientData);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static PasskeyAssertionVerifier Verifier()
    {
        return new PasskeyAssertionVerifier(PasskeyFixture.DefaultOptions(), new DetachedSignatureVerifier());
    }

    private static PasskeyCredentialData Stored(SyntheticAuthenticator authenticator, long signCount)
    {
        return new PasskeyCredentialData
        {
            PersonHandle = PasskeyFixture.Handle,
            CredentialId = authenticator.CredentialIdBase64Url,
            UserHandle = UserHandle,
            PublicKeyPem = authenticator.PublicKeyPem,
            Algorithm = (long)authenticator.Algorithm,
            SignCount = signCount,
            CreatedUtc = DateTime.UtcNow
        };
    }

    private sealed record RejectionOutcome(PasskeyVerificationFailure NullResponse, PasskeyVerificationFailure TamperedSignature, PasskeyVerificationFailure OtherKey,
        PasskeyVerificationFailure ForeignId, PasskeyVerificationFailure UserHandleMismatch, PasskeyVerificationFailure WrongType, PasskeyVerificationFailure ChallengeMismatch,
        PasskeyVerificationFailure Origin, PasskeyVerificationFailure RpId, PasskeyVerificationFailure BadAuthData, PasskeyVerificationFailure EmptySignature,
        PasskeyVerificationFailure SameCount, PasskeyVerificationFailure LowerCount, PasskeyVerificationFailure ZeroWithZeroStored, PasskeyVerificationFailure UnsupportedAlgorithm,
        PasskeyVerificationFailure BadStoredKey, PasskeyVerificationFailure UvRequired, PasskeyVerificationFailure ObjectType, PasskeyVerificationFailure ArrayChallenge,
        PasskeyVerificationFailure StringCrossOrigin);
}
