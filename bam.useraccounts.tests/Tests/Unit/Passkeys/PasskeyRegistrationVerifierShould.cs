using System.Text;
using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Encryption.Cose;
using Bam.Test;
using Bam.UserAccounts.Passkeys;
using Bam.UserAccounts.Tests.TestClasses;

namespace Bam.UserAccounts.Tests.Unit.Passkeys;

[UnitTestMenu("PasskeyRegistrationVerifier Should", Selector = "prv")]
public class PasskeyRegistrationVerifierShould : UnitTestMenuContainer
{
    public PasskeyRegistrationVerifierShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    [UnitTest]
    public void AcceptAnEs256Registration()
    {
        After.Setup(reg => reg.Set(new SyntheticAuthenticator()))
        .When<SyntheticAuthenticator>("verifies a well-formed ES256 registration", (authenticator, reg) =>
        {
            authenticator.BackupEligible = true;
            authenticator.SignCount = 3;
            byte[] challenge = SyntheticAuthenticator.RandomBytes(32);
            PasskeyRegistrationVerifier verifier = new PasskeyRegistrationVerifier(PasskeyFixture.DefaultOptions());
            PasskeyVerification verification = verifier.Verify(authenticator.Register(challenge), challenge);
            return new AcceptOutcome(authenticator, verification);
        })
        .TheTest
        .ShouldPass<AcceptOutcome>((because, outcome) =>
        {
            ParsedPasskeyCredential credential = outcome.Verification.Credential!;
            because.ItsTrue("verification succeeds", outcome.Verification.Success, outcome.Verification.Detail);
            because.ItsTrue("credential id is the authenticator's", credential.CredentialId == outcome.Authenticator.CredentialIdBase64Url);
            because.ItsTrue("raw credential id bytes match", credential.CredentialIdBytes.SequenceEqual(outcome.Authenticator.CredentialId));
            because.ItsTrue("public key is the credential key", credential.PublicKey.Pem == outcome.Authenticator.PublicKeyPem);
            because.ItsTrue("public key is an EccPublicKey", credential.PublicKey is EccPublicKey);
            because.ItsTrue("algorithm is ES256", credential.Algorithm == CoseAlgorithm.ES256);
            because.ItsTrue("aaguid is carried", credential.Aaguid.SequenceEqual(outcome.Authenticator.Aaguid));
            because.ItsTrue("sign count is carried", credential.SignCount == 3);
            because.ItsTrue("backup-eligible flag is carried", credential.Flags.HasFlag(AuthenticatorFlags.BackupEligible));
            because.ItsTrue("user-verified flag is carried", credential.Flags.HasFlag(AuthenticatorFlags.UserVerified));
            because.ItsTrue("transports are carried", credential.Transports.Contains("internal"));
            because.ItsTrue("authenticator data is returned", outcome.Verification.AuthenticatorData is not null && outcome.Verification.AuthenticatorData.AttestedCredential is not null);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void AcceptAnRs256Registration()
    {
        After.Setup(reg => reg.Set(new SyntheticAuthenticator(CoseAlgorithm.RS256)))
        .When<SyntheticAuthenticator>("verifies a well-formed RS256 registration", (authenticator, reg) =>
        {
            byte[] challenge = SyntheticAuthenticator.RandomBytes(32);
            PasskeyRegistrationVerifier verifier = new PasskeyRegistrationVerifier(PasskeyFixture.DefaultOptions());
            PasskeyVerification verification = verifier.Verify(authenticator.Register(challenge), challenge);
            return new AcceptOutcome(authenticator, verification);
        })
        .TheTest
        .ShouldPass<AcceptOutcome>((because, outcome) =>
        {
            because.ItsTrue("verification succeeds", outcome.Verification.Success, outcome.Verification.Detail);
            because.ItsTrue("public key is an RsaPublicKey", outcome.Verification.Credential!.PublicKey is RsaPublicKey);
            because.ItsTrue("algorithm is RS256", outcome.Verification.Credential.Algorithm == CoseAlgorithm.RS256);
            because.ItsTrue("public key pem matches", outcome.Verification.Credential.PublicKey.Pem == outcome.Authenticator.PublicKeyPem);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectEveryBrokenRegistration()
    {
        After.Setup(reg => reg.Set(new SyntheticAuthenticator()))
        .When<SyntheticAuthenticator>("verifies each broken registration", (authenticator, reg) =>
        {
            PasskeyOptions options = PasskeyFixture.DefaultOptions();
            PasskeyOptions requireUv = PasskeyFixture.DefaultOptions(requireUserVerification: true);
            byte[] challenge = SyntheticAuthenticator.RandomBytes(32);
            byte[] otherChallenge = SyntheticAuthenticator.RandomBytes(32);
            PasskeyRegistrationResponse good = authenticator.Register(challenge);

            PasskeyVerificationFailure nullResponse = Failure(options, null, challenge);
            PasskeyVerificationFailure wrongType = Failure(options, authenticator.Register(challenge, clientData: authenticator.ClientDataJson(ClientData.TypeGet, challenge)), challenge);
            PasskeyVerificationFailure challengeMismatch = Failure(options, authenticator.Register(otherChallenge), challenge);
            PasskeyVerificationFailure origin = Failure(options, authenticator.Register(challenge, origin: "https://evil.example"), challenge);
            PasskeyVerificationFailure rpId = Failure(options, authenticator.Register(challenge, rpId: "evil.example"), challenge);
            authenticator.UserPresent = false;
            PasskeyVerificationFailure notPresent = Failure(options, authenticator.Register(challenge), challenge);
            authenticator.UserPresent = true;
            authenticator.UserVerified = false;
            PasskeyVerificationFailure notVerifiedButRequired = Failure(requireUv, authenticator.Register(challenge), challenge);
            PasskeyVerificationFailure notVerifiedButPreferred = Failure(options, authenticator.Register(challenge), challenge);
            authenticator.UserVerified = true;
            PasskeyVerificationFailure idMismatch = Failure(options, authenticator.Register(challenge, id: Base64UrlEncoder.Default.Encode(SyntheticAuthenticator.RandomBytes(16))), challenge);
            PasskeyVerificationFailure unsupported = Failure(options, new SyntheticAuthenticator(CoseAlgorithm.ES384).Register(challenge), challenge);
            PasskeyVerificationFailure notJson = Failure(options, authenticator.Register(challenge, clientData: Encoding.UTF8.GetBytes("not json")), challenge);
            PasskeyVerificationFailure notBase64 = Failure(options, good with { Response = good.Response with { ClientDataJson = "%%%" } }, challenge);
            PasskeyVerificationFailure badAttestation = Failure(options, good with { Response = good.Response with { AttestationObject = Base64UrlEncoder.Default.Encode(Encoding.UTF8.GetBytes("garbage")) } }, challenge);
            PasskeyVerificationFailure noAttestedCredential = Failure(options, authenticator.Register(challenge, authData: authenticator.AuthenticatorData(false)), challenge);
            PasskeyVerificationFailure wrongResponseType = Failure(options, good with { Type = "password" }, challenge);
            byte[] withExtensions = authenticator.AuthenticatorData(true, extensions: CborWriter.Encode(CborWriter.Map(CborWriter.Entry("credProps", CborWriter.Map()))));
            PasskeyVerificationFailure extensionsAccepted = Failure(options, authenticator.Register(challenge, authData: withExtensions), challenge);
            byte[] trailing = authenticator.AuthenticatorData(true).Concat(new byte[] { 0x00 }).ToArray();
            PasskeyVerificationFailure trailingBytes = Failure(options, authenticator.Register(challenge, authData: trailing), challenge);
            return new RejectionOutcome(nullResponse, wrongType, challengeMismatch, origin, rpId, notPresent, notVerifiedButRequired,
                notVerifiedButPreferred, idMismatch, unsupported, notJson, notBase64, badAttestation, noAttestedCredential, wrongResponseType, extensionsAccepted, trailingBytes);
        })
        .TheTest
        .ShouldPass<RejectionOutcome>((because, outcome) =>
        {
            because.ItsTrue("null response is malformed client data", outcome.NullResponse == PasskeyVerificationFailure.MalformedClientData);
            because.ItsTrue("webauthn.get client data is the wrong type", outcome.WrongType == PasskeyVerificationFailure.WrongType);
            because.ItsTrue("another challenge is a challenge mismatch", outcome.ChallengeMismatch == PasskeyVerificationFailure.ChallengeMismatch);
            because.ItsTrue("unlisted origin is refused", outcome.Origin == PasskeyVerificationFailure.OriginNotAllowed);
            because.ItsTrue("another rp id is refused", outcome.RpId == PasskeyVerificationFailure.RpIdMismatch);
            because.ItsTrue("user not present is refused", outcome.NotPresent == PasskeyVerificationFailure.UserNotPresent);
            because.ItsTrue("user not verified is refused when required", outcome.NotVerifiedButRequired == PasskeyVerificationFailure.UserNotVerified);
            because.ItsTrue("user not verified is accepted when preferred", outcome.NotVerifiedButPreferred == PasskeyVerificationFailure.None);
            because.ItsTrue("response id not matching the attested credential is refused", outcome.IdMismatch == PasskeyVerificationFailure.CredentialIdMismatch);
            because.ItsTrue("algorithm the host did not offer is refused", outcome.Unsupported == PasskeyVerificationFailure.UnsupportedAlgorithm);
            because.ItsTrue("non-JSON client data is refused", outcome.NotJson == PasskeyVerificationFailure.MalformedClientData);
            because.ItsTrue("non-base64url client data is refused", outcome.NotBase64 == PasskeyVerificationFailure.MalformedClientData);
            because.ItsTrue("non-CBOR attestation object is refused", outcome.BadAttestation == PasskeyVerificationFailure.MalformedAttestation);
            because.ItsTrue("authenticator data without an attested credential is refused", outcome.NoAttestedCredential == PasskeyVerificationFailure.MalformedAuthenticatorData);
            because.ItsTrue("response type other than public-key is refused", outcome.WrongResponseType == PasskeyVerificationFailure.MalformedClientData);
            because.ItsTrue("authenticator data with an extensions map is accepted", outcome.ExtensionsAccepted == PasskeyVerificationFailure.None);
            because.ItsTrue("authenticator data with trailing bytes is refused", outcome.TrailingBytes == PasskeyVerificationFailure.MalformedAuthenticatorData);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static PasskeyVerificationFailure Failure(PasskeyOptions options, PasskeyRegistrationResponse? response, byte[] challenge)
    {
        return new PasskeyRegistrationVerifier(options).Verify(response, challenge).Failure;
    }

    private sealed record AcceptOutcome(SyntheticAuthenticator Authenticator, PasskeyVerification Verification);

    private sealed record RejectionOutcome(PasskeyVerificationFailure NullResponse, PasskeyVerificationFailure WrongType, PasskeyVerificationFailure ChallengeMismatch,
        PasskeyVerificationFailure Origin, PasskeyVerificationFailure RpId, PasskeyVerificationFailure NotPresent, PasskeyVerificationFailure NotVerifiedButRequired,
        PasskeyVerificationFailure NotVerifiedButPreferred, PasskeyVerificationFailure IdMismatch, PasskeyVerificationFailure Unsupported, PasskeyVerificationFailure NotJson,
        PasskeyVerificationFailure NotBase64, PasskeyVerificationFailure BadAttestation, PasskeyVerificationFailure NoAttestedCredential, PasskeyVerificationFailure WrongResponseType,
        PasskeyVerificationFailure ExtensionsAccepted, PasskeyVerificationFailure TrailingBytes);
}
