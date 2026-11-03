using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Protocol.Data;
using Bam.Protocol.Profile;
using Bam.Test;
using Bam.UserAccounts.Passkeys;
using Bam.UserAccounts.Tests.TestClasses;

namespace Bam.UserAccounts.Tests.Unit.Passkeys;

[UnitTestMenu("PasskeyCeremony Should", Selector = "pkc")]
public class PasskeyCeremonyShould : UnitTestMenuContainer
{
    public PasskeyCeremonyShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    [UnitTest]
    public void IssueCreationOptions()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture()))
        .When<PasskeyFixture>("begins a registration", (fixture, reg) =>
        {
            PasskeyCreationOptions options = fixture.Ceremony.BeginRegistration(PasskeyFixture.Handle, "Jane Doe");
            return new CreationOutcome(options, options.ToJson());
        })
        .TheTest
        .ShouldPass<CreationOutcome>((because, outcome) =>
        {
            PasskeyCreationOptions options = outcome.Options;
            because.ItsTrue("rp id and name come from the options", options.Rp.Id == "lumberjack.live" && options.Rp.Name == "Lumberjack");
            because.ItsTrue("user id is 32 random bytes", Base64UrlEncoder.Default.Decode(options.User.Id).Length == 32);
            because.ItsTrue("user name is the handle and display name is given", options.User.Name == PasskeyFixture.Handle && options.User.DisplayName == "Jane Doe");
            because.ItsTrue("challenge is 32 bytes", Base64UrlEncoder.Default.Decode(options.Challenge).Length == 32);
            because.ItsTrue("ES256 and RS256 are offered", options.PubKeyCredParams.Select(parameter => parameter.Alg).SequenceEqual(new long[] { -7, -257 }));
            because.ItsTrue("attestation is none", options.Attestation == "none");
            because.ItsTrue("timeout is 60 seconds in milliseconds", options.Timeout == 60000);
            because.ItsTrue("no credentials are excluded for a new person", options.ExcludeCredentials.Count == 0);
            because.ItsTrue("json is camelCase", outcome.Json.Contains("\"pubKeyCredParams\"") && outcome.Json.Contains("\"authenticatorSelection\""));
            because.ItsTrue("json omits nulls", !outcome.Json.Contains("\"transports\":null"));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RegisterTheFirstPasskeyAsTheKeySet()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture()))
        .When<PasskeyFixture>("completes a first registration", (fixture, reg) =>
        {
            SyntheticAuthenticator authenticator = new SyntheticAuthenticator();
            authenticator.BackedUp = true;
            authenticator.BackupEligible = true;
            PasskeyCreationOptions creation = fixture.Ceremony.BeginRegistration(PasskeyFixture.Handle, "Jane Doe");
            byte[] challenge = Base64UrlEncoder.Default.Decode(creation.Challenge);
            PasskeyRegistrationResult result = fixture.Ceremony.CompleteRegistration(PasskeyFixture.Handle, authenticator.Register(challenge));
            PasskeyCredentialData? stored = fixture.Credentials.FindByCredentialId(authenticator.CredentialIdBase64Url);
            PasskeyRegistrationResult again = fixture.Ceremony.CompleteRegistration(PasskeyFixture.Handle, authenticator.Register(challenge));
            return new RegistrationOutcome(fixture, authenticator, creation, result, stored, again);
        })
        .TheTest
        .ShouldPass<RegistrationOutcome>((because, outcome) =>
        {
            because.ItsTrue("registration succeeds", outcome.Result.Success, outcome.Result.Message);
            because.ItsTrue("key set is registered", outcome.Result.KeySetRegistered);
            because.ItsTrue("registrar received the handle and the ECC pem", outcome.Fixture.Registered.Count == 1
                && outcome.Fixture.Registered[0].KeySetHandle == PasskeyFixture.Handle
                && outcome.Fixture.Registered[0].PublicEccKey == outcome.Authenticator.PublicKeyPem
                && string.IsNullOrEmpty(outcome.Fixture.Registered[0].PublicRsaKey));
            because.ItsTrue("result names the credential", outcome.Result.CredentialId == outcome.Authenticator.CredentialIdBase64Url);
            because.ItsTrue("result carries the canonical fingerprint", outcome.Result.KeyFingerprint == PublicKeyFingerprint.Of(outcome.Authenticator.PublicKeyPem));
            because.ItsTrue("credential is stored", outcome.Stored is not null);
            because.ItsTrue("stored credential belongs to the handle and is the key set", outcome.Stored!.PersonHandle == PasskeyFixture.Handle && outcome.Stored.IsRegisteredKeySet);
            because.ItsTrue("stored user handle is the one issued", outcome.Stored.UserHandle == outcome.Creation.User.Id);
            because.ItsTrue("stored pem, algorithm and transports match", outcome.Stored.PublicKeyPem == outcome.Authenticator.PublicKeyPem && outcome.Stored.Algorithm == -7 && outcome.Stored.Transports == "internal");
            because.ItsTrue("stored aaguid is lowercase hex", outcome.Stored.Aaguid == Convert.ToHexString(outcome.Authenticator.Aaguid).ToLowerInvariant());
            because.ItsTrue("backup flags are stored", outcome.Stored.BackupEligible && outcome.Stored.BackedUp);
            because.ItsTrue("challenge is single-use", !outcome.Again.Success && outcome.Again.Failure == PasskeyVerificationFailure.NoPendingChallenge);
            because.ItsTrue("the pending registration challenge was consumed", outcome.Fixture.Challenges.Take("passkey-registration:" + PasskeyFixture.Handle) is null);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void AddASecondPasskeyWithoutReRegistering()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture()))
        .When<PasskeyFixture>("registers a second passkey for the same person", (fixture, reg) =>
        {
            SyntheticAuthenticator first = new SyntheticAuthenticator();
            SyntheticAuthenticator second = new SyntheticAuthenticator(Bam.Encryption.Cose.CoseAlgorithm.RS256);
            PasskeyRegistrationResult firstResult = fixture.Register(first);
            PasskeyCreationOptions creation = fixture.Ceremony.BeginRegistration(PasskeyFixture.Handle, "Jane Doe");
            byte[] challenge = Base64UrlEncoder.Default.Decode(creation.Challenge);
            PasskeyRegistrationResult secondResult = fixture.Ceremony.CompleteRegistration(PasskeyFixture.Handle, second.Register(challenge));
            return new SecondOutcome(fixture, first, firstResult, creation, secondResult);
        })
        .TheTest
        .ShouldPass<SecondOutcome>((because, outcome) =>
        {
            because.ItsTrue("both registrations succeed", outcome.FirstResult.Success && outcome.SecondResult.Success);
            because.ItsTrue("second creation reuses the user handle", outcome.Creation.User.Id == outcome.Fixture.Credentials.FindByCredentialId(outcome.First.CredentialIdBase64Url)!.UserHandle);
            because.ItsTrue("second creation excludes the first credential", outcome.Creation.ExcludeCredentials.Count == 1 && outcome.Creation.ExcludeCredentials[0].Id == outcome.First.CredentialIdBase64Url);
            because.ItsTrue("second passkey is not the key set", !outcome.SecondResult.KeySetRegistered);
            because.ItsTrue("registrar was called once", outcome.Fixture.Registered.Count == 1);
            because.ItsTrue("person has two credentials sharing a user handle", outcome.Fixture.Credentials.FindByHandle(PasskeyFixture.Handle).Select(credential => credential.UserHandle).Distinct().Count() == 1
                && outcome.Fixture.Credentials.FindByHandle(PasskeyFixture.Handle).Count == 2);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void FailRegistrationGenericallyAndHonourTheRegistrar()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture()))
        .When<PasskeyFixture>("runs each failing registration", (fixture, reg) =>
        {
            SyntheticAuthenticator authenticator = new SyntheticAuthenticator();
            PasskeyRegistrationResult noPending = fixture.Ceremony.CompleteRegistration(PasskeyFixture.Handle, authenticator.Register(SyntheticAuthenticator.RandomBytes(32)));

            fixture.Ceremony.BeginRegistration(PasskeyFixture.Handle, "Jane Doe");
            PasskeyRegistrationResult wrongChallenge = fixture.Ceremony.CompleteRegistration(PasskeyFixture.Handle, authenticator.Register(SyntheticAuthenticator.RandomBytes(32)));
            PasskeyRegistrationResult consumed = fixture.Ceremony.CompleteRegistration(PasskeyFixture.Handle, authenticator.Register(SyntheticAuthenticator.RandomBytes(32)));

            PasskeyFixture expiring = new PasskeyFixture(new PasskeyOptions
            {
                RpId = "lumberjack.live", RpName = "Lumberjack", AllowedOrigins = new List<string> { "https://lumberjack.live" }, ChallengeLifetime = TimeSpan.FromMilliseconds(1)
            });
            PasskeyCreationOptions expiringCreation = expiring.Ceremony.BeginRegistration(PasskeyFixture.Handle, "Jane Doe");
            Thread.Sleep(30);
            PasskeyRegistrationResult expired = expiring.Ceremony.CompleteRegistration(PasskeyFixture.Handle, authenticator.Register(Base64UrlEncoder.Default.Decode(expiringCreation.Challenge)));

            fixture.RegistrarThrows = new PublicKeySetConflictException(PasskeyFixture.Handle);
            PasskeyRegistrationResult conflict = fixture.Register(authenticator);
            PasskeyCredentialData? storedDespiteConflict = fixture.Credentials.FindByCredentialId(authenticator.CredentialIdBase64Url);

            fixture.RegistrarThrows = null;
            PasskeyRegistrationResult duplicate = fixture.Register(authenticator);

            SyntheticAuthenticator other = new SyntheticAuthenticator();
            fixture.RegistrarThrows = new PublicKeySetKeyMaterialConflictException("other-person", PasskeyFixture.Handle);
            PasskeyRegistrationResult materialConflict = fixture.Register(other, "other-person");
            bool otherStored = fixture.Credentials.FindByCredentialId(other.CredentialIdBase64Url) is not null;

            fixture.RegistrarThrows = new InvalidPublicKeySetException("third-person", "bad key", null);
            PasskeyRegistrationResult invalid = fixture.Register(new SyntheticAuthenticator(), "third-person");
            fixture.RegistrarThrows = null;

            return new FailureOutcome(noPending, wrongChallenge, consumed, expired, conflict, storedDespiteConflict, duplicate, materialConflict, otherStored, invalid);
        })
        .TheTest
        .ShouldPass<FailureOutcome>((because, outcome) =>
        {
            because.ItsTrue("no pending challenge fails", !outcome.NoPending.Success && outcome.NoPending.Failure == PasskeyVerificationFailure.NoPendingChallenge);
            because.ItsTrue("wrong challenge fails as a mismatch with the generic message", outcome.WrongChallenge.Failure == PasskeyVerificationFailure.ChallengeMismatch && outcome.WrongChallenge.Message == PasskeyCeremony.VerificationFailedMessage);
            because.ItsTrue("a failed attempt consumes the challenge", outcome.Consumed.Failure == PasskeyVerificationFailure.NoPendingChallenge);
            because.ItsTrue("expired challenge fails", outcome.Expired.Failure == PasskeyVerificationFailure.ChallengeExpired);
            because.ItsTrue("existing key set keeps the passkey as an extra credential", outcome.Conflict.Success && !outcome.Conflict.KeySetRegistered);
            because.ItsTrue("credential is stored without the key-set mark", outcome.StoredDespiteConflict is not null && !outcome.StoredDespiteConflict.IsRegisteredKeySet);
            because.ItsTrue("re-registering the same credential id fails", outcome.Duplicate.Failure == PasskeyVerificationFailure.CredentialAlreadyRegistered);
            because.ItsTrue("key material registered to someone else fails", outcome.MaterialConflict.Failure == PasskeyVerificationFailure.CredentialAlreadyRegistered);
            because.ItsTrue("nothing is stored when the registrar rejects the material", !outcome.OtherStored);
            because.ItsTrue("registrar rejecting the key fails as an invalid key", outcome.Invalid.Failure == PasskeyVerificationFailure.InvalidCredentialKey);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void SignInWithAnAssertion()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture()))
        .When<PasskeyFixture>("registers then asserts", (fixture, reg) =>
        {
            SyntheticAuthenticator authenticator = new SyntheticAuthenticator();
            fixture.Register(authenticator);
            authenticator.SignCount = 7;
            PasskeyRequestOptions request = fixture.Ceremony.BeginAssertion(PasskeyFixture.Handle);
            byte[] challenge = Base64UrlEncoder.Default.Decode(request.Challenge);
            PasskeyAssertionResponse response = authenticator.Assert(challenge, request.CeremonyId);
            PasskeySignInResult result = fixture.Ceremony.CompleteAssertion(response);
            PasskeyCredentialData stored = fixture.Credentials.FindByCredentialId(authenticator.CredentialIdBase64Url)!;
            PasskeySignInResult replay = fixture.Ceremony.CompleteAssertion(response);
            return new SignInOutcome(authenticator, request, result, stored, replay);
        })
        .TheTest
        .ShouldPass<SignInOutcome>((because, outcome) =>
        {
            because.ItsTrue("request lists the person's credential", outcome.Request.AllowCredentials.Count == 1 && outcome.Request.AllowCredentials[0].Id == outcome.Authenticator.CredentialIdBase64Url);
            because.ItsTrue("request carries a ceremony id and the rp id", !string.IsNullOrEmpty(outcome.Request.CeremonyId) && outcome.Request.RpId == "lumberjack.live");
            because.ItsTrue("sign-in succeeds", outcome.Result.Success, outcome.Result.Message);
            because.ItsTrue("result names the person and credential", outcome.Result.PersonHandle == PasskeyFixture.Handle && outcome.Result.CredentialId == outcome.Authenticator.CredentialIdBase64Url);
            because.ItsTrue("result reports user verification", outcome.Result.UserVerified);
            because.ItsTrue("result carries the fingerprint", outcome.Result.KeyFingerprint == PublicKeyFingerprint.Of(outcome.Authenticator.PublicKeyPem));
            because.ItsTrue("sign count is recorded", outcome.Stored.SignCount == 7);
            because.ItsTrue("last use is recorded", outcome.Stored.LastUsedUtc is not null);
            because.ItsTrue("replaying the response fails", !outcome.Replay.Success && outcome.Replay.Failure == PasskeyVerificationFailure.NoPendingChallenge);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void SignInDiscoverablyAndFailGenerically()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture()))
        .When<PasskeyFixture>("runs discoverable sign-in and each failing assertion", (fixture, reg) =>
        {
            SyntheticAuthenticator authenticator = new SyntheticAuthenticator();
            fixture.Register(authenticator);
            string userHandle = fixture.Credentials.FindByCredentialId(authenticator.CredentialIdBase64Url)!.UserHandle;

            authenticator.SignCount = 2;
            PasskeyRequestOptions discoverable = fixture.Ceremony.BeginAssertion(null);
            PasskeySignInResult discovered = fixture.Ceremony.CompleteAssertion(authenticator.Assert(Base64UrlEncoder.Default.Decode(discoverable.Challenge), discoverable.CeremonyId, userHandle));

            PasskeySignInResult nullResponse = fixture.Ceremony.CompleteAssertion(null);
            PasskeySignInResult unknownCeremony = fixture.Ceremony.CompleteAssertion(authenticator.Assert(SyntheticAuthenticator.RandomBytes(32), "bm90LWEtY2VyZW1vbnk"));

            SyntheticAuthenticator stranger = new SyntheticAuthenticator();
            PasskeySignInResult unknownCredential = fixture.SignIn(stranger);

            authenticator.SignCount = 2;
            PasskeySignInResult regressed = fixture.SignIn(authenticator);
            PasskeyCredentialData stored = fixture.Credentials.FindByCredentialId(authenticator.CredentialIdBase64Url)!;
            bool flagged = stored.SignCountRegressed;

            authenticator.SignCount = 3;
            PasskeyRequestOptions request = fixture.Ceremony.BeginAssertion(PasskeyFixture.Handle);
            PasskeyAssertionResponse good = authenticator.Assert(Base64UrlEncoder.Default.Decode(request.Challenge), request.CeremonyId);
            byte[] signature = Base64UrlEncoder.Default.Decode(good.Response.Signature);
            signature[^1] ^= 0x01;
            PasskeySignInResult tampered = fixture.Ceremony.CompleteAssertion(good with { Response = good.Response with { Signature = Base64UrlEncoder.Default.Encode(signature) } } );
            long signCountAfterTamper = fixture.Credentials.FindByCredentialId(authenticator.CredentialIdBase64Url)!.SignCount;

            return new AssertionFailureOutcome(discoverable, discovered, nullResponse, unknownCeremony, unknownCredential, regressed, flagged, tampered, signCountAfterTamper);
        })
        .TheTest
        .ShouldPass<AssertionFailureOutcome>((because, outcome) =>
        {
            because.ItsTrue("discoverable request lists no credentials", outcome.Discoverable.AllowCredentials.Count == 0);
            because.ItsTrue("discoverable sign-in succeeds and names the person", outcome.Discovered.Success && outcome.Discovered.PersonHandle == PasskeyFixture.Handle);
            because.ItsTrue("null response fails without a pending challenge", outcome.NullResponse.Failure == PasskeyVerificationFailure.NoPendingChallenge);
            because.ItsTrue("unknown ceremony id fails", outcome.UnknownCeremony.Failure == PasskeyVerificationFailure.NoPendingChallenge);
            because.ItsTrue("unregistered credential fails", outcome.UnknownCredential.Failure == PasskeyVerificationFailure.UnknownCredential);
            because.ItsTrue("sign count regression fails", outcome.Regressed.Failure == PasskeyVerificationFailure.SignCountRegressed);
            because.ItsTrue("sign count regression is flagged on the credential", outcome.Flagged);
            because.ItsTrue("tampered signature fails with the generic message", outcome.Tampered.Failure == PasskeyVerificationFailure.InvalidSignature && outcome.Tampered.Message == PasskeyCeremony.VerificationFailedMessage);
            because.ItsTrue("tampered assertion does not advance the sign count", outcome.SignCountAfterTamper == 2);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void BuildRequestOptionsFromAConfirmationChallenge()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture()))
        .When<PasskeyFixture>("maps a confirmation challenge to request options", (fixture, reg) =>
        {
            SyntheticAuthenticator authenticator = new SyntheticAuthenticator();
            fixture.Register(authenticator);
            ConfirmationChallenge challenge = new ConfirmationChallenge { PersonHandle = PasskeyFixture.Handle, ChallengeBytes = SyntheticAuthenticator.RandomBytes(32), ExpiresUtc = DateTime.UtcNow.AddMinutes(5) };
            PasskeyRequestOptions request = fixture.Ceremony.ToRequestOptions(challenge);
            return new RequestOutcome(challenge, request, authenticator);
        })
        .TheTest
        .ShouldPass<RequestOutcome>((because, outcome) =>
        {
            because.ItsTrue("challenge bytes are carried verbatim", outcome.Request.Challenge == Base64UrlEncoder.Default.Encode(outcome.Challenge.ChallengeBytes));
            because.ItsTrue("the person's credentials are allowed", outcome.Request.AllowCredentials.Count == 1 && outcome.Request.AllowCredentials[0].Id == outcome.Authenticator.CredentialIdBase64Url);
            because.ItsTrue("no ceremony id is issued", outcome.Request.CeremonyId is null);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private sealed record CreationOutcome(PasskeyCreationOptions Options, string Json);
    private sealed record RegistrationOutcome(PasskeyFixture Fixture, SyntheticAuthenticator Authenticator, PasskeyCreationOptions Creation, PasskeyRegistrationResult Result, PasskeyCredentialData? Stored, PasskeyRegistrationResult Again);
    private sealed record SecondOutcome(PasskeyFixture Fixture, SyntheticAuthenticator First, PasskeyRegistrationResult FirstResult, PasskeyCreationOptions Creation, PasskeyRegistrationResult SecondResult);
    private sealed record FailureOutcome(PasskeyRegistrationResult NoPending, PasskeyRegistrationResult WrongChallenge, PasskeyRegistrationResult Consumed, PasskeyRegistrationResult Expired,
        PasskeyRegistrationResult Conflict, PasskeyCredentialData? StoredDespiteConflict, PasskeyRegistrationResult Duplicate, PasskeyRegistrationResult MaterialConflict, bool OtherStored, PasskeyRegistrationResult Invalid);
    private sealed record SignInOutcome(SyntheticAuthenticator Authenticator, PasskeyRequestOptions Request, PasskeySignInResult Result, PasskeyCredentialData Stored, PasskeySignInResult Replay);
    private sealed record AssertionFailureOutcome(PasskeyRequestOptions Discoverable, PasskeySignInResult Discovered, PasskeySignInResult NullResponse, PasskeySignInResult UnknownCeremony,
        PasskeySignInResult UnknownCredential, PasskeySignInResult Regressed, bool Flagged, PasskeySignInResult Tampered, long SignCountAfterTamper);
    private sealed record RequestOutcome(ConfirmationChallenge Challenge, PasskeyRequestOptions Request, SyntheticAuthenticator Authenticator);
}
