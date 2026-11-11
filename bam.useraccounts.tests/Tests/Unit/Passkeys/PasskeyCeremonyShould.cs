using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Profile;
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
    public void AddASecondPasskeyOnlyThroughTheAuthenticatedPath()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture()))
        .When<PasskeyFixture>("registers a second passkey for the same person", (fixture, reg) =>
        {
            SyntheticAuthenticator first = new SyntheticAuthenticator();
            SyntheticAuthenticator intruder = new SyntheticAuthenticator();
            SyntheticAuthenticator second = new SyntheticAuthenticator(Bam.Encryption.Cose.CoseAlgorithm.RS256);
            PasskeyRegistrationResult firstResult = fixture.Register(first);
            string userHandle = fixture.Credentials.FindByCredentialId(first.CredentialIdBase64Url)!.UserHandle;

            // Anonymous sign-up against the existing handle: options reveal nothing, completion refuses.
            PasskeyCreationOptions signUpAgain = fixture.Ceremony.BeginRegistration(PasskeyFixture.Handle, "Jane Doe");
            PasskeyRegistrationResult intrusion = fixture.Ceremony.CompleteRegistration(PasskeyFixture.Handle, intruder.Register(Base64UrlEncoder.Default.Decode(signUpAgain.Challenge)));
            bool intruderStored = fixture.Credentials.FindByCredentialId(intruder.CredentialIdBase64Url) is not null;
            int registrarCallsAfterIntrusion = fixture.Registered.Count;

            // The authenticated path adds the passkey.
            PasskeyCreationOptions creation = fixture.Ceremony.BeginAdditionalRegistration(PasskeyFixture.Handle, "Jane Doe");
            PasskeyRegistrationResult secondResult = fixture.Ceremony.CompleteAdditionalRegistration(PasskeyFixture.Handle, second.Register(Base64UrlEncoder.Default.Decode(creation.Challenge)));
            return new SecondOutcome(fixture, first, firstResult, userHandle, signUpAgain, intrusion, intruderStored, registrarCallsAfterIntrusion, creation, secondResult);
        })
        .TheTest
        .ShouldPass<SecondOutcome>((because, outcome) =>
        {
            because.ItsTrue("first registration succeeds", outcome.FirstResult.Success, outcome.FirstResult.Message);
            because.ItsTrue("sign-up options for an existing handle exclude nothing", outcome.SignUpAgain.ExcludeCredentials.Count == 0);
            because.ItsTrue("sign-up options for an existing handle do not reveal its user handle", outcome.SignUpAgain.User.Id != outcome.UserHandle);
            because.ItsTrue("sign-up against an existing handle is refused", !outcome.Intrusion.Success && outcome.Intrusion.Failure == PasskeyVerificationFailure.HandleAlreadyRegistered);
            because.ItsTrue("refusal uses the generic message", outcome.Intrusion.Message == PasskeyCeremony.VerificationFailedMessage);
            because.ItsTrue("nothing is stored for the intruder", !outcome.IntruderStored);
            because.ItsTrue("registrar is not consulted for the intruder", outcome.RegistrarCallsAfterIntrusion == 1);
            because.ItsTrue("additional registration succeeds", outcome.SecondResult.Success, outcome.SecondResult.Message);
            because.ItsTrue("additional creation reuses the user handle", outcome.Creation.User.Id == outcome.UserHandle);
            because.ItsTrue("additional creation excludes the first credential", outcome.Creation.ExcludeCredentials.Count == 1 && outcome.Creation.ExcludeCredentials[0].Id == outcome.First.CredentialIdBase64Url);
            because.ItsTrue("second passkey is not the key set", !outcome.SecondResult.KeySetRegistered);
            because.ItsTrue("registrar was called once in all", outcome.Fixture.Registered.Count == 1);
            because.ItsTrue("person has two credentials sharing a user handle", outcome.Fixture.Credentials.FindByHandle(PasskeyFixture.Handle).Select(credential => credential.UserHandle).Distinct().Count() == 1
                && outcome.Fixture.Credentials.FindByHandle(PasskeyFixture.Handle).Count == 2);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void BindAHandleScopedAssertionToItsHandle()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture()))
        .When<PasskeyFixture>("completes a handle-scoped ceremony with another person's credential", (fixture, reg) =>
        {
            SyntheticAuthenticator alice = new SyntheticAuthenticator();
            SyntheticAuthenticator bob = new SyntheticAuthenticator();
            fixture.Register(alice);
            fixture.Register(bob, "other-person");
            bob.SignCount = 5;

            PasskeyRequestOptions scoped = fixture.Ceremony.BeginAssertion(PasskeyFixture.Handle);
            PasskeySignInResult crossed = fixture.Ceremony.CompleteAssertion(bob.Assert(Base64UrlEncoder.Default.Decode(scoped.Challenge), scoped.CeremonyId));
            bool scopedRowConsumed = fixture.Challenges.Take("passkey-assertion-handle:" + scoped.CeremonyId) is null;

            PasskeyRequestOptions discoverable = fixture.Ceremony.BeginAssertion(null);
            PasskeySignInResult discovered = fixture.Ceremony.CompleteAssertion(bob.Assert(Base64UrlEncoder.Default.Decode(discoverable.Challenge), discoverable.CeremonyId));

            bool discoverableRowConsumed = fixture.Challenges.Take("passkey-assertion-handle:" + discoverable.CeremonyId) is null;

            bob.SignCount = 6;
            PasskeyRequestOptions own = fixture.Ceremony.BeginAssertion("other-person");
            PasskeySignInResult ownResult = fixture.Ceremony.CompleteAssertion(bob.Assert(Base64UrlEncoder.Default.Decode(own.Challenge), own.CeremonyId));

            bob.SignCount = 7;
            PasskeyRequestOptions orphaned = fixture.Ceremony.BeginAssertion("other-person");
            fixture.Challenges.Take("passkey-assertion-handle:" + orphaned.CeremonyId);
            PasskeySignInResult orphanedResult = fixture.Ceremony.CompleteAssertion(bob.Assert(Base64UrlEncoder.Default.Decode(orphaned.Challenge), orphaned.CeremonyId));
            bool orphanedChallengeConsumed = fixture.Challenges.Take("passkey-assertion:" + orphaned.CeremonyId) is null;
            return new BindingOutcome(crossed, scopedRowConsumed, discovered, discoverableRowConsumed, ownResult, orphanedResult, orphanedChallengeConsumed);
        })
        .TheTest
        .ShouldPass<BindingOutcome>((because, outcome) =>
        {
            because.ItsTrue("another person's credential is refused as unknown", !outcome.Crossed.Success && outcome.Crossed.Failure == PasskeyVerificationFailure.UnknownCredential);
            because.ItsTrue("the handle binding row is consumed with the challenge", outcome.ScopedRowConsumed);
            because.ItsTrue("discoverable sign-in stays unbound and names the person", outcome.Discovered.Success && outcome.Discovered.PersonHandle == "other-person");
            because.ItsTrue("a discoverable ceremony writes and consumes its binding row", outcome.DiscoverableRowConsumed);
            because.ItsTrue("a ceremony begun for the person's own handle succeeds", outcome.OwnResult.Success, outcome.OwnResult.Message);
            because.ItsTrue("a ceremony whose binding row is gone fails closed as no pending challenge", !outcome.Orphaned.Success && outcome.Orphaned.Failure == PasskeyVerificationFailure.NoPendingChallenge);
            because.ItsTrue("the orphaned ceremony's challenge is consumed", outcome.OrphanedChallengeConsumed);
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
            bool storedDespiteConflict = fixture.Credentials.FindByCredentialId(authenticator.CredentialIdBase64Url) is not null;
            PasskeyRegistrationResult deviceKeyPersonAddsPasskey = fixture.RegisterAdditional(authenticator);
            PasskeyCredentialData? storedBesideKeySet = fixture.Credentials.FindByCredentialId(authenticator.CredentialIdBase64Url);

            fixture.RegistrarThrows = null;
            PasskeyRegistrationResult duplicate = fixture.RegisterAdditional(authenticator);

            SyntheticAuthenticator other = new SyntheticAuthenticator();
            fixture.RegistrarThrows = new PublicKeySetKeyMaterialConflictException("other-person", PasskeyFixture.Handle);
            PasskeyRegistrationResult materialConflict = fixture.Register(other, "other-person");
            bool otherStored = fixture.Credentials.FindByCredentialId(other.CredentialIdBase64Url) is not null;

            SyntheticAuthenticator third = new SyntheticAuthenticator();
            fixture.RegistrarThrows = new InvalidPublicKeySetException("third-person", "bad key", null);
            PasskeyRegistrationResult invalid = fixture.Register(third, "third-person");
            bool thirdStored = fixture.Credentials.FindByCredentialId(third.CredentialIdBase64Url) is not null;
            fixture.RegistrarThrows = null;

            return new FailureOutcome(noPending, wrongChallenge, consumed, expired, conflict, storedDespiteConflict, deviceKeyPersonAddsPasskey, storedBesideKeySet, duplicate, materialConflict, otherStored, invalid, thirdStored);
        })
        .TheTest
        .ShouldPass<FailureOutcome>((because, outcome) =>
        {
            because.ItsTrue("no pending challenge fails", !outcome.NoPending.Success && outcome.NoPending.Failure == PasskeyVerificationFailure.NoPendingChallenge);
            because.ItsTrue("wrong challenge fails as a mismatch with the generic message", outcome.WrongChallenge.Failure == PasskeyVerificationFailure.ChallengeMismatch && outcome.WrongChallenge.Message == PasskeyCeremony.VerificationFailedMessage);
            because.ItsTrue("a failed attempt consumes the challenge", outcome.Consumed.Failure == PasskeyVerificationFailure.NoPendingChallenge);
            because.ItsTrue("expired challenge fails", outcome.Expired.Failure == PasskeyVerificationFailure.ChallengeExpired);
            because.ItsTrue("sign-up for a handle that already has a key set is refused", !outcome.Conflict.Success && outcome.Conflict.Failure == PasskeyVerificationFailure.HandleAlreadyRegistered);
            because.ItsTrue("nothing is stored on a key-set conflict", !outcome.StoredDespiteConflict);
            because.ItsTrue("an authenticated device-key person adds a passkey beside the key set", outcome.DeviceKeyPersonAddsPasskey.Success && !outcome.DeviceKeyPersonAddsPasskey.KeySetRegistered);
            because.ItsTrue("that passkey is stored without the key-set mark", outcome.StoredBesideKeySet is not null && !outcome.StoredBesideKeySet.IsRegisteredKeySet);
            because.ItsTrue("re-registering the same credential id fails", outcome.Duplicate.Failure == PasskeyVerificationFailure.CredentialAlreadyRegistered);
            because.ItsTrue("key material registered to someone else fails", outcome.MaterialConflict.Failure == PasskeyVerificationFailure.CredentialAlreadyRegistered);
            because.ItsTrue("nothing is stored when the registrar rejects the material", !outcome.OtherStored);
            because.ItsTrue("registrar rejecting the key fails as an invalid key", outcome.Invalid.Failure == PasskeyVerificationFailure.InvalidCredentialKey);
            because.ItsTrue("nothing is stored when the registrar rejects the key", !outcome.ThirdStored);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RemoveTheSavedCredentialWhateverTheRegistrarDoes()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture()))
        .When<PasskeyFixture>("meets every registrar outcome after saving the credential", (fixture, reg) =>
        {
            SyntheticAuthenticator successorKey = new SyntheticAuthenticator();
            fixture.RegistrarThrows = new UnauthorizedSuccessorException(PasskeyFixture.Handle);
            PasskeyRegistrationResult successor = fixture.Register(successorKey);
            bool successorStored = fixture.Credentials.FindByCredentialId(successorKey.CredentialIdBase64Url) is not null;

            SyntheticAuthenticator faultKey = new SyntheticAuthenticator();
            fixture.RegistrarThrows = new InvalidOperationException("store offline");
            Exception? fault = null;
            try
            {
                fixture.Register(faultKey);
            }
            catch (Exception e)
            {
                fault = e;
            }
            bool faultStored = fixture.Credentials.FindByCredentialId(faultKey.CredentialIdBase64Url) is not null;
            int registrarCallsAfterFault = fixture.Registered.Count;
            fixture.RegistrarThrows = null;

            FaultingPasskeyCredentialRepository faulting = new FaultingPasskeyCredentialRepository(new InMemoryPasskeyCredentialRepository());
            PasskeyFixture faultingFixture = new PasskeyFixture(credentials: faulting);
            faulting.SaveThrows = new InvalidOperationException("save failed");
            Exception? saveFault = null;
            try
            {
                faultingFixture.Register(new SyntheticAuthenticator());
            }
            catch (Exception e)
            {
                saveFault = e;
            }
            int registrarCallsAfterSaveFault = faultingFixture.Registered.Count;

            PasskeyRegistrationResult afterFaults = fixture.Register(new SyntheticAuthenticator());
            return new RegistrarOutcome(successor, successorStored, fault, faultStored, registrarCallsAfterFault, saveFault, registrarCallsAfterSaveFault, afterFaults);
        })
        .TheTest
        .ShouldPass<RegistrarOutcome>((because, outcome) =>
        {
            because.ItsTrue("an unauthorized successor is refused as a handle that is not claimable", !outcome.Successor.Success && outcome.Successor.Failure == PasskeyVerificationFailure.HandleAlreadyRegistered);
            because.ItsTrue("nothing is stored after the successor refusal", !outcome.SuccessorStored);
            because.ItsTrue("a registrar fault propagates", outcome.Fault is InvalidOperationException);
            because.ItsTrue("nothing is stored after the registrar fault", !outcome.FaultStored);
            because.ItsTrue("the registrar was called for the fault", outcome.RegistrarCallsAfterFault == 2);
            because.ItsTrue("a custody fault before the registrar propagates", outcome.SaveFault is InvalidOperationException);
            because.ItsTrue("the registrar is never called when the credential could not be saved", outcome.RegistrarCallsAfterSaveFault == 0);
            because.ItsTrue("the handle is still claimable after the faults", outcome.AfterFaults.Success && outcome.AfterFaults.KeySetRegistered, outcome.AfterFaults.Message);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void KeepAdditionalRegistrationChallengesApartFromSignUp()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture()))
        .When<PasskeyFixture>("sees an anonymous sign-up attempt during an authenticated add-a-passkey ceremony", (fixture, reg) =>
        {
            SyntheticAuthenticator first = new SyntheticAuthenticator();
            fixture.Register(first);

            SyntheticAuthenticator second = new SyntheticAuthenticator();
            PasskeyCreationOptions adding = fixture.Ceremony.BeginAdditionalRegistration(PasskeyFixture.Handle, "Jane Doe");
            SyntheticAuthenticator intruder = new SyntheticAuthenticator();
            PasskeyCreationOptions intruding = fixture.Ceremony.BeginRegistration(PasskeyFixture.Handle, "Mallory");
            PasskeyRegistrationResult added = fixture.Ceremony.CompleteAdditionalRegistration(PasskeyFixture.Handle, second.Register(Base64UrlEncoder.Default.Decode(adding.Challenge)));
            PasskeyRegistrationResult intrusion = fixture.Ceremony.CompleteRegistration(PasskeyFixture.Handle, intruder.Register(Base64UrlEncoder.Default.Decode(intruding.Challenge)));
            return new ApartOutcome(added, intrusion, fixture.Credentials.FindByHandle(PasskeyFixture.Handle).Count);
        })
        .TheTest
        .ShouldPass<ApartOutcome>((because, outcome) =>
        {
            because.ItsTrue("the authenticated ceremony completes despite the sign-up attempt", outcome.Added.Success && !outcome.Added.KeySetRegistered, outcome.Added.Message);
            because.ItsTrue("the sign-up attempt is still refused", !outcome.Intrusion.Success && outcome.Intrusion.Failure == PasskeyVerificationFailure.HandleAlreadyRegistered);
            because.ItsTrue("the person has exactly two credentials", outcome.CredentialCount == 2);
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

    [UnitTest]
    public void KeepACredentialUnusableUntilTheRegistrarAccepts()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture()))
        .When<PasskeyFixture>("signs in with the in-flight credential from inside the registrar", (fixture, reg) =>
        {
            SyntheticAuthenticator inFlight = new SyntheticAuthenticator();
            List<PasskeySignInResult> during = new List<PasskeySignInResult>();
            List<int> allowedDuring = new List<int>();
            List<bool> pendingDuring = new List<bool>();
            fixture.DuringRegister = keySet =>
            {
                // The registrar has been asked and has not answered: the saved row must be inert.
                inFlight.SignCount = 2;
                during.Add(fixture.SignIn(inFlight, null));
                during.Add(fixture.SignIn(inFlight, keySet.KeySetHandle));
                allowedDuring.Add(fixture.Ceremony.BeginAssertion(keySet.KeySetHandle).AllowCredentials.Count);
                pendingDuring.Add(fixture.Credentials.FindByCredentialId(inFlight.CredentialIdBase64Url)?.Pending ?? false);
            };

            fixture.RegistrarThrows = new PublicKeySetConflictException("alice-device-key");
            PasskeyRegistrationResult conflict = fixture.Register(inFlight, "alice-device-key");
            bool conflictStored = fixture.Credentials.FindByCredentialId(inFlight.CredentialIdBase64Url) is not null;

            inFlight = new SyntheticAuthenticator();
            fixture.RegistrarThrows = new UnauthorizedSuccessorException("revoked-person");
            PasskeyRegistrationResult successor = fixture.Register(inFlight, "revoked-person");
            bool successorStored = fixture.Credentials.FindByCredentialId(inFlight.CredentialIdBase64Url) is not null;

            inFlight = new SyntheticAuthenticator();
            fixture.RegistrarThrows = new InvalidOperationException("store offline");
            Exception? fault = null;
            try
            {
                fixture.Register(inFlight, "faulting-person");
            }
            catch (Exception e)
            {
                fault = e;
            }
            bool faultStored = fixture.Credentials.FindByCredentialId(inFlight.CredentialIdBase64Url) is not null;

            inFlight = new SyntheticAuthenticator();
            fixture.RegistrarThrows = null;
            PasskeyRegistrationResult accepted = fixture.Register(inFlight);
            fixture.DuringRegister = null;
            PasskeyCredentialData? acceptedRow = fixture.Credentials.FindByCredentialId(inFlight.CredentialIdBase64Url);
            inFlight.SignCount = 3;
            PasskeySignInResult afterAccepted = fixture.SignIn(inFlight);
            return new PendingOutcome(during, allowedDuring, pendingDuring, conflict, conflictStored, successor, successorStored, fault, faultStored, accepted, acceptedRow, afterAccepted);
        })
        .TheTest
        .ShouldPass<PendingOutcome>((because, outcome) =>
        {
            because.ItsTrue("the registrar was reached four times, with two sign-in attempts each", outcome.During.Count == 8 && outcome.PendingDuring.Count == 4);
            because.ItsTrue("the saved row is pending while the registrar decides", outcome.PendingDuring.All(pending => pending));
            because.ItsTrue("no discoverable or handle-scoped sign-in succeeds with a pending credential", outcome.During.All(result => !result.Success && result.PersonHandle is null));
            because.ItsTrue("a pending credential is an unknown credential", outcome.During.All(result => result.Failure == PasskeyVerificationFailure.UnknownCredential));
            because.ItsTrue("a pending credential is not offered in allowCredentials", outcome.AllowedDuring.All(count => count == 0));
            because.ItsTrue("the conflict is refused and nothing stays stored", !outcome.Conflict.Success && outcome.Conflict.Failure == PasskeyVerificationFailure.HandleAlreadyRegistered && !outcome.ConflictStored);
            because.ItsTrue("the successor refusal leaves nothing stored", !outcome.Successor.Success && !outcome.SuccessorStored);
            because.ItsTrue("the fault propagates and leaves nothing stored", outcome.Fault is InvalidOperationException && !outcome.FaultStored);
            because.ItsTrue("an accepted registration activates the credential", outcome.Accepted.Success && outcome.Accepted.KeySetRegistered && outcome.AcceptedRow is not null && !outcome.AcceptedRow.Pending);
            because.ItsTrue("the accepted credential signs in", outcome.AfterAccepted.Success && outcome.AfterAccepted.PersonHandle == PasskeyFixture.Handle);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ReapAPendingCredentialLeftBehind()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture()))
        .When<PasskeyFixture>("meets pending rows left by a stopped process and by a sign-up in flight", (fixture, reg) =>
        {
            DateTime now = DateTime.UtcNow;
            fixture.Credentials.Save(PendingRow(PasskeyFixture.Handle, "stale-cred", now.Subtract(PasskeyCeremony.PendingCredentialGrace).AddMinutes(-1)));
            PasskeyRegistrationResult afterStale = fixture.Register(new SyntheticAuthenticator());
            bool staleRemains = fixture.Credentials.FindByCredentialId("stale-cred") is not null;

            fixture.Credentials.Save(PendingRow("busy-handle", "fresh-cred", now));
            PasskeyRegistrationResult whileInFlight = fixture.Register(new SyntheticAuthenticator(), "busy-handle");
            bool freshRemains = fixture.Credentials.FindByCredentialId("fresh-cred") is not null;
            SyntheticAuthenticator owner = new SyntheticAuthenticator();
            PasskeyRegistrationResult ownerAdds = fixture.RegisterAdditional(owner, "busy-handle");
            PasskeyCredentialData? ownerRow = fixture.Credentials.FindByCredentialId(owner.CredentialIdBase64Url);

            FaultingPasskeyCredentialRepository faulting = new FaultingPasskeyCredentialRepository(new InMemoryPasskeyCredentialRepository());
            PasskeyFixture faultingFixture = new PasskeyFixture(credentials: faulting);
            SyntheticAuthenticator doubleFault = new SyntheticAuthenticator();
            faultingFixture.RegistrarThrows = new InvalidOperationException("registrar down");
            faulting.RemoveThrows = new InvalidOperationException("store down");
            Exception? reported = null;
            try
            {
                faultingFixture.Register(doubleFault);
            }
            catch (Exception e)
            {
                reported = e;
            }
            faulting.RemoveThrows = null;
            faultingFixture.RegistrarThrows = null;
            PasskeyCredentialData? survivor = faulting.FindByCredentialId(doubleFault.CredentialIdBase64Url);
            doubleFault.SignCount = 2;
            PasskeySignInResult survivorSignIn = faultingFixture.SignIn(doubleFault);
            return new ReapOutcome(afterStale, staleRemains, whileInFlight, freshRemains, ownerAdds, ownerRow, reported, survivor, survivorSignIn);
        })
        .TheTest
        .ShouldPass<ReapOutcome>((because, outcome) =>
        {
            because.ItsTrue("a stale pending row does not hold its handle", outcome.AfterStale.Success && outcome.AfterStale.KeySetRegistered);
            because.ItsTrue("and is removed", !outcome.StaleRemains);
            because.ItsTrue("a fresh pending row refuses a second sign-up for the handle", !outcome.WhileInFlight.Success && outcome.WhileInFlight.Failure == PasskeyVerificationFailure.HandleAlreadyRegistered);
            because.ItsTrue("and is left alone", outcome.FreshRemains);
            because.ItsTrue("the authenticated path ignores someone else's pending row", outcome.OwnerAdds.Success && outcome.OwnerAdds.KeySetRegistered);
            because.ItsTrue("and never adopts its user handle", outcome.OwnerRow is not null && outcome.OwnerRow.UserHandle != "uh-in-flight" && !outcome.OwnerRow.Pending);
            because.ItsTrue("when the cleanup faults too, the registrar's fault is the one reported", outcome.Reported is InvalidOperationException && outcome.Reported.Message == "registrar down");
            because.ItsTrue("the row that could not be removed is still pending", outcome.Survivor is not null && outcome.Survivor.Pending);
            because.ItsTrue("so it cannot sign in", !outcome.SurvivorSignIn.Success && outcome.SurvivorSignIn.Failure == PasskeyVerificationFailure.UnknownCredential);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void FailClosedOnAnUnreadableHandleBinding()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture()))
        .When<PasskeyFixture>("completes assertions whose binding row was replaced", (fixture, reg) =>
        {
            SyntheticAuthenticator authenticator = new SyntheticAuthenticator();
            fixture.Register(authenticator);
            List<PasskeySignInResult> results = new List<PasskeySignInResult>();
            foreach (byte[] replacement in new byte[][] { Array.Empty<byte>(), new byte[] { 0x02, 0x41 }, new byte[] { 0x00, 0x41 }, new byte[] { 0x01 }, SyntheticAuthenticator.RandomBytes(32) })
            {
                PasskeyRequestOptions request = fixture.Ceremony.BeginAssertion(PasskeyFixture.Handle);
                ConfirmationChallenge? binding = fixture.Challenges.Take("passkey-assertion-handle:" + request.CeremonyId);
                fixture.Challenges.Save(new ConfirmationChallenge { PersonHandle = "passkey-assertion-handle:" + request.CeremonyId, ChallengeBytes = replacement, ExpiresUtc = binding!.ExpiresUtc });
                authenticator.SignCount++;
                results.Add(fixture.Ceremony.CompleteAssertion(authenticator.Assert(Base64UrlEncoder.Default.Decode(request.Challenge), request.CeremonyId)));
            }
            authenticator.SignCount++;
            PasskeySignInResult intact = fixture.SignIn(authenticator);
            PasskeySignInResult discoverable = fixture.SignIn(Bump(authenticator), null);
            return new UnreadableBindingOutcome(results, intact, discoverable);
        })
        .TheTest
        .ShouldPass<UnreadableBindingOutcome>((because, outcome) =>
        {
            because.ItsTrue("an empty, unknown-marker, over-long, truncated or random binding row never signs in", outcome.Replaced.All(result => !result.Success));
            because.ItsTrue("the first four are a lost binding", outcome.Replaced.Take(4).All(result => result.Failure == PasskeyVerificationFailure.NoPendingChallenge));
            because.ItsTrue("an intact handle-scoped ceremony signs in", outcome.Intact.Success);
            because.ItsTrue("an intact discoverable ceremony signs in", outcome.Discoverable.Success);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseACredentialIdSavedByAConcurrentRegistration()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture(credentials: new FaultingPasskeyCredentialRepository(new InMemoryPasskeyCredentialRepository()))))
        .When<PasskeyFixture>("races a second sign-up with the same credential id past the id check", (fixture, reg) =>
        {
            FaultingPasskeyCredentialRepository custody = (FaultingPasskeyCredentialRepository)fixture.Credentials;
            SyntheticAuthenticator shared = new SyntheticAuthenticator();
            PasskeyRegistrationResult? racing = null;
            List<PasskeySignInResult> during = new List<PasskeySignInResult>();
            string? ownerDuring = null;
            bool pendingDuring = false;
            fixture.DuringRegister = keySet =>
            {
                if (keySet.KeySetHandle != "alice-device-key")
                {
                    return;
                }
                // The victim handle's row is saved and its registrar call is in flight.  A second
                // sign-up for another handle presents the same credential id, having read custody
                // before that row existed, and its own registrar call would be accepted.
                Exception? victimAnswer = fixture.RegistrarThrows;
                fixture.RegistrarThrows = null;
                custody.StaleReadOf = shared.CredentialIdBase64Url;
                racing = fixture.Register(shared, "mallory");
                fixture.RegistrarThrows = victimAnswer;
                shared.SignCount = 2;
                during.Add(fixture.SignIn(shared, null));
                during.Add(fixture.SignIn(shared, "alice-device-key"));
                during.Add(fixture.SignIn(shared, "mallory"));
                PasskeyCredentialData? row = custody.FindByCredentialId(shared.CredentialIdBase64Url);
                ownerDuring = row?.PersonHandle;
                pendingDuring = row?.Pending ?? false;
            };
            fixture.RegistrarThrows = new PublicKeySetConflictException("alice-device-key");
            PasskeyRegistrationResult victim = fixture.Register(shared, "alice-device-key");
            fixture.DuringRegister = null;
            return new ConcurrentIdOutcome(racing, during, ownerDuring, pendingDuring, victim,
                custody.FindByCredentialId(shared.CredentialIdBase64Url) is not null,
                custody.FindByHandle("alice-device-key").Count, custody.FindByHandle("mallory").Count, fixture.Registered.Count);
        })
        .TheTest
        .ShouldPass<ConcurrentIdOutcome>((because, outcome) =>
        {
            because.ItsTrue("the racing sign-up is refused as a credential that is already registered", outcome.Racing is not null && !outcome.Racing.Success && outcome.Racing.Failure == PasskeyVerificationFailure.CredentialAlreadyRegistered);
            because.ItsTrue("it never reaches the registrar", outcome.RegistrarCalls == 1);
            because.ItsTrue("the row in custody is still the first registration's, still pending", outcome.OwnerDuring == "alice-device-key" && outcome.PendingDuring);
            because.ItsTrue("no sign-in succeeds with the shared credential, as anyone", outcome.During.Count == 3 && outcome.During.All(result => !result.Success && result.PersonHandle is null));
            because.ItsTrue("the first registration gets the registrar's refusal", !outcome.Victim.Success && outcome.Victim.Failure == PasskeyVerificationFailure.HandleAlreadyRegistered);
            because.ItsTrue("nothing is left in custody under either handle", !outcome.RowRemains && outcome.VictimRows == 0 && outcome.RacerRows == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void NeverLoseTheCredentialOfAnAcceptedKeySet()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture(credentials: new FaultingPasskeyCredentialRepository(new InMemoryPasskeyCredentialRepository()))))
        .When<PasskeyFixture>("faults or loses the row after the registrar accepted the key", (fixture, reg) =>
        {
            FaultingPasskeyCredentialRepository custody = (FaultingPasskeyCredentialRepository)fixture.Credentials;
            SyntheticAuthenticator first = new SyntheticAuthenticator();
            custody.ActivateThrows = new InvalidOperationException("store hiccup");
            Exception? reported = null;
            try
            {
                fixture.Register(first);
            }
            catch (Exception e)
            {
                reported = e;
            }
            custody.ActivateThrows = null;
            PasskeyCredentialData? afterFault = custody.FindByCredentialId(first.CredentialIdBase64Url);
            bool pendingAfterFault = afterFault?.Pending ?? false;
            bool registrarHoldsHandle = fixture.Accepted.ContainsKey(PasskeyFixture.Handle);
            first.SignCount = 2;
            PasskeySignInResult whilePending = fixture.SignIn(first);

            PasskeyRegistrationResult retryWhileFresh = fixture.Register(new SyntheticAuthenticator());
            bool pendingAfterFreshRetry = custody.FindByCredentialId(first.CredentialIdBase64Url)?.Pending ?? false;

            afterFault!.CreatedUtc = DateTime.UtcNow.Subtract(PasskeyCeremony.PendingCredentialGrace).AddMinutes(-1);
            fixture.ResolveThrows = new InvalidOperationException("registrar offline");
            PasskeyRegistrationResult retryRegistrarOffline = fixture.Register(new SyntheticAuthenticator());
            PasskeyCredentialData? afterOffline = custody.FindByCredentialId(first.CredentialIdBase64Url);
            bool keptWhileOffline = afterOffline is not null && afterOffline.Pending;
            fixture.ResolveThrows = null;

            PasskeyRegistrationResult retryWhenStale = fixture.Register(new SyntheticAuthenticator());
            PasskeyCredentialData? settled = custody.FindByCredentialId(first.CredentialIdBase64Url);
            first.SignCount = 3;
            PasskeySignInResult afterSettling = fixture.SignIn(first);

            PasskeyFixture other = new PasskeyFixture();
            SyntheticAuthenticator reaped = new SyntheticAuthenticator();
            other.DuringRegister = keySet => other.Credentials.Remove(PasskeyFixture.Handle, reaped.CredentialIdBase64Url);
            PasskeyRegistrationResult acceptedAfterRowWasRemoved = other.Register(reaped);
            PasskeyCredentialData? savedAgain = other.Credentials.FindByCredentialId(reaped.CredentialIdBase64Url);
            reaped.SignCount = 2;
            PasskeySignInResult savedAgainSignIn = other.SignIn(reaped);

            return new AcceptedOutcome(reported, afterFault is not null, pendingAfterFault, registrarHoldsHandle, whilePending, retryWhileFresh, pendingAfterFreshRetry,
                retryRegistrarOffline, keptWhileOffline, retryWhenStale, settled, afterSettling, fixture.Registered.Count, acceptedAfterRowWasRemoved, savedAgain, savedAgainSignIn);
        })
        .TheTest
        .ShouldPass<AcceptedOutcome>((because, outcome) =>
        {
            because.ItsTrue("the activation fault is reported", outcome.Reported is InvalidOperationException && outcome.Reported.Message == "store hiccup");
            because.ItsTrue("the registrar holds the handle", outcome.RegistrarHoldsHandle);
            because.ItsTrue("so the row is kept, pending", outcome.RowKept && outcome.PendingAfterFault);
            because.ItsTrue("a pending row still cannot sign in", !outcome.WhilePending.Success);
            because.ItsTrue("a retry while the row is fresh is refused and changes nothing", !outcome.RetryWhileFresh.Success && outcome.RetryWhileFresh.Failure == PasskeyVerificationFailure.HandleAlreadyRegistered && outcome.PendingAfterFreshRetry);
            because.ItsTrue("a stale row is left alone when the registrar cannot be asked", !outcome.RetryRegistrarOffline.Success && outcome.KeptWhileOffline);
            because.ItsTrue("a stale row whose key the registrar holds is activated, not removed", outcome.Settled is not null && !outcome.Settled.Pending);
            because.ItsTrue("the retry that settled it is refused: the handle has its passkey", !outcome.RetryWhenStale.Success && outcome.RetryWhenStale.Failure == PasskeyVerificationFailure.HandleAlreadyRegistered);
            because.ItsTrue("no retry reached the registrar", outcome.RegistrarCalls == 1);
            because.ItsTrue("the person signs in with the passkey they created", outcome.AfterSettling.Success && outcome.AfterSettling.PersonHandle == PasskeyFixture.Handle);
            because.ItsTrue("a row removed while the registrar was answering is saved again on acceptance", outcome.AcceptedAfterRowWasRemoved.Success && outcome.AcceptedAfterRowWasRemoved.KeySetRegistered && outcome.SavedAgain is not null && !outcome.SavedAgain.Pending);
            because.ItsTrue("and signs in", outcome.SavedAgainSignIn.Success);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void KeepTheRowWhenTheRegistrarFaultsAfterStoringTheKeySet()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture()))
        .When<PasskeyFixture>("meets a registrar that stores the key set and then faults", (fixture, reg) =>
        {
            SyntheticAuthenticator committed = new SyntheticAuthenticator();
            fixture.RegistrarThrowsAfterStoring = new TimeoutException("registrar timed out after committing");
            Exception? reported = null;
            try
            {
                fixture.Register(committed);
            }
            catch (Exception e)
            {
                reported = e;
            }
            fixture.RegistrarThrowsAfterStoring = null;
            PasskeyCredentialData? kept = fixture.Credentials.FindByCredentialId(committed.CredentialIdBase64Url);
            bool keptPending = kept?.Pending ?? false;
            kept!.CreatedUtc = DateTime.UtcNow.Subtract(PasskeyCeremony.PendingCredentialGrace).AddMinutes(-1);
            PasskeyRegistrationResult retry = fixture.Register(new SyntheticAuthenticator());
            committed.SignCount = 2;
            PasskeySignInResult signIn = fixture.SignIn(committed);

            // The registrar cannot be asked after its fault: the row is left alone, not removed.
            SyntheticAuthenticator unknown = new SyntheticAuthenticator();
            fixture.RegistrarThrows = new InvalidOperationException("registrar offline");
            fixture.ResolveThrows = new InvalidOperationException("registrar offline");
            Exception? offline = null;
            try
            {
                fixture.Register(unknown, "offline-person");
            }
            catch (Exception e)
            {
                offline = e;
            }
            fixture.RegistrarThrows = null;
            fixture.ResolveThrows = null;
            PasskeyCredentialData? leftAlone = fixture.Credentials.FindByCredentialId(unknown.CredentialIdBase64Url);

            // A stale pending row that carries the registered key but was never marked as the key
            // set is not an accepted credential: it is removed, not activated.
            PasskeyCredentialData unmarked = PendingRow("unmarked-person", "unmarked-cred", DateTime.UtcNow.Subtract(PasskeyCeremony.PendingCredentialGrace).AddMinutes(-1));
            unmarked.IsRegisteredKeySet = false;
            fixture.Accepted["unmarked-person"] = new PublicKeySetData { KeySetHandle = "unmarked-person", PublicEccKey = unmarked.PublicKeyPem };
            fixture.Credentials.Save(unmarked);
            fixture.RegistrarThrows = new PublicKeySetConflictException("unmarked-person");
            fixture.Register(new SyntheticAuthenticator(), "unmarked-person");
            fixture.RegistrarThrows = null;
            bool unmarkedRemains = fixture.Credentials.FindByCredentialId("unmarked-cred") is not null;
            return new CommittedFaultOutcome(reported, kept is not null, keptPending, retry, fixture.Credentials.FindByCredentialId(committed.CredentialIdBase64Url), signIn,
                offline, leftAlone, unmarkedRemains);
        })
        .TheTest
        .ShouldPass<CommittedFaultOutcome>((because, outcome) =>
        {
            because.ItsTrue("the registrar's fault is reported", outcome.Reported is TimeoutException);
            because.ItsTrue("the row of the key set the registrar stored is kept, pending", outcome.RowKept && outcome.KeptPending);
            because.ItsTrue("a later registration for the handle activates it", outcome.Settled is not null && !outcome.Settled.Pending);
            because.ItsTrue("and is itself refused", !outcome.Retry.Success && outcome.Retry.Failure == PasskeyVerificationFailure.HandleAlreadyRegistered);
            because.ItsTrue("the person signs in with the passkey they created", outcome.SignIn.Success && outcome.SignIn.PersonHandle == PasskeyFixture.Handle);
            because.ItsTrue("when the registrar cannot be asked, its fault is still the one reported", outcome.Offline is InvalidOperationException && outcome.Offline.Message == "registrar offline");
            because.ItsTrue("and the row is left pending rather than removed", outcome.LeftAlone is not null && outcome.LeftAlone.Pending);
            because.ItsTrue("a stale pending row not marked as the key set is removed even when it carries the registered key", !outcome.UnmarkedRemains);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void FlagASignCountRegressionOnlyForTheKeyHolder()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture()))
        .When<PasskeyFixture>("sends a low counter signed by another key, then by the credential's key", (fixture, reg) =>
        {
            SyntheticAuthenticator owner = new SyntheticAuthenticator();
            fixture.Register(owner);
            owner.SignCount = 5;
            PasskeySignInResult first = fixture.SignIn(owner);

            SyntheticAuthenticator imposter = new SyntheticAuthenticator();
            imposter.CredentialId = owner.CredentialId;
            imposter.SignCount = 1;
            PasskeySignInResult forged = fixture.SignIn(imposter);
            PasskeyCredentialData? afterForgery = fixture.Credentials.FindByCredentialId(owner.CredentialIdBase64Url);
            bool flaggedByForgery = afterForgery?.SignCountRegressed ?? true;
            long countAfterForgery = afterForgery?.SignCount ?? -1;

            owner.SignCount = 5;
            PasskeySignInResult regressed = fixture.SignIn(owner);
            bool flaggedByOwner = fixture.Credentials.FindByCredentialId(owner.CredentialIdBase64Url)?.SignCountRegressed ?? false;
            return new CounterOutcome(first, forged, flaggedByForgery, countAfterForgery, regressed, flaggedByOwner);
        })
        .TheTest
        .ShouldPass<CounterOutcome>((because, outcome) =>
        {
            because.ItsTrue("the owner signs in and the counter is recorded", outcome.First.Success);
            because.ItsTrue("a low counter under another key is an invalid signature", !outcome.Forged.Success && outcome.Forged.Failure == PasskeyVerificationFailure.InvalidSignature);
            because.ItsTrue("and does not flag the credential or move its counter", !outcome.FlaggedByForgery && outcome.CountAfterForgery == 5);
            because.ItsTrue("a counter that does not advance under the credential's own key is a regression", !outcome.Regressed.Success && outcome.Regressed.Failure == PasskeyVerificationFailure.SignCountRegressed);
            because.ItsTrue("and flags the credential", outcome.FlaggedByOwner);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static SyntheticAuthenticator Bump(SyntheticAuthenticator authenticator)
    {
        authenticator.SignCount++;
        return authenticator;
    }

    private static PasskeyCredentialData PendingRow(string handle, string credentialId, DateTime createdUtc)
    {
        return new PasskeyCredentialData
        {
            PersonHandle = handle,
            CredentialId = credentialId,
            UserHandle = "uh-in-flight",
            PublicKeyPem = new SyntheticAuthenticator().PublicKeyPem,
            Algorithm = -7,
            CreatedUtc = createdUtc,
            IsRegisteredKeySet = true,
            Pending = true
        };
    }

    private sealed record PendingOutcome(List<PasskeySignInResult> During, List<int> AllowedDuring, List<bool> PendingDuring, PasskeyRegistrationResult Conflict, bool ConflictStored,
        PasskeyRegistrationResult Successor, bool SuccessorStored, Exception? Fault, bool FaultStored, PasskeyRegistrationResult Accepted, PasskeyCredentialData? AcceptedRow,
        PasskeySignInResult AfterAccepted);
    private sealed record ReapOutcome(PasskeyRegistrationResult AfterStale, bool StaleRemains, PasskeyRegistrationResult WhileInFlight, bool FreshRemains, PasskeyRegistrationResult OwnerAdds,
        PasskeyCredentialData? OwnerRow, Exception? Reported, PasskeyCredentialData? Survivor, PasskeySignInResult SurvivorSignIn);
    private sealed record UnreadableBindingOutcome(List<PasskeySignInResult> Replaced, PasskeySignInResult Intact, PasskeySignInResult Discoverable);
    private sealed record ConcurrentIdOutcome(PasskeyRegistrationResult? Racing, List<PasskeySignInResult> During, string? OwnerDuring, bool PendingDuring, PasskeyRegistrationResult Victim,
        bool RowRemains, int VictimRows, int RacerRows, int RegistrarCalls);
    private sealed record AcceptedOutcome(Exception? Reported, bool RowKept, bool PendingAfterFault, bool RegistrarHoldsHandle, PasskeySignInResult WhilePending,
        PasskeyRegistrationResult RetryWhileFresh, bool PendingAfterFreshRetry, PasskeyRegistrationResult RetryRegistrarOffline, bool KeptWhileOffline, PasskeyRegistrationResult RetryWhenStale,
        PasskeyCredentialData? Settled, PasskeySignInResult AfterSettling, int RegistrarCalls, PasskeyRegistrationResult AcceptedAfterRowWasRemoved, PasskeyCredentialData? SavedAgain,
        PasskeySignInResult SavedAgainSignIn);
    private sealed record CommittedFaultOutcome(Exception? Reported, bool RowKept, bool KeptPending, PasskeyRegistrationResult Retry, PasskeyCredentialData? Settled, PasskeySignInResult SignIn,
        Exception? Offline, PasskeyCredentialData? LeftAlone, bool UnmarkedRemains);
    private sealed record CounterOutcome(PasskeySignInResult First, PasskeySignInResult Forged, bool FlaggedByForgery, long CountAfterForgery, PasskeySignInResult Regressed, bool FlaggedByOwner);
    private sealed record CreationOutcome(PasskeyCreationOptions Options, string Json);
    private sealed record RegistrationOutcome(PasskeyFixture Fixture, SyntheticAuthenticator Authenticator, PasskeyCreationOptions Creation, PasskeyRegistrationResult Result, PasskeyCredentialData? Stored, PasskeyRegistrationResult Again);
    private sealed record SecondOutcome(PasskeyFixture Fixture, SyntheticAuthenticator First, PasskeyRegistrationResult FirstResult, string UserHandle, PasskeyCreationOptions SignUpAgain,
        PasskeyRegistrationResult Intrusion, bool IntruderStored, int RegistrarCallsAfterIntrusion, PasskeyCreationOptions Creation, PasskeyRegistrationResult SecondResult);
    private sealed record BindingOutcome(PasskeySignInResult Crossed, bool ScopedRowConsumed, PasskeySignInResult Discovered, bool DiscoverableRowConsumed, PasskeySignInResult OwnResult,
        PasskeySignInResult Orphaned, bool OrphanedChallengeConsumed);
    private sealed record RegistrarOutcome(PasskeyRegistrationResult Successor, bool SuccessorStored, Exception? Fault, bool FaultStored, int RegistrarCallsAfterFault,
        Exception? SaveFault, int RegistrarCallsAfterSaveFault, PasskeyRegistrationResult AfterFaults);
    private sealed record ApartOutcome(PasskeyRegistrationResult Added, PasskeyRegistrationResult Intrusion, int CredentialCount);
    private sealed record FailureOutcome(PasskeyRegistrationResult NoPending, PasskeyRegistrationResult WrongChallenge, PasskeyRegistrationResult Consumed, PasskeyRegistrationResult Expired,
        PasskeyRegistrationResult Conflict, bool StoredDespiteConflict, PasskeyRegistrationResult DeviceKeyPersonAddsPasskey, PasskeyCredentialData? StoredBesideKeySet, PasskeyRegistrationResult Duplicate,
        PasskeyRegistrationResult MaterialConflict, bool OtherStored, PasskeyRegistrationResult Invalid, bool ThirdStored);
    private sealed record SignInOutcome(SyntheticAuthenticator Authenticator, PasskeyRequestOptions Request, PasskeySignInResult Result, PasskeyCredentialData Stored, PasskeySignInResult Replay);
    private sealed record AssertionFailureOutcome(PasskeyRequestOptions Discoverable, PasskeySignInResult Discovered, PasskeySignInResult NullResponse, PasskeySignInResult UnknownCeremony,
        PasskeySignInResult UnknownCredential, PasskeySignInResult Regressed, bool Flagged, PasskeySignInResult Tampered, long SignCountAfterTamper);
    private sealed record RequestOutcome(ConfirmationChallenge Challenge, PasskeyRequestOptions Request, SyntheticAuthenticator Authenticator);
}
