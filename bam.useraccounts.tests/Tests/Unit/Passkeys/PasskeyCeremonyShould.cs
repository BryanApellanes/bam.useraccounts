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
            because.ItsTrue("a discoverable ceremony writes and consumes an empty binding row", outcome.DiscoverableRowConsumed);
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
