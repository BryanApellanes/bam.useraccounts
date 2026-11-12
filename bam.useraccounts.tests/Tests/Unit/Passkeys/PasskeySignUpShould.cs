using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Protocol.Data;
using Bam.Protocol.Profile.Registration;
using Bam.Test;
using Bam.UserAccounts.Passkeys;
using Bam.UserAccounts.Tests.TestClasses;
using NSubstitute;

namespace Bam.UserAccounts.Tests.Unit.Passkeys;

[UnitTestMenu("PasskeySignUp Should", Selector = "pksu")]
public class PasskeySignUpShould : UnitTestMenuContainer
{
    public PasskeySignUpShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    private static PasskeySignUpRequest Request(string handle = "jane-doe", string? displayName = "Jane Doe", string? email = null, string? invite = null)
    {
        return new PasskeySignUpRequest { Handle = handle, DisplayName = displayName, Email = email, InviteCode = invite };
    }

    [UnitTest]
    public void SignUpAPersonWithAPasskey()
    {
        After.Setup(reg => reg.Set(new SignUpFixture()))
        .When<SignUpFixture>("signs a person up on an open host", (fixture, reg) =>
        {
            SyntheticAuthenticator authenticator = new SyntheticAuthenticator();
            PasskeySignUpRequest request = Request("  Jane-Doe ", "Jane Q Doe", " jane@example.com ");
            PasskeySignUpBeginResult begun = fixture.SignUp.Begin(request);
            byte[] challenge = Base64UrlEncoder.Default.Decode(begun.Options!.Challenge);
            PasskeySignUpResult result = fixture.SignUp.Complete(request, authenticator.Register(challenge));
            authenticator.SignCount = 2;
            PasskeySignInResult signIn = fixture.Passkeys.SignIn(authenticator, "jane-doe");
            return new SignUpOutcome(fixture, begun, result, authenticator.CredentialIdBase64Url, signIn);
        })
        .TheTest
        .ShouldPass<SignUpOutcome>((because, outcome) =>
        {
            SignUpFixture fixture = outcome.Fixture;
            because.ItsTrue("begin succeeds with options for the normalized handle", outcome.Begun.Success && outcome.Begun.PersonHandle == "jane-doe" && outcome.Begun.Options!.User.Name == "jane-doe");
            because.ItsTrue("the options carry the display name", outcome.Begun.Options!.User.DisplayName == "Jane Q Doe");
            because.ItsTrue("complete succeeds with no refusal", outcome.Result.Success && outcome.Result.Refusal == SignUpRefusal.None);
            because.ItsTrue("the result names the person and the credential", outcome.Result.PersonHandle == "jane-doe" && outcome.Result.DisplayName == "Jane Q Doe" && outcome.Result.CredentialId == outcome.CredentialId);
            because.ItsTrue("the passkey became the registered key set", fixture.Passkeys.Registered.Count == 1 && !string.IsNullOrEmpty(outcome.Result.KeyFingerprint));
            because.ItsTrue("the person was registered once", fixture.RegisteredPersons.Count == 1 && outcome.Result.ProfileCreated);
            PersonRegistrationData person = fixture.RegisteredPersons[0];
            because.ItsTrue("with the normalized handle", person.Handle == "jane-doe");
            because.ItsTrue("the display name split into first and remaining names", person.FirstName == "Jane" && person.LastName == "Q Doe");
            because.ItsTrue("and the trimmed email", person.Email == "jane@example.com");
            because.ItsTrue("the profile name is left alone when it already matches", fixture.ProfileNames.Count == 0);
            because.ItsTrue("no next url without a step", outcome.Result.NextUrl is null);
            because.ItsTrue("the new passkey signs in as the person", outcome.SignIn.Success && outcome.SignIn.PersonHandle == "jane-doe");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseBeforeAnyChallengeWhenClosedOrUninvited()
    {
        After.Setup(reg => reg.Set(new SignUpFixture(new SignUpPolicy { OpenSignUp = false })))
        .When<SignUpFixture>("applies a closed and then an invite-only policy", (fixture, reg) =>
        {
            SyntheticAuthenticator authenticator = new SyntheticAuthenticator();
            PasskeySignUpBeginResult closed = fixture.SignUp.Begin(Request());
            bool closedLeftAChallenge = fixture.HasPendingRegistration("jane-doe");
            PasskeySignUpResult closedComplete = fixture.SignUp.Complete(Request(), authenticator.Register(SyntheticAuthenticator.RandomBytes(32)));

            fixture.Policy.InviteCodes.Add("first-code");
            fixture.Policy.InviteCodes.Add("second-code");
            PasskeySignUpBeginResult noCode = fixture.SignUp.Begin(Request());
            PasskeySignUpBeginResult wrongCode = fixture.SignUp.Begin(Request(invite: "first-cod"));
            bool uninvitedLeftAChallenge = fixture.HasPendingRegistration("jane-doe");
            PasskeySignUpResult invited = fixture.Run(Request(invite: "second-code"), authenticator);
            PasskeySignUpRequest swapped = Request("john-doe", "John Doe", invite: "second-code");
            PasskeySignUpBeginResult begunInvited = fixture.SignUp.Begin(swapped);
            swapped.InviteCode = "guess";
            PasskeySignUpResult completeWithoutInvite = fixture.SignUp.Complete(swapped, new SyntheticAuthenticator().Register(Base64UrlEncoder.Default.Decode(begunInvited.Options!.Challenge)));
            return new PolicyOutcome(fixture, closed, closedLeftAChallenge, closedComplete, noCode, wrongCode, uninvitedLeftAChallenge, invited, completeWithoutInvite);
        })
        .TheTest
        .ShouldPass<PolicyOutcome>((because, outcome) =>
        {
            because.ItsTrue("a closed host refuses at begin", !outcome.Closed.Success && outcome.Closed.Refusal == SignUpRefusal.SignUpClosed && outcome.Closed.Options is null);
            because.ItsTrue("and leaves no challenge behind", !outcome.ClosedLeftAChallenge);
            because.ItsTrue("a closed host refuses at completion too", !outcome.ClosedComplete.Success && outcome.ClosedComplete.Refusal == SignUpRefusal.SignUpClosed);
            because.ItsTrue("an invite-only host refuses a missing code", outcome.NoCode.Refusal == SignUpRefusal.InviteRequired);
            because.ItsTrue("and a near-miss code", outcome.WrongCode.Refusal == SignUpRefusal.InviteRequired);
            because.ItsTrue("without creating a challenge", !outcome.UninvitedLeftAChallenge);
            because.ItsTrue("any listed code is accepted", outcome.Invited.Success && outcome.Invited.PersonHandle == "jane-doe");
            because.ItsTrue("completion re-checks the invite", !outcome.CompleteWithoutInvite.Success && outcome.CompleteWithoutInvite.Refusal == SignUpRefusal.InviteRequired);
            because.ItsTrue("only the invited person exists", outcome.Fixture.RegisteredPersons.Count == 1 && outcome.Fixture.Passkeys.Registered.Count == 1);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseUnacceptableHandlesAndEmails()
    {
        After.Setup(reg => reg.Set(new SignUpFixture(new SignUpPolicy { RequireEmail = true })))
        .When<SignUpFixture>("submits handles and emails the policy does not accept", (fixture, reg) =>
        {
            List<SignUpRefusal> handles = new List<SignUpRefusal>();
            foreach (string handle in new string[] { "ab", "passkey-registration", "has space", "-leading", "under_score", new string('a', 33), "" })
            {
                handles.Add(fixture.SignUp.Begin(Request(handle, email: "a@example.com")).Refusal);
            }
            SignUpRefusal nullRequest = fixture.SignUp.Begin(null).Refusal;
            SignUpRefusal nullComplete = fixture.SignUp.Complete(null, null).Refusal;
            SignUpRefusal blankEmail = fixture.SignUp.Begin(Request(email: "  ")).Refusal;
            SignUpRefusal malformedEmail = fixture.SignUp.Begin(Request(email: "jane@nowhere")).Refusal;
            fixture.Policy.RequireEmail = false;
            SignUpRefusal optionalBlank = fixture.SignUp.Begin(Request()).Refusal;
            SignUpRefusal optionalMalformed = fixture.SignUp.Begin(Request(email: "two@@example.com")).Refusal;
            bool reservedReachedTheCeremony = fixture.HasPendingRegistration("passkey-registration");
            return new ValidationOutcome(handles, nullRequest, nullComplete, blankEmail, malformedEmail, optionalBlank, optionalMalformed, reservedReachedTheCeremony);
        })
        .TheTest
        .ShouldPass<ValidationOutcome>((because, outcome) =>
        {
            because.ItsTrue("every unacceptable handle is refused as invalid", outcome.Handles.All(refusal => refusal == SignUpRefusal.InvalidHandle));
            because.ItsTrue("a reserved-prefix handle never reaches the ceremony", !outcome.ReservedReachedTheCeremony);
            because.ItsTrue("a null request is refused, not thrown", outcome.NullRequest == SignUpRefusal.InvalidHandle && outcome.NullComplete == SignUpRefusal.InvalidHandle);
            because.ItsTrue("a required email must be present", outcome.BlankEmail == SignUpRefusal.EmailRequired);
            because.ItsTrue("and plausible", outcome.MalformedEmail == SignUpRefusal.EmailRequired);
            because.ItsTrue("an optional email may be blank", outcome.OptionalBlank == SignUpRefusal.None);
            because.ItsTrue("but not malformed", outcome.OptionalMalformed == SignUpRefusal.EmailRequired);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ValidateThePolicy()
    {
        When.A<SignUpPolicy>("validates and applies its rules", new SignUpPolicy(), (policy) =>
        {
            policy.InviteCodes.Add("open-sesame");
            return new PolicyRulesOutcome(
                Throws(() => new SignUpPolicy().Validate()),
                Throws(() => new SignUpPolicy { HandlePattern = "[unclosed" }.Validate()),
                Throws(() => new SignUpPolicy { HandlePattern = " " }.Validate()),
                Throws(() => new SignUpPolicy { ReservedHandlePrefixes = new List<string> { "" } }.Validate()),
                Throws(() => new SignUpPolicy { InviteCodes = new List<string> { " " } }.Validate()),
                policy.AcceptsInvite("open-sesame"),
                policy.AcceptsInvite("open-sesam") || policy.AcceptsInvite(null) || policy.AcceptsInvite(string.Empty),
                SignUpPolicy.NormalizeHandle("  MiXed "),
                policy.IsHandleAcceptable("abc") && policy.IsHandleAcceptable("a1-b2") && !policy.IsHandleAcceptable("abc\n"),
                SignUpPolicy.IsPlausibleEmail("a@b.co") && !SignUpPolicy.IsPlausibleEmail("a b@c.de") && !SignUpPolicy.IsPlausibleEmail("@c.de") && !SignUpPolicy.IsPlausibleEmail("a@.de") && !SignUpPolicy.IsPlausibleEmail(new string('a', 250) + "@b.co"));
        })
        .TheTest
        .ShouldPass<PolicyRulesOutcome>((because, outcome) =>
        {
            because.ItsTrue("the default policy is valid", !outcome.DefaultThrows);
            because.ItsTrue("a broken pattern is refused", outcome.BadPatternThrows && outcome.BlankPatternThrows);
            because.ItsTrue("blank reserved prefixes and invite codes are refused", outcome.BlankPrefixThrows && outcome.BlankInviteThrows);
            because.ItsTrue("a listed invite is accepted", outcome.InviteAccepted);
            because.ItsTrue("a near miss, null and empty are not", !outcome.OtherInvitesAccepted);
            because.ItsTrue("handles normalize to trimmed lowercase", outcome.Normalized == "mixed");
            because.ItsTrue("the pattern must match the whole handle", outcome.HandleRules);
            because.ItsTrue("emails are checked for shape and length", outcome.EmailRules);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ReportHandleAvailability()
    {
        After.Setup(reg => reg.Set(new SignUpFixture()))
        .When<SignUpFixture>("checks handles held by a passkey, by a person, and by nobody", (fixture, reg) =>
        {
            fixture.Run(Request("has-passkey"), new SyntheticAuthenticator());
            fixture.Persons.Add("device-person");
            HandleAvailability free = fixture.SignUp.CheckHandle(" Free-Handle ");
            HandleAvailability passkey = fixture.SignUp.CheckHandle("has-passkey");
            HandleAvailability person = fixture.SignUp.CheckHandle("device-person");
            HandleAvailability invalid = fixture.SignUp.CheckHandle("x");
            PasskeySignUpBeginResult takenBegin = fixture.SignUp.Begin(Request("device-person"));
            bool takenLeftAChallenge = fixture.HasPendingRegistration("device-person");

            fixture.Policy.AllowHandleAvailabilityCheck = false;
            HandleAvailability notChecked = fixture.SignUp.CheckHandle("has-passkey");
            PasskeySignUpRequest again = Request("has-passkey");
            PasskeySignUpBeginResult silentBegin = fixture.SignUp.Begin(again);
            PasskeySignUpResult silentComplete = fixture.SignUp.Complete(again, new SyntheticAuthenticator().Register(Base64UrlEncoder.Default.Decode(silentBegin.Options!.Challenge)));
            PasskeySignUpResult personComplete = fixture.Run(Request("device-person"), new SyntheticAuthenticator());
            return new AvailabilityOutcome(fixture, free, passkey, person, invalid, takenBegin, takenLeftAChallenge, notChecked, silentBegin, silentComplete, personComplete);
        })
        .TheTest
        .ShouldPass<AvailabilityOutcome>((because, outcome) =>
        {
            because.ItsTrue("a free handle is available, normalized", outcome.Free.Available && outcome.Free.Handle == "free-handle" && outcome.Free.Reason == HandleAvailabilityReason.Available);
            because.ItsTrue("a handle with a passkey is taken", !outcome.Passkey.Available && outcome.Passkey.Reason == HandleAvailabilityReason.Taken);
            because.ItsTrue("a person without a passkey is taken too", !outcome.Person.Available && outcome.Person.Reason == HandleAvailabilityReason.Taken);
            because.ItsTrue("an unacceptable handle is invalid", !outcome.Invalid.Available && outcome.Invalid.Reason == HandleAvailabilityReason.Invalid);
            because.ItsTrue("begin refuses a taken handle by name", outcome.TakenBegin.Refusal == SignUpRefusal.HandleTaken && outcome.TakenBegin.Message == "That handle is taken");
            because.ItsTrue("before any challenge exists", !outcome.TakenLeftAChallenge);
            because.ItsTrue("with the check off nothing is looked up", outcome.NotChecked.Available && outcome.NotChecked.Reason == HandleAvailabilityReason.NotChecked);
            because.ItsTrue("and begin does not disclose a taken handle", outcome.SilentBegin.Success && outcome.SilentBegin.Options is not null);
            because.ItsTrue("completion refuses it generically", !outcome.SilentComplete.Success && outcome.SilentComplete.Refusal == SignUpRefusal.HandleTaken && outcome.SilentComplete.Message == PasskeySignUp.SignUpFailedMessage);
            because.ItsTrue("a person without any key is refused at completion, generically", !outcome.PersonComplete.Success && outcome.PersonComplete.Refusal == SignUpRefusal.HandleTaken && outcome.PersonComplete.Message == PasskeySignUp.SignUpFailedMessage);
            because.ItsTrue("only the first sign-up registered anything", outcome.Fixture.Passkeys.Registered.Count == 1 && outcome.Fixture.RegisteredPersons.Count == 1);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void StoreNothingWhenTheCeremonyRefuses()
    {
        After.Setup(reg => reg.Set(new SignUpFixture()))
        .When<SignUpFixture>("completes with a response from the wrong origin", (fixture, reg) =>
        {
            SyntheticAuthenticator authenticator = new SyntheticAuthenticator(origin: "https://evil.example");
            PasskeySignUpResult wrongOrigin = fixture.Run(Request(), authenticator);
            PasskeySignUpResult noResponse = fixture.SignUp.Complete(Request(), null);
            return new RefusalOutcome(fixture, wrongOrigin, noResponse, fixture.Passkeys.Credentials.FindByHandle("jane-doe").Count);
        })
        .TheTest
        .ShouldPass<RefusalOutcome>((because, outcome) =>
        {
            because.ItsTrue("the refusal is CeremonyFailed with the generic message", !outcome.WrongOrigin.Success && outcome.WrongOrigin.Refusal == SignUpRefusal.CeremonyFailed && outcome.WrongOrigin.Message == PasskeySignUp.SignUpFailedMessage);
            because.ItsTrue("a missing response is refused the same way", !outcome.NoResponse.Success && outcome.NoResponse.Refusal == SignUpRefusal.CeremonyFailed);
            because.ItsTrue("no credential is stored", outcome.StoredCredentials == 0);
            because.ItsTrue("no key set is registered", outcome.Fixture.Passkeys.Registered.Count == 0);
            because.ItsTrue("the account service is never asked", outcome.Fixture.RegisterAttempts == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void KeepTheSignUpWhenTheProfileFaults()
    {
        After.Setup(reg => reg.Set(new SignUpFixture()))
        .When<SignUpFixture>("loses the profile write after the passkey claimed the handle", (fixture, reg) =>
        {
            SyntheticAuthenticator authenticator = new SyntheticAuthenticator();
            fixture.RegisterPersonThrows = new InvalidOperationException("store is down");
            PasskeySignUpResult faulted = fixture.Run(Request(), authenticator);
            authenticator.SignCount = 2;
            PasskeySignInResult signIn = fixture.Passkeys.SignIn(authenticator, "jane-doe");

            fixture.RegisterPersonThrows = null;
            fixture.RegisterPersonRefuses = true;
            PasskeySignUpResult refused = fixture.Run(Request("john-doe", "John Doe"), new SyntheticAuthenticator());
            fixture.RegisterPersonRefuses = false;

            ProfileCompletion stranger = fixture.SignUp.CompleteProfile("nobody-here", "Nobody", null);
            bool hadProfile = fixture.SignUp.HasProfile("jane-doe");
            int attemptsBeforeBadEmail = fixture.RegisterAttempts;
            ProfileCompletion badEmail = fixture.SignUp.CompleteProfile("Jane-Doe", "Jane Doe", "not-an-email");
            int attemptsAfterBadEmail = fixture.RegisterAttempts - attemptsBeforeBadEmail;
            ProfileCompletion finished = fixture.SignUp.CompleteProfile("Jane-Doe", "  Jane Doe ", null);
            int attemptsAfterFinish = fixture.RegisterAttempts;
            ProfileCompletion finishedAgain = fixture.SignUp.CompleteProfile("jane-doe", "Jane Doe", null);
            return new ProfileFaultOutcome(fixture, faulted, signIn, refused, stranger, hadProfile, badEmail, attemptsAfterBadEmail, finished, fixture.SignUp.HasProfile("jane-doe"), finishedAgain, attemptsAfterFinish);
        })
        .TheTest
        .ShouldPass<ProfileFaultOutcome>((because, outcome) =>
        {
            because.ItsTrue("the sign-up still succeeds", outcome.Faulted.Success && outcome.Faulted.PersonHandle == "jane-doe");
            because.ItsTrue("and reports the missing profile", !outcome.Faulted.ProfileCreated && outcome.Faulted.Refusal == SignUpRefusal.ProfileFailed);
            because.ItsTrue("the person can sign in", outcome.SignIn.Success && outcome.SignIn.PersonHandle == "jane-doe");
            because.ItsTrue("a profile the account service refuses is reported the same way", outcome.Refused.Success && !outcome.Refused.ProfileCreated);
            because.ItsTrue($"CompleteProfile refuses a handle without a passkey ({outcome.Stranger})", outcome.Stranger == ProfileCompletion.NoPasskey);
            because.ItsTrue("HasProfile reports the missing profile", !outcome.HadProfile);
            because.ItsTrue($"an implausible email is refused, not dropped, and nothing is written ({outcome.BadEmail})", outcome.BadEmail == ProfileCompletion.InvalidEmail && outcome.AttemptsAfterBadEmail == 0);
            because.ItsTrue($"CompleteProfile writes the missing profile ({outcome.Finished})", outcome.Finished == ProfileCompletion.Created && outcome.Fixture.RegisteredPersons.Count == 1 && outcome.Fixture.RegisteredPersons[0].Handle == "jane-doe");
            because.ItsTrue("with the name the person gave", outcome.Fixture.RegisteredPersons[0].FirstName == "Jane" && outcome.Fixture.RegisteredPersons[0].LastName == "Doe");
            because.ItsTrue("and HasProfile then says so", outcome.HasProfileAfter);
            because.ItsTrue($"and is a no-op once the person exists ({outcome.FinishedAgain})", outcome.FinishedAgain == ProfileCompletion.AlreadyExists && outcome.Fixture.RegisterAttempts == outcome.AttemptsAfterFinish);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RequireTheEmailWhenCompletingAProfile()
    {
        After.Setup(reg => reg.Set(new SignUpFixture(new SignUpPolicy { RequireEmail = true })))
        .When<SignUpFixture>("finishes a lost profile on a host that requires email", (fixture, reg) =>
        {
            fixture.RegisterPersonThrows = new InvalidOperationException("store is down");
            PasskeySignUpResult faulted = fixture.Run(Request(email: "jane@example.com"), new SyntheticAuthenticator());
            fixture.RegisterPersonThrows = null;
            ProfileCompletion withoutEmail = fixture.SignUp.CompleteProfile("jane-doe", "Jane Doe", "  ");
            int personsAfterRefusal = fixture.RegisteredPersons.Count;
            ProfileCompletion withEmail = fixture.SignUp.CompleteProfile("jane-doe", "Jane Doe", " jane@example.com ");
            return new RequiredEmailOutcome(fixture, faulted, withoutEmail, personsAfterRefusal, withEmail);
        })
        .TheTest
        .ShouldPass<RequiredEmailOutcome>((because, outcome) =>
        {
            because.ItsTrue("the sign-up kept the passkey without a profile", outcome.Faulted.Success && !outcome.Faulted.ProfileCreated);
            because.ItsTrue($"a profile without an email is refused ({outcome.WithoutEmail})", outcome.WithoutEmail == ProfileCompletion.InvalidEmail && outcome.PersonsAfterRefusal == 0);
            because.ItsTrue($"one with an email is written, trimmed ({outcome.WithEmail})", outcome.WithEmail == ProfileCompletion.Created && outcome.Fixture.RegisteredPersons.Count == 1 && outcome.Fixture.RegisteredPersons[0].Email == "jane@example.com");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void WriteOneProfileWhenTwoCompletionsRace()
    {
        After.Setup(reg => reg.Set(new SignUpFixture()))
        .When<SignUpFixture>("finishes a lost profile from two places at once", (fixture, reg) =>
        {
            fixture.RegisterPersonThrows = new InvalidOperationException("store is down");
            fixture.Run(Request(), new SyntheticAuthenticator());
            fixture.RegisterPersonThrows = null;
            // Both lookups read "no person" before either writes, unless something serializes them.
            fixture.FindPersonRendezvous = new Barrier(2);
            Task<ProfileCompletion> tab = Task.Run(() => fixture.SignUp.CompleteProfile("jane-doe", "Jane Doe", null));
            Task<ProfileCompletion> app = Task.Run(() => fixture.SignUp.CompleteProfile("jane-doe", "Jane Doe", null));
            List<ProfileCompletion> outcomes = new List<ProfileCompletion> { tab.GetAwaiter().GetResult(), app.GetAwaiter().GetResult() };
            fixture.FindPersonRendezvous = null;
            return new ProfileRaceOutcome(fixture, outcomes);
        })
        .TheTest
        .ShouldPass<ProfileRaceOutcome>((because, outcome) =>
        {
            because.ItsTrue($"one completion writes and the other finds it ({string.Join(", ", outcome.Outcomes)})",
                outcome.Outcomes.Count(result => result == ProfileCompletion.Created) == 1 && outcome.Outcomes.Count(result => result == ProfileCompletion.AlreadyExists) == 1);
            because.ItsTrue($"so the handle has one person ({outcome.Fixture.RegisteredPersons.Count})", outcome.Fixture.RegisteredPersons.Count == 1);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RunPostSignUpStepsInOrder()
    {
        After.Setup(reg => reg.Set(new SignUpFixture()))
        .When<SignUpFixture>("runs a faulting step and two steps that name a next url", (fixture, reg) =>
        {
            List<SignedUpPerson> seen = new List<SignedUpPerson>();
            IPostSignUpStep faulting = Substitute.For<IPostSignUpStep>();
            faulting.Run(Arg.Any<SignedUpPerson>()).Returns(callInfo => throw new InvalidOperationException("step is broken"));
            IPostSignUpStep first = Substitute.For<IPostSignUpStep>();
            first.Run(Arg.Any<SignedUpPerson>()).Returns(callInfo =>
            {
                seen.Add(callInfo.Arg<SignedUpPerson>());
                return new PostSignUpOutcome { NextUrl = "/app/clients/new" };
            });
            IPostSignUpStep second = Substitute.For<IPostSignUpStep>();
            second.Run(Arg.Any<SignedUpPerson>()).Returns(callInfo =>
            {
                seen.Add(callInfo.Arg<SignedUpPerson>());
                return new PostSignUpOutcome { NextUrl = "/elsewhere" };
            });
            fixture.Steps.Add(faulting);
            fixture.Steps.Add(first);
            fixture.Steps.Add(() => second);
            PasskeySignUpResult result = fixture.Run(Request("cher", "Cher", "cher@example.com"), new SyntheticAuthenticator());
            return new StepsOutcome(fixture, result, seen);
        })
        .TheTest
        .ShouldPass<StepsOutcome>((because, outcome) =>
        {
            because.ItsTrue("a faulting step does not undo the sign-up", outcome.Result.Success && outcome.Result.ProfileCreated);
            because.ItsTrue("every later step still runs", outcome.Seen.Count == 2);
            because.ItsTrue("the first next url wins", outcome.Result.NextUrl == "/app/clients/new");
            SignedUpPerson person = outcome.Seen[0];
            because.ItsTrue("steps receive the person", person.PersonHandle == "cher" && person.DisplayName == "Cher" && person.Email == "cher@example.com" && person.ProfileCreated);
            because.ItsTrue("with the key fingerprint", person.KeyFingerprint == outcome.Result.KeyFingerprint && !string.IsNullOrEmpty(person.KeyFingerprint));
            because.ItsTrue("a single-word name fills both name fields", outcome.Fixture.RegisteredPersons[0].FirstName == "Cher" && outcome.Fixture.RegisteredPersons[0].LastName == "Cher");
            because.ItsTrue("and the profile name is set to the display name", outcome.Fixture.ProfileNames.TryGetValue("profile-cher", out string? name) && name == "Cher");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void DefaultAndBoundTheDisplayName()
    {
        After.Setup(reg => reg.Set(new SignUpFixture()))
        .When<SignUpFixture>("signs up with a blank and an oversized display name", (fixture, reg) =>
        {
            PasskeySignUpResult blank = fixture.Run(Request("no-name", "   "), new SyntheticAuthenticator());
            PasskeySignUpResult longName = fixture.Run(Request("long-name", new string('x', 150)), new SyntheticAuthenticator());
            return new DisplayNameOutcome(blank, longName);
        })
        .TheTest
        .ShouldPass<DisplayNameOutcome>((because, outcome) =>
        {
            because.ItsTrue("a blank display name falls back to the handle", outcome.Blank.Success && outcome.Blank.DisplayName == "no-name");
            because.ItsTrue("an oversized display name is cut", outcome.LongName.Success && outcome.LongName.DisplayName!.Length == SignUpPolicy.MaxDisplayNameLength);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RegisterOnTopOfAddPasskeys()
    {
        When.A<ServiceRegistry>("registers sign-up with and without AddPasskeys", new ServiceRegistry(), (bare) =>
        {
            bool withoutPasskeysThrows = Throws(() => bare.AddPasskeySignUp(new SignUpPolicy()));

            ServiceRegistry registry = new ServiceRegistry();
            registry.For<IConfirmationChallengeRepository>().UseSingleton(new InMemoryConfirmationChallengeRepository());
            registry.For<IPasskeyCredentialRepository>().UseSingleton(new InMemoryPasskeyCredentialRepository());
            registry.For<IPublicKeySetRegistrar>().Use(Substitute.For<IPublicKeySetRegistrar>());
            registry.For<IProfileRepository>().Use(Substitute.For<IProfileRepository>());
            registry.For<IUserAccountService>().Use(Substitute.For<IUserAccountService>());
            registry.AddPasskeys(PasskeyFixture.DefaultOptions());
            IPostSignUpStep early = Substitute.For<IPostSignUpStep>();
            registry.AddPostSignUpStep(early);
            bool invalidPolicyThrows = Throws(() => registry.AddPasskeySignUp(new SignUpPolicy { HandlePattern = "(" }));
            SignUpPolicy policy = new SignUpPolicy { OpenSignUp = false };
            registry.AddPasskeySignUp(policy);
            registry.AddPostSignUpStep<RecordingStep>();
            PostSignUpSteps steps = registry.Get<PostSignUpSteps>();
            return new RegistrationOutcome(
                withoutPasskeysThrows,
                invalidPolicyThrows,
                registry.Get<IPasskeySignUp>(),
                registry.Get<IPasskeyInventory>(),
                ReferenceEquals(registry.Get<SignUpPolicy>(), policy),
                steps.Count,
                ReferenceEquals(steps.Snapshot()[0](), early),
                steps.Snapshot()[1]() is RecordingStep);
        })
        .TheTest
        .ShouldPass<RegistrationOutcome>((because, outcome) =>
        {
            because.ItsTrue("AddPasskeySignUp requires AddPasskeys", outcome.WithoutPasskeysThrows);
            because.ItsTrue("an invalid policy is refused at registration", outcome.InvalidPolicyThrows);
            because.ItsTrue("IPasskeySignUp resolves to PasskeySignUp", outcome.SignUp is PasskeySignUp);
            because.ItsTrue("IPasskeyInventory resolves to PasskeyInventory", outcome.Inventory is PasskeyInventory);
            because.ItsTrue("the policy is the host's instance", outcome.SamePolicy);
            because.ItsTrue("steps added before and after registration are both kept, in order", outcome.StepCount == 2 && outcome.FirstIsEarly && outcome.SecondIsResolved);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static bool Throws(Action action)
    {
        try
        {
            action();
            return false;
        }
        catch (Exception)
        {
            return true;
        }
    }

    /// <summary>A step the registry can construct.</summary>
    public sealed class RecordingStep : IPostSignUpStep
    {
        public PostSignUpOutcome Run(SignedUpPerson person)
        {
            return new PostSignUpOutcome();
        }
    }

    private sealed record SignUpOutcome(SignUpFixture Fixture, PasskeySignUpBeginResult Begun, PasskeySignUpResult Result, string CredentialId, PasskeySignInResult SignIn);

    private sealed record PolicyOutcome(SignUpFixture Fixture, PasskeySignUpBeginResult Closed, bool ClosedLeftAChallenge, PasskeySignUpResult ClosedComplete,
        PasskeySignUpBeginResult NoCode, PasskeySignUpBeginResult WrongCode, bool UninvitedLeftAChallenge, PasskeySignUpResult Invited, PasskeySignUpResult CompleteWithoutInvite);

    private sealed record ValidationOutcome(List<SignUpRefusal> Handles, SignUpRefusal NullRequest, SignUpRefusal NullComplete, SignUpRefusal BlankEmail,
        SignUpRefusal MalformedEmail, SignUpRefusal OptionalBlank, SignUpRefusal OptionalMalformed, bool ReservedReachedTheCeremony);

    private sealed record PolicyRulesOutcome(bool DefaultThrows, bool BadPatternThrows, bool BlankPatternThrows, bool BlankPrefixThrows, bool BlankInviteThrows,
        bool InviteAccepted, bool OtherInvitesAccepted, string Normalized, bool HandleRules, bool EmailRules);

    private sealed record AvailabilityOutcome(SignUpFixture Fixture, HandleAvailability Free, HandleAvailability Passkey, HandleAvailability Person, HandleAvailability Invalid,
        PasskeySignUpBeginResult TakenBegin, bool TakenLeftAChallenge, HandleAvailability NotChecked, PasskeySignUpBeginResult SilentBegin, PasskeySignUpResult SilentComplete,
        PasskeySignUpResult PersonComplete);

    private sealed record RefusalOutcome(SignUpFixture Fixture, PasskeySignUpResult WrongOrigin, PasskeySignUpResult NoResponse, int StoredCredentials);

    private sealed record ProfileFaultOutcome(SignUpFixture Fixture, PasskeySignUpResult Faulted, PasskeySignInResult SignIn, PasskeySignUpResult Refused, ProfileCompletion Stranger,
        bool HadProfile, ProfileCompletion BadEmail, int AttemptsAfterBadEmail, ProfileCompletion Finished, bool HasProfileAfter, ProfileCompletion FinishedAgain, int AttemptsAfterFinish);

    private sealed record RequiredEmailOutcome(SignUpFixture Fixture, PasskeySignUpResult Faulted, ProfileCompletion WithoutEmail, int PersonsAfterRefusal, ProfileCompletion WithEmail);

    private sealed record ProfileRaceOutcome(SignUpFixture Fixture, List<ProfileCompletion> Outcomes);

    private sealed record StepsOutcome(SignUpFixture Fixture, PasskeySignUpResult Result, List<SignedUpPerson> Seen);

    private sealed record DisplayNameOutcome(PasskeySignUpResult Blank, PasskeySignUpResult LongName);

    private sealed record RegistrationOutcome(bool WithoutPasskeysThrows, bool InvalidPolicyThrows, IPasskeySignUp SignUp, IPasskeyInventory Inventory, bool SamePolicy,
        int StepCount, bool FirstIsEarly, bool SecondIsResolved);
}
