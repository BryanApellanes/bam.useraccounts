using System.Net;
using Bam.DependencyInjection;
using Bam.Test;
using Bam.UserAccounts.Passkeys;
using Bam.UserAccounts.Tests.TestClasses;
using Bam.UserAccounts.Web.Tests.TestClasses;

namespace Bam.UserAccounts.Web.Tests.Unit;

[UnitTestMenu("AccountEndpoints Should", Selector = "acep")]
public class AccountEndpointsShould : UnitTestMenuContainer
{
    private const string Evil = "https://evil.example";

    public AccountEndpointsShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    [UnitTest]
    public void OpenASessionAtSignUp()
    {
        When.A<AccountHost>("signs a person up through the endpoints",
            () => new AccountHost(),
            (host) =>
            {
                try
                {
                    SyntheticAuthenticator authenticator = new SyntheticAuthenticator();
                    AccountReply completed = host.SignUp("alice", "Alice Example", authenticator);
                    string? cookie = completed.SessionCookie;
                    AccountReply listed = host.Get("/account/passkeys", cookie);
                    AccountReply anonymous = host.Get("/account/passkeys");
                    AccountReply again = host.SignUp("alice", "Alice Again", new SyntheticAuthenticator());
                    return new SignUpOutcome(completed, completed.Status == HttpStatusCode.OK ? completed.As<SignedInResponse>() : null,
                        listed, listed.Status == HttpStatusCode.OK ? listed.As<PasskeyListResponse>() : null, anonymous, again,
                        host.Fixture.RegisteredPersons.Count, authenticator.CredentialIdBase64Url);
                }
                finally
                {
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<SignUpOutcome>((because, outcome) =>
            {
                because.ItsTrue($"registration completes ({outcome.Completed.Status}: {outcome.Completed.Body})", outcome.Completed.Status == HttpStatusCode.OK);
                because.ItsTrue("the reply names the person and a local next URL", outcome.SignedIn?.Handle == "alice" && outcome.SignedIn.DisplayName == "Alice Example" && outcome.SignedIn.NextUrl == "/account" && outcome.SignedIn.ProfileCreated);
                because.ItsTrue("a session cookie is issued", outcome.Completed.SessionCookie is not null);
                string setCookie = (outcome.Completed.SetCookie ?? string.Empty).ToLowerInvariant();
                because.ItsTrue($"the cookie is HttpOnly, Secure and SameSite=Lax ({setCookie})", setCookie.Contains("httponly") && setCookie.Contains("secure") && setCookie.Contains("samesite=lax"));
                because.ItsTrue("the person's profile was registered once", outcome.RegisteredPersons == 1);
                because.ItsTrue($"the session lists the person's passkey ({outcome.Listed.Status})", outcome.Passkeys?.Passkeys.Count == 1 && outcome.Passkeys.Passkeys[0].Id == outcome.CredentialId);
                because.ItsTrue("and marks it as the session's own and the registered key set", outcome.Passkeys?.Passkeys[0].Current == true && outcome.Passkeys.Passkeys[0].RegisteredKeySet);
                because.ItsTrue("the list carries no key material", !outcome.Listed.Body.Contains("BEGIN", StringComparison.Ordinal) && !outcome.Listed.Body.Contains("publicKey", StringComparison.OrdinalIgnoreCase));
                because.ItsTrue($"without the cookie the list is 401, not a redirect ({outcome.Anonymous.Status})", outcome.Anonymous.Status == HttpStatusCode.Unauthorized);
                because.ItsTrue($"a second sign-up for the handle is refused as taken ({outcome.Again.Status} {outcome.Again.ErrorCode})", outcome.Again.Status == HttpStatusCode.Conflict && outcome.Again.ErrorCode == AccountErrorCodes.HandleTaken);
                because.ItsTrue("and issues no cookie", outcome.Again.SessionCookie is null);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void SignInWithARegisteredPasskeyOnly()
    {
        When.A<AccountHost>("signs in through the endpoints",
            () => new AccountHost(),
            (host) =>
            {
                try
                {
                    SyntheticAuthenticator authenticator = new SyntheticAuthenticator();
                    host.SignUp("alice", "Alice Example", authenticator);
                    AccountReply scoped = host.SignIn(authenticator, "alice", "/app/start");
                    AccountReply discoverable = host.SignIn(authenticator, null, Evil + "/landing");
                    AccountReply schemeRelative = host.SignIn(authenticator, null, "//evil.example/landing");
                    AccountReply wrongOrigin = host.SignIn(authenticator, "alice", null, Evil);
                    AccountReply stranger = host.SignIn(new SyntheticAuthenticator(), "alice");
                    AccountReply unknownHandle = host.SignIn(authenticator, "nobody-here");
                    AccountReply malformed = host.Post("/account/passkey/assertion/complete", new AssertionBeginRequest { Handle = "alice" });
                    return new SignInOutcome(scoped, Parsed(scoped), discoverable, Parsed(discoverable), Parsed(schemeRelative), wrongOrigin, stranger, unknownHandle, malformed, host.Site.Strings.SignInFailedMessage);
                }
                finally
                {
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<SignInOutcome>((because, outcome) =>
            {
                because.ItsTrue($"a handle-scoped sign-in succeeds ({outcome.Scoped.Status}: {outcome.Scoped.Body})", outcome.Scoped.Status == HttpStatusCode.OK && outcome.Scoped.SessionCookie is not null);
                because.ItsTrue("and goes to the local return URL", outcome.ScopedBody?.Handle == "alice" && outcome.ScopedBody.NextUrl == "/app/start");
                because.ItsTrue($"a sign-in without a handle succeeds ({outcome.Discoverable.Status}: {outcome.Discoverable.Body})", outcome.Discoverable.Status == HttpStatusCode.OK && outcome.Discoverable.SessionCookie is not null);
                because.ItsTrue("an absolute return URL is replaced by the default", outcome.DiscoverableBody?.NextUrl == "/account");
                because.ItsTrue("a scheme-relative return URL is replaced by the default", outcome.SchemeRelativeBody?.NextUrl == "/account");
                Refused(because, "an assertion made for another origin", outcome.WrongOrigin, outcome.GenericMessage);
                Refused(because, "an assertion from a passkey that was never registered", outcome.Stranger, outcome.GenericMessage);
                Refused(because, "a sign-in for an unknown handle", outcome.UnknownHandle, outcome.GenericMessage);
                because.ItsTrue($"a body without a credential is a bad request ({outcome.Malformed.Status})", outcome.Malformed.Status == HttpStatusCode.BadRequest && outcome.Malformed.ErrorCode == AccountErrorCodes.BadRequest);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseStateChangingRequestsThatAreNotTheSitesOwn()
    {
        When.A<AccountHost>("receives requests without the header or from another origin",
            () => new AccountHost(),
            (host) =>
            {
                try
                {
                    SyntheticAuthenticator authenticator = new SyntheticAuthenticator();
                    string cookie = host.SignUp("alice", "Alice Example", authenticator).SessionCookie!;
                    PasskeySignUpRequest request = new PasskeySignUpRequest { Handle = "bob", DisplayName = "Bob" };
                    AccountReply noHeader = host.Post("/account/passkey/registration/begin", request, null, false);
                    AccountReply foreign = host.Post("/account/passkey/registration/begin", request, null, true, Evil);
                    AccountReply own = host.Post("/account/passkey/registration/begin", request, null, true, host.BaseUrl.TrimEnd('/'));
                    AccountReply relyingParty = host.Post("/account/passkey/registration/begin", request, null, true, "https://lumberjack.live");
                    AccountReply signOutNoHeader = host.Post("/account/signout", new AssertionBeginRequest(), cookie, false);
                    AccountReply addForeign = host.Post("/account/passkey/additional/begin", new AssertionBeginRequest(), cookie, true, Evil);
                    AccountReply stillSignedIn = host.Get("/account/passkeys", cookie);
                    return new GuardOutcome(noHeader, foreign, own, relyingParty, signOutNoHeader, addForeign, stillSignedIn);
                }
                finally
                {
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<GuardOutcome>((because, outcome) =>
            {
                because.ItsTrue($"a POST without the header is refused ({outcome.NoHeader.Status})", outcome.NoHeader.Status == HttpStatusCode.Forbidden && outcome.NoHeader.ErrorCode == AccountErrorCodes.RequestRefused);
                because.ItsTrue($"a POST from another origin is refused ({outcome.Foreign.Status})", outcome.Foreign.Status == HttpStatusCode.Forbidden && outcome.Foreign.ErrorCode == AccountErrorCodes.RequestRefused);
                because.ItsTrue($"a POST from the host's own origin is served ({outcome.Own.Status})", outcome.Own.Status == HttpStatusCode.OK);
                because.ItsTrue($"a POST from an allowed relying-party origin is served ({outcome.RelyingParty.Status})", outcome.RelyingParty.Status == HttpStatusCode.OK);
                because.ItsTrue($"a sign-out without the header is refused ({outcome.SignOutNoHeader.Status})", outcome.SignOutNoHeader.Status == HttpStatusCode.Forbidden && !outcome.SignOutNoHeader.ClearsSession);
                because.ItsTrue($"a signed-in POST from another origin is refused ({outcome.AddForeign.Status})", outcome.AddForeign.Status == HttpStatusCode.Forbidden);
                because.ItsTrue("and the session is untouched", outcome.StillSignedIn.Status == HttpStatusCode.OK);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void ManagePasskeysForTheSessionsPersonOnly()
    {
        When.A<AccountHost>("adds, renames and removes passkeys through the endpoints",
            () => new AccountHost(),
            (host) =>
            {
                try
                {
                    SyntheticAuthenticator first = new SyntheticAuthenticator();
                    SyntheticAuthenticator second = new SyntheticAuthenticator();
                    SyntheticAuthenticator bobs = new SyntheticAuthenticator();
                    string alice = host.SignUp("alice", "Alice Example", first).SessionCookie!;
                    string bob = host.SignUp("bob", "Bob Example", bobs).SessionCookie!;

                    AccountReply anonymousBegin = host.Post("/account/passkey/additional/begin", new AssertionBeginRequest());
                    AccountReply anonymousRemove = host.Delete("/account/passkeys/" + first.CredentialIdBase64Url);
                    AccountReply removeOnly = host.Delete("/account/passkeys/" + first.CredentialIdBase64Url, alice);

                    AccountReply begun = host.Post("/account/passkey/additional/begin", new AssertionBeginRequest(), alice);
                    byte[] challenge = Base64UrlEncoder.Default.Decode(begun.As<CreationOptionsResponse>().Options.Challenge);
                    AccountReply added = host.Post("/account/passkey/additional/complete", new AdditionalCompleteRequest { Credential = second.Register(challenge), Name = "  phone  " }, alice);
                    AccountReply renamed = host.Post("/account/passkeys/" + first.CredentialIdBase64Url + "/name", new RenameRequest { Name = "laptop" }, alice);
                    AccountReply bobRenames = host.Post("/account/passkeys/" + first.CredentialIdBase64Url + "/name", new RenameRequest { Name = "mine now" }, bob);
                    AccountReply bobRemoves = host.Delete("/account/passkeys/" + second.CredentialIdBase64Url, bob);
                    PasskeyListResponse listed = host.Get("/account/passkeys", alice).As<PasskeyListResponse>();
                    PasskeyListResponse bobsList = host.Get("/account/passkeys", bob).As<PasskeyListResponse>();

                    AccountReply removeOther = host.Delete("/account/passkeys/" + second.CredentialIdBase64Url, alice);
                    AccountReply afterOther = host.Get("/account/passkeys", alice);
                    AccountReply secondSignsIn = host.SignIn(second, "alice");
                    return new ManageOutcome(anonymousBegin, anonymousRemove, removeOnly, added, renamed, bobRenames, bobRemoves, listed, bobsList, removeOther, afterOther, secondSignsIn,
                        first.CredentialIdBase64Url, second.CredentialIdBase64Url);
                }
                finally
                {
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<ManageOutcome>((because, outcome) =>
            {
                because.ItsTrue($"adding a passkey needs a session ({outcome.AnonymousBegin.Status})", outcome.AnonymousBegin.Status == HttpStatusCode.Unauthorized);
                because.ItsTrue($"removing a passkey needs a session ({outcome.AnonymousRemove.Status})", outcome.AnonymousRemove.Status == HttpStatusCode.Unauthorized);
                because.ItsTrue($"a person's only passkey cannot be removed ({outcome.RemoveOnly.Status})", outcome.RemoveOnly.Status == HttpStatusCode.Conflict && outcome.RemoveOnly.ErrorCode == AccountErrorCodes.LastPasskey);
                because.ItsTrue($"a signed-in person adds a passkey ({outcome.Added.Status}: {outcome.Added.Body})", outcome.Added.Status == HttpStatusCode.OK && outcome.Added.As<PasskeyAddedResponse>().CredentialId == outcome.SecondId);
                because.ItsTrue($"and renames one ({outcome.Renamed.Status})", outcome.Renamed.Status == HttpStatusCode.NoContent);
                because.ItsTrue($"another person cannot rename it ({outcome.BobRenames.Status})", outcome.BobRenames.Status == HttpStatusCode.NotFound);
                because.ItsTrue($"or remove it ({outcome.BobRemoves.Status})", outcome.BobRemoves.Status == HttpStatusCode.NotFound);
                because.ItsTrue("the list shows both passkeys under their names", outcome.Listed.Passkeys.Count == 2
                    && outcome.Listed.Passkeys.Single(passkey => passkey.Id == outcome.FirstId).Name == "laptop"
                    && outcome.Listed.Passkeys.Single(passkey => passkey.Id == outcome.SecondId).Name == "phone");
                because.ItsTrue("only the session's own passkey is marked current", outcome.Listed.Passkeys.Single(passkey => passkey.Current).Id == outcome.FirstId);
                because.ItsTrue("another person's list holds only their own passkey", outcome.BobsList.Passkeys.Count == 1 && outcome.BobsList.Passkeys[0].Id != outcome.FirstId && outcome.BobsList.Passkeys[0].Id != outcome.SecondId);
                because.ItsTrue($"removing another of one's passkeys keeps the session ({outcome.RemoveOther.Status})", outcome.RemoveOther.Status == HttpStatusCode.OK && !outcome.RemoveOther.As<SignedOutResponse>().SignedOut && outcome.AfterOther.Status == HttpStatusCode.OK);
                because.ItsTrue($"the removed passkey no longer signs in ({outcome.SecondSignsIn.Status})", outcome.SecondSignsIn.Status == HttpStatusCode.BadRequest && outcome.SecondSignsIn.ErrorCode == AccountErrorCodes.SignInFailed);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void EndTheSessionsOfARemovedPasskey()
    {
        When.A<AccountHost>("removes the passkey a session was opened with",
            () => new AccountHost(),
            (host) =>
            {
                try
                {
                    SyntheticAuthenticator first = new SyntheticAuthenticator();
                    SyntheticAuthenticator second = new SyntheticAuthenticator();
                    string firstSession = host.SignUp("alice", "Alice Example", first).SessionCookie!;
                    AccountReply begun = host.Post("/account/passkey/additional/begin", new AssertionBeginRequest(), firstSession);
                    byte[] challenge = Base64UrlEncoder.Default.Decode(begun.As<CreationOptionsResponse>().Options.Challenge);
                    host.Post("/account/passkey/additional/complete", new AdditionalCompleteRequest { Credential = second.Register(challenge) }, firstSession);
                    string secondSession = host.SignIn(second, "alice").SessionCookie!;

                    // The second session removes the first passkey: the first session's cookie is still held by its browser.
                    AccountReply removedElsewhere = host.Delete("/account/passkeys/" + first.CredentialIdBase64Url, secondSession);
                    AccountReply staleSession = host.Get("/account/passkeys", firstSession);
                    AccountReply stalePage = host.Get("/account", firstSession);
                    AccountReply survivor = host.Get("/account/passkeys", secondSession);

                    AccountReply signedOut = host.Post("/account/signout", new AssertionBeginRequest(), secondSession);
                    return new RevocationOutcome(removedElsewhere, staleSession, stalePage, survivor, signedOut);
                }
                finally
                {
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<RevocationOutcome>((because, outcome) =>
            {
                because.ItsTrue($"the passkey is removed from another session ({outcome.RemovedElsewhere.Status}: {outcome.RemovedElsewhere.Body})", outcome.RemovedElsewhere.Status == HttpStatusCode.OK && !outcome.RemovedElsewhere.As<SignedOutResponse>().SignedOut);
                because.ItsTrue($"the session opened with it is refused at its next request ({outcome.StaleSession.Status})", outcome.StaleSession.Status == HttpStatusCode.Unauthorized);
                because.ItsTrue("and its cookie is cleared", outcome.StaleSession.ClearsSession);
                because.ItsTrue($"its page request is sent to sign-in ({outcome.StalePage.Status} {outcome.StalePage.Location})", outcome.StalePage.Status == HttpStatusCode.Redirect && (outcome.StalePage.Location ?? string.Empty).Contains("/account/signin", StringComparison.Ordinal));
                because.ItsTrue($"the session that removed it carries on ({outcome.Survivor.Status})", outcome.Survivor.Status == HttpStatusCode.OK);
                because.ItsTrue($"signing out clears the cookie and names the signed-out page ({outcome.SignedOut.Status})", outcome.SignedOut.Status == HttpStatusCode.OK && outcome.SignedOut.ClearsSession && outcome.SignedOut.As<SignedOutResponse>().NextUrl == "/account/signedout");
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void SignOutWhenTheSessionsOwnPasskeyIsRemoved()
    {
        When.A<AccountHost>("removes the session's own passkey",
            () => new AccountHost(),
            (host) =>
            {
                try
                {
                    SyntheticAuthenticator first = new SyntheticAuthenticator();
                    SyntheticAuthenticator second = new SyntheticAuthenticator();
                    string session = host.SignUp("alice", "Alice Example", first).SessionCookie!;
                    AccountReply begun = host.Post("/account/passkey/additional/begin", new AssertionBeginRequest(), session);
                    byte[] challenge = Base64UrlEncoder.Default.Decode(begun.As<CreationOptionsResponse>().Options.Challenge);
                    host.Post("/account/passkey/additional/complete", new AdditionalCompleteRequest { Credential = second.Register(challenge) }, session);
                    AccountReply removed = host.Delete("/account/passkeys/" + first.CredentialIdBase64Url, session);
                    AccountReply after = host.Get("/account/passkeys", session);
                    return new OwnRemovalOutcome(removed, after);
                }
                finally
                {
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<OwnRemovalOutcome>((because, outcome) =>
            {
                because.ItsTrue($"the removal succeeds and reports the session ended ({outcome.Removed.Status}: {outcome.Removed.Body})", outcome.Removed.Status == HttpStatusCode.OK && outcome.Removed.As<SignedOutResponse>().SignedOut);
                because.ItsTrue("the reply clears the cookie and names the signed-out page", outcome.Removed.ClearsSession && outcome.Removed.As<SignedOutResponse>().NextUrl == "/account/signedout");
                because.ItsTrue($"the old cookie no longer opens the account ({outcome.After.Status})", outcome.After.Status == HttpStatusCode.Unauthorized);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void ApplyTheSignUpPolicyAndRateLimits()
    {
        When.A<AccountHost>("is invite-only, with a low request limit",
            () => new AccountHost(site =>
            {
                site.SignUp.OpenSignUp = false;
                site.SignUp.InviteCodes.Add("welcome-2026");
                site.RateLimits.PermitLimit = 4;
            }),
            (host) =>
            {
                try
                {
                    AccountReply noInvite = host.Post("/account/passkey/registration/begin", new PasskeySignUpRequest { Handle = "alice", DisplayName = "Alice" });
                    AccountReply wrongInvite = host.Post("/account/passkey/registration/begin", new PasskeySignUpRequest { Handle = "alice", DisplayName = "Alice", InviteCode = "guess" });
                    AccountReply invited = host.Post("/account/passkey/registration/begin", new PasskeySignUpRequest { Handle = "alice", DisplayName = "Alice", InviteCode = "welcome-2026" });
                    AccountReply reserved = host.Post("/account/passkey/registration/begin", new PasskeySignUpRequest { Handle = "passkey-x", DisplayName = "Alice", InviteCode = "welcome-2026" });
                    AccountReply limited = host.Post("/account/passkey/registration/begin", new PasskeySignUpRequest { Handle = "alice", DisplayName = "Alice", InviteCode = "welcome-2026" });
                    return new PolicyOutcome(noInvite, wrongInvite, invited, reserved, limited, noInvite.Body.Contains("welcome-2026", StringComparison.Ordinal) || wrongInvite.Body.Contains("welcome-2026", StringComparison.Ordinal));
                }
                finally
                {
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<PolicyOutcome>((because, outcome) =>
            {
                because.ItsTrue($"sign-up without an invite is refused ({outcome.NoInvite.Status} {outcome.NoInvite.ErrorCode})", outcome.NoInvite.Status == HttpStatusCode.Forbidden && outcome.NoInvite.ErrorCode == AccountErrorCodes.InviteRequired);
                because.ItsTrue($"and with a wrong one ({outcome.WrongInvite.Status} {outcome.WrongInvite.ErrorCode})", outcome.WrongInvite.Status == HttpStatusCode.Forbidden && outcome.WrongInvite.ErrorCode == AccountErrorCodes.InviteRequired);
                because.ItsTrue("no refusal echoes an invite code", !outcome.LeaksInvite);
                because.ItsTrue($"the right invite gets creation options ({outcome.Invited.Status})", outcome.Invited.Status == HttpStatusCode.OK && outcome.Invited.As<CreationOptionsResponse>().Options.Challenge.Length > 0);
                because.ItsTrue($"a handle in the ceremony's reserved namespace is refused ({outcome.Reserved.Status} {outcome.Reserved.ErrorCode})", outcome.Reserved.Status == HttpStatusCode.BadRequest && outcome.Reserved.ErrorCode == AccountErrorCodes.InvalidHandle);
                because.ItsTrue($"the request past the limit is 429 ({outcome.Limited.Status})", outcome.Limited.Status == HttpStatusCode.TooManyRequests);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void AnswerHandleAvailabilityOnlyWhenTheHostAllowsIt()
    {
        When.A<AccountHost>("is asked whether handles are available",
            () => new AccountHost(),
            (host) =>
            {
                AccountHost closed = new AccountHost(site => site.SignUp.AllowHandleAvailabilityCheck = false);
                try
                {
                    host.SignUp("alice", "Alice Example", new SyntheticAuthenticator());
                    AccountReply taken = host.Get("/account/handle/alice/availability");
                    AccountReply free = host.Get("/account/handle/carol/availability");
                    AccountReply invalid = host.Get("/account/handle/No%20Spaces/availability");
                    closed.SignUp("alice", "Alice Example", new SyntheticAuthenticator());
                    AccountReply disabled = closed.Get("/account/handle/alice/availability");
                    AccountReply takenWhenDisabled = closed.SignUp("alice", "Alice Again", new SyntheticAuthenticator());
                    return new AvailabilityOutcome(taken.As<AvailabilityResponse>(), free.As<AvailabilityResponse>(), invalid.As<AvailabilityResponse>(), disabled, takenWhenDisabled);
                }
                finally
                {
                    closed.Dispose();
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<AvailabilityOutcome>((because, outcome) =>
            {
                because.ItsTrue($"a handle with an account is taken ({outcome.Taken.Reason})", !outcome.Taken.Available && outcome.Taken.Reason == "Taken");
                because.ItsTrue($"an unused handle is available ({outcome.Free.Reason})", outcome.Free.Available && outcome.Free.Reason == "Available");
                because.ItsTrue($"a handle that breaks the rules is invalid ({outcome.Invalid.Reason})", !outcome.Invalid.Available && outcome.Invalid.Reason == "Invalid");
                because.ItsTrue($"with the check turned off the endpoint does not exist ({outcome.Disabled.Status})", outcome.Disabled.Status == HttpStatusCode.NotFound);
                because.ItsTrue($"and sign-up for a taken handle fails without saying why ({outcome.TakenWhenDisabled.Status} {outcome.TakenWhenDisabled.ErrorCode})",
                    outcome.TakenWhenDisabled.Status == HttpStatusCode.BadRequest && outcome.TakenWhenDisabled.ErrorCode == AccountErrorCodes.SignUpFailed);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    private static SignedInResponse? Parsed(AccountReply reply)
    {
        return reply.Status == HttpStatusCode.OK ? reply.As<SignedInResponse>() : null;
    }

    private static void Refused(Because because, string what, AccountReply reply, string genericMessage)
    {
        because.ItsTrue($"{what} is refused ({reply.Status} {reply.ErrorCode})", reply.Status == HttpStatusCode.BadRequest && reply.ErrorCode == AccountErrorCodes.SignInFailed);
        because.ItsTrue($"{what} gets the one generic message and no cookie", reply.SessionCookie is null && reply.As<AccountError>().Message == genericMessage);
    }

    private sealed record SignUpOutcome(AccountReply Completed, SignedInResponse? SignedIn, AccountReply Listed, PasskeyListResponse? Passkeys, AccountReply Anonymous, AccountReply Again, int RegisteredPersons, string CredentialId);

    private sealed record SignInOutcome(AccountReply Scoped, SignedInResponse? ScopedBody, AccountReply Discoverable, SignedInResponse? DiscoverableBody, SignedInResponse? SchemeRelativeBody,
        AccountReply WrongOrigin, AccountReply Stranger, AccountReply UnknownHandle, AccountReply Malformed, string GenericMessage);

    private sealed record GuardOutcome(AccountReply NoHeader, AccountReply Foreign, AccountReply Own, AccountReply RelyingParty, AccountReply SignOutNoHeader, AccountReply AddForeign, AccountReply StillSignedIn);

    private sealed record ManageOutcome(AccountReply AnonymousBegin, AccountReply AnonymousRemove, AccountReply RemoveOnly, AccountReply Added, AccountReply Renamed, AccountReply BobRenames, AccountReply BobRemoves,
        PasskeyListResponse Listed, PasskeyListResponse BobsList, AccountReply RemoveOther, AccountReply AfterOther, AccountReply SecondSignsIn, string FirstId, string SecondId);

    private sealed record RevocationOutcome(AccountReply RemovedElsewhere, AccountReply StaleSession, AccountReply StalePage, AccountReply Survivor, AccountReply SignedOut);

    private sealed record OwnRemovalOutcome(AccountReply Removed, AccountReply After);

    private sealed record PolicyOutcome(AccountReply NoInvite, AccountReply WrongInvite, AccountReply Invited, AccountReply Reserved, AccountReply Limited, bool LeaksInvite);

    private sealed record AvailabilityOutcome(AvailabilityResponse Taken, AvailabilityResponse Free, AvailabilityResponse Invalid, AccountReply Disabled, AccountReply TakenWhenDisabled);
}
