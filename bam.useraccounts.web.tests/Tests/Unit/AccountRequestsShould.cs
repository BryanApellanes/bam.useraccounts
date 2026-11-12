using System.Net;
using Bam.DependencyInjection;
using Bam.Test;
using Bam.UserAccounts.Passkeys;
using Bam.UserAccounts.Tests.TestClasses;
using Bam.UserAccounts.Web.Tests.TestClasses;

namespace Bam.UserAccounts.Web.Tests.Unit;

[UnitTestMenu("AccountRequests Should", Selector = "acrq")]
public class AccountRequestsShould : UnitTestMenuContainer
{
    public AccountRequestsShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    [UnitTest]
    public void RefuseBodiesTheEndpointsDoNotRead()
    {
        When.A<AccountHost>("is sent bodies it must not read",
            () => new AccountHost(),
            (host) =>
            {
                try
                {
                    string small = "{\"handle\":\"alice\",\"displayName\":\"Alice Example\"}";
                    string oversized = "{\"handle\":\"alice\",\"displayName\":\"" + new string('a', 70 * 1024) + "\"}";
                    AccountReply accepted = host.PostRaw("/account/passkey/registration/begin", small, "application/json");
                    AccountReply declared = host.PostRaw("/account/passkey/registration/begin", oversized, "application/json");
                    long declaredRead = host.LastBodyBytesRead;
                    AccountReply streamed = host.PostRaw("/account/passkey/registration/begin", oversized, "application/json", chunked: true);
                    AccountReply plainText = host.PostRaw("/account/passkey/registration/begin", small, "text/plain");
                    AccountReply malformed = host.PostRaw("/account/passkey/registration/begin", "{\"handle\":", "application/json");
                    return new BodyOutcome(accepted, declared, declaredRead, streamed, plainText, malformed);
                }
                finally
                {
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<BodyOutcome>((because, outcome) =>
            {
                because.ItsTrue($"a small JSON body is read ({outcome.Accepted.Status})", outcome.Accepted.Status == HttpStatusCode.OK);
                BadRequest(because, "a body declaring more than 64 KB", outcome.Declared);
                because.ItsTrue($"and it is refused on the declared length, before a byte is read ({outcome.DeclaredBytesRead} read)", outcome.DeclaredBytesRead == 0);
                BadRequest(because, "a chunked body over 64 KB with no length", outcome.Streamed);
                BadRequest(because, "a body that isn't application/json", outcome.PlainText);
                BadRequest(because, "malformed JSON", outcome.Malformed);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void KeepHandlesPrivateAtSignIn()
    {
        When.A<AccountHost>("begins sign-in by handle on a host that keeps handles private",
            () => new AccountHost(site => site.SignUp.AllowHandleAvailabilityCheck = false),
            (closed) =>
            {
                AccountHost open = new AccountHost();
                try
                {
                    SyntheticAuthenticator alice = new SyntheticAuthenticator();
                    closed.SignUp("alice", "Alice Example", alice);
                    open.SignUp("alice", "Alice Example", new SyntheticAuthenticator());
                    RequestOptionsResponse taken = closed.Post("/account/passkey/assertion/begin", new AssertionBeginRequest { Handle = "alice" }).As<RequestOptionsResponse>();
                    RequestOptionsResponse unused = closed.Post("/account/passkey/assertion/begin", new AssertionBeginRequest { Handle = "nobody-here" }).As<RequestOptionsResponse>();
                    RequestOptionsResponse openTaken = open.Post("/account/passkey/assertion/begin", new AssertionBeginRequest { Handle = "alice" }).As<RequestOptionsResponse>();
                    AccountReply signIn = closed.SignIn(alice, "alice");
                    return new PrivateHandleOutcome(taken.Options.AllowCredentials.Count, unused.Options.AllowCredentials.Count, openTaken.Options.AllowCredentials.Count, signIn);
                }
                finally
                {
                    open.Dispose();
                    closed.Dispose();
                }
            })
            .TheTest
            .ShouldPass<PrivateHandleOutcome>((because, outcome) =>
            {
                because.ItsTrue($"a taken handle and an unused one get the same options ({outcome.TakenDescriptors}, {outcome.UnusedDescriptors})", outcome.TakenDescriptors == 0 && outcome.UnusedDescriptors == 0);
                because.ItsTrue($"a host that publishes handles still scopes sign-in to the handle ({outcome.OpenDescriptors})", outcome.OpenDescriptors == 1);
                because.ItsTrue($"and the person still signs in with the discoverable ceremony ({outcome.SignIn.Status}: {outcome.SignIn.Body})", outcome.SignIn.Status == HttpStatusCode.OK && outcome.SignIn.SessionCookie is not null);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void FinishAProfileThatWasNotSavedFromWhatThePersonEnters()
    {
        When.A<AccountHost>("signs a person up while the profile store is down, on a host that requires email",
            () => new AccountHost(site => site.SignUp.RequireEmail = true),
            (host) =>
            {
                try
                {
                    host.Fixture.RegisterPersonThrows = new InvalidOperationException("store is down");
                    AccountReply signedUp = host.SignUp("alice", "Alice Example", new SyntheticAuthenticator(), email: "alice@example.com");
                    host.Fixture.RegisterPersonThrows = null;
                    string? cookie = signedUp.SessionCookie;
                    AccountReply anonymous = host.Post("/account/profile", new ProfileRequest { DisplayName = "Alice Example", Email = "alice@example.com" });
                    AccountReply pageBefore = host.Get("/account", cookie);
                    int personsAfterPage = host.Fixture.RegisteredPersons.Count;
                    AccountReply withoutEmail = host.Post("/account/profile", new ProfileRequest { DisplayName = "Alice Example" }, cookie);
                    int personsAfterRefusal = host.Fixture.RegisteredPersons.Count;
                    AccountReply saved = host.Post("/account/profile", new ProfileRequest { DisplayName = "Alice Example", Email = "alice@example.com" }, cookie);
                    AccountReply pageAfter = host.Get("/account", cookie);
                    return new ProfileOutcome(host.Fixture, signedUp, anonymous, pageBefore, personsAfterPage, withoutEmail, personsAfterRefusal, saved, pageAfter);
                }
                finally
                {
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<ProfileOutcome>((because, outcome) =>
            {
                because.ItsTrue($"the sign-up keeps the passkey without a profile ({outcome.SignedUp.Status})", outcome.SignedUp.Status == HttpStatusCode.OK && !outcome.SignedUp.As<SignedInResponse>().ProfileCreated);
                because.ItsTrue($"without a session the profile endpoint is 401 ({outcome.Anonymous.Status})", outcome.Anonymous.Status == HttpStatusCode.Unauthorized);
                because.ItsTrue("the manage page asks for the details", outcome.PageBefore.Status == HttpStatusCode.OK && outcome.PageBefore.Body.Contains("id=\"account-profile\"", StringComparison.Ordinal));
                because.ItsTrue("and writes nothing on its own", outcome.PersonsAfterPage == 0);
                because.ItsTrue($"a profile without the required email is refused ({outcome.WithoutEmail.Status} {outcome.WithoutEmail.ErrorCode})",
                    outcome.WithoutEmail.Status == HttpStatusCode.BadRequest && outcome.WithoutEmail.ErrorCode == AccountErrorCodes.EmailRequired && outcome.PersonsAfterRefusal == 0);
                because.ItsTrue($"the details the person enters are saved ({outcome.Saved.Status})", outcome.Saved.Status == HttpStatusCode.NoContent && outcome.Fixture.RegisteredPersons.Count == 1 && outcome.Fixture.RegisteredPersons[0].Email == "alice@example.com");
                because.ItsTrue("and the page stops asking", outcome.PageAfter.Status == HttpStatusCode.OK && !outcome.PageAfter.Body.Contains("id=\"account-profile\"", StringComparison.Ordinal));
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    private static void BadRequest(Because because, string what, AccountReply reply)
    {
        because.ItsTrue($"{what} is refused ({reply.Status} {reply.ErrorCode})", reply.Status == HttpStatusCode.BadRequest && reply.ErrorCode == AccountErrorCodes.BadRequest);
    }

    private sealed record BodyOutcome(AccountReply Accepted, AccountReply Declared, long DeclaredBytesRead, AccountReply Streamed, AccountReply PlainText, AccountReply Malformed);

    private sealed record PrivateHandleOutcome(int TakenDescriptors, int UnusedDescriptors, int OpenDescriptors, AccountReply SignIn);

    private sealed record ProfileOutcome(SignUpFixture Fixture, AccountReply SignedUp, AccountReply Anonymous, AccountReply PageBefore, int PersonsAfterPage, AccountReply WithoutEmail,
        int PersonsAfterRefusal, AccountReply Saved, AccountReply PageAfter);
}
