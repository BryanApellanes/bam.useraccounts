using System.Net;
using Bam.DependencyInjection;
using Bam.Test;
using Bam.UserAccounts.Tests.TestClasses;
using Bam.UserAccounts.Web.Tests.TestClasses;

namespace Bam.UserAccounts.Web.Tests.Unit;

[UnitTestMenu("RazorClassLibrary Should", Selector = "acrl")]
public class RazorClassLibraryShould : UnitTestMenuContainer
{
    public RazorClassLibraryShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    [UnitTest]
    public void ServeItsPagesAndStaticAssetsFromAHost()
    {
        When.A<AccountHost>("hosts the class library's pages, browser module and stylesheet on Kestrel",
            () => new AccountHost(site =>
            {
                site.Tagline = "Logs, kept";
                site.TermsUrl = "/terms";
                site.Branding = BrandingTier.ThreeHeadzCompany;
                site.Strings.CreatePasskey = "Make my passkey";
                site.Theme.Primary = "#0a5d2e";
            }),
            (host) =>
            {
                try
                {
                    AccountReply signUp = host.Get("/account/signup");
                    AccountReply signIn = host.Get("/account/signin?returnUrl=%2Fapp%2Fstart");
                    AccountReply signInForeign = host.Get("/account/signin?returnUrl=https%3A%2F%2Fevil.example%2F");
                    AccountReply signedOut = host.Get("/account/signedout");
                    AccountReply manageAnonymous = host.Get("/account");
                    string cookie = host.SignUp("alice", "Alice <b>Example</b>", new SyntheticAuthenticator()).SessionCookie!;
                    AccountReply manage = host.Get("/account", cookie);
                    AccountReply module = host.Get("/_content/bam.useraccounts.web/passkeys.js");
                    AccountReply stylesheet = host.Get("/_content/bam.useraccounts.web/account.css");
                    return new PagesOutcome(signUp, signIn, signInForeign, signedOut, manageAnonymous, manage, module, stylesheet);
                }
                finally
                {
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<PagesOutcome>((because, outcome) =>
            {
                because.ItsTrue($"the sign-up page renders through the host router ({outcome.SignUp.Status})", outcome.SignUp.Status == HttpStatusCode.OK);
                because.ItsTrue("with the host's product name, tagline and wording", outcome.SignUp.Body.Contains("Lumberjack", StringComparison.Ordinal) && outcome.SignUp.Body.Contains("Logs, kept", StringComparison.Ordinal) && outcome.SignUp.Body.Contains("Make my passkey", StringComparison.Ordinal));
                because.ItsTrue("with the host's theme, terms link and parent-brand line", outcome.SignUp.Body.Contains("--account-primary:#0a5d2e;", StringComparison.Ordinal) && outcome.SignUp.Body.Contains("href=\"/terms\"", StringComparison.Ordinal) && outcome.SignUp.Body.Contains("A Three Headz company", StringComparison.Ordinal));
                because.ItsTrue("and it loads the module and hands it its settings", outcome.SignUp.Body.Contains("/_content/bam.useraccounts.web/passkeys.js", StringComparison.Ordinal) && outcome.SignUp.Body.Contains("data-account-config=", StringComparison.Ordinal) && outcome.SignUp.Body.Contains("data-account-action=\"register\"", StringComparison.Ordinal));
                because.ItsTrue($"the sign-in page renders ({outcome.SignIn.Status}) and carries a local return URL", outcome.SignIn.Status == HttpStatusCode.OK && outcome.SignIn.Body.Contains("data-account-return=\"/app/start\"", StringComparison.Ordinal));
                because.ItsTrue($"the sign-in page drops a return URL on another site ({outcome.SignInForeign.Status}: {Around(outcome.SignInForeign.Body, "evil.example")})", outcome.SignInForeign.Status == HttpStatusCode.OK && !outcome.SignInForeign.Body.Contains("evil.example", StringComparison.Ordinal));
                because.ItsTrue($"the signed-out page renders ({outcome.SignedOut.Status})", outcome.SignedOut.Status == HttpStatusCode.OK);
                because.ItsTrue($"the manage page sends an anonymous visitor to sign-in ({outcome.ManageAnonymous.Status} {outcome.ManageAnonymous.Location})",
                    outcome.ManageAnonymous.Status == HttpStatusCode.Redirect && (outcome.ManageAnonymous.Location ?? string.Empty).Contains("/account/signin?returnUrl=%2Faccount", StringComparison.Ordinal));
                because.ItsTrue($"the manage page renders for a session ({outcome.Manage.Status})", outcome.Manage.Status == HttpStatusCode.OK && outcome.Manage.Body.Contains("data-account-action=\"remove\"", StringComparison.Ordinal) && outcome.Manage.Body.Contains("data-account-action=\"signout\"", StringComparison.Ordinal));
                because.ItsTrue("and encodes the person's name", outcome.Manage.Body.Contains("Alice &lt;b&gt;Example&lt;/b&gt;", StringComparison.Ordinal) && !outcome.Manage.Body.Contains("<b>Example</b>", StringComparison.Ordinal));
                because.ItsTrue($"the module is served under _content as JavaScript ({outcome.Module.Status} {outcome.Module.MediaType})", outcome.Module.Status == HttpStatusCode.OK && outcome.Module.MediaType == "text/javascript" && outcome.Module.Body.Contains("export async function register", StringComparison.Ordinal));
                because.ItsTrue($"the stylesheet is served under _content ({outcome.Stylesheet.Status} {outcome.Stylesheet.MediaType})", outcome.Stylesheet.Status == HttpStatusCode.OK && outcome.Stylesheet.MediaType == "text/css" && outcome.Stylesheet.Body.Contains(".account-shell", StringComparison.Ordinal));
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void ShowNoSignUpFormWhenSignUpIsClosed()
    {
        When.A<AccountHost>("has sign-up closed with no invite codes",
            () => new AccountHost(site => site.SignUp.OpenSignUp = false),
            (host) =>
            {
                AccountHost invited = new AccountHost(site =>
                {
                    site.SignUp.OpenSignUp = false;
                    site.SignUp.InviteCodes.Add("welcome-2026");
                });
                try
                {
                    return new ClosedOutcome(host.Get("/account/signup"), invited.Get("/account/signup"), host.Site.Strings.SignUpClosed);
                }
                finally
                {
                    invited.Dispose();
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<ClosedOutcome>((because, outcome) =>
            {
                because.ItsTrue("a closed site says so and renders no form", outcome.Closed.Status == HttpStatusCode.OK && outcome.Closed.Body.Contains(outcome.ClosedMessage, StringComparison.Ordinal) && !outcome.Closed.Body.Contains("data-account-action=\"register\"", StringComparison.Ordinal));
                because.ItsTrue("an invite-only site renders the form with an invite field", outcome.Invited.Body.Contains("name=\"inviteCode\"", StringComparison.Ordinal) && outcome.Invited.Body.Contains("data-account-action=\"register\"", StringComparison.Ordinal));
                because.ItsTrue("and never renders an invite code", !outcome.Invited.Body.Contains("welcome-2026", StringComparison.Ordinal));
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    private static string Around(string body, string text)
    {
        int at = body.IndexOf(text, StringComparison.Ordinal);
        return at < 0 ? "absent" : body.Substring(Math.Max(0, at - 120), Math.Min(body.Length - Math.Max(0, at - 120), 240));
    }

    private sealed record PagesOutcome(AccountReply SignUp, AccountReply SignIn, AccountReply SignInForeign, AccountReply SignedOut, AccountReply ManageAnonymous, AccountReply Manage, AccountReply Module, AccountReply Stylesheet);

    private sealed record ClosedOutcome(AccountReply Closed, AccountReply Invited, string ClosedMessage);
}
