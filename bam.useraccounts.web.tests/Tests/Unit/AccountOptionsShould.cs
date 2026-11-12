using System.Security.Claims;
using Bam.DependencyInjection;
using Bam.Test;
using Bam.UserAccounts.Passkeys;
using Bam.UserAccounts.Tests.TestClasses;
using Bam.UserAccounts.Web.Tests.TestClasses;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Bam.UserAccounts.Web.Tests.Unit;

[UnitTestMenu("AccountOptions Should", Selector = "acop")]
public class AccountOptionsShould : UnitTestMenuContainer
{
    public AccountOptionsShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    [UnitTest]
    public void RefuseSettingsAHostCannotRunWith()
    {
        When.A<List<string>>("validates options with one unusable setting each",
            () => new List<string>(),
            (problems) =>
            {
                problems.Add(Problem(site => { }));
                problems.Add(Problem(site => site.ProductName = "  "));
                problems.Add(Problem(site => site.LogoUrl = "javascript:alert(1)"));
                problems.Add(Problem(site => site.TermsUrl = "//evil.example/terms"));
                problems.Add(Problem(site => site.PrivacyUrl = "https://lumberjack.live/privacy"));
                problems.Add(Problem(site => site.SupportEmail = "not an address"));
                problems.Add(Problem(site => site.DefaultReturnUrl = "https://evil.example/"));
                problems.Add(Problem(site => site.SignedOutUrl = "/\\evil.example"));
                problems.Add(Problem(site => site.Theme.Primary = "red; background: url(https://evil.example/x)"));
                problems.Add(Problem(site => site.Strings.SignInTitle = null!));
                problems.Add(Problem(site => site.Slots.Hero = typeof(string)));
                problems.Add(Problem(site => site.Cookie.SessionLifetime = TimeSpan.Zero));
                problems.Add(Problem(site => site.Cookie.SameSite = SameSiteMode.None));
                problems.Add(Problem(site => site.RateLimits.PermitLimit = 0));
                problems.Add(Problem(site => site.SignUp.HandlePattern = "("));
                return problems;
            })
            .TheTest
            .ShouldPass<List<string>>((because, problems) =>
            {
                because.ItsTrue($"options with only a product name are usable ({problems[0]})", problems[0].Length == 0);
                because.ItsTrue("a blank product name is refused", problems[1].Contains("ProductName", StringComparison.Ordinal));
                because.ItsTrue("a logo URL that is not http(s) or a local path is refused", problems[2].Contains("LogoUrl", StringComparison.Ordinal));
                because.ItsTrue("a scheme-relative terms URL is refused", problems[3].Contains("TermsUrl", StringComparison.Ordinal));
                because.ItsTrue($"an absolute https privacy URL is accepted ({problems[4]})", problems[4].Length == 0);
                because.ItsTrue("a support address that is not an email is refused", problems[5].Contains("SupportEmail", StringComparison.Ordinal));
                because.ItsTrue("a default return URL on another site is refused", problems[6].Contains("DefaultReturnUrl", StringComparison.Ordinal));
                because.ItsTrue("a signed-out URL a browser would read as another site is refused", problems[7].Contains("SignedOutUrl", StringComparison.Ordinal));
                because.ItsTrue("a theme value that starts another declaration is refused", problems[8].Contains("AccountTheme.Primary", StringComparison.Ordinal));
                because.ItsTrue("a null string is refused by name", problems[9].Contains("AccountStrings.SignInTitle", StringComparison.Ordinal));
                because.ItsTrue("a slot that is not a component is refused", problems[10].Contains("AccountSlots.Hero", StringComparison.Ordinal));
                because.ItsTrue("a zero session lifetime is refused", problems[11].Contains("SessionLifetime", StringComparison.Ordinal));
                because.ItsTrue("SameSite=None is refused", problems[12].Contains("SameSite", StringComparison.Ordinal));
                because.ItsTrue("a zero permit limit is refused", problems[13].Contains("PermitLimit", StringComparison.Ordinal));
                because.ItsTrue("an invalid handle pattern is refused", problems[14].Contains("HandlePattern", StringComparison.Ordinal));
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void DefaultToAnUnbrandedThemeAndASafeCookie()
    {
        When.A<AccountSiteOptions>("is left at its defaults",
            () => new AccountSiteOptions { ProductName = "Lumberjack" },
            (site) =>
            {
                AccountTheme themed = new AccountTheme { Primary = " #0a5d2e ", Radius = "0.25rem", Font = "Inter, sans-serif" };
                return new DefaultsOutcome(site, site.Theme.ToStyleAttribute(), themed.ToStyleAttribute(), AccountClientConfig.For(site));
            })
            .TheTest
            .ShouldPass<DefaultsOutcome>((because, outcome) =>
            {
                AccountSiteOptions site = outcome.Site;
                because.ItsTrue("no parent-brand line by default", site.Branding == BrandingTier.None);
                because.ItsTrue("an unset theme declares nothing", outcome.DefaultStyle.Length == 0);
                because.ItsTrue($"a theme declares its set properties, trimmed ({outcome.ThemedStyle})", outcome.ThemedStyle == "--account-primary:#0a5d2e;--account-radius:0.25rem;--account-font:Inter, sans-serif;");
                because.ItsTrue("sessions last 14 days, slide, and are rechecked every 5 minutes", site.Cookie.SessionLifetime == TimeSpan.FromDays(14) && site.Cookie.SlidingExpiration && site.Cookie.RevalidateEvery == TimeSpan.FromMinutes(5));
                because.ItsTrue("the cookie is SameSite=Lax", site.Cookie.SameSite == SameSiteMode.Lax);
                because.ItsTrue("rate limits are on: 10 and 30 a minute", site.RateLimits.Enabled && site.RateLimits.PermitLimit == 10 && site.RateLimits.AvailabilityPermitLimit == 30 && site.RateLimits.Window == TimeSpan.FromMinutes(1));
                because.ItsTrue("people land on the manage page", site.DefaultReturnUrl == "/account" && site.SignedOutUrl == "/account/signedout");
                because.ItsTrue("the browser module is told the host's wording, and not where to send requests", outcome.Client.Availability && outcome.Client.Messages["signInFailed"] == site.Strings.SignInFailedMessage
                    && !outcome.Client.ToJson().Contains("prefix", StringComparison.OrdinalIgnoreCase) && !outcome.Client.ToJson().Contains("header", StringComparison.OrdinalIgnoreCase));
                because.ItsTrue("local paths are told from other sites' URLs", AccountRoutes.IsLocalPath("/app?x=1") && !AccountRoutes.IsLocalPath("//evil.example") && !AccountRoutes.IsLocalPath("/\\evil.example") && !AccountRoutes.IsLocalPath("https://evil.example") && !AccountRoutes.IsLocalPath("app") && !AccountRoutes.IsLocalPath(null) && !AccountRoutes.IsLocalPath("/a\nb"));
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void BuildAPrincipalOnlyFromAVerifiedResult()
    {
        When.A<PasskeySignInResult>("is turned into a session principal",
            () => new PasskeySignInResult { Success = true, PersonHandle = "alice", CredentialId = "cred-a1", KeyFingerprint = "fp-a1" },
            (signedIn) =>
            {
                ClaimsPrincipal? fromSignIn = AccountPrincipal.From(signedIn);
                ClaimsPrincipal? fromSignUp = AccountPrincipal.From(new PasskeySignUpResult { Success = true, PersonHandle = "bob", DisplayName = " Bob Example ", CredentialId = "cred-b1", KeyFingerprint = "fp-b1" });
                ClaimsPrincipal? fromFailure = AccountPrincipal.From(new PasskeySignInResult { Success = false, PersonHandle = "alice", CredentialId = "cred-a1" });
                ClaimsPrincipal? fromFailedSignUp = AccountPrincipal.From(new PasskeySignUpResult { Success = false, PersonHandle = "bob", CredentialId = "cred-b1" });
                ClaimsPrincipal? withoutCredential = AccountPrincipal.From(new PasskeySignInResult { Success = true, PersonHandle = "alice" });
                ClaimsPrincipal otherScheme = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim> { new Claim(AccountClaims.Handle, "mallory"), new Claim(AccountClaims.CredentialId, "cred-m1") }, "SomeOtherScheme"));
                ClaimsPrincipal unauthenticated = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim> { new Claim(AccountClaims.Handle, "mallory") }));
                return new PrincipalOutcome(fromSignIn, fromSignUp, fromFailure, fromFailedSignUp, withoutCredential, AccountPrincipal.Handle(otherScheme), AccountPrincipal.Handle(unauthenticated));
            })
            .TheTest
            .ShouldPass<PrincipalOutcome>((because, outcome) =>
            {
                because.ItsTrue("a verified sign-in yields an authenticated principal under the account scheme", outcome.FromSignIn?.Identity?.IsAuthenticated == true && outcome.FromSignIn.Identity.AuthenticationType == AccountCookieOptions.Scheme);
                because.ItsTrue("carrying the handle, credential id and fingerprint", AccountPrincipal.Handle(outcome.FromSignIn) == "alice" && AccountPrincipal.CredentialId(outcome.FromSignIn) == "cred-a1" && outcome.FromSignIn?.FindFirst(AccountClaims.KeyFingerprint)?.Value == "fp-a1");
                because.ItsTrue("marked as a passkey authentication with its time", outcome.FromSignIn?.FindFirst(AccountClaims.AuthenticationMethod)?.Value == "passkey" && long.TryParse(outcome.FromSignIn.FindFirst(AccountClaims.AuthenticationTime)?.Value, out long _));
                because.ItsTrue("the handle stands in for a display name that is not known", AccountPrincipal.DisplayName(outcome.FromSignIn) == "alice");
                because.ItsTrue("a completed sign-up carries the person's display name", AccountPrincipal.Handle(outcome.FromSignUp) == "bob" && AccountPrincipal.DisplayName(outcome.FromSignUp) == "Bob Example");
                because.ItsTrue($"the identity's name is the handle, never the name the person typed ({outcome.FromSignUp?.Identity?.Name}, {outcome.FromSignIn?.Identity?.Name})",
                    outcome.FromSignUp?.Identity?.Name == "bob" && outcome.FromSignIn?.Identity?.Name == "alice");
                because.ItsTrue("a failed sign-in yields no principal", outcome.FromFailure is null);
                because.ItsTrue("a failed sign-up yields no principal", outcome.FromFailedSignUp is null);
                because.ItsTrue("a result without a credential id yields no principal", outcome.WithoutCredential is null);
                because.ItsTrue("a handle claim under another scheme is not read as an account handle", outcome.OtherSchemeHandle is null);
                because.ItsTrue("nor is one on an unauthenticated identity", outcome.UnauthenticatedHandle is null);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void NameEveryMissingBindingAtStartup()
    {
        When.A<SignUpFixture>("backs a host whose registry lacks what the template needs",
            () => new SignUpFixture(),
            (fixture) =>
            {
                string notRegistered = Startup(null, fixture);
                ServiceRegistry empty = new ServiceRegistry();
                empty.For<IConfirmationChallengeRepository>().UseSingleton(fixture.Passkeys.Challenges);
                empty.For<IPasskeyCredentialRepository>().UseSingleton(fixture.Passkeys.Credentials);
                string missing = Startup(empty, fixture);
                string complete = Startup(AccountHost.BindHostServices(new ServiceRegistry(), fixture), fixture);
                return new StartupOutcome(notRegistered, missing, complete);
            })
            .TheTest
            .ShouldPass<StartupOutcome>((because, outcome) =>
            {
                because.ItsTrue($"a host that never registered the template is told to ({outcome.NotRegistered})", outcome.NotRegistered.Contains("AddPasskeyAccounts", StringComparison.Ordinal));
                because.ItsTrue($"every missing binding is named in one message ({outcome.Missing})", outcome.Missing.Contains("IPublicKeySetRegistrar", StringComparison.Ordinal) && outcome.Missing.Contains("IUserAccountService", StringComparison.Ordinal) && outcome.Missing.Contains("IProfileRepository", StringComparison.Ordinal));
                because.ItsTrue($"a complete registry passes ({outcome.Complete})", outcome.Complete.Length == 0);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    private static string Problem(Action<AccountSiteOptions> change)
    {
        AccountSiteOptions site = new AccountSiteOptions { ProductName = "Lumberjack" };
        change(site);
        try
        {
            site.Validate();
            return string.Empty;
        }
        catch (Exception e) when (e is InvalidOperationException || e is ArgumentException)
        {
            return e.Message;
        }
    }

    private static string Startup(ServiceRegistry? registry, SignUpFixture fixture)
    {
        ServiceCollection services = new ServiceCollection();
        services.AddLogging();
        try
        {
            if (registry is not null)
            {
                services.AddPasskeyAccounts(registry, new AccountSiteOptions { ProductName = "Lumberjack" }, PasskeyFixture.DefaultOptions());
            }
            using ServiceProvider provider = services.BuildServiceProvider();
            AccountWebRegistration.VerifyPrerequisites(provider);
            return string.Empty;
        }
        catch (InvalidOperationException e)
        {
            return e.Message;
        }
    }

    private sealed record DefaultsOutcome(AccountSiteOptions Site, string DefaultStyle, string ThemedStyle, AccountClientConfig Client);

    private sealed record PrincipalOutcome(ClaimsPrincipal? FromSignIn, ClaimsPrincipal? FromSignUp, ClaimsPrincipal? FromFailure, ClaimsPrincipal? FromFailedSignUp, ClaimsPrincipal? WithoutCredential, string? OtherSchemeHandle, string? UnauthenticatedHandle);

    private sealed record StartupOutcome(string NotRegistered, string Missing, string Complete);
}
