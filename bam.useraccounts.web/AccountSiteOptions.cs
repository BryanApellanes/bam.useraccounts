using Bam.UserAccounts.Passkeys;

namespace Bam.UserAccounts.Web;

/// <summary>Which parent-brand line the account pages carry in their footer.</summary>
public enum BrandingTier
{
    /// <summary>No parent-brand line.</summary>
    None = 0,

    /// <summary>"A Three Headz company".</summary>
    ThreeHeadzCompany,

    /// <summary>"A Three Headz platform".</summary>
    ThreeHeadzPlatform
}

/// <summary>
/// Everything a host brands or toggles on the passkey account pages: names, links, theme, copy,
/// slot components, the session cookie, rate limits and the sign-up policy.  One instance per
/// host, passed to <see cref="AccountWebRegistration.AddPasskeyAccounts"/>.
/// </summary>
public sealed class AccountSiteOptions
{
    /// <summary>The product name shown on every account page.  Required.</summary>
    public string ProductName { get; set; } = null!;

    /// <summary>Logo image URL (absolute http(s) or root-relative), or null for the product name alone.</summary>
    public string? LogoUrl { get; set; }

    /// <summary>A short line under the product name, or null.</summary>
    public string? Tagline { get; set; }

    /// <summary>A support address shown on the pages, or null.</summary>
    public string? SupportEmail { get; set; }

    /// <summary>Terms of service URL (absolute http(s) or root-relative), or null.</summary>
    public string? TermsUrl { get; set; }

    /// <summary>Privacy policy URL (absolute http(s) or root-relative), or null.</summary>
    public string? PrivacyUrl { get; set; }

    /// <summary>The parent-brand line in the footer.  Defaults to none.</summary>
    public BrandingTier Branding { get; set; } = BrandingTier.None;

    /// <summary>Where a person lands after signing in or signing up when nothing else names a destination.  Root-relative; defaults to the manage page.</summary>
    public string DefaultReturnUrl { get; set; } = AccountRoutes.Manage;

    /// <summary>Where a person lands after signing out.  Root-relative; defaults to the signed-out page.</summary>
    public string SignedOutUrl { get; set; } = AccountRoutes.SignedOut;

    /// <summary>Colours, radius and font, emitted as CSS custom properties.</summary>
    public AccountTheme Theme { get; set; } = new AccountTheme();

    /// <summary>Every visible string, with English defaults.</summary>
    public AccountStrings Strings { get; set; } = new AccountStrings();

    /// <summary>Host components rendered inside the pages.</summary>
    public AccountSlots Slots { get; set; } = new AccountSlots();

    /// <summary>The session cookie.</summary>
    public AccountCookieOptions Cookie { get; set; } = new AccountCookieOptions();

    /// <summary>Rate limits on the anonymous endpoints.</summary>
    public AccountRateLimitOptions RateLimits { get; set; } = new AccountRateLimitOptions();

    /// <summary>Who may sign up and what a handle looks like.</summary>
    public SignUpPolicy SignUp { get; set; } = new SignUpPolicy();

    /// <summary>Throws <see cref="InvalidOperationException"/> naming the first setting that is not usable.</summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(ProductName))
        {
            throw new InvalidOperationException("AccountSiteOptions.ProductName is required.");
        }
        RequireLink(nameof(LogoUrl), LogoUrl);
        RequireLink(nameof(TermsUrl), TermsUrl);
        RequireLink(nameof(PrivacyUrl), PrivacyUrl);
        if (SupportEmail is not null && !SignUpPolicy.IsPlausibleEmail(SupportEmail))
        {
            throw new InvalidOperationException("AccountSiteOptions.SupportEmail is not an email address.");
        }
        if (!AccountRoutes.IsLocalPath(DefaultReturnUrl))
        {
            throw new InvalidOperationException("AccountSiteOptions.DefaultReturnUrl must be a root-relative path such as \"/account\".");
        }
        if (!AccountRoutes.IsLocalPath(SignedOutUrl))
        {
            throw new InvalidOperationException("AccountSiteOptions.SignedOutUrl must be a root-relative path such as \"/account/signedout\".");
        }
        (Theme ?? throw new InvalidOperationException("AccountSiteOptions.Theme is required.")).Validate();
        (Strings ?? throw new InvalidOperationException("AccountSiteOptions.Strings is required.")).Validate();
        (Slots ?? throw new InvalidOperationException("AccountSiteOptions.Slots is required.")).Validate();
        (Cookie ?? throw new InvalidOperationException("AccountSiteOptions.Cookie is required.")).Validate();
        (RateLimits ?? throw new InvalidOperationException("AccountSiteOptions.RateLimits is required.")).Validate();
        (SignUp ?? throw new InvalidOperationException("AccountSiteOptions.SignUp is required.")).Validate();
    }

    private static void RequireLink(string name, string? value)
    {
        if (value is null)
        {
            return;
        }
        if (AccountRoutes.IsLocalPath(value))
        {
            return;
        }
        if (Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp))
        {
            return;
        }
        throw new InvalidOperationException($"AccountSiteOptions.{name} must be an absolute http(s) URL or a root-relative path.");
    }
}
