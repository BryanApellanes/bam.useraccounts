namespace Bam.UserAccounts.Web;

/// <summary>
/// The account pages' and endpoints' paths.  The prefix is fixed: the pages are routable
/// components whose routes are compiled in, so a host cannot move them by configuration.
/// </summary>
public static class AccountRoutes
{
    /// <summary>The path every account page and endpoint lives under.</summary>
    public const string Prefix = "/account";

    /// <summary>The manage-passkeys page.</summary>
    public const string Manage = Prefix;

    /// <summary>The sign-up page.</summary>
    public const string SignUp = Prefix + "/signup";

    /// <summary>The sign-in page.</summary>
    public const string SignIn = Prefix + "/signin";

    /// <summary>The page shown after signing out.</summary>
    public const string SignedOut = Prefix + "/signedout";

    /// <summary>The browser module, as served from the class library's static web assets.</summary>
    public const string Module = "/_content/bam.useraccounts.web/passkeys.js";

    /// <summary>The class library's stylesheet.</summary>
    public const string Stylesheet = "/_content/bam.useraccounts.web/account.css";

    /// <summary>
    /// The header every state-changing account request must carry (any non-empty value).  A
    /// browser cannot add a custom header to a cross-site request without a CORS preflight the
    /// host never grants, so its presence shows the request came from the site's own script or
    /// from a non-browser client.
    /// </summary>
    public const string RequestHeader = "X-Bam-Account";

    /// <summary>
    /// Whether <paramref name="url"/> is a path on this site: starts with one slash, and is not a
    /// scheme-relative (<c>//host</c>) or backslash form a browser would read as another site.
    /// </summary>
    /// <param name="url">The candidate.</param>
    /// <returns>True when a redirect to it stays on this site.</returns>
    public static bool IsLocalPath(string? url)
    {
        if (string.IsNullOrEmpty(url) || url[0] != '/')
        {
            return false;
        }
        if (url.Length > 1 && (url[1] == '/' || url[1] == '\\'))
        {
            return false;
        }
        foreach (char character in url)
        {
            if (char.IsControl(character) || character == '\\')
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>Returns <paramref name="url"/> when it is a local path, otherwise <paramref name="fallback"/>.</summary>
    /// <param name="url">The requested destination, typically a <c>returnUrl</c> query value.</param>
    /// <param name="fallback">The destination to use instead.</param>
    /// <returns>A local path.</returns>
    public static string LocalOr(string? url, string fallback)
    {
        return IsLocalPath(url) ? url! : fallback;
    }
}
