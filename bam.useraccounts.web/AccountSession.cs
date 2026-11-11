using System.Globalization;
using System.Security.Claims;
using Bam.Logging;
using Bam.UserAccounts.Passkeys;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;

namespace Bam.UserAccounts.Web;

/// <summary>
/// Issues and clears the account session cookie, and revalidates a session against the
/// credential store so removing a passkey ends the sessions opened with it.
/// </summary>
public sealed class AccountSession
{
    private const string ValidatedItem = "bam.account.validated";

    private readonly IPasskeyCredentialRepository _credentials;
    private readonly AccountSiteOptions _site;

    /// <summary>Initializes the session over passkey custody and the host's options.</summary>
    /// <param name="credentials">Passkey custody.</param>
    /// <param name="site">The host's account options.</param>
    public AccountSession(IPasskeyCredentialRepository credentials, AccountSiteOptions site)
    {
        _credentials = credentials;
        _site = site;
    }

    /// <summary>Issues the session cookie for a principal built by <see cref="AccountPrincipal"/>.</summary>
    /// <param name="context">The current request.</param>
    /// <param name="principal">The verified person.</param>
    public Task SignInAsync(HttpContext context, ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(principal);
        if (AccountPrincipal.Handle(principal) is null || AccountPrincipal.CredentialId(principal) is null)
        {
            throw new ArgumentException("The principal is not an account principal: it carries no handle or credential id.", nameof(principal));
        }
        AuthenticationProperties properties = new AuthenticationProperties { IsPersistent = true, AllowRefresh = _site.Cookie.SlidingExpiration };
        properties.Items[ValidatedItem] = Stamp(DateTimeOffset.UtcNow);
        Log.Info("Account session opened for {0}", AccountPrincipal.Handle(principal)!);
        return context.SignInAsync(AccountCookieOptions.Scheme, principal, properties);
    }

    /// <summary>Clears the session cookie.</summary>
    /// <param name="context">The current request.</param>
    public Task SignOutAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.SignOutAsync(AccountCookieOptions.Scheme);
    }

    /// <summary>
    /// The cookie handler's validation hook.  At most once per
    /// <see cref="AccountCookieOptions.RevalidateEvery"/>, the session's passkey is looked up; a
    /// session whose passkey is gone, pending, or belongs to someone else is rejected and its
    /// cookie cleared.
    /// </summary>
    /// <param name="context">The cookie validation context.</param>
    public async Task ValidateAsync(CookieValidatePrincipalContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        string? handle = AccountPrincipal.Handle(context.Principal);
        string? credentialId = AccountPrincipal.CredentialId(context.Principal);
        if (handle is null || credentialId is null)
        {
            await RejectAsync(context);
            return;
        }
        DateTimeOffset now = DateTimeOffset.UtcNow;
        TimeSpan interval = _site.Cookie.RevalidateEvery;
        if (interval > TimeSpan.Zero && LastValidated(context.Properties) is DateTimeOffset last && now >= last && now - last < interval)
        {
            return;
        }
        if (!StillHeld(handle, credentialId))
        {
            Log.Info("Account session of {0} ended: its passkey is no longer registered", handle);
            await RejectAsync(context);
            return;
        }
        if (interval > TimeSpan.Zero)
        {
            context.Properties.Items[ValidatedItem] = Stamp(now);
            context.ShouldRenew = true;
        }
    }

    /// <summary>Whether a person still holds an active passkey with this credential id.</summary>
    /// <param name="personHandle">The session's handle.</param>
    /// <param name="credentialId">The session's credential id.</param>
    public bool StillHeld(string personHandle, string credentialId)
    {
        PasskeyCredentialData? credential = _credentials.FindByCredentialId(credentialId);
        return credential is not null && !credential.Pending && string.Equals(credential.PersonHandle, personHandle, StringComparison.Ordinal);
    }

    private static async Task RejectAsync(CookieValidatePrincipalContext context)
    {
        context.RejectPrincipal();
        await context.HttpContext.SignOutAsync(AccountCookieOptions.Scheme);
    }

    private static DateTimeOffset? LastValidated(AuthenticationProperties properties)
    {
        if (properties.Items.TryGetValue(ValidatedItem, out string? text)
            && long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out long seconds))
        {
            return DateTimeOffset.FromUnixTimeSeconds(seconds);
        }
        return null;
    }

    private static string Stamp(DateTimeOffset moment)
    {
        return moment.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
    }
}
