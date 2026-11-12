using Microsoft.AspNetCore.Http;

namespace Bam.UserAccounts.Web;

/// <summary>
/// The account session cookie.  It is always <c>HttpOnly</c> and <c>Secure</c>; these are the
/// settings a host may change.
/// </summary>
public sealed class AccountCookieOptions
{
    /// <summary>The authentication scheme the account session is issued under.</summary>
    public const string Scheme = "Bam.Account";

    /// <summary>The cookie's name.</summary>
    public string CookieName { get; set; } = ".Bam.Account";

    /// <summary>How long a session lasts without use.  Defaults to 14 days.</summary>
    public TimeSpan SessionLifetime { get; set; } = TimeSpan.FromDays(14);

    /// <summary>Whether use extends the session.  Defaults to true.</summary>
    public bool SlidingExpiration { get; set; } = true;

    /// <summary>
    /// How often a session's passkey is checked against the credential store.  A session whose
    /// passkey was removed ends at the first request after this interval.  Zero checks on every
    /// request.  Defaults to 5 minutes.
    /// </summary>
    public TimeSpan RevalidateEvery { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>The cookie's SameSite mode: <see cref="SameSiteMode.Lax"/> (default) or <see cref="SameSiteMode.Strict"/>.</summary>
    public SameSiteMode SameSite { get; set; } = SameSiteMode.Lax;

    /// <summary>Throws <see cref="InvalidOperationException"/> naming the first setting that is not usable.</summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(CookieName))
        {
            throw new InvalidOperationException("AccountCookieOptions.CookieName is required.");
        }
        if (SessionLifetime <= TimeSpan.Zero)
        {
            throw new InvalidOperationException("AccountCookieOptions.SessionLifetime must be positive.");
        }
        if (RevalidateEvery < TimeSpan.Zero)
        {
            throw new InvalidOperationException("AccountCookieOptions.RevalidateEvery must not be negative.");
        }
        if (SameSite != SameSiteMode.Lax && SameSite != SameSiteMode.Strict)
        {
            throw new InvalidOperationException("AccountCookieOptions.SameSite must be Lax or Strict: the session cookie is never sent on cross-site requests.");
        }
    }
}

/// <summary>Fixed-window, per-client-address limits on the anonymous account endpoints.</summary>
public sealed class AccountRateLimitOptions
{
    /// <summary>The rate-limiter policy on the sign-up and sign-in endpoints.</summary>
    public const string AnonymousPolicy = "account-anonymous";

    /// <summary>The rate-limiter policy on the handle availability check.</summary>
    public const string AvailabilityPolicy = "account-availability";

    /// <summary>Whether the limits apply.  Defaults to true; a host limiting at its proxy may turn them off.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Sign-up and sign-in requests allowed per client address per window.  Defaults to 10.</summary>
    public int PermitLimit { get; set; } = 10;

    /// <summary>Availability checks allowed per client address per window.  Defaults to 30.</summary>
    public int AvailabilityPermitLimit { get; set; } = 30;

    /// <summary>The window.  Defaults to one minute.</summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>Throws <see cref="InvalidOperationException"/> naming the first setting that is not usable.</summary>
    public void Validate()
    {
        if (PermitLimit < 1)
        {
            throw new InvalidOperationException("AccountRateLimitOptions.PermitLimit must be at least 1.");
        }
        if (AvailabilityPermitLimit < 1)
        {
            throw new InvalidOperationException("AccountRateLimitOptions.AvailabilityPermitLimit must be at least 1.");
        }
        if (Window <= TimeSpan.Zero)
        {
            throw new InvalidOperationException("AccountRateLimitOptions.Window must be positive.");
        }
    }
}
