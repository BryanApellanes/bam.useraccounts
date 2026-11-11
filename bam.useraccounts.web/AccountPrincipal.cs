using System.Globalization;
using System.Security.Claims;
using Bam.UserAccounts.Passkeys;

namespace Bam.UserAccounts.Web;

/// <summary>The claim types an account session carries.</summary>
public static class AccountClaims
{
    /// <summary>The person's handle.</summary>
    public const string Handle = "bam:account:handle";

    /// <summary>The person's display name.</summary>
    public const string DisplayName = "bam:account:name";

    /// <summary>Fingerprint of the passkey's public key.</summary>
    public const string KeyFingerprint = "bam:account:key";

    /// <summary>The credential id of the passkey the session was opened with, base64url.</summary>
    public const string CredentialId = "bam:account:credential";

    /// <summary>How the person authenticated; always <see cref="PasskeyMethod"/>.</summary>
    public const string AuthenticationMethod = "amr";

    /// <summary>When the person authenticated, seconds since the Unix epoch.</summary>
    public const string AuthenticationTime = "auth_time";

    /// <summary>The value of <see cref="AuthenticationMethod"/>.</summary>
    public const string PasskeyMethod = "passkey";
}

/// <summary>Builds the account session's principal from a verified ceremony, and reads it back.</summary>
public static class AccountPrincipal
{
    /// <summary>The principal for a verified sign-in, or null when the result is not a success.</summary>
    /// <param name="result">The ceremony's sign-in result.</param>
    /// <param name="displayName">The person's display name, when known; the handle is used otherwise.</param>
    /// <returns>An authenticated principal under <see cref="AccountCookieOptions.Scheme"/>, or null.</returns>
    public static ClaimsPrincipal? From(PasskeySignInResult? result, string? displayName = null)
    {
        if (result is null || !result.Success)
        {
            return null;
        }
        return Build(result.PersonHandle, displayName, result.CredentialId, result.KeyFingerprint);
    }

    /// <summary>The principal for a completed sign-up, or null when the result is not a success.</summary>
    /// <param name="result">The sign-up result.</param>
    /// <returns>An authenticated principal under <see cref="AccountCookieOptions.Scheme"/>, or null.</returns>
    public static ClaimsPrincipal? From(PasskeySignUpResult? result)
    {
        if (result is null || !result.Success)
        {
            return null;
        }
        return Build(result.PersonHandle, result.DisplayName, result.CredentialId, result.KeyFingerprint);
    }

    /// <summary>The handle of an account session's principal, or null when it is not one.</summary>
    /// <param name="principal">The request's user.</param>
    public static string? Handle(ClaimsPrincipal? principal)
    {
        return Read(principal, AccountClaims.Handle);
    }

    /// <summary>The credential id an account session was opened with, or null.</summary>
    /// <param name="principal">The request's user.</param>
    public static string? CredentialId(ClaimsPrincipal? principal)
    {
        return Read(principal, AccountClaims.CredentialId);
    }

    /// <summary>The display name of an account session's principal, falling back to its handle.</summary>
    /// <param name="principal">The request's user.</param>
    public static string? DisplayName(ClaimsPrincipal? principal)
    {
        return Read(principal, AccountClaims.DisplayName) ?? Handle(principal);
    }

    private static string? Read(ClaimsPrincipal? principal, string claimType)
    {
        if (principal is null)
        {
            return null;
        }
        foreach (ClaimsIdentity identity in principal.Identities)
        {
            if (identity.IsAuthenticated && string.Equals(identity.AuthenticationType, AccountCookieOptions.Scheme, StringComparison.Ordinal))
            {
                string? value = identity.FindFirst(claimType)?.Value;
                return string.IsNullOrEmpty(value) ? null : value;
            }
        }
        return null;
    }

    private static ClaimsPrincipal? Build(string? handle, string? displayName, string? credentialId, string? fingerprint)
    {
        if (string.IsNullOrWhiteSpace(handle) || string.IsNullOrWhiteSpace(credentialId))
        {
            return null;
        }
        string name = string.IsNullOrWhiteSpace(displayName) ? handle : displayName.Trim();
        List<Claim> claims = new List<Claim>
        {
            new Claim(AccountClaims.Handle, handle),
            new Claim(AccountClaims.DisplayName, name),
            new Claim(AccountClaims.CredentialId, credentialId),
            new Claim(AccountClaims.AuthenticationMethod, AccountClaims.PasskeyMethod),
            new Claim(AccountClaims.AuthenticationTime, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture))
        };
        if (!string.IsNullOrWhiteSpace(fingerprint))
        {
            claims.Add(new Claim(AccountClaims.KeyFingerprint, fingerprint));
        }
        ClaimsIdentity identity = new ClaimsIdentity(claims, AccountCookieOptions.Scheme, AccountClaims.DisplayName, ClaimTypes.Role);
        return new ClaimsPrincipal(identity);
    }
}
