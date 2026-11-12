using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// A host's policy for who may sign up and what a handle looks like.  Bound as a singleton by
/// <see cref="PasskeySignUpServiceRegistration.AddPasskeySignUp"/> and applied by
/// <see cref="PasskeySignUp"/> at both the begin and the complete step, so no step of a sign-up
/// can be reached around it.
/// </summary>
public sealed class SignUpPolicy
{
    /// <summary>The default handle pattern: 3 to 32 lowercase letters, digits and hyphens, starting with a letter or digit.</summary>
    public const string DefaultHandlePattern = "^[a-z0-9][a-z0-9-]{2,31}$";

    /// <summary>The longest display name kept; longer names are truncated.</summary>
    public const int MaxDisplayNameLength = 100;

    /// <summary>The longest email address accepted (RFC 5321 path limit).</summary>
    public const int MaxEmailLength = 254;

    private static readonly TimeSpan PatternTimeout = TimeSpan.FromMilliseconds(250);

    /// <summary>Whether anyone may sign up.  When false, only a caller presenting one of <see cref="InviteCodes"/> may; with no invite codes sign-up is closed.</summary>
    public bool OpenSignUp { get; set; } = true;

    /// <summary>The invite codes accepted while <see cref="OpenSignUp"/> is false.  Codes are not consumed by use; the host removes one to retire it.</summary>
    public List<string> InviteCodes { get; set; } = new List<string>();

    /// <summary>Whether a sign-up must carry an email address.</summary>
    public bool RequireEmail { get; set; }

    /// <summary>The regular expression a normalized (trimmed, lowercased) handle must match in full.</summary>
    public string HandlePattern { get; set; } = DefaultHandlePattern;

    /// <summary>
    /// Prefixes no handle may start with.  The default keeps handles out of the passkey ceremony's
    /// <c>passkey-*</c> challenge-key namespace.
    /// </summary>
    public List<string> ReservedHandlePrefixes { get; set; } = new List<string> { "passkey-" };

    /// <summary>
    /// Whether an anonymous caller may ask if a handle is free before creating a passkey.  On by
    /// default: a handle is a public identifier, and learning that it is taken only at completion
    /// would leave an orphan passkey in the visitor's authenticator.  Turn off for hosts that
    /// treat handles as private; the ceremony itself never discloses.
    /// </summary>
    public bool AllowHandleAvailabilityCheck { get; set; } = true;

    /// <summary>Throws when the policy cannot be applied.</summary>
    /// <exception cref="ArgumentException">The handle pattern is blank or not a valid regular expression, or a reserved prefix or invite code is blank.</exception>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(HandlePattern))
        {
            throw new ArgumentException("SignUpPolicy.HandlePattern is required.");
        }
        try
        {
            Regex.Match(string.Empty, HandlePattern, RegexOptions.CultureInvariant, PatternTimeout);
        }
        catch (ArgumentException e)
        {
            throw new ArgumentException("SignUpPolicy.HandlePattern is not a valid regular expression: " + e.Message, e);
        }
        if (ReservedHandlePrefixes is null || ReservedHandlePrefixes.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("SignUpPolicy.ReservedHandlePrefixes must not contain a blank prefix.");
        }
        if (InviteCodes is null || InviteCodes.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("SignUpPolicy.InviteCodes must not contain a blank code.");
        }
    }

    /// <summary>Trims and lowercases a handle the way every policy check and the stored handle see it.</summary>
    /// <param name="handle">The handle as typed.</param>
    /// <returns>The normalized handle; empty for null.</returns>
    public static string NormalizeHandle(string? handle)
    {
        return (handle ?? string.Empty).Trim().ToLowerInvariant();
    }

    /// <summary>Whether a normalized handle matches <see cref="HandlePattern"/> in full and starts with no reserved prefix.</summary>
    /// <param name="handle">The normalized handle.</param>
    public bool IsHandleAcceptable(string? handle)
    {
        if (string.IsNullOrEmpty(handle))
        {
            return false;
        }
        if (ReservedHandlePrefixes.Any(prefix => handle.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }
        try
        {
            Match match = Regex.Match(handle, HandlePattern, RegexOptions.CultureInvariant, PatternTimeout);
            return match.Success && match.Index == 0 && match.Length == handle.Length;
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    /// <summary>
    /// Whether an invite code is one of <see cref="InviteCodes"/>.  Every code is compared, each in
    /// fixed time over SHA-256 digests, so the answer's timing reveals neither a code's length nor
    /// how much of it matched.
    /// </summary>
    /// <param name="code">The code presented, or null.</param>
    public bool AcceptsInvite(string? code)
    {
        byte[] presented = SHA256.HashData(Encoding.UTF8.GetBytes(code ?? string.Empty));
        bool accepted = false;
        foreach (string invite in InviteCodes)
        {
            byte[] expected = SHA256.HashData(Encoding.UTF8.GetBytes(invite));
            accepted |= CryptographicOperations.FixedTimeEquals(presented, expected);
        }
        return accepted && !string.IsNullOrEmpty(code);
    }

    /// <summary>
    /// Whether an email address is plausibly one: a local part, one <c>@</c>, a dotted domain, no
    /// whitespace, within <see cref="MaxEmailLength"/>.  Deliverability is the host's concern.
    /// </summary>
    /// <param name="email">The address to check.</param>
    public static bool IsPlausibleEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email) || email.Length > MaxEmailLength || email.Any(char.IsWhiteSpace))
        {
            return false;
        }
        int at = email.IndexOf('@');
        if (at <= 0 || at != email.LastIndexOf('@'))
        {
            return false;
        }
        string domain = email.Substring(at + 1);
        return domain.Length >= 3 && domain.Contains('.') && !domain.StartsWith('.') && !domain.EndsWith('.');
    }
}
