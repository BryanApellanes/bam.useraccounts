namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// What a sign-up form submits.  The same request accompanies both steps of a sign-up
/// (<see cref="IPasskeySignUp.Begin"/> and <see cref="IPasskeySignUp.Complete"/>) so the policy
/// is applied at each and nothing is held server-side between them except the ceremony's challenge.
/// </summary>
public sealed class PasskeySignUpRequest
{
    /// <summary>The handle the visitor wants; normalized (trimmed, lowercased) before use.</summary>
    public string? Handle { get; set; }

    /// <summary>The name to show for the person; the handle is used when blank.</summary>
    public string? DisplayName { get; set; }

    /// <summary>The person's email address, if given.  Never checked for uniqueness.</summary>
    public string? Email { get; set; }

    /// <summary>The invite code, for an invite-only host.  Never logged.</summary>
    public string? InviteCode { get; set; }
}
