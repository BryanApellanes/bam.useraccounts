namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Why <see cref="IPasskeySignUp"/> refused a sign-up, for the host's logs and UI.  The web
/// template shows a specific message only for refusals that disclose nothing an anonymous
/// visitor could not already learn (see <see cref="SignUpPolicy.AllowHandleAvailabilityCheck"/>).
/// </summary>
public enum SignUpRefusal
{
    /// <summary>Not refused.</summary>
    None = 0,

    /// <summary>Sign-up is closed: the policy is not open and has no invite codes.</summary>
    SignUpClosed,

    /// <summary>Sign-up is invite-only and the invite code was missing or wrong.</summary>
    InviteRequired,

    /// <summary>The handle does not match the policy's pattern or starts with a reserved prefix.</summary>
    InvalidHandle,

    /// <summary>The handle already belongs to a person.</summary>
    HandleTaken,

    /// <summary>The policy requires an email address and none was given, or the one given is malformed.</summary>
    EmailRequired,

    /// <summary>The passkey ceremony refused the registration; nothing was stored.</summary>
    CeremonyFailed,

    /// <summary>The passkey claimed the handle but the person profile could not be written.</summary>
    ProfileFailed
}
