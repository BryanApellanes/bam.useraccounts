namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// The outcome of <see cref="IPasskeySignUp.Begin"/>: creation options for the browser, or a refusal.
/// </summary>
public sealed class PasskeySignUpBeginResult : UserAccountResponse
{
    /// <summary>Why the sign-up was refused, or <see cref="SignUpRefusal.None"/>.</summary>
    public SignUpRefusal Refusal { get; set; }

    /// <summary>The normalized handle the ceremony was begun for.</summary>
    public string? PersonHandle { get; set; }

    /// <summary>The options for <c>navigator.credentials.create()</c>, on success.</summary>
    public PasskeyCreationOptions? Options { get; set; }
}

/// <summary>
/// The outcome of <see cref="IPasskeySignUp.Complete"/>.  <see cref="UserAccountResponse.Success"/>
/// is true once the passkey has claimed the handle, even when <see cref="ProfileCreated"/> is
/// false: the person can sign in and finish their profile later.
/// </summary>
public sealed class PasskeySignUpResult : UserAccountResponse
{
    /// <summary>
    /// Why the sign-up was refused, or <see cref="SignUpRefusal.None"/>.
    /// <see cref="SignUpRefusal.ProfileFailed"/> accompanies a successful result whose profile was not written.
    /// </summary>
    public SignUpRefusal Refusal { get; set; }

    /// <summary>The new person's handle.</summary>
    public string? PersonHandle { get; set; }

    /// <summary>The name shown for the person.</summary>
    public string? DisplayName { get; set; }

    /// <summary>The stored credential id (base64url).</summary>
    public string? CredentialId { get; set; }

    /// <summary>The canonical fingerprint of the passkey's public key, the person's registered key set.</summary>
    public string? KeyFingerprint { get; set; }

    /// <summary>Whether the person profile was written.</summary>
    public bool ProfileCreated { get; set; }

    /// <summary>Where a post-sign-up step asked the person to be sent next, or null.</summary>
    public string? NextUrl { get; set; }
}

/// <summary>Why a handle is or is not available.</summary>
public enum HandleAvailabilityReason
{
    /// <summary>The handle is acceptable and nobody holds it.</summary>
    Available = 0,

    /// <summary>The handle does not satisfy the policy.</summary>
    Invalid,

    /// <summary>The handle belongs to a person.</summary>
    Taken,

    /// <summary>The policy does not allow availability checks; nothing was looked up.</summary>
    NotChecked
}

/// <summary>
/// The answer to <see cref="IPasskeySignUp.CheckHandle"/>.
/// </summary>
public sealed class HandleAvailability
{
    /// <summary>The normalized handle the answer is about.</summary>
    public string Handle { get; set; } = string.Empty;

    /// <summary>Whether a sign-up for the handle may proceed.  True for <see cref="HandleAvailabilityReason.NotChecked"/>: the ceremony decides.</summary>
    public bool Available { get; set; }

    /// <summary>Why.</summary>
    public HandleAvailabilityReason Reason { get; set; }
}
