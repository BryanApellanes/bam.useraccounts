namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// The passkey sign-up sequence: host policy, the registration ceremony (which claims the handle
/// by registering the passkey as the person's key set), the person profile, and the host's
/// post-sign-up steps.  Safe to expose to anonymous callers behind a rate limit: no method
/// throws on caller input.
/// </summary>
public interface IPasskeySignUp
{
    /// <summary>Applies the policy and begins the registration ceremony.</summary>
    /// <param name="request">The sign-up form.</param>
    /// <returns>Creation options for the browser, or a refusal.</returns>
    PasskeySignUpBeginResult Begin(PasskeySignUpRequest? request);

    /// <summary>
    /// Applies the policy again, completes the ceremony, writes the person profile and runs the
    /// post-sign-up steps.
    /// </summary>
    /// <param name="request">The same sign-up form submitted to <see cref="Begin"/>.</param>
    /// <param name="response">The browser's <c>PublicKeyCredential</c> for the creation.</param>
    /// <returns>The new person, or a refusal with nothing stored.</returns>
    PasskeySignUpResult Complete(PasskeySignUpRequest? request, PasskeyRegistrationResponse? response);

    /// <summary>
    /// Whether a handle is acceptable and free.  Answers
    /// <see cref="HandleAvailabilityReason.NotChecked"/> without looking anything up when the
    /// policy forbids the check.
    /// </summary>
    /// <param name="handle">The handle as typed.</param>
    HandleAvailability CheckHandle(string? handle);

    /// <summary>Whether a person profile exists for the handle.</summary>
    /// <param name="personHandle">The person's handle.</param>
    bool HasProfile(string personHandle);

    /// <summary>
    /// Writes the person profile for a handle whose passkey exists but whose profile does not
    /// (a sign-up that ended with <see cref="PasskeySignUpResult.ProfileCreated"/> false), from
    /// details the person enters again.  The email rule is sign-up's: required when the policy
    /// says so, and refused when given but implausible.  Nothing is written for the person
    /// without their details.  The caller must have authenticated the person as
    /// <paramref name="personHandle"/>.
    /// </summary>
    /// <param name="personHandle">The authenticated person's handle.</param>
    /// <param name="displayName">The name to show for the person; the handle when blank.</param>
    /// <param name="email">The person's email address, or null.</param>
    /// <returns>What happened.</returns>
    ProfileCompletion CompleteProfile(string personHandle, string? displayName, string? email);
}
