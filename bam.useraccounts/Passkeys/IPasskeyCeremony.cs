namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// The two WebAuthn ceremonies a relying party runs: registration (a person adds a passkey,
/// and the first one becomes their registered key set) and assertion (a passkey signs in).
/// Each ceremony is two calls: <c>Begin</c> issues options carrying a single-use challenge for
/// the browser's <c>navigator.credentials.create</c> / <c>get</c>, <c>Complete</c> verifies the
/// browser's response against it.  Implementations never throw on client input; failures come
/// back as a result with <see cref="UserAccountResponse.Success"/> false and a
/// <see cref="PasskeyVerificationFailure"/>.
/// </summary>
public interface IPasskeyCeremony
{
    /// <summary>
    /// Issues creation options for <paramref name="personHandle"/>, replacing any pending
    /// registration challenge for that handle.
    /// </summary>
    /// <param name="personHandle">The handle the credential will belong to.</param>
    /// <param name="displayName">The name the authenticator shows for the account.</param>
    /// <returns>Options to pass to <c>navigator.credentials.create</c>.</returns>
    PasskeyCreationOptions BeginRegistration(string personHandle, string displayName);

    /// <summary>
    /// Verifies a registration response against the pending challenge for the handle, stores the
    /// credential and, for the person's first passkey, registers its public key as their key set.
    /// The pending challenge is consumed whatever the outcome.
    /// </summary>
    /// <param name="personHandle">The handle the registration was begun for.</param>
    /// <param name="response">The browser's registration response.</param>
    /// <returns>The outcome.</returns>
    PasskeyRegistrationResult CompleteRegistration(string personHandle, PasskeyRegistrationResponse? response);

    /// <summary>
    /// Issues request options carrying a fresh challenge.  With a handle, the options list that
    /// person's credentials (identifier-first sign-in); without one, the browser offers any
    /// discoverable credential for the relying party.
    /// </summary>
    /// <param name="personHandle">The handle to sign in, or null for discoverable sign-in.</param>
    /// <returns>Options to pass to <c>navigator.credentials.get</c>, with a <see cref="PasskeyRequestOptions.CeremonyId"/> the response must echo.</returns>
    PasskeyRequestOptions BeginAssertion(string? personHandle);

    /// <summary>
    /// Verifies an assertion response against the challenge its <see cref="PasskeyAssertionResponse.CeremonyId"/>
    /// names and the stored credential its id names, recording the sign counter on success.  The
    /// pending challenge is consumed whatever the outcome.
    /// </summary>
    /// <param name="response">The browser's assertion response.</param>
    /// <returns>The outcome, naming the signed-in person on success.</returns>
    PasskeySignInResult CompleteAssertion(PasskeyAssertionResponse? response);

    /// <summary>
    /// Builds request options for a challenge issued through <see cref="IAccountConfirmation.CreateChallenge"/>,
    /// so a host that confirms accounts through that contract can drive the browser with the same
    /// challenge bytes it will later verify through <see cref="IAccountConfirmation.VerifySignedChallenge"/>.
    /// </summary>
    /// <param name="challenge">The pending confirmation challenge.</param>
    /// <returns>Options to pass to <c>navigator.credentials.get</c>.</returns>
    PasskeyRequestOptions ToRequestOptions(ConfirmationChallenge challenge);
}
