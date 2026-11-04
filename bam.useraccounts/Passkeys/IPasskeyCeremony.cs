namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// The WebAuthn ceremonies a relying party runs: sign-up registration (a person claims a handle
/// with their first passkey, which becomes their registered key set), additional registration (an
/// authenticated person adds another passkey) and assertion (a passkey signs in).  Each ceremony
/// is two calls: <c>Begin</c> issues options carrying a single-use challenge for the browser's
/// <c>navigator.credentials.create</c> / <c>get</c>, <c>Complete</c> verifies the browser's
/// response against it.  Implementations never throw on client input; failures come back as a
/// result with <see cref="UserAccountResponse.Success"/> false and a
/// <see cref="PasskeyVerificationFailure"/>.
/// <para>
/// Every <c>Begin</c> call stores a challenge row for any caller, so a host exposing one to
/// anonymous traffic must rate-limit it (the same duty <see cref="PersistedConfirmationChallengeRepository"/>
/// documents for confirmation challenges).  <see cref="BeginAssertion"/> with a handle discloses
/// whether the handle has credentials; anonymous surfaces should prefer discoverable sign-in.
/// </para>
/// </summary>
public interface IPasskeyCeremony
{
    /// <summary>
    /// Sign-up: issues creation options for <paramref name="personHandle"/>, replacing any pending
    /// registration challenge for that handle.  Safe to expose to anonymous callers: the options
    /// reveal nothing about whether the handle already exists (a fresh user id, no excluded
    /// credentials); <see cref="CompleteRegistration"/> refuses a handle that is already taken.
    /// </summary>
    /// <param name="personHandle">The handle the credential will belong to.</param>
    /// <param name="displayName">The name the authenticator shows for the account.</param>
    /// <returns>Options to pass to <c>navigator.credentials.create</c>.</returns>
    PasskeyCreationOptions BeginRegistration(string personHandle, string displayName);

    /// <summary>
    /// Sign-up: verifies a registration response against the pending challenge for the handle,
    /// stores the credential and registers its public key as the person's key set through
    /// <see cref="Bam.Protocol.Data.IPublicKeySetRegistrar"/>.  Refuses with
    /// <see cref="PasskeyVerificationFailure.HandleAlreadyRegistered"/>, storing nothing, when the
    /// handle already has a passkey or a key set, so an anonymous caller cannot attach a credential
    /// to an existing person.  The pending challenge is consumed whatever the outcome.
    /// </summary>
    /// <param name="personHandle">The handle the registration was begun for.</param>
    /// <param name="response">The browser's registration response.</param>
    /// <returns>The outcome.</returns>
    PasskeyRegistrationResult CompleteRegistration(string personHandle, PasskeyRegistrationResponse? response);

    /// <summary>
    /// Adds a passkey to an existing person: issues creation options that reuse the person's user
    /// id and exclude their registered credentials.  <b>The host must have authenticated the caller
    /// as <paramref name="personHandle"/> before calling this</b>; it is never exposed to anonymous
    /// callers.
    /// </summary>
    /// <param name="personHandle">The authenticated person's handle.</param>
    /// <param name="displayName">The name the authenticator shows for the account.</param>
    /// <returns>Options to pass to <c>navigator.credentials.create</c>.</returns>
    PasskeyCreationOptions BeginAdditionalRegistration(string personHandle, string displayName);

    /// <summary>
    /// Adds a passkey to an existing person: verifies the response against the pending challenge
    /// for the handle and stores the credential.  When the person has no passkey yet (a device-key
    /// account) the key is offered to the registrar; an existing key set stands and the passkey is
    /// stored as an additional credential.  <b>The host must have authenticated the caller as
    /// <paramref name="personHandle"/> before calling this.</b>  The pending challenge is consumed
    /// whatever the outcome.
    /// </summary>
    /// <param name="personHandle">The authenticated person's handle.</param>
    /// <param name="response">The browser's registration response.</param>
    /// <returns>The outcome.</returns>
    PasskeyRegistrationResult CompleteAdditionalRegistration(string personHandle, PasskeyRegistrationResponse? response);

    /// <summary>
    /// Issues request options carrying a fresh challenge.  With a handle, the options list that
    /// person's credentials (identifier-first sign-in) and the ceremony is bound to the handle:
    /// <see cref="CompleteAssertion"/> refuses a credential belonging to anyone else.  Without one,
    /// the browser offers any discoverable credential for the relying party and the result names
    /// whoever signed in.
    /// </summary>
    /// <param name="personHandle">The handle to sign in, or null for discoverable sign-in.</param>
    /// <returns>Options to pass to <c>navigator.credentials.get</c>, with a <see cref="PasskeyRequestOptions.CeremonyId"/> the response must echo.</returns>
    PasskeyRequestOptions BeginAssertion(string? personHandle);

    /// <summary>
    /// Verifies an assertion response against the challenge its <see cref="PasskeyAssertionResponse.CeremonyId"/>
    /// names and the stored credential its id names, recording the sign counter on success.  The
    /// pending challenge is consumed whatever the outcome.  Hosts establish the session from
    /// <see cref="PasskeySignInResult.PersonHandle"/>, never from success alone.
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
