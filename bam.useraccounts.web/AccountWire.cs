using Bam.UserAccounts.Passkeys;

namespace Bam.UserAccounts.Web;

// The JSON bodies of the account endpoints (camelCase on the wire).  The browser module and
// non-browser clients (a native app) speak exactly these shapes.

/// <summary>Body of <c>registration/complete</c>: the sign-up form again, plus the browser's registration response.</summary>
public sealed class RegistrationCompleteRequest
{
    /// <summary>The handle sent at begin.</summary>
    public string? Handle { get; set; }

    /// <summary>The display name sent at begin.</summary>
    public string? DisplayName { get; set; }

    /// <summary>The email sent at begin, if any.</summary>
    public string? Email { get; set; }

    /// <summary>The invite code sent at begin, if any.</summary>
    public string? InviteCode { get; set; }

    /// <summary><c>PublicKeyCredential.toJSON()</c> of the created credential.</summary>
    public PasskeyRegistrationResponse? Credential { get; set; }
}

/// <summary>Body of <c>assertion/begin</c>.</summary>
public sealed class AssertionBeginRequest
{
    /// <summary>The handle to sign in as, or null/blank to let the authenticator offer its passkeys.</summary>
    public string? Handle { get; set; }
}

/// <summary>Body of <c>assertion/complete</c>.</summary>
public sealed class AssertionCompleteRequest
{
    /// <summary>The <c>ceremonyId</c> returned by <c>assertion/begin</c>.</summary>
    public string? CeremonyId { get; set; }

    /// <summary><c>PublicKeyCredential.toJSON()</c> of the assertion.</summary>
    public PasskeyAssertionResponse? Credential { get; set; }

    /// <summary>Where to go after sign-in; used only when it is a path on this site.</summary>
    public string? ReturnUrl { get; set; }
}

/// <summary>Body of <c>passkeys/{id}/handover/begin</c> (bam.useraccounts#20).</summary>
public sealed class HandoverBeginRequest
{
    /// <summary>The passkey to move the key set to, or null for the passkey this session signed in with.</summary>
    public string? Heir { get; set; }
}

/// <summary>Body of <c>keyset/recovery/begin</c> (bam.protocol#85).</summary>
public sealed class RecoveryBeginRequest
{
    /// <summary>The lost key-set passkey to take out of sign-in, or null when it was already removed.</summary>
    public string? Removes { get; set; }

    /// <summary>The passkey to move the key set to, or null for the passkey this session signed in with.</summary>
    public string? Heir { get; set; }
}

/// <summary>Body of <c>keyset/recovery/complete</c>.</summary>
public sealed class RecoveryCompleteRequest
{
    /// <summary>The <c>recoveryId</c> returned by <c>keyset/recovery/begin</c>.</summary>
    public string? RecoveryId { get; set; }

    /// <summary><c>PublicKeyCredential.toJSON()</c> of the assertion the heir made.</summary>
    public PasskeyAssertionResponse? Credential { get; set; }
}

/// <summary>Body of <c>passkeys/{id}/handover/complete</c>.</summary>
public sealed class HandoverCompleteRequest
{
    /// <summary>The <c>handoverId</c> returned by <c>handover/begin</c>.</summary>
    public string? HandoverId { get; set; }

    /// <summary><c>PublicKeyCredential.toJSON()</c> of the assertion the passkey being removed made.</summary>
    public PasskeyAssertionResponse? Credential { get; set; }
}

/// <summary>Body of <c>additional/complete</c>.</summary>
public sealed class AdditionalCompleteRequest
{
    /// <summary><c>PublicKeyCredential.toJSON()</c> of the created credential.</summary>
    public PasskeyRegistrationResponse? Credential { get; set; }

    /// <summary>A name for the new passkey, or null.</summary>
    public string? Name { get; set; }
}

/// <summary>Body of <c>passkeys/{credentialId}/name</c>.</summary>
public sealed class RenameRequest
{
    /// <summary>The new name; blank clears it.</summary>
    public string? Name { get; set; }
}

/// <summary>Body of <c>profile</c>: the details for a profile that wasn't saved at sign-up.</summary>
public sealed class ProfileRequest
{
    /// <summary>The name to show; the handle when blank.</summary>
    public string? DisplayName { get; set; }

    /// <summary>The email address, or null. Required when the host's sign-up policy requires one.</summary>
    public string? Email { get; set; }
}

/// <summary>Every refusal: a coarse code a client can branch on and a message a person can read.</summary>
public sealed class AccountError
{
    /// <summary>The coarse code, one of <see cref="AccountErrorCodes"/>.</summary>
    public string Error { get; set; } = string.Empty;

    /// <summary>The host's wording for that code.</summary>
    public string Message { get; set; } = string.Empty;
}

/// <summary>
/// The values of <see cref="AccountError.Error"/>.  Sign-in and ceremony failures carry one code
/// each whatever the cause, so a response never says which check failed.
/// </summary>
public static class AccountErrorCodes
{
    /// <summary>The request was not well-formed JSON of the expected shape.</summary>
    public const string BadRequest = "BadRequest";

    /// <summary>The request lacked the <see cref="AccountRoutes.RequestHeader"/> header or came from an origin that is not this site's.</summary>
    public const string RequestRefused = "RequestRefused";

    /// <summary>The caller is not signed in.</summary>
    public const string NotSignedIn = "NotSignedIn";

    /// <summary>Sign-up is closed.</summary>
    public const string SignUpClosed = "SignUpClosed";

    /// <summary>An invite code is required and was missing or wrong.</summary>
    public const string InviteRequired = "InviteRequired";

    /// <summary>The handle does not fit the host's rules.</summary>
    public const string InvalidHandle = "InvalidHandle";

    /// <summary>The handle is taken (only reported when the host allows the availability check).</summary>
    public const string HandleTaken = "HandleTaken";

    /// <summary>An email address is required and was missing or malformed.</summary>
    public const string EmailRequired = "EmailRequired";

    /// <summary>Sign-up failed for a reason that is not disclosed.</summary>
    public const string SignUpFailed = "SignUpFailed";

    /// <summary>Sign-in failed.</summary>
    public const string SignInFailed = "SignInFailed";

    /// <summary>Adding a passkey failed.</summary>
    public const string PasskeyNotAdded = "PasskeyNotAdded";

    /// <summary>The person has no such passkey.</summary>
    public const string NotFound = "NotFound";

    /// <summary>The passkey is the person's only one and cannot be removed.</summary>
    public const string LastPasskey = "LastPasskey";

    /// <summary>Too many requests from this address.</summary>
    public const string RateLimited = "RateLimited";

    /// <summary>The profile couldn't be saved; try again later.</summary>
    public const string ProfileNotSaved = "ProfileNotSaved";

    /// <summary>The passkey holds the account's key set: hand it over first, or remove it with <c>?keySet=keep</c>.</summary>
    public const string KeySetHandoverRequired = "KeySetHandoverRequired";

    /// <summary>A handover was asked for the person's only passkey.</summary>
    public const string LastCredential = "LastCredential";

    /// <summary>The heir isn't another registered passkey of this person.</summary>
    public const string InvalidHeir = "InvalidHeir";

    /// <summary>The passkey doesn't hold the key set; remove it with a plain <c>DELETE</c>.</summary>
    public const string NotKeySet = "NotKeySet";

    /// <summary>This host can't move a key set between passkeys; <c>DELETE ?keySet=keep</c> removes it.</summary>
    public const string RotationUnavailable = "RotationUnavailable";

    /// <summary>The <c>handoverId</c> is unknown, used or expired.</summary>
    public const string HandoverExpired = "HandoverExpired";

    /// <summary>The assertion didn't prove the move.</summary>
    public const string ProofRefused = "ProofRefused";

    /// <summary>The key set moved, or the passkey was removed, since the handover began.</summary>
    public const string KeySetChanged = "KeySetChanged";

    /// <summary>The heir was removed since the handover began.</summary>
    public const string HeirGone = "HeirGone";

    /// <summary>The heir passkey was registered too recently to recover the key set; the body carries <c>eligibleUtc</c>.</summary>
    public const string HeirTooNew = "HeirTooNew";

    /// <summary>A lost-device recovery is already waiting.</summary>
    public const string RecoveryPending = "RecoveryPending";

    /// <summary>A passkey still holds the key set: name it in <c>removes</c>, or hand the key set over with it.</summary>
    public const string RemovesRequired = "RemovesRequired";

    /// <summary>There is no key set to recover.</summary>
    public const string NoKeySet = "NoKeySet";
}

/// <summary>The <see cref="AccountErrorCodes.HeirTooNew"/> refusal: the usual error body plus when the heir becomes old enough.</summary>
public sealed class HeirTooNewError
{
    /// <summary>Always <see cref="AccountErrorCodes.HeirTooNew"/>.</summary>
    public string Error { get; set; } = AccountErrorCodes.HeirTooNew;

    /// <summary>The host's message.</summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>When the heir can recover the key set.</summary>
    public DateTime EligibleUtc { get; set; }
}

/// <summary>Response of <c>registration/begin</c> and <c>additional/begin</c>.</summary>
public sealed class CreationOptionsResponse
{
    /// <summary>The options for <c>navigator.credentials.create</c> (<c>publicKey</c> member).</summary>
    public PasskeyCreationOptions Options { get; set; } = null!;
}

/// <summary>Response of <c>assertion/begin</c>.</summary>
public sealed class RequestOptionsResponse
{
    /// <summary>The options for <c>navigator.credentials.get</c> (<c>publicKey</c> member).</summary>
    public PasskeyRequestOptions Options { get; set; } = null!;

    /// <summary>The ceremony id to send back at <c>assertion/complete</c>.</summary>
    public string CeremonyId { get; set; } = string.Empty;
}

/// <summary>Response of <c>registration/complete</c> and <c>assertion/complete</c>; the session cookie rides on the same response.</summary>
public sealed class SignedInResponse
{
    /// <summary>The signed-in person's handle.</summary>
    public string Handle { get; set; } = string.Empty;

    /// <summary>The person's display name.</summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>Where the client should go next; always a path on this site.</summary>
    public string NextUrl { get; set; } = string.Empty;

    /// <summary>False when sign-up claimed the handle but the profile could not be written; true otherwise.</summary>
    public bool ProfileCreated { get; set; } = true;

    /// <summary>
    /// The person's lost-device recovery that is waiting to move the key set, or null.  Set on
    /// sign-in, when <see cref="NextUrl"/> is then the manage page: a client shows it and offers the
    /// cancel (<c>keyset/recovery/{id}/cancel</c>).
    /// </summary>
    public PendingRecoverySummary? PendingRecovery { get; set; }
}

/// <summary>Response of <c>passkeys/{id}/handover/begin</c>.</summary>
public sealed class HandoverBeginResponse
{
    /// <summary>Send back to <c>handover/complete</c>; works once, for as long as a ceremony does.</summary>
    public string HandoverId { get; set; } = string.Empty;

    /// <summary>Assertion options that allow only the passkey being removed.</summary>
    public PasskeyRequestOptions Options { get; set; } = null!;
}

/// <summary>Response of <c>keyset/recovery/begin</c>.</summary>
public sealed class RecoveryBeginResponse
{
    /// <summary>Send back to <c>keyset/recovery/complete</c>; works once, for as long as a ceremony does.  Also the waiting recovery's id.</summary>
    public string RecoveryId { get; set; } = string.Empty;

    /// <summary>Assertion options that allow only the heir, user verification required.</summary>
    public PasskeyRequestOptions Options { get; set; } = null!;
}

/// <summary>Response (202) of <c>keyset/recovery/complete</c>.</summary>
public sealed class RecoveryCompleteResponse
{
    /// <summary>Whether this session ended (it was signed in with the passkey taken out of sign-in).</summary>
    public bool SignedOut { get; set; }

    /// <summary>Where to go when <see cref="SignedOut"/>, else null.</summary>
    public string? NextUrl { get; set; }

    /// <summary>When the key set moves unless the recovery is canceled.</summary>
    public DateTime EffectiveUtc { get; set; }
}

/// <summary>A waiting lost-device recovery, as <c>GET passkeys</c> shows it.</summary>
public sealed class PendingRecoverySummary
{
    /// <summary>The recovery id, for <c>keyset/recovery/{id}/cancel</c>.</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>The passkey that was taken out of sign-in, or null.</summary>
    public string? Removes { get; set; }

    /// <summary>The passkey the key set moves to.</summary>
    public string Heir { get; set; } = string.Empty;

    /// <summary>When the key set moves.</summary>
    public DateTime EffectiveUtc { get; set; }

    /// <summary>Builds the summary of a stored recovery.</summary>
    /// <param name="recovery">The waiting recovery.</param>
    public static PendingRecoverySummary Of(PendingKeySetRecoveryData recovery)
    {
        ArgumentNullException.ThrowIfNull(recovery);
        return new PendingRecoverySummary { Id = recovery.RecoveryId, Removes = recovery.RemovedCredentialId, Heir = recovery.HeirCredentialId, EffectiveUtc = recovery.EffectiveUtc };
    }
}

/// <summary>Response of <c>additional/complete</c>.</summary>
public sealed class PasskeyAddedResponse
{
    /// <summary>The new passkey's credential id, base64url.</summary>
    public string CredentialId { get; set; } = string.Empty;
}

/// <summary>Response of <c>signout</c> and of removing a passkey.</summary>
public sealed class SignedOutResponse
{
    /// <summary>Whether the session ended.</summary>
    public bool SignedOut { get; set; }

    /// <summary>Where the client should go when it did.</summary>
    public string? NextUrl { get; set; }
}

/// <summary>Response of the handle availability check.</summary>
public sealed class AvailabilityResponse
{
    /// <summary>The handle as normalized.</summary>
    public string Handle { get; set; } = string.Empty;

    /// <summary>Whether it can be signed up with.</summary>
    public bool Available { get; set; }

    /// <summary>The name of the <see cref="HandleAvailabilityReason"/>.</summary>
    public string Reason { get; set; } = string.Empty;
}

/// <summary>Response of <c>GET passkeys</c>.</summary>
public sealed class PasskeyListResponse
{
    /// <summary>The signed-in person's passkeys, oldest first.</summary>
    public List<PasskeySummary> Passkeys { get; set; } = new List<PasskeySummary>();

    /// <summary>The waiting lost-device recovery, or null (bam.protocol#85).</summary>
    public PendingRecoverySummary? PendingRecovery { get; set; }

    /// <summary>Whether the person can start a recovery: this host can recover, they have a key set, no passkey holds it, and nothing is waiting.</summary>
    public bool KeySetRecoverable { get; set; }

    /// <summary>
    /// Whether the person has a key set no passkey holds, nothing is waiting, and no recovery can start
    /// for it, so the client should send them to support.  Omitted when false; never true together
    /// with <see cref="KeySetRecoverable"/>, and false when the person has no key set.
    /// </summary>
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    public bool KeySetUnrecoverable { get; set; }
}

/// <summary>One passkey as the manage page shows it.  No key material.</summary>
public sealed class PasskeySummary
{
    /// <summary>The credential id, base64url.</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>The name the person gave it, or null.</summary>
    public string? Name { get; set; }

    /// <summary>When it was registered.</summary>
    public DateTime CreatedUtc { get; set; }

    /// <summary>When it last signed in, or null.</summary>
    public DateTime? LastUsedUtc { get; set; }

    /// <summary>Whether this session was opened with it.</summary>
    public bool Current { get; set; }

    /// <summary>Whether it is the person's registered key set (their first passkey).</summary>
    public bool RegisteredKeySet { get; set; }

    /// <summary>Builds the summary of a stored credential.</summary>
    /// <param name="credential">The stored credential.</param>
    /// <param name="currentCredentialId">The session's credential id.</param>
    public static PasskeySummary Of(PasskeyCredentialData credential, string? currentCredentialId)
    {
        ArgumentNullException.ThrowIfNull(credential);
        return new PasskeySummary
        {
            Id = credential.CredentialId,
            Name = credential.Name,
            CreatedUtc = credential.CreatedUtc,
            LastUsedUtc = credential.LastUsedUtc,
            Current = string.Equals(credential.CredentialId, currentCredentialId, StringComparison.Ordinal),
            RegisteredKeySet = credential.IsRegisteredKeySet
        };
    }
}
