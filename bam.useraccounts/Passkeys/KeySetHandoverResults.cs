namespace Bam.UserAccounts.Passkeys;

/// <summary>Why a key-set handover step was refused, or <see cref="None"/>.</summary>
public enum KeySetHandoverRefusal
{
    /// <summary>Not refused.</summary>
    None = 0,

    /// <summary>The person has no such passkey (it does not exist, is pending, or is someone else's).</summary>
    NotFound,

    /// <summary>The passkey is the person's only one: there is nothing to hand the key set over to.</summary>
    LastCredential,

    /// <summary>The heir is not another accepted passkey of the same person.</summary>
    InvalidHeir,

    /// <summary>The passkey does not hold the key set: remove it with a plain removal.</summary>
    NotKeySet,

    /// <summary>This host has no passkey rotation proof: a removal keeps the key set, as before bam.useraccounts#20.</summary>
    RotationUnavailable,

    /// <summary>The handover id is unknown, already used, expired, or another person's.</summary>
    HandoverExpired,

    /// <summary>The assertion did not prove the rotation.</summary>
    ProofRefused,

    /// <summary>The key set, or the passkey holding it, changed since the handover began.</summary>
    KeySetChanged,

    /// <summary>The heir was removed since the handover began.</summary>
    HeirGone
}

/// <summary>The outcome of <see cref="IKeySetHandover.Begin"/>.</summary>
public sealed class KeySetHandoverStart
{
    /// <summary>Why it was refused, or <see cref="KeySetHandoverRefusal.None"/>.</summary>
    public KeySetHandoverRefusal Refusal { get; set; }

    /// <summary>Whether the handover began.</summary>
    public bool Success => Refusal == KeySetHandoverRefusal.None;

    /// <summary>The id to send back at completion; works once, for <see cref="PasskeyOptions.ChallengeLifetime"/>.</summary>
    public string? HandoverId { get; set; }

    /// <summary>The options for <c>navigator.credentials.get</c>: they allow only the passkey being removed.</summary>
    public PasskeyRequestOptions? Options { get; set; }

    /// <summary>The credential id of the passkey the key set moves to.</summary>
    public string? HeirCredentialId { get; set; }
}

/// <summary>The outcome of <see cref="IKeySetHandover.Complete"/>.</summary>
public sealed class KeySetHandoverResult
{
    /// <summary>Why it was refused, or <see cref="KeySetHandoverRefusal.None"/>.</summary>
    public KeySetHandoverRefusal Refusal { get; set; }

    /// <summary>Whether the key set moved and the old passkey was removed.</summary>
    public bool Success => Refusal == KeySetHandoverRefusal.None;

    /// <summary>The credential id of the passkey that was removed, on success.</summary>
    public string? RemovedCredentialId { get; set; }

    /// <summary>The credential id of the passkey that now holds the key set, on success.</summary>
    public string? HeirCredentialId { get; set; }
}
