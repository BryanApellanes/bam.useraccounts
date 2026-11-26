namespace Bam.UserAccounts.Passkeys;

/// <summary>Why a lost-device recovery step was refused, or <see cref="None"/>.</summary>
public enum KeySetRecoveryRefusal
{
    /// <summary>Not refused.</summary>
    None = 0,

    /// <summary>The passkey named in <c>removes</c> is not one of the person's (it does not exist, is pending, or is someone else's).</summary>
    NotFound,

    /// <summary>The passkey named in <c>removes</c> does not hold the key set: remove it with a plain removal.</summary>
    NotKeySet,

    /// <summary>The heir is not another accepted passkey of the person, or it is the passkey being removed.</summary>
    InvalidHeir,

    /// <summary>A passkey still holds the key set: name it in <c>removes</c>, or hand the key set over with it.</summary>
    RemovesRequired,

    /// <summary>The heir was registered less than <see cref="PasskeyOptions.RecoveryCredentialAge"/> ago.</summary>
    HeirTooNew,

    /// <summary>A recovery is already waiting for this person.</summary>
    RecoveryPending,

    /// <summary>The person has no registered key set to recover.</summary>
    NoKeySet,

    /// <summary>This host has no recovery proof: remove the lost passkey keeping the key set (option A).</summary>
    RotationUnavailable,

    /// <summary>The recovery id is unknown, already used, expired, or another person's.</summary>
    RecoveryExpired,

    /// <summary>The heir's assertion did not prove the rotation, or was not user-verified.</summary>
    ProofRefused,

    /// <summary>The key set, or the passkey holding it, changed since the recovery began.</summary>
    KeySetChanged,

    /// <summary>The heir was removed since the recovery began.</summary>
    HeirGone
}

/// <summary>How a recovery ended without moving the key set, as recorded in <see cref="PendingKeySetRecoveryData.CancelReason"/>.</summary>
public static class KeySetRecoveryEnd
{
    /// <summary>A signed-in session of the person canceled it.</summary>
    public const string Canceled = "canceled";

    /// <summary>The heir was removed before the key set moved.</summary>
    public const string HeirGone = "heir-gone";

    /// <summary>The key set moved some other way before the recovery was due.</summary>
    public const string KeySetChanged = "key-set-changed";

    /// <summary>The registrar refused the rotation at settle (for example, the heir's key is blocklisted).</summary>
    public const string Refused = "refused";
}

/// <summary>What <see cref="IKeySetRecovery.Settle"/> did.</summary>
public enum KeySetRecoverySettlement
{
    /// <summary>The person has no recovery waiting.</summary>
    NothingPending = 0,

    /// <summary>A recovery is waiting and not yet due.</summary>
    NotDue,

    /// <summary>The key set moved to the heir.</summary>
    Settled,

    /// <summary>The recovery ended without moving the key set (heir gone, key set changed, or refused); see the row's <see cref="PendingKeySetRecoveryData.CancelReason"/>.</summary>
    Ended,

    /// <summary>It was due but couldn't settle now (too soon after another rotation, or a custody fault); the next request tries again.</summary>
    Deferred
}

/// <summary>The outcome of <see cref="IKeySetRecovery.Begin"/>.</summary>
public sealed class KeySetRecoveryStart
{
    /// <summary>Why it was refused, or <see cref="KeySetRecoveryRefusal.None"/>.</summary>
    public KeySetRecoveryRefusal Refusal { get; set; }

    /// <summary>Whether the recovery began.</summary>
    public bool Success => Refusal == KeySetRecoveryRefusal.None;

    /// <summary>The id to send back at completion; works once, for <see cref="PasskeyOptions.ChallengeLifetime"/>.</summary>
    public string? RecoveryId { get; set; }

    /// <summary>The options for <c>navigator.credentials.get</c>: they allow only the heir, and require user verification.</summary>
    public PasskeyRequestOptions? Options { get; set; }

    /// <summary>The credential id of the passkey the key set will move to.</summary>
    public string? HeirCredentialId { get; set; }

    /// <summary>On <see cref="KeySetRecoveryRefusal.HeirTooNew"/>, when the heir becomes old enough.</summary>
    public DateTime? EligibleUtc { get; set; }
}

/// <summary>The outcome of <see cref="IKeySetRecovery.Complete"/>.</summary>
public sealed class KeySetRecoveryResult
{
    /// <summary>Why it was refused, or <see cref="KeySetRecoveryRefusal.None"/>.</summary>
    public KeySetRecoveryRefusal Refusal { get; set; }

    /// <summary>Whether the recovery was proved and is now waiting.</summary>
    public bool Success => Refusal == KeySetRecoveryRefusal.None;

    /// <summary>The recovery id, on success.</summary>
    public string? RecoveryId { get; set; }

    /// <summary>The passkey taken out of sign-in, or null when none was named.</summary>
    public string? RemovedCredentialId { get; set; }

    /// <summary>The passkey the key set will move to, on success.</summary>
    public string? HeirCredentialId { get; set; }

    /// <summary>When the key set may move, on success.</summary>
    public DateTime? EffectiveUtc { get; set; }
}
