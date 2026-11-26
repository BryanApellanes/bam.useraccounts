using Bam.Data.Repositories;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// A lost-device key-set recovery that was proved and is waiting out
/// <see cref="PasskeyOptions.RecoveryDelay"/> (bam.protocol#85).  Written once the heir's assertion
/// over the rotation has verified; settled, canceled or marked stale later, never deleted, so the
/// rows are the audit trail of every recovery a person started.
/// </summary>
[Serializable]
public class PendingKeySetRecoveryData : KeyedAuditRepoData
{
    /// <summary>The person whose key set moves.</summary>
    [CompositeKey]
    public string PersonHandle { get; set; } = null!;

    /// <summary>The recovery id the client was given at begin.</summary>
    [CompositeKey]
    public string RecoveryId { get; set; } = null!;

    /// <summary>The key-set passkey that was taken out of sign-in when the recovery was proved, or null when it was already gone.</summary>
    public string? RemovedCredentialId { get; set; }

    /// <summary>The fingerprint of the removed passkey's key, or null.</summary>
    public string? RemovedKeyFingerprint { get; set; }

    /// <summary>The passkey the key set moves to.</summary>
    public string HeirCredentialId { get; set; } = null!;

    /// <summary>The fingerprint of the heir's key at begin; the recovery moves the key set to exactly this key.</summary>
    public string HeirKeyFingerprint { get; set; } = null!;

    /// <summary>SHA-256 of the key the key set was anchored on at begin (<c>KeySetRotationPayload.AnchorSha256</c>).</summary>
    public string Anchor { get; set; } = null!;

    /// <summary>The heir's assertion over the rotation, as the UTF-8 JSON it was verified from.</summary>
    public string AssertionJson { get; set; } = null!;

    /// <summary>When the recovery was proved.</summary>
    public DateTime BeganUtc { get; set; }

    /// <summary>When the key set may move: <see cref="BeganUtc"/> plus <see cref="PasskeyOptions.RecoveryDelay"/>.</summary>
    public DateTime EffectiveUtc { get; set; }

    /// <summary>When it was canceled or found stale, or null.</summary>
    public DateTime? CanceledUtc { get; set; }

    /// <summary>Why it ended without moving the key set (<see cref="KeySetRecoveryEnd"/>), or null.</summary>
    public string? CancelReason { get; set; }

    /// <summary>The passkey whose session canceled it, when a person canceled it.</summary>
    public string? CanceledByCredentialId { get; set; }

    /// <summary>When the key set moved, or null.</summary>
    public DateTime? CompletedUtc { get; set; }

    /// <summary>Whether it is still waiting: neither canceled nor completed.  A method, not a property, so the object store doesn't persist it.</summary>
    public bool IsOpen()
    {
        return CanceledUtc is null && CompletedUtc is null;
    }

    /// <summary>
    /// Copies onto this stored row only what a recovery may change after it is stored, and only
    /// forward: an end (cancel, stale) or a completion is recorded once and never cleared or
    /// rewritten, and nothing that was proved (the heir, the anchor, the assertion, the times) is
    /// touched.  Both recovery stores update through this, so a canceled recovery can't be reopened
    /// through <see cref="IKeySetRecoveryRepository.Update"/>.
    /// </summary>
    /// <param name="changed">The row as a caller changed it.</param>
    public void AdvanceFrom(PendingKeySetRecoveryData changed)
    {
        ArgumentNullException.ThrowIfNull(changed);
        if (CanceledUtc is null && CompletedUtc is null && changed.CanceledUtc is not null)
        {
            CanceledUtc = changed.CanceledUtc;
            CancelReason = changed.CancelReason;
            CanceledByCredentialId = changed.CanceledByCredentialId;
        }
        if (CompletedUtc is null && CanceledUtc is null && changed.CompletedUtc is not null)
        {
            CompletedUtc = changed.CompletedUtc;
        }
    }
}
