namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Custody of <see cref="PendingKeySetRecoveryData"/> rows (bam.protocol#85).  Rows are addressed
/// by the person's handle and the recovery id together, so one person can never read or change
/// another's recovery by guessing its id.
/// </summary>
public interface IKeySetRecoveryRepository
{
    /// <summary>Stores a new recovery row.</summary>
    /// <param name="recovery">The row.</param>
    /// <returns>The stored row.</returns>
    PendingKeySetRecoveryData Save(PendingKeySetRecoveryData recovery);

    /// <summary>Returns every recovery row of the person, oldest first.</summary>
    /// <param name="personHandle">The person's handle.</param>
    IReadOnlyList<PendingKeySetRecoveryData> FindByHandle(string personHandle);

    /// <summary>Returns the person's recovery with that id, or null.</summary>
    /// <param name="personHandle">The person's handle.</param>
    /// <param name="recoveryId">The recovery id.</param>
    PendingKeySetRecoveryData? Find(string personHandle, string recoveryId);

    /// <summary>
    /// Stores the changed state of an existing row (cancel, stale, complete).  Only those fields are
    /// written, and only forward (<see cref="PendingKeySetRecoveryData.AdvanceFrom"/>): an ended or
    /// completed row stays so.
    /// </summary>
    /// <param name="recovery">The row, as read from this repository and changed.</param>
    /// <returns>Whether the row existed and was updated.</returns>
    bool Update(PendingKeySetRecoveryData recovery);

    /// <summary>
    /// Records that a passkey of the person with this key was removed.  A recovery that names no
    /// <c>removes</c> may only move a key set holding one of these keys, so it can never take over a
    /// key set no passkey of the person held (an admin rebind, a device key).  Recording the same key
    /// twice keeps one record.
    /// </summary>
    /// <param name="personHandle">The person's handle.</param>
    /// <param name="credentialId">The removed passkey.</param>
    /// <param name="keyFingerprint">The canonical fingerprint of its key (<c>PublicKeyFingerprint.Of</c>).</param>
    void RecordRemovedPasskeyKey(string personHandle, string credentialId, string keyFingerprint);

    /// <summary>Whether a passkey of the person with this key was removed (<see cref="RecordRemovedPasskeyKey"/>).</summary>
    /// <param name="personHandle">The person's handle.</param>
    /// <param name="keyFingerprint">The canonical key fingerprint.</param>
    bool WasRemovedPasskeyKey(string personHandle, string keyFingerprint);
}
