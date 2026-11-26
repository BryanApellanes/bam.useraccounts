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

    /// <summary>Stores the changed state of an existing row (cancel, stale, complete).</summary>
    /// <param name="recovery">The row, as read from this repository and changed.</param>
    /// <returns>Whether the row existed and was updated.</returns>
    bool Update(PendingKeySetRecoveryData recovery);
}
