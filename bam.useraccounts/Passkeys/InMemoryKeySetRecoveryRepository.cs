namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Process-local <see cref="IKeySetRecoveryRepository"/> for tests and single-process hosts.
/// Register as a singleton.  Recoveries and removed-key records do not survive a restart, so a host
/// that restarts within <see cref="PasskeyOptions.RecoveryDelay"/> loses its pending recoveries.  If
/// a lost recovery had already removed the passkey that held the key set, the key set can then only
/// be recovered by an operator (bam.useraccounts#29).
/// </summary>
public sealed class InMemoryKeySetRecoveryRepository : IKeySetRecoveryRepository
{
    private readonly List<PendingKeySetRecoveryData> _rows = new List<PendingKeySetRecoveryData>();
    private readonly HashSet<RemovedKey> _removedKeys = new HashSet<RemovedKey>();
    private readonly object _lock = new object();

    private sealed record RemovedKey(string PersonHandle, string KeyFingerprint);

    /// <inheritdoc />
    public PendingKeySetRecoveryData Save(PendingKeySetRecoveryData recovery)
    {
        ArgumentNullException.ThrowIfNull(recovery);
        lock (_lock)
        {
            if (FindRow(recovery.PersonHandle, recovery.RecoveryId) is not null)
            {
                throw new InvalidOperationException("A recovery with that id is already stored for the person.");
            }
            _rows.Add(Copy(recovery));
            return recovery;
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<PendingKeySetRecoveryData> FindByHandle(string personHandle)
    {
        lock (_lock)
        {
            return _rows.Where(row => string.Equals(row.PersonHandle, personHandle, StringComparison.Ordinal))
                .OrderBy(row => row.BeganUtc)
                .Select(Copy)
                .ToList();
        }
    }

    /// <inheritdoc />
    public PendingKeySetRecoveryData? Find(string personHandle, string recoveryId)
    {
        lock (_lock)
        {
            PendingKeySetRecoveryData? row = FindRow(personHandle, recoveryId);
            return row is null ? null : Copy(row);
        }
    }

    /// <inheritdoc />
    public bool Update(PendingKeySetRecoveryData recovery)
    {
        ArgumentNullException.ThrowIfNull(recovery);
        lock (_lock)
        {
            PendingKeySetRecoveryData? row = FindRow(recovery.PersonHandle, recovery.RecoveryId);
            if (row is null)
            {
                return false;
            }
            // Only the fields a recovery may change after it is stored, and only forward, as the
            // persisted store does.
            row.AdvanceFrom(recovery);
            return true;
        }
    }

    /// <inheritdoc />
    public void RecordRemovedPasskeyKey(string personHandle, string credentialId, string keyFingerprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(personHandle);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyFingerprint);
        lock (_lock)
        {
            _removedKeys.Add(new RemovedKey(personHandle, keyFingerprint));
        }
    }

    /// <inheritdoc />
    public bool WasRemovedPasskeyKey(string personHandle, string keyFingerprint)
    {
        lock (_lock)
        {
            return _removedKeys.Contains(new RemovedKey(personHandle, keyFingerprint));
        }
    }

    private PendingKeySetRecoveryData? FindRow(string personHandle, string recoveryId)
    {
        return _rows.FirstOrDefault(row => string.Equals(row.PersonHandle, personHandle, StringComparison.Ordinal) && string.Equals(row.RecoveryId, recoveryId, StringComparison.Ordinal));
    }

    // Callers get copies, as from a durable store: a changed row is stored only through Update.
    private static PendingKeySetRecoveryData Copy(PendingKeySetRecoveryData row)
    {
        return new PendingKeySetRecoveryData
        {
            PersonHandle = row.PersonHandle,
            RecoveryId = row.RecoveryId,
            RemovedCredentialId = row.RemovedCredentialId,
            RemovedKeyFingerprint = row.RemovedKeyFingerprint,
            HeirCredentialId = row.HeirCredentialId,
            HeirKeyFingerprint = row.HeirKeyFingerprint,
            Anchor = row.Anchor,
            AssertionJson = row.AssertionJson,
            BeganUtc = row.BeganUtc,
            EffectiveUtc = row.EffectiveUtc,
            CanceledUtc = row.CanceledUtc,
            CancelReason = row.CancelReason,
            CanceledByCredentialId = row.CanceledByCredentialId,
            CompletedUtc = row.CompletedUtc
        };
    }
}
