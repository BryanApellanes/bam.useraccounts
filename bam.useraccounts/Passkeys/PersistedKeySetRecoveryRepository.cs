using Bam.Data.Repositories;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Durable <see cref="IKeySetRecoveryRepository"/> over an <see cref="IRepository"/>, the same
/// shape as <see cref="PersistedPasskeyCredentialRepository"/>: keyed queries only, <c>AddType</c>
/// in the constructor, a process-local lock around every operation.  Register as a singleton.
/// </summary>
public sealed class PersistedKeySetRecoveryRepository : IKeySetRecoveryRepository
{
    private readonly IRepository _repository;
    private readonly object _lock = new object();

    /// <summary>
    /// Initializes the repository over the backing store, registering
    /// <see cref="PendingKeySetRecoveryData"/> as a storable type.
    /// </summary>
    /// <param name="repository">The durable store.</param>
    public PersistedKeySetRecoveryRepository(IRepository repository)
    {
        _repository = repository;
        _repository.AddType<PendingKeySetRecoveryData>();
        _repository.AddType<RemovedPasskeyKeyData>();
    }

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
            PendingKeySetRecoveryData created = _repository.Create(recovery);
            return created ?? recovery;
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<PendingKeySetRecoveryData> FindByHandle(string personHandle)
    {
        lock (_lock)
        {
            return ByHandle(personHandle).OrderBy(row => row.BeganUtc).ToList();
        }
    }

    /// <inheritdoc />
    public PendingKeySetRecoveryData? Find(string personHandle, string recoveryId)
    {
        lock (_lock)
        {
            return FindRow(personHandle, recoveryId);
        }
    }

    /// <inheritdoc />
    public bool Update(PendingKeySetRecoveryData recovery)
    {
        ArgumentNullException.ThrowIfNull(recovery);
        lock (_lock)
        {
            PendingKeySetRecoveryData? stored = FindRow(recovery.PersonHandle, recovery.RecoveryId);
            if (stored is null)
            {
                return false;
            }
            // Only the fields a recovery may change after it is stored, and only forward.
            stored.AdvanceFrom(recovery);
            _repository.Update(stored);
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
            if (FindRemovedKey(personHandle, keyFingerprint) is not null)
            {
                return;
            }
            _repository.Create(new RemovedPasskeyKeyData { PersonHandle = personHandle, KeyFingerprint = keyFingerprint, CredentialId = credentialId ?? string.Empty, RemovedUtc = DateTime.UtcNow });
        }
    }

    /// <inheritdoc />
    public bool WasRemovedPasskeyKey(string personHandle, string keyFingerprint)
    {
        if (string.IsNullOrWhiteSpace(personHandle) || string.IsNullOrWhiteSpace(keyFingerprint))
        {
            return false;
        }
        lock (_lock)
        {
            return FindRemovedKey(personHandle, keyFingerprint) is not null;
        }
    }

    private RemovedPasskeyKeyData? FindRemovedKey(string personHandle, string keyFingerprint)
    {
        Dictionary<string, object> query = new Dictionary<string, object> { { nameof(RemovedPasskeyKeyData.PersonHandle), personHandle } };
        return _repository.Query<RemovedPasskeyKeyData>(query)
            .FirstOrDefault(row => string.Equals(row.PersonHandle, personHandle, StringComparison.Ordinal) && string.Equals(row.KeyFingerprint, keyFingerprint, StringComparison.Ordinal));
    }

    private PendingKeySetRecoveryData? FindRow(string personHandle, string recoveryId)
    {
        return ByHandle(personHandle).FirstOrDefault(row => string.Equals(row.RecoveryId, recoveryId, StringComparison.Ordinal));
    }

    private IEnumerable<PendingKeySetRecoveryData> ByHandle(string personHandle)
    {
        Dictionary<string, object> query = new Dictionary<string, object> { { nameof(PendingKeySetRecoveryData.PersonHandle), personHandle } };
        return _repository.Query<PendingKeySetRecoveryData>(query)
            .Where(row => string.Equals(row.PersonHandle, personHandle, StringComparison.Ordinal));
    }
}
