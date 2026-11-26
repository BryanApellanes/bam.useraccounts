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
            // Only the fields a recovery may change after it is stored.
            stored.CanceledUtc = recovery.CanceledUtc;
            stored.CancelReason = recovery.CancelReason;
            stored.CanceledByCredentialId = recovery.CanceledByCredentialId;
            stored.CompletedUtc = recovery.CompletedUtc;
            _repository.Update(stored);
            return true;
        }
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
