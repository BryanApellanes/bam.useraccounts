using Bam.Data.Repositories;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Durable <see cref="IPasskeyCredentialRepository"/> over an <see cref="IRepository"/>, the same
/// shape as <see cref="PersistedConfirmationChallengeRepository"/>: keyed queries only (no
/// predicate scans), <c>AddType</c> in the constructor, a process-local lock around every
/// operation.  Register as a singleton.
/// </summary>
public sealed class PersistedPasskeyCredentialRepository : IPasskeyCredentialRepository
{
    private readonly IRepository _repository;
    private readonly object _lock = new object();

    /// <summary>
    /// Initializes the repository over the backing store, registering
    /// <see cref="PasskeyCredentialData"/> as a storable type.
    /// </summary>
    /// <param name="repository">The durable store.</param>
    public PersistedPasskeyCredentialRepository(IRepository repository)
    {
        _repository = repository;
        _repository.AddType<PasskeyCredentialData>();
    }

    /// <inheritdoc />
    public PasskeyCredentialData Save(PasskeyCredentialData credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        lock (_lock)
        {
            PasskeyCredentialData created = _repository.Create(credential);
            return created ?? credential;
        }
    }

    /// <inheritdoc />
    public PasskeyCredentialData? FindByCredentialId(string credentialId)
    {
        lock (_lock)
        {
            return QueryBy(nameof(PasskeyCredentialData.CredentialId), credentialId).FirstOrDefault();
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<PasskeyCredentialData> FindByHandle(string personHandle)
    {
        lock (_lock)
        {
            return QueryBy(nameof(PasskeyCredentialData.PersonHandle), personHandle).OrderBy(credential => credential.CreatedUtc).ToList();
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<PasskeyCredentialData> FindByUserHandle(string userHandle)
    {
        lock (_lock)
        {
            return QueryBy(nameof(PasskeyCredentialData.UserHandle), userHandle).OrderBy(credential => credential.CreatedUtc).ToList();
        }
    }

    /// <inheritdoc />
    public void RecordUse(string credentialId, long signCount, DateTime usedUtc)
    {
        lock (_lock)
        {
            PasskeyCredentialData? credential = QueryBy(nameof(PasskeyCredentialData.CredentialId), credentialId).FirstOrDefault();
            if (credential is null)
            {
                return;
            }
            credential.SignCount = signCount;
            credential.LastUsedUtc = usedUtc;
            _repository.Update(credential);
        }
    }

    /// <inheritdoc />
    public void FlagSignCountRegression(string credentialId)
    {
        lock (_lock)
        {
            PasskeyCredentialData? credential = QueryBy(nameof(PasskeyCredentialData.CredentialId), credentialId).FirstOrDefault();
            if (credential is null)
            {
                return;
            }
            credential.SignCountRegressed = true;
            _repository.Update(credential);
        }
    }

    /// <inheritdoc />
    public bool Activate(string credentialId)
    {
        lock (_lock)
        {
            PasskeyCredentialData? credential = QueryBy(nameof(PasskeyCredentialData.CredentialId), credentialId).FirstOrDefault();
            if (credential is null)
            {
                return false;
            }
            credential.Pending = false;
            _repository.Update(credential);
            return true;
        }
    }

    /// <inheritdoc />
    public bool Remove(string credentialId)
    {
        lock (_lock)
        {
            bool removed = false;
            foreach (PasskeyCredentialData credential in QueryBy(nameof(PasskeyCredentialData.CredentialId), credentialId).ToList())
            {
                removed |= _repository.Delete(credential);
            }
            return removed;
        }
    }

    private IEnumerable<PasskeyCredentialData> QueryBy(string propertyName, string value)
    {
        Dictionary<string, object> query = new Dictionary<string, object> { { propertyName, value } };
        return _repository.Query<PasskeyCredentialData>(query);
    }
}
