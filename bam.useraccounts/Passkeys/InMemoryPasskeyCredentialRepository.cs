namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Process-local <see cref="IPasskeyCredentialRepository"/> for tests and single-process hosts.
/// Register as a singleton; credentials do not survive a restart.
/// </summary>
public sealed class InMemoryPasskeyCredentialRepository : IPasskeyCredentialRepository
{
    private readonly Dictionary<string, PasskeyCredentialData> _byCredentialId = new Dictionary<string, PasskeyCredentialData>(StringComparer.Ordinal);
    private readonly object _lock = new object();

    /// <inheritdoc />
    public PasskeyCredentialData Save(PasskeyCredentialData credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        lock (_lock)
        {
            if (!_byCredentialId.TryAdd(credential.CredentialId, credential))
            {
                throw new PasskeyCredentialConflictException(credential.CredentialId);
            }
            return credential;
        }
    }

    /// <inheritdoc />
    public PasskeyCredentialData? FindByCredentialId(string credentialId)
    {
        lock (_lock)
        {
            return _byCredentialId.TryGetValue(credentialId, out PasskeyCredentialData? credential) ? credential : null;
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<PasskeyCredentialData> FindByHandle(string personHandle)
    {
        lock (_lock)
        {
            return _byCredentialId.Values
                .Where(credential => string.Equals(credential.PersonHandle, personHandle, StringComparison.Ordinal))
                .OrderBy(credential => credential.CreatedUtc)
                .ToList();
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<PasskeyCredentialData> FindByUserHandle(string userHandle)
    {
        lock (_lock)
        {
            return _byCredentialId.Values
                .Where(credential => string.Equals(credential.UserHandle, userHandle, StringComparison.Ordinal))
                .OrderBy(credential => credential.CreatedUtc)
                .ToList();
        }
    }

    /// <inheritdoc />
    public void RecordUse(string credentialId, long signCount, DateTime usedUtc)
    {
        lock (_lock)
        {
            if (_byCredentialId.TryGetValue(credentialId, out PasskeyCredentialData? credential))
            {
                credential.SignCount = signCount;
                credential.LastUsedUtc = usedUtc;
            }
        }
    }

    /// <inheritdoc />
    public void FlagSignCountRegression(string credentialId)
    {
        lock (_lock)
        {
            if (_byCredentialId.TryGetValue(credentialId, out PasskeyCredentialData? credential))
            {
                credential.SignCountRegressed = true;
            }
        }
    }

    /// <inheritdoc />
    public bool Activate(string personHandle, string credentialId)
    {
        lock (_lock)
        {
            if (!_byCredentialId.TryGetValue(credentialId, out PasskeyCredentialData? credential)
                || !string.Equals(credential.PersonHandle, personHandle, StringComparison.Ordinal))
            {
                return false;
            }
            credential.Pending = false;
            return true;
        }
    }

    /// <inheritdoc />
    public bool SetName(string personHandle, string credentialId, string? name)
    {
        lock (_lock)
        {
            if (!_byCredentialId.TryGetValue(credentialId, out PasskeyCredentialData? credential)
                || !string.Equals(credential.PersonHandle, personHandle, StringComparison.Ordinal))
            {
                return false;
            }
            credential.Name = string.IsNullOrWhiteSpace(name) ? null : name.Trim();
            return true;
        }
    }

    /// <inheritdoc />
    public bool SetRegisteredKeySet(string personHandle, string credentialId, bool isRegisteredKeySet)
    {
        lock (_lock)
        {
            if (!_byCredentialId.TryGetValue(credentialId, out PasskeyCredentialData? credential)
                || !string.Equals(credential.PersonHandle, personHandle, StringComparison.Ordinal))
            {
                return false;
            }
            credential.IsRegisteredKeySet = isRegisteredKeySet;
            return true;
        }
    }

    /// <inheritdoc />
    public bool Remove(string personHandle, string credentialId)
    {
        lock (_lock)
        {
            if (!_byCredentialId.TryGetValue(credentialId, out PasskeyCredentialData? credential)
                || !string.Equals(credential.PersonHandle, personHandle, StringComparison.Ordinal))
            {
                return false;
            }
            return _byCredentialId.Remove(credentialId);
        }
    }
}
