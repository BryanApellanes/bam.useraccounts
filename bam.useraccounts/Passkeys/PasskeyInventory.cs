using Bam.Logging;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// <see cref="IPasskeyInventory"/> over <see cref="IPasskeyCredentialRepository"/>.
/// <para>
/// On a host that can hand a key set over (<see cref="IKeySetHandover.IsAvailable"/>), removing
/// the passkey that holds the person's key set answers <see cref="PasskeyRemoval.KeySetHandoverRequired"/>
/// unless the caller asks to keep the key set: the handover moves it to a passkey the person
/// keeps first (bam.useraccounts#20).  Removing it keeping the key set is always allowed (a lost
/// first device must be removable by its owner): sign-in and account confirmation both go
/// through the credential store, so the removed passkey stops working at once.  The key set then
/// stays registered under the handle until it is rotated or revoked through <c>bam.protocol</c>;
/// that is logged at warning level.  Without a handover, every removal is that one.
/// </para>
/// </summary>
public sealed class PasskeyInventory : IPasskeyInventory
{
    /// <summary>The longest passkey name kept.</summary>
    public const int MaxNameLength = 64;

    /// <summary>
    /// Serializes removals with each other and with key-set handover completion, so counting a
    /// person's passkeys and removing one is a single step.  Process-wide (cross-process custody is #4).
    /// </summary>
    internal static readonly object RemovalLock = new object();

    private readonly IPasskeyCredentialRepository _credentials;
    private readonly IKeySetHandover? _handover;

    /// <summary>Initializes the inventory over passkey custody, with no key-set handover.</summary>
    /// <param name="credentials">Passkey custody.</param>
    public PasskeyInventory(IPasskeyCredentialRepository credentials)
        : this(credentials, null)
    {
    }

    /// <summary>Initializes the inventory over passkey custody and the host's key-set handover.</summary>
    /// <param name="credentials">Passkey custody.</param>
    /// <param name="handover">The key-set handover, or null when the host has none.</param>
    public PasskeyInventory(IPasskeyCredentialRepository credentials, IKeySetHandover? handover)
    {
        _credentials = credentials;
        _handover = handover;
    }

    /// <inheritdoc />
    public IReadOnlyList<PasskeyCredentialData> List(string personHandle)
    {
        if (string.IsNullOrWhiteSpace(personHandle))
        {
            return new List<PasskeyCredentialData>();
        }
        // A pending row is a registration the registrar has not accepted: not one of the person's passkeys.
        return _credentials.FindByHandle(personHandle).Where(credential => !credential.Pending).ToList();
    }

    /// <inheritdoc />
    public bool Rename(string personHandle, string credentialId, string? name)
    {
        PasskeyCredentialData? credential = Owned(personHandle, credentialId);
        if (credential is null)
        {
            return false;
        }
        string? trimmed = string.IsNullOrWhiteSpace(name) ? null : name.Trim();
        if (trimmed is not null && trimmed.Length > MaxNameLength)
        {
            trimmed = trimmed.Substring(0, MaxNameLength).TrimEnd();
        }
        bool renamed = _credentials.SetName(personHandle, credential.CredentialId, trimmed);
        if (renamed)
        {
            Log.Info("Passkey {0} of {1} renamed", credential.CredentialId, personHandle);
        }
        return renamed;
    }

    /// <inheritdoc />
    public PasskeyRemoval Remove(string personHandle, string credentialId)
    {
        return Remove(personHandle, credentialId, keepKeySet: false);
    }

    /// <inheritdoc />
    public PasskeyRemoval Remove(string personHandle, string credentialId, bool keepKeySet)
    {
        PasskeyCredentialData? credential = Owned(personHandle, credentialId);
        if (credential is null)
        {
            return PasskeyRemoval.NotFound;
        }
        // The count, the key-set decision and the removal are one step under the lock a handover
        // completes under: two removals racing for a person's last two passkeys must leave one, and
        // a removal racing a handover must see the key set where the handover left it, or it could
        // remove the heir that has just become the key set.  Removals are rare, so one process-wide
        // lock is enough; the repositories themselves are process-local (cross-process custody is #4).
        lock (RemovalLock)
        {
            credential = Owned(personHandle, credentialId);
            if (credential is null)
            {
                return PasskeyRemoval.NotFound;
            }
            if (List(personHandle).Count <= 1)
            {
                return PasskeyRemoval.LastCredential;
            }
            if (!keepKeySet && _handover is not null && _handover.IsRequiredFor(credential))
            {
                return PasskeyRemoval.KeySetHandoverRequired;
            }
            if (!_credentials.Remove(personHandle, credential.CredentialId))
            {
                return PasskeyRemoval.NotFound;
            }
        }
        if (credential.IsRegisteredKeySet)
        {
            Log.Warn("Passkey {0} of {1} removed{2}; it was the registered key set, which stays registered until rotated or revoked", credential.CredentialId, personHandle, keepKeySet ? " keeping the key set" : string.Empty);
        }
        else
        {
            Log.Info("Passkey {0} of {1} removed", credential.CredentialId, personHandle);
        }
        return PasskeyRemoval.Removed;
    }

    private PasskeyCredentialData? Owned(string personHandle, string credentialId)
    {
        if (string.IsNullOrWhiteSpace(personHandle) || string.IsNullOrWhiteSpace(credentialId))
        {
            return null;
        }
        PasskeyCredentialData? credential = _credentials.FindByCredentialId(credentialId);
        return credential is not null && !credential.Pending && string.Equals(credential.PersonHandle, personHandle, StringComparison.Ordinal) ? credential : null;
    }
}
