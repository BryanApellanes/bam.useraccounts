using Bam.Logging;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// <see cref="IPasskeyInventory"/> over <see cref="IPasskeyCredentialRepository"/>.
/// <para>
/// Removing the credential that is the person's registered key set is allowed (a lost first
/// device must be revocable by its owner): sign-in and account confirmation both go through the
/// credential store, so the removed passkey stops working at once.  The key set itself stays
/// registered under the handle until it is rotated or revoked through <c>bam.protocol</c>; that
/// is logged at warning level.
/// </para>
/// </summary>
public sealed class PasskeyInventory : IPasskeyInventory
{
    /// <summary>The longest passkey name kept.</summary>
    public const int MaxNameLength = 64;

    private readonly IPasskeyCredentialRepository _credentials;

    /// <summary>Initializes the inventory over passkey custody.</summary>
    /// <param name="credentials">Passkey custody.</param>
    public PasskeyInventory(IPasskeyCredentialRepository credentials)
    {
        _credentials = credentials;
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
        bool renamed = _credentials.SetName(credential.CredentialId, trimmed);
        if (renamed)
        {
            Log.Info("Passkey {0} of {1} renamed", credential.CredentialId, personHandle);
        }
        return renamed;
    }

    /// <inheritdoc />
    public PasskeyRemoval Remove(string personHandle, string credentialId)
    {
        PasskeyCredentialData? credential = Owned(personHandle, credentialId);
        if (credential is null)
        {
            return PasskeyRemoval.NotFound;
        }
        if (List(personHandle).Count <= 1)
        {
            return PasskeyRemoval.LastCredential;
        }
        if (!_credentials.Remove(credential.CredentialId))
        {
            return PasskeyRemoval.NotFound;
        }
        if (credential.IsRegisteredKeySet)
        {
            Log.Warn("Passkey {0} of {1} removed; it was the registered key set, which stays registered until rotated or revoked", credential.CredentialId, personHandle);
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
