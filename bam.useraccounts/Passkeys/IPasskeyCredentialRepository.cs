namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Custody of passkey credentials.  Credential ids are unique across all persons; a person may
/// hold several credentials that share one user handle.
/// </summary>
public interface IPasskeyCredentialRepository
{
    /// <summary>Stores a new credential.</summary>
    /// <param name="credential">The credential to store.</param>
    /// <returns>The stored credential.</returns>
    PasskeyCredentialData Save(PasskeyCredentialData credential);

    /// <summary>Finds a credential by its base64url id, or null.</summary>
    PasskeyCredentialData? FindByCredentialId(string credentialId);

    /// <summary>Finds every credential registered to a person, oldest first.</summary>
    IReadOnlyList<PasskeyCredentialData> FindByHandle(string personHandle);

    /// <summary>Finds every credential carrying a user handle (base64url), across persons.</summary>
    IReadOnlyList<PasskeyCredentialData> FindByUserHandle(string userHandle);

    /// <summary>Records a successful assertion: the new sign counter and the time of use.</summary>
    void RecordUse(string credentialId, long signCount, DateTime usedUtc);

    /// <summary>Flags a credential whose sign counter regressed.</summary>
    void FlagSignCountRegression(string credentialId);

    /// <summary>Clears <see cref="PasskeyCredentialData.Pending"/> on a credential, making it usable.</summary>
    /// <param name="credentialId">The credential id, base64url.</param>
    /// <returns>Whether a credential with that id exists (and is now not pending).</returns>
    bool Activate(string credentialId);

    /// <summary>Removes a credential; returns whether one was removed.</summary>
    bool Remove(string credentialId);
}
