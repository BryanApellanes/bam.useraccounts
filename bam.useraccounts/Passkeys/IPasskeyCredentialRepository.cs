namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Custody of passkey credentials.  Credential ids are unique across all persons; a person may
/// hold several credentials that share one user handle.
/// </summary>
public interface IPasskeyCredentialRepository
{
    /// <summary>
    /// Stores a new credential.  Never replaces a row: the credential-id check and the insert
    /// are one operation under the repository's lock.
    /// </summary>
    /// <param name="credential">The credential to store.</param>
    /// <returns>The stored credential.</returns>
    /// <exception cref="PasskeyCredentialConflictException">A credential with the same credential id is already stored, for this person or any other.</exception>
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

    /// <summary>
    /// Clears <see cref="PasskeyCredentialData.Pending"/> on one person's credential, making it
    /// usable.  The row is addressed by person and credential id together, so one registration
    /// can never activate a row another registration saved.
    /// </summary>
    /// <param name="personHandle">The person the credential belongs to.</param>
    /// <param name="credentialId">The credential id, base64url.</param>
    /// <returns>Whether that person has a credential with that id (and it is now not pending).</returns>
    bool Activate(string personHandle, string credentialId);

    /// <summary>
    /// Sets the display name a person gave one of their credentials (for example "work laptop"),
    /// so they can tell their passkeys apart.  The name is trimmed; a blank name clears it.  The
    /// row is addressed by person and credential id together; a credential with that id
    /// belonging to someone else is left alone.
    /// </summary>
    /// <param name="personHandle">The person the credential belongs to.</param>
    /// <param name="credentialId">The credential id, base64url.</param>
    /// <param name="name">The new display name, or null/blank to clear it.</param>
    /// <returns>Whether that person has a credential with that id and it was updated.</returns>
    bool SetName(string personHandle, string credentialId, string? name);

    /// <summary>
    /// Removes one person's credential.  The row is addressed by person and credential id
    /// together; a credential with that id belonging to someone else is left alone.
    /// </summary>
    /// <param name="personHandle">The person the credential belongs to.</param>
    /// <param name="credentialId">The credential id, base64url.</param>
    /// <returns>Whether one was removed.</returns>
    bool Remove(string personHandle, string credentialId);
}
