namespace Bam.UserAccounts.Passkeys;

/// <summary>The outcome of <see cref="IPasskeyInventory.Remove"/>.</summary>
public enum PasskeyRemoval
{
    /// <summary>The credential was removed.</summary>
    Removed = 0,

    /// <summary>The person has no credential with that id (it does not exist, or it is someone else's).</summary>
    NotFound,

    /// <summary>The credential is the person's only passkey; removing it would lock them out.</summary>
    LastCredential
}

/// <summary>
/// The rules of a person's "manage passkeys" page.  Every method takes the handle of the person
/// the host has authenticated and never touches another person's credential.
/// </summary>
public interface IPasskeyInventory
{
    /// <summary>The person's passkeys, oldest first.</summary>
    /// <param name="personHandle">The authenticated person's handle.</param>
    IReadOnlyList<PasskeyCredentialData> List(string personHandle);

    /// <summary>Names one of the person's passkeys.</summary>
    /// <param name="personHandle">The authenticated person's handle.</param>
    /// <param name="credentialId">The credential id, base64url.</param>
    /// <param name="name">The new name; trimmed, cut to <see cref="PasskeyInventory.MaxNameLength"/>, blank clears it.</param>
    /// <returns>Whether the person has that credential and it was renamed.</returns>
    bool Rename(string personHandle, string credentialId, string? name);

    /// <summary>Removes one of the person's passkeys, unless it is their last.</summary>
    /// <param name="personHandle">The authenticated person's handle.</param>
    /// <param name="credentialId">The credential id, base64url.</param>
    PasskeyRemoval Remove(string personHandle, string credentialId);
}
