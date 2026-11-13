namespace Bam.UserAccounts.Passkeys;

/// <summary>The outcome of <see cref="IPasskeyInventory.Remove"/>.</summary>
public enum PasskeyRemoval
{
    /// <summary>The credential was removed.</summary>
    Removed = 0,

    /// <summary>The person has no credential with that id (it does not exist, or it is someone else's).</summary>
    NotFound,

    /// <summary>The credential is the person's only passkey; removing it would lock them out.</summary>
    LastCredential,

    /// <summary>
    /// The credential holds the person's key set and this host can hand it over
    /// (<see cref="IKeySetHandover"/>): move the key set first, or remove it keeping the key set.
    /// </summary>
    KeySetHandoverRequired
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

    /// <summary>
    /// Removes one of the person's passkeys, unless it is their last, or it holds their key set
    /// and the host can hand that over (<see cref="PasskeyRemoval.KeySetHandoverRequired"/>).
    /// </summary>
    /// <param name="personHandle">The authenticated person's handle.</param>
    /// <param name="credentialId">The credential id, base64url.</param>
    PasskeyRemoval Remove(string personHandle, string credentialId);

    /// <summary>
    /// Removes one of the person's passkeys, unless it is their last.  With
    /// <paramref name="keepKeySet"/>, a passkey holding the key set is removed without a handover
    /// and the key set stays registered until it is rotated or revoked: removal is always possible,
    /// so a lost device comes off sign-in at once.
    /// </summary>
    /// <param name="personHandle">The authenticated person's handle.</param>
    /// <param name="credentialId">The credential id, base64url.</param>
    /// <param name="keepKeySet">Remove a key-set passkey without moving the key set.</param>
    PasskeyRemoval Remove(string personHandle, string credentialId, bool keepKeySet);
}
