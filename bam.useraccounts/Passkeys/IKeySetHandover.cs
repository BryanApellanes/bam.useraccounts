namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Removes the passkey that is a person's registered key set by first moving the key set to a
/// passkey they keep (bam.useraccounts#20).  Begin returns assertion options for the passkey being
/// removed, over the rotation's challenge; complete rotates the key set with that assertion and
/// then removes the passkey.  Every method takes the handle of the person the host has
/// authenticated and never touches another person's credential.  A refused or abandoned handover
/// leaves the passkey and the key set as they were.
/// </summary>
public interface IKeySetHandover
{
    /// <summary>Whether this host can hand a key set over: a passkey rotation proof is trusted.</summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Whether removing <paramref name="credential"/> needs a handover: this host can hand over,
    /// and the credential's key is exactly its person's registered key set.
    /// </summary>
    /// <param name="credential">One of the person's accepted passkeys.</param>
    bool IsRequiredFor(PasskeyCredentialData credential);

    /// <summary>Begins handing the key set held by <paramref name="credentialId"/> over to the heir.</summary>
    /// <param name="personHandle">The authenticated person's handle.</param>
    /// <param name="credentialId">The passkey to remove; it must hold the key set.</param>
    /// <param name="heirCredentialId">The passkey to move the key set to, or null for <paramref name="sessionCredentialId"/>.</param>
    /// <param name="sessionCredentialId">The passkey the person's session was opened with.</param>
    KeySetHandoverStart Begin(string personHandle, string credentialId, string? heirCredentialId, string? sessionCredentialId);

    /// <summary>Completes a handover: rotates the key set with the assertion, then removes the old passkey.</summary>
    /// <param name="personHandle">The authenticated person's handle; must be the one the handover began for.</param>
    /// <param name="handoverId">The id <see cref="Begin"/> returned.</param>
    /// <param name="assertionJson">UTF-8 JSON of the passkey assertion (<c>PublicKeyCredential.toJSON()</c>).</param>
    KeySetHandoverResult Complete(string personHandle, string? handoverId, byte[]? assertionJson);
}
