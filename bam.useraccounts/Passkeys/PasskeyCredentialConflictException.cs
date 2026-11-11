namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Thrown by <see cref="IPasskeyCredentialRepository.Save"/> when a credential with the same
/// credential id is already stored.  Credential ids are unique across all persons, and custody
/// enforces that itself (the check and the insert are one operation under the repository's
/// lock) so two registrations that present one credential id can never both store a row.
/// </summary>
public class PasskeyCredentialConflictException : Exception
{
    /// <summary>Initializes the exception for a credential id.</summary>
    /// <param name="credentialId">The credential id that is already stored.</param>
    public PasskeyCredentialConflictException(string credentialId)
        : base($"A passkey credential with id '{credentialId}' is already stored.")
    {
        CredentialId = credentialId;
    }

    /// <summary>The credential id that is already stored.</summary>
    public string CredentialId { get; }
}
