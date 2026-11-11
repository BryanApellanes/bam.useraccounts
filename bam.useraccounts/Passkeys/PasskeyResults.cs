namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// The outcome of <see cref="IPasskeyCeremony.CompleteRegistration"/>.
/// </summary>
public class PasskeyRegistrationResult : UserAccountResponse
{
    /// <summary>Why the registration was refused, or <see cref="PasskeyVerificationFailure.None"/>.</summary>
    public PasskeyVerificationFailure Failure { get; set; }

    /// <summary>The stored credential id (base64url) on success.</summary>
    public string? CredentialId { get; set; }

    /// <summary>Whether this credential became the handle's registered key set (true for the first passkey, unless the handle already had a key set).</summary>
    public bool KeySetRegistered { get; set; }

    /// <summary>The canonical fingerprint of the credential's public key, for <c>handle@fingerprint</c> admission.</summary>
    public string? KeyFingerprint { get; set; }
}

/// <summary>
/// The outcome of <see cref="IPasskeyCeremony.CompleteAssertion"/>.
/// </summary>
public class PasskeySignInResult : UserAccountResponse
{
    /// <summary>Why the sign-in was refused, or <see cref="PasskeyVerificationFailure.None"/>.</summary>
    public PasskeyVerificationFailure Failure { get; set; }

    /// <summary>The person handle the credential belongs to, on success.</summary>
    public string? PersonHandle { get; set; }

    /// <summary>The credential id (base64url) that signed, on success.</summary>
    public string? CredentialId { get; set; }

    /// <summary>The canonical fingerprint of the signing credential's public key.</summary>
    public string? KeyFingerprint { get; set; }

    /// <summary>Whether the authenticator reported user verification.</summary>
    public bool UserVerified { get; set; }
}
