namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Raised when WebAuthn client data, authenticator data, an attestation object or a response
/// DTO is malformed.  Verifiers catch it and report a <see cref="PasskeyVerificationFailure"/>;
/// it only escapes the <c>Parse</c> methods.
/// </summary>
public class PasskeyFormatException : FormatException
{
    /// <summary>Initializes a new instance with a message.</summary>
    public PasskeyFormatException(string message) : base(message)
    {
    }

    /// <summary>Initializes a new instance with a message and cause.</summary>
    public PasskeyFormatException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
