namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Raised when WebAuthn client data, authenticator data, an attestation object or a response
/// DTO is malformed.  Verifiers catch it and report a <see cref="PasskeyVerificationFailure"/>;
/// it only escapes the <c>Parse</c> and <c>FromJson</c> methods.
/// <para>
/// The message describes bytes a caller chose and often quotes them (a parser naming the
/// property it choked on), so both constructors pass it through <see cref="PasskeyText.Printable"/>:
/// <see cref="Exception.Message"/> is always one line of at most
/// <see cref="PasskeyVerification.MaxDetailLength"/> characters plus a truncation note.  Code that
/// relays the message may pass it through <see cref="PasskeyText.Printable"/> again without
/// changing it.  An inner exception keeps its own full text.
/// </para>
/// </summary>
public class PasskeyFormatException : FormatException
{
    /// <summary>Initializes a new instance with a message.</summary>
    public PasskeyFormatException(string message) : base(PasskeyText.Printable(message, PasskeyVerification.MaxDetailLength))
    {
    }

    /// <summary>Initializes a new instance with a message and cause.</summary>
    public PasskeyFormatException(string message, Exception innerException) : base(PasskeyText.Printable(message, PasskeyVerification.MaxDetailLength), innerException)
    {
    }
}
