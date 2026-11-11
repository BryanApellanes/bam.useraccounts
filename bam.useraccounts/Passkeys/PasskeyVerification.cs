using Bam.Encryption;
using Bam.Encryption.Cose;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// The outcome of a pure passkey verification: success with the parsed material, or a failure
/// reason plus a detail string meant for logs (never for the caller).
/// </summary>
public sealed record PasskeyVerification
{
    private PasskeyVerification(bool success, PasskeyVerificationFailure failure, string detail, ParsedPasskeyCredential? credential, AuthenticatorData? authenticatorData)
    {
        Success = success;
        Failure = failure;
        Detail = detail;
        Credential = credential;
        AuthenticatorData = authenticatorData;
    }

    /// <summary>Whether verification passed.</summary>
    public bool Success { get; }

    /// <summary>The failure reason, or <see cref="PasskeyVerificationFailure.None"/>.</summary>
    public PasskeyVerificationFailure Failure { get; }

    /// <summary>A short diagnostic for logs; contains no credential material or PII.</summary>
    public string Detail { get; }

    /// <summary>The parsed credential on a successful registration verification.</summary>
    public ParsedPasskeyCredential? Credential { get; }

    /// <summary>The parsed authenticator data on success.</summary>
    public AuthenticatorData? AuthenticatorData { get; }

    /// <summary>A successful registration verification.</summary>
    public static PasskeyVerification Ok(ParsedPasskeyCredential credential, AuthenticatorData authenticatorData)
    {
        return new PasskeyVerification(true, PasskeyVerificationFailure.None, string.Empty, credential, authenticatorData);
    }

    /// <summary>A successful assertion verification.</summary>
    public static PasskeyVerification Ok(AuthenticatorData authenticatorData)
    {
        return new PasskeyVerification(true, PasskeyVerificationFailure.None, string.Empty, null, authenticatorData);
    }

    /// <summary>The most characters of a failure detail that are kept.</summary>
    public const int MaxDetailLength = 400;

    /// <summary>
    /// The cap to use when a detail is made printable again on its way to a log: a detail that
    /// <see cref="Fail"/> already cut carries a truncation note after its <see cref="MaxDetailLength"/>
    /// characters, and a second cut at the same length would replace that note with a wrong count.
    /// </summary>
    public const int MaxLoggedDetailLength = MaxDetailLength + 32;

    /// <summary>
    /// A failed verification.  The detail may quote what the client sent (an origin, a type, a
    /// parser's complaint about its bytes), so it is passed through <see cref="PasskeyText.Printable"/>:
    /// one line, no control characters, at most <see cref="MaxDetailLength"/> characters.
    /// </summary>
    public static PasskeyVerification Fail(PasskeyVerificationFailure failure, string detail)
    {
        return new PasskeyVerification(false, failure, PasskeyText.Printable(detail, MaxDetailLength), null, null);
    }
}

/// <summary>
/// The credential a successful registration verification extracted from the attested
/// credential data.
/// </summary>
/// <param name="CredentialId">The credential id, base64url.</param>
/// <param name="CredentialIdBytes">The credential id bytes.</param>
/// <param name="PublicKey">The credential public key as a framework key.</param>
/// <param name="Algorithm">The COSE algorithm the credential signs with.</param>
/// <param name="Aaguid">The authenticator's AAGUID (16 bytes).</param>
/// <param name="SignCount">The initial sign counter.</param>
/// <param name="Flags">The authenticator data flags at registration.</param>
/// <param name="Transports">The transports the browser reported, possibly empty.</param>
public sealed record ParsedPasskeyCredential(
    string CredentialId,
    byte[] CredentialIdBytes,
    IPublicKey PublicKey,
    CoseAlgorithm Algorithm,
    byte[] Aaguid,
    uint SignCount,
    AuthenticatorFlags Flags,
    IReadOnlyList<string> Transports);
