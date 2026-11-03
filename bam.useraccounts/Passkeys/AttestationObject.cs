using Bam.Encryption.Cose;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// The CBOR attestation object a registration response carries (§6.5): <c>fmt</c>, the raw
/// <c>authData</c>, and the attestation statement map, which is kept but never trusted
/// (registration asks for attestation <c>none</c>).
/// </summary>
public sealed record AttestationObject
{
    private AttestationObject(string fmt, byte[] authData, CborMap attStmt)
    {
        Fmt = fmt;
        AuthData = authData;
        AttStmt = attStmt;
    }

    /// <summary>The attestation statement format (<c>none</c>, <c>packed</c>, ...).</summary>
    public string Fmt { get; }

    /// <summary>The raw authenticator data.</summary>
    public byte[] AuthData { get; }

    /// <summary>The attestation statement, retained for diagnostics only.</summary>
    public CborMap AttStmt { get; }

    /// <summary>
    /// Parses an attestation object, reporting the reason instead of throwing when it is malformed.
    /// </summary>
    /// <param name="cbor">The CBOR bytes.</param>
    /// <param name="attestationObject">The parsed object on success.</param>
    /// <param name="error">Why parsing failed, on failure.</param>
    public static bool TryParse(byte[]? cbor, out AttestationObject? attestationObject, out string? error)
    {
        attestationObject = null;
        error = null;
        if (cbor is null || cbor.Length == 0)
        {
            error = "attestationObject is empty.";
            return false;
        }
        CborValue value;
        try
        {
            value = CborReader.Read(cbor);
        }
        catch (CborFormatException e)
        {
            error = "attestationObject is not valid CBOR: " + e.Message;
            return false;
        }
        if (value is not CborMap map)
        {
            error = "attestationObject is not a CBOR map.";
            return false;
        }
        if (map["fmt"] is not CborText fmt || map["authData"] is not CborBytes authData || map["attStmt"] is not CborMap attStmt)
        {
            error = "attestationObject is missing fmt, authData or attStmt.";
            return false;
        }
        attestationObject = new AttestationObject(fmt.Value, authData.Value, attStmt);
        return true;
    }

    /// <summary>Parses an attestation object.</summary>
    /// <exception cref="PasskeyFormatException">The bytes are not a valid attestation object.</exception>
    public static AttestationObject Parse(byte[] cbor)
    {
        if (!TryParse(cbor, out AttestationObject? attestationObject, out string? error))
        {
            throw new PasskeyFormatException(error!);
        }
        return attestationObject!;
    }
}
