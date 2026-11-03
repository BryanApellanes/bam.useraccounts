using System.Buffers.Binary;
using Bam.Encryption.Cose;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// The flags byte of WebAuthn authenticator data (§6.1).
/// </summary>
[Flags]
public enum AuthenticatorFlags : byte
{
    /// <summary>No flags.</summary>
    None = 0,
    /// <summary>UP: the user was present.</summary>
    UserPresent = 0x01,
    /// <summary>UV: the user was verified.</summary>
    UserVerified = 0x04,
    /// <summary>BE: the credential is eligible for backup (synced passkey).</summary>
    BackupEligible = 0x08,
    /// <summary>BS: the credential is currently backed up.</summary>
    BackedUp = 0x10,
    /// <summary>AT: attested credential data follows.</summary>
    AttestedCredentialIncluded = 0x40,
    /// <summary>ED: extension data follows.</summary>
    ExtensionsIncluded = 0x80
}

/// <summary>
/// The attested credential data an authenticator includes at registration.
/// </summary>
/// <param name="Aaguid">The authenticator's AAGUID (16 bytes).</param>
/// <param name="CredentialId">The credential id bytes.</param>
/// <param name="Key">The credential public key.</param>
public sealed record AttestedCredential(byte[] Aaguid, byte[] CredentialId, CoseKey Key);

/// <summary>
/// Parsed WebAuthn authenticator data (§6.1): <c>rpIdHash(32) || flags(1) || signCount(4, big endian)
/// || [attestedCredentialData] || [extensions]</c>.  Keeps the raw bytes because the signature
/// covers them as-is.
/// </summary>
public sealed record AuthenticatorData
{
    private const int HeaderLength = 37;
    private const int AaguidLength = 16;

    private AuthenticatorData(byte[] rpIdHash, AuthenticatorFlags flags, uint signCount, AttestedCredential? attestedCredential, byte[] rawBytes)
    {
        RpIdHash = rpIdHash;
        Flags = flags;
        SignCount = signCount;
        AttestedCredential = attestedCredential;
        RawBytes = rawBytes;
    }

    /// <summary>The SHA-256 of the RP id the authenticator scoped the credential to.</summary>
    public byte[] RpIdHash { get; }

    /// <summary>The flags.</summary>
    public AuthenticatorFlags Flags { get; }

    /// <summary>The signature counter.</summary>
    public uint SignCount { get; }

    /// <summary>The attested credential, present only when <see cref="AuthenticatorFlags.AttestedCredentialIncluded"/> is set.</summary>
    public AttestedCredential? AttestedCredential { get; }

    /// <summary>The exact bytes the authenticator produced.</summary>
    public byte[] RawBytes { get; }

    /// <summary>Whether the user-present flag is set.</summary>
    public bool UserPresent => Flags.HasFlag(AuthenticatorFlags.UserPresent);

    /// <summary>Whether the user-verified flag is set.</summary>
    public bool UserVerified => Flags.HasFlag(AuthenticatorFlags.UserVerified);

    /// <summary>
    /// Parses authenticator data, reporting the reason instead of throwing when it is malformed.
    /// An attested credential's COSE key is parsed strictly; extension data is required to be a
    /// single well-formed CBOR item and is otherwise ignored.
    /// </summary>
    /// <param name="rawBytes">The authenticator data bytes.</param>
    /// <param name="authenticatorData">The parsed data on success.</param>
    /// <param name="error">Why parsing failed, on failure.</param>
    public static bool TryParse(byte[]? rawBytes, out AuthenticatorData? authenticatorData, out string? error)
    {
        authenticatorData = null;
        error = null;
        if (rawBytes is null || rawBytes.Length < HeaderLength)
        {
            error = "authenticatorData is shorter than 37 bytes.";
            return false;
        }
        byte[] rpIdHash = rawBytes[..32];
        AuthenticatorFlags flags = (AuthenticatorFlags)rawBytes[32];
        uint signCount = BinaryPrimitives.ReadUInt32BigEndian(rawBytes.AsSpan(33, 4));
        int position = HeaderLength;
        AttestedCredential? attested = null;

        if (flags.HasFlag(AuthenticatorFlags.AttestedCredentialIncluded))
        {
            if (rawBytes.Length < position + AaguidLength + 2)
            {
                error = "authenticatorData flags AT but is too short for attested credential data.";
                return false;
            }
            byte[] aaguid = rawBytes[position..(position + AaguidLength)];
            position += AaguidLength;
            int credentialIdLength = BinaryPrimitives.ReadUInt16BigEndian(rawBytes.AsSpan(position, 2));
            position += 2;
            if (credentialIdLength == 0 || rawBytes.Length < position + credentialIdLength)
            {
                error = "authenticatorData credential id length is zero or exceeds the data.";
                return false;
            }
            byte[] credentialId = rawBytes[position..(position + credentialIdLength)];
            position += credentialIdLength;
            CborValue keyValue;
            int consumed;
            try
            {
                keyValue = CborReader.Read(rawBytes.AsSpan(position), out consumed);
            }
            catch (CborFormatException e)
            {
                error = "authenticatorData credential public key is not valid CBOR: " + e.Message;
                return false;
            }
            if (keyValue is not CborMap keyMap)
            {
                error = "authenticatorData credential public key is not a CBOR map.";
                return false;
            }
            CoseKey key;
            try
            {
                key = CoseKey.From(keyMap);
            }
            catch (CoseKeyException e)
            {
                error = "authenticatorData credential public key is not a supported COSE key: " + e.Message;
                return false;
            }
            position += consumed;
            attested = new AttestedCredential(aaguid, credentialId, key);
        }

        if (flags.HasFlag(AuthenticatorFlags.ExtensionsIncluded))
        {
            try
            {
                CborReader.Read(rawBytes.AsSpan(position), out int extensionLength);
                position += extensionLength;
            }
            catch (CborFormatException e)
            {
                error = "authenticatorData extensions are not valid CBOR: " + e.Message;
                return false;
            }
        }

        if (position != rawBytes.Length)
        {
            error = $"authenticatorData has {rawBytes.Length - position} trailing bytes.";
            return false;
        }
        authenticatorData = new AuthenticatorData(rpIdHash, flags, signCount, attested, rawBytes);
        return true;
    }

    /// <summary>Parses authenticator data.</summary>
    /// <exception cref="PasskeyFormatException">The bytes are not valid authenticator data.</exception>
    public static AuthenticatorData Parse(byte[] rawBytes)
    {
        if (!TryParse(rawBytes, out AuthenticatorData? authenticatorData, out string? error))
        {
            throw new PasskeyFormatException(error!);
        }
        return authenticatorData!;
    }
}
