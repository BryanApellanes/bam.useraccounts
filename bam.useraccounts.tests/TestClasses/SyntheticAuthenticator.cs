using System.Security.Cryptography;
using System.Text;
using Bam.Encryption;
using Bam.Encryption.Cose;
using Bam.UserAccounts.Passkeys;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Bam.UserAccounts.Tests.TestClasses;

/// <summary>
/// A software WebAuthn authenticator for tests: holds one credential (ES256 or RS256), builds
/// <c>clientDataJSON</c>, <c>authenticatorData</c> and a <c>none</c> attestation object exactly
/// as a browser would hand them to the relying party, and signs assertions.  Every field can be
/// overridden to produce a specific wrong input.
/// </summary>
public sealed class SyntheticAuthenticator
{
    private readonly AsymmetricCipherKeyPair _keyPair;

    /// <summary>Creates an authenticator with a fresh credential on the given algorithm.</summary>
    public SyntheticAuthenticator(CoseAlgorithm algorithm = CoseAlgorithm.ES256, string origin = "https://lumberjack.live", string rpId = "lumberjack.live")
    {
        Algorithm = algorithm;
        Origin = origin;
        RpId = rpId;
        CredentialId = RandomBytes(16);
        Aaguid = RandomBytes(16);
        if (algorithm == CoseAlgorithm.RS256)
        {
            _keyPair = new RsaPublicPrivateKeyPair(RsaKeyLength._2048).GetAsymmetricCipherKeyPair();
            CoseKey = CoseKey.FromRsa(new RsaPublicKey(_keyPair.Public.ToPem()));
        }
        else
        {
            _keyPair = EccPublicPrivateKeyPair.Generate();
            CoseKey = CoseKey.FromEcc(new EccPublicKey(_keyPair.Public), algorithm);
        }
    }

    public CoseAlgorithm Algorithm { get; }
    public string Origin { get; set; }
    public string RpId { get; set; }
    public byte[] CredentialId { get; set; }
    public byte[] Aaguid { get; }
    public CoseKey CoseKey { get; }
    public uint SignCount { get; set; } = 1;
    public bool UserPresent { get; set; } = true;
    public bool UserVerified { get; set; } = true;
    public bool BackupEligible { get; set; }
    public bool BackedUp { get; set; }

    /// <summary>The credential id as the browser reports it.</summary>
    public string CredentialIdBase64Url => Base64UrlEncoder.Default.Encode(CredentialId);

    /// <summary>The credential's public key PEM, as the relying party stores it.</summary>
    public string PublicKeyPem => CoseKey.ToPublicKey().Pem;

    /// <summary>Builds the client data JSON for a ceremony type and challenge.</summary>
    public byte[] ClientDataJson(string type, byte[] challenge, string? origin = null)
    {
        string json = "{\"type\":\"" + type + "\",\"challenge\":\"" + Base64UrlEncoder.Default.Encode(challenge)
            + "\",\"origin\":\"" + (origin ?? Origin) + "\",\"crossOrigin\":false}";
        return Encoding.UTF8.GetBytes(json);
    }

    /// <summary>Builds authenticator data, with the attested credential when <paramref name="attested"/> is true.</summary>
    public byte[] AuthenticatorData(bool attested, string? rpId = null, byte[]? extensions = null)
    {
        byte flags = 0;
        if (UserPresent) flags |= 0x01;
        if (UserVerified) flags |= 0x04;
        if (BackupEligible) flags |= 0x08;
        if (BackedUp) flags |= 0x10;
        if (attested) flags |= 0x40;
        if (extensions is not null) flags |= 0x80;
        List<byte> bytes = new List<byte>();
        bytes.AddRange(SHA256.HashData(Encoding.UTF8.GetBytes(rpId ?? RpId)));
        bytes.Add(flags);
        bytes.AddRange(new byte[] { (byte)(SignCount >> 24), (byte)(SignCount >> 16), (byte)(SignCount >> 8), (byte)SignCount });
        if (attested)
        {
            bytes.AddRange(Aaguid);
            bytes.Add((byte)(CredentialId.Length >> 8));
            bytes.Add((byte)CredentialId.Length);
            bytes.AddRange(CredentialId);
            bytes.AddRange(CborWriter.Encode(CoseKey.ToCbor()));
        }
        if (extensions is not null)
        {
            bytes.AddRange(extensions);
        }
        return bytes.ToArray();
    }

    /// <summary>Builds a <c>none</c> attestation object around authenticator data.</summary>
    public static byte[] AttestationObject(byte[] authData, string fmt = "none")
    {
        return CborWriter.Encode(CborWriter.Map(
            CborWriter.Entry("fmt", new CborText(fmt)),
            CborWriter.Entry("authData", new CborBytes(authData)),
            CborWriter.Entry("attStmt", CborWriter.Map())));
    }

    /// <summary>Builds a complete registration response for a challenge.</summary>
    public PasskeyRegistrationResponse Register(byte[] challenge, string? origin = null, string? rpId = null, byte[]? clientData = null, byte[]? authData = null, string? id = null, List<string>? transports = null)
    {
        byte[] client = clientData ?? ClientDataJson(ClientData.TypeCreate, challenge, origin);
        byte[] auth = authData ?? AuthenticatorData(true, rpId);
        string credentialId = id ?? CredentialIdBase64Url;
        return new PasskeyRegistrationResponse
        {
            Id = credentialId,
            RawId = credentialId,
            Type = "public-key",
            Response = new PasskeyAttestationResponseData
            {
                ClientDataJson = Base64UrlEncoder.Default.Encode(client),
                AttestationObject = Base64UrlEncoder.Default.Encode(AttestationObject(auth)),
                Transports = transports ?? new List<string> { "internal" }
            }
        };
    }

    /// <summary>Builds a complete, correctly signed assertion response for a challenge.</summary>
    public PasskeyAssertionResponse Assert(byte[] challenge, string? ceremonyId = null, string? userHandle = null, string? origin = null, string? rpId = null, byte[]? clientData = null, byte[]? authData = null, byte[]? signature = null, string? id = null)
    {
        byte[] client = clientData ?? ClientDataJson(ClientData.TypeGet, challenge, origin);
        byte[] auth = authData ?? AuthenticatorData(false, rpId);
        byte[] sig = signature ?? Sign(auth, client);
        string credentialId = id ?? CredentialIdBase64Url;
        return new PasskeyAssertionResponse
        {
            Id = credentialId,
            RawId = credentialId,
            Type = "public-key",
            CeremonyId = ceremonyId,
            Response = new PasskeyAssertionResponseData
            {
                ClientDataJson = Base64UrlEncoder.Default.Encode(client),
                AuthenticatorData = Base64UrlEncoder.Default.Encode(auth),
                Signature = Base64UrlEncoder.Default.Encode(sig),
                UserHandle = userHandle
            }
        };
    }

    /// <summary>Signs <c>authenticatorData || SHA-256(clientDataJSON)</c> with the credential's private key.</summary>
    public byte[] Sign(byte[] authData, byte[] clientDataJson)
    {
        byte[] hash = SHA256.HashData(clientDataJson);
        byte[] payload = new byte[authData.Length + hash.Length];
        Buffer.BlockCopy(authData, 0, payload, 0, authData.Length);
        Buffer.BlockCopy(hash, 0, payload, authData.Length, hash.Length);
        ISigner signer = SignerUtilities.GetSigner(CoseAlgorithms.SignerName(Algorithm));
        signer.Init(true, _keyPair.Private);
        signer.BlockUpdate(payload, 0, payload.Length);
        return signer.GenerateSignature();
    }

    public static byte[] RandomBytes(int count)
    {
        byte[] bytes = new byte[count];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }
}
