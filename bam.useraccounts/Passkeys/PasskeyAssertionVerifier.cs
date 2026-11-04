using System.Security.Cryptography;
using Bam.Encryption;
using Bam.Encryption.Cose;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// The WebAuthn §7.2 checks for an assertion against the issued challenge, the relying-party
/// policy and the stored credential: client data type, challenge and origin; authenticator data
/// shape, RP id hash, user presence and verification policy; user handle, when returned,
/// matches the credential; sign counter monotonic when the stored counter is non-zero; and the
/// signature over <c>authenticatorData || SHA-256(clientDataJSON)</c> verifies under the
/// credential's public key.  Pure: no storage, never throws on client input.
/// </summary>
public sealed class PasskeyAssertionVerifier
{
    private readonly PasskeyOptions _options;
    private readonly IDetachedSignatureVerifier _signatureVerifier;

    /// <summary>Initializes the verifier with the relying-party policy and a detached signature verifier.</summary>
    public PasskeyAssertionVerifier(PasskeyOptions options, IDetachedSignatureVerifier signatureVerifier)
    {
        _options = options;
        _signatureVerifier = signatureVerifier;
    }

    /// <summary>
    /// Verifies an assertion response.
    /// </summary>
    /// <param name="response">The browser's assertion response.</param>
    /// <param name="expectedChallenge">The challenge bytes issued by the server.</param>
    /// <param name="credential">The stored credential the response id resolved to.</param>
    /// <returns>The verification outcome, with the parsed authenticator data on success.</returns>
    public PasskeyVerification Verify(PasskeyAssertionResponse? response, byte[] expectedChallenge, PasskeyCredentialData credential)
    {
        ArgumentNullException.ThrowIfNull(expectedChallenge);
        ArgumentNullException.ThrowIfNull(credential);
        if (response?.Response is null || string.IsNullOrEmpty(response.Id))
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.MalformedClientData, "assertion response is missing id or response.");
        }
        if (!string.Equals(response.Id, credential.CredentialId, StringComparison.Ordinal))
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.UnknownCredential, "assertion response id is not the credential's id.");
        }

        byte[]? clientDataBytes = PasskeyEncoding.TryDecode(response.Response.ClientDataJson);
        if (clientDataBytes is null)
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.MalformedClientData, "clientDataJSON is not base64url.");
        }
        if (!ClientData.TryParse(clientDataBytes, out ClientData? clientData, out string? clientError))
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.MalformedClientData, clientError ?? "clientDataJSON is malformed.");
        }
        PasskeyVerification? clientFailure = PasskeyEncoding.CheckClientData(clientData!, ClientData.TypeGet, expectedChallenge, _options);
        if (clientFailure is not null)
        {
            return clientFailure;
        }

        byte[]? authenticatorBytes = PasskeyEncoding.TryDecode(response.Response.AuthenticatorData);
        if (authenticatorBytes is null)
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.MalformedAuthenticatorData, "authenticatorData is not base64url.");
        }
        if (!AuthenticatorData.TryParse(authenticatorBytes, out AuthenticatorData? authenticatorData, out string? authError))
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.MalformedAuthenticatorData, authError ?? "authenticatorData is malformed.");
        }
        PasskeyVerification? authFailure = PasskeyEncoding.CheckAuthenticatorData(authenticatorData!, _options);
        if (authFailure is not null)
        {
            return authFailure;
        }

        if (!string.IsNullOrEmpty(response.Response.UserHandle) && !string.Equals(response.Response.UserHandle, credential.UserHandle, StringComparison.Ordinal))
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.UnknownCredential, "assertion user handle does not match the credential's user handle.");
        }

        if (credential.SignCount > 0 && authenticatorData!.SignCount <= credential.SignCount)
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.SignCountRegressed, $"sign counter {authenticatorData.SignCount} did not advance past {credential.SignCount}.");
        }

        byte[]? signature = PasskeyEncoding.TryDecode(response.Response.Signature);
        if (signature is null || signature.Length == 0)
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.InvalidSignature, "signature is missing or not base64url.");
        }
        if (!CoseAlgorithms.IsSupported(credential.Algorithm))
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.UnsupportedAlgorithm, $"stored credential algorithm {credential.Algorithm} is not supported.");
        }
        CoseAlgorithm algorithm = (CoseAlgorithm)credential.Algorithm;
        IPublicKey publicKey;
        try
        {
            publicKey = CoseAlgorithms.KeyType(algorithm) == CoseAlgorithms.KeyTypeRsa
                ? new RsaPublicKey(credential.PublicKeyPem)
                : new EccPublicKey(credential.PublicKeyPem);
        }
        catch (Exception e)
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.InvalidCredentialKey, "stored credential key does not parse: " + e.Message);
        }
        if (publicKey.Value is null || publicKey.Value.IsPrivate)
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.InvalidCredentialKey, "stored credential key is not a public key PEM.");
        }

        byte[] clientDataHash = clientData!.Hash();
        byte[] payload = new byte[authenticatorData!.RawBytes.Length + clientDataHash.Length];
        Buffer.BlockCopy(authenticatorData.RawBytes, 0, payload, 0, authenticatorData.RawBytes.Length);
        Buffer.BlockCopy(clientDataHash, 0, payload, authenticatorData.RawBytes.Length, clientDataHash.Length);

        ISignatureVerification verification = _signatureVerifier.Verify(payload, signature, publicKey, CoseAlgorithms.SignerName(algorithm));
        if (!verification.Success)
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.InvalidSignature, "signature does not verify: " + verification.Message);
        }
        return PasskeyVerification.Ok(authenticatorData);
    }
}
