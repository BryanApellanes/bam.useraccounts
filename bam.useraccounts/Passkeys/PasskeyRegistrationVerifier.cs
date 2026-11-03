using System.Security.Cryptography;
using System.Text;
using Bam.Encryption;
using Bam.Encryption.Cose;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// The WebAuthn §7.1 checks for a registration response: client data type, challenge and
/// origin; attestation object and authenticator data shape; RP id hash; user presence and,
/// when required, verification; the credential id matches the attested one; the algorithm is
/// one the host offers; the public key parses.  Pure: no storage, never throws on client input.
/// Attestation statements are not verified (registration requests <c>none</c>).
/// </summary>
public sealed class PasskeyRegistrationVerifier
{
    private readonly PasskeyOptions _options;

    /// <summary>Initializes the verifier with the relying-party policy.</summary>
    public PasskeyRegistrationVerifier(PasskeyOptions options)
    {
        _options = options;
    }

    /// <summary>
    /// Verifies a registration response against the challenge that was issued for it.
    /// </summary>
    /// <param name="response">The browser's registration response.</param>
    /// <param name="expectedChallenge">The challenge bytes issued by the server.</param>
    /// <returns>The verification outcome, with the parsed credential on success.</returns>
    public PasskeyVerification Verify(PasskeyRegistrationResponse? response, byte[] expectedChallenge)
    {
        ArgumentNullException.ThrowIfNull(expectedChallenge);
        if (response?.Response is null || string.IsNullOrEmpty(response.Id))
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.MalformedClientData, "registration response is missing id or response.");
        }
        if (!string.Equals(response.Type, "public-key", StringComparison.Ordinal))
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.MalformedClientData, "registration response type is not public-key.");
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
        PasskeyVerification? clientFailure = PasskeyEncoding.CheckClientData(clientData!, ClientData.TypeCreate, expectedChallenge, _options);
        if (clientFailure is not null)
        {
            return clientFailure;
        }

        byte[]? attestationBytes = PasskeyEncoding.TryDecode(response.Response.AttestationObject);
        if (attestationBytes is null)
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.MalformedAttestation, "attestationObject is not base64url.");
        }
        if (!AttestationObject.TryParse(attestationBytes, out AttestationObject? attestation, out string? attestationError))
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.MalformedAttestation, attestationError ?? "attestationObject is malformed.");
        }
        if (!AuthenticatorData.TryParse(attestation!.AuthData, out AuthenticatorData? authenticatorData, out string? authError))
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.MalformedAuthenticatorData, authError!);
        }
        PasskeyVerification? authFailure = PasskeyEncoding.CheckAuthenticatorData(authenticatorData!, _options);
        if (authFailure is not null)
        {
            return authFailure;
        }
        if (authenticatorData!.AttestedCredential is null)
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.MalformedAuthenticatorData, "authenticatorData carries no attested credential.");
        }

        AttestedCredential attested = authenticatorData.AttestedCredential;
        string credentialId = Base64UrlEncoder.Default.Encode(attested.CredentialId);
        byte[]? responseId = PasskeyEncoding.TryDecode(response.Id);
        byte[]? responseRawId = string.IsNullOrEmpty(response.RawId) ? responseId : PasskeyEncoding.TryDecode(response.RawId);
        if (responseId is null || responseRawId is null
            || !CryptographicOperations.FixedTimeEquals(responseId, attested.CredentialId)
            || !CryptographicOperations.FixedTimeEquals(responseRawId, attested.CredentialId))
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.CredentialIdMismatch, "response id does not match the attested credential id.");
        }
        if (!_options.Algorithms.Contains(attested.Key.Algorithm))
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.UnsupportedAlgorithm, $"credential algorithm {attested.Key.Algorithm} is not offered.");
        }
        IPublicKey publicKey;
        try
        {
            publicKey = attested.Key.ToPublicKey();
        }
        catch (CoseKeyException e)
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.InvalidCredentialKey, e.Message);
        }

        List<string> transports = response.Response.Transports?.Where(transport => !string.IsNullOrWhiteSpace(transport)).ToList() ?? new List<string>();
        ParsedPasskeyCredential credential = new ParsedPasskeyCredential(
            credentialId,
            attested.CredentialId,
            publicKey,
            attested.Key.Algorithm,
            attested.Aaguid,
            authenticatorData.SignCount,
            authenticatorData.Flags,
            transports);
        return PasskeyVerification.Ok(credential, authenticatorData);
    }
}

/// <summary>
/// The checks and decoding shared by the registration and assertion verifiers.
/// </summary>
internal static class PasskeyEncoding
{
    /// <summary>
    /// The longest base64url field accepted from a response (64 KiB of text, about 48 KiB of
    /// bytes).  Real <c>clientDataJSON</c>, <c>authenticatorData</c> and <c>attestationObject</c>
    /// values are a few hundred bytes to a few KiB; the cap keeps a hostile response from
    /// driving a large decode and CBOR parse.  Hosts should still bound the request body.
    /// </summary>
    public const int MaxFieldLength = 64 * 1024;

    /// <summary>Decodes base64url, returning null instead of throwing (also for over-long input).</summary>
    public static byte[]? TryDecode(string? base64Url)
    {
        if (string.IsNullOrEmpty(base64Url) || base64Url.Length > MaxFieldLength)
        {
            return null;
        }
        try
        {
            return Base64UrlEncoder.Default.Decode(base64Url);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>The SHA-256 of the RP id, as the authenticator computes it.</summary>
    public static byte[] RpIdHash(PasskeyOptions options)
    {
        return SHA256.HashData(Encoding.UTF8.GetBytes(options.RpId));
    }

    /// <summary>Type, challenge and origin checks on parsed client data; null when they pass.</summary>
    public static PasskeyVerification? CheckClientData(ClientData clientData, string expectedType, byte[] expectedChallenge, PasskeyOptions options)
    {
        if (!string.Equals(clientData.Type, expectedType, StringComparison.Ordinal))
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.WrongType, $"clientDataJSON type is '{clientData.Type}', expected '{expectedType}'.");
        }
        byte[]? presentedChallenge = TryDecode(clientData.Challenge);
        if (presentedChallenge is null || !CryptographicOperations.FixedTimeEquals(presentedChallenge, expectedChallenge))
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.ChallengeMismatch, "clientDataJSON challenge does not match the issued challenge.");
        }
        if (!options.IsOriginAllowed(clientData.Origin))
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.OriginNotAllowed, $"clientDataJSON origin '{clientData.Origin}' is not allowed.");
        }
        return null;
    }

    /// <summary>RP id hash, user presence and user verification checks; null when they pass.</summary>
    public static PasskeyVerification? CheckAuthenticatorData(AuthenticatorData authenticatorData, PasskeyOptions options)
    {
        if (!CryptographicOperations.FixedTimeEquals(authenticatorData.RpIdHash, RpIdHash(options)))
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.RpIdMismatch, "authenticatorData rpIdHash does not match the configured RP id.");
        }
        if (!authenticatorData.UserPresent)
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.UserNotPresent, "authenticatorData user-present flag is not set.");
        }
        if (options.RequireUserVerification && !authenticatorData.UserVerified)
        {
            return PasskeyVerification.Fail(PasskeyVerificationFailure.UserNotVerified, "user verification is required and the user-verified flag is not set.");
        }
        return null;
    }
}
