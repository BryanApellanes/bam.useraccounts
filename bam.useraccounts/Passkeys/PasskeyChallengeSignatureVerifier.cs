using System.Text;
using Bam.Encryption;
using Bam.Protocol.Profile;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// <see cref="IChallengeSignatureVerifier"/> for passkeys: the "signed challenge" is the UTF-8
/// JSON of a <see cref="PasskeyAssertionResponse"/> whose client data carries the challenge
/// bytes.  The credential the response names must belong to the challenge's person; the
/// assertion is then verified as in the sign-in ceremony (sign counter recorded, regressions
/// flagged).  <paramref name="signerPublicKey"/> is honoured when the credential is the person's
/// registered key set: its fingerprint must match.  Later credentials of the same person carry
/// their own keys, so for those the credential store is the trust anchor and the key-set key is
/// not compared.  That is sound because the store is written only by the sign-up ceremony, which
/// refuses a handle that already has a credential or a key set, and by the additional-registration
/// path, which the host exposes only to a caller already authenticated as the person.
/// </summary>
public sealed class PasskeyChallengeSignatureVerifier : IChallengeSignatureVerifier
{
    private readonly PasskeyCeremony _ceremony;
    private readonly IPasskeyCredentialRepository _credentials;

    /// <summary>Initializes the verifier over the ceremony and the credential store.</summary>
    public PasskeyChallengeSignatureVerifier(PasskeyCeremony ceremony, IPasskeyCredentialRepository credentials)
    {
        _ceremony = ceremony;
        _credentials = credentials;
    }

    /// <inheritdoc />
    public ISignatureVerification Verify(ConfirmationChallenge challenge, byte[] signedChallenge, IPublicKey signerPublicKey)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        PasskeyAssertionResponse? response;
        try
        {
            response = signedChallenge is null || signedChallenge.Length == 0 ? null : PasskeyAssertionResponse.FromJson(signedChallenge);
        }
        catch (PasskeyFormatException e)
        {
            // FromJson's PasskeyFormatException is built in PasskeyJson.Deserialize, which has already made the
            // parser's message one bounded line.  Cutting it again here would replace its truncation note with a wrong count.
            return Failed(signerPublicKey, "assertion is not valid JSON: " + e.Message);
        }
        if (response is null || string.IsNullOrEmpty(response.Id))
        {
            return Failed(signerPublicKey, "assertion names no credential.");
        }
        PasskeyCredentialData? credential = _credentials.FindByCredentialId(response.Id);
        if (credential is null || credential.Pending || !string.Equals(credential.PersonHandle, challenge.PersonHandle, StringComparison.Ordinal))
        {
            return Failed(signerPublicKey, "credential is not registered to the challenged handle.");
        }
        if (credential.IsRegisteredKeySet && signerPublicKey is not null)
        {
            string? expected = PublicKeyFingerprint.Of(signerPublicKey.Pem);
            string? actual = PublicKeyFingerprint.Of(credential.PublicKeyPem);
            if (expected is null || actual is null || !string.Equals(expected, actual, StringComparison.Ordinal))
            {
                return Failed(signerPublicKey, "credential key is not the registered key set.");
            }
        }
        PasskeySignInResult result = _ceremony.Assert(response, challenge.ChallengeBytes, credential);
        return new SignatureVerification
        {
            Success = result.Success,
            Message = result.Success ? result.Message : result.Failure.ToString(),
            IssuerPublicKey = signerPublicKey!,
            Signature = new Signature
            {
                SignatureBytes = Encoding.UTF8.GetBytes(response.Response?.Signature ?? string.Empty),
                Data = Convert.ToBase64String(challenge.ChallengeBytes),
                Algorithm = CoseAlgorithmName(credential.Algorithm)
            }
        };
    }

    private static string CoseAlgorithmName(long algorithm)
    {
        return Bam.Encryption.Cose.CoseAlgorithms.IsSupported(algorithm)
            ? ((Bam.Encryption.Cose.CoseAlgorithm)algorithm).ToString()
            : algorithm.ToString();
    }

    private static SignatureVerification Failed(IPublicKey signerPublicKey, string message)
    {
        return new SignatureVerification { Success = false, Message = message, IssuerPublicKey = signerPublicKey!, Signature = new Signature() };
    }
}
