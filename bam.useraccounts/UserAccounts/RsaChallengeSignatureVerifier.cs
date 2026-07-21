using Bam.Encryption;

namespace Bam.UserAccounts;

/// <summary>
/// Verifies challenge signatures produced by the framework RSA signing convention
/// (<see cref="RsaPrivateKey.Sign(byte[])"/>): the signature algorithm is SHA512WITHRSA and the
/// signed payload is the UTF-8 encoding of the base64 string form of the challenge bytes.
/// </summary>
public class RsaChallengeSignatureVerifier : IChallengeSignatureVerifier
{
    /// <summary>
    /// The BouncyCastle signature algorithm used by the framework RSA signing convention.
    /// </summary>
    public const string Algorithm = "SHA512WITHRSA";

    private readonly ISignatureProvider _signatureProvider;

    public RsaChallengeSignatureVerifier(ISignatureProvider signatureProvider)
    {
        _signatureProvider = signatureProvider;
    }

    public ISignatureVerification Verify(ConfirmationChallenge challenge, byte[] signedChallenge, IPublicKey signerPublicKey)
    {
        Signature signature = new Signature
        {
            SignatureBytes = signedChallenge,
            Data = Convert.ToBase64String(challenge.ChallengeBytes),
            Algorithm = Algorithm
        };
        return _signatureProvider.VerifySignature(signature, signerPublicKey);
    }
}
