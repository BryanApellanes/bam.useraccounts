using Bam.Encryption;

namespace Bam.UserAccounts;

/// <summary>
/// Decides whether signature bytes are a valid signature over a confirmation challenge
/// by the holder of the private key matching the specified public key.
/// </summary>
public interface IChallengeSignatureVerifier
{
    /// <summary>
    /// Verifies that <paramref name="signedChallenge"/> is a valid signature over
    /// <paramref name="challenge"/>'s bytes, made with the private key matching
    /// <paramref name="signerPublicKey"/>.
    /// </summary>
    /// <param name="challenge">The challenge whose bytes were signed.</param>
    /// <param name="signedChallenge">The raw signature bytes presented by the caller.</param>
    /// <param name="signerPublicKey">The public key to verify against.</param>
    /// <returns>The verification result; <see cref="ISignatureVerification.Success"/> is true only for a valid signature.</returns>
    ISignatureVerification Verify(ConfirmationChallenge challenge, byte[] signedChallenge, IPublicKey signerPublicKey);
}
