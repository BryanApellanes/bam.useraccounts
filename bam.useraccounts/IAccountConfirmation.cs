namespace Bam.UserAccounts;

/// <summary>
/// Confirms account ownership by challenge and response.
/// </summary>
public interface IAccountConfirmation
{
    /// <summary>
    /// Creates a pending confirmation challenge for the specified person handle, replacing any
    /// previously pending challenge for that handle.  The caller proves key possession by signing
    /// the challenge bytes and presenting the signature to
    /// <see cref="VerifySignedChallenge(string, byte[])"/> before the challenge expires.
    /// </summary>
    /// <param name="personHandle">The handle of the person to challenge.</param>
    /// <returns>The pending challenge.</returns>
    ConfirmationChallenge CreateChallenge(string personHandle);

    /// <summary>
    /// Verifies that <paramref name="signedChallenge"/> is a valid signature over the pending
    /// challenge for <paramref name="personHandle"/>, made with the private key matching the
    /// public key set registered under that handle.
    /// <para>
    /// Signature convention: <paramref name="signedChallenge"/> is the raw signature bytes
    /// produced by the framework RSA signing path (<c>RsaPrivateKey.Sign(byte[])</c>) — algorithm
    /// SHA512WITHRSA over the UTF-8 encoding of <c>Convert.ToBase64String(challenge.ChallengeBytes)</c>.
    /// </para>
    /// <para>
    /// The pending challenge is single-use: it is consumed by this call regardless of outcome, so
    /// a failed verification requires a new challenge to retry.
    /// </para>
    /// <para>
    /// Trust assumption: verification proves possession of the private key matching the public
    /// key set REGISTERED under the handle — it is only as strong as the custody of key-set
    /// registration itself (who may save or replace a <c>PublicKeySetData</c> for a handle).
    /// Registration custody is the host's responsibility; hardening it framework-side is
    /// tracked as BryanApellanes/bam.protocol#8.
    /// </para>
    /// </summary>
    /// <param name="personHandle">The handle whose pending challenge is being answered.</param>
    /// <param name="signedChallenge">The raw signature bytes over the challenge.</param>
    /// <returns>The confirmation result; <c>Confirmed</c> is true only for a valid signature.</returns>
    ConfirmationResult VerifySignedChallenge(string personHandle, byte[] signedChallenge);
}
