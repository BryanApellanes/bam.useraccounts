using System.Security.Cryptography;
using Bam.Encryption;
using Bam.Protocol;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Common;
using Bam.Protocol.Data.Profile;
using Org.BouncyCastle.X509;

namespace Bam.UserAccounts;

/// <summary>
/// Confirms account ownership by proof of key possession: a caller is confirmed only by presenting
/// a valid signature, made with the private key matching the public key set registered under their
/// handle, over the challenge nonce previously issued for that handle.
/// </summary>
public class DeviceKeyAccountConfirmation : IAccountConfirmation
{
    private readonly ICertificateManager _certificateManager;
    private readonly IProfileRepository _profileRepository;
    private readonly IChallengeSignatureVerifier _signatureVerifier;
    private readonly IConfirmationChallengeRepository _challengeRepository;

    public DeviceKeyAccountConfirmation(
        ICertificateManager certificateManager,
        IProfileRepository profileRepository,
        IChallengeSignatureVerifier signatureVerifier,
        IConfirmationChallengeRepository challengeRepository)
    {
        _certificateManager = certificateManager;
        _profileRepository = profileRepository;
        _signatureVerifier = signatureVerifier;
        _challengeRepository = challengeRepository;
    }

    public ConfirmationChallenge CreateChallenge(string personHandle)
    {
        byte[] challengeBytes = new byte[32];
        RandomNumberGenerator.Fill(challengeBytes);

        ConfirmationChallenge challenge = new ConfirmationChallenge
        {
            PersonHandle = personHandle,
            ChallengeBytes = challengeBytes,
            ExpiresUtc = DateTime.UtcNow.AddMinutes(10)
        };

        _challengeRepository.Save(challenge);

        return challenge;
    }

    public ConfirmationResult VerifySignedChallenge(string personHandle, byte[] signedChallenge)
    {
        ConfirmationChallenge? challenge = _challengeRepository.Take(personHandle);
        if (challenge == null)
        {
            return new ConfirmationResult
            {
                Confirmed = false,
                Success = false,
                Message = "No pending challenge for this handle"
            };
        }

        if (DateTime.UtcNow > challenge.ExpiresUtc)
        {
            return new ConfirmationResult
            {
                Confirmed = false,
                Success = false,
                Message = "Challenge has expired"
            };
        }

        PublicKeySetData publicKeySet = _profileRepository.FindPublicKeySetByHandle(personHandle);
        if (publicKeySet == null || string.IsNullOrEmpty(publicKeySet.PublicRsaKey))
        {
            return new ConfirmationResult
            {
                Confirmed = false,
                Success = false,
                Message = "No registered signing key for this handle"
            };
        }

        ISignatureVerification verification;
        try
        {
            RsaPublicKey signerPublicKey = new RsaPublicKey(publicKeySet.PublicRsaKey);
            verification = _signatureVerifier.Verify(challenge, signedChallenge, signerPublicKey);
        }
        catch (Exception)
        {
            return new ConfirmationResult
            {
                Confirmed = false,
                Success = false,
                Message = "Signature verification failed"
            };
        }

        if (!verification.Success)
        {
            return new ConfirmationResult
            {
                Confirmed = false,
                Success = false,
                Message = $"Signature invalid: expected {RsaChallengeSignatureVerifier.Algorithm} over the base64 form of the challenge bytes ({verification.Message})"
            };
        }

        ActorData person = new ActorData
        {
            Handle = personHandle,
            Name = ResolveActorName(personHandle)
        };

        X509Certificate certificate = _certificateManager.CreateSignedCertificate(person);

        return new ConfirmationResult
        {
            Confirmed = true,
            Success = true,
            Certificate = certificate,
            Message = "Account confirmed via device key"
        };
    }

    private string ResolveActorName(string personHandle)
    {
        ProfileData profile = _profileRepository.FindProfileByHandle(personHandle)
            ?? _profileRepository.FindProfileByPersonHandle(personHandle);
        if (profile == null || string.IsNullOrEmpty(profile.Name))
        {
            return personHandle;
        }
        return profile.Name;
    }
}
