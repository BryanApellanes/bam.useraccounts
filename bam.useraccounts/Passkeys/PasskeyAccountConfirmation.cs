using System.Security.Cryptography;
using Bam.Encryption;
using Bam.Protocol;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Common;
using Bam.Protocol.Data.Profile;
using Org.BouncyCastle.X509;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// <see cref="IAccountConfirmation"/> for passkeys, the shape of <see cref="DeviceKeyAccountConfirmation"/>
/// with the signed challenge being a passkey assertion (UTF-8 JSON of a
/// <see cref="PasskeyAssertionResponse"/>) and the registered key set resolved by its ECC key
/// first, then RSA.  Hosts drive the browser with <see cref="IPasskeyCeremony.ToRequestOptions"/>
/// on the challenge this creates.  Confirmation issues the same signed actor certificate the
/// device-key path issues.
/// </summary>
public sealed class PasskeyAccountConfirmation : IAccountConfirmation
{
    private readonly PasskeyOptions _options;
    private readonly ICertificateManager _certificateManager;
    private readonly IProfileRepository _profileRepository;
    private readonly PasskeyChallengeSignatureVerifier _signatureVerifier;
    private readonly IConfirmationChallengeRepository _challengeRepository;

    /// <summary>Initializes the confirmation over its collaborators.</summary>
    public PasskeyAccountConfirmation(
        PasskeyOptions options,
        ICertificateManager certificateManager,
        IProfileRepository profileRepository,
        PasskeyChallengeSignatureVerifier signatureVerifier,
        IConfirmationChallengeRepository challengeRepository)
    {
        _options = options;
        _certificateManager = certificateManager;
        _profileRepository = profileRepository;
        _signatureVerifier = signatureVerifier;
        _challengeRepository = challengeRepository;
    }

    /// <inheritdoc />
    public ConfirmationChallenge CreateChallenge(string personHandle)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(personHandle);
        byte[] challengeBytes = new byte[32];
        RandomNumberGenerator.Fill(challengeBytes);
        ConfirmationChallenge challenge = new ConfirmationChallenge
        {
            PersonHandle = personHandle,
            ChallengeBytes = challengeBytes,
            ExpiresUtc = DateTime.UtcNow.Add(_options.ChallengeLifetime)
        };
        _challengeRepository.Save(challenge);
        return challenge;
    }

    /// <inheritdoc />
    public ConfirmationResult VerifySignedChallenge(string personHandle, byte[] signedChallenge)
    {
        ConfirmationChallenge? challenge = _challengeRepository.Take(personHandle);
        if (challenge is null)
        {
            return Failed("No pending challenge for this handle");
        }
        if (DateTime.UtcNow > challenge.ExpiresUtc)
        {
            return Failed("Challenge has expired");
        }

        PublicKeySetData? keySet = _profileRepository.FindPublicKeySetByHandle(personHandle);
        IPublicKey? signerPublicKey = ResolveKeySetKey(keySet);
        if (signerPublicKey is null)
        {
            return Failed(DeviceKeyAccountConfirmation.VerificationFailedMessage);
        }

        ISignatureVerification verification;
        try
        {
            verification = _signatureVerifier.Verify(challenge, signedChallenge, signerPublicKey);
        }
        catch (Exception)
        {
            return Failed(DeviceKeyAccountConfirmation.VerificationFailedMessage);
        }
        if (!verification.Success)
        {
            return Failed(DeviceKeyAccountConfirmation.VerificationFailedMessage);
        }

        ActorData person = new ActorData { Handle = personHandle, Name = ResolveActorName(personHandle) };
        X509Certificate certificate = _certificateManager.CreateSignedCertificate(person);
        return new ConfirmationResult
        {
            Confirmed = true,
            Success = true,
            Certificate = certificate,
            Message = "Account confirmed via passkey"
        };
    }

    private static IPublicKey? ResolveKeySetKey(PublicKeySetData? keySet)
    {
        if (keySet is null)
        {
            return null;
        }
        try
        {
            if (!string.IsNullOrEmpty(keySet.PublicEccKey))
            {
                return new EccPublicKey(keySet.PublicEccKey);
            }
            if (!string.IsNullOrEmpty(keySet.PublicRsaKey))
            {
                return new RsaPublicKey(keySet.PublicRsaKey);
            }
        }
        catch (Exception)
        {
            return null;
        }
        return null;
    }

    private string ResolveActorName(string personHandle)
    {
        ProfileData? profile = _profileRepository.FindProfileByHandle(personHandle)
            ?? _profileRepository.FindProfileByPersonHandle(personHandle);
        return profile is null || string.IsNullOrEmpty(profile.Name) ? personHandle : profile.Name;
    }

    private static ConfirmationResult Failed(string message)
    {
        return new ConfirmationResult { Confirmed = false, Success = false, Message = message };
    }
}
