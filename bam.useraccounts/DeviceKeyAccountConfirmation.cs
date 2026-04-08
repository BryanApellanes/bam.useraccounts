using System.Security.Cryptography;
using Bam.Protocol;
using Bam.Protocol.Data;
using Bam.Protocol.Profile;

namespace Bam.UserAccounts;

public class DeviceKeyAccountConfirmation : IAccountConfirmation
{
    private readonly ICertificateManager _certificateManager;
    private readonly IKeyManager _keyManager;
    private readonly IProfileManager _profileManager;
    private readonly Dictionary<string, ConfirmationChallenge> _pendingChallenges = new();
    private readonly object _lock = new();

    public DeviceKeyAccountConfirmation(
        ICertificateManager certificateManager,
        IKeyManager keyManager,
        IProfileManager profileManager)
    {
        _certificateManager = certificateManager;
        _keyManager = keyManager;
        _profileManager = profileManager;
    }

    public ConfirmationChallenge CreateChallenge(string personHandle)
    {
        var challengeBytes = new byte[32];
        RandomNumberGenerator.Fill(challengeBytes);

        var challenge = new ConfirmationChallenge
        {
            PersonHandle = personHandle,
            ChallengeBytes = challengeBytes,
            ExpiresUtc = DateTime.UtcNow.AddMinutes(10)
        };

        lock (_lock)
        {
            _pendingChallenges[personHandle] = challenge;
        }

        return challenge;
    }

    public ConfirmationResult VerifySignedChallenge(string personHandle, byte[] signedChallenge)
    {
        ConfirmationChallenge? challenge;
        lock (_lock)
        {
            if (!_pendingChallenges.TryGetValue(personHandle, out challenge))
            {
                return new ConfirmationResult
                {
                    Confirmed = false,
                    Success = false,
                    Message = "No pending challenge for this handle"
                };
            }

            _pendingChallenges.Remove(personHandle);
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

        var profile = _profileManager.FindProfileByHandle(personHandle);
        if (profile == null)
        {
            return new ConfirmationResult
            {
                Confirmed = false,
                Success = false,
                Message = "Profile not found"
            };
        }

        var publicKey = _profileManager.FindProfileByPublicKey(profile.PersonHandle);
        if (publicKey == null)
        {
            return new ConfirmationResult
            {
                Confirmed = false,
                Success = false,
                Message = "Public key not found for profile"
            };
        }

        var person = new Bam.Protocol.Data.Common.ActorData
        {
            Handle = personHandle,
            Name = profile.Name
        };

        var certificate = _certificateManager.CreateSignedCertificate(person);

        return new ConfirmationResult
        {
            Confirmed = true,
            Success = true,
            Certificate = certificate,
            Message = "Account confirmed via device key"
        };
    }
}
