using Bam.Data.Repositories;

namespace Bam.UserAccounts;

/// <summary>
/// Persisted form of a pending <see cref="ConfirmationChallenge"/>.  The nonce is stored
/// base64-encoded so composite-key hashing operates on a string.
/// </summary>
[Serializable]
public class ConfirmationChallengeData : KeyedAuditRepoData
{
    [CompositeKey]
    public string PersonHandle { get; set; } = null!;

    [CompositeKey]
    public string NonceBase64 { get; set; } = null!;

    public DateTime ExpiresUtc { get; set; }
}
