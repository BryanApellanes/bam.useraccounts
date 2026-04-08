namespace Bam.UserAccounts;

public class ConfirmationChallenge
{
    public string PersonHandle { get; set; } = null!;
    public byte[] ChallengeBytes { get; set; } = null!;
    public DateTime ExpiresUtc { get; set; }
}
