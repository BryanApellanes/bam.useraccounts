namespace Bam.UserAccounts;

/// <summary>
/// Custody of pending confirmation challenges.  At most one challenge is pending per person handle,
/// and a pending challenge is single-use: <see cref="Take"/> removes it, so a challenge can be
/// presented for verification exactly once regardless of the verification outcome.
/// </summary>
public interface IConfirmationChallengeRepository
{
    /// <summary>
    /// Stores the specified challenge as the pending challenge for its person handle,
    /// replacing any previously pending challenge for that handle.
    /// </summary>
    /// <param name="challenge">The challenge to store.</param>
    void Save(ConfirmationChallenge challenge);

    /// <summary>
    /// Atomically retrieves AND removes the pending challenge for the specified person handle.
    /// Returns null when no challenge is pending.  Because the challenge is removed before any
    /// verification occurs, a failed verification consumes the challenge and a new one must be
    /// created to retry.
    /// </summary>
    /// <param name="personHandle">The person handle whose pending challenge to take.</param>
    /// <returns>The pending challenge, or null if none exists.</returns>
    ConfirmationChallenge? Take(string personHandle);
}
