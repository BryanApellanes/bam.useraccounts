namespace Bam.UserAccounts;

/// <summary>
/// Process-local <see cref="IConfirmationChallengeRepository"/> backed by an in-memory dictionary.
/// Pending challenges do not survive a process restart and are not visible to other processes;
/// use <see cref="PersistedConfirmationChallengeRepository"/> for server deployments.
/// </summary>
public class InMemoryConfirmationChallengeRepository : IConfirmationChallengeRepository
{
    private readonly Dictionary<string, ConfirmationChallenge> _pendingChallenges = new();
    private readonly object _lock = new();

    public void Save(ConfirmationChallenge challenge)
    {
        lock (_lock)
        {
            _pendingChallenges[challenge.PersonHandle] = challenge;
        }
    }

    public ConfirmationChallenge? Take(string personHandle)
    {
        lock (_lock)
        {
            if (!_pendingChallenges.TryGetValue(personHandle, out ConfirmationChallenge? challenge))
            {
                return null;
            }

            _pendingChallenges.Remove(personHandle);
            return challenge;
        }
    }
}
