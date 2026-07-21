using Bam.Data.Repositories;

namespace Bam.UserAccounts;

/// <summary>
/// Durable <see cref="IConfirmationChallengeRepository"/> backed by an <see cref="IRepository"/>,
/// so pending challenges survive a process restart.  Maintains the one-pending-challenge-per-handle
/// invariant by deleting any prior records for a handle on <see cref="Save"/>.
/// </summary>
public class PersistedConfirmationChallengeRepository : IConfirmationChallengeRepository
{
    private readonly IRepository _repository;
    private readonly object _lock = new();

    public PersistedConfirmationChallengeRepository(IRepository repository)
    {
        _repository = repository;
        _repository.AddType<ConfirmationChallengeData>();
    }

    public void Save(ConfirmationChallenge challenge)
    {
        lock (_lock)
        {
            DeletePending(challenge.PersonHandle);
            ConfirmationChallengeData data = new ConfirmationChallengeData
            {
                PersonHandle = challenge.PersonHandle,
                NonceBase64 = Convert.ToBase64String(challenge.ChallengeBytes),
                ExpiresUtc = challenge.ExpiresUtc
            };
            _repository.Create(data);
        }
    }

    public ConfirmationChallenge? Take(string personHandle)
    {
        lock (_lock)
        {
            ConfirmationChallengeData? data = _repository
                .Query<ConfirmationChallengeData>(pending => pending.PersonHandle == personHandle)
                .OrderByDescending(pending => pending.ExpiresUtc)
                .FirstOrDefault();
            if (data == null)
            {
                return null;
            }

            DeletePending(personHandle);
            return new ConfirmationChallenge
            {
                PersonHandle = data.PersonHandle,
                ChallengeBytes = Convert.FromBase64String(data.NonceBase64),
                ExpiresUtc = data.ExpiresUtc
            };
        }
    }

    private void DeletePending(string personHandle)
    {
        List<ConfirmationChallengeData> existing = _repository
            .Query<ConfirmationChallengeData>(pending => pending.PersonHandle == personHandle)
            .ToList();
        foreach (ConfirmationChallengeData data in existing)
        {
            _repository.Delete(data);
        }
    }
}
