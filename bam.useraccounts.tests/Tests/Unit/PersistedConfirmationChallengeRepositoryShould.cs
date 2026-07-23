using Bam.Data.Repositories;
using Bam.DependencyInjection;
using Bam.Test;
using Bam.UserAccounts;
using NSubstitute;

namespace Bam.UserAccounts.Tests.Unit;

[UnitTestMenu("PersistedConfirmationChallengeRepository Should", Selector = "pccr")]
public class PersistedConfirmationChallengeRepositoryShould : UnitTestMenuContainer
{
    public PersistedConfirmationChallengeRepositoryShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    private static void SetupDefaults(TestCaseRegistry reg)
    {
        List<ConfirmationChallengeData> store = new List<ConfirmationChallengeData>();
        IRepository backingRepository = CreateBackingRepository(store);

        reg.For<List<ConfirmationChallengeData>>().Use(store);
        reg.For<IRepository>().Use(backingRepository);
        reg.For<IConfirmationChallengeRepository>().Use(CreateRepository(backingRepository));
    }

    private static void SetupClaimAlwaysLost(TestCaseRegistry reg)
    {
        List<ConfirmationChallengeData> store = new List<ConfirmationChallengeData>();
        IRepository backingRepository = CreateBackingRepository(store);
        backingRepository.Delete(Arg.Any<ConfirmationChallengeData>()).Returns(false);

        reg.For<List<ConfirmationChallengeData>>().Use(store);
        reg.For<IRepository>().Use(backingRepository);
        reg.For<IConfirmationChallengeRepository>().Use(CreateRepository(backingRepository));
    }

    private static IRepository CreateBackingRepository(List<ConfirmationChallengeData> store)
    {
        IRepository backingRepository = Substitute.For<IRepository>();
        // The predicate overload retrieves the full record set on real backends; the hardened
        // repository must never use it, so calling it fails the test outright.
        backingRepository.Query(Arg.Any<Func<ConfirmationChallengeData, bool>>())
            .Returns(callInfo => throw new InvalidOperationException("full-table predicate scan was used"));
        backingRepository.Query<ConfirmationChallengeData>(Arg.Any<Dictionary<string, object>>())
            .Returns(callInfo =>
            {
                Dictionary<string, object> queryParameters = callInfo.Arg<Dictionary<string, object>>();
                string personHandle = (string)queryParameters[nameof(ConfirmationChallengeData.PersonHandle)];
                return store.Where(pending => pending.PersonHandle == personHandle).ToList();
            });
        backingRepository.Create(Arg.Any<ConfirmationChallengeData>())
            .Returns(callInfo =>
            {
                store.Add(callInfo.Arg<ConfirmationChallengeData>());
                return callInfo.Arg<ConfirmationChallengeData>();
            });
        backingRepository.Delete(Arg.Any<ConfirmationChallengeData>())
            .Returns(callInfo => store.Remove(callInfo.Arg<ConfirmationChallengeData>()));
        backingRepository.DeleteWhere<ConfirmationChallengeData>(Arg.Any<object>())
            .Returns(callInfo => store.RemoveAll(pending => pending.ExpiresUtc < DateTime.UtcNow) > 0);
        return backingRepository;
    }

    private static PersistedConfirmationChallengeRepository CreateRepository(IRepository backingRepository)
    {
        return new PersistedConfirmationChallengeRepository(backingRepository)
        {
            ReapInterval = TimeSpan.Zero
        };
    }

    private static ConfirmationChallenge NewChallenge(string personHandle, byte[] challengeBytes)
    {
        return new ConfirmationChallenge
        {
            PersonHandle = personHandle,
            ChallengeBytes = challengeBytes,
            ExpiresUtc = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc)
        };
    }

    private static ConfirmationChallengeData NewChallengeData(string personHandle, DateTime expiresUtc)
    {
        return new ConfirmationChallengeData
        {
            PersonHandle = personHandle,
            NonceBase64 = Convert.ToBase64String(new byte[] { 1, 2, 3 }),
            ExpiresUtc = expiresUtc
        };
    }

    [UnitTest]
    public void RoundTripChallengeThroughPersistence()
    {
        After.Setup(SetupDefaults)
        .When<IConfirmationChallengeRepository>("saves then takes a challenge", (repository) =>
        {
            repository.Save(NewChallenge("person-abc", new byte[] { 9, 8, 7, 6 }));
            return repository.Take("person-abc");
        })
        .TheTest
        .ShouldPass<ConfirmationChallenge>((because, challenge) =>
        {
            because.ItsTrue("person handle round-trips", challenge.PersonHandle == "person-abc");
            because.ItsTrue("challenge bytes round-trip through base64", challenge.ChallengeBytes.SequenceEqual(new byte[] { 9, 8, 7, 6 }));
            because.ItsTrue("expiry round-trips", challenge.ExpiresUtc == new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void DeletePersistedRecordOnTake()
    {
        After.Setup(SetupDefaults)
        .When<IConfirmationChallengeRepository>("takes the same handle twice", (repository) =>
        {
            repository.Save(NewChallenge("person-abc", new byte[] { 1, 2, 3 }));
            repository.Take("person-abc");
            return new SecondTakeOutcome(repository.Take("person-abc"));
        })
        .TheTest
        .ShouldPass<SecondTakeOutcome>((because, outcome) =>
        {
            because.ItsTrue("second take returns null - the record was deleted", outcome.Second == null);

            IRepository backingRepository = because.TestCaseRegistry.Get<IRepository>();
            backingRepository.Received(1).Delete(Arg.Any<ConfirmationChallengeData>());
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ReplacePriorPendingRecordOnSave()
    {
        After.Setup(SetupDefaults)
        .When<IConfirmationChallengeRepository>("saves two challenges for the same handle", (repository) =>
        {
            repository.Save(NewChallenge("person-abc", new byte[] { 1, 1, 1 }));
            repository.Save(NewChallenge("person-abc", new byte[] { 2, 2, 2 }));
            ConfirmationChallenge? taken = repository.Take("person-abc");
            return new ReplaceOutcome(taken, repository.Take("person-abc"));
        })
        .TheTest
        .ShouldPass<ReplaceOutcome>((because, outcome) =>
        {
            because.ItsTrue("the latest challenge wins", outcome.Taken != null && outcome.Taken.ChallengeBytes.SequenceEqual(new byte[] { 2, 2, 2 }));
            because.ItsTrue("only one record was pending", outcome.SecondTake == null);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void NotScanTheChallengeTableOnSaveOrTake()
    {
        After.Setup(SetupDefaults)
        .When<IConfirmationChallengeRepository>("runs a full save/take cycle", (repository) =>
        {
            repository.Save(NewChallenge("person-abc", new byte[] { 4, 5, 6 }));
            return new ScanOutcome(repository.Take("person-abc"), repository.Take("person-missing"));
        })
        .TheTest
        .ShouldPass<ScanOutcome>((because, outcome) =>
        {
            because.ItsTrue("the pending challenge was still taken", outcome.Taken != null);
            because.ItsTrue("a missing handle yields null", outcome.Missing == null);

            IRepository backingRepository = because.TestCaseRegistry.Get<IRepository>();
            backingRepository.DidNotReceive().Query(Arg.Any<Func<ConfirmationChallengeData, bool>>());
            backingRepository.Received().Query<ConfirmationChallengeData>(Arg.Any<Dictionary<string, object>>());
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ReapExpiredChallengesOnOperation()
    {
        After.Setup(SetupDefaults)
        .When<IConfirmationChallengeRepository>("saves a challenge while expired rows exist", (repository, reg) =>
        {
            List<ConfirmationChallengeData> store = reg.Get<List<ConfirmationChallengeData>>();
            store.Add(NewChallengeData("person-expired", DateTime.UtcNow.AddMinutes(-30)));
            store.Add(NewChallengeData("person-live", DateTime.UtcNow.AddMinutes(30)));

            repository.Save(NewChallenge("person-abc", new byte[] { 7, 7, 7 }));

            return new ReapOutcome(
                store.Any(pending => pending.PersonHandle == "person-expired"),
                store.Any(pending => pending.PersonHandle == "person-live"));
        })
        .TheTest
        .ShouldPass<ReapOutcome>((because, outcome) =>
        {
            because.ItsTrue("the expired challenge was reaped", !outcome.ExpiredRemains);
            because.ItsTrue("the live challenge was kept", outcome.LiveRemains);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ThrottleReapingByReapInterval()
    {
        After.Setup(SetupDefaults)
        .When<IConfirmationChallengeRepository>("performs two operations inside one reap interval", (repository) =>
        {
            ((PersistedConfirmationChallengeRepository)repository).ReapInterval = TimeSpan.FromHours(1);
            repository.Save(NewChallenge("person-abc", new byte[] { 1, 2, 3 }));
            repository.Save(NewChallenge("person-def", new byte[] { 4, 5, 6 }));
            return repository;
        })
        .TheTest
        .ShouldPass<IConfirmationChallengeRepository>((because, repository) =>
        {
            IRepository backingRepository = because.TestCaseRegistry.Get<IRepository>();
            backingRepository.Received(1).DeleteWhere<ConfirmationChallengeData>(Arg.Any<object>());
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ReturnNullWhenTheClaimIsLost()
    {
        After.Setup(SetupClaimAlwaysLost)
        .When<IConfirmationChallengeRepository>("takes a challenge another process already removed", (repository) =>
        {
            repository.Save(NewChallenge("person-abc", new byte[] { 1, 2, 3 }));
            return new ClaimLostOutcome(repository.Take("person-abc"));
        })
        .TheTest
        .ShouldPass<ClaimLostOutcome>((because, outcome) =>
        {
            because.ItsTrue("a lost claim yields null instead of a double-take", outcome.Taken == null);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ServeTakeFromTheCacheWithoutAStoreQuery()
    {
        After.Setup(SetupDefaults)
        .When<IConfirmationChallengeRepository>("saves then takes with a warm cache", (repository) =>
        {
            repository.Save(NewChallenge("person-abc", new byte[] { 1, 2, 3 }));
            return new CacheHitOutcome(repository.Take("person-abc"));
        })
        .TheTest
        .ShouldPass<CacheHitOutcome>((because, outcome) =>
        {
            because.ItsTrue("the challenge was taken", outcome.Taken != null);

            // Save performs the single keyed query (the replace-prior sweep); the take itself is
            // served from the write-through cache, so no further store query occurs.
            IRepository backingRepository = because.TestCaseRegistry.Get<IRepository>();
            backingRepository.Received(1).Query<ConfirmationChallengeData>(Arg.Any<Dictionary<string, object>>());
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void FallBackToTheStoreWhenTheCacheIsFull()
    {
        After.Setup(SetupDefaults)
        .When<IConfirmationChallengeRepository>("saves beyond the cache cap then takes the uncached handle", (repository) =>
        {
            ((PersistedConfirmationChallengeRepository)repository).MaxCachedChallenges = 1;
            repository.Save(NewChallenge("person-cached", new byte[] { 1, 1, 1 }));
            repository.Save(NewChallenge("person-uncached", new byte[] { 2, 2, 2 }));
            return new CacheCapOutcome(
                repository.Take("person-uncached"),
                repository.Take("person-cached"));
        })
        .TheTest
        .ShouldPass<CacheCapOutcome>((because, outcome) =>
        {
            because.ItsTrue("the uncached handle is still taken via a keyed store query", outcome.UncachedTaken != null && outcome.UncachedTaken.ChallengeBytes.SequenceEqual(new byte[] { 2, 2, 2 }));
            because.ItsTrue("the cached handle is taken normally", outcome.CachedTaken != null && outcome.CachedTaken.ChallengeBytes.SequenceEqual(new byte[] { 1, 1, 1 }));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private sealed record SecondTakeOutcome(ConfirmationChallenge? Second);

    private sealed record ReplaceOutcome(ConfirmationChallenge? Taken, ConfirmationChallenge? SecondTake);

    private sealed record ScanOutcome(ConfirmationChallenge? Taken, ConfirmationChallenge? Missing);

    private sealed record ReapOutcome(bool ExpiredRemains, bool LiveRemains);

    private sealed record CacheHitOutcome(ConfirmationChallenge? Taken);

    private sealed record CacheCapOutcome(ConfirmationChallenge? UncachedTaken, ConfirmationChallenge? CachedTaken);

    private sealed record ClaimLostOutcome(ConfirmationChallenge? Taken);
}
