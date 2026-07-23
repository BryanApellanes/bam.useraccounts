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
        IRepository backingRepository = Substitute.For<IRepository>();
        backingRepository.Query(Arg.Any<Func<ConfirmationChallengeData, bool>>())
            .Returns(callInfo => store.Where(callInfo.Arg<Func<ConfirmationChallengeData, bool>>()).ToList());
        backingRepository.Create(Arg.Any<ConfirmationChallengeData>())
            .Returns(callInfo =>
            {
                store.Add(callInfo.Arg<ConfirmationChallengeData>());
                return callInfo.Arg<ConfirmationChallengeData>();
            });
        backingRepository.Delete(Arg.Any<ConfirmationChallengeData>())
            .Returns(callInfo => store.Remove(callInfo.Arg<ConfirmationChallengeData>()));

        reg.For<IRepository>().Use(backingRepository);
        reg.For<IConfirmationChallengeRepository>().Use(new PersistedConfirmationChallengeRepository(backingRepository));
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

    private sealed record SecondTakeOutcome(ConfirmationChallenge? Second);

    private sealed record ReplaceOutcome(ConfirmationChallenge? Taken, ConfirmationChallenge? SecondTake);
}
