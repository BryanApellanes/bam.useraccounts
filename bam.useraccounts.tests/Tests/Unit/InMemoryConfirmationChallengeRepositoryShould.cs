using Bam.DependencyInjection;
using Bam.Test;
using Bam.UserAccounts;

namespace Bam.UserAccounts.Tests.Unit;

[UnitTestMenu("InMemoryConfirmationChallengeRepository Should", Selector = "imccr")]
public class InMemoryConfirmationChallengeRepositoryShould : UnitTestMenuContainer
{
    public InMemoryConfirmationChallengeRepositoryShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    private static void SetupDefaults(TestCaseRegistry reg)
    {
        reg.For<IConfirmationChallengeRepository>().Use(new InMemoryConfirmationChallengeRepository());
    }

    private static ConfirmationChallenge NewChallenge(string personHandle, byte[] challengeBytes)
    {
        return new ConfirmationChallenge
        {
            PersonHandle = personHandle,
            ChallengeBytes = challengeBytes,
            ExpiresUtc = DateTime.UtcNow.AddMinutes(10)
        };
    }

    [UnitTest]
    public void TakeReturnsSavedChallengeAndRemovesIt()
    {
        After.Setup(SetupDefaults)
        .When<IConfirmationChallengeRepository>("saves then takes twice", (repository) =>
        {
            repository.Save(NewChallenge("person-abc", new byte[] { 1, 2, 3 }));
            ConfirmationChallenge? first = repository.Take("person-abc");
            ConfirmationChallenge? second = repository.Take("person-abc");
            return new TakeTwiceOutcome(first, second);
        })
        .TheTest
        .ShouldPass<TakeTwiceOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("first take returns the challenge", outcome.First != null && outcome.First.ChallengeBytes.SequenceEqual(new byte[] { 1, 2, 3 }));
            because.ItsTrue("second take returns null - challenge was removed", outcome.Second == null);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void SaveReplacesPriorPendingChallenge()
    {
        After.Setup(SetupDefaults)
        .When<IConfirmationChallengeRepository>("saves two challenges for the same handle", (repository) =>
        {
            repository.Save(NewChallenge("person-abc", new byte[] { 1, 1, 1 }));
            repository.Save(NewChallenge("person-abc", new byte[] { 2, 2, 2 }));
            return repository.Take("person-abc");
        })
        .TheTest
        .ShouldPass<ConfirmationChallenge>((because, _, challenge) =>
        {
            because.ItsTrue("the latest challenge wins", challenge.ChallengeBytes.SequenceEqual(new byte[] { 2, 2, 2 }));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void IsolateChallengesPerHandle()
    {
        After.Setup(SetupDefaults)
        .When<IConfirmationChallengeRepository>("saves challenges for two handles and takes one", (repository) =>
        {
            repository.Save(NewChallenge("person-abc", new byte[] { 1, 1, 1 }));
            repository.Save(NewChallenge("person-xyz", new byte[] { 2, 2, 2 }));
            repository.Take("person-abc");
            return new TakeTwiceOutcome(repository.Take("person-xyz"), repository.Take("person-abc"));
        })
        .TheTest
        .ShouldPass<TakeTwiceOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("the other handle's challenge is still pending", outcome.First != null && outcome.First.ChallengeBytes.SequenceEqual(new byte[] { 2, 2, 2 }));
            because.ItsTrue("the taken handle has nothing pending", outcome.Second == null);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private sealed record TakeTwiceOutcome(ConfirmationChallenge? First, ConfirmationChallenge? Second);
}
