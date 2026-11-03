using Bam.Data.Repositories;
using Bam.DependencyInjection;
using Bam.Test;
using Bam.UserAccounts.Passkeys;
using NSubstitute;

namespace Bam.UserAccounts.Tests.Unit.Passkeys;

/// <summary>
/// The same custody contract exercised against both implementations: the in-memory store and
/// the persisted store over a fake <see cref="IRepository"/> that answers keyed queries the way
/// a real backend does.
/// </summary>
[UnitTestMenu("PasskeyCredentialRepositories Should", Selector = "pkcr")]
public class PasskeyCredentialRepositoriesShould : UnitTestMenuContainer
{
    public PasskeyCredentialRepositoriesShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    [UnitTest]
    public void KeepCustodyInMemory()
    {
        After.Setup(reg => reg.Set<IPasskeyCredentialRepository>(new InMemoryPasskeyCredentialRepository()))
        .When<IPasskeyCredentialRepository>("exercises the in-memory custody contract", (repository, reg) => Exercise(repository))
        .TheTest
        .ShouldPass<CustodyOutcome>(AssertCustody)
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void KeepCustodyInAStore()
    {
        After.Setup(reg =>
        {
            List<PasskeyCredentialData> store = new List<PasskeyCredentialData>();
            IRepository backing = CreateBackingRepository(store);
            reg.Set(backing);
            reg.Set<IPasskeyCredentialRepository>(new PersistedPasskeyCredentialRepository(backing));
        })
        .When<IPasskeyCredentialRepository>("exercises the persisted custody contract", (repository, reg) =>
        {
            CustodyOutcome outcome = Exercise(repository);
            IRepository backing = reg.Get<IRepository>();
            backing.Received().AddType<PasskeyCredentialData>();
            backing.Received(2).Update(Arg.Any<PasskeyCredentialData>());
            return outcome;
        })
        .TheTest
        .ShouldPass<CustodyOutcome>(AssertCustody)
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static CustodyOutcome Exercise(IPasskeyCredentialRepository repository)
    {
        DateTime start = new DateTime(2026, 11, 3, 0, 0, 0, DateTimeKind.Utc);
        PasskeyCredentialData first = Credential("alice", "cred-a1", "uh-alice", start);
        PasskeyCredentialData second = Credential("alice", "cred-a2", "uh-alice", start.AddMinutes(1));
        PasskeyCredentialData bobs = Credential("bob", "cred-b1", "uh-bob", start.AddMinutes(2));
        repository.Save(second);
        repository.Save(first);
        repository.Save(bobs);

        PasskeyCredentialData? found = repository.FindByCredentialId("cred-a2");
        PasskeyCredentialData? missing = repository.FindByCredentialId("cred-zz");
        IReadOnlyList<PasskeyCredentialData> alices = repository.FindByHandle("alice");
        IReadOnlyList<PasskeyCredentialData> byUserHandle = repository.FindByUserHandle("uh-bob");

        repository.RecordUse("cred-a1", 42, start.AddHours(1));
        repository.FlagSignCountRegression("cred-b1");
        repository.RecordUse("cred-zz", 1, start);
        repository.FlagSignCountRegression("cred-zz");
        PasskeyCredentialData? used = repository.FindByCredentialId("cred-a1");
        PasskeyCredentialData? flagged = repository.FindByCredentialId("cred-b1");

        bool removed = repository.Remove("cred-a2");
        bool removedAgain = repository.Remove("cred-a2");
        int remaining = repository.FindByHandle("alice").Count;
        return new CustodyOutcome(found, missing, alices, byUserHandle, used, flagged, removed, removedAgain, remaining);
    }

    private static void AssertCustody(Because because, CustodyOutcome outcome)
    {
        because.ItsTrue("finds a credential by id", outcome.Found is not null && outcome.Found.PersonHandle == "alice");
        because.ItsTrue("returns null for an unknown id", outcome.Missing is null);
        because.ItsTrue("lists a person's credentials oldest first", outcome.Alices.Count == 2 && outcome.Alices[0].CredentialId == "cred-a1" && outcome.Alices[1].CredentialId == "cred-a2");
        because.ItsTrue("finds credentials by user handle", outcome.ByUserHandle.Count == 1 && outcome.ByUserHandle[0].CredentialId == "cred-b1");
        because.ItsTrue("records sign count and last use", outcome.Used is not null && outcome.Used.SignCount == 42 && outcome.Used.LastUsedUtc == new DateTime(2026, 11, 3, 1, 0, 0, DateTimeKind.Utc));
        because.ItsTrue("flags a sign count regression", outcome.Flagged is not null && outcome.Flagged.SignCountRegressed);
        because.ItsTrue("removes a credential once", outcome.Removed && !outcome.RemovedAgain);
        because.ItsTrue("removal leaves the person's other credential", outcome.Remaining == 1);
    }

    private static PasskeyCredentialData Credential(string handle, string credentialId, string userHandle, DateTime createdUtc)
    {
        return new PasskeyCredentialData
        {
            PersonHandle = handle,
            CredentialId = credentialId,
            UserHandle = userHandle,
            PublicKeyPem = "-----BEGIN PUBLIC KEY-----\nplaceholder\n-----END PUBLIC KEY-----",
            Algorithm = -7,
            CreatedUtc = createdUtc
        };
    }

    private static IRepository CreateBackingRepository(List<PasskeyCredentialData> store)
    {
        IRepository backing = Substitute.For<IRepository>();
        backing.Query<PasskeyCredentialData>(Arg.Any<Dictionary<string, object>>())
            .Returns(callInfo =>
            {
                Dictionary<string, object> query = callInfo.Arg<Dictionary<string, object>>();
                KeyValuePair<string, object> key = query.Single();
                return store.Where(credential => string.Equals(ValueOf(credential, key.Key), (string)key.Value, StringComparison.Ordinal)).ToList();
            });
        backing.Create(Arg.Any<PasskeyCredentialData>())
            .Returns(callInfo =>
            {
                store.Add(callInfo.Arg<PasskeyCredentialData>());
                return callInfo.Arg<PasskeyCredentialData>();
            });
        backing.Update(Arg.Any<PasskeyCredentialData>())
            .Returns(callInfo => callInfo.Arg<PasskeyCredentialData>());
        backing.Delete(Arg.Any<PasskeyCredentialData>())
            .Returns(callInfo => store.Remove(callInfo.Arg<PasskeyCredentialData>()));
        return backing;
    }

    private static string ValueOf(PasskeyCredentialData credential, string propertyName)
    {
        switch (propertyName)
        {
            case nameof(PasskeyCredentialData.CredentialId):
                return credential.CredentialId;
            case nameof(PasskeyCredentialData.PersonHandle):
                return credential.PersonHandle;
            case nameof(PasskeyCredentialData.UserHandle):
                return credential.UserHandle;
            default:
                throw new ArgumentException("unexpected query property " + propertyName);
        }
    }

    private sealed record CustodyOutcome(PasskeyCredentialData? Found, PasskeyCredentialData? Missing, IReadOnlyList<PasskeyCredentialData> Alices,
        IReadOnlyList<PasskeyCredentialData> ByUserHandle, PasskeyCredentialData? Used, PasskeyCredentialData? Flagged, bool Removed, bool RemovedAgain, int Remaining);
}
