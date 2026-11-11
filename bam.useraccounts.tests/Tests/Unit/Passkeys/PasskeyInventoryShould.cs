using Bam.DependencyInjection;
using Bam.Test;
using Bam.UserAccounts.Passkeys;

namespace Bam.UserAccounts.Tests.Unit.Passkeys;

[UnitTestMenu("PasskeyInventory Should", Selector = "pkin")]
public class PasskeyInventoryShould : UnitTestMenuContainer
{
    public PasskeyInventoryShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    private static IPasskeyCredentialRepository SeededCustody()
    {
        InMemoryPasskeyCredentialRepository custody = new InMemoryPasskeyCredentialRepository();
        DateTime start = new DateTime(2026, 11, 11, 0, 0, 0, DateTimeKind.Utc);
        custody.Save(Credential("alice", "cred-a1", start, isKeySet: true));
        custody.Save(Credential("alice", "cred-a2", start.AddMinutes(1), isKeySet: false));
        custody.Save(Credential("bob", "cred-b1", start.AddMinutes(2), isKeySet: true));
        // A registration the registrar has not accepted: never one of bob's passkeys.
        PasskeyCredentialData pending = Credential("bob", "cred-b-pending", start.AddMinutes(3), isKeySet: true);
        pending.Pending = true;
        custody.Save(pending);
        return custody;
    }

    private static PasskeyCredentialData Credential(string handle, string credentialId, DateTime createdUtc, bool isKeySet)
    {
        return new PasskeyCredentialData
        {
            PersonHandle = handle,
            CredentialId = credentialId,
            UserHandle = "uh-" + handle,
            PublicKeyPem = "-----BEGIN PUBLIC KEY-----\nplaceholder\n-----END PUBLIC KEY-----",
            Algorithm = -7,
            CreatedUtc = createdUtc,
            IsRegisteredKeySet = isKeySet
        };
    }

    [UnitTest]
    public void ListOnlyThePersonsPasskeys()
    {
        After.Setup(reg => reg.Set<IPasskeyCredentialRepository>(SeededCustody()))
        .When<IPasskeyCredentialRepository>("lists passkeys per person", (custody, reg) =>
        {
            PasskeyInventory inventory = new PasskeyInventory(custody);
            return new ListOutcome(inventory.List("alice"), inventory.List("bob"), inventory.List("nobody"), inventory.List(" "));
        })
        .TheTest
        .ShouldPass<ListOutcome>((because, outcome) =>
        {
            because.ItsTrue("a person's passkeys are listed oldest first", outcome.Alices.Select(credential => credential.CredentialId).SequenceEqual(new string[] { "cred-a1", "cred-a2" }));
            because.ItsTrue("another person's are not included", outcome.Bobs.Count == 1 && outcome.Bobs[0].CredentialId == "cred-b1");
            because.ItsTrue("an unknown or blank handle lists nothing", outcome.Nobodys.Count == 0 && outcome.Blank.Count == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RenameOnlyThePersonsOwnPasskey()
    {
        After.Setup(reg => reg.Set<IPasskeyCredentialRepository>(SeededCustody()))
        .When<IPasskeyCredentialRepository>("renames passkeys", (custody, reg) =>
        {
            PasskeyInventory inventory = new PasskeyInventory(custody);
            bool own = inventory.Rename("alice", "cred-a2", "  phone  ");
            string? ownName = custody.FindByCredentialId("cred-a2")?.Name;
            bool others = inventory.Rename("alice", "cred-b1", "mine now");
            bool unknown = inventory.Rename("alice", "cred-zz", "ghost");
            bool blankHandle = inventory.Rename("", "cred-a1", "anonymous") || inventory.Rename("bob", "cred-b-pending", "not yet mine");
            bool longName = inventory.Rename("alice", "cred-a1", new string('n', 200));
            int longLength = custody.FindByCredentialId("cred-a1")?.Name?.Length ?? 0;
            bool cleared = inventory.Rename("alice", "cred-a2", " ");
            return new RenameOutcome(own, ownName, others, custody.FindByCredentialId("cred-b1")?.Name, unknown, blankHandle, longName, longLength, cleared, custody.FindByCredentialId("cred-a2")?.Name);
        })
        .TheTest
        .ShouldPass<RenameOutcome>((because, outcome) =>
        {
            because.ItsTrue("a person renames their own passkey, trimmed", outcome.Own && outcome.OwnName == "phone");
            because.ItsTrue("but not another person's", !outcome.Others && outcome.OthersName is null);
            because.ItsTrue("nor an unknown credential, nor without a handle, nor a pending one", !outcome.Unknown && !outcome.BlankHandle);
            because.ItsTrue("a long name is cut to the limit", outcome.LongName && outcome.LongLength == PasskeyInventory.MaxNameLength);
            because.ItsTrue("a blank name clears it", outcome.Cleared && outcome.ClearedName is null);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RemoveAPasskeyButNeverTheLast()
    {
        After.Setup(reg => reg.Set<IPasskeyCredentialRepository>(SeededCustody()))
        .When<IPasskeyCredentialRepository>("removes passkeys", (custody, reg) =>
        {
            PasskeyInventory inventory = new PasskeyInventory(custody);
            PasskeyRemoval others = inventory.Remove("alice", "cred-b1");
            PasskeyRemoval unknown = inventory.Remove("alice", "cred-zz");
            PasskeyRemoval bobsLast = inventory.Remove("bob", "cred-b1");
            PasskeyRemoval keySet = inventory.Remove("alice", "cred-a1");
            PasskeyRemoval again = inventory.Remove("alice", "cred-a1");
            PasskeyRemoval alicesLast = inventory.Remove("alice", "cred-a2");
            return new RemoveOutcome(others, unknown, bobsLast, keySet, again, alicesLast,
                custody.FindByHandle("alice").Select(credential => credential.CredentialId).ToList(), custody.FindByHandle("bob").Count);
        })
        .TheTest
        .ShouldPass<RemoveOutcome>((because, outcome) =>
        {
            because.ItsTrue("another person's passkey is not found", outcome.Others == PasskeyRemoval.NotFound);
            because.ItsTrue("an unknown credential is not found", outcome.Unknown == PasskeyRemoval.NotFound);
            because.ItsTrue("a person's only passkey is refused, a pending row beside it notwithstanding", outcome.BobsLast == PasskeyRemoval.LastCredential && outcome.BobsRemaining == 2);
            because.ItsTrue("the key-set passkey can be removed while another remains", outcome.KeySet == PasskeyRemoval.Removed);
            because.ItsTrue("removing it twice is not found", outcome.Again == PasskeyRemoval.NotFound);
            because.ItsTrue("the remaining passkey is then the last and stays", outcome.AlicesLast == PasskeyRemoval.LastCredential && outcome.AlicesRemaining.SequenceEqual(new string[] { "cred-a2" }));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private sealed record ListOutcome(IReadOnlyList<PasskeyCredentialData> Alices, IReadOnlyList<PasskeyCredentialData> Bobs, IReadOnlyList<PasskeyCredentialData> Nobodys, IReadOnlyList<PasskeyCredentialData> Blank);

    private sealed record RenameOutcome(bool Own, string? OwnName, bool Others, string? OthersName, bool Unknown, bool BlankHandle, bool LongName, int LongLength, bool Cleared, string? ClearedName);

    private sealed record RemoveOutcome(PasskeyRemoval Others, PasskeyRemoval Unknown, PasskeyRemoval BobsLast, PasskeyRemoval KeySet, PasskeyRemoval Again, PasskeyRemoval AlicesLast,
        List<string> AlicesRemaining, int BobsRemaining);
}
