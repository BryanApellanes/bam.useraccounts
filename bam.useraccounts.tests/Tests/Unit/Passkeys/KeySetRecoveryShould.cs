using System.Text;
using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Encryption.Cose;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Profile;
using Bam.Protocol.Profile;
using Bam.Test;
using Bam.UserAccounts.Passkeys;
using Bam.UserAccounts.Tests.TestClasses;

namespace Bam.UserAccounts.Tests.Unit.Passkeys;

/// <summary>
/// Pins lost-device recovery (bam.protocol#85, option 2; bam.useraccounts#20 part 2): a surviving
/// passkey at least <see cref="PasskeyOptions.RecoveryCredentialAge"/> old proves the move, the key
/// set moves only after <see cref="PasskeyOptions.RecoveryDelay"/>, and any session can cancel it
/// before then.  Runs over a real registrar and proof chain, so "the lost key no longer verifies as
/// the handle" is what bam.protocol resolves.
/// </summary>
[UnitTestMenu("KeySetRecovery Should", Selector = "ksrc")]
public class KeySetRecoveryShould : UnitTestMenuContainer
{
    private const string Handle = HandoverFixture.Handle;

    public KeySetRecoveryShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    [UnitTest]
    public void MoveTheKeySetToTheHeirOnlyAfterTheDelay()
    {
        When.A<HandoverFixture>("recovers a lost key-set passkey with an old enough heir", new HandoverFixture(nameof(MoveTheKeySetToTheHeirOnlyAfterTheDelay)), (fixture) =>
        {
            SyntheticAuthenticator lost = new SyntheticAuthenticator(CoseAlgorithm.ES256);
            SyntheticAuthenticator heir = new SyntheticAuthenticator(CoseAlgorithm.RS256);
            string lostId = fixture.SignUp(lost);
            string heirId = fixture.Add(heir);
            fixture.AgePasskeys();

            PublicKeySetData before = fixture.Registrar.Resolve(Handle)!;
            KeySetRecoveryStart start = fixture.Recovery.Begin(Handle, lostId, null, heirId);
            byte[] expected = PasskeyKeySetRotationProof.Challenge(before, PasskeyKeySet.From(fixture.Credentials.FindByCredentialId(heirId)!));
            bool challengeIsTheRotation = start.Options is not null && Base64UrlEncoder.Default.Decode(start.Options.Challenge).SequenceEqual(expected);
            bool allowsOnlyTheHeir = start.Options is not null && start.Options.AllowCredentials.Count == 1 && start.Options.AllowCredentials[0].Id == heirId;
            bool requiresVerification = start.Options?.UserVerification == "required";
            DateTime proved = fixture.Clock.GetUtcNow().UtcDateTime;
            KeySetRecoveryResult done = fixture.Recovery.Complete(Handle, start.RecoveryId, HandoverFixture.AssertionJson(heir, start));

            bool lostRemovedNow = fixture.Credentials.FindByCredentialId(lostId) is null;
            bool keySetStillTheLostKey = fixture.KeySetIs(lost);
            // Still live: nothing is tombstoned yet (the blocklist probe only answers once the key is not live).
            bool lostNotYetBlocklisted = !fixture.Store.RetrieveAll<PublicKeySetData>().Any(row => row.RevokedBy is not null);
            PendingKeySetRecoveryData? pending = fixture.Recovery.Pending(Handle);
            KeySetRecoverySettlement early = fixture.Recovery.Settle(Handle);
            bool anchoredEarly = fixture.RecoveryProof.Anchors(before);

            fixture.Clock.Advance(fixture.Options.RecoveryDelay + TimeSpan.FromMinutes(1));
            bool anchoredWhenDue = fixture.RecoveryProof.Anchors(before);
            KeySetRecoverySettlement settled = fixture.Recovery.Settle(Handle);
            bool movedToHeir = fixture.KeySetIs(heir);
            bool lostBlocklisted = fixture.KeyIsBlocklisted(lost);
            bool heirMarked = fixture.Credentials.FindByCredentialId(heirId)!.IsRegisteredKeySet;
            bool auditNamesRecovery = fixture.Store.RetrieveAll<PublicKeySetData>().Any(row => row.RevokedBy == PublicKeySetData.RotationRevokedByPrefix + PasskeyRecoveryRotationProof.ProofName);
            PendingKeySetRecoveryData stored = fixture.Recoveries.FindByHandle(Handle).Single();
            KeySetRecoverySettlement again = fixture.Recovery.Settle(Handle);
            bool cancelAfterSettle = fixture.Recovery.Cancel(Handle, start.RecoveryId!, heirId);

            return new HappyOutcome(start, challengeIsTheRotation, allowsOnlyTheHeir, requiresVerification, done, done.EffectiveUtc == proved + fixture.Options.RecoveryDelay,
                lostRemovedNow, keySetStillTheLostKey, lostNotYetBlocklisted, pending, early, anchoredEarly, anchoredWhenDue, settled, movedToHeir, lostBlocklisted,
                heirMarked, auditNamesRecovery, stored, again, cancelAfterSettle);
        })
        .TheTest
        .ShouldPass<HappyOutcome>((because, outcome) =>
        {
            because.ItsTrue("the recovery begins", outcome.Start.Success && outcome.Start.RecoveryId is not null);
            because.ItsTrue("the challenge is SHA-256 of the rotation payload to the heir", outcome.ChallengeIsTheRotation);
            because.ItsTrue("the options allow only the heir", outcome.AllowsOnlyTheHeir);
            because.ItsTrue("the options require user verification", outcome.RequiresVerification);
            because.ItsTrue("the recovery is proved", outcome.Done.Success && outcome.Done.RemovedCredentialId is not null);
            because.ItsTrue("the key set moves after exactly the delay", outcome.EffectiveIsTheDelay);
            because.ItsTrue("the lost passkey leaves sign-in at once", outcome.LostRemovedNow);
            because.ItsTrue("before the delay the key set is still the lost key", outcome.KeySetStillTheLostKey && outcome.LostNotYetBlocklisted);
            because.ItsTrue("the recovery is pending", outcome.Pending is not null && outcome.Pending.RecoveryId == outcome.Start.RecoveryId);
            because.ItsTrue("settling before the delay does nothing", outcome.Early == KeySetRecoverySettlement.NotDue && !outcome.AnchoredEarly);
            because.ItsTrue("the recovery proof anchors the key set once due", outcome.AnchoredWhenDue);
            because.ItsTrue("after the delay the next request settles it", outcome.Settled == KeySetRecoverySettlement.Settled && outcome.MovedToHeir);
            because.ItsTrue("the lost key is blocklisted under any handle", outcome.LostBlocklisted);
            because.ItsTrue("the heir is marked as the key set", outcome.HeirMarked);
            because.ItsTrue("the tombstone names the recovery proof", outcome.AuditNamesRecovery);
            because.ItsTrue("the stored row is completed", outcome.Stored.CompletedUtc is not null && outcome.Stored.CanceledUtc is null);
            because.ItsTrue("a settled recovery settles once", outcome.Again == KeySetRecoverySettlement.NothingPending);
            because.ItsTrue("a cancel after settle finds nothing", !outcome.CancelAfterSettle);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RecoverAKeySetWhosePasskeyWasAlreadyRemoved()
    {
        When.A<HandoverFixture>("removes the lost passkey keeping the key set, then recovers it", new HandoverFixture(nameof(RecoverAKeySetWhosePasskeyWasAlreadyRemoved)), (fixture) =>
        {
            SyntheticAuthenticator lost = new SyntheticAuthenticator();
            SyntheticAuthenticator heir = new SyntheticAuthenticator();
            string lostId = fixture.SignUp(lost);
            string heirId = fixture.Add(heir);
            bool recoverableWhileHeld = fixture.Recovery.IsRecoverable(Handle);
            PasskeyRemoval removal = fixture.Inventory.Remove(Handle, lostId, keepKeySet: true);
            bool recoverableAfterRemoval = fixture.Recovery.IsRecoverable(Handle);
            fixture.AgePasskeys();

            KeySetRecoveryStart start = fixture.Recovery.Begin(Handle, null, null, heirId);
            KeySetRecoveryResult done = fixture.Recovery.Complete(Handle, start.RecoveryId, HandoverFixture.AssertionJson(heir, start));
            bool recoverableWhilePending = fixture.Recovery.IsRecoverable(Handle);
            fixture.Clock.Advance(fixture.Options.RecoveryDelay);
            KeySetRecoverySettlement settled = fixture.Recovery.Settle(Handle);
            return new AlreadyRemovedOutcome(recoverableWhileHeld, removal, recoverableAfterRemoval, start, done, recoverableWhilePending, settled,
                fixture.KeySetIs(heir), fixture.KeyIsBlocklisted(lost), fixture.Recovery.IsRecoverable(Handle));
        })
        .TheTest
        .ShouldPass<AlreadyRemovedOutcome>((because, outcome) =>
        {
            because.ItsTrue("a key set a passkey holds is not recoverable", !outcome.RecoverableWhileHeld);
            because.ItsTrue("the lost passkey is removed keeping the key set", outcome.Removal == PasskeyRemoval.Removed);
            because.ItsTrue("then the key set is recoverable", outcome.RecoverableAfterRemoval);
            because.ItsTrue("recovery begins with no removes and the session's passkey as heir", outcome.Start.Success && outcome.Start.HeirCredentialId is not null);
            because.ItsTrue("it completes and removes nothing", outcome.Done.Success && outcome.Done.RemovedCredentialId is null);
            because.ItsTrue("a pending recovery is not offered again", !outcome.RecoverableWhilePending);
            because.ItsTrue("at exactly the delay it settles", outcome.Settled == KeySetRecoverySettlement.Settled);
            because.ItsTrue("the key set is the heir's and the lost key is blocklisted", outcome.MovedToHeir && outcome.LostBlocklisted);
            because.ItsTrue("a held key set is not recoverable", !outcome.RecoverableAfterSettle);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseToBeginOutsideTheRule()
    {
        When.A<HandoverFixture>("refuses recoveries the rule doesn't allow", new HandoverFixture(nameof(RefuseToBeginOutsideTheRule)), (fixture) =>
        {
            SyntheticAuthenticator first = new SyntheticAuthenticator();
            SyntheticAuthenticator second = new SyntheticAuthenticator();
            SyntheticAuthenticator bobs = new SyntheticAuthenticator();
            string firstId = fixture.SignUp(first);
            string secondId = fixture.Add(second);
            string bobsId = fixture.SignUp(bobs, "bob");

            KeySetRecoveryStart tooNew = fixture.Recovery.Begin(Handle, firstId, secondId, null);
            DateTime secondCreated = fixture.Credentials.FindByCredentialId(secondId)!.CreatedUtc;
            bool eligibleAtTheGate = tooNew.EligibleUtc == secondCreated + fixture.Options.RecoveryCredentialAge;
            fixture.Clock.Advance(fixture.Options.RecoveryCredentialAge - TimeSpan.FromMinutes(1));
            KeySetRecoveryRefusal justTooNew = fixture.Recovery.Begin(Handle, firstId, secondId, null).Refusal;
            fixture.AgePasskeys();

            KeySetRecoveryRefusal unknown = fixture.Recovery.Begin(Handle, "no-such-credential", secondId, null).Refusal;
            KeySetRecoveryRefusal someoneElses = fixture.Recovery.Begin(Handle, bobsId, secondId, null).Refusal;
            KeySetRecoveryRefusal notKeySet = fixture.Recovery.Begin(Handle, secondId, null, firstId).Refusal;
            KeySetRecoveryRefusal removesRequired = fixture.Recovery.Begin(Handle, null, secondId, null).Refusal;
            KeySetRecoveryRefusal heirIsRemoves = fixture.Recovery.Begin(Handle, firstId, firstId, null).Refusal;
            KeySetRecoveryRefusal defaultHeirIsRemoves = fixture.Recovery.Begin(Handle, firstId, null, firstId).Refusal;
            KeySetRecoveryRefusal noHeir = fixture.Recovery.Begin(Handle, firstId, null, null).Refusal;
            KeySetRecoveryRefusal heirIsBobs = fixture.Recovery.Begin(Handle, firstId, bobsId, null).Refusal;
            KeySetRecoveryRefusal noKeySet = fixture.Recovery.Begin("nobody", null, null, null).Refusal;

            HandoverFixture withoutProof = new HandoverFixture(nameof(RefuseToBeginOutsideTheRule) + "-noproof", trustRecoveryProof: false);
            SyntheticAuthenticator a = new SyntheticAuthenticator();
            SyntheticAuthenticator b = new SyntheticAuthenticator();
            string aId = withoutProof.SignUp(a);
            string bId = withoutProof.Add(b);
            withoutProof.AgePasskeys();
            KeySetRecoveryRefusal unavailable = withoutProof.Recovery.Begin(Handle, aId, bId, null).Refusal;
            withoutProof.Inventory.Remove(Handle, aId, keepKeySet: true);
            bool unavailableReported = !withoutProof.Recovery.IsAvailable && !withoutProof.Recovery.IsRecoverable(Handle) && fixture.Recovery.IsAvailable;

            return new BeginRefusalOutcome(tooNew, eligibleAtTheGate, justTooNew, unknown, someoneElses, notKeySet, removesRequired, heirIsRemoves, defaultHeirIsRemoves,
                noHeir, heirIsBobs, noKeySet, unavailable, unavailableReported, fixture.KeySetIs(first), fixture.Recoveries.FindByHandle(Handle).Count);
        })
        .TheTest
        .ShouldPass<BeginRefusalOutcome>((because, outcome) =>
        {
            because.ItsTrue("an heir younger than the age gate is refused", outcome.TooNew.Refusal == KeySetRecoveryRefusal.HeirTooNew);
            because.ItsTrue("the refusal says when the heir is old enough", outcome.EligibleAtTheGate);
            because.ItsTrue("a minute short of the gate is still too new", outcome.JustTooNew == KeySetRecoveryRefusal.HeirTooNew);
            because.ItsTrue("an unknown passkey is not found", outcome.Unknown == KeySetRecoveryRefusal.NotFound);
            because.ItsTrue("another person's passkey is not found", outcome.SomeoneElses == KeySetRecoveryRefusal.NotFound);
            because.ItsTrue("a passkey that doesn't hold the key set is not the key set", outcome.NotKeySet == KeySetRecoveryRefusal.NotKeySet);
            because.ItsTrue("leaving out removes while a passkey holds the key set is refused", outcome.RemovesRequired == KeySetRecoveryRefusal.RemovesRequired);
            because.ItsTrue("the heir can't be the passkey being removed", outcome.HeirIsRemoves == KeySetRecoveryRefusal.InvalidHeir && outcome.DefaultHeirIsRemoves == KeySetRecoveryRefusal.InvalidHeir);
            because.ItsTrue("there must be an heir", outcome.NoHeir == KeySetRecoveryRefusal.InvalidHeir);
            because.ItsTrue("another person's passkey can't be the heir", outcome.HeirIsBobs == KeySetRecoveryRefusal.InvalidHeir);
            because.ItsTrue("a person with no key set has nothing to recover", outcome.NoKeySet == KeySetRecoveryRefusal.NoKeySet);
            because.ItsTrue("a host without the recovery proof can't recover", outcome.Unavailable == KeySetRecoveryRefusal.RotationUnavailable && outcome.UnavailableReported);
            because.ItsTrue("no refusal changed the key set or stored a recovery", outcome.KeySetKept && outcome.StoredRecoveries == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseACompletionThatDoesNotProveTheRecovery()
    {
        When.A<HandoverFixture>("completes recoveries with bad ids and bad assertions", new HandoverFixture(nameof(RefuseACompletionThatDoesNotProveTheRecovery)), (fixture) =>
        {
            SyntheticAuthenticator lost = new SyntheticAuthenticator();
            SyntheticAuthenticator heir = new SyntheticAuthenticator();
            SyntheticAuthenticator third = new SyntheticAuthenticator();
            string lostId = fixture.SignUp(lost);
            string heirId = fixture.Add(heir);
            string thirdId = fixture.Add(third);
            fixture.AgePasskeys();
            List<KeySetRecoveryRefusal> refusals = new List<KeySetRecoveryRefusal>();

            refusals.Add(fixture.Recovery.Complete(Handle, "no-such-recovery", HandoverFixture.AssertionJson(heir, new byte[32])).Refusal);
            KeySetRecoveryStart start = fixture.Recovery.Begin(Handle, lostId, heirId, null);
            refusals.Add(fixture.Recovery.Complete("bob", start.RecoveryId, HandoverFixture.AssertionJson(heir, start)).Refusal);
            refusals.Add(fixture.Recovery.Complete(Handle, start.RecoveryId, HandoverFixture.AssertionJson(heir, start)).Refusal);

            KeySetRecoveryStart byTheLost = fixture.Recovery.Begin(Handle, lostId, heirId, null);
            refusals.Add(fixture.Recovery.Complete(Handle, byTheLost.RecoveryId, HandoverFixture.AssertionJson(lost, byTheLost)).Refusal);

            KeySetRecoveryStart unverified = fixture.Recovery.Begin(Handle, lostId, heirId, null);
            heir.UserVerified = false;
            refusals.Add(fixture.Recovery.Complete(Handle, unverified.RecoveryId, HandoverFixture.AssertionJson(heir, unverified)).Refusal);
            heir.UserVerified = true;

            KeySetRecoveryStart wrongChallenge = fixture.Recovery.Begin(Handle, lostId, heirId, null);
            refusals.Add(fixture.Recovery.Complete(Handle, wrongChallenge.RecoveryId, HandoverFixture.AssertionJson(heir, new byte[32])).Refusal);

            KeySetRecoveryStart replayed = fixture.Recovery.Begin(Handle, lostId, heirId, null);
            // The unverified attempt verified its signature and recorded the counter; reuse that count.
            uint recorded = (uint)fixture.Credentials.FindByCredentialId(heirId)!.SignCount;
            heir.SignCount = recorded - 1;
            refusals.Add(fixture.Recovery.Complete(Handle, replayed.RecoveryId, HandoverFixture.AssertionJson(heir, replayed)).Refusal);
            heir.SignCount = recorded + 1;

            KeySetRecoveryStart heirRemoved = fixture.Recovery.Begin(Handle, lostId, heirId, null);
            byte[] heirAssertion = HandoverFixture.AssertionJson(heir, heirRemoved);
            fixture.Credentials.Remove(Handle, heirId);
            KeySetRecoveryRefusal heirGone = fixture.Recovery.Complete(Handle, heirRemoved.RecoveryId, heirAssertion).Refusal;

            // The key set moves (a handover by the lost passkey) between begin and complete.
            KeySetRecoveryStart stale = fixture.Recovery.Begin(Handle, lostId, thirdId, null);
            KeySetHandoverStart handover = fixture.Handover.Begin(Handle, lostId, thirdId, null);
            bool handedOver = fixture.Handover.Complete(Handle, handover.HandoverId, HandoverFixture.AssertionJson(lost, handover)).Success;
            KeySetRecoveryRefusal keySetChanged = fixture.Recovery.Complete(Handle, stale.RecoveryId, HandoverFixture.AssertionJson(third, stale)).Refusal;

            return new CompleteRefusalOutcome(refusals, heirGone, handedOver, keySetChanged, fixture.Recoveries.FindByHandle(Handle).Count, fixture.KeySetIs(third));
        })
        .TheTest
        .ShouldPass<CompleteRefusalOutcome>((because, outcome) =>
        {
            because.ItsTrue("an unknown recovery id is expired", outcome.Refusals[0] == KeySetRecoveryRefusal.RecoveryExpired);
            because.ItsTrue("another person's recovery id is expired", outcome.Refusals[1] == KeySetRecoveryRefusal.RecoveryExpired);
            because.ItsTrue("a recovery id works once: it was taken by the wrong person's attempt", outcome.Refusals[2] == KeySetRecoveryRefusal.RecoveryExpired);
            because.ItsTrue("an assertion by the lost passkey is refused", outcome.Refusals[3] == KeySetRecoveryRefusal.ProofRefused);
            because.ItsTrue("an assertion without user verification is refused", outcome.Refusals[4] == KeySetRecoveryRefusal.ProofRefused);
            because.ItsTrue("an assertion over another challenge is refused", outcome.Refusals[5] == KeySetRecoveryRefusal.ProofRefused);
            because.ItsTrue("a replayed assertion (counter not advanced) is refused", outcome.Refusals[6] == KeySetRecoveryRefusal.ProofRefused);
            because.ItsTrue("an heir removed since begin is gone", outcome.HeirGone == KeySetRecoveryRefusal.HeirGone);
            because.ItsTrue("a key set that moved since begin is refused", outcome.HandedOver && outcome.KeySetChanged == KeySetRecoveryRefusal.KeySetChanged);
            because.ItsTrue("no refusal stored a recovery", outcome.StoredRecoveries == 0);
            because.ItsTrue("the handover's result stands", outcome.KeySetIsTheHandoverHeir);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void NeverSettleACanceledRecovery()
    {
        When.A<HandoverFixture>("cancels a waiting recovery from another session", new HandoverFixture(nameof(NeverSettleACanceledRecovery)), (fixture) =>
        {
            SyntheticAuthenticator lost = new SyntheticAuthenticator();
            SyntheticAuthenticator heir = new SyntheticAuthenticator();
            SyntheticAuthenticator other = new SyntheticAuthenticator();
            string lostId = fixture.SignUp(lost);
            string heirId = fixture.Add(heir);
            string otherId = fixture.Add(other);
            fixture.AgePasskeys();
            KeySetRecoveryStart start = fixture.Recovery.Begin(Handle, lostId, heirId, null);
            fixture.Recovery.Complete(Handle, start.RecoveryId, HandoverFixture.AssertionJson(heir, start));

            KeySetRecoveryRefusal secondBegin = fixture.Recovery.Begin(Handle, null, otherId, null).Refusal;
            KeySetHandoverRefusal handoverWhilePending = fixture.Handover.Begin(Handle, heirId, otherId, null).Refusal;
            bool canceledByBob = fixture.Recovery.Cancel("bob", start.RecoveryId!, null);
            bool canceledUnknown = fixture.Recovery.Cancel(Handle, "no-such-recovery", otherId);
            bool canceled = fixture.Recovery.Cancel(Handle, start.RecoveryId!, otherId);
            bool canceledTwice = fixture.Recovery.Cancel(Handle, start.RecoveryId!, otherId);
            PendingKeySetRecoveryData? pending = fixture.Recovery.Pending(Handle);
            fixture.Clock.Advance(fixture.Options.RecoveryDelay + TimeSpan.FromHours(1));
            KeySetRecoverySettlement settled = fixture.Recovery.Settle(Handle);
            bool anchors = fixture.RecoveryProof.Anchors(fixture.Registrar.Resolve(Handle)!);
            PendingKeySetRecoveryData row = fixture.Recoveries.FindByHandle(Handle).Single();
            return new CancelOutcome(secondBegin, handoverWhilePending, canceledByBob, canceledUnknown, canceled, canceledTwice, pending, settled, anchors,
                fixture.KeySetIs(lost), row, fixture.Recovery.IsRecoverable(Handle));
        })
        .TheTest
        .ShouldPass<CancelOutcome>((because, outcome) =>
        {
            because.ItsTrue("a second begin while one waits is refused", outcome.SecondBegin == KeySetRecoveryRefusal.RecoveryPending);
            because.ItsTrue("a handover while a recovery waits is refused", outcome.HandoverWhilePending == KeySetHandoverRefusal.RecoveryPending);
            because.ItsTrue("another person can't cancel it", !outcome.CanceledByBob);
            because.ItsTrue("an unknown id cancels nothing", !outcome.CanceledUnknown);
            because.ItsTrue("any session of the person cancels it, once", outcome.Canceled && !outcome.CanceledTwice);
            because.ItsTrue("nothing is pending after the cancel", outcome.Pending is null);
            because.ItsTrue("a canceled recovery never settles", outcome.Settled == KeySetRecoverySettlement.NothingPending && !outcome.Anchors);
            because.ItsTrue("the key set stays the lost key", outcome.KeySetKept);
            because.ItsTrue("the row records who canceled it", outcome.Row.CancelReason == KeySetRecoveryEnd.Canceled && outcome.Row.CanceledByCredentialId is not null && outcome.Row.CompletedUtc is null);
            because.ItsTrue("the person can start again", outcome.RecoverableAgain);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void EndARecoveryWhoseHeirIsRemovedOrWhoseKeySetMoved()
    {
        When.A<HandoverFixture>("removes the heir of one recovery and moves the key set under another", new HandoverFixture(nameof(EndARecoveryWhoseHeirIsRemovedOrWhoseKeySetMoved)), (fixture) =>
        {
            SyntheticAuthenticator lost = new SyntheticAuthenticator();
            SyntheticAuthenticator heir = new SyntheticAuthenticator();
            SyntheticAuthenticator other = new SyntheticAuthenticator();
            string lostId = fixture.SignUp(lost);
            string heirId = fixture.Add(heir);
            string otherId = fixture.Add(other);
            fixture.AgePasskeys();
            KeySetRecoveryStart start = fixture.Recovery.Begin(Handle, lostId, heirId, null);
            fixture.Recovery.Complete(Handle, start.RecoveryId, HandoverFixture.AssertionJson(heir, start));
            PasskeyRemoval heirRemoval = fixture.Inventory.Remove(Handle, heirId);
            PendingKeySetRecoveryData? afterHeirRemoved = fixture.Recovery.Pending(Handle);
            string? heirGoneReason = fixture.Recoveries.Find(Handle, start.RecoveryId!)?.CancelReason;

            KeySetRecoveryStart second = fixture.Recovery.Begin(Handle, null, otherId, null);
            fixture.Recovery.Complete(Handle, second.RecoveryId, HandoverFixture.AssertionJson(other, second));
            // Stands in for the key set moving some other way while the recovery waits (an admin
            // re-bind): the row's anchor no longer matches the registered key set.
            PendingKeySetRecoveryData row = fixture.Recoveries.Find(Handle, second.RecoveryId!)!;
            row.Anchor = "not-the-current-key-set";
            fixture.Recoveries.RewriteAtRest(row);
            fixture.Clock.Advance(fixture.Options.RecoveryDelay);
            KeySetRecoverySettlement settled = fixture.Recovery.Settle(Handle);
            string? changedReason = fixture.Recoveries.Find(Handle, second.RecoveryId!)?.CancelReason;
            return new EndOutcome(heirRemoval, afterHeirRemoved, heirGoneReason, second.Success, settled, changedReason, fixture.KeySetIs(lost));
        })
        .TheTest
        .ShouldPass<EndOutcome>((because, outcome) =>
        {
            because.ItsTrue("the heir is removed plainly (it doesn't hold the key set)", outcome.HeirRemoval == PasskeyRemoval.Removed);
            because.ItsTrue("removing the heir cancels the recovery", outcome.AfterHeirRemoved is null && outcome.HeirGoneReason == KeySetRecoveryEnd.HeirGone);
            because.ItsTrue("a new recovery can begin after that", outcome.SecondBegun);
            because.ItsTrue("a key set that changed while waiting ends the recovery", outcome.Settled == KeySetRecoverySettlement.Ended && outcome.ChangedReason == KeySetRecoveryEnd.KeySetChanged);
            because.ItsTrue("the key set is left alone", outcome.KeySetKept);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void EndARecoveryWhoseHeirKeyIsBlocklisted()
    {
        When.A<HandoverFixture>("recovers to an heir whose key was rotated away from", new HandoverFixture(nameof(EndARecoveryWhoseHeirKeyIsBlocklisted)), (fixture) =>
        {
            SyntheticAuthenticator first = new SyntheticAuthenticator();
            SyntheticAuthenticator second = new SyntheticAuthenticator();
            string firstId = fixture.SignUp(first);
            string secondId = fixture.Add(second);
            KeySetHandoverStart handover = fixture.Handover.Begin(Handle, firstId, secondId, null);
            bool handedOver = fixture.Handover.Complete(Handle, handover.HandoverId, HandoverFixture.AssertionJson(first, handover)).Success;
            bool firstBlocklisted = fixture.KeyIsBlocklisted(first);

            // The first key comes back as a new credential: registering a passkey doesn't ask the registrar.
            first.CredentialId = SyntheticAuthenticator.RandomBytes(16);
            string returnedId = fixture.Add(first);
            fixture.Inventory.Remove(Handle, secondId, keepKeySet: true);
            fixture.AgePasskeys();
            KeySetRecoveryStart start = fixture.Recovery.Begin(Handle, null, returnedId, null);
            KeySetRecoveryResult done = fixture.Recovery.Complete(Handle, start.RecoveryId, HandoverFixture.AssertionJson(first, start));
            fixture.Clock.Advance(fixture.Options.RecoveryDelay);
            KeySetRecoverySettlement settled = fixture.Recovery.Settle(Handle);
            string? reason = fixture.Recoveries.FindByHandle(Handle).Single().CancelReason;
            return new BlocklistedOutcome(handedOver, firstBlocklisted, done.Success, settled, reason, fixture.KeySetIs(second));
        })
        .TheTest
        .ShouldPass<BlocklistedOutcome>((because, outcome) =>
        {
            because.ItsTrue("the first key was handed over and blocklisted", outcome.HandedOver && outcome.FirstBlocklisted);
            because.ItsTrue("the recovery to the returned key is proved", outcome.Proved);
            because.ItsTrue("the registrar refuses the blocklisted key at settle, and the recovery ends", outcome.Settled == KeySetRecoverySettlement.Ended && outcome.Reason == KeySetRecoveryEnd.Refused);
            because.ItsTrue("the key set is left alone", outcome.KeySetKept);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void EndARecoveryTheProofRefusesAtSettle()
    {
        When.A<HandoverFixture>("settles a recovery whose heir's key changed under the same credential id", new HandoverFixture(nameof(EndARecoveryTheProofRefusesAtSettle)), (fixture) =>
        {
            SyntheticAuthenticator lost = new SyntheticAuthenticator();
            SyntheticAuthenticator heir = new SyntheticAuthenticator();
            string lostId = fixture.SignUp(lost);
            string heirId = fixture.Add(heir);
            fixture.AgePasskeys();
            KeySetRecoveryStart start = fixture.Recovery.Begin(Handle, lostId, heirId, null);
            fixture.Recovery.Complete(Handle, start.RecoveryId, HandoverFixture.AssertionJson(heir, start));
            // The heir's credential id now names another key: the stored assertion no longer proves the move.
            fixture.Credentials.Remove(Handle, heirId);
            fixture.Add(new SyntheticAuthenticator { CredentialId = heir.CredentialId });
            fixture.Clock.Advance(fixture.Options.RecoveryDelay);
            KeySetRecoverySettlement settled = fixture.Recovery.Settle(Handle);
            string? reason = fixture.Recoveries.Find(Handle, start.RecoveryId!)?.CancelReason;
            return new ProofRefusedOutcome(settled, reason, fixture.KeySetIs(lost));
        })
        .TheTest
        .ShouldPass<ProofRefusedOutcome>((because, outcome) =>
        {
            because.ItsTrue("a clean refusal by the proof ends the recovery rather than leaving it waiting", outcome.Settled == KeySetRecoverySettlement.Ended && outcome.Reason == KeySetRecoveryEnd.Refused);
            because.ItsTrue("the key set stays", outcome.KeySetKept);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void WaitWhenTheHandleRotatedTooRecently()
    {
        When.A<HandoverFixture>("settles a due recovery inside the minimum rotation interval", new HandoverFixture(nameof(WaitWhenTheHandleRotatedTooRecently), minimumRotationInterval: TimeSpan.FromDays(2)), (fixture) =>
        {
            fixture.Options.RecoveryDelay = TimeSpan.FromHours(1);
            SyntheticAuthenticator first = new SyntheticAuthenticator();
            SyntheticAuthenticator second = new SyntheticAuthenticator();
            SyntheticAuthenticator third = new SyntheticAuthenticator();
            string firstId = fixture.SignUp(first);
            string secondId = fixture.Add(second);
            string thirdId = fixture.Add(third);
            fixture.AgePasskeys();
            KeySetHandoverStart handover = fixture.Handover.Begin(Handle, firstId, secondId, null);
            fixture.Handover.Complete(Handle, handover.HandoverId, HandoverFixture.AssertionJson(first, handover));
            fixture.Inventory.Remove(Handle, secondId, keepKeySet: true);

            KeySetRecoveryStart start = fixture.Recovery.Begin(Handle, null, thirdId, null);
            fixture.Recovery.Complete(Handle, start.RecoveryId, HandoverFixture.AssertionJson(third, start));
            fixture.Clock.Advance(TimeSpan.FromHours(2));
            KeySetRecoverySettlement tooSoon = fixture.Recovery.Settle(Handle);
            bool stillPending = fixture.Recovery.Pending(Handle) is not null;
            bool keySetStillSecond = fixture.KeySetIs(second);
            fixture.Clock.Advance(TimeSpan.FromDays(2));
            KeySetRecoverySettlement settled = fixture.Recovery.Settle(Handle);
            return new TooSoonOutcome(tooSoon, stillPending, keySetStillSecond, settled, fixture.KeySetIs(third));
        })
        .TheTest
        .ShouldPass<TooSoonOutcome>((because, outcome) =>
        {
            because.ItsTrue("a settle inside the interval is deferred", outcome.TooSoon == KeySetRecoverySettlement.Deferred);
            because.ItsTrue("the recovery keeps waiting and the key set stays", outcome.StillPending && outcome.KeySetStillSecond);
            because.ItsTrue("once the interval has passed it settles", outcome.Settled == KeySetRecoverySettlement.Settled && outcome.MovedToThird);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void AnchorAndVerifyOnlyTheDueRecoverysOwnRotation()
    {
        When.A<HandoverFixture>("asks the recovery proof about other key sets and other proofs", new HandoverFixture(nameof(AnchorAndVerifyOnlyTheDueRecoverysOwnRotation)), (fixture) =>
        {
            SyntheticAuthenticator lost = new SyntheticAuthenticator();
            SyntheticAuthenticator heir = new SyntheticAuthenticator();
            SyntheticAuthenticator other = new SyntheticAuthenticator();
            SyntheticAuthenticator bobs = new SyntheticAuthenticator();
            string lostId = fixture.SignUp(lost);
            string heirId = fixture.Add(heir);
            string otherId = fixture.Add(other);
            fixture.SignUp(bobs, "bob");
            fixture.AgePasskeys();
            PublicKeySetData current = fixture.Registrar.Resolve(Handle)!;
            KeySetRecoveryStart start = fixture.Recovery.Begin(Handle, lostId, heirId, null);
            byte[] assertion = HandoverFixture.AssertionJson(heir, start);
            fixture.Recovery.Complete(Handle, start.RecoveryId, assertion);
            fixture.Clock.Advance(fixture.Options.RecoveryDelay);

            PublicKeySetData toHeir = PasskeyKeySet.From(fixture.Credentials.FindByCredentialId(heirId)!);
            PublicKeySetData toOther = PasskeyKeySet.From(fixture.Credentials.FindByCredentialId(otherId)!);
            bool anchorsCurrent = fixture.RecoveryProof.Anchors(current);
            bool anchorsProposed = fixture.RecoveryProof.Anchors(toHeir);
            bool anchorsBobs = fixture.RecoveryProof.Anchors(fixture.Registrar.Resolve("bob")!);
            bool verifies = fixture.RecoveryProof.Verify(current, toHeir, assertion).Success;
            bool otherBytes = fixture.RecoveryProof.Verify(current, toHeir, Encoding.UTF8.GetBytes("{}")).Success;
            bool otherTarget = fixture.RecoveryProof.Verify(current, toOther, assertion).Success;
            PublicKeySetData crossHandle = PasskeyKeySet.From("bob", CoseAlgorithm.ES256, heir.PublicKeyPem);
            bool otherHandle = fixture.RecoveryProof.Verify(current, crossHandle, assertion).Success;
            // The stored assertion is checked again at settle: a tampered row doesn't verify.
            PendingKeySetRecoveryData row = fixture.Recoveries.Find(Handle, start.RecoveryId!)!;
            string original = row.AssertionJson;
            PasskeyAssertionResponse parsed = PasskeyAssertionResponse.FromJson(Encoding.UTF8.GetBytes(original));
            string tampered = PasskeyJson.Serialize(parsed with { Response = parsed.Response! with { Signature = Base64UrlEncoder.Default.Encode(new byte[64]) } });
            row.AssertionJson = tampered;
            fixture.Recoveries.RewriteAtRest(row);
            bool tamperedVerifies = fixture.RecoveryProof.Verify(current, toHeir, Encoding.UTF8.GetBytes(tampered)).Success;
            row.AssertionJson = original;
            fixture.Recoveries.RewriteAtRest(row);
            return new ProofOutcome(anchorsCurrent, anchorsProposed, anchorsBobs, verifies, otherBytes, otherTarget, otherHandle, tamperedVerifies);
        })
        .TheTest
        .ShouldPass<ProofOutcome>((because, outcome) =>
        {
            because.ItsTrue("it anchors the key set its due recovery began from", outcome.AnchorsCurrent);
            because.ItsTrue("it doesn't anchor the proposed key set", !outcome.AnchorsProposed);
            because.ItsTrue("it doesn't anchor another person's key set", !outcome.AnchorsBobs);
            because.ItsTrue("the stored assertion verifies the recovery's rotation", outcome.Verifies);
            because.ItsTrue("other proof bytes are refused", !outcome.OtherBytes);
            because.ItsTrue("a rotation to another passkey is refused", !outcome.OtherTarget);
            because.ItsTrue("a rotation onto another handle is refused", !outcome.OtherHandle);
            because.ItsTrue("a stored assertion whose signature was changed doesn't verify", !outcome.TamperedVerifies);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseARecoveryRowAlteredAtRest()
    {
        When.A<HandoverFixture>("rewrites a due recovery's stored assertion and heir with genuine signatures", new HandoverFixture(nameof(RefuseARecoveryRowAlteredAtRest)), (fixture) =>
        {
            SyntheticAuthenticator lost = new SyntheticAuthenticator();
            SyntheticAuthenticator heir = new SyntheticAuthenticator();
            SyntheticAuthenticator other = new SyntheticAuthenticator();
            string lostId = fixture.SignUp(lost);
            string heirId = fixture.Add(heir);
            string otherId = fixture.Add(other);
            fixture.AgePasskeys();
            PublicKeySetData current = fixture.Registrar.Resolve(Handle)!;
            KeySetRecoveryStart start = fixture.Recovery.Begin(Handle, lostId, heirId, null);
            fixture.Recovery.Complete(Handle, start.RecoveryId, HandoverFixture.AssertionJson(heir, start));
            fixture.Clock.Advance(fixture.Options.RecoveryDelay);
            PublicKeySetData toHeir = PasskeyKeySet.From(fixture.Credentials.FindByCredentialId(heirId)!);
            PublicKeySetData toOther = PasskeyKeySet.From(fixture.Credentials.FindByCredentialId(otherId)!);

            // The heir really signed, but without user verification.
            heir.UserVerified = false;
            byte[] unverified = HandoverFixture.AssertionJson(heir, PasskeyKeySetRotationProof.Challenge(current, toHeir));
            heir.UserVerified = true;
            Store(fixture, start, unverified);
            bool unverifiedVerifies = fixture.RecoveryProof.Verify(current, toHeir, unverified).Success;

            // The heir really signed, but a rotation to another passkey's key set.
            byte[] elsewhere = HandoverFixture.AssertionJson(heir, PasskeyKeySetRotationProof.Challenge(current, toOther));
            Store(fixture, start, elsewhere);
            bool elsewhereVerifies = fixture.RecoveryProof.Verify(current, toOther, elsewhere).Success;

            // The heir's credential id now names another key, which signed for itself.
            SyntheticAuthenticator swapped = new SyntheticAuthenticator { CredentialId = heir.CredentialId };
            fixture.Credentials.Remove(Handle, heirId);
            fixture.Add(swapped);
            PublicKeySetData toSwapped = PasskeyKeySet.From(fixture.Credentials.FindByCredentialId(heirId)!);
            byte[] bySwapped = HandoverFixture.AssertionJson(swapped, PasskeyKeySetRotationProof.Challenge(current, toSwapped));
            Store(fixture, start, bySwapped);
            bool swappedVerifies = fixture.RecoveryProof.Verify(current, toSwapped, bySwapped).Success;
            return new AlteredOutcome(unverifiedVerifies, elsewhereVerifies, swappedVerifies);
        })
        .TheTest
        .ShouldPass<AlteredOutcome>((because, outcome) =>
        {
            because.ItsTrue("a stored assertion without user verification doesn't verify", !outcome.UnverifiedVerifies);
            because.ItsTrue("a stored assertion for a rotation to another key set doesn't verify", !outcome.ElsewhereVerifies);
            because.ItsTrue("a heir whose key changed since the recovery began doesn't verify", !outcome.SwappedVerifies);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseACompletionAfterTheKeySetWasRebound()
    {
        When.A<HandoverFixture>("rebinds an unheld key set to a new key between begin and complete", new HandoverFixture(nameof(RefuseACompletionAfterTheKeySetWasRebound)), (fixture) =>
        {
            SyntheticAuthenticator lost = new SyntheticAuthenticator();
            SyntheticAuthenticator heir = new SyntheticAuthenticator();
            SyntheticAuthenticator other = new SyntheticAuthenticator();
            string lostId = fixture.SignUp(lost);
            string heirId = fixture.Add(heir);
            string otherId = fixture.Add(other);
            fixture.Inventory.Remove(Handle, lostId, keepKeySet: true);
            fixture.AgePasskeys();
            KeySetRecoveryStart start = fixture.Recovery.Begin(Handle, null, heirId, null);

            // A re-bind by a proof other than the passkey proofs, to the key of another passkey the
            // person then removes: the key set is again one a removed passkey held, and only the
            // anchor shows it is not the key set the recovery began from.
            RebindProof rebind = new RebindProof();
            fixture.Proofs.Add(rebind);
            rebind.Armed = true;
            PublicKeySetData rebound = PasskeyKeySet.From(Handle, other.Algorithm, other.PublicKeyPem);
            fixture.Registrar.Rotate(rebound, new byte[] { 1 });
            rebind.Armed = false;
            fixture.Inventory.Remove(Handle, otherId, keepKeySet: true);

            KeySetRecoveryResult done = fixture.Recovery.Complete(Handle, start.RecoveryId, HandoverFixture.AssertionJson(heir, start));
            return new ReboundOutcome(done.Refusal, fixture.Recoveries.FindByHandle(Handle).Count, fixture.Credentials.FindByCredentialId(heirId) is not null);
        })
        .TheTest
        .ShouldPass<ReboundOutcome>((because, outcome) =>
        {
            because.ItsTrue("a key set that moved since begin is refused at complete", outcome.Refusal == KeySetRecoveryRefusal.KeySetChanged);
            because.ItsTrue("nothing is stored and the heir stays", outcome.StoredRecoveries == 0 && outcome.HeirKept);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void WaitWhenTheStoreFaultsAtSettle()
    {
        When.A<HandoverFixture>("settles a due recovery while the recovery store times out once", new HandoverFixture(nameof(WaitWhenTheStoreFaultsAtSettle)), (fixture) =>
        {
            SyntheticAuthenticator lost = new SyntheticAuthenticator();
            SyntheticAuthenticator heir = new SyntheticAuthenticator();
            string lostId = fixture.SignUp(lost);
            string heirId = fixture.Add(heir);
            fixture.AgePasskeys();
            KeySetRecoveryStart start = fixture.Recovery.Begin(Handle, lostId, heirId, null);
            fixture.Recovery.Complete(Handle, start.RecoveryId, HandoverFixture.AssertionJson(heir, start));
            fixture.Clock.Advance(fixture.Options.RecoveryDelay);

            // Read 1 finds the pending recovery; read 2 is the proof's, asked before the registrar.
            fixture.Recoveries.FailOneReadAfter(1);
            KeySetRecoverySettlement proofFault = fixture.Recovery.Settle(Handle);
            bool faultedAtTheProof = fixture.Recoveries.Faults == 1;
            bool waitingAfterProofFault = fixture.Recovery.Pending(Handle) is not null && fixture.KeySetIs(lost);

            // From read 3 on, the registrar's own asks of the proof, after the proof verified once.
            fixture.Recoveries.FailReadsAfter(2);
            KeySetRecoverySettlement registrarFault = fixture.Recovery.Settle(Handle);
            fixture.Recoveries.Heal();
            bool faultedAtTheRegistrar = fixture.Recoveries.Faults > 1;
            bool waitingAfterRegistrarFault = fixture.Recovery.Pending(Handle) is not null && fixture.KeySetIs(lost);

            KeySetRecoverySettlement settled = fixture.Recovery.Settle(Handle);
            return new FaultOutcome(proofFault, faultedAtTheProof, waitingAfterProofFault, registrarFault, faultedAtTheRegistrar, waitingAfterRegistrarFault, settled, fixture.KeySetIs(heir));
        })
        .TheTest
        .ShouldPass<FaultOutcome>((because, outcome) =>
        {
            because.ItsTrue("a store fault in the proof defers the settle", outcome.ProofFault == KeySetRecoverySettlement.Deferred && outcome.FaultedAtTheProof);
            because.ItsTrue("the recovery keeps waiting and the key set stays", outcome.WaitingAfterProofFault);
            because.ItsTrue("a store fault inside the registrar defers the settle too", outcome.RegistrarFault == KeySetRecoverySettlement.Deferred && outcome.FaultedAtTheRegistrar);
            because.ItsTrue("and the recovery still waits", outcome.WaitingAfterRegistrarFault);
            because.ItsTrue("the next settle moves the key set", outcome.Settled == KeySetRecoverySettlement.Settled && outcome.MovedToHeir);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RecoverOnlyAKeySetAPasskeyHeld()
    {
        When.A<HandoverFixture>("tries to recover a key set an admin rebound to a key no passkey held", new HandoverFixture(nameof(RecoverOnlyAKeySetAPasskeyHeld)), (fixture) =>
        {
            SyntheticAuthenticator lost = new SyntheticAuthenticator();
            SyntheticAuthenticator heir = new SyntheticAuthenticator();
            bool unrecoverableWithNoKeySet = fixture.Recovery.IsUnrecoverable(Handle);
            string lostId = fixture.SignUp(lost);
            string heirId = fixture.Add(heir);
            bool unrecoverableWhenHeld = fixture.Recovery.IsUnrecoverable(Handle);
            fixture.Inventory.Remove(Handle, lostId, keepKeySet: true);
            bool recoverableWhenOrphaned = fixture.Recovery.IsRecoverable(Handle);
            bool unrecoverableWhenOrphaned = fixture.Recovery.IsUnrecoverable(Handle);

            // An admin re-bind before any recovery begins: the key set is now a key no passkey held.
            RebindProof rebind = new RebindProof();
            fixture.Proofs.Add(rebind);
            rebind.Armed = true;
            fixture.Registrar.Rotate(PasskeyKeySet.From(Handle, CoseAlgorithm.ES256, new SyntheticAuthenticator().PublicKeyPem), new byte[] { 1 });
            rebind.Armed = false;
            fixture.AgePasskeys();

            bool recoverableWhenRebound = fixture.Recovery.IsRecoverable(Handle);
            bool unrecoverableWhenRebound = fixture.Recovery.IsUnrecoverable(Handle);

            // A device-key person who then adds a passkey: the key set was never a passkey's, so
            // passkey recovery can't move it either; the signal says so, and the copy isn't a fault.
            const string deviceHandle = "device-person";
            fixture.Registrar.Register(PasskeyKeySet.From(deviceHandle, CoseAlgorithm.ES256, new SyntheticAuthenticator().PublicKeyPem));
            fixture.Add(new SyntheticAuthenticator(), deviceHandle);
            bool deviceKeyRecoverable = fixture.Recovery.IsRecoverable(deviceHandle);
            bool deviceKeyUnrecoverable = fixture.Recovery.IsUnrecoverable(deviceHandle);
            KeySetRecoveryRefusal begin = fixture.Recovery.Begin(Handle, null, heirId, null).Refusal;
            return new ReboundBeforeBeginOutcome(recoverableWhenOrphaned, recoverableWhenRebound, begin, fixture.Recoveries.FindByHandle(Handle).Count,
                unrecoverableWithNoKeySet, unrecoverableWhenHeld, unrecoverableWhenOrphaned, unrecoverableWhenRebound, deviceKeyRecoverable, deviceKeyUnrecoverable);
        })
        .TheTest
        .ShouldPass<ReboundBeforeBeginOutcome>((because, outcome) =>
        {
            because.ItsTrue("a key set whose passkey was removed is recoverable", outcome.RecoverableWhenOrphaned);
            because.ItsTrue("a key set no passkey held is not offered", !outcome.RecoverableWhenRebound);
            because.ItsTrue("a person with no key set isn't told to contact support", !outcome.UnrecoverableWithNoKeySet);
            because.ItsTrue("nor is one whose passkey holds the key set", !outcome.UnrecoverableWhenHeld);
            because.ItsTrue("nor one who can recover", !outcome.UnrecoverableWhenOrphaned);
            because.ItsTrue("a key set no passkey held and no recovery can take is flagged as one passkey recovery can't move", outcome.UnrecoverableWhenRebound);
            because.ItsTrue("so is a device-key key set after a passkey is added, and it isn't offered for recovery", outcome.DeviceKeyUnrecoverable && !outcome.DeviceKeyRecoverable);
            because.ItsTrue("and beginning a recovery of it is refused", outcome.Begin == KeySetRecoveryRefusal.NoKeySet);
            because.ItsTrue("nothing is stored", outcome.StoredRecoveries == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void KeepACancelFinalWhenTheCounterStaysAtZero()
    {
        When.A<HandoverFixture>("replays a canceled recovery's assertion from a passkey whose counter stays at 0", new HandoverFixture(nameof(KeepACancelFinalWhenTheCounterStaysAtZero)), (fixture) =>
        {
            SyntheticAuthenticator lost = new SyntheticAuthenticator();
            // A synced passkey: its counter is always 0, so the verifier doesn't judge it.
            SyntheticAuthenticator heir = new SyntheticAuthenticator { SignCount = 0 };
            string lostId = fixture.SignUp(lost);
            string heirId = fixture.Add(heir);
            fixture.AgePasskeys();
            KeySetRecoveryStart start = fixture.Recovery.Begin(Handle, lostId, heirId, null);
            byte[] assertion = Encoding.UTF8.GetBytes(PasskeyJson.Serialize(heir.Assert(Base64UrlEncoder.Default.Decode(start.Options!.Challenge))));
            bool proved = fixture.Recovery.Complete(Handle, start.RecoveryId, assertion).Success;
            bool canceled = fixture.Recovery.Cancel(Handle, start.RecoveryId!, heirId);

            KeySetRecoveryStart again = fixture.Recovery.Begin(Handle, null, heirId, null);
            KeySetRecoveryRefusal replayed = fixture.Recovery.Complete(Handle, again.RecoveryId, assertion).Refusal;
            // The same signed parts with an unsigned field added: the text differs, the signature doesn't.
            KeySetRecoveryStart altered = fixture.Recovery.Begin(Handle, null, heirId, null);
            string alteredText = "{\"ceremonyId\":\"x\"," + Encoding.UTF8.GetString(assertion).Substring(1);
            KeySetRecoveryRefusal alteredReplayed = fixture.Recovery.Complete(Handle, altered.RecoveryId, Encoding.UTF8.GetBytes(alteredText)).Refusal;
            KeySetRecoveryStart third = fixture.Recovery.Begin(Handle, null, heirId, null);
            byte[] fresh = Encoding.UTF8.GetBytes(PasskeyJson.Serialize(heir.Assert(Base64UrlEncoder.Default.Decode(third.Options!.Challenge))));
            bool freshProved = fixture.Recovery.Complete(Handle, third.RecoveryId, fresh).Success;
            return new ReplayOutcome(proved, canceled, again.Success, replayed, alteredText != Encoding.UTF8.GetString(assertion), alteredReplayed, freshProved);
        })
        .TheTest
        .ShouldPass<ReplayOutcome>((because, outcome) =>
        {
            because.ItsTrue("the first recovery is proved and canceled", outcome.Proved && outcome.Canceled);
            because.ItsTrue("the key set its removed passkey held can be recovered again", outcome.BegunAgain);
            because.ItsTrue("the canceled recovery's assertion can't prove a new one", outcome.Replayed == KeySetRecoveryRefusal.ProofRefused);
            because.ItsTrue("nor can it with an unsigned field added to change its text", outcome.AlteredTextDiffers && outcome.AlteredReplayed == KeySetRecoveryRefusal.ProofRefused);
            because.ItsTrue("a fresh assertion by the heir can", outcome.FreshProved);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void SettleARecoveryAfterTheDelayWasRaisedWhileItWaited()
    {
        When.A<HandoverFixture>("raises the recovery delay while a recovery waits", new HandoverFixture(nameof(SettleARecoveryAfterTheDelayWasRaisedWhileItWaited)), (fixture) =>
        {
            SyntheticAuthenticator lost = new SyntheticAuthenticator();
            SyntheticAuthenticator heir = new SyntheticAuthenticator();
            string lostId = fixture.SignUp(lost);
            string heirId = fixture.Add(heir);
            fixture.AgePasskeys();
            KeySetRecoveryStart start = fixture.Recovery.Begin(Handle, lostId, heirId, null);
            fixture.Recovery.Complete(Handle, start.RecoveryId, HandoverFixture.AssertionJson(heir, start));
            TimeSpan original = fixture.Options.RecoveryDelay;
            fixture.Options.RecoveryDelay = original.Add(TimeSpan.FromHours(24));

            fixture.Clock.Advance(original);
            KeySetRecoverySettlement atTheOldDelay = fixture.Recovery.Settle(Handle);
            bool stillWaiting = fixture.Recovery.Pending(Handle) is not null && fixture.KeySetIs(lost);
            fixture.Clock.Advance(TimeSpan.FromHours(24));
            KeySetRecoverySettlement atTheNewDelay = fixture.Recovery.Settle(Handle);
            return new RaisedDelayOutcome(atTheOldDelay, stillWaiting, atTheNewDelay, fixture.KeySetIs(heir));
        })
        .TheTest
        .ShouldPass<RaisedDelayOutcome>((because, outcome) =>
        {
            because.ItsTrue("at the old delay the recovery isn't due yet", outcome.AtTheOldDelay == KeySetRecoverySettlement.NotDue);
            because.ItsTrue("it keeps waiting and the key set stays", outcome.StillWaiting);
            because.ItsTrue("once the raised delay passes it settles rather than being refused", outcome.AtTheNewDelay == KeySetRecoverySettlement.Settled && outcome.MovedToHeir);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void HoldTheDelayAndAnchorOnlyASingleOpenRecovery()
    {
        When.A<HandoverFixture>("rewrites a recovery's effective time and adds a second open one", new HandoverFixture(nameof(HoldTheDelayAndAnchorOnlyASingleOpenRecovery)), (fixture) =>
        {
            SyntheticAuthenticator lost = new SyntheticAuthenticator();
            SyntheticAuthenticator heir = new SyntheticAuthenticator();
            string lostId = fixture.SignUp(lost);
            string heirId = fixture.Add(heir);
            fixture.AgePasskeys();
            PublicKeySetData current = fixture.Registrar.Resolve(Handle)!;
            KeySetRecoveryStart start = fixture.Recovery.Begin(Handle, lostId, heirId, null);
            fixture.Recovery.Complete(Handle, start.RecoveryId, HandoverFixture.AssertionJson(heir, start));

            PendingKeySetRecoveryData row = fixture.Recoveries.Find(Handle, start.RecoveryId!)!;
            row.EffectiveUtc = row.BeganUtc;
            fixture.Recoveries.RewriteAtRest(row);
            bool anchorsWithAnEarlyEffectiveTime = fixture.RecoveryProof.Anchors(current);
            KeySetRecoverySettlement earlySettle = fixture.Recovery.Settle(Handle);
            row.EffectiveUtc = row.BeganUtc.Add(fixture.Options.RecoveryDelay);
            fixture.Recoveries.RewriteAtRest(row);

            fixture.Clock.Advance(fixture.Options.RecoveryDelay);
            bool anchorsWhenDue = fixture.RecoveryProof.Anchors(current);
            PendingKeySetRecoveryData second = fixture.Recoveries.Find(Handle, start.RecoveryId!)!;
            second.RecoveryId = "second";
            fixture.Recoveries.Save(second);
            bool anchorsWithTwoOpen = fixture.RecoveryProof.Anchors(current);
            return new DelayHeldOutcome(anchorsWithAnEarlyEffectiveTime, earlySettle, anchorsWhenDue, anchorsWithTwoOpen, fixture.KeySetIs(lost));
        })
        .TheTest
        .ShouldPass<DelayHeldOutcome>((because, outcome) =>
        {
            because.ItsTrue("an effective time earlier than the delay doesn't anchor", !outcome.AnchorsWithAnEarlyEffectiveTime);
            because.ItsTrue("so the early settle just waits", outcome.EarlySettle == KeySetRecoverySettlement.NotDue);
            because.ItsTrue("once the delay has really passed it anchors", outcome.AnchorsWhenDue);
            because.ItsTrue("two open recoveries anchor nothing", !outcome.AnchorsWithTwoOpen);
            because.ItsTrue("the key set stays", outcome.KeySetKept);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RecordAMoveThatAlreadyHappened()
    {
        When.A<HandoverFixture>("settles a recovery whose rotation went through but was not recorded", new HandoverFixture(nameof(RecordAMoveThatAlreadyHappened)), (fixture) =>
        {
            SyntheticAuthenticator lost = new SyntheticAuthenticator();
            SyntheticAuthenticator heir = new SyntheticAuthenticator();
            string lostId = fixture.SignUp(lost);
            string heirId = fixture.Add(heir);
            fixture.AgePasskeys();
            KeySetRecoveryStart start = fixture.Recovery.Begin(Handle, lostId, heirId, null);
            fixture.Recovery.Complete(Handle, start.RecoveryId, HandoverFixture.AssertionJson(heir, start));
            fixture.Clock.Advance(fixture.Options.RecoveryDelay);
            // The rotation a settle makes, without the settle recording it.
            PendingKeySetRecoveryData row = fixture.Recoveries.Find(Handle, start.RecoveryId!)!;
            fixture.Registrar.Rotate(PasskeyKeySet.From(fixture.Credentials.FindByCredentialId(heirId)!), Encoding.UTF8.GetBytes(row.AssertionJson));
            KeySetRecoverySettlement settled = fixture.Recovery.Settle(Handle);
            PendingKeySetRecoveryData after = fixture.Recoveries.Find(Handle, start.RecoveryId!)!;
            return new AlreadyMovedOutcome(settled, after, fixture.Credentials.FindByCredentialId(heirId)!.IsRegisteredKeySet, fixture.KeySetIs(heir));
        })
        .TheTest
        .ShouldPass<AlreadyMovedOutcome>((because, outcome) =>
        {
            because.ItsTrue("the recovery is recorded as settled, not as changed", outcome.Settled == KeySetRecoverySettlement.Settled && outcome.Row.CompletedUtc is not null && outcome.Row.CancelReason is null);
            because.ItsTrue("the heir is marked as the key set", outcome.HeirMarked && outcome.MovedToHeir);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void KeepRecoveriesInAStore()
    {
        When.A<PersistedKeySetRecoveryRepository>("stores, finds and updates recoveries in the object store",
            new PersistedKeySetRecoveryRepository(HandoverFixture.CreateObjectDataRepository(nameof(KeepRecoveriesInAStore))), (repository) =>
        {
            DateTime start = new DateTime(2026, 11, 20, 0, 0, 0, DateTimeKind.Utc);
            repository.Save(Row("alice", "r1", start));
            repository.Save(Row("alice", "r2", start.AddMinutes(1)));
            repository.Save(Row("bob", "r1", start.AddMinutes(2)));
            bool duplicateRefused;
            try
            {
                repository.Save(Row("alice", "r1", start));
                duplicateRefused = false;
            }
            catch (InvalidOperationException)
            {
                duplicateRefused = true;
            }
            IReadOnlyList<PendingKeySetRecoveryData> alices = repository.FindByHandle("alice");
            PendingKeySetRecoveryData changed = repository.Find("alice", "r1")!;
            changed.CanceledUtc = start.AddHours(1);
            changed.CancelReason = KeySetRecoveryEnd.Canceled;
            changed.Anchor = "rewritten";
            bool updated = repository.Update(changed);
            PendingKeySetRecoveryData reread = repository.Find("alice", "r1")!;
            bool updatedMissing = repository.Update(Row("carol", "r9", start));
            // Forward only: a canceled row stays canceled, and doesn't become completed.
            PendingKeySetRecoveryData reopened = repository.Find("alice", "r1")!;
            reopened.CanceledUtc = null;
            reopened.CancelReason = null;
            reopened.CompletedUtc = start.AddHours(2);
            repository.Update(reopened);
            PendingKeySetRecoveryData stillCanceled = repository.Find("alice", "r1")!;
            repository.RecordRemovedPasskeyKey("alice", "cred-1", "fp-1");
            repository.RecordRemovedPasskeyKey("alice", "cred-1", "fp-1");
            bool removedKeys = repository.WasRemovedPasskeyKey("alice", "fp-1") && !repository.WasRemovedPasskeyKey("bob", "fp-1") && !repository.WasRemovedPasskeyKey("alice", "fp-2");
            return new StoreOutcome(duplicateRefused, alices.Select(row => row.RecoveryId).ToList(), updated, reread, repository.Find("bob", "r1"), repository.Find("bob", "r2"), updatedMissing, stillCanceled, removedKeys);
        })
        .TheTest
        .ShouldPass<StoreOutcome>((because, outcome) =>
        {
            because.ItsTrue("a second row with the same handle and id is refused", outcome.DuplicateRefused);
            because.ItsTrue("a person's rows come back oldest first, and only theirs", outcome.AliceIds.SequenceEqual(new[] { "r1", "r2" }));
            because.ItsTrue("an update stores the cancel", outcome.Updated && outcome.Reread.CancelReason == KeySetRecoveryEnd.Canceled && outcome.Reread.CanceledUtc is not null && !outcome.Reread.IsOpen());
            because.ItsTrue("an update can't rewrite what was proved", outcome.Reread.Anchor == "anchor-r1");
            because.ItsTrue("ids are scoped to the person", outcome.BobsR1 is not null && outcome.BobsR1.IsOpen() && outcome.BobsR2 is null);
            because.ItsTrue("updating a row that doesn't exist does nothing", !outcome.UpdatedMissing);
            because.ItsTrue("an update can't reopen or complete a canceled row", !outcome.StillCanceled.IsOpen() && outcome.StillCanceled.CancelReason == KeySetRecoveryEnd.Canceled && outcome.StillCanceled.CompletedUtc is null);
            because.ItsTrue("removed passkey keys are kept per person", outcome.RemovedKeys);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static void Store(HandoverFixture fixture, KeySetRecoveryStart start, byte[] assertion)
    {
        PendingKeySetRecoveryData row = fixture.Recoveries.Find(Handle, start.RecoveryId!)!;
        row.AssertionJson = Encoding.UTF8.GetString(assertion);
        fixture.Recoveries.RewriteAtRest(row);
    }

    private static PendingKeySetRecoveryData Row(string handle, string id, DateTime began)
    {
        return new PendingKeySetRecoveryData
        {
            PersonHandle = handle,
            RecoveryId = id,
            HeirCredentialId = "heir-" + id,
            HeirKeyFingerprint = "fp-" + id,
            Anchor = "anchor-" + id,
            AssertionJson = "{}",
            BeganUtc = began,
            EffectiveUtc = began.AddHours(72)
        };
    }

    private sealed record HappyOutcome(KeySetRecoveryStart Start, bool ChallengeIsTheRotation, bool AllowsOnlyTheHeir, bool RequiresVerification, KeySetRecoveryResult Done, bool EffectiveIsTheDelay,
        bool LostRemovedNow, bool KeySetStillTheLostKey, bool LostNotYetBlocklisted, PendingKeySetRecoveryData? Pending, KeySetRecoverySettlement Early, bool AnchoredEarly, bool AnchoredWhenDue,
        KeySetRecoverySettlement Settled, bool MovedToHeir, bool LostBlocklisted, bool HeirMarked, bool AuditNamesRecovery, PendingKeySetRecoveryData Stored, KeySetRecoverySettlement Again, bool CancelAfterSettle);

    private sealed record AlreadyRemovedOutcome(bool RecoverableWhileHeld, PasskeyRemoval Removal, bool RecoverableAfterRemoval, KeySetRecoveryStart Start, KeySetRecoveryResult Done,
        bool RecoverableWhilePending, KeySetRecoverySettlement Settled, bool MovedToHeir, bool LostBlocklisted, bool RecoverableAfterSettle);

    private sealed record BeginRefusalOutcome(KeySetRecoveryStart TooNew, bool EligibleAtTheGate, KeySetRecoveryRefusal JustTooNew, KeySetRecoveryRefusal Unknown, KeySetRecoveryRefusal SomeoneElses,
        KeySetRecoveryRefusal NotKeySet, KeySetRecoveryRefusal RemovesRequired, KeySetRecoveryRefusal HeirIsRemoves, KeySetRecoveryRefusal DefaultHeirIsRemoves, KeySetRecoveryRefusal NoHeir,
        KeySetRecoveryRefusal HeirIsBobs, KeySetRecoveryRefusal NoKeySet, KeySetRecoveryRefusal Unavailable, bool UnavailableReported, bool KeySetKept, int StoredRecoveries);

    private sealed record CompleteRefusalOutcome(List<KeySetRecoveryRefusal> Refusals, KeySetRecoveryRefusal HeirGone, bool HandedOver, KeySetRecoveryRefusal KeySetChanged, int StoredRecoveries, bool KeySetIsTheHandoverHeir);

    private sealed record CancelOutcome(KeySetRecoveryRefusal SecondBegin, KeySetHandoverRefusal HandoverWhilePending, bool CanceledByBob, bool CanceledUnknown, bool Canceled, bool CanceledTwice,
        PendingKeySetRecoveryData? Pending, KeySetRecoverySettlement Settled, bool Anchors, bool KeySetKept, PendingKeySetRecoveryData Row, bool RecoverableAgain);

    private sealed record EndOutcome(PasskeyRemoval HeirRemoval, PendingKeySetRecoveryData? AfterHeirRemoved, string? HeirGoneReason, bool SecondBegun, KeySetRecoverySettlement Settled, string? ChangedReason, bool KeySetKept);

    private sealed record BlocklistedOutcome(bool HandedOver, bool FirstBlocklisted, bool Proved, KeySetRecoverySettlement Settled, string? Reason, bool KeySetKept);

    private sealed record TooSoonOutcome(KeySetRecoverySettlement TooSoon, bool StillPending, bool KeySetStillSecond, KeySetRecoverySettlement Settled, bool MovedToThird);

    private sealed record ProofOutcome(bool AnchorsCurrent, bool AnchorsProposed, bool AnchorsBobs, bool Verifies, bool OtherBytes, bool OtherTarget, bool OtherHandle, bool TamperedVerifies);

    private sealed record AlteredOutcome(bool UnverifiedVerifies, bool ElsewhereVerifies, bool SwappedVerifies);

    private sealed record ReboundOutcome(KeySetRecoveryRefusal Refusal, int StoredRecoveries, bool HeirKept);

    private sealed record StoreOutcome(bool DuplicateRefused, List<string> AliceIds, bool Updated, PendingKeySetRecoveryData Reread, PendingKeySetRecoveryData? BobsR1, PendingKeySetRecoveryData? BobsR2, bool UpdatedMissing,
        PendingKeySetRecoveryData StillCanceled, bool RemovedKeys);

    private sealed record FaultOutcome(KeySetRecoverySettlement ProofFault, bool FaultedAtTheProof, bool WaitingAfterProofFault, KeySetRecoverySettlement RegistrarFault, bool FaultedAtTheRegistrar,
        bool WaitingAfterRegistrarFault, KeySetRecoverySettlement Settled, bool MovedToHeir);

    private sealed record ReboundBeforeBeginOutcome(bool RecoverableWhenOrphaned, bool RecoverableWhenRebound, KeySetRecoveryRefusal Begin, int StoredRecoveries,
        bool UnrecoverableWithNoKeySet, bool UnrecoverableWhenHeld, bool UnrecoverableWhenOrphaned, bool UnrecoverableWhenRebound, bool DeviceKeyRecoverable, bool DeviceKeyUnrecoverable);

    private sealed record ReplayOutcome(bool Proved, bool Canceled, bool BegunAgain, KeySetRecoveryRefusal Replayed, bool AlteredTextDiffers, KeySetRecoveryRefusal AlteredReplayed, bool FreshProved);

    private sealed record RaisedDelayOutcome(KeySetRecoverySettlement AtTheOldDelay, bool StillWaiting, KeySetRecoverySettlement AtTheNewDelay, bool MovedToHeir);

    private sealed record DelayHeldOutcome(bool AnchorsWithAnEarlyEffectiveTime, KeySetRecoverySettlement EarlySettle, bool AnchorsWhenDue, bool AnchorsWithTwoOpen, bool KeySetKept);

    private sealed record ProofRefusedOutcome(KeySetRecoverySettlement Settled, string? Reason, bool KeySetKept);

    private sealed record AlreadyMovedOutcome(KeySetRecoverySettlement Settled, PendingKeySetRecoveryData Row, bool HeirMarked, bool MovedToHeir);
}
