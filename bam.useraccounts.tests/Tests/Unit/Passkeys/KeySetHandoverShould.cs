using System.Text;
using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Encryption.Cose;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Profile;
using Bam.Test;
using Bam.UserAccounts.Passkeys;
using Bam.UserAccounts.Tests.TestClasses;

namespace Bam.UserAccounts.Tests.Unit.Passkeys;

/// <summary>
/// Pins bam.useraccounts#20 part 1: removing the passkey that holds the key set first moves the
/// key set to a passkey the person keeps, proved by an assertion of the passkey being removed.
/// Runs over a real registrar and proof chain, so "the removed key no longer verifies as the
/// handle" is what bam.protocol resolves, not what a fake answers.
/// </summary>
[UnitTestMenu("KeySetHandover Should", Selector = "ksho")]
public class KeySetHandoverShould : UnitTestMenuContainer
{
    private const string Handle = HandoverFixture.Handle;

    public KeySetHandoverShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    [UnitTest]
    public void MoveTheKeySetToTheHeirAndRemoveTheOldPasskey()
    {
        When.A<HandoverFixture>("hands an ES256 key set to an RS256 passkey, then on to an ES256 one", new HandoverFixture(nameof(MoveTheKeySetToTheHeirAndRemoveTheOldPasskey)), (fixture) =>
        {
            SyntheticAuthenticator first = new SyntheticAuthenticator(CoseAlgorithm.ES256);
            SyntheticAuthenticator second = new SyntheticAuthenticator(CoseAlgorithm.RS256);
            SyntheticAuthenticator third = new SyntheticAuthenticator(CoseAlgorithm.ES256);
            string firstId = fixture.SignUp(first);
            string secondId = fixture.Add(second);
            PasskeyRemoval plainRemoval = fixture.Inventory.Remove(Handle, firstId);
            PasskeyRemoval heirRemoval = fixture.Inventory.Remove(Handle, secondId, keepKeySet: false);
            bool heirStillThere = fixture.Credentials.FindByCredentialId(secondId) is not null;
            // second was removed above (it does not hold the key set): add it back as a new passkey
            second = new SyntheticAuthenticator(CoseAlgorithm.RS256);
            secondId = fixture.Add(second);

            PublicKeySetData before = fixture.Registrar.Resolve(Handle)!;
            KeySetHandoverStart start = fixture.Handover.Begin(Handle, firstId, null, secondId);            byte[] expectedChallenge = PasskeyKeySetRotationProof.Challenge(before, PasskeyKeySet.From(fixture.Credentials.FindByCredentialId(secondId)!));
            bool challengeIsTheRotation = start.Options is not null && Base64UrlEncoder.Default.Decode(start.Options.Challenge).SequenceEqual(expectedChallenge);
            bool allowsOnlyTheOldPasskey = start.Options is not null && start.Options.AllowCredentials.Count == 1 && start.Options.AllowCredentials[0].Id == firstId;
            KeySetHandoverResult done = fixture.Handover.Complete(Handle, start.HandoverId, HandoverFixture.AssertionJson(first, start));

            bool movedToSecond = fixture.KeySetIs(second);
            bool firstGone = fixture.Credentials.FindByCredentialId(firstId) is null;
            bool secondMarked = fixture.Credentials.FindByCredentialId(secondId)!.IsRegisteredKeySet;
            bool firstBlocklisted = fixture.KeyIsBlocklisted(first);
            // the heir is now the only passkey, so removing it is refused as the last one
            bool secondIsTheLast = fixture.Inventory.Remove(Handle, secondId) == PasskeyRemoval.LastCredential;

            // From an RSA-slot passkey key set: the RSA proof anchors it too and refuses the
            // assertion first; the passkey proof still proves it.
            string thirdId = fixture.Add(third);
            bool secondNowNeedsHandover = secondIsTheLast && fixture.Inventory.Remove(Handle, secondId) == PasskeyRemoval.KeySetHandoverRequired;
            KeySetHandoverStart again = fixture.Handover.Begin(Handle, secondId, thirdId, null);
            KeySetHandoverResult againDone = fixture.Handover.Complete(Handle, again.HandoverId, HandoverFixture.AssertionJson(second, again));
            bool movedToThird = fixture.KeySetIs(third);
            bool secondBlocklisted = fixture.KeyIsBlocklisted(second);

            return new HandoverOutcome(plainRemoval, heirRemoval, heirStillThere, start, challengeIsTheRotation, allowsOnlyTheOldPasskey, done,
                movedToSecond, firstGone, secondMarked, firstBlocklisted, secondNowNeedsHandover, againDone, movedToThird, secondBlocklisted,
                fixture.Inventory.List(Handle).Count);
        })
        .TheTest
        .ShouldPass<HandoverOutcome>((because, outcome) =>
        {
            because.ItsTrue("removing the key-set passkey asks for a handover", outcome.PlainRemoval == PasskeyRemoval.KeySetHandoverRequired);
            because.ItsTrue("a passkey that does not hold the key set is removed plainly", outcome.HeirRemoval == PasskeyRemoval.Removed && !outcome.HeirStillThere);
            because.ItsTrue("the handover begins with the session's passkey as heir", outcome.Start.Success && outcome.Start.HandoverId is not null);
            because.ItsTrue("the challenge is SHA-256 of the rotation payload", outcome.ChallengeIsTheRotation);
            because.ItsTrue("the options allow only the passkey being removed", outcome.AllowsOnlyTheOldPasskey);
            because.ItsTrue("the handover completes", outcome.Done.Success);
            because.ItsTrue("the key set is now the heir's key", outcome.MovedToSecond);
            because.ItsTrue("the old passkey is removed", outcome.FirstGone);
            because.ItsTrue("the heir is marked as the key set", outcome.SecondMarked);
            because.ItsTrue("the old key is blocklisted under any handle", outcome.FirstBlocklisted);
            because.ItsTrue("the heir is the last passkey alone, and needs a handover to be removed once another is added", outcome.SecondNowNeedsHandover);
            because.ItsTrue("an RSA-slot passkey key set hands over too", outcome.AgainDone.Success && outcome.MovedToThird && outcome.SecondBlocklisted);
            because.ItsTrue("one passkey is left", outcome.Remaining == 1);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseToBeginWithoutAKeySetPasskeyAndAnHeir()
    {
        When.A<HandoverFixture>("refuses handovers that can't begin", new HandoverFixture(nameof(RefuseToBeginWithoutAKeySetPasskeyAndAnHeir)), (fixture) =>
        {
            SyntheticAuthenticator first = new SyntheticAuthenticator();
            SyntheticAuthenticator second = new SyntheticAuthenticator();
            SyntheticAuthenticator bobs = new SyntheticAuthenticator();
            string firstId = fixture.SignUp(first);
            string bobsId = fixture.SignUp(bobs, "bob");
            KeySetHandoverRefusal last = fixture.Handover.Begin(Handle, firstId, null, firstId).Refusal;
            PasskeyRemoval lastRemoval = fixture.Inventory.Remove(Handle, firstId);
            string secondId = fixture.Add(second);

            KeySetHandoverRefusal unknown = fixture.Handover.Begin(Handle, "no-such-credential", secondId, null).Refusal;
            KeySetHandoverRefusal someoneElses = fixture.Handover.Begin(Handle, bobsId, secondId, null).Refusal;
            KeySetHandoverRefusal notKeySet = fixture.Handover.Begin(Handle, secondId, firstId, null).Refusal;
            KeySetHandoverRefusal heirIsTheOldOne = fixture.Handover.Begin(Handle, firstId, firstId, null).Refusal;
            KeySetHandoverRefusal defaultHeirIsTheOldOne = fixture.Handover.Begin(Handle, firstId, null, firstId).Refusal;
            KeySetHandoverRefusal noHeir = fixture.Handover.Begin(Handle, firstId, null, null).Refusal;
            KeySetHandoverRefusal heirIsBobs = fixture.Handover.Begin(Handle, firstId, bobsId, null).Refusal;

            HandoverFixture withoutProof = new HandoverFixture(nameof(RefuseToBeginWithoutAKeySetPasskeyAndAnHeir) + "-noproof", trustPasskeyProof: false);
            SyntheticAuthenticator a = new SyntheticAuthenticator();
            SyntheticAuthenticator b = new SyntheticAuthenticator();
            string aId = withoutProof.SignUp(a);
            string bId = withoutProof.Add(b);
            KeySetHandoverRefusal unavailable = withoutProof.Handover.Begin(Handle, aId, bId, null).Refusal;
            bool unavailableReported = !withoutProof.Handover.IsAvailable && fixture.Handover.IsAvailable;
            // Without a passkey proof, removal is exactly as before #20: allowed, key set kept.
            PasskeyRemoval optionA = withoutProof.Inventory.Remove(Handle, aId);
            bool keySetKept = withoutProof.KeySetIs(a);

            return new BeginRefusalOutcome(last, lastRemoval, unknown, someoneElses, notKeySet, heirIsTheOldOne, defaultHeirIsTheOldOne, noHeir, heirIsBobs,
                unavailable, unavailableReported, optionA, keySetKept, fixture.KeySetIs(first));
        })
        .TheTest
        .ShouldPass<BeginRefusalOutcome>((because, outcome) =>
        {
            because.ItsTrue("the last passkey can't hand over or be removed", outcome.Last == KeySetHandoverRefusal.LastCredential && outcome.LastRemoval == PasskeyRemoval.LastCredential);
            because.ItsTrue("an unknown passkey is not found", outcome.Unknown == KeySetHandoverRefusal.NotFound);
            because.ItsTrue("another person's passkey is not found", outcome.SomeoneElses == KeySetHandoverRefusal.NotFound);
            because.ItsTrue("a passkey that does not hold the key set is refused", outcome.NotKeySet == KeySetHandoverRefusal.NotKeySet);
            because.ItsTrue("the heir can't be the passkey being removed", outcome.HeirIsTheOldOne == KeySetHandoverRefusal.InvalidHeir && outcome.DefaultHeirIsTheOldOne == KeySetHandoverRefusal.InvalidHeir);
            because.ItsTrue("a handover needs an heir", outcome.NoHeir == KeySetHandoverRefusal.InvalidHeir);
            because.ItsTrue("the heir must be the same person's", outcome.HeirIsBobs == KeySetHandoverRefusal.InvalidHeir);
            because.ItsTrue("a host without the passkey proof can't hand over", outcome.Unavailable == KeySetHandoverRefusal.RotationUnavailable && outcome.UnavailableReported);
            because.ItsTrue("and removes the key-set passkey as before, keeping the key set", outcome.OptionA == PasskeyRemoval.Removed && outcome.KeySetKept);
            because.ItsTrue("no refusal moved the key set", outcome.KeySetUnchanged);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseACompletionThatDoesNotProveTheRotation()
    {
        When.A<HandoverFixture>("refuses completions and leaves the passkey and the key set as they were", new HandoverFixture(nameof(RefuseACompletionThatDoesNotProveTheRotation)), (fixture) =>
        {
            SyntheticAuthenticator first = new SyntheticAuthenticator();
            SyntheticAuthenticator second = new SyntheticAuthenticator();
            SyntheticAuthenticator third = new SyntheticAuthenticator();
            string firstId = fixture.SignUp(first);
            string secondId = fixture.Add(second);
            string thirdId = fixture.Add(third);

            List<KeySetHandoverRefusal> refusals = new List<KeySetHandoverRefusal>();
            KeySetHandoverStart start = fixture.Handover.Begin(Handle, firstId, secondId, null);
            refusals.Add(fixture.Handover.Complete("bob", start.HandoverId, HandoverFixture.AssertionJson(first, start)).Refusal);
            refusals.Add(fixture.Handover.Complete(Handle, start.HandoverId, HandoverFixture.AssertionJson(first, start)).Refusal);

            start = fixture.Handover.Begin(Handle, firstId, secondId, null);
            refusals.Add(fixture.Handover.Complete(Handle, start.HandoverId, HandoverFixture.AssertionJson(second, start)).Refusal);
            start = fixture.Handover.Begin(Handle, firstId, secondId, null);
            refusals.Add(fixture.Handover.Complete(Handle, start.HandoverId, HandoverFixture.AssertionJson(first, SyntheticAuthenticator.RandomBytes(32))).Refusal);
            // An assertion over the rotation to another heir does not prove the rotation to this one.
            KeySetHandoverStart toThird = fixture.Handover.Begin(Handle, firstId, thirdId, null);
            start = fixture.Handover.Begin(Handle, firstId, secondId, null);
            refusals.Add(fixture.Handover.Complete(Handle, start.HandoverId, HandoverFixture.AssertionJson(first, toThird)).Refusal);
            start = fixture.Handover.Begin(Handle, firstId, secondId, null);
            refusals.Add(fixture.Handover.Complete(Handle, start.HandoverId, Encoding.UTF8.GetBytes("{not json")).Refusal);
            start = fixture.Handover.Begin(Handle, firstId, secondId, null);
            refusals.Add(fixture.Handover.Complete(Handle, start.HandoverId, Array.Empty<byte>()).Refusal);
            refusals.Add(fixture.Handover.Complete(Handle, "no-such-handover", HandoverFixture.AssertionJson(first, start)).Refusal);
            refusals.Add(fixture.Handover.Complete(Handle, null, HandoverFixture.AssertionJson(first, start)).Refusal);

            bool keySetUnchanged = fixture.KeySetIs(first);
            bool allStillThere = fixture.Inventory.List(Handle).Count == 3;

            // The heir is removed after begin.
            start = fixture.Handover.Begin(Handle, firstId, thirdId, null);
            fixture.Inventory.Remove(Handle, thirdId);
            KeySetHandoverRefusal heirGone = fixture.Handover.Complete(Handle, start.HandoverId, HandoverFixture.AssertionJson(first, start)).Refusal;

            // The key set moves after begin: a second handover completes first.
            KeySetHandoverStart stale = fixture.Handover.Begin(Handle, firstId, secondId, null);
            KeySetHandoverStart winner = fixture.Handover.Begin(Handle, firstId, secondId, null);
            bool winnerDone = fixture.Handover.Complete(Handle, winner.HandoverId, HandoverFixture.AssertionJson(first, winner)).Success;
            KeySetHandoverRefusal keySetChanged = fixture.Handover.Complete(Handle, stale.HandoverId, HandoverFixture.AssertionJson(first, stale)).Refusal;

            return new CompleteRefusalOutcome(refusals, keySetUnchanged, allStillThere, heirGone, winnerDone, keySetChanged, fixture.KeySetIs(second));
        })
        .TheTest
        .ShouldPass<CompleteRefusalOutcome>((because, outcome) =>
        {
            because.ItsTrue("another person can't complete it", outcome.Refusals[0] == KeySetHandoverRefusal.HandoverExpired);
            because.ItsTrue("an attempt by the wrong person still uses the id up", outcome.Refusals[1] == KeySetHandoverRefusal.HandoverExpired);
            because.ItsTrue("an assertion by the heir is refused", outcome.Refusals[2] == KeySetHandoverRefusal.ProofRefused);
            because.ItsTrue("an assertion over another challenge is refused", outcome.Refusals[3] == KeySetHandoverRefusal.ProofRefused);
            because.ItsTrue("an assertion over the rotation to another heir is refused", outcome.Refusals[4] == KeySetHandoverRefusal.ProofRefused);
            because.ItsTrue("a proof that is not JSON is refused", outcome.Refusals[5] == KeySetHandoverRefusal.ProofRefused);
            because.ItsTrue("an empty proof is refused", outcome.Refusals[6] == KeySetHandoverRefusal.ProofRefused);
            because.ItsTrue("an unknown or missing handover id is refused", outcome.Refusals[7] == KeySetHandoverRefusal.HandoverExpired && outcome.Refusals[8] == KeySetHandoverRefusal.HandoverExpired);
            because.ItsTrue("no refusal moved the key set", outcome.KeySetUnchanged);
            because.ItsTrue("no refusal removed a passkey", outcome.AllStillThere);
            because.ItsTrue("an heir removed since begin is refused", outcome.HeirGone == KeySetHandoverRefusal.HeirGone);
            because.ItsTrue("a key set that moved since begin is refused", outcome.WinnerDone && outcome.KeySetChanged == KeySetHandoverRefusal.KeySetChanged && outcome.MovedOnce);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RemoveTheKeySetPasskeyKeepingTheKeySetWhenAsked()
    {
        When.A<HandoverFixture>("removes a lost key-set passkey without a handover", new HandoverFixture(nameof(RemoveTheKeySetPasskeyKeepingTheKeySetWhenAsked)), (fixture) =>
        {
            SyntheticAuthenticator first = new SyntheticAuthenticator();
            SyntheticAuthenticator second = new SyntheticAuthenticator();
            string firstId = fixture.SignUp(first);
            string secondId = fixture.Add(second);
            PasskeyRemoval removal = fixture.Inventory.Remove(Handle, firstId, keepKeySet: true);
            bool gone = fixture.Credentials.FindByCredentialId(firstId) is null;
            bool keySetKept = fixture.KeySetIs(first);
            // With the key-set passkey gone, the survivor holds nothing: a plain removal, refused only as the last one.
            KeySetHandoverRefusal noHandover = fixture.Handover.Begin(Handle, secondId, null, null).Refusal;
            PasskeyRemoval last = fixture.Inventory.Remove(Handle, secondId, keepKeySet: true);
            return new KeepOutcome(removal, gone, keySetKept, noHandover, last);
        })
        .TheTest
        .ShouldPass<KeepOutcome>((because, outcome) =>
        {
            because.ItsTrue("the key-set passkey is removed", outcome.Removal == PasskeyRemoval.Removed && outcome.Gone);
            because.ItsTrue("the key set stays registered", outcome.KeySetKept);
            because.ItsTrue("the survivor does not hold the key set", outcome.NoHandover == KeySetHandoverRefusal.LastCredential || outcome.NoHandover == KeySetHandoverRefusal.NotKeySet);
            because.ItsTrue("keeping the key set never removes the last passkey", outcome.Last == PasskeyRemoval.LastCredential);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void AnchorAndProveOnlyForThePasskeyThatHoldsTheKeySet()
    {
        When.A<HandoverFixture>("checks the passkey rotation proof on its own", new HandoverFixture(nameof(AnchorAndProveOnlyForThePasskeyThatHoldsTheKeySet)), (fixture) =>
        {
            SyntheticAuthenticator first = new SyntheticAuthenticator();
            SyntheticAuthenticator second = new SyntheticAuthenticator();
            SyntheticAuthenticator bobs = new SyntheticAuthenticator();
            string firstId = fixture.SignUp(first);
            string secondId = fixture.Add(second);
            fixture.SignUp(bobs, "bob");
            PublicKeySetData current = fixture.Registrar.Resolve(Handle)!;
            PublicKeySetData proposed = PasskeyKeySet.From(fixture.Credentials.FindByCredentialId(secondId)!);
            PasskeyKeySetRotationProof proof = fixture.Proof;

            bool anchorsCurrent = proof.Anchors(current);
            bool anchorsProposedHeir = proof.Anchors(proposed);
            PublicKeySetData twoKeys = new PublicKeySetData { KeySetHandle = Handle, PublicEccKey = first.PublicKeyPem, PublicRsaKey = new SyntheticAuthenticator(CoseAlgorithm.RS256).PublicKeyPem };
            bool anchorsTwoKeys = proof.Anchors(twoKeys);
            bool anchorsUnderAnotherHandle = proof.Anchors(PasskeyKeySet.From("bob", CoseAlgorithm.ES256, first.PublicKeyPem));
            bool anchorsAStranger = proof.Anchors(PasskeyKeySet.From(Handle, CoseAlgorithm.ES256, new SyntheticAuthenticator().PublicKeyPem));
            bool anchorsEmpty = proof.Anchors(new PublicKeySetData { KeySetHandle = Handle });

            byte[] challenge = PasskeyKeySetRotationProof.Challenge(current, proposed);
            bool valid = proof.Verify(current, proposed, HandoverFixture.AssertionJson(first, challenge)).Success;
            // The same assertion again: its counter does not advance.
            byte[] replayed = Encoding.UTF8.GetBytes(PasskeyJson.Serialize(first.Assert(challenge)));
            bool replayRefused = !proof.Verify(current, proposed, replayed).Success;
            bool heirRefused = !proof.Verify(current, proposed, HandoverFixture.AssertionJson(second, challenge)).Success;
            bool bobRefused = !proof.Verify(current, proposed, HandoverFixture.AssertionJson(bobs, challenge)).Success;
            bool untaggedRefused = !proof.Verify(current, proposed, HandoverFixture.AssertionJson(first, System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(KeySetRotationPayload.Compose(KeySetRotationPayload.AnchorSha256(current), proposed))))).Success;
            // Signed over the other handle's own challenge, so only the handle check can refuse it.
            PublicKeySetData toBob = PasskeyKeySet.From("bob", CoseAlgorithm.ES256, second.PublicKeyPem);
            bool otherHandleRefused = !proof.Verify(current, toBob, HandoverFixture.AssertionJson(first, PasskeyKeySetRotationProof.Challenge(current, toBob))).Success;
            // Signed by the key-set passkey but naming another passkey: only the id check can refuse it.
            first.SignCount++;
            bool otherIdRefused = !proof.Verify(current, proposed, Encoding.UTF8.GetBytes(PasskeyJson.Serialize(first.Assert(challenge, id: secondId)))).Success;
            ISignatureVerification garbage = proof.Verify(current, proposed, Encoding.UTF8.GetBytes("{\"id\":\"" + firstId + "\",\"response\":{\"signature\":\"c2VjcmV0LWJ5dGVz\""));
            bool garbageMessageClean = !garbage.Success && !garbage.Message.Contains("c2VjcmV0", StringComparison.Ordinal) && !garbage.Message.Contains(firstId, StringComparison.Ordinal);

            PasskeyCredentialData pendingHeir = fixture.Credentials.FindByCredentialId(secondId)!;
            pendingHeir.Pending = true;
            bool anchorsPending = proof.Anchors(proposed);
            pendingHeir.Pending = false;

            return new ProofOutcome(anchorsCurrent, anchorsProposedHeir, anchorsTwoKeys, anchorsUnderAnotherHandle, anchorsAStranger, anchorsEmpty, anchorsPending,
                valid, replayRefused, heirRefused, bobRefused, untaggedRefused, otherHandleRefused, otherIdRefused, garbageMessageClean);
        })
        .TheTest
        .ShouldPass<ProofOutcome>((because, outcome) =>
        {
            because.ItsTrue("it anchors the key set its passkey holds", outcome.AnchorsCurrent);
            because.ItsTrue("it anchors a proposed set exactly one accepted passkey of the handle holds", outcome.AnchorsProposedHeir);
            because.ItsTrue("it never anchors a key set with two keys", !outcome.AnchorsTwoKeys);
            because.ItsTrue("it never anchors a passkey's key under another handle", !outcome.AnchorsUnderAnotherHandle);
            because.ItsTrue("it never anchors a key no passkey of the handle holds", !outcome.AnchorsAStranger && !outcome.AnchorsEmpty);
            because.ItsTrue("it never anchors a pending passkey's key", !outcome.AnchorsPending);
            because.ItsTrue("the key-set passkey's assertion over the rotation verifies", outcome.Valid);
            because.ItsTrue("a replayed assertion is refused", outcome.ReplayRefused);
            because.ItsTrue("another passkey of the person can't prove it", outcome.HeirRefused);
            because.ItsTrue("another person's passkey can't prove it", outcome.BobRefused);
            because.ItsTrue("an assertion over the untagged payload is refused", outcome.UntaggedRefused);
            because.ItsTrue("a rotation onto another handle is refused", outcome.OtherHandleRefused);
            because.ItsTrue("an assertion naming another passkey is refused", outcome.OtherIdRefused);
            because.ItsTrue("a failure message carries no proof bytes or credential id", outcome.GarbageMessageClean);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private sealed record HandoverOutcome(PasskeyRemoval PlainRemoval, PasskeyRemoval HeirRemoval, bool HeirStillThere, KeySetHandoverStart Start, bool ChallengeIsTheRotation,
        bool AllowsOnlyTheOldPasskey, KeySetHandoverResult Done, bool MovedToSecond, bool FirstGone, bool SecondMarked, bool FirstBlocklisted, bool SecondNowNeedsHandover,
        KeySetHandoverResult AgainDone, bool MovedToThird, bool SecondBlocklisted, int Remaining);

    private sealed record BeginRefusalOutcome(KeySetHandoverRefusal Last, PasskeyRemoval LastRemoval, KeySetHandoverRefusal Unknown, KeySetHandoverRefusal SomeoneElses,
        KeySetHandoverRefusal NotKeySet, KeySetHandoverRefusal HeirIsTheOldOne, KeySetHandoverRefusal DefaultHeirIsTheOldOne, KeySetHandoverRefusal NoHeir,
        KeySetHandoverRefusal HeirIsBobs, KeySetHandoverRefusal Unavailable, bool UnavailableReported, PasskeyRemoval OptionA, bool KeySetKept, bool KeySetUnchanged);

    private sealed record CompleteRefusalOutcome(List<KeySetHandoverRefusal> Refusals, bool KeySetUnchanged, bool AllStillThere, KeySetHandoverRefusal HeirGone,
        bool WinnerDone, KeySetHandoverRefusal KeySetChanged, bool MovedOnce);

    private sealed record KeepOutcome(PasskeyRemoval Removal, bool Gone, bool KeySetKept, KeySetHandoverRefusal NoHandover, PasskeyRemoval Last);

    private sealed record ProofOutcome(bool AnchorsCurrent, bool AnchorsProposedHeir, bool AnchorsTwoKeys, bool AnchorsUnderAnotherHandle, bool AnchorsAStranger,
        bool AnchorsEmpty, bool AnchorsPending, bool Valid, bool ReplayRefused, bool HeirRefused, bool BobRefused, bool UntaggedRefused, bool OtherHandleRefused,
        bool OtherIdRefused, bool GarbageMessageClean);
}
