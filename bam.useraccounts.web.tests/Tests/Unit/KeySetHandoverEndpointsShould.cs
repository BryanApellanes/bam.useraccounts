using System.Net;
using Bam.DependencyInjection;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Profile;
using Bam.Protocol.Profile;
using Bam.Test;
using Bam.UserAccounts.Passkeys;
using Bam.UserAccounts.Tests.TestClasses;
using Bam.UserAccounts.Web.Tests.TestClasses;

namespace Bam.UserAccounts.Web.Tests.Unit;

/// <summary>
/// The key-set handover endpoints (bam.useraccounts#20) over a real registrar that trusts the
/// passkey rotation proof: <c>DELETE</c> asks for a handover, <c>handover/begin</c> and
/// <c>handover/complete</c> move the key set and remove the old passkey, and <c>?keySet=keep</c>
/// removes it without the move.
/// </summary>
[UnitTestMenu("KeySetHandoverEndpoints Should", Selector = "kshe")]
public class KeySetHandoverEndpointsShould : UnitTestMenuContainer
{
    public KeySetHandoverEndpointsShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    [UnitTest]
    public void HandTheKeySetOverAndRemoveThePasskey()
    {
        When.A<AccountHost>("signs up, adds a passkey, then removes the one that holds the key set",
            () => HostWithRotation(nameof(HandTheKeySetOverAndRemoveThePasskey)),
            (host) =>
            {
                try
                {
                    SyntheticAuthenticator first = new SyntheticAuthenticator();
                    SyntheticAuthenticator second = new SyntheticAuthenticator();
                    string firstId = first.CredentialIdBase64Url;
                    string secondId = second.CredentialIdBase64Url;
                    string firstSession = host.SignUp("alice", "Alice Example", first).SessionCookie!;
                    Add(host, second, firstSession);
                    string handle = host.Fixture.Passkeys.Credentials.FindByCredentialId(firstId)!.PersonHandle;
                    PasskeyListResponse listed = host.Get("/account/passkeys", firstSession).As<PasskeyListResponse>();
                    bool firstListedAsKeySet = listed.Passkeys.Any(passkey => passkey.Id == firstId && passkey.RegisteredKeySet);
                    string page = host.Get("/account", firstSession).Body;
                    bool pageSaysTheKeyMoves = page.Contains("account-keyset badge", StringComparison.Ordinal) && page.Contains("account-keyset-note text-muted small\">Removing it moves", StringComparison.Ordinal)
                        && !page.Contains("account-keyset-note text-muted small\">Removing it doesn", StringComparison.Ordinal);

                    AccountReply plainDelete = host.Delete("/account/passkeys/" + firstId, firstSession);
                    AccountReply ownHeir = host.Post(HandoverPath(firstId, "begin"), new HandoverBeginRequest(), firstSession);
                    AccountReply noHeader = host.Post(HandoverPath(firstId, "begin"), new HandoverBeginRequest { Heir = secondId }, firstSession, withHeader: false);
                    AccountReply begun = host.Post(HandoverPath(firstId, "begin"), new HandoverBeginRequest { Heir = secondId }, firstSession);
                    HandoverBeginResponse start = begun.As<HandoverBeginResponse>();
                    bool allowsOnlyFirst = start.Options.AllowCredentials.Count == 1 && start.Options.AllowCredentials[0].Id == firstId;

                    AccountReply completed = host.Post(HandoverPath(firstId, "complete"), Proof(first, start), firstSession);
                    bool firstGone = host.Fixture.Passkeys.Credentials.FindByCredentialId(firstId) is null;
                    bool keySetIsSecond = KeySetIs(host, handle, second);
                    AccountReply firstSessionAfter = host.Get("/account/passkeys", firstSession);

                    return new HandoverOutcome(firstListedAsKeySet, pageSaysTheKeyMoves, plainDelete, ownHeir, noHeader, begun, allowsOnlyFirst, completed, firstGone, keySetIsSecond, firstSessionAfter);
                }
                finally
                {
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<HandoverOutcome>((because, outcome) =>
            {
                because.ItsTrue("the list marks the passkey that holds the key set", outcome.FirstListedAsKeySet);
                because.ItsTrue("the manage page marks it and says removing it moves the key first", outcome.PageSaysTheKeyMoves);
                because.ItsTrue($"a plain DELETE of it asks for a handover ({outcome.PlainDelete.Status}: {outcome.PlainDelete.Body})", outcome.PlainDelete.Status == HttpStatusCode.Conflict && outcome.PlainDelete.ErrorCode == AccountErrorCodes.KeySetHandoverRequired);
                because.ItsTrue($"the session's own passkey can't be its own heir ({outcome.OwnHeir.Status})", outcome.OwnHeir.Status == HttpStatusCode.BadRequest && outcome.OwnHeir.ErrorCode == AccountErrorCodes.InvalidHeir);
                because.ItsTrue($"begin without the request header is refused ({outcome.NoHeader.Status})", outcome.NoHeader.Status == HttpStatusCode.Forbidden);
                because.ItsTrue($"begin with another passkey as heir succeeds ({outcome.Begun.Status}: {outcome.Begun.Body})", outcome.Begun.Status == HttpStatusCode.OK);
                because.ItsTrue("and asks only for the passkey being removed", outcome.AllowsOnlyFirst);
                because.ItsTrue($"complete removes it and ends the session that used it ({outcome.Completed.Status}: {outcome.Completed.Body})", outcome.Completed.Status == HttpStatusCode.OK && outcome.Completed.As<SignedOutResponse>().SignedOut && outcome.Completed.ClearsSession);
                because.ItsTrue("the old passkey is gone", outcome.FirstGone);
                because.ItsTrue("the key set is now the heir's key", outcome.KeySetIsSecond);
                because.ItsTrue($"the old passkey's session no longer opens the account ({outcome.FirstSessionAfter.Status})", outcome.FirstSessionAfter.Status == HttpStatusCode.Unauthorized);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseAHandoverTheOldPasskeyDidNotProve()
    {
        When.A<AccountHost>("begins a handover and completes it with the wrong passkey",
            () => HostWithRotation(nameof(RefuseAHandoverTheOldPasskeyDidNotProve)),
            (host) =>
            {
                try
                {
                    SyntheticAuthenticator first = new SyntheticAuthenticator();
                    SyntheticAuthenticator second = new SyntheticAuthenticator();
                    string firstId = first.CredentialIdBase64Url;
                    string session = host.SignUp("alice", "Alice Example", first).SessionCookie!;
                    Add(host, second, session);
                    string secondSession = host.SignIn(second, "alice").SessionCookie!;
                    string handle = host.Fixture.Passkeys.Credentials.FindByCredentialId(firstId)!.PersonHandle;

                    // From the second passkey's session the default heir is the second passkey.
                    HandoverBeginResponse start = host.Post(HandoverPath(firstId, "begin"), new HandoverBeginRequest(), secondSession).As<HandoverBeginResponse>();
                    AccountReply wrongPasskey = host.Post(HandoverPath(firstId, "complete"), Proof(second, start), secondSession);
                    // a handover works once: the refused attempt used it up, so the right passkey can't reuse it
                    AccountReply retried = host.Post(HandoverPath(firstId, "complete"), Proof(first, start), secondSession);
                    AccountReply unknownId = host.Post(HandoverPath(firstId, "complete"), new HandoverCompleteRequest { HandoverId = "not-a-handover", Credential = first.Assert(new byte[32]) }, secondSession);
                    AccountReply noCredential = host.Post(HandoverPath(firstId, "complete"), new HandoverCompleteRequest { HandoverId = start.HandoverId }, secondSession);
                    bool firstKept = host.Fixture.Passkeys.Credentials.FindByCredentialId(firstId) is not null;
                    bool keySetKept = KeySetIs(host, handle, first);

                    AccountReply notKeySet = host.Post(HandoverPath(second.CredentialIdBase64Url, "begin"), new HandoverBeginRequest { Heir = firstId }, secondSession);
                    AccountReply kept = host.Delete("/account/passkeys/" + firstId + "?keySet=keep", secondSession);
                    bool removedWithoutMove = host.Fixture.Passkeys.Credentials.FindByCredentialId(firstId) is null && KeySetIs(host, handle, first);
                    return new RefusalOutcome(wrongPasskey, retried, unknownId, noCredential, firstKept, keySetKept, notKeySet, kept, removedWithoutMove);
                }
                finally
                {
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<RefusalOutcome>((because, outcome) =>
            {
                because.ItsTrue($"an assertion by another passkey is refused ({outcome.WrongPasskey.Status}: {outcome.WrongPasskey.Body})", outcome.WrongPasskey.Status == HttpStatusCode.BadRequest && outcome.WrongPasskey.ErrorCode == AccountErrorCodes.ProofRefused);
                because.ItsTrue($"a handover works once, even after a refused attempt ({outcome.Retried.Status}: {outcome.Retried.Body})", outcome.Retried.Status == HttpStatusCode.BadRequest && outcome.Retried.ErrorCode == AccountErrorCodes.HandoverExpired);
                because.ItsTrue($"an unknown handover is refused ({outcome.UnknownId.Status})", outcome.UnknownId.Status == HttpStatusCode.BadRequest && outcome.UnknownId.ErrorCode == AccountErrorCodes.HandoverExpired);
                because.ItsTrue($"a complete without an assertion is a bad request ({outcome.NoCredential.Status})", outcome.NoCredential.Status == HttpStatusCode.BadRequest && outcome.NoCredential.ErrorCode == AccountErrorCodes.BadRequest);
                because.ItsTrue("the refused handover leaves the passkey", outcome.FirstKept);
                because.ItsTrue("and the key set where they were", outcome.KeySetKept);
                because.ItsTrue($"a passkey that doesn't hold the key set has nothing to hand over ({outcome.NotKeySet.Status})", outcome.NotKeySet.Status == HttpStatusCode.BadRequest && outcome.NotKeySet.ErrorCode == AccountErrorCodes.NotKeySet);
                because.ItsTrue($"?keySet=keep removes it ({outcome.Kept.Status}: {outcome.Kept.Body})", outcome.Kept.Status == HttpStatusCode.OK && !outcome.Kept.As<SignedOutResponse>().SignedOut);
                because.ItsTrue("without moving the key set", outcome.RemovedWithoutMove);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void RemoveAsBeforeWhereTheKeySetCannotMove()
    {
        When.A<AccountHost>("has no passkey rotation proof",
            () => new AccountHost(),
            (host) =>
            {
                try
                {
                    SyntheticAuthenticator first = new SyntheticAuthenticator();
                    SyntheticAuthenticator second = new SyntheticAuthenticator();
                    string session = host.SignUp("alice", "Alice Example", first).SessionCookie!;
                    Add(host, second, session);
                    string page = host.Get("/account", session).Body;
                    bool pageSaysTheKeyStays = page.Contains("account-keyset badge", StringComparison.Ordinal) && page.Contains("account-keyset-note text-muted small\">Removing it doesn", StringComparison.Ordinal)
                        && !page.Contains("account-keyset-note text-muted small\">Removing it moves", StringComparison.Ordinal);
                    AccountReply begin = host.Post(HandoverPath(first.CredentialIdBase64Url, "begin"), new HandoverBeginRequest { Heir = second.CredentialIdBase64Url }, session);
                    AccountReply removed = host.Delete("/account/passkeys/" + first.CredentialIdBase64Url, session);
                    return new UnavailableOutcome(pageSaysTheKeyStays, begin, removed);
                }
                finally
                {
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<UnavailableOutcome>((because, outcome) =>
            {
                because.ItsTrue("the manage page marks the key-set passkey and says removing it leaves the key", outcome.PageSaysTheKeyStays);
                because.ItsTrue($"begin says the key set can't move on this host ({outcome.Begin.Status}: {outcome.Begin.Body})", outcome.Begin.Status == HttpStatusCode.Conflict && outcome.Begin.ErrorCode == AccountErrorCodes.RotationUnavailable);
                because.ItsTrue($"a plain DELETE removes the key-set passkey, as before #20 ({outcome.Removed.Status})", outcome.Removed.Status == HttpStatusCode.OK);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    private static AccountHost HostWithRotation(string testName)
    {
        return new AccountHost(bind: registry =>
        {
            // What a host's profile repository registration binds since bam.protocol#72: the default
            // proofs and a registrar over them. AddPasskeys then adds the passkey proof to the same list.
            KeySetRotationProofs proofs = KeySetRotationProofChain.DefaultProofs();
            PublicKeySetRegistrar registrar = new PublicKeySetRegistrar(HandoverFixture.CreateObjectDataRepository("web-" + testName), new KeySetRotationProofChain(proofs));
            registry.For<KeySetRotationProofs>().UseSingleton(proofs);
            registry.For<IPublicKeySetRegistrar>().UseSingleton(registrar);
        });
    }

    private static string HandoverPath(string credentialId, string step)
    {
        return "/account/passkeys/" + credentialId + "/handover/" + step;
    }

    private static void Add(AccountHost host, SyntheticAuthenticator authenticator, string session)
    {
        AccountReply begun = host.Post("/account/passkey/additional/begin", new AssertionBeginRequest(), session);
        byte[] challenge = Base64UrlEncoder.Default.Decode(begun.As<CreationOptionsResponse>().Options.Challenge);
        AccountReply added = host.Post("/account/passkey/additional/complete", new AdditionalCompleteRequest { Credential = authenticator.Register(challenge) }, session);
        if (added.Status != HttpStatusCode.OK)
        {
            throw new InvalidOperationException("adding a passkey failed: " + added.Body);
        }
    }

    private static HandoverCompleteRequest Proof(SyntheticAuthenticator authenticator, HandoverBeginResponse start)
    {
        authenticator.SignCount++;
        return new HandoverCompleteRequest { HandoverId = start.HandoverId, Credential = authenticator.Assert(Base64UrlEncoder.Default.Decode(start.Options.Challenge)) };
    }

    private static bool KeySetIs(AccountHost host, string handle, SyntheticAuthenticator authenticator)
    {
        PublicKeySetData? keySet = host.Registry.Get<IPublicKeySetRegistrar>().Resolve(handle);
        return PasskeyKeySet.IsHeldBy(keySet, new PasskeyCredentialData { PersonHandle = handle, PublicKeyPem = authenticator.PublicKeyPem });
    }

    private sealed record HandoverOutcome(bool FirstListedAsKeySet, bool PageSaysTheKeyMoves, AccountReply PlainDelete, AccountReply OwnHeir, AccountReply NoHeader, AccountReply Begun, bool AllowsOnlyFirst,
        AccountReply Completed, bool FirstGone, bool KeySetIsSecond, AccountReply FirstSessionAfter);

    private sealed record RefusalOutcome(AccountReply WrongPasskey, AccountReply Retried, AccountReply UnknownId, AccountReply NoCredential, bool FirstKept, bool KeySetKept, AccountReply NotKeySet, AccountReply Kept, bool RemovedWithoutMove);

    private sealed record UnavailableOutcome(bool PageSaysTheKeyStays, AccountReply Begin, AccountReply Removed);
}
