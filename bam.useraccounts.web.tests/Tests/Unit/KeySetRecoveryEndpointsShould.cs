using System.Net;
using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Profile;
using Bam.Protocol.Profile;
using Bam.Test;
using Bam.UserAccounts.Passkeys;
using Bam.UserAccounts.Tests.TestClasses;
using Bam.UserAccounts.Web.Tests.TestClasses;

namespace Bam.UserAccounts.Web.Tests.Unit;

/// <summary>
/// The lost-device recovery endpoints (bam.protocol#85, bam.useraccounts#20 part 2) over a real
/// registrar that trusts the passkey and recovery proofs, with a clock the test moves:
/// <c>keyset/recovery/begin</c>, <c>complete</c> and <c>{id}/cancel</c>, the list's
/// <c>pendingRecovery</c> and <c>keySetRecoverable</c>, and the manage page's banner and action.
/// </summary>
[UnitTestMenu("KeySetRecoveryEndpoints Should", Selector = "ksre")]
public class KeySetRecoveryEndpointsShould : UnitTestMenuContainer
{
    private const string Begin = "/account/keyset/recovery/begin";
    private const string Complete = "/account/keyset/recovery/complete";

    public KeySetRecoveryEndpointsShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    [UnitTest]
    public void RecoverTheKeySetAfterTheDelay()
    {
        ManualClock clock = new ManualClock();
        When.A<AccountHost>("removes a lost key-set passkey through recovery and lets the delay pass",
            () => HostWithRecovery(nameof(RecoverTheKeySetAfterTheDelay), clock),
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
                    string secondSession = host.SignIn(second, "alice").SessionCookie!;
                    string handle = host.Fixture.Passkeys.Credentials.FindByCredentialId(firstId)!.PersonHandle;
                    bool recoverableWhileHeld = host.Get("/account/passkeys", secondSession).As<PasskeyListResponse>().KeySetRecoverable;

                    AccountReply tooNew = host.Post(Begin, new RecoveryBeginRequest { Removes = firstId }, secondSession);
                    clock.Advance(TimeSpan.FromDays(8));
                    AccountReply begun = host.Post(Begin, new RecoveryBeginRequest { Removes = firstId }, secondSession);
                    RecoveryBeginResponse start = begun.As<RecoveryBeginResponse>();
                    bool allowsOnlySecond = start.Options.AllowCredentials.Count == 1 && start.Options.AllowCredentials[0].Id == secondId && start.Options.UserVerification == "required";
                    AccountReply completed = host.Post(Complete, Proof(second, start), secondSession);
                    AccountReply firstSessionAfter = host.Get("/account/passkeys", firstSession);
                    PasskeyListResponse pendingList = host.Get("/account/passkeys", secondSession).As<PasskeyListResponse>();
                    string page = host.Get("/account", secondSession).Body;
                    bool pageShowsTheBanner = page.Contains("account-recovery-pending", StringComparison.Ordinal) && page.Contains("data-account-action=\"cancelrecovery\"", StringComparison.Ordinal);
                    AccountReply secondBegin = host.Post(Begin, new RecoveryBeginRequest(), secondSession);
                    AccountReply handoverWhilePending = host.Post("/account/passkeys/" + secondId + "/handover/begin", new HandoverBeginRequest(), secondSession);
                    bool keySetStillFirst = KeySetIs(host, handle, first);

                    clock.Advance(TimeSpan.FromHours(73));
                    PasskeyListResponse settledList = host.Get("/account/passkeys", secondSession).As<PasskeyListResponse>();
                    bool keySetIsSecond = KeySetIs(host, handle, second);
                    AccountReply cancelAfterSettle = host.Post("/account/keyset/recovery/" + start.RecoveryId + "/cancel", new RenameRequest(), secondSession);
                    return new RecoveryOutcome(recoverableWhileHeld, tooNew, begun, allowsOnlySecond, completed, firstSessionAfter, pendingList, pageShowsTheBanner, secondBegin,
                        handoverWhilePending, keySetStillFirst, settledList, keySetIsSecond, cancelAfterSettle, secondId);
                }
                finally
                {
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<RecoveryOutcome>((because, outcome) =>
            {
                because.ItsTrue("a key set a passkey holds is not offered for recovery", !outcome.RecoverableWhileHeld);
                because.ItsTrue($"a new heir is refused with when it becomes eligible ({outcome.TooNew.Status}: {outcome.TooNew.Body})",
                    outcome.TooNew.Status == HttpStatusCode.Conflict && outcome.TooNew.ErrorCode == AccountErrorCodes.HeirTooNew && outcome.TooNew.As<HeirTooNewError>().EligibleUtc > DateTime.UtcNow);
                because.ItsTrue($"begin succeeds once the heir is old enough ({outcome.Begun.Status}: {outcome.Begun.Body})", outcome.Begun.Status == HttpStatusCode.OK);
                because.ItsTrue("and asks only the heir, user-verified", outcome.AllowsOnlySecond);
                because.ItsTrue($"complete is accepted with the time the key moves ({outcome.Completed.Status}: {outcome.Completed.Body})",
                    outcome.Completed.Status == HttpStatusCode.Accepted && !outcome.Completed.As<RecoveryCompleteResponse>().SignedOut && outcome.Completed.As<RecoveryCompleteResponse>().EffectiveUtc > DateTime.UtcNow);
                because.ItsTrue($"the lost passkey's session ends at once ({outcome.FirstSessionAfter.Status})", outcome.FirstSessionAfter.Status == HttpStatusCode.Unauthorized);
                because.ItsTrue("the list shows the pending recovery and offers no other", outcome.PendingList.PendingRecovery is not null && outcome.PendingList.PendingRecovery.Heir == outcome.SecondId && !outcome.PendingList.KeySetRecoverable);
                because.ItsTrue("the manage page shows the banner with cancel", outcome.PageShowsTheBanner);
                because.ItsTrue($"a second begin is refused ({outcome.SecondBegin.Status})", outcome.SecondBegin.Status == HttpStatusCode.Conflict && outcome.SecondBegin.ErrorCode == AccountErrorCodes.RecoveryPending);
                because.ItsTrue($"a handover is refused while it waits ({outcome.HandoverWhilePending.Status})", outcome.HandoverWhilePending.Status == HttpStatusCode.Conflict && outcome.HandoverWhilePending.ErrorCode == AccountErrorCodes.RecoveryPending);
                because.ItsTrue("before the delay the key set stays", outcome.KeySetStillFirst);
                because.ItsTrue("after the delay the list request settles it", outcome.SettledList.PendingRecovery is null && outcome.KeySetIsSecond
                    && outcome.SettledList.Passkeys.Single().RegisteredKeySet);
                because.ItsTrue($"a cancel after settle is not found ({outcome.CancelAfterSettle.Status})", outcome.CancelAfterSettle.Status == HttpStatusCode.NotFound);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void OfferRecoveryAndLetAnySessionCancelIt()
    {
        ManualClock clock = new ManualClock();
        When.A<AccountHost>("removes the key-set passkey keeping the key, recovers, then cancels",
            () => HostWithRecovery(nameof(OfferRecoveryAndLetAnySessionCancelIt), clock),
            (host) =>
            {
                try
                {
                    SyntheticAuthenticator first = new SyntheticAuthenticator();
                    SyntheticAuthenticator second = new SyntheticAuthenticator();
                    SyntheticAuthenticator third = new SyntheticAuthenticator();
                    string firstId = first.CredentialIdBase64Url;
                    string session = host.SignUp("alice", "Alice Example", first).SessionCookie!;
                    Add(host, second, session);
                    Add(host, third, session);
                    string secondSession = host.SignIn(second, "alice").SessionCookie!;
                    string thirdSession = host.SignIn(third, "alice").SessionCookie!;
                    string keepPage = host.Get("/account", secondSession).Body;
                    bool keepCopyPointsAtRecovery = keepPage.Contains("You can then recover the key with another passkey", StringComparison.Ordinal);
                    AccountReply kept = host.Delete("/account/passkeys/" + firstId + "?keySet=keep", secondSession);
                    PasskeyListResponse recoverable = host.Get("/account/passkeys", secondSession).As<PasskeyListResponse>();
                    string page = host.Get("/account", secondSession).Body;
                    bool pageOffersRecovery = page.Contains("account-recovery alert", StringComparison.Ordinal) && page.Contains("data-account-action=\"recover\"", StringComparison.Ordinal);

                    clock.Advance(TimeSpan.FromDays(8));
                    RecoveryBeginResponse start = host.Post(Begin, new RecoveryBeginRequest(), secondSession).As<RecoveryBeginResponse>();
                    AccountReply completed = host.Post(Complete, Proof(second, start), secondSession);
                    string cancelPath = "/account/keyset/recovery/" + start.RecoveryId + "/cancel";
                    AccountReply noHeader = host.Post(cancelPath, new RenameRequest(), thirdSession, withHeader: false);
                    AccountReply canceled = host.Post(cancelPath, new RenameRequest(), thirdSession);
                    PasskeyListResponse afterCancel = host.Get("/account/passkeys", secondSession).As<PasskeyListResponse>();
                    AccountReply again = host.Post(cancelPath, new RenameRequest(), thirdSession);
                    clock.Advance(TimeSpan.FromDays(4));
                    host.Get("/account/passkeys", secondSession);
                    string handle = host.Fixture.Passkeys.Credentials.FindByCredentialId(second.CredentialIdBase64Url)!.PersonHandle;
                    return new CancelOutcome(keepCopyPointsAtRecovery, kept, recoverable, pageOffersRecovery, completed, noHeader, canceled, afterCancel, again, KeySetIs(host, handle, first));
                }
                finally
                {
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<CancelOutcome>((because, outcome) =>
            {
                because.ItsTrue("the keep-the-key confirmation points at recovery", outcome.KeepCopyPointsAtRecovery);
                because.ItsTrue($"the key-set passkey is removed keeping the key ({outcome.Kept.Status})", outcome.Kept.Status == HttpStatusCode.OK);
                because.ItsTrue("then the list offers recovery", outcome.Recoverable.KeySetRecoverable && outcome.Recoverable.PendingRecovery is null);
                because.ItsTrue("and the manage page offers it", outcome.PageOffersRecovery);
                because.ItsTrue($"a recovery with no removes is accepted ({outcome.Completed.Status}: {outcome.Completed.Body})", outcome.Completed.Status == HttpStatusCode.Accepted);
                because.ItsTrue($"cancel without the request header is refused ({outcome.NoHeader.Status})", outcome.NoHeader.Status == HttpStatusCode.Forbidden);
                because.ItsTrue($"another session of the person cancels it ({outcome.Canceled.Status}: {outcome.Canceled.Body})", outcome.Canceled.Status == HttpStatusCode.NoContent);
                because.ItsTrue("nothing waits after the cancel, and recovery is offered again", outcome.AfterCancel.PendingRecovery is null && outcome.AfterCancel.KeySetRecoverable);
                because.ItsTrue($"a second cancel is not found ({outcome.Again.Status})", outcome.Again.Status == HttpStatusCode.NotFound);
                because.ItsTrue("a canceled recovery never moves the key", outcome.KeySetKept);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseRecoveriesOutsideTheRule()
    {
        ManualClock clock = new ManualClock();
        When.A<AccountHost>("begins recoveries the rule doesn't allow",
            () => HostWithRecovery(nameof(RefuseRecoveriesOutsideTheRule), clock),
            (host) =>
            {
                try
                {
                    SyntheticAuthenticator first = new SyntheticAuthenticator();
                    SyntheticAuthenticator second = new SyntheticAuthenticator();
                    string firstId = first.CredentialIdBase64Url;
                    string secondId = second.CredentialIdBase64Url;
                    string session = host.SignUp("alice", "Alice Example", first).SessionCookie!;
                    Add(host, second, session);
                    clock.Advance(TimeSpan.FromDays(8));
                    AccountReply removesRequired = host.Post(Begin, new RecoveryBeginRequest { Heir = secondId }, session);
                    AccountReply notKeySet = host.Post(Begin, new RecoveryBeginRequest { Removes = secondId }, session);
                    AccountReply invalidHeir = host.Post(Begin, new RecoveryBeginRequest { Removes = firstId }, session);
                    AccountReply notFound = host.Post(Begin, new RecoveryBeginRequest { Removes = "no-such-passkey", Heir = secondId }, session);
                    AccountReply unknownId = host.Post(Complete, new RecoveryCompleteRequest { RecoveryId = "not-a-recovery", Credential = second.Assert(new byte[32]) }, session);
                    AccountReply noBody = host.Post(Complete, new RecoveryCompleteRequest { RecoveryId = "not-a-recovery" }, session);
                    AccountReply signedOut = host.Post(Begin, new RecoveryBeginRequest { Removes = firstId, Heir = secondId });
                    return new RuleOutcome(removesRequired, notKeySet, invalidHeir, notFound, unknownId, noBody, signedOut);
                }
                finally
                {
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<RuleOutcome>((because, outcome) =>
            {
                because.ItsTrue($"leaving out removes while a passkey holds the key is refused ({outcome.RemovesRequired.Status})", outcome.RemovesRequired.Status == HttpStatusCode.BadRequest && outcome.RemovesRequired.ErrorCode == AccountErrorCodes.RemovesRequired);
                because.ItsTrue($"removes must hold the key set ({outcome.NotKeySet.Status})", outcome.NotKeySet.Status == HttpStatusCode.BadRequest && outcome.NotKeySet.ErrorCode == AccountErrorCodes.NotKeySet);
                because.ItsTrue($"the session's passkey can't be its own heir ({outcome.InvalidHeir.Status})", outcome.InvalidHeir.Status == HttpStatusCode.BadRequest && outcome.InvalidHeir.ErrorCode == AccountErrorCodes.InvalidHeir);
                because.ItsTrue($"an unknown removes is not found ({outcome.NotFound.Status})", outcome.NotFound.Status == HttpStatusCode.NotFound && outcome.NotFound.ErrorCode == AccountErrorCodes.NotFound);
                because.ItsTrue($"an unknown recovery id is expired ({outcome.UnknownId.Status})", outcome.UnknownId.Status == HttpStatusCode.BadRequest && outcome.UnknownId.ErrorCode == AccountErrorCodes.HandoverExpired);
                because.ItsTrue($"a complete without an assertion is a bad request ({outcome.NoBody.Status})", outcome.NoBody.Status == HttpStatusCode.BadRequest && outcome.NoBody.ErrorCode == AccountErrorCodes.BadRequest);
                because.ItsTrue($"recovery needs a session ({outcome.SignedOut.Status})", outcome.SignedOut.Status == HttpStatusCode.Unauthorized);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void SayTheKeyCannotMoveWhereThereIsNoRotation()
    {
        When.A<AccountHost>("has no rotation proofs at all",
            () => new AccountHost(),
            (host) =>
            {
                try
                {
                    SyntheticAuthenticator first = new SyntheticAuthenticator();
                    SyntheticAuthenticator second = new SyntheticAuthenticator();
                    string session = host.SignUp("alice", "Alice Example", first).SessionCookie!;
                    Add(host, second, session);
                    AccountReply recovery = host.Post(Begin, new RecoveryBeginRequest { Removes = first.CredentialIdBase64Url, Heir = second.CredentialIdBase64Url }, session);
                    AccountReply handover = host.Post("/account/passkeys/" + first.CredentialIdBase64Url + "/handover/begin", new HandoverBeginRequest { Heir = second.CredentialIdBase64Url }, session);
                    PasskeyListResponse list = host.Get("/account/passkeys", session).As<PasskeyListResponse>();
                    string page = host.Get("/account", session).Body;
                    return new UnavailableOutcome(recovery, handover, list, page.Contains("account-recovery", StringComparison.Ordinal), host.Site.Strings.KeySetRotationUnavailableMessage);
                }
                finally
                {
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<UnavailableOutcome>((because, outcome) =>
            {
                because.ItsTrue($"recovery says the key can't move here ({outcome.Recovery.Status}: {outcome.Recovery.Body})", outcome.Recovery.Status == HttpStatusCode.Conflict && outcome.Recovery.ErrorCode == AccountErrorCodes.RotationUnavailable
                    && outcome.Recovery.As<AccountError>().Message == outcome.Message);
                because.ItsTrue($"so does the handover, in its own words ({outcome.Handover.Body})", outcome.Handover.ErrorCode == AccountErrorCodes.RotationUnavailable && outcome.Handover.As<AccountError>().Message == outcome.Message);
                because.ItsTrue("the list offers no recovery", !outcome.List.KeySetRecoverable && outcome.List.PendingRecovery is null);
                because.ItsTrue("the manage page shows no recovery", !outcome.PageMentionsRecovery);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void PinTheKeySetBadgeToTheRegistrar()
    {
        ManualClock clock = new ManualClock();
        When.A<AccountHost>("stores the key-set flag on the wrong passkey",
            () => HostWithRecovery(nameof(PinTheKeySetBadgeToTheRegistrar), clock),
            (host) =>
            {
                try
                {
                    SyntheticAuthenticator first = new SyntheticAuthenticator();
                    SyntheticAuthenticator second = new SyntheticAuthenticator();
                    string firstId = first.CredentialIdBase64Url;
                    string secondId = second.CredentialIdBase64Url;
                    string session = host.SignUp("alice", "Alice Example", first).SessionCookie!;
                    Add(host, second, session);
                    string handle = host.Fixture.Passkeys.Credentials.FindByCredentialId(firstId)!.PersonHandle;
                    host.Fixture.Passkeys.Credentials.SetRegisteredKeySet(handle, firstId, false);
                    host.Fixture.Passkeys.Credentials.SetRegisteredKeySet(handle, secondId, true);
                    string page = host.Get("/account", session).Body;
                    return new BadgeOutcome(HasBadge(page, firstId), HasBadge(page, secondId));
                }
                finally
                {
                    host.Dispose();
                }
            })
            .TheTest
            .ShouldPass<BadgeOutcome>((because, outcome) =>
            {
                because.ItsTrue("the passkey the registrar holds as the key set has the badge, whatever its stored flag", outcome.FirstBadged);
                because.ItsTrue("the passkey whose stored flag is wrong has none", !outcome.SecondBadged);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    private static AccountHost HostWithRecovery(string testName, ManualClock clock)
    {
        return new AccountHost(bind: registry =>
        {
            KeySetRotationProofs proofs = KeySetRotationProofChain.DefaultProofs();
            PublicKeySetRegistrar registrar = new PublicKeySetRegistrar(HandoverFixture.CreateObjectDataRepository("web-" + testName), new KeySetRotationProofChain(proofs));
            registry.For<KeySetRotationProofs>().UseSingleton(proofs);
            registry.For<IPublicKeySetRegistrar>().UseSingleton(registrar);
            registry.For<TimeProvider>().UseSingleton(clock);
        });
    }

    // The badge inside the list item of one passkey.
    private static bool HasBadge(string page, string credentialId)
    {
        foreach (string item in page.Split("<li class=\"account-passkey list-group-item\">", StringSplitOptions.None).Skip(1))
        {
            if (item.Contains("account-passkey-" + credentialId + "\"", StringComparison.Ordinal))
            {
                return item.Contains("account-keyset badge", StringComparison.Ordinal);
            }
        }
        return false;
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

    private static RecoveryCompleteRequest Proof(SyntheticAuthenticator authenticator, RecoveryBeginResponse start)
    {
        authenticator.SignCount++;
        return new RecoveryCompleteRequest { RecoveryId = start.RecoveryId, Credential = authenticator.Assert(Base64UrlEncoder.Default.Decode(start.Options.Challenge)) };
    }

    private static bool KeySetIs(AccountHost host, string handle, SyntheticAuthenticator authenticator)
    {
        PublicKeySetData? keySet = host.Registry.Get<IPublicKeySetRegistrar>().Resolve(handle);
        return PasskeyKeySet.IsHeldBy(keySet, new PasskeyCredentialData { PersonHandle = handle, PublicKeyPem = authenticator.PublicKeyPem });
    }

    private sealed record RecoveryOutcome(bool RecoverableWhileHeld, AccountReply TooNew, AccountReply Begun, bool AllowsOnlySecond, AccountReply Completed, AccountReply FirstSessionAfter,
        PasskeyListResponse PendingList, bool PageShowsTheBanner, AccountReply SecondBegin, AccountReply HandoverWhilePending, bool KeySetStillFirst, PasskeyListResponse SettledList,
        bool KeySetIsSecond, AccountReply CancelAfterSettle, string SecondId);

    private sealed record CancelOutcome(bool KeepCopyPointsAtRecovery, AccountReply Kept, PasskeyListResponse Recoverable, bool PageOffersRecovery, AccountReply Completed, AccountReply NoHeader,
        AccountReply Canceled, PasskeyListResponse AfterCancel, AccountReply Again, bool KeySetKept);

    private sealed record RuleOutcome(AccountReply RemovesRequired, AccountReply NotKeySet, AccountReply InvalidHeir, AccountReply NotFound, AccountReply UnknownId, AccountReply NoBody, AccountReply SignedOut);

    private sealed record UnavailableOutcome(AccountReply Recovery, AccountReply Handover, PasskeyListResponse List, bool PageMentionsRecovery, string Message);

    private sealed record BadgeOutcome(bool FirstBadged, bool SecondBadged);
}
