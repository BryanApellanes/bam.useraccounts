using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Test;
using Bam.UserAccounts.Passkeys;
using Bam.UserAccounts.Tests.TestClasses;

namespace Bam.UserAccounts.Tests.Unit.Passkeys;

/// <summary>
/// Covers native app origins (bam.useraccounts#12): an Android app presents
/// <c>android:apk-key-hash:...</c> in clientDataJSON, which is accepted only when it is listed,
/// exactly, in <see cref="PasskeyOptions.AllowedAppOrigins"/>.
/// </summary>
[UnitTestMenu("Passkey app origins Should", Selector = "pkao")]
public class PasskeyAppOriginsShould : UnitTestMenuContainer
{
    private const string Listed = "android:apk-key-hash:-sYXRdwJA3hvue3mKpYrOZ9zSPC7b4mbgzJmdZEDO5w";
    private const string Unlisted = "android:apk-key-hash:AAAARdwJA3hvue3mKpYrOZ9zSPC7b4mbgzJmdZEDO5w";
    private const string UserHandle = "dXNlci1oYW5kbGU";

    public PasskeyAppOriginsShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    [UnitTest]
    public void MatchAppOriginsExactly()
    {
        After.Setup(reg => reg.Set(AppOptions()))
        .When<PasskeyOptions>("checks listed, unlisted and near-miss app origins, and the browser origin", (options, reg) =>
        {
            options.Validate();
            PasskeyOptions none = PasskeyFixture.DefaultOptions();
            none.Validate();
            return new MatchOutcome(
                options.IsOriginAllowed(Listed),
                options.IsOriginAllowed(Unlisted),
                options.IsOriginAllowed(Listed.ToLowerInvariant()),
                options.IsOriginAllowed(Listed.ToUpperInvariant()),
                options.IsOriginAllowed(Listed + "A"),
                options.IsOriginAllowed(Listed.Substring(0, Listed.Length - 1)),
                options.IsOriginAllowed(Listed + " ") || options.IsOriginAllowed(" " + Listed) || options.IsOriginAllowed(Listed + "\n"),
                options.IsOriginAllowed(PasskeyOptions.AndroidAppOriginPrefix),
                options.IsOriginAllowed("ANDROID:apk-key-hash:" + Listed.Substring(PasskeyOptions.AndroidAppOriginPrefix.Length)),
                options.IsOriginAllowed("android:apk-key-hash://lumberjack.live"),
                options.IsOriginAllowed("ios:bundle-id:live.lumberjack.app"),
                options.IsOriginAllowed("https://lumberjack.live"),
                options.IsOriginAllowed("https://evil.example"),
                none.IsOriginAllowed(Listed),
                none.AllowedAppOrigins.Count);
        })
        .TheTest
        .ShouldPass<MatchOutcome>((because, outcome) =>
        {
            because.ItsTrue("a listed app origin is allowed", outcome.Listed);
            because.ItsTrue("an unlisted app origin is refused", !outcome.Unlisted);
            because.ItsTrue("a lowercased hash is a different hash and is refused", !outcome.Lowercased);
            because.ItsTrue("an uppercased origin is refused", !outcome.Uppercased);
            because.ItsTrue("a longer value with the listed one as prefix is refused", !outcome.Extended);
            because.ItsTrue("a truncated value is refused", !outcome.Truncated);
            because.ItsTrue("whitespace around a listed value is refused", !outcome.WithWhitespace);
            because.ItsTrue("the bare prefix is refused", !outcome.PrefixOnly);
            because.ItsTrue("the scheme is matched case-sensitively", !outcome.UppercaseScheme);
            because.ItsTrue("an app-scheme origin shaped like a URL is refused", !outcome.UrlShaped);
            because.ItsTrue("another non-http scheme is refused", !outcome.OtherScheme);
            because.ItsTrue("the browser origin is still allowed", outcome.BrowserOrigin);
            because.ItsTrue("an unlisted browser origin is still refused", !outcome.ForeignBrowserOrigin);
            because.ItsTrue("with no app origins configured, an app origin is refused", !outcome.ListedWithoutConfiguration);
            because.ItsTrue("the app list is empty by default", outcome.DefaultCount == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ValidateAppOrigins()
    {
        After.Setup(reg => reg.Set(AppOptions()))
        .When<PasskeyOptions>("validates well-formed and malformed app origin lists", (unused, reg) =>
        {
            return new ValidationOutcome(
                !Throws(o => o.AllowedAppOrigins = new List<string>()),
                !Throws(o => o.AllowedAppOrigins = new List<string> { Listed, Unlisted }),
                Throws(o => o.AllowedAppOrigins = null!),
                Throws(o => o.AllowedAppOrigins = new List<string> { null! }),
                Throws(o => o.AllowedAppOrigins = new List<string> { PasskeyOptions.AndroidAppOriginPrefix }),
                Throws(o => o.AllowedAppOrigins = new List<string> { Listed + "=" }),
                Throws(o => o.AllowedAppOrigins = new List<string> { "android:apk-key-hash:ab+/cd" }),
                Throws(o => o.AllowedAppOrigins = new List<string> { Listed + "\n" }),
                Throws(o => o.AllowedAppOrigins = new List<string> { " " + Listed }),
                Throws(o => o.AllowedAppOrigins = new List<string> { "https://lumberjack.live" }),
                Throws(o => o.AllowedAppOrigins = new List<string> { "ios:bundle-id:live.lumberjack.app" }),
                Throws(o => o.AllowedAppOrigins = new List<string> { "Android:apk-key-hash:abc" }),
                Throws(o => o.AllowedOrigins = new List<string> { Listed }),
                Throws(o => o.AllowedOrigins = new List<string>()));
        })
        .TheTest
        .ShouldPass<ValidationOutcome>((because, outcome) =>
        {
            because.ItsTrue("an empty app list is valid", outcome.EmptyAccepted);
            because.ItsTrue("several well-formed app origins are valid", outcome.SeveralAccepted);
            because.ItsTrue("a null app list is refused", outcome.NullList);
            because.ItsTrue("a null entry is refused", outcome.NullEntry);
            because.ItsTrue("the bare prefix is refused", outcome.PrefixOnly);
            because.ItsTrue("base64 padding is refused", outcome.Padded);
            because.ItsTrue("standard base64 characters are refused", outcome.StandardBase64);
            because.ItsTrue("a trailing newline is refused", outcome.TrailingNewline);
            because.ItsTrue("a leading space is refused", outcome.LeadingSpace);
            because.ItsTrue("a browser origin in the app list is refused", outcome.BrowserOriginInAppList);
            because.ItsTrue("another scheme in the app list is refused", outcome.OtherScheme);
            because.ItsTrue("a differently cased prefix is refused", outcome.WrongCasePrefix);
            because.ItsTrue("an app origin in the browser list is still refused", outcome.AppOriginInBrowserList);
            because.ItsTrue("a browser origin is still required", outcome.NoBrowserOrigins);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void VerifyCeremoniesFromAListedApp()
    {
        After.Setup(reg => reg.Set(new SyntheticAuthenticator(origin: Listed)))
        .When<SyntheticAuthenticator>("verifies a registration and an assertion whose client data carries an app origin", (authenticator, reg) =>
        {
            PasskeyOptions options = AppOptions();
            PasskeyRegistrationVerifier registrationVerifier = new PasskeyRegistrationVerifier(options);
            PasskeyAssertionVerifier assertionVerifier = new PasskeyAssertionVerifier(options, new DetachedSignatureVerifier());
            PasskeyAssertionVerifier browserOnlyVerifier = new PasskeyAssertionVerifier(PasskeyFixture.DefaultOptions(), new DetachedSignatureVerifier());
            PasskeyCredentialData stored = Stored(authenticator);

            byte[] registrationChallenge = SyntheticAuthenticator.RandomBytes(32);
            PasskeyVerification registered = registrationVerifier.Verify(authenticator.Register(registrationChallenge), registrationChallenge);
            PasskeyVerification unlistedRegistration = registrationVerifier.Verify(authenticator.Register(registrationChallenge, origin: Unlisted), registrationChallenge);
            PasskeyVerification browserOnlyRegistration = new PasskeyRegistrationVerifier(PasskeyFixture.DefaultOptions()).Verify(authenticator.Register(registrationChallenge), registrationChallenge);

            byte[] assertionChallenge = SyntheticAuthenticator.RandomBytes(32);
            authenticator.SignCount = 1;
            PasskeyVerification asserted = assertionVerifier.Verify(authenticator.Assert(assertionChallenge, userHandle: UserHandle), assertionChallenge, stored);
            authenticator.SignCount = 2;
            PasskeyVerification unlistedAssertion = assertionVerifier.Verify(authenticator.Assert(assertionChallenge, userHandle: UserHandle, origin: Unlisted), assertionChallenge, stored);
            authenticator.SignCount = 3;
            PasskeyVerification browserOnlyAssertion = browserOnlyVerifier.Verify(authenticator.Assert(assertionChallenge, userHandle: UserHandle), assertionChallenge, stored);
            authenticator.SignCount = 4;
            PasskeyVerification browserOriginStillWorks = assertionVerifier.Verify(authenticator.Assert(assertionChallenge, userHandle: UserHandle, origin: "https://lumberjack.live"), assertionChallenge, stored);

            return new CeremonyOutcome(
                registered.Success, registered.Detail,
                unlistedRegistration.Failure, browserOnlyRegistration.Failure,
                asserted.Success, asserted.Detail,
                unlistedAssertion.Failure, browserOnlyAssertion.Failure,
                browserOriginStillWorks.Success);
        })
        .TheTest
        .ShouldPass<CeremonyOutcome>((because, outcome) =>
        {
            because.ItsTrue("a registration from a listed app verifies", outcome.Registered, outcome.RegisteredDetail);
            because.ItsTrue("a registration from an unlisted app is refused on origin", outcome.UnlistedRegistration == PasskeyVerificationFailure.OriginNotAllowed);
            because.ItsTrue("a registration from an app is refused when no app origins are configured", outcome.BrowserOnlyRegistration == PasskeyVerificationFailure.OriginNotAllowed);
            because.ItsTrue("an assertion from a listed app verifies", outcome.Asserted, outcome.AssertedDetail);
            because.ItsTrue("an assertion from an unlisted app is refused on origin", outcome.UnlistedAssertion == PasskeyVerificationFailure.OriginNotAllowed);
            because.ItsTrue("an assertion from an app is refused when no app origins are configured", outcome.BrowserOnlyAssertion == PasskeyVerificationFailure.OriginNotAllowed);
            because.ItsTrue("the same credential still signs in from the browser origin", outcome.BrowserOriginStillWorks);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RunTheWholeCeremonyFromAListedApp()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture(AppOptions())))
        .When<PasskeyFixture>("signs up and signs in through the ceremony with an app origin", (fixture, reg) =>
        {
            SyntheticAuthenticator app = new SyntheticAuthenticator(origin: Listed);
            PasskeyRegistrationResult registered = fixture.Register(app);
            app.SignCount++;
            PasskeySignInResult signedIn = fixture.SignIn(app, handle: null);

            SyntheticAuthenticator otherApp = new SyntheticAuthenticator(origin: Unlisted);
            PasskeyRegistrationResult refused = fixture.Register(otherApp, "someone-else");
            return new WholeCeremonyOutcome(registered.Success, registered.Message, signedIn.Success, signedIn.PersonHandle, refused.Success, refused.Failure);
        })
        .TheTest
        .ShouldPass<WholeCeremonyOutcome>((because, outcome) =>
        {
            because.ItsTrue("sign-up from a listed app succeeds", outcome.Registered, outcome.RegisteredMessage);
            because.ItsTrue("discoverable sign-in from the app succeeds", outcome.SignedIn);
            because.ItsTrue("the sign-in names the person", outcome.SignedInHandle == PasskeyFixture.Handle);
            because.ItsTrue("sign-up from an unlisted app is refused", !outcome.UnlistedRegistered);
            because.ItsTrue("and the reason is the origin", outcome.UnlistedFailure == PasskeyVerificationFailure.OriginNotAllowed);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static PasskeyOptions AppOptions()
    {
        PasskeyOptions options = PasskeyFixture.DefaultOptions();
        options.AllowedAppOrigins = new List<string> { Listed };
        return options;
    }

    private static bool Throws(Action<PasskeyOptions> mutate)
    {
        PasskeyOptions options = AppOptions();
        mutate(options);
        try
        {
            options.Validate();
            return false;
        }
        catch (ArgumentException)
        {
            return true;
        }
    }

    private static PasskeyCredentialData Stored(SyntheticAuthenticator authenticator)
    {
        return new PasskeyCredentialData
        {
            PersonHandle = PasskeyFixture.Handle,
            CredentialId = authenticator.CredentialIdBase64Url,
            UserHandle = UserHandle,
            PublicKeyPem = authenticator.PublicKeyPem,
            Algorithm = (long)authenticator.Algorithm,
            SignCount = 0,
            CreatedUtc = DateTime.UtcNow
        };
    }

    private sealed record MatchOutcome(bool Listed, bool Unlisted, bool Lowercased, bool Uppercased, bool Extended, bool Truncated, bool WithWhitespace, bool PrefixOnly, bool UppercaseScheme, bool UrlShaped, bool OtherScheme, bool BrowserOrigin, bool ForeignBrowserOrigin, bool ListedWithoutConfiguration, int DefaultCount);

    private sealed record ValidationOutcome(bool EmptyAccepted, bool SeveralAccepted, bool NullList, bool NullEntry, bool PrefixOnly, bool Padded, bool StandardBase64, bool TrailingNewline, bool LeadingSpace, bool BrowserOriginInAppList, bool OtherScheme, bool WrongCasePrefix, bool AppOriginInBrowserList, bool NoBrowserOrigins);

    private sealed record CeremonyOutcome(bool Registered, string? RegisteredDetail, PasskeyVerificationFailure UnlistedRegistration, PasskeyVerificationFailure BrowserOnlyRegistration, bool Asserted, string? AssertedDetail, PasskeyVerificationFailure UnlistedAssertion, PasskeyVerificationFailure BrowserOnlyAssertion, bool BrowserOriginStillWorks);

    private sealed record WholeCeremonyOutcome(bool Registered, string? RegisteredMessage, bool SignedIn, string? SignedInHandle, bool UnlistedRegistered, PasskeyVerificationFailure UnlistedFailure);
}
