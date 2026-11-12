using Bam.DependencyInjection;
using Bam.Encryption.Cose;
using Bam.Test;
using Bam.UserAccounts.Passkeys;
using Bam.UserAccounts.Tests.TestClasses;

namespace Bam.UserAccounts.Tests.Unit.Passkeys;

[UnitTestMenu("PasskeyOptions Should", Selector = "pko")]
public class PasskeyOptionsShould : UnitTestMenuContainer
{
    public PasskeyOptionsShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    [UnitTest]
    public void ValidateCoherentOptions()
    {
        After.Setup(reg => reg.Set(PasskeyFixture.DefaultOptions()))
        .When<PasskeyOptions>("validates the default options and matches origins", (options, reg) =>
        {
            options.AllowedOrigins.Add("https://app.lumberjack.live:8443");
            options.Validate();
            return new OriginOutcome(
                options.IsOriginAllowed("https://lumberjack.live"),
                options.IsOriginAllowed("https://LUMBERJACK.live"),
                options.IsOriginAllowed("https://app.lumberjack.live:8443"),
                options.IsOriginAllowed("http://lumberjack.live"),
                options.IsOriginAllowed("https://lumberjack.live:444"),
                options.IsOriginAllowed("https://evil.example"),
                options.IsOriginAllowed(null),
                options.IsOriginAllowed("https://lumberjack.live/path"),
                options.IsOriginAllowed("https://lumberjack.live/?q=1"),
                options.IsOriginAllowed("https://user@lumberjack.live"),
                options.IsOriginAllowed(" https://lumberjack.live") || options.IsOriginAllowed("https://lumberjack.live "),
                options.UserVerification);
        })
        .TheTest
        .ShouldPass<OriginOutcome>((because, outcome) =>
        {
            because.ItsTrue("exact origin is allowed", outcome.Exact);
            because.ItsTrue("host comparison is case-insensitive", outcome.UpperHost);
            because.ItsTrue("subdomain origin with port is allowed when listed", outcome.Subdomain);
            because.ItsTrue("scheme must match", !outcome.WrongScheme);
            because.ItsTrue("port must match", !outcome.WrongPort);
            because.ItsTrue("unlisted host is refused", !outcome.OtherHost);
            because.ItsTrue("null origin is refused", !outcome.Null);
            because.ItsTrue("origin with a path is refused", !outcome.WithPath);
            because.ItsTrue("origin with a query is refused", !outcome.WithQuery);
            because.ItsTrue("origin with user info is refused", !outcome.WithUserInfo);
            because.ItsTrue("origin with surrounding whitespace is refused", !outcome.WithWhitespace);
            because.ItsTrue("user verification defaults to preferred", outcome.UserVerification == "preferred");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectIncoherentOptions()
    {
        After.Setup(reg => reg.Set(PasskeyFixture.DefaultOptions()))
        .When<PasskeyOptions>("validates each broken variant", (options, reg) =>
        {
            return new RejectionOutcome(
                Throws(o => o.RpId = "https://lumberjack.live"),
                Throws(o => o.RpId = "Lumberjack.live"),
                Throws(o => o.RpName = ""),
                Throws(o => o.AllowedOrigins = new List<string>()),
                Throws(o => o.AllowedOrigins = new List<string> { "https://lumberjack.live/login" }),
                Throws(o => o.AllowedOrigins = new List<string> { "https://evil.example" }),
                Throws(o => o.AllowedOrigins = new List<string> { "https://notlumberjack.live" }),
                Throws(o => o.Algorithms = new List<CoseAlgorithm>()),
                Throws(o => o.Algorithms = new List<CoseAlgorithm> { (CoseAlgorithm)99 }),
                Throws(o => o.ChallengeLifetime = TimeSpan.Zero),
                !Throws(o => o.RequireUserVerification = true),
                Throws(o => o.ResidentKey = "Required"),
                Throws(o => o.ResidentKey = "always"),
                !Throws(o => o.ResidentKey = "required") && !Throws(o => o.ResidentKey = "discouraged"));
        })
        .TheTest
        .ShouldPass<RejectionOutcome>((because, outcome) =>
        {
            because.ItsTrue("rp id with a scheme is refused", outcome.RpIdWithScheme);
            because.ItsTrue("mixed-case rp id is refused", outcome.RpIdMixedCase);
            because.ItsTrue("empty rp name is refused", outcome.EmptyRpName);
            because.ItsTrue("no origins is refused", outcome.NoOrigins);
            because.ItsTrue("origin with a path is refused", outcome.OriginWithPath);
            because.ItsTrue("origin on another host is refused", outcome.ForeignOrigin);
            because.ItsTrue("origin on a host that merely ends with the rp id is refused", outcome.SuffixOrigin);
            because.ItsTrue("no algorithms is refused", outcome.NoAlgorithms);
            because.ItsTrue("unsupported algorithm is refused", outcome.UnsupportedAlgorithm);
            because.ItsTrue("zero lifetime is refused", outcome.ZeroLifetime);
            because.ItsTrue("requiring user verification is fine", outcome.RequireUvAccepted);
            because.ItsTrue("a residentKey in the wrong case is refused", outcome.ResidentKeyWrongCase);
            because.ItsTrue("an unknown residentKey is refused", outcome.ResidentKeyUnknown);
            because.ItsTrue("the three spec values are accepted", outcome.ResidentKeyAccepted);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static bool Throws(Action<PasskeyOptions> mutate)
    {
        PasskeyOptions options = PasskeyFixture.DefaultOptions();
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

    private sealed record OriginOutcome(bool Exact, bool UpperHost, bool Subdomain, bool WrongScheme, bool WrongPort, bool OtherHost, bool Null, bool WithPath, bool WithQuery, bool WithUserInfo, bool WithWhitespace, string UserVerification);

    private sealed record RejectionOutcome(bool RpIdWithScheme, bool RpIdMixedCase, bool EmptyRpName, bool NoOrigins, bool OriginWithPath,
        bool ForeignOrigin, bool SuffixOrigin, bool NoAlgorithms, bool UnsupportedAlgorithm, bool ZeroLifetime, bool RequireUvAccepted, bool ResidentKeyWrongCase, bool ResidentKeyUnknown, bool ResidentKeyAccepted);
}
