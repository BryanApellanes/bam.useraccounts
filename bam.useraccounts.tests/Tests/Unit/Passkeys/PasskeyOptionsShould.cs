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
                !Throws(o => o.RequireUserVerification = true));
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

    private sealed record OriginOutcome(bool Exact, bool UpperHost, bool Subdomain, bool WrongScheme, bool WrongPort, bool OtherHost, bool Null, string UserVerification);

    private sealed record RejectionOutcome(bool RpIdWithScheme, bool RpIdMixedCase, bool EmptyRpName, bool NoOrigins, bool OriginWithPath,
        bool ForeignOrigin, bool SuffixOrigin, bool NoAlgorithms, bool UnsupportedAlgorithm, bool ZeroLifetime, bool RequireUvAccepted);
}
