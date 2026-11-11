using System.Text.RegularExpressions;
using Bam.Encryption.Cose;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Relying-party policy for passkey (WebAuthn) ceremonies: the RP id and name, the origins a
/// browser or a native app may present, whether user verification is required, challenge lifetime and the
/// algorithms offered at registration.  Call <see cref="Validate"/> (done by
/// <see cref="PasskeysServiceRegistration.AddPasskeys"/>) before use.
/// </summary>
public sealed class PasskeyOptions
{
    /// <summary>The prefix of the origin an Android app presents: <c>android:apk-key-hash:</c> followed by a base64url hash of the app's signing certificate.</summary>
    public const string AndroidAppOriginPrefix = "android:apk-key-hash:";

    // The prefix, then unpadded base64url and nothing else.
    private static readonly Regex AndroidAppOrigin = new Regex(@"\Aandroid:apk-key-hash:[A-Za-z0-9_-]+\z", RegexOptions.CultureInvariant);

    /// <summary>The RP id: a registrable domain suffix of every allowed origin's host (e.g. <c>lumberjack.live</c>).</summary>
    public string RpId { get; set; } = null!;

    /// <summary>The human-readable relying-party name shown by the authenticator.</summary>
    public string RpName { get; set; } = null!;

    /// <summary>The exact origins (scheme, host, port) a browser may present in <c>clientDataJSON</c>.</summary>
    public List<string> AllowedOrigins { get; set; } = new List<string>();

    /// <summary>
    /// The origins native apps may present in <c>clientDataJSON</c>, matched as exact strings.  An
    /// Android app that uses Credential Manager presents <c>android:apk-key-hash:&lt;base64url hash
    /// of its signing certificate&gt;</c> instead of an https origin, so each signing key that may
    /// sign the app (debug, upload, Play app signing) needs its own entry.  Default empty: no
    /// native Android app is accepted.  Apple apps present <c>https://&lt;rp id&gt;</c> and are
    /// covered by <see cref="AllowedOrigins"/>.
    /// </summary>
    public List<string> AllowedAppOrigins { get; set; } = new List<string>();

    /// <summary>When true, assertions and registrations without the user-verified flag are refused. Default false (user verification <c>preferred</c>).</summary>
    public bool RequireUserVerification { get; set; }

    /// <summary>How long an issued challenge stays valid. Default five minutes.</summary>
    public TimeSpan ChallengeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>The timeout hint sent to the browser. Default sixty seconds.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>The algorithms offered in <c>pubKeyCredParams</c>, in preference order. Default ES256 then RS256.</summary>
    public List<CoseAlgorithm> Algorithms { get; set; } = new List<CoseAlgorithm> { CoseAlgorithm.ES256, CoseAlgorithm.RS256 };

    /// <summary>The <c>residentKey</c> preference sent at registration. Default <c>preferred</c>.</summary>
    public string ResidentKey { get; set; } = "preferred";

    /// <summary>The <c>userVerification</c> value sent to the browser, derived from <see cref="RequireUserVerification"/>.</summary>
    public string UserVerification => RequireUserVerification ? "required" : "preferred";

    /// <summary>
    /// Checks the options are coherent: a bare lowercase host as <see cref="RpId"/>, at least one
    /// absolute http(s) origin whose host is the RP id or a subdomain of it, app origins that are
    /// each <see cref="AndroidAppOriginPrefix"/> followed by unpadded base64url (the list may be
    /// empty but not null), and at least one supported algorithm.
    /// </summary>
    /// <exception cref="ArgumentException">The options are not valid.</exception>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(RpId))
        {
            throw new ArgumentException("PasskeyOptions.RpId is required.");
        }
        if (RpId.Contains('/') || RpId.Contains(':') || RpId.Contains(' '))
        {
            throw new ArgumentException($"PasskeyOptions.RpId '{RpId}' must be a bare host name without scheme, port or path.");
        }
        if (!string.Equals(RpId, RpId.ToLowerInvariant(), StringComparison.Ordinal))
        {
            throw new ArgumentException($"PasskeyOptions.RpId '{RpId}' must be lowercase.");
        }
        if (string.IsNullOrWhiteSpace(RpName))
        {
            throw new ArgumentException("PasskeyOptions.RpName is required.");
        }
        if (AllowedOrigins == null || AllowedOrigins.Count == 0)
        {
            throw new ArgumentException("PasskeyOptions.AllowedOrigins must list at least one origin.");
        }
        foreach (string origin in AllowedOrigins)
        {
            if (!Uri.TryCreate(origin, UriKind.Absolute, out Uri? uri) || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            {
                throw new ArgumentException($"PasskeyOptions.AllowedOrigins entry '{origin}' is not an absolute http(s) origin.");
            }
            if (uri.PathAndQuery != "/" || !string.IsNullOrEmpty(uri.Fragment))
            {
                throw new ArgumentException($"PasskeyOptions.AllowedOrigins entry '{origin}' must be an origin (scheme, host, port) with no path.");
            }
            if (!IsRegistrableSuffix(uri.Host, RpId))
            {
                throw new ArgumentException($"PasskeyOptions.AllowedOrigins entry '{origin}' has host '{uri.Host}', which is not '{RpId}' or a subdomain of it.");
            }
        }
        if (AllowedAppOrigins == null)
        {
            throw new ArgumentException("PasskeyOptions.AllowedAppOrigins must not be null; use an empty list to accept no native apps.");
        }
        foreach (string appOrigin in AllowedAppOrigins)
        {
            if (appOrigin is null || !AndroidAppOrigin.IsMatch(appOrigin))
            {
                throw new ArgumentException($"PasskeyOptions.AllowedAppOrigins entries must be '{AndroidAppOriginPrefix}' followed by an unpadded base64url certificate hash.");
            }
        }
        if (Algorithms == null || Algorithms.Count == 0)
        {
            throw new ArgumentException("PasskeyOptions.Algorithms must list at least one algorithm.");
        }
        foreach (CoseAlgorithm algorithm in Algorithms)
        {
            if (!CoseAlgorithms.IsSupported((long)algorithm))
            {
                throw new ArgumentException($"PasskeyOptions.Algorithms entry {algorithm} is not supported.");
            }
        }
        if (ChallengeLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentException("PasskeyOptions.ChallengeLifetime must be positive.");
        }
    }

    /// <summary>
    /// Returns whether an origin presented by a browser matches one of <see cref="AllowedOrigins"/>
    /// on scheme, host (case-insensitively) and port, or an origin presented by a native app is
    /// one of <see cref="AllowedAppOrigins"/> exactly.  The two lists never cross: an app origin is
    /// only ever compared, as a whole string and case-sensitively, with the app list.
    /// </summary>
    /// <param name="origin">The origin from <c>clientDataJSON</c>.</param>
    public bool IsOriginAllowed(string? origin)
    {
        if (string.IsNullOrEmpty(origin) || origin.Any(char.IsWhiteSpace))
        {
            return false;
        }
        if (origin.StartsWith(AndroidAppOriginPrefix, StringComparison.Ordinal))
        {
            // A certificate hash is an identifier, not a URI: exact match or nothing.  The base64url
            // alphabet is case-sensitive, so a case-insensitive comparison would accept a different hash.
            return AllowedAppOrigins is not null && AllowedAppOrigins.Contains(origin, StringComparer.Ordinal);
        }
        if (!Uri.TryCreate(origin, UriKind.Absolute, out Uri? presented)
            || (presented.Scheme != Uri.UriSchemeHttps && presented.Scheme != Uri.UriSchemeHttp))
        {
            return false;
        }
        if (presented.AbsolutePath != "/" || !string.IsNullOrEmpty(presented.Query) || !string.IsNullOrEmpty(presented.Fragment) || !string.IsNullOrEmpty(presented.UserInfo))
        {
            // A browser origin is scheme://host[:port] and nothing else.
            return false;
        }
        foreach (string allowed in AllowedOrigins)
        {
            if (Uri.TryCreate(allowed, UriKind.Absolute, out Uri? allowedUri)
                && string.Equals(allowedUri.Scheme, presented.Scheme, StringComparison.OrdinalIgnoreCase)
                && string.Equals(allowedUri.Host, presented.Host, StringComparison.OrdinalIgnoreCase)
                && allowedUri.Port == presented.Port)
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsRegistrableSuffix(string host, string rpId)
    {
        return string.Equals(host, rpId, StringComparison.OrdinalIgnoreCase)
            || host.EndsWith("." + rpId, StringComparison.OrdinalIgnoreCase);
    }
}
