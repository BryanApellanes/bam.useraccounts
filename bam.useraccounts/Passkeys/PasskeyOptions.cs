using Bam.Encryption.Cose;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Relying-party policy for passkey (WebAuthn) ceremonies: the RP id and name, the origins a
/// browser may present, whether user verification is required, challenge lifetime and the
/// algorithms offered at registration.  Call <see cref="Validate"/> (done by
/// <see cref="PasskeysServiceRegistration.AddPasskeys"/>) before use.
/// </summary>
public sealed class PasskeyOptions
{
    /// <summary>The RP id: a registrable domain suffix of every allowed origin's host (e.g. <c>lumberjack.live</c>).</summary>
    public string RpId { get; set; } = null!;

    /// <summary>The human-readable relying-party name shown by the authenticator.</summary>
    public string RpName { get; set; } = null!;

    /// <summary>The exact origins (scheme, host, port) a browser may present in <c>clientDataJSON</c>.</summary>
    public List<string> AllowedOrigins { get; set; } = new List<string>();

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
    /// absolute http(s) origin whose host is the RP id or a subdomain of it, and at least one
    /// supported algorithm.
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
    /// on scheme, host (case-insensitively) and port.
    /// </summary>
    /// <param name="origin">The origin from <c>clientDataJSON</c>.</param>
    public bool IsOriginAllowed(string? origin)
    {
        if (string.IsNullOrEmpty(origin) || !Uri.TryCreate(origin, UriKind.Absolute, out Uri? presented))
        {
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
