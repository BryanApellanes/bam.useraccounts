using Bam.UserAccounts.Passkeys;

namespace Bam.UserAccounts.Web;

/// <summary>
/// What the page hands the browser module: where the endpoints are, the header to send, and the
/// host's wording for the messages the module shows on its own.  Serialized into a data
/// attribute on the page shell.
/// </summary>
public sealed class AccountClientConfig
{
    /// <summary>The endpoint prefix.</summary>
    public string Prefix { get; set; } = AccountRoutes.Prefix;

    /// <summary>The header every state-changing request carries.</summary>
    public string Header { get; set; } = AccountRoutes.RequestHeader;

    /// <summary>Whether the handle availability check is mapped.</summary>
    public bool Availability { get; set; }

    /// <summary>Messages by key.</summary>
    public Dictionary<string, string> Messages { get; set; } = new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>Builds the configuration for a host's options.</summary>
    /// <param name="site">The host's account options.</param>
    public static AccountClientConfig For(AccountSiteOptions site)
    {
        ArgumentNullException.ThrowIfNull(site);
        AccountStrings strings = site.Strings;
        AccountClientConfig config = new AccountClientConfig { Availability = site.SignUp.AllowHandleAvailabilityCheck };
        config.Messages["cancelled"] = strings.CancelledMessage;
        config.Messages["unsupported"] = strings.UnsupportedMessage;
        config.Messages["rateLimited"] = strings.RateLimitedMessage;
        config.Messages["signUpFailed"] = strings.SignUpFailedMessage;
        config.Messages["signInFailed"] = strings.SignInFailedMessage;
        config.Messages["actionFailed"] = strings.ActionFailedMessage;
        config.Messages["working"] = strings.WorkingMessage;
        config.Messages["removeConfirmation"] = strings.RemoveConfirmation;
        config.Messages["handleTaken"] = strings.HandleTakenMessage;
        config.Messages["handleInvalid"] = strings.HandleInvalidMessage;
        config.Messages["handleAvailable"] = strings.HandleAvailableMessage;
        return config;
    }

    /// <summary>The configuration as JSON.</summary>
    public string ToJson()
    {
        return PasskeyJson.Serialize(this);
    }
}
