namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// The WebAuthn <c>PublicKeyCredentialRequestOptions</c> a host sends to the browser for
/// <c>navigator.credentials.get()</c>, plus the <see cref="CeremonyId"/> the browser response must
/// echo so the server can find the pending challenge.
/// </summary>
public sealed record PasskeyRequestOptions
{
    /// <summary>The challenge, base64url.</summary>
    public string Challenge { get; init; } = null!;

    /// <summary>The RP id.</summary>
    public string RpId { get; init; } = null!;

    /// <summary>The timeout hint in milliseconds.</summary>
    public long Timeout { get; init; }

    /// <summary>The credentials the browser may use; empty lets the browser offer discoverable passkeys.</summary>
    public List<PasskeyCredentialDescriptor> AllowCredentials { get; init; } = new List<PasskeyCredentialDescriptor>();

    /// <summary>The user-verification preference.</summary>
    public string UserVerification { get; init; } = "preferred";

    /// <summary>
    /// Identifies the pending challenge; the host must put it on the
    /// <see cref="PasskeyAssertionResponse.CeremonyId"/> it posts back.  Null for a confirmation
    /// challenge, whose pending record is keyed by the person handle instead.
    /// </summary>
    public string? CeremonyId { get; init; }

    /// <summary>Serializes to the WebAuthn JSON shape.</summary>
    public string ToJson()
    {
        return PasskeyJson.Serialize(this);
    }
}
