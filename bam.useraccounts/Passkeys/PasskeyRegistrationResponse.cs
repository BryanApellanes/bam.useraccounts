using Newtonsoft.Json;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// What the browser returns from <c>navigator.credentials.create()</c>, as
/// <c>PublicKeyCredential.toJSON()</c> emits it (all binary fields base64url).
/// </summary>
public sealed record PasskeyRegistrationResponse
{
    /// <summary>The credential id, base64url.</summary>
    public string Id { get; init; } = null!;

    /// <summary>The credential id again, base64url.</summary>
    public string RawId { get; init; } = null!;

    /// <summary>Always <c>public-key</c>.</summary>
    public string Type { get; init; } = null!;

    /// <summary>The authenticator's attestation response.</summary>
    public PasskeyAttestationResponseData Response { get; init; } = null!;

    /// <summary>Parses the browser JSON.</summary>
    /// <exception cref="PasskeyFormatException">The JSON is not a registration response.</exception>
    public static PasskeyRegistrationResponse FromJson(byte[] utf8Json)
    {
        return PasskeyJson.Deserialize<PasskeyRegistrationResponse>(utf8Json);
    }

    /// <summary>Serializes to the browser JSON shape.</summary>
    public string ToJson()
    {
        return PasskeyJson.Serialize(this);
    }
}

/// <summary>The <c>response</c> member of a registration response.</summary>
public sealed record PasskeyAttestationResponseData
{
    /// <summary>The <c>clientDataJSON</c> bytes, base64url.</summary>
    [JsonProperty("clientDataJSON")]
    public string ClientDataJson { get; init; } = null!;

    /// <summary>The CBOR attestation object, base64url.</summary>
    public string AttestationObject { get; init; } = null!;

    /// <summary>The transports the authenticator reported, when the browser supplied them.</summary>
    public List<string>? Transports { get; init; }
}
