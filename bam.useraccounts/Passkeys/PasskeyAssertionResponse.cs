using System.Text;
using Newtonsoft.Json;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// What the browser returns from <c>navigator.credentials.get()</c>, as
/// <c>PublicKeyCredential.toJSON()</c> emits it, plus the <see cref="CeremonyId"/> echoed from
/// <see cref="PasskeyRequestOptions"/>.
/// </summary>
public sealed record PasskeyAssertionResponse
{
    /// <summary>The credential id, base64url.</summary>
    public string Id { get; init; } = null!;

    /// <summary>The credential id again, base64url.</summary>
    public string RawId { get; init; } = null!;

    /// <summary>Always <c>public-key</c>.</summary>
    public string Type { get; init; } = null!;

    /// <summary>The authenticator's assertion response.</summary>
    public PasskeyAssertionResponseData Response { get; init; } = null!;

    /// <summary>The ceremony id from the request options, when the challenge was issued by <see cref="IPasskeyCeremony.BeginAssertion"/>.</summary>
    public string? CeremonyId { get; init; }

    /// <summary>Parses the browser JSON.</summary>
    /// <exception cref="PasskeyFormatException">The JSON is not an assertion response.</exception>
    public static PasskeyAssertionResponse FromJson(byte[] utf8Json)
    {
        return PasskeyJson.Deserialize<PasskeyAssertionResponse>(utf8Json);
    }

    /// <summary>Serializes to the browser JSON shape.</summary>
    public string ToJson()
    {
        return PasskeyJson.Serialize(this);
    }

    /// <summary>Serializes to UTF-8 JSON bytes, the form <see cref="IAccountConfirmation.VerifySignedChallenge"/> accepts as the signed challenge.</summary>
    public byte[] ToJsonBytes()
    {
        return Encoding.UTF8.GetBytes(ToJson());
    }
}

/// <summary>The <c>response</c> member of an assertion response.</summary>
public sealed record PasskeyAssertionResponseData
{
    /// <summary>The <c>clientDataJSON</c> bytes, base64url.</summary>
    [JsonProperty("clientDataJSON")]
    public string ClientDataJson { get; init; } = null!;

    /// <summary>The authenticator data bytes, base64url.</summary>
    public string AuthenticatorData { get; init; } = null!;

    /// <summary>The signature bytes, base64url (ASN.1 DER for ECDSA).</summary>
    public string Signature { get; init; } = null!;

    /// <summary>The user handle the authenticator stored at registration, base64url, when it returned one.</summary>
    public string? UserHandle { get; init; }
}
