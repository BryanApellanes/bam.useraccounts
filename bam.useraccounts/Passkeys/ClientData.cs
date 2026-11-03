using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Parsed WebAuthn <c>clientDataJSON</c> (§5.8.1): the ceremony type, the challenge the browser
/// saw (base64url), the origin, and the cross-origin flag.  Keeps the raw bytes because the
/// signature covers their SHA-256, not a re-serialization.
/// </summary>
public sealed record ClientData
{
    /// <summary>The type expected at registration.</summary>
    public const string TypeCreate = "webauthn.create";

    /// <summary>The type expected at assertion.</summary>
    public const string TypeGet = "webauthn.get";

    private ClientData(string type, string challenge, string origin, bool crossOrigin, byte[] rawBytes)
    {
        Type = type;
        Challenge = challenge;
        Origin = origin;
        CrossOrigin = crossOrigin;
        RawBytes = rawBytes;
    }

    /// <summary>The ceremony type: <see cref="TypeCreate"/> or <see cref="TypeGet"/>.</summary>
    public string Type { get; }

    /// <summary>The challenge as the browser encoded it, base64url.</summary>
    public string Challenge { get; }

    /// <summary>The origin the browser was on.</summary>
    public string Origin { get; }

    /// <summary>Whether the ceremony ran in a cross-origin iframe.</summary>
    public bool CrossOrigin { get; }

    /// <summary>The exact bytes the browser produced.</summary>
    public byte[] RawBytes { get; }

    /// <summary>The SHA-256 of <see cref="RawBytes"/>, the second half of the signed payload.</summary>
    public byte[] Hash()
    {
        return SHA256.HashData(RawBytes);
    }

    /// <summary>
    /// Parses client data, reporting the reason instead of throwing when it is malformed.
    /// </summary>
    /// <param name="rawBytes">The <c>clientDataJSON</c> bytes.</param>
    /// <param name="clientData">The parsed data on success.</param>
    /// <param name="error">Why parsing failed, on failure.</param>
    public static bool TryParse(byte[]? rawBytes, out ClientData? clientData, out string? error)
    {
        clientData = null;
        error = null;
        if (rawBytes is null || rawBytes.Length == 0)
        {
            error = "clientDataJSON is empty.";
            return false;
        }
        JObject json;
        try
        {
            json = JObject.Parse(Encoding.UTF8.GetString(rawBytes));
        }
        catch (JsonException e)
        {
            error = "clientDataJSON is not valid JSON: " + e.Message;
            return false;
        }
        catch (ArgumentException e)
        {
            error = "clientDataJSON is not valid UTF-8 JSON: " + e.Message;
            return false;
        }
        string? type = json.Value<string>("type");
        string? challenge = json.Value<string>("challenge");
        string? origin = json.Value<string>("origin");
        if (string.IsNullOrEmpty(type) || string.IsNullOrEmpty(challenge) || string.IsNullOrEmpty(origin))
        {
            error = "clientDataJSON is missing type, challenge or origin.";
            return false;
        }
        bool crossOrigin = json.Value<bool?>("crossOrigin") ?? false;
        clientData = new ClientData(type, challenge, origin, crossOrigin, rawBytes);
        return true;
    }

    /// <summary>Parses client data.</summary>
    /// <exception cref="PasskeyFormatException">The bytes are not valid client data.</exception>
    public static ClientData Parse(byte[] rawBytes)
    {
        if (!TryParse(rawBytes, out ClientData? clientData, out string? error))
        {
            throw new PasskeyFormatException(error!);
        }
        return clientData!;
    }
}
