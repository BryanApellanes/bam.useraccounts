using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// The JSON conventions shared by the passkey DTOs: camelCase names, nulls omitted, so the
/// shapes match what <c>PublicKeyCredential.toJSON()</c> and
/// <c>PublicKeyCredential.parseCreationOptionsFromJSON()</c> expect.
/// </summary>
public static class PasskeyJson
{
    /// <summary>The serializer settings used by every passkey DTO.</summary>
    public static readonly JsonSerializerSettings Settings = new JsonSerializerSettings
    {
        ContractResolver = new CamelCasePropertyNamesContractResolver(),
        NullValueHandling = NullValueHandling.Ignore
    };

    /// <summary>Serializes a DTO with the passkey conventions.</summary>
    public static string Serialize(object value)
    {
        return JsonConvert.SerializeObject(value, Settings);
    }

    /// <summary>Deserializes UTF-8 JSON with the passkey conventions.</summary>
    /// <exception cref="PasskeyFormatException">The bytes are not valid JSON for the type.</exception>
    public static T Deserialize<T>(byte[] utf8Json) where T : class
    {
        ArgumentNullException.ThrowIfNull(utf8Json);
        try
        {
            T? value = JsonConvert.DeserializeObject<T>(Encoding.UTF8.GetString(utf8Json), Settings);
            if (value is null)
            {
                throw new PasskeyFormatException($"JSON did not produce a {typeof(T).Name}.");
            }
            return value;
        }
        catch (JsonException e)
        {
            throw new PasskeyFormatException($"JSON is not a valid {typeof(T).Name}: {e.Message}", e);
        }
    }
}
