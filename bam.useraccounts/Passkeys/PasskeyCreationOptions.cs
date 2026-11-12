namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// The WebAuthn <c>PublicKeyCredentialCreationOptions</c> a host sends to the browser for
/// <c>navigator.credentials.create()</c>; binary fields are base64url so the JSON can be passed to
/// <c>PublicKeyCredential.parseCreationOptionsFromJSON()</c> unchanged.
/// </summary>
public sealed record PasskeyCreationOptions
{
    /// <summary>The relying party.</summary>
    public PasskeyRelyingParty Rp { get; init; } = null!;

    /// <summary>The user entity; <see cref="PasskeyUser.Id"/> is the opaque user handle.</summary>
    public PasskeyUser User { get; init; } = null!;

    /// <summary>The challenge, base64url.</summary>
    public string Challenge { get; init; } = null!;

    /// <summary>The algorithms offered, in preference order.</summary>
    public List<PasskeyCredentialParameter> PubKeyCredParams { get; init; } = new List<PasskeyCredentialParameter>();

    /// <summary>The timeout hint in milliseconds.</summary>
    public long Timeout { get; init; }

    /// <summary>The attestation conveyance preference; always <c>none</c>.</summary>
    public string Attestation { get; init; } = "none";

    /// <summary>Authenticator selection criteria.</summary>
    public PasskeyAuthenticatorSelection AuthenticatorSelection { get; init; } = null!;

    /// <summary>Credentials already registered for the user, so the authenticator refuses to create a duplicate.</summary>
    public List<PasskeyCredentialDescriptor> ExcludeCredentials { get; init; } = new List<PasskeyCredentialDescriptor>();

    /// <summary>Serializes to the WebAuthn JSON shape.</summary>
    public string ToJson()
    {
        return PasskeyJson.Serialize(this);
    }
}

/// <summary>The <c>rp</c> entity.</summary>
public sealed record PasskeyRelyingParty
{
    /// <summary>The RP id.</summary>
    public string Id { get; init; } = null!;

    /// <summary>The RP display name.</summary>
    public string Name { get; init; } = null!;
}

/// <summary>The <c>user</c> entity.</summary>
public sealed record PasskeyUser
{
    /// <summary>The opaque user handle, base64url (never the person handle or an email).</summary>
    public string Id { get; init; } = null!;

    /// <summary>The account name shown by the authenticator.</summary>
    public string Name { get; init; } = null!;

    /// <summary>The display name shown by the authenticator.</summary>
    public string DisplayName { get; init; } = null!;
}

/// <summary>One <c>pubKeyCredParams</c> entry.</summary>
public sealed record PasskeyCredentialParameter
{
    /// <summary>Always <c>public-key</c>.</summary>
    public string Type { get; init; } = "public-key";

    /// <summary>The COSE algorithm number.</summary>
    public long Alg { get; init; }
}

/// <summary>The <c>authenticatorSelection</c> entry.</summary>
public sealed record PasskeyAuthenticatorSelection
{
    /// <summary>The resident-key preference (<c>discouraged</c>, <c>preferred</c>, <c>required</c>).</summary>
    public string ResidentKey { get; init; } = "preferred";

    /// <summary>The Level 1 form of <see cref="ResidentKey"/>: true exactly when it is <c>required</c>, for browsers that predate <c>residentKey</c>.</summary>
    public bool RequireResidentKey { get; init; }

    /// <summary>The user-verification preference (<c>discouraged</c>, <c>preferred</c>, <c>required</c>).</summary>
    public string UserVerification { get; init; } = "preferred";
}

/// <summary>A <c>PublicKeyCredentialDescriptor</c>, used in <c>excludeCredentials</c> and <c>allowCredentials</c>.</summary>
public sealed record PasskeyCredentialDescriptor
{
    /// <summary>Always <c>public-key</c>.</summary>
    public string Type { get; init; } = "public-key";

    /// <summary>The credential id, base64url.</summary>
    public string Id { get; init; } = null!;

    /// <summary>The transports the credential reported at registration, when known.</summary>
    public List<string>? Transports { get; init; }
}
