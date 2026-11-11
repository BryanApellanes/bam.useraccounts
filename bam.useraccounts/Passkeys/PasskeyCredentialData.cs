using Bam.Data.Repositories;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// One stored passkey credential.  Keyed by person handle and credential id; the public key is
/// kept as canonical PEM so <c>PublicKeyFingerprint.Of</c> and the framework key types work on
/// it directly.
/// </summary>
[Serializable]
public class PasskeyCredentialData : KeyedAuditRepoData
{
    /// <summary>The person the credential belongs to.</summary>
    [CompositeKey]
    public string PersonHandle { get; set; } = null!;

    /// <summary>The credential id, base64url.</summary>
    [CompositeKey]
    public string CredentialId { get; set; } = null!;

    /// <summary>The opaque WebAuthn user handle (32 random bytes), base64url; shared by all of a person's credentials.</summary>
    public string UserHandle { get; set; } = null!;

    /// <summary>The credential public key, PEM.</summary>
    public string PublicKeyPem { get; set; } = null!;

    /// <summary>The COSE algorithm number the credential signs with.</summary>
    public long Algorithm { get; set; }

    /// <summary>The last sign counter seen from the authenticator.</summary>
    public long SignCount { get; set; }

    /// <summary>The authenticator AAGUID, lowercase hex.</summary>
    public string Aaguid { get; set; } = string.Empty;

    /// <summary>The transports reported at registration, comma separated.</summary>
    public string Transports { get; set; } = string.Empty;

    /// <summary>Whether the authenticator flagged the credential as backup eligible.</summary>
    public bool BackupEligible { get; set; }

    /// <summary>Whether the authenticator flagged the credential as backed up.</summary>
    public bool BackedUp { get; set; }

    /// <summary>A host-assigned display name for the credential, if any.</summary>
    public string? Name { get; set; }

    /// <summary>When the credential was registered.</summary>
    public DateTime CreatedUtc { get; set; }

    /// <summary>When the credential last signed in, or null.</summary>
    public DateTime? LastUsedUtc { get; set; }

    /// <summary>Whether this credential's key is the person's registered key set.</summary>
    public bool IsRegisteredKeySet { get; set; }

    /// <summary>
    /// True from the moment the row is saved until <c>IPublicKeySetRegistrar</c> has accepted
    /// its key as the person's key set.  A pending credential is not usable: it cannot sign in
    /// or confirm an account, and it is not listed as one of the person's passkeys.  A pending
    /// row left behind by a stopped process is removed by the next registration for its handle.
    /// </summary>
    public bool Pending { get; set; }

    /// <summary>Set when an assertion reported a sign counter that did not advance (possible cloned authenticator); never cleared by the framework.</summary>
    public bool SignCountRegressed { get; set; }

    /// <summary>The transports as a list.</summary>
    public List<string> TransportList()
    {
        return string.IsNullOrEmpty(Transports)
            ? new List<string>()
            : Transports.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
    }
}
