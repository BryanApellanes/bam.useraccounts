using Bam.Data.Repositories;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// The key of a passkey the person removed (<see cref="IKeySetRecoveryRepository.RecordRemovedPasskeyKey"/>).
/// A lost-device recovery that names no passkey to remove may move only a key set holding one of
/// these keys: that is what shows the key set was a passkey's of this person, and not an admin
/// rebind or a device key.
/// </summary>
[Serializable]
public class RemovedPasskeyKeyData : KeyedAuditRepoData
{
    /// <summary>The person whose passkey it was.</summary>
    [CompositeKey]
    public string PersonHandle { get; set; } = null!;

    /// <summary>The canonical fingerprint of the removed passkey's key.</summary>
    [CompositeKey]
    public string KeyFingerprint { get; set; } = null!;

    /// <summary>The removed passkey's credential id.</summary>
    public string CredentialId { get; set; } = null!;

    /// <summary>When it was removed.</summary>
    public DateTime RemovedUtc { get; set; }
}
