using Bam.Encryption.Cose;
using Bam.Protocol.Data.Profile;
using Bam.Protocol.Profile;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// The key set a passkey registers as, or rotates to, in <c>bam.protocol</c>: one key, in the
/// RSA slot for an RS256 credential and in the ECC slot for an ES256 one.  Shared by sign-up
/// (the first passkey becomes the key set) and the key-set handover (bam.useraccounts#20), so
/// both build exactly the same key set from a credential.
/// </summary>
public static class PasskeyKeySet
{
    /// <summary>Builds the key set a credential with this algorithm and key registers as.</summary>
    /// <param name="personHandle">The handle the key set is for.</param>
    /// <param name="algorithm">The credential's COSE algorithm.</param>
    /// <param name="publicKeyPem">The credential's public key, PEM.</param>
    /// <returns>A key set holding the one key in the slot its algorithm calls for.</returns>
    public static PublicKeySetData From(string personHandle, CoseAlgorithm algorithm, string publicKeyPem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(personHandle);
        ArgumentException.ThrowIfNullOrWhiteSpace(publicKeyPem);
        PublicKeySetData keySet = new PublicKeySetData { KeySetHandle = personHandle };
        if (CoseAlgorithms.KeyType(algorithm) == CoseAlgorithms.KeyTypeRsa)
        {
            keySet.PublicRsaKey = publicKeyPem;
        }
        else
        {
            keySet.PublicEccKey = publicKeyPem;
        }
        return keySet;
    }

    /// <summary>Builds the key set a stored credential registers as, under its own handle.</summary>
    /// <param name="credential">The stored credential.</param>
    /// <returns>A key set holding the credential's key.</returns>
    /// <exception cref="ArgumentException">The credential's algorithm is not one passkeys support.</exception>
    public static PublicKeySetData From(PasskeyCredentialData credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        if (!CoseAlgorithms.IsSupported(credential.Algorithm))
        {
            throw new ArgumentException("The credential's algorithm is not a supported passkey algorithm.", nameof(credential));
        }
        return From(credential.PersonHandle, (CoseAlgorithm)credential.Algorithm, credential.PublicKeyPem);
    }

    /// <summary>
    /// Whether <paramref name="keySet"/> is exactly the key set <paramref name="credential"/>
    /// registers as: same handle, one key, and that key is the credential's.  Keys are compared by
    /// canonical fingerprint, never by PEM text, so a re-encoded key still matches.
    /// </summary>
    /// <param name="keySet">A registered or proposed key set.</param>
    /// <param name="credential">A stored credential.</param>
    public static bool IsHeldBy(PublicKeySetData? keySet, PasskeyCredentialData? credential)
    {
        if (keySet is null || credential is null || !string.Equals(keySet.KeySetHandle, credential.PersonHandle, StringComparison.Ordinal))
        {
            return false;
        }
        bool hasRsa = !string.IsNullOrEmpty(keySet.PublicRsaKey);
        bool hasEcc = !string.IsNullOrEmpty(keySet.PublicEccKey);
        if (hasRsa == hasEcc)
        {
            // Neither key, or both: a passkey key set holds exactly one.
            return false;
        }
        string? keySetKey = PublicKeyFingerprint.Of(hasRsa ? keySet.PublicRsaKey : keySet.PublicEccKey);
        string? credentialKey = PublicKeyFingerprint.Of(credential.PublicKeyPem);
        return keySetKey is not null && string.Equals(keySetKey, credentialKey, StringComparison.Ordinal);
    }

    /// <summary>
    /// Whether the credential's key is one of the keys of <paramref name="keySet"/>, under the
    /// credential's own handle.  Weaker than <see cref="IsHeldBy"/>: a key set with two keys can
    /// contain a passkey's key without being that passkey's key set.
    /// </summary>
    /// <param name="keySet">A registered key set.</param>
    /// <param name="credential">A stored credential.</param>
    public static bool Contains(PublicKeySetData? keySet, PasskeyCredentialData? credential)
    {
        if (keySet is null || credential is null || !string.Equals(keySet.KeySetHandle, credential.PersonHandle, StringComparison.Ordinal))
        {
            return false;
        }
        string? credentialKey = PublicKeyFingerprint.Of(credential.PublicKeyPem);
        if (credentialKey is null)
        {
            return false;
        }
        string? registeredRsa = string.IsNullOrEmpty(keySet.PublicRsaKey) ? null : PublicKeyFingerprint.Of(keySet.PublicRsaKey);
        string? registeredEcc = string.IsNullOrEmpty(keySet.PublicEccKey) ? null : PublicKeyFingerprint.Of(keySet.PublicEccKey);
        return string.Equals(credentialKey, registeredRsa, StringComparison.Ordinal) || string.Equals(credentialKey, registeredEcc, StringComparison.Ordinal);
    }
}
