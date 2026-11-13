using System.Security.Cryptography;
using System.Text;
using Bam.Encryption;
using Bam.Logging;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Profile;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Proves a key-set rotation with a WebAuthn assertion (bam.useraccounts#20).  The proof bytes
/// are the UTF-8 JSON of a <see cref="PasskeyAssertionResponse"/> made by the passkey whose key
/// <i>is</i> the current key set, over the challenge SHA-256 of
/// <see cref="KeySetRotationPayload.ComposeFor"/>(current, proposed).  So the assertion proves
/// possession of that passkey and names the exact rotation: another proposed key set, or the
/// same proposal from another current key set, needs another assertion.
/// <para>
/// It anchors only a key set that is exactly one stored, accepted passkey's key under that
/// passkey's own handle (<see cref="PasskeyKeySet.IsHeldBy"/>).  It never widens who can rotate
/// an RSA key set from a device key, or a key set with two keys: those have no passkey holding
/// them.  Failure messages never carry the assertion or any key: the chain logs them.
/// </para>
/// </summary>
public sealed class PasskeyKeySetRotationProof : IKeySetRotationProof
{
    /// <summary>The name recorded when this proof authorizes a rotation (<c>RevokedBy = rotation:passkey</c>).</summary>
    public const string ProofName = "passkey";

    private readonly IPasskeyCredentialRepository _credentials;
    private readonly Func<PasskeyCeremony> _ceremony;

    /// <summary>Initializes the proof over passkey custody and the ceremony that verifies assertions.</summary>
    /// <param name="credentials">Passkey custody.</param>
    /// <param name="ceremony">The ceremony; its <c>Assert</c> verifies the assertion and records the sign counter.</param>
    public PasskeyKeySetRotationProof(IPasskeyCredentialRepository credentials, PasskeyCeremony ceremony)
        : this(credentials, () => ceremony)
    {
        ArgumentNullException.ThrowIfNull(ceremony);
    }

    /// <summary>
    /// Initializes the proof with the ceremony resolved on first use.  The ceremony depends on the
    /// registrar, which depends on the proof list this proof is added to, so a registration-time
    /// proof can't take the ceremony itself.
    /// </summary>
    /// <param name="credentials">Passkey custody.</param>
    /// <param name="ceremony">Resolves the ceremony when a rotation is verified.</param>
    public PasskeyKeySetRotationProof(IPasskeyCredentialRepository credentials, Func<PasskeyCeremony> ceremony)
    {
        ArgumentNullException.ThrowIfNull(credentials);
        ArgumentNullException.ThrowIfNull(ceremony);
        _credentials = credentials;
        _ceremony = ceremony;
    }

    /// <inheritdoc />
    public string Name => ProofName;

    /// <summary>
    /// The challenge a rotation assertion is made over: SHA-256 of the UTF-8
    /// <see cref="KeySetRotationPayload.ComposeFor"/> of the rotation, which opens with the
    /// rotation context tag for every passkey key set without an RSA key.
    /// </summary>
    /// <param name="current">The registered key set being rotated away from.</param>
    /// <param name="proposed">The key set being rotated to.</param>
    /// <returns>The 32 challenge bytes.</returns>
    public static byte[] Challenge(PublicKeySetData current, PublicKeySetData proposed)
    {
        return SHA256.HashData(Encoding.UTF8.GetBytes(KeySetRotationPayload.ComposeFor(current, proposed)));
    }

    /// <inheritdoc />
    public bool Anchors(PublicKeySetData current)
    {
        return HoldingCredential(current) is not null;
    }

    /// <inheritdoc />
    public ISignatureVerification Verify(PublicKeySetData current, PublicKeySetData proposed, byte[] proof)
    {
        if (current is null || proposed is null || !string.Equals(current.KeySetHandle, proposed.KeySetHandle, StringComparison.Ordinal))
        {
            return Failed("The rotation does not stay on one handle.");
        }
        PasskeyCredentialData? holder = HoldingCredential(current);
        if (holder is null)
        {
            return Failed("No passkey holds the current key set.");
        }
        PasskeyAssertionResponse? response;
        try
        {
            response = proof is null || proof.Length == 0 ? null : PasskeyAssertionResponse.FromJson(proof);
        }
        catch (PasskeyFormatException)
        {
            // The format exception's message can quote the caller's bytes; the chain logs ours.
            return Failed("The proof is not a passkey assertion.");
        }
        if (response is null || !string.Equals(response.Id, holder.CredentialId, StringComparison.Ordinal))
        {
            return Failed("The assertion is not by the passkey that holds the current key set.");
        }
        PasskeySignInResult result = _ceremony().Assert(response, Challenge(current, proposed), holder);
        if (!result.Success)
        {
            return Failed("The assertion did not verify: " + result.Failure);
        }
        return new SignatureVerification
        {
            Success = true,
            Message = string.Empty,
            IssuerPublicKey = null!,
            Signature = new Signature { SignatureBytes = Array.Empty<byte>(), Data = string.Empty, Algorithm = holder.Algorithm.ToString(System.Globalization.CultureInfo.InvariantCulture) }
        };
    }

    // The one accepted credential of the key set's handle whose key is exactly the key set.  Never
    // throws: Anchors is asked outside the registrar's try block, so a custody fault answers "no".
    private PasskeyCredentialData? HoldingCredential(PublicKeySetData? keySet)
    {
        if (keySet is null || string.IsNullOrWhiteSpace(keySet.KeySetHandle))
        {
            return null;
        }
        try
        {
            return _credentials.FindByHandle(keySet.KeySetHandle).FirstOrDefault(credential => !credential.Pending && PasskeyKeySet.IsHeldBy(keySet, credential));
        }
        catch (Exception e)
        {
            Log.Warn("Passkey rotation proof could not read the credentials of {0}: {1}", PasskeyText.Printable(keySet.KeySetHandle), PasskeyText.Printable(e.Message, PasskeyVerification.MaxDetailLength));
            return null;
        }
    }

    private static SignatureVerification Failed(string message)
    {
        return new SignatureVerification { Success = false, Message = message, IssuerPublicKey = null!, Signature = null! };
    }
}
