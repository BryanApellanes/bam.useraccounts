using Bam.Encryption;
using Bam.Protocol.Data;
using Bam.Protocol.Data.Profile;
using Bam.Protocol.Profile;

namespace Bam.UserAccounts.Tests.TestClasses;

/// <summary>Stands in for an administrative re-bind: anchors and verifies only while armed.</summary>
public sealed class RebindProof : IKeySetRotationProof
{
    /// <summary>Whether the proof anchors and verifies right now.</summary>
    public bool Armed { get; set; }

    /// <inheritdoc />
    public string Name => "test-rebind";

    /// <inheritdoc />
    public bool Anchors(PublicKeySetData current)
    {
        return Armed;
    }

    /// <inheritdoc />
    public ISignatureVerification Verify(PublicKeySetData current, PublicKeySetData proposed, byte[] proof)
    {
        return new KeySetRotationVerification { Success = Armed, Message = Armed ? "rebound" : "not armed", ProofName = Name };
    }
}
