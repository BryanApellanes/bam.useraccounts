namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Why a passkey registration or assertion was refused.  Reported on results for the host's
/// logging and UX; the caller-facing message stays generic.
/// </summary>
public enum PasskeyVerificationFailure
{
    /// <summary>Verification succeeded.</summary>
    None,
    /// <summary>The response or its <c>clientDataJSON</c> could not be decoded.</summary>
    MalformedClientData,
    /// <summary>The <c>clientDataJSON</c> type was not the one expected for the ceremony.</summary>
    WrongType,
    /// <summary>The <c>clientDataJSON</c> challenge does not equal the issued challenge.</summary>
    ChallengeMismatch,
    /// <summary>The <c>clientDataJSON</c> origin is not an allowed origin.</summary>
    OriginNotAllowed,
    /// <summary>The authenticator data's RP id hash is not the hash of the configured RP id.</summary>
    RpIdMismatch,
    /// <summary>The user-present flag was not set.</summary>
    UserNotPresent,
    /// <summary>User verification is required and the user-verified flag was not set.</summary>
    UserNotVerified,
    /// <summary>The authenticator data could not be decoded.</summary>
    MalformedAuthenticatorData,
    /// <summary>The attestation object could not be decoded.</summary>
    MalformedAttestation,
    /// <summary>The credential's algorithm is not one the host offers.</summary>
    UnsupportedAlgorithm,
    /// <summary>The credential's public key is not a valid key for its algorithm.</summary>
    InvalidCredentialKey,
    /// <summary>The response id does not match the attested credential id.</summary>
    CredentialIdMismatch,
    /// <summary>A credential with this id is already stored.</summary>
    CredentialAlreadyRegistered,
    /// <summary>No stored credential matches the response id (or it belongs to another person).</summary>
    UnknownCredential,
    /// <summary>The authenticator's sign counter did not advance past the stored one.</summary>
    SignCountRegressed,
    /// <summary>The signature does not verify under the credential's public key.</summary>
    InvalidSignature,
    /// <summary>The pending challenge had expired.</summary>
    ChallengeExpired,
    /// <summary>No challenge was pending for the handle or ceremony.</summary>
    NoPendingChallenge,
    /// <summary>
    /// Sign-up was attempted for a handle that already has a passkey or a registered key set.
    /// Additional passkeys are added through the authenticated path.
    /// </summary>
    HandleAlreadyRegistered
}
