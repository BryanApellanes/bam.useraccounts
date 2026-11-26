namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Moves a person's key set to a surviving passkey when the passkey that held it is lost
/// (bam.protocol#85, option 2).  The heir must be at least
/// <see cref="PasskeyOptions.RecoveryCredentialAge"/> old and must make a user-verified assertion
/// over the rotation; the key set then moves only after <see cref="PasskeyOptions.RecoveryDelay"/>,
/// and any signed-in session of the person can cancel it before then.  A lost passkey named in
/// <c>removes</c> leaves sign-in at once: only the key-set move waits.
/// <para>
/// No scheduler runs the move: <see cref="Settle"/> does it on the person's next request after the
/// delay (sign-in, the passkey list, the manage page).  Every method takes the handle of the person
/// the host has authenticated and never touches another person's credentials or recoveries.
/// </para>
/// </summary>
public interface IKeySetRecovery
{
    /// <summary>Whether this host can recover a key set: the recovery proof and the passkey rotation proof are both trusted.</summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Whether the person could start a recovery now: this host can recover, the person has a
    /// registered key set, no accepted passkey holds it, and no recovery is waiting.
    /// </summary>
    /// <param name="personHandle">The authenticated person's handle.</param>
    bool IsRecoverable(string personHandle);

    /// <summary>Begins a recovery: checks the rule and returns assertion options for the heir over the rotation's challenge.</summary>
    /// <param name="personHandle">The authenticated person's handle.</param>
    /// <param name="removesCredentialId">The lost key-set passkey to take out of sign-in, or null when it is already gone.</param>
    /// <param name="heirCredentialId">The passkey to move the key set to, or null for <paramref name="sessionCredentialId"/>.</param>
    /// <param name="sessionCredentialId">The passkey the person's session was opened with.</param>
    KeySetRecoveryStart Begin(string personHandle, string? removesCredentialId, string? heirCredentialId, string? sessionCredentialId);

    /// <summary>
    /// Completes a begun recovery with the heir's assertion: records it as waiting until
    /// <see cref="PasskeyOptions.RecoveryDelay"/> has passed, and removes the passkey named in
    /// <c>removes</c> from sign-in now.
    /// </summary>
    /// <param name="personHandle">The authenticated person's handle; must be the one the recovery began for.</param>
    /// <param name="recoveryId">The id <see cref="Begin"/> returned.</param>
    /// <param name="assertionJson">UTF-8 JSON of the heir's assertion (<c>PublicKeyCredential.toJSON()</c>).</param>
    KeySetRecoveryResult Complete(string personHandle, string? recoveryId, byte[]? assertionJson);

    /// <summary>Cancels the person's waiting recovery.  Logged with the passkey of the session that canceled it.</summary>
    /// <param name="personHandle">The authenticated person's handle.</param>
    /// <param name="recoveryId">The waiting recovery's id.</param>
    /// <param name="sessionCredentialId">The passkey the canceling session was opened with.</param>
    /// <returns>False when the person has no waiting recovery with that id (unknown, settled or already canceled).</returns>
    bool Cancel(string personHandle, string recoveryId, string? sessionCredentialId);

    /// <summary>
    /// Returns the person's waiting recovery, or null.  A recovery whose heir has been removed is
    /// canceled here (and logged) rather than shown.
    /// </summary>
    /// <param name="personHandle">The authenticated person's handle.</param>
    PendingKeySetRecoveryData? Pending(string personHandle);

    /// <summary>
    /// Moves the key set if the person's waiting recovery is due.  Never throws: it runs on
    /// ordinary requests, and a fault leaves the recovery waiting for the next one.
    /// </summary>
    /// <param name="personHandle">The authenticated person's handle.</param>
    KeySetRecoverySettlement Settle(string personHandle);
}
