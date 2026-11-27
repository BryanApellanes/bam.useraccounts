using Bam.UserAccounts.Passkeys;

namespace Bam.UserAccounts.Tests.TestClasses;

/// <summary>
/// A process-local <see cref="IKeySetRecoveryRepository"/> for tests that can do what a real store
/// can do to its rows outside the code: fail one read the way a store times out
/// (<see cref="FailOneReadAfter"/>), and have a row rewritten at rest (<see cref="RewriteAtRest"/>),
/// which <see cref="IKeySetRecoveryRepository.Update"/> never does.
/// </summary>
public sealed class FaultingKeySetRecoveryRepository : IKeySetRecoveryRepository
{
    private readonly InMemoryKeySetRecoveryRepository _inner = new InMemoryKeySetRecoveryRepository();
    private readonly Dictionary<string, PendingKeySetRecoveryData> _rewritten = new Dictionary<string, PendingKeySetRecoveryData>();
    private int _readsBeforeFault = -1;
    private bool _keepFailing;

    /// <summary>Lets <paramref name="reads"/> reads through, then throws once.</summary>
    /// <param name="reads">How many reads succeed before the fault.</param>
    public void FailOneReadAfter(int reads)
    {
        _readsBeforeFault = reads;
        _keepFailing = false;
    }

    /// <summary>Lets <paramref name="reads"/> reads through, then throws on every read until <see cref="Heal"/>.</summary>
    /// <param name="reads">How many reads succeed before the outage.</param>
    public void FailReadsAfter(int reads)
    {
        _readsBeforeFault = reads;
        _keepFailing = true;
    }

    /// <summary>Ends an outage: every read succeeds again.</summary>
    public void Heal()
    {
        _readsBeforeFault = -1;
        _keepFailing = false;
    }

    /// <summary>How many reads have thrown.</summary>
    public int Faults { get; private set; }

    /// <summary>Replaces a stored row wholesale, as someone with access to the store could.</summary>
    /// <param name="row">The row as it should read from now on.</param>
    public void RewriteAtRest(PendingKeySetRecoveryData row)
    {
        _rewritten[Key(row.PersonHandle, row.RecoveryId)] = Copy(row);
    }

    /// <inheritdoc />
    public PendingKeySetRecoveryData Save(PendingKeySetRecoveryData recovery)
    {
        return _inner.Save(recovery);
    }

    /// <inheritdoc />
    public IReadOnlyList<PendingKeySetRecoveryData> FindByHandle(string personHandle)
    {
        Read();
        return _inner.FindByHandle(personHandle).Select(Overlay).ToList();
    }

    /// <inheritdoc />
    public PendingKeySetRecoveryData? Find(string personHandle, string recoveryId)
    {
        Read();
        PendingKeySetRecoveryData? row = _inner.Find(personHandle, recoveryId);
        return row is null ? null : Overlay(row);
    }

    /// <inheritdoc />
    public bool Update(PendingKeySetRecoveryData recovery)
    {
        if (_rewritten.TryGetValue(Key(recovery.PersonHandle, recovery.RecoveryId), out PendingKeySetRecoveryData? rewritten))
        {
            rewritten.AdvanceFrom(recovery);
        }
        return _inner.Update(recovery);
    }

    /// <inheritdoc />
    public void RecordRemovedPasskeyKey(string personHandle, string credentialId, string keyFingerprint)
    {
        _inner.RecordRemovedPasskeyKey(personHandle, credentialId, keyFingerprint);
    }

    /// <inheritdoc />
    public bool WasRemovedPasskeyKey(string personHandle, string keyFingerprint)
    {
        return _inner.WasRemovedPasskeyKey(personHandle, keyFingerprint);
    }

    private PendingKeySetRecoveryData Overlay(PendingKeySetRecoveryData row)
    {
        return _rewritten.TryGetValue(Key(row.PersonHandle, row.RecoveryId), out PendingKeySetRecoveryData? rewritten) ? Copy(rewritten) : row;
    }

    private void Read()
    {
        if (_readsBeforeFault < 0)
        {
            return;
        }
        if (_readsBeforeFault == 0)
        {
            if (!_keepFailing)
            {
                _readsBeforeFault = -1;
            }
            Faults++;
            throw new TimeoutException("the recovery store timed out");
        }
        _readsBeforeFault--;
    }

    private static string Key(string personHandle, string recoveryId)
    {
        return personHandle + "\n" + recoveryId;
    }

    private static PendingKeySetRecoveryData Copy(PendingKeySetRecoveryData row)
    {
        return new PendingKeySetRecoveryData
        {
            PersonHandle = row.PersonHandle,
            RecoveryId = row.RecoveryId,
            RemovedCredentialId = row.RemovedCredentialId,
            RemovedKeyFingerprint = row.RemovedKeyFingerprint,
            HeirCredentialId = row.HeirCredentialId,
            HeirKeyFingerprint = row.HeirKeyFingerprint,
            Anchor = row.Anchor,
            AssertionJson = row.AssertionJson,
            BeganUtc = row.BeganUtc,
            EffectiveUtc = row.EffectiveUtc,
            CanceledUtc = row.CanceledUtc,
            CancelReason = row.CancelReason,
            CanceledByCredentialId = row.CanceledByCredentialId,
            CompletedUtc = row.CompletedUtc
        };
    }
}
