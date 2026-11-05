using Bam.UserAccounts.Passkeys;

namespace Bam.UserAccounts.Tests.TestClasses;

/// <summary>
/// Wraps a credential repository and throws from <see cref="Save"/> when <see cref="SaveThrows"/>
/// is set, so tests can prove what the ceremony does when custody faults before the registrar.
/// </summary>
public sealed class FaultingPasskeyCredentialRepository : IPasskeyCredentialRepository
{
    private readonly IPasskeyCredentialRepository _inner;

    public FaultingPasskeyCredentialRepository(IPasskeyCredentialRepository inner)
    {
        _inner = inner;
    }

    public Exception? SaveThrows { get; set; }

    public int SaveCalls { get; private set; }

    public PasskeyCredentialData Save(PasskeyCredentialData credential)
    {
        SaveCalls++;
        if (SaveThrows is not null)
        {
            throw SaveThrows;
        }
        return _inner.Save(credential);
    }

    public PasskeyCredentialData? FindByCredentialId(string credentialId) => _inner.FindByCredentialId(credentialId);

    public IReadOnlyList<PasskeyCredentialData> FindByHandle(string personHandle) => _inner.FindByHandle(personHandle);

    public IReadOnlyList<PasskeyCredentialData> FindByUserHandle(string userHandle) => _inner.FindByUserHandle(userHandle);

    public void RecordUse(string credentialId, long signCount, DateTime usedUtc) => _inner.RecordUse(credentialId, signCount, usedUtc);

    public void FlagSignCountRegression(string credentialId) => _inner.FlagSignCountRegression(credentialId);

    public bool Remove(string credentialId) => _inner.Remove(credentialId);
}
