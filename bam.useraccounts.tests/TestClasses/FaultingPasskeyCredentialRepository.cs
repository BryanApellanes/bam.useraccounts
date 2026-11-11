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

    public Exception? RemoveThrows { get; set; }

    public Exception? ActivateThrows { get; set; }

    /// <summary>
    /// A credential id <see cref="FindByCredentialId"/> answers null for until the next
    /// <see cref="Save"/>: a registration that read custody before another registration saved
    /// the same credential id.
    /// </summary>
    public string? StaleReadOf { get; set; }

    public int SaveCalls { get; private set; }

    public PasskeyCredentialData Save(PasskeyCredentialData credential)
    {
        SaveCalls++;
        StaleReadOf = null;
        if (SaveThrows is not null)
        {
            throw SaveThrows;
        }
        return _inner.Save(credential);
    }

    public PasskeyCredentialData? FindByCredentialId(string credentialId)
    {
        return string.Equals(credentialId, StaleReadOf, StringComparison.Ordinal) ? null : _inner.FindByCredentialId(credentialId);
    }

    public IReadOnlyList<PasskeyCredentialData> FindByHandle(string personHandle) => _inner.FindByHandle(personHandle);

    public IReadOnlyList<PasskeyCredentialData> FindByUserHandle(string userHandle) => _inner.FindByUserHandle(userHandle);

    public void RecordUse(string credentialId, long signCount, DateTime usedUtc) => _inner.RecordUse(credentialId, signCount, usedUtc);

    public void FlagSignCountRegression(string credentialId) => _inner.FlagSignCountRegression(credentialId);

    public bool Activate(string personHandle, string credentialId)
    {
        if (ActivateThrows is not null)
        {
            throw ActivateThrows;
        }
        return _inner.Activate(personHandle, credentialId);
    }

    public bool Remove(string personHandle, string credentialId)
    {
        if (RemoveThrows is not null)
        {
            throw RemoveThrows;
        }
        return _inner.Remove(personHandle, credentialId);
    }
}
