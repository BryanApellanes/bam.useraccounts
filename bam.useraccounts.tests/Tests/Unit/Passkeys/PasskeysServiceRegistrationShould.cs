using Bam.Data.Repositories;
using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Protocol;
using Bam.Protocol.Data;
using Bam.Test;
using Bam.UserAccounts.Passkeys;
using Bam.UserAccounts.Tests.TestClasses;
using NSubstitute;

namespace Bam.UserAccounts.Tests.Unit.Passkeys;

[UnitTestMenu("PasskeysServiceRegistration Should", Selector = "pksr")]
public class PasskeysServiceRegistrationShould : UnitTestMenuContainer
{
    public PasskeysServiceRegistrationShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    private static ServiceRegistry HostRegistry()
    {
        ServiceRegistry registry = new ServiceRegistry();
        registry.For<IRepository>().Use(Substitute.For<IRepository>());
        registry.For<IProfileRepository>().Use(Substitute.For<IProfileRepository>());
        registry.For<ICertificateManager>().Use(Substitute.For<ICertificateManager>());
        registry.For<IPublicKeySetRegistrar>().Use(Substitute.For<IPublicKeySetRegistrar>());
        return registry;
    }

    [UnitTest]
    public void ResolveTheCeremonyAndAdapters()
    {
        After.Setup(reg => reg.For<ServiceRegistry>().Use(HostRegistry().AddPasskeys(PasskeyFixture.DefaultOptions())))
        .When<ServiceRegistry>("resolves everything AddPasskeys registers", (registry, reg) =>
        {
            return new ResolutionOutcome(
                registry.Get<IPasskeyCeremony>(),
                registry.Get<PasskeyAccountConfirmation>(),
                registry.Get<PasskeyChallengeSignatureVerifier>(),
                registry.Get<IDetachedSignatureVerifier>(),
                registry.Get<IConfirmationChallengeRepository>(),
                registry.Get<IPasskeyCredentialRepository>(),
                ReferenceEquals(registry.Get<IPasskeyCredentialRepository>(), registry.Get<IPasskeyCredentialRepository>()),
                ReferenceEquals(registry.Get<IConfirmationChallengeRepository>(), registry.Get<IConfirmationChallengeRepository>()),
                ReferenceEquals(registry.Get<PasskeyOptions>(), registry.Get<PasskeyOptions>()),
                registry.Get<IAccountConfirmation>(),
                registry.Get<IChallengeSignatureVerifier>());
        })
        .TheTest
        .ShouldPass<ResolutionOutcome>((because, outcome) =>
        {
            because.ItsTrue("IPasskeyCeremony resolves to PasskeyCeremony", outcome.Ceremony is PasskeyCeremony);
            because.ItsTrue("PasskeyAccountConfirmation resolves", outcome.Confirmation is not null);
            because.ItsTrue("PasskeyChallengeSignatureVerifier resolves", outcome.ChallengeVerifier is not null);
            because.ItsTrue("IDetachedSignatureVerifier defaults to DetachedSignatureVerifier", outcome.SignatureVerifier is DetachedSignatureVerifier);
            because.ItsTrue("challenge custody defaults to the persisted repository", outcome.Challenges is PersistedConfirmationChallengeRepository);
            because.ItsTrue("credential custody defaults to the persisted repository", outcome.Credentials is PersistedPasskeyCredentialRepository);
            because.ItsTrue("credential custody is a singleton", outcome.SameCredentials);
            because.ItsTrue("challenge custody is a singleton", outcome.SameChallenges);
            because.ItsTrue("options are a singleton", outcome.SameOptions);
            because.ItsTrue("IAccountConfirmation resolves to the passkey confirmation on a passkey-only host", outcome.AccountConfirmation is PasskeyAccountConfirmation);
            because.ItsTrue("IChallengeSignatureVerifier resolves to the passkey verifier on a passkey-only host", outcome.InterfaceChallengeVerifier is PasskeyChallengeSignatureVerifier);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RespectHostBindingsAndCoexistWithDeviceKeys()
    {
        After.Setup(reg =>
        {
            ServiceRegistry registry = HostRegistry();
            registry.AddDeviceKeyAccountConfirmation();
            registry.For<IPasskeyCredentialRepository>().Use(new InMemoryPasskeyCredentialRepository());
            registry.For<IConfirmationChallengeRepository>().Use(new InMemoryConfirmationChallengeRepository());
            registry.AddPasskeys(PasskeyFixture.DefaultOptions());
            reg.For<ServiceRegistry>().Use(registry);
        })
        .When<ServiceRegistry>("resolves with host custody and the device-key path registered", (registry, reg) =>
        {
            return new CoexistenceOutcome(
                registry.Get<IPasskeyCredentialRepository>(),
                registry.Get<IConfirmationChallengeRepository>(),
                registry.Get<IAccountConfirmation>(),
                registry.Get<IChallengeSignatureVerifier>(),
                registry.Get<PasskeyAccountConfirmation>(),
                Throws(() => HostRegistry().AddPasskeys(new PasskeyOptions { RpId = "Bad Host", RpName = "x" })));
        })
        .TheTest
        .ShouldPass<CoexistenceOutcome>((because, outcome) =>
        {
            because.ItsTrue("host credential custody is kept", outcome.Credentials is InMemoryPasskeyCredentialRepository);
            because.ItsTrue("host challenge custody is kept", outcome.Challenges is InMemoryConfirmationChallengeRepository);
            because.ItsTrue("IAccountConfirmation is still the device-key path", outcome.AccountConfirmation is DeviceKeyAccountConfirmation);
            because.ItsTrue("IChallengeSignatureVerifier is still the RSA path", outcome.ChallengeVerifier is RsaChallengeSignatureVerifier);
            because.ItsTrue("the passkey confirmation resolves beside it", outcome.PasskeyConfirmation is not null);
            because.ItsTrue("invalid options are refused at registration", outcome.InvalidOptionsThrow);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static bool Throws(Action action)
    {
        try
        {
            action();
            return false;
        }
        catch (ArgumentException)
        {
            return true;
        }
    }

    private sealed record ResolutionOutcome(IPasskeyCeremony Ceremony, PasskeyAccountConfirmation Confirmation, PasskeyChallengeSignatureVerifier ChallengeVerifier,
        IDetachedSignatureVerifier SignatureVerifier, IConfirmationChallengeRepository Challenges, IPasskeyCredentialRepository Credentials,
        bool SameCredentials, bool SameChallenges, bool SameOptions, IAccountConfirmation AccountConfirmation, IChallengeSignatureVerifier InterfaceChallengeVerifier);

    private sealed record CoexistenceOutcome(IPasskeyCredentialRepository Credentials, IConfirmationChallengeRepository Challenges, IAccountConfirmation AccountConfirmation,
        IChallengeSignatureVerifier ChallengeVerifier, PasskeyAccountConfirmation PasskeyConfirmation, bool InvalidOptionsThrow);
}
