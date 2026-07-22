using Bam.Data.Repositories;
using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Protocol;
using Bam.Protocol.Data;
using Bam.Test;
using Bam.UserAccounts;
using NSubstitute;

namespace Bam.UserAccounts.Tests.Unit;

[UnitTestMenu("UserAccountsServiceRegistration Should", Selector = "uasr")]
public class UserAccountsServiceRegistrationShould : UnitTestMenuContainer
{
    public UserAccountsServiceRegistrationShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    private static ServiceRegistry ComposeRegistry()
    {
        ServiceRegistry registry = new ServiceRegistry();
        registry.For<IRepository>().Use(Substitute.For<IRepository>());
        registry.For<IProfileRepository>().Use(Substitute.For<IProfileRepository>());
        registry.For<ICertificateManager>().Use(Substitute.For<ICertificateManager>());
        return registry.AddDeviceKeyAccountConfirmation();
    }

    private static void SetupDefaults(TestCaseRegistry reg)
    {
        reg.For<ServiceRegistry>().Use(ComposeRegistry());
    }

    [UnitTest]
    public void ResolveAccountConfirmationFromComposedRegistry()
    {
        After.Setup(SetupDefaults)
        .When<ServiceRegistry>("resolves IAccountConfirmation from the composed registry", (registry) =>
        {
            return new ResolutionOutcome(
                registry.Get<IAccountConfirmation>(),
                registry.Get<ISignatureProvider>(),
                registry.Get<IChallengeSignatureVerifier>());
        })
        .TheTest
        .ShouldPass<ResolutionOutcome>((because, outcome) =>
        {
            because.ItsTrue("IAccountConfirmation resolves to DeviceKeyAccountConfirmation", outcome.AccountConfirmation is DeviceKeyAccountConfirmation);
            because.ItsTrue("ISignatureProvider defaults to RsaSignatureProvider", outcome.SignatureProvider is RsaSignatureProvider);
            because.ItsTrue("IChallengeSignatureVerifier resolves to RsaChallengeSignatureVerifier", outcome.SignatureVerifier is RsaChallengeSignatureVerifier);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ShareChallengeCustodyAcrossResolutions()
    {
        After.Setup(SetupDefaults)
        .When<ServiceRegistry>("saves through one resolution and takes through another", (registry) =>
        {
            IConfirmationChallengeRepository first = registry.Get<IConfirmationChallengeRepository>();
            IConfirmationChallengeRepository second = registry.Get<IConfirmationChallengeRepository>();
            return new CustodyOutcome(ReferenceEquals(first, second));
        })
        .TheTest
        .ShouldPass<CustodyOutcome>((because, outcome) =>
        {
            because.ItsTrue("both resolutions return the same repository instance - custody state is shared", outcome.SameInstance);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RespectExistingSignatureProviderBinding()
    {
        ISignatureProvider existingProvider = Substitute.For<ISignatureProvider>();

        After.Setup(reg =>
        {
            ServiceRegistry registry = new ServiceRegistry();
            registry.For<IRepository>().Use(Substitute.For<IRepository>());
            registry.For<IProfileRepository>().Use(Substitute.For<IProfileRepository>());
            registry.For<ICertificateManager>().Use(Substitute.For<ICertificateManager>());
            registry.For<ISignatureProvider>().Use(existingProvider);
            reg.For<ServiceRegistry>().Use(registry.AddDeviceKeyAccountConfirmation());
        })
        .When<ServiceRegistry>("resolves ISignatureProvider after composing", (registry) =>
        {
            return registry.Get<ISignatureProvider>();
        })
        .TheTest
        .ShouldPass<ISignatureProvider>((because, provider) =>
        {
            because.ItsTrue("the pre-existing ISignatureProvider binding is respected", ReferenceEquals(provider, existingProvider));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private sealed record ResolutionOutcome(
        IAccountConfirmation AccountConfirmation,
        ISignatureProvider SignatureProvider,
        IChallengeSignatureVerifier SignatureVerifier);

    private sealed record CustodyOutcome(bool SameInstance);
}
