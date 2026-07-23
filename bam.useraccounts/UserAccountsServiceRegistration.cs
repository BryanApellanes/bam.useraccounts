using Bam.DependencyInjection;
using Bam.Encryption;

namespace Bam.UserAccounts;

public static class UserAccountsServiceRegistration
{
    /// <summary>
    /// Registers the device-key account-confirmation flow: durable challenge custody
    /// (<see cref="PersistedConfirmationChallengeRepository"/>), RSA challenge-signature
    /// verification, and <see cref="DeviceKeyAccountConfirmation"/> as the
    /// <see cref="IAccountConfirmation"/> implementation.
    /// <para>
    /// The host registry must already provide <c>IRepository</c> (e.g. <c>ObjectDataRepository</c>),
    /// <c>IProfileRepository</c> (e.g. via <c>AddEncryptedProfileRepository</c>), and
    /// <c>ICertificateManager</c>.  An existing <see cref="ISignatureProvider"/> binding is
    /// respected; <see cref="RsaSignatureProvider"/> is bound only when none is present.
    /// </para>
    /// <para>
    /// The challenge repository and verifier are bound as singletons: challenge custody is
    /// state that must be shared across resolutions — a transient binding would give every
    /// resolution its own lock (and, for the in-memory implementation, its own empty store),
    /// breaking the single-use invariant.
    /// </para>
    /// </summary>
    public static ServiceRegistry AddDeviceKeyAccountConfirmation(this ServiceRegistry registry)
    {
        if (!registry.Contains<ISignatureProvider>())
        {
            registry.For<ISignatureProvider>().Use<RsaSignatureProvider>();
        }

        registry
            .For<IChallengeSignatureVerifier>().UseSingleton<RsaChallengeSignatureVerifier>()
            .For<IConfirmationChallengeRepository>().UseSingleton<PersistedConfirmationChallengeRepository>()
            .For<IAccountConfirmation>().Use<DeviceKeyAccountConfirmation>();

        return registry;
    }
}
