using Bam.DependencyInjection;
using Bam.Encryption;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Registers the passkey ceremony and its collaborators.
/// </summary>
public static class PasskeysServiceRegistration
{
    /// <summary>
    /// Registers passkeys: the validated <see cref="PasskeyOptions"/>, the registration and
    /// assertion verifiers, <see cref="IPasskeyCeremony"/> (<see cref="PasskeyCeremony"/>), the
    /// <see cref="IChallengeSignatureVerifier"/>-shaped <see cref="PasskeyChallengeSignatureVerifier"/>
    /// and the <see cref="IAccountConfirmation"/>-shaped <see cref="PasskeyAccountConfirmation"/>.
    /// The two adapters are bound under their own concrete types, not the interfaces, so a host
    /// that also runs <see cref="UserAccountsServiceRegistration.AddDeviceKeyAccountConfirmation"/>
    /// keeps the device-key bindings and picks the passkey path by resolving the concrete type.
    /// <para>
    /// Singleton custody is bound only when the host has not bound it: an existing
    /// <see cref="IConfirmationChallengeRepository"/>, <see cref="IPasskeyCredentialRepository"/> or
    /// <see cref="IDetachedSignatureVerifier"/> binding is respected; otherwise
    /// <see cref="PersistedConfirmationChallengeRepository"/>, <see cref="PersistedPasskeyCredentialRepository"/>
    /// and <see cref="DetachedSignatureVerifier"/> are bound as singletons.  The persisted
    /// repositories are constructed at registration, so the host registry must already provide
    /// <c>IRepository</c>, and must provide <c>IPublicKeySetRegistrar</c>, <c>IProfileRepository</c>
    /// and <c>ICertificateManager</c> by the time the ceremony and confirmation are resolved.
    /// </para>
    /// </summary>
    /// <param name="registry">The host registry.</param>
    /// <param name="options">The relying-party policy; validated here.</param>
    /// <returns>The registry.</returns>
    /// <exception cref="ArgumentException">The options are invalid (see <see cref="PasskeyOptions.Validate"/>).</exception>
    public static ServiceRegistry AddPasskeys(this ServiceRegistry registry, PasskeyOptions options)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();

        registry.For<PasskeyOptions>().UseSingleton(options);
        if (!registry.Contains<IDetachedSignatureVerifier>())
        {
            registry.For<IDetachedSignatureVerifier>().UseSingleton<DetachedSignatureVerifier>();
        }
        if (!registry.Contains<IConfirmationChallengeRepository>())
        {
            registry.For<IConfirmationChallengeRepository>().UseSingleton<PersistedConfirmationChallengeRepository>();
        }
        if (!registry.Contains<IPasskeyCredentialRepository>())
        {
            registry.For<IPasskeyCredentialRepository>().UseSingleton<PersistedPasskeyCredentialRepository>();
        }

        registry
            .For<PasskeyRegistrationVerifier>().Use<PasskeyRegistrationVerifier>()
            .For<PasskeyAssertionVerifier>().Use<PasskeyAssertionVerifier>()
            .For<PasskeyCeremony>().Use<PasskeyCeremony>()
            .For<IPasskeyCeremony>().Use<PasskeyCeremony>()
            .For<PasskeyChallengeSignatureVerifier>().Use<PasskeyChallengeSignatureVerifier>()
            .For<PasskeyAccountConfirmation>().Use<PasskeyAccountConfirmation>();

        return registry;
    }
}
