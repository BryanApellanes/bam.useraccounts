using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Protocol.Data;

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
    /// The two adapters are always bound under their concrete types, and under
    /// <see cref="IAccountConfirmation"/> / <see cref="IChallengeSignatureVerifier"/> only when the
    /// host has not bound those interfaces: a passkey-only host gets <c>UserAccountService</c> on
    /// passkeys purely by registration, while a host that ran
    /// <see cref="UserAccountsServiceRegistration.AddDeviceKeyAccountConfirmation"/> first keeps the
    /// device-key bindings and reaches the passkey path through the concrete types.
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
        if (!registry.Contains<IChallengeSignatureVerifier>())
        {
            registry.For<IChallengeSignatureVerifier>().Use<PasskeyChallengeSignatureVerifier>();
        }
        if (!registry.Contains<IAccountConfirmation>())
        {
            registry.For<IAccountConfirmation>().Use<PasskeyAccountConfirmation>();
        }

        // The handover is always bound; it is available only once a passkey rotation proof is trusted.
        registry.For<IKeySetHandover>().Use<KeySetHandover>(reg => new KeySetHandover(
            reg.Get<IPasskeyCredentialRepository>(),
            reg.Get<IPublicKeySetRegistrar>(),
            reg.Contains<KeySetRotationProofs>() ? reg.Get<KeySetRotationProofs>() : null,
            reg.Get<IConfirmationChallengeRepository>(),
            reg.Get<PasskeyOptions>()));
        if (registry.Contains<KeySetRotationProofs>())
        {
            registry.AddPasskeyKeySetRotation();
        }

        return registry;
    }

    /// <summary>
    /// Trusts <see cref="PasskeyKeySetRotationProof"/> for key-set rotation (bam.useraccounts#20):
    /// adds it to the host's <see cref="KeySetRotationProofs"/>, which makes
    /// <see cref="IKeySetHandover"/> available.  <see cref="AddPasskeys"/> calls this when the proof
    /// list is already registered (the profile repository registration, for example
    /// <c>AddEncryptedProfileRepository</c>, registers it); a host that registers the profile
    /// repository after <see cref="AddPasskeys"/> calls this itself afterwards.  Calling it twice
    /// adds the proof once.
    /// </summary>
    /// <param name="registry">The host registry, with <see cref="AddPasskeys"/> applied.</param>
    /// <returns>The registry.</returns>
    /// <exception cref="InvalidOperationException">The registry has no <see cref="KeySetRotationProofs"/>, or <see cref="AddPasskeys"/> has not run.</exception>
    public static ServiceRegistry AddPasskeyKeySetRotation(this ServiceRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);
        if (!registry.Contains<KeySetRotationProofs>() || !registry.Contains<IPasskeyCredentialRepository>() || !registry.Contains<PasskeyCeremony>())
        {
            throw new InvalidOperationException("AddPasskeyKeySetRotation needs AddPasskeys and a registered KeySetRotationProofs (the profile repository registration).");
        }
        KeySetRotationProofs proofs = registry.Get<KeySetRotationProofs>();
        if (proofs.All.Any(proof => proof is PasskeyKeySetRotationProof))
        {
            return registry;
        }
        // The ceremony is resolved per rotation: it depends on the registrar, which depends on this list.
        proofs.Add(new PasskeyKeySetRotationProof(registry.Get<IPasskeyCredentialRepository>(), () => registry.Get<PasskeyCeremony>()));
        return registry;
    }
}
