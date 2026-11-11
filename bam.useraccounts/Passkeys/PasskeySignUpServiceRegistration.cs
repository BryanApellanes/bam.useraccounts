using Bam.DependencyInjection;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Registers the passkey sign-up sequence and the passkey inventory.
/// </summary>
public static class PasskeySignUpServiceRegistration
{
    /// <summary>
    /// Registers <see cref="IPasskeySignUp"/> (<see cref="PasskeySignUp"/>),
    /// <see cref="IPasskeyInventory"/> (<see cref="PasskeyInventory"/>), the validated
    /// <see cref="SignUpPolicy"/> and the host's <see cref="PostSignUpSteps"/> collection.
    /// <see cref="PasskeysServiceRegistration.AddPasskeys"/> must have run first; the host registry
    /// must also provide <c>IUserAccountService</c> and <c>IProfileRepository</c> by the time
    /// <see cref="IPasskeySignUp"/> is resolved.  An existing <see cref="PostSignUpSteps"/> binding
    /// (steps added before this call) is kept.
    /// </summary>
    /// <param name="registry">The host registry.</param>
    /// <param name="policy">The sign-up policy; validated here.</param>
    /// <returns>The registry.</returns>
    /// <exception cref="ArgumentException">The policy is invalid (see <see cref="SignUpPolicy.Validate"/>).</exception>
    /// <exception cref="InvalidOperationException"><see cref="PasskeysServiceRegistration.AddPasskeys"/> has not run on the registry.</exception>
    public static ServiceRegistry AddPasskeySignUp(this ServiceRegistry registry, SignUpPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(policy);
        policy.Validate();
        if (!registry.Contains<IPasskeyCeremony>() || !registry.Contains<IPasskeyCredentialRepository>())
        {
            throw new InvalidOperationException("AddPasskeySignUp requires AddPasskeys to have been called on the registry first.");
        }

        registry.For<SignUpPolicy>().UseSingleton(policy);
        EnsureSteps(registry);
        registry
            .For<PasskeySignUp>().Use<PasskeySignUp>()
            .For<IPasskeySignUp>().Use<PasskeySignUp>()
            .For<PasskeyInventory>().Use<PasskeyInventory>()
            .For<IPasskeyInventory>().Use<PasskeyInventory>();
        return registry;
    }

    /// <summary>
    /// Adds a post-sign-up step resolved from the registry each time a sign-up completes.  May be
    /// called before or after <see cref="AddPasskeySignUp"/>; steps run in the order added.
    /// </summary>
    /// <typeparam name="TStep">The step type; constructed by the registry.</typeparam>
    /// <param name="registry">The host registry.</param>
    /// <returns>The registry.</returns>
    public static ServiceRegistry AddPostSignUpStep<TStep>(this ServiceRegistry registry) where TStep : class, IPostSignUpStep
    {
        ArgumentNullException.ThrowIfNull(registry);
        EnsureSteps(registry).Add(() => registry.Get<TStep>());
        return registry;
    }

    /// <summary>
    /// Adds a post-sign-up step instance.  May be called before or after
    /// <see cref="AddPasskeySignUp"/>; steps run in the order added.
    /// </summary>
    /// <param name="registry">The host registry.</param>
    /// <param name="step">The step.</param>
    /// <returns>The registry.</returns>
    public static ServiceRegistry AddPostSignUpStep(this ServiceRegistry registry, IPostSignUpStep step)
    {
        ArgumentNullException.ThrowIfNull(registry);
        EnsureSteps(registry).Add(step);
        return registry;
    }

    private static PostSignUpSteps EnsureSteps(ServiceRegistry registry)
    {
        if (!registry.Contains<PostSignUpSteps>())
        {
            registry.For<PostSignUpSteps>().UseSingleton(new PostSignUpSteps());
        }
        return registry.Get<PostSignUpSteps>();
    }
}
