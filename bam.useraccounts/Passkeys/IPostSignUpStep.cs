namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// A host hook run once after a person has signed up (for lumberjack.live: send the person to
/// register a client application).  Register with
/// <see cref="PasskeySignUpServiceRegistration.AddPostSignUpStep{TStep}"/>.  A step that throws is
/// logged and skipped; it never undoes the sign-up.
/// </summary>
public interface IPostSignUpStep
{
    /// <summary>Runs the step for a newly signed-up person.</summary>
    /// <param name="person">The person who signed up.</param>
    /// <returns>What the step asks of the flow.</returns>
    PostSignUpOutcome Run(SignedUpPerson person);
}

/// <summary>
/// The newly signed-up person handed to each <see cref="IPostSignUpStep"/>.
/// </summary>
public sealed class SignedUpPerson
{
    /// <summary>The person's handle.</summary>
    public string PersonHandle { get; set; } = string.Empty;

    /// <summary>The name shown for the person.</summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>The person's email address, or null.</summary>
    public string? Email { get; set; }

    /// <summary>The canonical fingerprint of the person's registered key set (their first passkey).</summary>
    public string? KeyFingerprint { get; set; }

    /// <summary>Whether the person profile was written.</summary>
    public bool ProfileCreated { get; set; }
}

/// <summary>
/// What an <see cref="IPostSignUpStep"/> asks of the sign-up flow.
/// </summary>
public sealed class PostSignUpOutcome
{
    /// <summary>A local URL to send the person to next, or null for no preference.  The first step to name one wins.</summary>
    public string? NextUrl { get; set; }

    /// <summary>A note for the host's logs, or null.</summary>
    public string? Message { get; set; }
}

/// <summary>
/// The ordered post-sign-up steps of a host.  <c>ServiceRegistry</c> binds one implementation
/// per type, so the steps are kept in this singleton collection instead of being resolved as an
/// enumerable.
/// </summary>
public sealed class PostSignUpSteps
{
    private readonly List<Func<IPostSignUpStep>> _steps = new List<Func<IPostSignUpStep>>();
    private readonly object _lock = new object();

    /// <summary>Adds a step instance; steps run in the order added.</summary>
    /// <param name="step">The step.</param>
    public void Add(IPostSignUpStep step)
    {
        ArgumentNullException.ThrowIfNull(step);
        Add(() => step);
    }

    /// <summary>Adds a step resolved each time a sign-up completes; steps run in the order added.</summary>
    /// <param name="step">Resolves the step.</param>
    public void Add(Func<IPostSignUpStep> step)
    {
        ArgumentNullException.ThrowIfNull(step);
        lock (_lock)
        {
            _steps.Add(step);
        }
    }

    /// <summary>The number of registered steps.</summary>
    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _steps.Count;
            }
        }
    }

    /// <summary>A snapshot of the step resolvers, in order.</summary>
    public IReadOnlyList<Func<IPostSignUpStep>> Snapshot()
    {
        lock (_lock)
        {
            return _steps.ToList();
        }
    }
}
