using Microsoft.AspNetCore.Components;

namespace Bam.UserAccounts.Web;

/// <summary>
/// Host components the account pages render in fixed places.  Each is a component type from the
/// host's own assembly, rendered without parameters.
/// </summary>
public sealed class AccountSlots
{
    /// <summary>Rendered above the form on the sign-up and sign-in pages.</summary>
    public Type? Hero { get; set; }

    /// <summary>Rendered on the manage page, above the passkey list (for example a "what's next" panel).</summary>
    public Type? PostSignUp { get; set; }

    /// <summary>Rendered in the footer, before the terms and privacy links.</summary>
    public Type? Legal { get; set; }

    /// <summary>Throws <see cref="InvalidOperationException"/> when a slot type is not a component.</summary>
    public void Validate()
    {
        Check(nameof(Hero), Hero);
        Check(nameof(PostSignUp), PostSignUp);
        Check(nameof(Legal), Legal);
    }

    private static void Check(string name, Type? type)
    {
        if (type is not null && !typeof(IComponent).IsAssignableFrom(type))
        {
            throw new InvalidOperationException($"AccountSlots.{name} must be a component type; {type.FullName} does not implement IComponent.");
        }
    }
}
