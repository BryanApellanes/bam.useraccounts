using System.Text;

namespace Bam.UserAccounts.Web;

/// <summary>
/// The account pages' look, emitted as CSS custom properties on the page shell so a host's
/// stylesheet (or the library's <c>account.css</c>) can read them.  A null value leaves the
/// stylesheet's default in place.
/// </summary>
public sealed class AccountTheme
{
    /// <summary>Primary (button and link) colour, <c>--account-primary</c>.</summary>
    public string? Primary { get; set; }

    /// <summary>Text colour on the primary colour, <c>--account-on-primary</c>.</summary>
    public string? OnPrimary { get; set; }

    /// <summary>Card background, <c>--account-surface</c>.</summary>
    public string? Surface { get; set; }

    /// <summary>Page background, <c>--account-background</c>.</summary>
    public string? Background { get; set; }

    /// <summary>Text colour, <c>--account-text</c>.</summary>
    public string? Text { get; set; }

    /// <summary>Corner radius, <c>--account-radius</c> (for example <c>0.5rem</c>).</summary>
    public string? Radius { get; set; }

    /// <summary>Font family, <c>--account-font</c>.</summary>
    public string? Font { get; set; }

    /// <summary>
    /// The value of a <c>style</c> attribute declaring every set property, or an empty string
    /// when none is set.
    /// </summary>
    /// <returns>For example <c>--account-primary:#0a5;--account-radius:0.5rem;</c>.</returns>
    public string ToStyleAttribute()
    {
        StringBuilder style = new StringBuilder();
        Append(style, "--account-primary", Primary);
        Append(style, "--account-on-primary", OnPrimary);
        Append(style, "--account-surface", Surface);
        Append(style, "--account-background", Background);
        Append(style, "--account-text", Text);
        Append(style, "--account-radius", Radius);
        Append(style, "--account-font", Font);
        return style.ToString();
    }

    /// <summary>Throws <see cref="InvalidOperationException"/> when a value could end its declaration and start another.</summary>
    public void Validate()
    {
        Check(nameof(Primary), Primary);
        Check(nameof(OnPrimary), OnPrimary);
        Check(nameof(Surface), Surface);
        Check(nameof(Background), Background);
        Check(nameof(Text), Text);
        Check(nameof(Radius), Radius);
        Check(nameof(Font), Font);
    }

    private static void Append(StringBuilder style, string property, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            style.Append(property).Append(':').Append(value.Trim()).Append(';');
        }
    }

    private static void Check(string name, string? value)
    {
        if (value is null)
        {
            return;
        }
        foreach (char character in value)
        {
            if (character == ';' || character == '{' || character == '}' || character == '<' || character == '>' || character == '\\' || char.IsControl(character))
            {
                throw new InvalidOperationException($"AccountTheme.{name} must be a single CSS value (no ';', braces, angle brackets, backslashes or control characters).");
            }
        }
    }
}
