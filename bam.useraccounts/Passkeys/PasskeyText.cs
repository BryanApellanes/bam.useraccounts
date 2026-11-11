using System.Globalization;
using System.Text;

namespace Bam.UserAccounts.Passkeys;

/// <summary>
/// Makes caller-chosen text safe to put in a log entry or a failure detail.  Handles, origins,
/// credential ids and parser messages all start as bytes an anonymous caller picked, so before
/// one is written anywhere an operator reads it is reduced to a single bounded line.
/// </summary>
public static class PasskeyText
{
    /// <summary>The default cap, long enough for any real origin, handle or credential id.</summary>
    public const int DefaultMaxLength = 120;

    /// <summary>What stands in for a character that is not shown.</summary>
    public const char Replacement = '?';

    /// <summary>
    /// Returns the text as one printable line of bounded length: control characters, line and
    /// paragraph separators, format characters (bidirectional overrides, zero-width marks),
    /// unassigned and private-use code points and lone surrogates each become
    /// <see cref="Replacement"/>, and anything past <paramref name="maxLength"/> characters is cut
    /// and replaced by a note of how much was dropped.  Ordinary letters, digits, punctuation and
    /// spaces in any script are kept, so a legitimate value reads as it was sent.
    /// </summary>
    /// <param name="text">The caller-chosen text; null reads as <c>(none)</c>.</param>
    /// <param name="maxLength">The most characters of the text to keep; values below one keep one.</param>
    /// <returns>A single-line string with no control characters, at most <paramref name="maxLength"/> characters of the original plus the truncation note.</returns>
    public static string Printable(string? text, int maxLength = DefaultMaxLength)
    {
        if (text is null)
        {
            return "(none)";
        }
        int limit = Math.Max(1, maxLength);
        int kept = Math.Min(text.Length, limit);
        StringBuilder printable = new StringBuilder(kept + 24);
        for (int index = 0; index < kept; index++)
        {
            char current = text[index];
            if (char.IsHighSurrogate(current) && index + 1 < kept && char.IsLowSurrogate(text[index + 1]))
            {
                // A whole pair inside the kept range: judge the code point, keep or replace both halves together.
                if (IsShown(char.GetUnicodeCategory(text, index)))
                {
                    printable.Append(current).Append(text[index + 1]);
                }
                else
                {
                    printable.Append(Replacement);
                }
                index++;
                continue;
            }
            printable.Append(char.IsSurrogate(current) || !IsShown(char.GetUnicodeCategory(current)) ? Replacement : current);
        }
        if (text.Length > kept)
        {
            printable.Append("...(+").Append((text.Length - kept).ToString(CultureInfo.InvariantCulture)).Append(" more)");
        }
        return printable.ToString();
    }

    private static bool IsShown(UnicodeCategory category)
    {
        return category switch
        {
            UnicodeCategory.Control => false,
            UnicodeCategory.Format => false,
            UnicodeCategory.LineSeparator => false,
            UnicodeCategory.ParagraphSeparator => false,
            UnicodeCategory.Surrogate => false,
            UnicodeCategory.PrivateUse => false,
            UnicodeCategory.OtherNotAssigned => false,
            _ => true
        };
    }
}
