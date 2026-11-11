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

    // "...(+" then up to ten digits then " more)": the longest note Printable can append.
    private const int MaxNoteLength = 21;
    private const string NoteStart = "...(+";
    private const string NoteEnd = " more)";

    /// <summary>
    /// Returns the text as one printable line of bounded length: control characters, line and
    /// paragraph separators, format characters (bidirectional overrides, zero-width marks),
    /// unassigned and private-use code points and lone surrogates each become
    /// <see cref="Replacement"/>, and anything past <paramref name="maxLength"/> characters is cut
    /// and replaced by a note of how much was dropped.  Ordinary letters, digits, punctuation and
    /// spaces in any script are kept, so a legitimate value reads as it was sent, with two
    /// exceptions: a replaced character is not recoverable (it is replaced, not escaped, and
    /// <see cref="Replacement"/> is itself a legal character in a URL, so a <c>?</c> in the
    /// output may be either), and zero-width joiners are format characters, so an emoji sequence
    /// or a word that uses one shows a <c>?</c> in the middle.  The result is for reading, never
    /// for comparing or parsing.
    /// <para>
    /// Applying it twice with the same cap gives the same result as applying it once: text that
    /// already ends in a truncation note and is no longer than the cap plus that note is kept
    /// whole.  Printable text is routinely wrapped and passed on (a parser message inside an
    /// exception inside a failure detail inside a log entry), and a second cut would replace the
    /// note with a wrong count.  The price is that a caller can end their own text with a
    /// note-shaped suffix and gain up to 21 characters past the cap; the result is still one
    /// bounded line.
    /// </para>
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
        if (text.Length > limit && text.Length <= limit + MaxNoteLength && EndsWithNote(text))
        {
            // Already cut by an earlier pass: keep its note rather than cutting through it.
            kept = text.Length;
        }
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
            printable.Append(NoteStart).Append((text.Length - kept).ToString(CultureInfo.InvariantCulture)).Append(NoteEnd);
        }
        return printable.ToString();
    }

    private static bool EndsWithNote(string text)
    {
        if (!text.EndsWith(NoteEnd, StringComparison.Ordinal))
        {
            return false;
        }
        int digitsEnd = text.Length - NoteEnd.Length;
        int digitsStart = digitsEnd;
        while (digitsStart > 0 && digitsEnd - digitsStart < 10 && char.IsAsciiDigit(text[digitsStart - 1]))
        {
            digitsStart--;
        }
        return digitsStart < digitsEnd
            && digitsStart >= NoteStart.Length
            && string.CompareOrdinal(text, digitsStart - NoteStart.Length, NoteStart, 0, NoteStart.Length) == 0;
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
