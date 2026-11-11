using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Logging;
using Bam.Test;
using Bam.UserAccounts.Passkeys;
using Bam.UserAccounts.Tests.TestClasses;

namespace Bam.UserAccounts.Tests.Unit.Passkeys;

/// <summary>
/// Covers bam.useraccounts#17: text an anonymous caller chose (origin, client data type, handle,
/// credential id, parser messages about its bytes) reaches failure details and the log as one
/// bounded line with no control characters.
/// </summary>
[UnitTestMenu("PasskeyText Should", Selector = "pktx")]
public class PasskeyTextShould : UnitTestMenuContainer
{
    private const string Forged = "FORGED-ENTRY";

    public PasskeyTextShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    [UnitTest]
    public void ReduceTextToOnePrintableLine()
    {
        After.Setup(reg => reg.Set(new SyntheticAuthenticator()))
        .When<SyntheticAuthenticator>("makes hostile and ordinary strings printable", (unused, reg) =>
        {
            return new PrintableOutcome(
                PasskeyText.Printable(null),
                PasskeyText.Printable(string.Empty),
                PasskeyText.Printable("https://lumberjack.live"),
                PasskeyText.Printable("android:apk-key-hash:-sYXRdwJA3hvue3mKpYrOZ9zSPC7b4mbgzJmdZEDO5w"),
                PasskeyText.Printable("a\rb\nc\td\0e" + U(0x001B) + "f"),
                PasskeyText.Printable("a" + U(0x2028) + "b" + U(0x2029) + "c" + U(0x0085) + "d"),
                PasskeyText.Printable("a" + U(0x202E) + "b" + U(0x200B) + "c" + U(0xFEFF) + "d"),
                PasskeyText.Printable("a" + U(0xD800) + "b" + U(0xDC00) + "c"),
                PasskeyText.Printable("jos" + U(0x00E9) + " " + U(0x65E5) + "" + U(0x672C) + " " + U(0x1F511) + ""),
                PasskeyText.Printable("a" + U(0xE000) + "b"),
                PasskeyText.Printable(new string('x', 500)),
                PasskeyText.Printable("abcdef", 3),
                PasskeyText.Printable("abcdef", 0),
                PasskeyText.Printable("ab" + U(0x1F511) + "", 3),
                PasskeyText.Printable("abcdef", 6));
        })
        .TheTest
        .ShouldPass<PrintableOutcome>((because, outcome) =>
        {
            because.ItsTrue("null reads as (none)", outcome.Null == "(none)");
            because.ItsTrue("empty stays empty", outcome.Empty.Length == 0);
            because.ItsTrue("a browser origin is unchanged", outcome.BrowserOrigin == "https://lumberjack.live");
            because.ItsTrue("an app origin is unchanged", outcome.AppOrigin == "android:apk-key-hash:-sYXRdwJA3hvue3mKpYrOZ9zSPC7b4mbgzJmdZEDO5w");
            because.ItsTrue("CR, LF, tab, NUL and escape are replaced", outcome.Controls == "a?b?c?d?e?f");
            because.ItsTrue("line separator, paragraph separator and NEL are replaced", outcome.Separators == "a?b?c?d");
            because.ItsTrue("bidirectional override, zero-width space and BOM are replaced", outcome.Formats == "a?b?c?d");
            because.ItsTrue("lone surrogates are replaced", outcome.LoneSurrogates == "a?b?c");
            because.ItsTrue("accented letters, other scripts and a valid surrogate pair are kept", outcome.International == "jos" + U(0x00E9) + " " + U(0x65E5) + "" + U(0x672C) + " " + U(0x1F511) + "");
            because.ItsTrue("a private-use character is replaced", outcome.PrivateUse == "a?b");
            because.ItsTrue("long text is cut at the default length with a note", outcome.Long == new string('x', 120) + "...(+380 more)");
            because.ItsTrue("a smaller cap is honoured", outcome.Short == "abc...(+3 more)");
            because.ItsTrue("a cap below one keeps one character", outcome.ZeroCap == "a...(+5 more)");
            because.ItsTrue("a surrogate pair split by the cap does not leave half a character", outcome.SplitPair == "ab?...(+1 more)");
            because.ItsTrue("text exactly at the cap gets no note", outcome.ExactlyAtCap == "abcdef");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void KeepClientTextOutOfFailureDetails()
    {
        After.Setup(reg => reg.Set(new SyntheticAuthenticator()))
        .When<SyntheticAuthenticator>("verifies registrations whose origin and type carry line breaks and bulk", (authenticator, reg) =>
        {
            PasskeyRegistrationVerifier verifier = new PasskeyRegistrationVerifier(PasskeyFixture.DefaultOptions());
            byte[] challenge = SyntheticAuthenticator.RandomBytes(32);
            // Escaped in the JSON, so the parsed origin holds real CR and LF characters.
            string hostileOrigin = "https://evil.example\\r\\n" + Forged + "\\u2028" + new string('A', 20000);
            PasskeyVerification origin = verifier.Verify(authenticator.Register(challenge, origin: hostileOrigin), challenge);

            string challengeText = Base64UrlEncoder.Default.Encode(challenge);
            byte[] hostileType = System.Text.Encoding.UTF8.GetBytes("{\"type\":\"webauthn.create\\r\\n" + Forged + "\",\"challenge\":\"" + challengeText + "\",\"origin\":\"https://lumberjack.live\"}");
            PasskeyVerification type = verifier.Verify(authenticator.Register(challenge, clientData: hostileType), challenge);

            PasskeyVerification direct = PasskeyVerification.Fail(PasskeyVerificationFailure.MalformedClientData, "parser said: \r\n" + Forged + new string('B', 5000));
            return new DetailOutcome(
                origin.Failure, HasLineBreak(origin.Detail), origin.Detail!.Length, origin.Detail.Contains("https://evil.example"),
                type.Failure, HasLineBreak(type.Detail), type.Detail!.Contains(Forged),
                HasLineBreak(direct.Detail), direct.Detail!.Length);
        })
        .TheTest
        .ShouldPass<DetailOutcome>((because, outcome) =>
        {
            because.ItsTrue("the hostile origin is still refused as an origin", outcome.OriginFailure == PasskeyVerificationFailure.OriginNotAllowed);
            because.ItsTrue("the origin detail is one line", !outcome.OriginHasLineBreak);
            because.ItsTrue("the origin detail is bounded, length " + outcome.OriginDetailLength, outcome.OriginDetailLength < 250);
            because.ItsTrue("the origin detail still names the origin's start", outcome.OriginStillNamed);
            because.ItsTrue("the hostile type is refused as a wrong type", outcome.TypeFailure == PasskeyVerificationFailure.WrongType);
            because.ItsTrue("the type detail is one line", !outcome.TypeHasLineBreak);
            because.ItsTrue("the forged text survives only inline", outcome.TypeStillNamed);
            because.ItsTrue("any detail passed to Fail is one line", !outcome.DirectHasLineBreak);
            because.ItsTrue("any detail passed to Fail is bounded, length " + outcome.DirectLength, outcome.DirectLength < 450);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void KeepClientTextOutOfTheLog()
    {
        After.Setup(reg => reg.Set(new PasskeyFixture()))
        .When<PasskeyFixture>("fails a sign-up and a sign-in whose handle, origin and credential id carry line breaks", (fixture, reg) =>
        {
            ILogger? previous = Log.Default;
            CapturingLogger logger = new CapturingLogger();
            Log.Default = logger;
            try
            {
                string hostileHandle = "jane\r\n" + Forged + "-HANDLE";
                SyntheticAuthenticator authenticator = new SyntheticAuthenticator();
                PasskeyCreationOptions creation = fixture.Ceremony.BeginRegistration(hostileHandle, "Jane");
                byte[] challenge = Base64UrlEncoder.Default.Decode(creation.Challenge);
                PasskeyRegistrationResult registration = fixture.Ceremony.CompleteRegistration(hostileHandle, authenticator.Register(challenge, origin: "https://evil.example\\r\\n" + Forged + "-ORIGIN" + new string('C', 20000)));

                PasskeyRequestOptions request = fixture.Ceremony.BeginAssertion(null);
                byte[] assertionChallenge = Base64UrlEncoder.Default.Decode(request.Challenge);
                PasskeySignInResult signIn = fixture.Ceremony.CompleteAssertion(authenticator.Assert(assertionChallenge, request.CeremonyId, id: "unknown\r\n" + Forged + "-CREDENTIAL" + U(0x2028) + "" + new string('D', 20000)));

                // A detail longer than the cap: Newtonsoft quotes the caller's 3,000-character property name.
                PasskeyCreationOptions longCreation = fixture.Ceremony.BeginRegistration("long-detail", "Jane");
                byte[] longChallenge = Base64UrlEncoder.Default.Decode(longCreation.Challenge);
                byte[] longClientData = System.Text.Encoding.UTF8.GetBytes("{\"" + new string('p', 3000) + "\":x}");
                PasskeyVerification longVerification = new PasskeyRegistrationVerifier(fixture.Options).Verify(authenticator.Register(longChallenge, clientData: longClientData), longChallenge);
                fixture.Ceremony.CompleteRegistration("long-detail", authenticator.Register(longChallenge, clientData: longClientData));

                // The same long parser message through the challenge verifier, which returns it to the host.
                byte[] longAssertion = System.Text.Encoding.UTF8.GetBytes("{\"" + new string('p', 3000) + "\":x}");
                string exceptionMessage = string.Empty;
                try
                {
                    PasskeyAssertionResponse.FromJson(longAssertion);
                }
                catch (PasskeyFormatException e)
                {
                    exceptionMessage = e.Message;
                }
                string verifierMessage = new PasskeyChallengeSignatureVerifier(fixture.Ceremony, fixture.Credentials)
                    .Verify(new ConfirmationChallenge { PersonHandle = "long-detail", ChallengeBytes = longChallenge, ExpiresUtc = DateTime.UtcNow.AddMinutes(1) }, longAssertion, null!)
                    .Message;

                IReadOnlyList<LogEvent> events = logger.Events;
                List<string> values = events.SelectMany(e => e.MessageVariableValues ?? Array.Empty<string?>()).Where(v => v is not null).Select(v => v!).ToList();
                return new LogOutcome(
                    registration.Success, signIn.Success, registration.Message, events.Count,
                    values.Any(HasLineBreak),
                    values.Count == 0 ? 0 : values.Max(v => v.Length),
                    values.Any(v => v.Contains(Forged + "-HANDLE")),
                    values.Any(v => v.Contains(Forged + "-ORIGIN")),
                    values.Any(v => v.Contains(Forged + "-CREDENTIAL")),
                    longVerification.Detail!.Length > PasskeyVerification.MaxDetailLength,
                    longVerification.Detail.Substring(longVerification.Detail.LastIndexOf("...(+", StringComparison.Ordinal)),
                    values.Any(v => v == longVerification.Detail),
                    exceptionMessage.Length > PasskeyVerification.MaxDetailLength && !HasLineBreak(exceptionMessage),
                    exceptionMessage.Substring(Math.Max(0, exceptionMessage.LastIndexOf("...(+", StringComparison.Ordinal))),
                    verifierMessage.EndsWith(exceptionMessage, StringComparison.Ordinal),
                    verifierMessage.Length);
            }
            finally
            {
                Log.Default = previous;
                logger.StopLoggingThread();
            }
        })
        .TheTest
        .ShouldPass<LogOutcome>((because, outcome) =>
        {
            because.ItsTrue("the sign-up is refused", !outcome.Registered);
            because.ItsTrue("the sign-in is refused", !outcome.SignedIn);
            because.ItsTrue("the caller still gets only the generic message", outcome.RegistrationMessage is not null && !outcome.RegistrationMessage.Contains(Forged));
            because.ItsTrue("all three failures are logged, events " + outcome.Events, outcome.Events == 3);
            because.ItsTrue("no logged value contains a line break", !outcome.AnyLineBreak);
            because.ItsTrue("no logged value is unbounded, longest " + outcome.LongestValue, outcome.LongestValue < 460);
            because.ItsTrue("the handle is still logged, inline", outcome.HandleLogged);
            because.ItsTrue("the origin is still logged, inline", outcome.OriginLogged);
            because.ItsTrue("the credential id is still logged, inline", outcome.CredentialLogged);
            because.ItsTrue("the long detail was cut by Fail", outcome.LongDetailWasCut);
            because.ItsTrue("the log carries that detail unchanged, with the real dropped count " + outcome.LongDetailNote, outcome.LongDetailLoggedUnchanged);
            because.ItsTrue("the JSON exception's message is cut once, on one line, note " + outcome.ExceptionNote, outcome.ExceptionMessageCutOnce);
            because.ItsTrue("the challenge verifier returns that message uncut, with the same note", outcome.VerifierKeepsTheNote);
            because.ItsTrue("the challenge verifier's message is bounded, length " + outcome.VerifierMessageLength, outcome.VerifierMessageLength < 520);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static string U(int codePoint)
    {
        // Built from numbers so the source file stays ASCII and no editor can turn an escape into the character.
        return codePoint >= 0xD800 && codePoint <= 0xDFFF ? ((char)codePoint).ToString() : char.ConvertFromUtf32(codePoint);
    }

    private static bool HasLineBreak(string? text)
    {
        return text is not null && text.Any(c => char.IsControl(c) || c == (char)0x2028 || c == (char)0x2029);
    }

    /// <summary>A logger that keeps every committed event so a test can read what was logged.</summary>
    private sealed class CapturingLogger : Logger
    {
        private readonly List<LogEvent> _events = new List<LogEvent>();

        public CapturingLogger()
        {
            CommitCycleDelay = 0;
        }

        public IReadOnlyList<LogEvent> Events
        {
            get
            {
                BlockUntilEventQueueIsEmpty();
                lock (_events)
                {
                    return _events.ToList();
                }
            }
        }

        public override void CommitLogEvent(LogEvent logEvent)
        {
            lock (_events)
            {
                _events.Add(logEvent);
            }
        }
    }

    private sealed record PrintableOutcome(string Null, string Empty, string BrowserOrigin, string AppOrigin, string Controls, string Separators, string Formats, string LoneSurrogates, string International, string PrivateUse, string Long, string Short, string ZeroCap, string SplitPair, string ExactlyAtCap);

    private sealed record DetailOutcome(PasskeyVerificationFailure OriginFailure, bool OriginHasLineBreak, int OriginDetailLength, bool OriginStillNamed, PasskeyVerificationFailure TypeFailure, bool TypeHasLineBreak, bool TypeStillNamed, bool DirectHasLineBreak, int DirectLength);

    private sealed record LogOutcome(bool Registered, bool SignedIn, string? RegistrationMessage, int Events, bool AnyLineBreak, int LongestValue, bool HandleLogged, bool OriginLogged, bool CredentialLogged, bool LongDetailWasCut, string LongDetailNote, bool LongDetailLoggedUnchanged, bool ExceptionMessageCutOnce, string ExceptionNote, bool VerifierKeepsTheNote, int VerifierMessageLength);
}
