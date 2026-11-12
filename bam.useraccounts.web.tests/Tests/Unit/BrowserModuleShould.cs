using System.Diagnostics;
using Bam.DependencyInjection;
using Bam.Test;

namespace Bam.UserAccounts.Web.Tests.Unit;

[UnitTestMenu("BrowserModule Should", Selector = "brmo")]
public class BrowserModuleShould : UnitTestMenuContainer
{
    public BrowserModuleShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    // The module loads on host pages next to content the host didn't write, so injected markup
    // must not be able to choose where its requests go or where the browser navigates.
    // BrowserModule/passkeys.check.mjs runs the module against a stub DOM; it needs Node on PATH.
    [UnitTest]
    public void TakeNothingThatRoutesRequestsOrNavigationFromThePage()
    {
        When.A<NodeCheck>("runs the browser module against markup a host page might carry",
            () => new NodeCheck(Path.Combine(AppContext.BaseDirectory, "BrowserModule")),
            (check) => check.Run("passkeys.check.mjs", "passkeys.js"))
            .TheTest
            .ShouldPass<NodeCheckResult>((because, result) =>
            {
                because.ItsTrue($"node ran the check ({result.Started}: {result.Error})", result.Started);
                because.ItsTrue($"and every check passed (exit {result.ExitCode}): {result.Output}", result.ExitCode == 0 && result.Output.Contains("checks passed", StringComparison.Ordinal));
            })
            .SoBeHappy()
            .UnlessItFailed();
    }
}

/// <summary>Runs a Node script from a directory and captures what it printed.</summary>
public sealed class NodeCheck
{
    private readonly string _directory;

    public NodeCheck(string directory)
    {
        _directory = directory;
    }

    public NodeCheckResult Run(string script, string argument)
    {
        ProcessStartInfo start = new ProcessStartInfo("node")
        {
            WorkingDirectory = _directory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        start.ArgumentList.Add(Path.Combine(_directory, script));
        start.ArgumentList.Add(Path.Combine(_directory, argument));
        try
        {
            using Process process = Process.Start(start) ?? throw new InvalidOperationException("node did not start");
            Task<string> output = process.StandardOutput.ReadToEndAsync();
            Task<string> error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(60_000))
            {
                process.Kill(true);
                return new NodeCheckResult(true, -1, output.GetAwaiter().GetResult(), "timed out after 60 s");
            }
            return new NodeCheckResult(true, process.ExitCode, output.GetAwaiter().GetResult(), error.GetAwaiter().GetResult());
        }
        catch (System.ComponentModel.Win32Exception e)
        {
            return new NodeCheckResult(false, -1, string.Empty, "node is required for this check and was not found on PATH: " + e.Message);
        }
    }
}

/// <summary>What a Node check printed and how it exited.</summary>
public sealed record NodeCheckResult(bool Started, int ExitCode, string Output, string Error);
