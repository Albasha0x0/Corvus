using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary>What a child process sees: the minimal environment plus its start's declared variables.</summary>
[Collection(ProcessEnvironmentCollection.Name)]
public sealed class ChildEnvironmentTests
{
    /// <summary>Runs the fake tool's environment mode and returns its working folder and variables.</summary>
    private static (string Folder, Dictionary<string, string> Variables) Report(ChildProcessStart start)
    {
        using var child = ChildProcess.Start(start);
        child.StandardInput.Dispose();
        var text = new StreamReader(child.StandardOutput).ReadToEnd();
        child.Exited.Wait(TimeSpan.FromSeconds(30));
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        var folder = lines.First(l => l.StartsWith("cwd=", StringComparison.Ordinal))[4..];
        var names = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        var variables = lines.Where(l => !l.StartsWith("cwd=", StringComparison.Ordinal) && l.IndexOf('=') > 0)
            .GroupBy(l => l[..l.IndexOf('=')], names).ToDictionary(g => g.Key, g => g.First()[(g.Key.Length + 1)..], names);
        return (folder, variables);
    }

    // Variables a POSIX shell sets for itself, here the fake tool's launcher and the watching shell.
    private static readonly string[] ShellVariables = ["PWD", "OLDPWD", "SHLVL", "_"];

    [Fact]
    public void A_child_gets_the_minimal_environment_and_its_declared_variables()
    {
        // The run sets this variable in its own environment (LeakGuard).
        Assert.NotNull(Environment.GetEnvironmentVariable(Native.Providers.Ghidra.GhidraOptions.WorkerDirectoryVariable));
        var (_, variables) = Report(new ChildProcessStart(FakeTool.Executable, ["environment"])
        {
            Environment = new Dictionary<string, string?> { ["CORVUS_CHILD_EXTRA"] = "declared" },
        });
        Assert.Equal("declared", variables["CORVUS_CHILD_EXTRA"]);
        Assert.Contains("PATH", variables.Keys, StringComparer.OrdinalIgnoreCase);
        var unexpected = variables.Keys.Where(n => !ExternalTools.Kept(n) && n != "CORVUS_CHILD_EXTRA" && !ShellVariables.Contains(n)).ToList();
        Assert.True(unexpected.Count == 0, "variables past the minimal set: " + string.Join(", ", unexpected));
    }

    [Fact]
    public void A_server_variable_reaches_a_child_only_when_CORVUS_CHILD_ENV_lists_it()
    {
        var start = new ChildProcessStart(FakeTool.Executable, ["environment"]);
        using (new EnvironmentScope().Set("PYTHONPATH", "listed-path"))
            Assert.DoesNotContain("PYTHONPATH", Report(start).Variables.Keys);
        using (new EnvironmentScope().Set("PYTHONPATH", "listed-path").Set(ExternalTools.ChildEnvironmentVariable, "OTHER, PYTHON*"))
            Assert.Equal("listed-path", Report(start).Variables["PYTHONPATH"]);
    }

    [Fact]
    public void A_child_runs_in_a_private_folder_of_its_own_removed_after_it_exits()
    {
        var start = new ChildProcessStart(FakeTool.Executable, ["environment"]);
        var (first, _) = Report(start);
        var (second, _) = Report(start);
        Assert.StartsWith(Path.Combine(Path.GetTempPath(), "corvus-run") + Path.DirectorySeparatorChar, first + Path.DirectorySeparatorChar);
        Assert.NotEqual(Path.GetFullPath(Environment.CurrentDirectory), Path.GetFullPath(first));
        Assert.NotEqual(first, second);
        Assert.True(SpinWait.SpinUntil(() => !Directory.Exists(first), TimeSpan.FromSeconds(10)), $"{first} was left behind");
    }

    [Fact]
    public void A_child_running_this_program_also_gets_its_settings()
    {
        var (_, variables) = Report(new ChildProcessStart(FakeTool.Executable, ["environment"]) { OwnProgram = true });
        Assert.Equal(Environment.GetEnvironmentVariable(Native.Providers.Ghidra.GhidraOptions.WorkerDirectoryVariable),
            variables[Native.Providers.Ghidra.GhidraOptions.WorkerDirectoryVariable]);
    }
}
