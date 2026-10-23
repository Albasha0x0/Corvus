using System.Diagnostics;

namespace Corvus.Tests;

/// <summary>Creates directory links (symbolic link, or a junction on Windows without the symlink privilege) and hard links.</summary>
public static class Links
{
    private static readonly Lazy<string?> DirectoryProbe = new(() => Probe(CreateDirectoryLink));
    private static readonly Lazy<string?> HardProbe = new(() => Probe((link, target) => CreateHardLink(link, Path.Combine(target, "f"))));

    /// <summary>Why directory links cannot be created here, or null.</summary>
    public static string? DirectoryLinkUnavailable => DirectoryProbe.Value;

    /// <summary>Why hard links cannot be created here, or null.</summary>
    public static string? HardLinkUnavailable => HardProbe.Value;

    private static string? Probe(Action<string, string> create)
    {
        var root = Path.Combine(Path.GetTempPath(), "corvus-test-link-probe-" + Guid.NewGuid().ToString("N"));
        try
        {
            var target = Directory.CreateDirectory(Path.Combine(root, "target")).FullName;
            File.WriteAllText(Path.Combine(target, "f"), "x");
            create(Path.Combine(root, "link"), target);
            return null;
        }
        catch (Exception ex) { return $"The OS refused to create the link: {ex.Message}"; }
        finally
        {
            try { Directory.Delete(root, true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    public static void CreateDirectoryLink(string link, string target)
    {
        try { Directory.CreateSymbolicLink(link, target); }
        catch (Exception ex) when (OperatingSystem.IsWindows() && ex is IOException or UnauthorizedAccessException)
        {
            Run("cmd.exe", "/c", "mklink", "/J", link, target); // junctions need no privilege
        }
    }

    public static void CreateHardLink(string link, string target)
    {
        if (OperatingSystem.IsWindows()) Run("cmd.exe", "/c", "mklink", "/H", link, target);
        else Run("ln", target, link);
    }

    private static void Run(string file, params string[] args)
    {
        var info = new ProcessStartInfo(file) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in args) info.ArgumentList.Add(a);
        using var p = Process.Start(info)!;
        var error = p.StandardError.ReadToEnd() + p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0) throw new IOException($"{file} {string.Join(' ', args)} failed: {error.Trim()}");
    }
}

/// <summary>A fact skipped, with the reason, where the OS refuses to create directory links; the probe (mklink /J) runs when a test runs.</summary>
[Xunit.Sdk.XunitTestCaseDiscoverer(RunTimeSkips.FactDiscoverer, RunTimeSkips.Assembly)]
public sealed class DirectoryLinkFactAttribute : FactAttribute, IRunTimeSkip
{
    public string? RunTimeSkip() => Links.DirectoryLinkUnavailable;
}

/// <summary>A fact skipped, with the reason, where the OS refuses to create hard links; the probe (mklink /H, ln) runs when a test runs.</summary>
[Xunit.Sdk.XunitTestCaseDiscoverer(RunTimeSkips.FactDiscoverer, RunTimeSkips.Assembly)]
public sealed class HardLinkFactAttribute : FactAttribute, IRunTimeSkip
{
    public string? RunTimeSkip() => Links.HardLinkUnavailable;
}
