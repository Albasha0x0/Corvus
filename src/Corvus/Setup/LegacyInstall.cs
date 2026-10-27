using System.Diagnostics;

namespace Corvus.Setup;

/// <summary>Migration only: the install layout from before the rename, moved to the current layout on its next install or update.</summary>
internal static class LegacyInstall
{
    public static string ExeName => OperatingSystem.IsWindows() ? "NetDecompilerMcp.exe" : "NetDecompilerMcp";

    public static string Root(SetupEnvironment env) =>
        env.Os == HostOs.Windows ? Path.Combine(env.LocalAppData, "NetDecompilerMcp") : Path.Combine(Installation.XdgData(env), "net-decompiler-mcp");

    /// <summary>Whether <paramref name="root"/> is the old layout's install root.</summary>
    public static bool IsRoot(SetupEnvironment env, string root) => SamePath(root, Root(env));

    /// <summary>From the old layout: copies the build to the current layout, runs <paramref name="args"/> there and removes the old files; else null.</summary>
    public static int? Relocate(string[] args, TextWriter output, SetupEnvironment env)
    {
        if (Installation.Root() is not { } root || !IsRoot(env, root)) return null;
        var newRoot = Installation.DefaultRoot(env);
        output.WriteLine($"Moving the program from {root} to {newRoot}.");
        string target;
        try
        {
            target = CopyBuild(AppContext.BaseDirectory, Path.Combine(newRoot, "versions"), Installation.Version);
            Installation.PointCurrent(newRoot, target);
            Installation.PutOnPath(newRoot, root, ExeName);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            output.WriteLine($"Could not move the program to {newRoot}: {ex.Message}");
            return 1;
        }
        var start = new ProcessStartInfo(Path.Combine(newRoot, "current", Installation.ExeName)) { UseShellExecute = false };
        foreach (var arg in args) start.ArgumentList.Add(arg);
        int code;
        using (var p = Process.Start(start)!)
        {
            p.WaitForExit();
            code = p.ExitCode;
        }
        // This process runs from the old files: on Windows they are deleted once it exits.
        var plan = Plan(root);
        if (OperatingSystem.IsWindows())
            Process.Start(new ProcessStartInfo("cmd.exe", "/c " + Installation.DeferredWindowsCommand(plan)) { UseShellExecute = false, CreateNoWindow = true });
        else Installation.Apply(plan);
        return code;
    }

    /// <summary>Removes the old layout's program files, PATH entry or link and the empty folder; null when there is no old install.</summary>
    public static string? Remove(SetupEnvironment env, string newRoot)
    {
        var root = Root(env);
        if (!Directory.Exists(Path.Combine(root, "versions")) || SamePath(root, newRoot)) return null;
        Installation.PutOnPath(newRoot, root, ExeName);
        RemoveVersions(root);
        return root;
    }

    /// <summary>Deletes each old build no process runs from, then current and the empty folders.</summary>
    // Windows cannot rename a folder holding a running program, and a half-deleted build would fail its server.
    internal static void RemoveVersions(string root)
    {
        var versions = Path.Combine(root, "versions");
        foreach (var dir in Directory.EnumerateDirectories(versions))
        {
            var aside = dir + ".remove-" + Guid.NewGuid().ToString("N")[..6];
            try
            {
                Directory.Move(dir, aside);
                Directory.Delete(aside, recursive: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        if (Directory.EnumerateFileSystemEntries(versions).Any()) return;
        Installation.Apply(Plan(root));
    }

    /// <summary>The old program files (current, versions/), then the folder once empty: on Windows it also held data, which stays until moved.</summary>
    internal static Installation.Removal Plan(string root) => Installation.PlanRemoval(root, root, purgeData: false);

    /// <summary>Copies the build in <paramref name="source"/>, without the old program name, to versions/&lt;version&gt; unless there.</summary>
    internal static string CopyBuild(string source, string versions, string version)
    {
        var target = Path.Combine(versions, version);
        if (File.Exists(Path.Combine(target, Installation.ExeName))) return target;
        var staging = Path.Combine(versions, ".new-" + Guid.NewGuid().ToString("N")[..8]);
        Copy(source, staging, top: true);
        if (Directory.Exists(target)) Corvus.Core.SafeFile.WhenReleased(() => Directory.Delete(target, recursive: true));
        Corvus.Core.SafeFile.WhenReleased(() => Directory.Move(staging, target));
        return target;
    }

    private static void Copy(string source, string destination, bool top)
    {
        Directory.CreateDirectory(destination);
        foreach (var file in Directory.EnumerateFiles(source))
            if (!(top && Path.GetFileName(file).Equals(ExeName, StringComparison.OrdinalIgnoreCase)))
                File.Copy(file, Path.Combine(destination, Path.GetFileName(file)));
        foreach (var dir in Directory.EnumerateDirectories(source)) Copy(dir, Path.Combine(destination, Path.GetFileName(dir)), top: false);
    }

    private static bool SamePath(string a, string b) =>
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(a)).Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(b)),
            OperatingSystem.IsLinux() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase);
}
