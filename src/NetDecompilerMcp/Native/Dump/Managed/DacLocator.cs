using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Runtime;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Pdb;

namespace NetDecompilerMcp.Native.Dump.Managed;

/// <summary>Where to look for the runtime's data access library (DAC): a caller's path, and whether a download is allowed.</summary>
public sealed record DacRequest(string? Path = null, bool Download = false, string? Server = null)
{
    /// <summary>Tests: skip the local candidates, so the download path runs on a machine that has the runtime.</summary>
    internal bool DownloadOnly { get; init; }
}

/// <summary>A DAC file to try, and where it came from.</summary>
public sealed record DacCandidate(string Path, string Source);

/// <summary>
/// Finds the DAC (mscordaccore.dll / mscordacwks.dll) that matches a dumped runtime, offline first: the caller's path,
/// the runtime's own folder when it holds the same build, the runtimes installed on this machine, and local symbol
/// stores. A download from a symbol server happens only when asked for, never under NDM_OFFLINE=1. Every file must
/// carry Microsoft's signature (embedded or through a system catalog) before it is loaded.
/// </summary>
public static class DacLocator
{
    public const string Publisher = "Microsoft Corporation";
    public static readonly TimeSpan DownloadTimeout = TimeSpan.FromMinutes(2);
    public const long MaxDownloadBytes = 64L << 20;

    /// <summary>Local candidates, best first; none of them is checked for its signature yet.</summary>
    public static IEnumerable<DacCandidate> Local(ClrInfo clr, DumpModule runtime, DacRequest request)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var names = FileNames(clr);
        foreach (var c in Explicit(request.Path, names)) if (seen.Add(c.Path)) yield return c;

        // the runtime's recorded folder, when its file there is the dumped build
        if (System.IO.Path.GetDirectoryName(runtime.Path) is { Length: > 0 } dir && DumpImages.Check(runtime.Path, runtime).Matches)
            foreach (var n in names)
                if (Existing(System.IO.Path.Combine(dir, n)) is { } p && seen.Add(p)) yield return new(p, "the runtime's folder");

        foreach (var folder in InstalledRuntimeFolders(runtime.FileName))
        {
            var file = System.IO.Path.Combine(folder, runtime.FileName);
            if (!File.Exists(file) || !DumpImages.Check(file, runtime).Matches) continue;
            foreach (var n in names)
                if (Existing(System.IO.Path.Combine(folder, n)) is { } p && seen.Add(p)) yield return new(p, "an installed runtime of the same build");
        }

        var servers = new List<string>();
        foreach (var store in PdbLocator.LocalStores(servers))
            foreach (var (name, key, _) in StoreKeys(clr))
                if (Existing(System.IO.Path.Combine(store, name, key, name)) is { } p && seen.Add(p)) yield return new(p, $"symbol store {store}");
    }

    /// <summary>Downloads the DAC by each of its store keys from <paramref name="request"/>'s server, else the symbol path's servers, else Microsoft's.</summary>
    public static async Task<(DacCandidate? Candidate, string? Error)> Download(ClrInfo clr, DacRequest request, CancellationToken ct)
    {
        var servers = new List<string>();
        if (request.Server is { Length: > 0 } s) servers.Add(s);
        else
        {
            PdbLocator.LocalStores(servers);
            if (servers.Count == 0) servers.Add(PdbLocator.DefaultServer);
        }
        string? error = null;
        foreach (var server in servers)
            foreach (var (name, key, check) in StoreKeys(clr))
            {
                try
                {
                    var path = await PdbLocator.DownloadImageAsync(name, key, check, server, DownloadTimeout, MaxDownloadBytes, ct: ct).ConfigureAwait(false);
                    return (new DacCandidate(path, $"downloaded from {server}"), null);
                }
                catch (ToolError e) { error ??= e.Message; }
            }
        return (null, error ?? "no symbol store key for this runtime's DAC");
    }

    /// <summary>Null when the file carries Microsoft's signature, embedded or through a system catalog; else why not.</summary>
    public static string? Verify(byte[] bytes, string path)
    {
        var embedded = Certificates.VerifyPublisher(bytes, Publisher);
        if (embedded != "no embedded signature") return embedded;
        return CatalogSignature.Verify(path, Publisher) is { } catalog ? $"no embedded signature; {catalog}" : null;
    }

    private static IEnumerable<DacCandidate> Explicit(string? path, IReadOnlyList<string> names)
    {
        if (string.IsNullOrWhiteSpace(path)) yield break;
        string full;
        try { full = System.IO.Path.GetFullPath(path.Trim()); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ToolError(ErrorCode.InvalidArgument, $"dacPath: '{path}' is not a valid path: {ex.Message}");
        }
        if (Directory.Exists(full))
        {
            foreach (var n in names)
                if (Existing(System.IO.Path.Combine(full, n)) is { } p) yield return new(p, "dacPath");
        }
        else if (File.Exists(full)) yield return new(full, "dacPath");
        else throw new ToolError(ErrorCode.NotFound, $"dacPath: nothing at '{path}'.", "pass the DAC file or the folder of the dumped runtime");
    }

    /// <summary>The DAC's file names for this host: the plain name, then the long name debuggers use.</summary>
    private static List<string> FileNames(ClrInfo clr)
    {
        var names = new List<string> { clr.Flavor == ClrFlavor.Core ? "mscordaccore.dll" : "mscordacwks.dll" };
        foreach (var d in clr.DebuggingLibraries)
            if (d.Kind == DebugLibraryKind.Dac && System.IO.Path.GetFileName(d.FileName) is { Length: > 0 } n && !names.Contains(n, StringComparer.OrdinalIgnoreCase))
                names.Add(n);
        return names;
    }

    /// <summary>
    /// Symbol store keys of the DAC for this host's architecture: its own timestamp and size (checked after a download),
    /// then the runtime's (the long-name file, matched by its signature and version only).
    /// </summary>
    private static IEnumerable<(string Name, string Key, Func<string, string?>? Check)> StoreKeys(ClrInfo clr)
    {
        var arch = RuntimeInformation.ProcessArchitecture;
        foreach (var d in clr.DebuggingLibraries.OrderBy(d => d.ArchivedUnder == SymbolProperties.Self ? 0 : 1))
        {
            if (d.Kind != DebugLibraryKind.Dac || d.Platform != OSPlatform.Windows || d.TargetArchitecture != arch || d.IndexTimeStamp == 0 || d.IndexFileSize == 0) continue;
            string name = System.IO.Path.GetFileName(d.FileName);
            uint stamp = (uint)d.IndexTimeStamp, size = (uint)d.IndexFileSize;
            Func<string, string?>? check = d.ArchivedUnder == SymbolProperties.Self ? p => PdbLocator.CheckImage(p, stamp, size) : null;
            yield return (name, PdbLocator.ImageKey(stamp, size), check);
        }
    }

    private static IEnumerable<string> InstalledRuntimeFolders(string runtimeFile)
    {
        if (runtimeFile.Equals("coreclr.dll", StringComparison.OrdinalIgnoreCase))
        {
            var roots = new List<string>();
            if (Environment.GetEnvironmentVariable("DOTNET_ROOT") is { Length: > 0 } root) roots.Add(root);
            foreach (var pf in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
                if (Environment.GetFolderPath(pf) is { Length: > 0 } p) roots.Add(System.IO.Path.Combine(p, "dotnet"));
            // this server's own runtime: <root>/shared/Microsoft.NETCore.App/<version>/
            if (System.IO.Path.GetDirectoryName(typeof(object).Assembly.Location) is { Length: > 0 } own
                && Directory.GetParent(own)?.Parent?.Parent is { } ownRoot) roots.Add(ownRoot.FullName);
            foreach (var r in roots.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var shared = System.IO.Path.Combine(r, "shared", "Microsoft.NETCore.App");
                if (!Directory.Exists(shared)) continue;
                string[] versions;
                try { versions = Directory.GetDirectories(shared); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
                foreach (var v in versions) yield return v;
            }
        }
        else if (runtimeFile.Equals("clr.dll", StringComparison.OrdinalIgnoreCase) && Environment.GetFolderPath(Environment.SpecialFolder.Windows) is { Length: > 0 } windows)
        {
            yield return System.IO.Path.Combine(windows, "Microsoft.NET", Environment.Is64BitProcess ? "Framework64" : "Framework", "v4.0.30319");
        }
    }

    private static string? Existing(string path)
    {
        try { return File.Exists(path) ? System.IO.Path.GetFullPath(path) : null; }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
    }
}
