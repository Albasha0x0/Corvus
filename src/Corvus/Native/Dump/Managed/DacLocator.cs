using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Runtime;
using Corvus.Core;
using Corvus.Native.Pdb;

namespace Corvus.Native.Dump.Managed;

/// <summary>Where to look for the runtime's data access library (DAC): a caller's path, and whether a download is allowed.</summary>
public sealed record DacRequest(string? Path = null, bool Download = false, string? Server = null)
{
    /// <summary>Tests: skip the local candidates, so the download path runs on a machine that has the runtime.</summary>
    internal bool DownloadOnly { get; init; }

    /// <summary>Tests: the 32-bit decoder's path in place of the process-wide CORVUS_CLR32.</summary>
    internal string? Decoder { get; init; }
}

/// <summary>A DAC file to try, and where it came from.</summary>
public sealed record DacCandidate(string Path, string Source);

/// <summary>Finds the DAC matching a runtime, local first, downloading only on request and never under CORVUS_OFFLINE=1; each file must carry Microsoft's signature, embedded or through a system catalog, before it loads.</summary>
public static class DacLocator
{
    public const string Publisher = "Microsoft Corporation";
    public static readonly TimeSpan DownloadTimeout = TimeSpan.FromMinutes(2);
    public const long MaxDownloadBytes = 64L << 20;

    /// <summary>Local DAC candidates for <paramref name="arch"/>, best first, signatures not yet checked.</summary>
    public static IEnumerable<DacCandidate> Local(ClrInfo clr, DumpModule runtime, DacRequest request, Architecture arch, string? runtimeFolder = null)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var names = FileNames(clr.Flavor, clr.DebuggingLibraries);
        foreach (var c in Explicit(request.Path, names)) if (seen.Add(c.Path)) yield return c;

        // The runtime's recorded folder, when its file there is the dumped build.
        string? dir = runtimeFolder ?? (System.IO.Path.GetDirectoryName(runtime.Path) is { Length: > 0 } d && InputFiles.NamedProblem(runtime.Path) == null
            && DumpImages.Check(runtime.Path, runtime).Matches ? d : null);
        if (dir != null)
            foreach (var n in names)
                if (Existing(System.IO.Path.Combine(dir, n)) is { } p && seen.Add(p)) yield return new(p, "the runtime's folder");

        foreach (var folder in InstalledRuntimeFolders(runtime.FileName, arch))
        {
            var file = System.IO.Path.Combine(folder, runtime.FileName);
            if (!File.Exists(file) || !DumpImages.Check(file, runtime).Matches) continue;
            foreach (var n in names)
                if (Existing(System.IO.Path.Combine(folder, n)) is { } p && seen.Add(p)) yield return new(p, "an installed runtime of the same build");
        }

        var servers = new List<string>();
        foreach (var store in PdbLocator.LocalStores(servers))
            foreach (var (name, key, _) in StoreKeys(clr.DebuggingLibraries, arch))
                if (Existing(System.IO.Path.Combine(store, name, key, name)) is { } p && seen.Add(p)) yield return new(p, $"symbol store {store}");
    }

    /// <summary>Downloads the DAC by each of its store keys from <paramref name="request"/>'s server, else the symbol path's servers, else Microsoft's.</summary>
    public static async Task<(DacCandidate? Candidate, string? Error)> Download(ClrInfo clr, DacRequest request, Architecture arch, CancellationToken ct)
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
            foreach (var (name, key, check) in StoreKeys(clr.DebuggingLibraries, arch))
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
    public static string? Verify(byte[] bytes, string path) => Verify(bytes, path, out _);

    /// <summary>As <see cref="Verify(byte[], string)"/>; <paramref name="note"/> names a check that could not be made (revocation).</summary>
    public static string? Verify(byte[] bytes, string path, out string? note)
    {
        var embedded = Certificates.VerifyPublisher(bytes, Publisher, out note);
        if (embedded != "no embedded signature") return embedded;
        return CatalogSignature.Verify(path, Publisher, out note) is { } catalog ? $"no embedded signature; {catalog}" : null;
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
        else throw Targets.FileNotFound(path);
    }

    /// <summary>The DAC's file names for this host (Windows DLLs only): the plain name, then the long name debuggers use.</summary>
    internal static List<string> FileNames(ClrFlavor flavor, IEnumerable<DebugLibraryInfo> libraries)
    {
        var names = new List<string> { flavor == ClrFlavor.Core ? "mscordaccore.dll" : "mscordacwks.dll" };
        foreach (var d in libraries)
            if (d.Kind == DebugLibraryKind.Dac && d.Platform == OSPlatform.Windows && System.IO.Path.GetFileName(d.FileName) is { Length: > 0 } n && !names.Contains(n, StringComparer.OrdinalIgnoreCase))
                names.Add(n);
        return names;
    }

    /// <summary>The symbol store key of a file archived under a Linux runtime's build id (the SSQP "elf-buildid-coreclr" key).</summary>
    internal static string ElfKey(IEnumerable<byte> buildId) => "elf-buildid-coreclr-" + Convert.ToHexStringLower([.. buildId]);

    /// <summary>Symbol store keys of the DAC for <paramref name="arch"/>: its own (size and timestamp checked after download), the runtime's, then a Linux runtime's build id (both signature and version checked only).</summary>
    internal static IEnumerable<(string Name, string Key, Func<string, string?>? Check)> StoreKeys(IEnumerable<DebugLibraryInfo> libraries, Architecture arch)
    {
        foreach (var d in libraries.OrderBy(d => d.ArchivedUnder == SymbolProperties.Self ? 0 : 1))
        {
            if (d.Kind != DebugLibraryKind.Dac || d.Platform != OSPlatform.Windows || d.TargetArchitecture != arch) continue;
            string name = System.IO.Path.GetFileName(d.FileName);
            if (d.IndexTimeStamp == 0 || d.IndexFileSize == 0)
            {
                if (d.ArchivedUnder == SymbolProperties.Coreclr && d.IndexBuildId.Length > 0) yield return (name, ElfKey(d.IndexBuildId), null);
                continue;
            }
            uint stamp = (uint)d.IndexTimeStamp, size = (uint)d.IndexFileSize;
            Func<string, string?>? check = d.ArchivedUnder == SymbolProperties.Self ? p => PdbLocator.CheckImage(p, stamp, size) : null;
            yield return (name, PdbLocator.ImageKey(stamp, size), check);
        }
    }

    private static IEnumerable<string> InstalledRuntimeFolders(string runtimeFile, Architecture arch)
    {
        bool x86 = arch == Architecture.X86 && Environment.Is64BitOperatingSystem;
        if (runtimeFile.Equals("coreclr.dll", StringComparison.OrdinalIgnoreCase))
        {
            var roots = new List<string>();
            if (Environment.GetEnvironmentVariable(x86 ? "DOTNET_ROOT(x86)" : "DOTNET_ROOT") is { Length: > 0 } root) roots.Add(root);
            foreach (var pf in x86 ? [Environment.SpecialFolder.ProgramFilesX86] : new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
                if (Environment.GetFolderPath(pf) is { Length: > 0 } p) roots.Add(System.IO.Path.Combine(p, "dotnet"));
            // This server's own runtime: <root>/shared/Microsoft.NETCore.App/<version>/.
            if (!x86 && System.IO.Path.GetDirectoryName(typeof(object).Assembly.Location) is { Length: > 0 } own
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
            yield return System.IO.Path.Combine(windows, "Microsoft.NET", arch == Architecture.X86 ? "Framework" : "Framework64", "v4.0.30319");
        }
    }

    private static string? Existing(string path)
    {
        try { return File.Exists(path) ? System.IO.Path.GetFullPath(path) : null; }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
    }
}
