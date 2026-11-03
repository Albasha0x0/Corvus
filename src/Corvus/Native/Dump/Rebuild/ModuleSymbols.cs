using Corvus.Core;
using Corvus.Native.Pdb;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Outcome of <see cref="ModuleSymbols.Find"/>: <c>found</c>, <c>no_codeview</c>, <c>not_found</c>, <c>mismatch</c> or <c>refused</c>.</summary>
public sealed record ModuleSymbolResult(string Status, string? PdbPath, string? Reason, IReadOnlyList<PdbProbe> Looked);

/// <summary>Finds the PDB named by the CodeView record of a rebuilt module.</summary>
public static class ModuleSymbols
{
    /// <summary>Time limit of one symbol server download.</summary>
    public static readonly TimeSpan DownloadTimeout = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Locates the PDB of <paramref name="rebuilt"/> by GUID and age in <paramref name="imageDirectories"/>
    /// (separated by the path separator), local stores and _NT_SYMBOL_PATH; with <paramref name="download"/> it then
    /// asks the configured symbol servers. A PDB of another build or age is reported, never returned.
    /// <paramref name="offline"/> defaults to CORVUS_OFFLINE, which refuses the download.
    /// </summary>
    public static ModuleSymbolResult Find(byte[] rebuilt, string? imageDirectories, bool download, CancellationToken ct,
        bool? offline = null)
    {
        PeFile pe;
        try { pe = PeFile.FromBytes(rebuilt); }
        catch (ToolError e) { return new("no_codeview", null, "the module is not a readable PE image: " + e.Message, []); }

        var cv = pe.CodeView;
        if (cv == null) return new("no_codeview", null, "the module has no CodeView debug record", []);
        if (cv.Format != "RSDS")
            return new("no_codeview", null, "the module has a PDB 2.0 (NB10) record; only PDB 7.0 (RSDS) is matched", []);

        var looked = new List<PdbProbe>();
        var servers = new List<string>();
        var directories = (imageDirectories ?? "")
            .Split(System.IO.Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var dir in directories.Length > 0 ? directories : new string?[] { null })
        {
            ct.ThrowIfCancellationRequested();
            var location = PdbLocator.Locate(pe, dir);
            foreach (var p in location.Probes)
                if (!looked.Contains(p)) looked.Add(p);
            foreach (var s in location.Servers)
                if (!servers.Contains(s, StringComparer.OrdinalIgnoreCase)) servers.Add(s);
            if (location.Path != null) return new("found", location.Path, null, looked);
        }

        if (!download) return NotFound(looked, "download was not requested");
        if (offline ?? ReferencePacks.Offline)
            return new("refused", null, "CORVUS_OFFLINE is set: no symbol server is asked", looked);

        foreach (var server in PdbLocator.ConfiguredServers())
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var path = PdbLocator.DownloadAsync(cv, server, DownloadTimeout, PdbLocator.DefaultMaxDownloadBytes, null, null, ct)
                    .GetAwaiter().GetResult();
                looked.Add(new PdbProbe(server, "downloaded to " + path));
                return new("found", path, null, looked);
            }
            catch (ToolError e)
            {
                looked.Add(new PdbProbe(server, "download failed: " + e.Message));
            }
        }
        return NotFound(looked, "no symbol server had it");
    }

    private static ModuleSymbolResult NotFound(List<PdbProbe> looked, string tail)
    {
        var mismatch = looked.FirstOrDefault(p => p.Outcome.StartsWith("different ", StringComparison.Ordinal));
        return mismatch != null
            ? new("mismatch", null, $"{mismatch.Location}: {mismatch.Outcome}; {tail}", looked)
            : new("not_found", null, "no PDB with this GUID and age was found; " + tail, looked);
    }
}
