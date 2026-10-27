using System.IO.Compression;
using System.Text;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>search_container kind=electron: surface rows of the app's own scripts, matched by value, kind or call; add-ons name their N-API registrations.</summary>
internal sealed class ElectronSearchKind : IContainerSearchKind
{
    private const long MaxScriptBytes = 16 * 1024 * 1024;

    public IReadOnlyList<string> Kinds => ["electron"];

    public IEnumerable<ContainerMatch> Search(ContainerScope scope, string kind, Func<string, bool> matches, CancellationToken ct)
    {
        var addons = new Dictionary<string, Addon?>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in Rows(scope, ct))
            if (matches(row.Value) || matches(row.Kind) || row.Call != null && matches(row.Call))
            {
                var file = row.Site[..row.Site.IndexOf(':')];
                var detail = $"{row.Kind} at {row.Site}" + (row.Call != null ? $" ({row.Call})" : "") + (row.Link != null ? "; " + row.Link : "");
                if (row.Kind == "native-require" && Find(scope.Source, file, row.Value, addons, ct) is { } addon) detail += "; " + addon.Summary;
                else if (row is { Kind: "native-call", Link: { } request } && Find(scope.Source, file, request, addons, ct) is { } called) detail += "; " + called.Join(row.Value);
                yield return new ContainerMatch(file, row.Value, "electron") { Detail = detail };
            }
    }

    /// <summary>An add-on with its N-API registrations: a summary line, and the native function a JavaScript name reaches.</summary>
    internal sealed record Addon(string Path, ulong ImageBase, IReadOnlyList<Native.NodeApi.Registration> Registrations)
    {
        public string Summary => $"add-on {Path}: {Registrations.Count} N-API registration(s)" +
                                 (Registrations.Count > 0 ? ": " + string.Join(", ", Registrations.Select(r => r.JsName).Distinct().Take(12)) + (Registrations.Count > 12 ? ", ..." : "") : "");

        /// <summary>The registration of <paramref name="name"/> (a function, Class.method, or a class constructed with new).</summary>
        public string Join(string name)
        {
            var hit = Registrations.FirstOrDefault(r => r.JsName == name) ?? Registrations.FirstOrDefault(r => r.JsName.EndsWith("." + name, StringComparison.Ordinal));
            return hit != null
                ? $"native {Path} 0x{ImageBase + hit.Function:X} (RVA 0x{hit.Function:X}, {hit.Kind} '{hit.JsName}')"
                : $"add-on {Path}: no N-API registration named '{name}' read ({Registrations.Count} read)";
        }
    }

    /// <summary>The add-on a require names under the app's app.asar.unpacked folder, with its N-API registrations; null when not found.</summary>
    internal static Addon? Find(string source, string script, string request, Dictionary<string, Addon?> seen, CancellationToken ct)
    {
        var root = source.EndsWith(".asar", StringComparison.OrdinalIgnoreCase) ? source + ".unpacked"
            : Path.Combine(Path.GetDirectoryName(source) ?? "", "resources", "app.asar.unpacked");
        if (!Directory.Exists(root)) return null;
        var path = Locate(root, script, request);
        if (path == null || !Path.GetFullPath(path).StartsWith(Path.GetFullPath(root), StringComparison.OrdinalIgnoreCase) || !File.Exists(path)) return null;
        if (seen.TryGetValue(path, out var known)) return known;
        Addon? result = null;
        try
        {
            var image = Native.NativeImageLoader.Open(path);
            if (Native.NodeApi.IsAddon(image))
                result = new Addon(Path.GetRelativePath(root, path).Replace('\\', '/'), image.ImageBase,
                    Native.NodeApi.Find(Native.Code.NativeCodeIndex.Build(image, ct: ct), ct).Registrations);
        }
        catch (ToolError) { }
        seen[path] = result;
        return result;
    }

    /// <summary>The .node file of a relative path, bindings('name') (Release first) or node_modules package (this OS first); null when none.</summary>
    private static string? Locate(string root, string script, string request)
    {
        if (request.StartsWith('.')) return Path.GetFullPath(Path.Combine(root, Path.GetDirectoryName(script) ?? "", request));
        var options = new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 8, AttributesToSkip = FileAttributes.ReparsePoint, IgnoreInaccessible = true };
        try
        {
            if (request.StartsWith("bindings:", StringComparison.Ordinal))
            {
                var name = request["bindings:".Length..];
                if (!name.EndsWith(".node", StringComparison.OrdinalIgnoreCase)) name += ".node";
                return Directory.EnumerateFiles(root, Path.GetFileName(name), options).OrderBy(f => f.Contains("Release", StringComparison.Ordinal) ? 0 : 1).FirstOrDefault();
            }
            var package = Path.Combine(root, "node_modules", request.Replace('/', Path.DirectorySeparatorChar));
            if (!Directory.Exists(package)) return null;
            var os = OperatingSystem.IsWindows() ? "win32" : OperatingSystem.IsMacOS() ? "darwin" : "linux";
            return Directory.EnumerateFiles(package, "*.node", options).OrderBy(f => Path.GetFileName(f).Contains(os, StringComparison.Ordinal) ? 0 : 1).FirstOrDefault();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    private static List<ElectronRow> Rows(ContainerScope scope, CancellationToken ct)
    {
        var rows = new List<ElectronRow>();
        var source = scope.Source;
        byte[] head = new byte[8];
        try
        {
            using var f = File.OpenRead(source);
            f.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return rows; }
        if (Blob.Identify(head) == "zip")
        {
            using var zip = ZipFile.OpenRead(source);
            var names = zip.Entries.Select(e => e.FullName.Replace('\\', '/')).ToHashSet(StringComparer.Ordinal);
            var graph = new ElectronGraph { Exists = names.Contains };
            foreach (var e in zip.Entries)
            {
                ct.ThrowIfCancellationRequested();
                var path = e.FullName.Replace('\\', '/');
                if (!IsAppScript(path) || e.Length > MaxScriptBytes) continue;
                using var s = e.Open();
                using var copy = new MemoryStream();
                s.CopyTo(copy);
                graph.Add(path, Encoding.UTF8.GetString(copy.ToArray()), ct);
            }
            return graph.Finish();
        }
        // An Electron executable or .asar is read as summarize_file reads it.
        try
        {
            if (new FileInfo(source).Length <= AnalysisLimits.Default.MaxItemBytes
                && ElectronInspector.Of(source, File.ReadAllBytes(source), ct) is { } facts) return [.. facts.Surface];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return rows;
    }

    private static bool IsAppScript(string p) =>
        (p.EndsWith(".js", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".cjs", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".mjs", StringComparison.OrdinalIgnoreCase))
        && !p.StartsWith("node_modules/", StringComparison.Ordinal) && !p.Contains("/node_modules/", StringComparison.Ordinal);
}
