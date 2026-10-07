using System.Text.Json.Serialization;
using dnlib.DotNet;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Services.Analysis;

/// <summary>
/// Opens a container file and walks everything in it: containers inside containers are opened too (e.g. a
/// Costura-packed app inside a single-file bundle), up to <see cref="AnalysisLimits.MaxDepth"/>.
/// <see cref="Unpack"/> writes the files to disk and loads the .NET assemblies; <see cref="List"/> only reports the
/// assemblies. Unpack output goes to a directory of its own (by default under the temp folder, named after the file's
/// hash), marked so a second unpack of the same file reuses it and an unrelated directory is never written into.
/// </summary>
public sealed class UnpackService(AssemblyWorkspace workspace)
{
    private const string Marker = ".netdecomp-unpack";
    private const string DotNet = ".NET assembly";

    /// <summary>One extracted file. ReadyToRun and Merged are set for .NET assemblies only.</summary>
    public sealed record UnpackedFile(string Path, string Kind, long Size, string Sha256, string Origin, string? LoadedAs,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? ReadyToRun = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Merged = null);

    public sealed record UnpackReport(string Source, string Container, string OutputDirectory, List<UnpackedFile> Files, List<string> Notes);

    /// <summary>A managed assembly inside a container. Path is its location inside the container (nested ones under "x_unpacked/").</summary>
    public sealed record ContainedAssembly(string Path, string? Name, string? Version, long Size, string Sha256, string Origin, bool ReadyToRun,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Merged);

    public sealed record ContainerListing(string Source, string Container, List<ContainedAssembly> Assemblies, List<string> Notes);

    /// <summary>A file found in the container, with its sanitized relative output path.</summary>
    private sealed record Found(string Relative, byte[] Bytes, string Kind, string Sha256, string Origin);

    private sealed record Walked(string Container, List<Found> Items, List<string> Notes);

    public UnpackReport Unpack(string path, string? outputDirectory, bool load, AnalysisLimits limits, CancellationToken ct)
    {
        var (source, data, sha) = ReadSource(path, limits);
        var root = PrepareOutput(outputDirectory ?? DefaultOutput(source, sha), source, sha);
        var walked = Walk(data, sha, Path.GetFileName(source), limits, ct);
        var notes = walked.Notes;
        var files = new List<UnpackedFile>();
        foreach (var item in walked.Items)
        {
            ct.ThrowIfCancellationRequested();
            string written;
            try { written = Blob.WriteUnique(root, item.Relative, item.Bytes); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) // e.g. "a.dll" and "a.dll/b.dll" in one archive
            {
                notes.Add($"Could not write {item.Relative}: {ex.Message}");
                continue;
            }
            var file = new UnpackedFile(written, item.Kind, item.Bytes.Length, item.Sha256, item.Origin, null);
            if (item.Kind == DotNet)
                file = file with { ReadyToRun = AssemblyTraits.IsReadyToRun(item.Bytes), Merged = Inspect(item.Bytes)?.Merged };
            files.Add(file);
        }

        if (load) LoadAssemblies(files, notes);
        return new UnpackReport(source, walked.Container, root, files, notes);
    }

    /// <summary>
    /// The managed assemblies inside a container, without writing anything. A plain assembly lists itself.
    /// Throws <see cref="ToolError"/> when the container itself is corrupt.
    /// </summary>
    public ContainerListing List(string path, AnalysisLimits limits, CancellationToken ct)
    {
        var managed = Managed(path, limits, ct);
        return new ContainerListing(managed.Source, managed.Container,
            managed.Assemblies.Select(a => Describe(a.Path, a.Bytes, a.Sha256, a.Origin)).ToList(), managed.Notes);
    }

    /// <summary>A symbol found by <see cref="Search"/>: where it lives in the container, and what it is.</summary>
    public sealed record ContainerSymbol(string Path, string Assembly, string Name, string Kind);

    public sealed record ContainerSearch(string Source, string Container, int AssembliesSearched, List<ContainerSymbol> Matches, int Total,
        bool Truncated, List<string> Notes);

    /// <summary>The kinds search_container accepts; null or "any" for all (events included).</summary>
    public static SymbolKind ParseSearchKind(string? kind) => kind?.Trim().ToLowerInvariant() switch
    {
        null or "" or "any" => SymbolKind.Any,
        "type" => SymbolKind.Type,
        "method" => SymbolKind.Method,
        "field" => SymbolKind.Field,
        "property" => SymbolKind.Property,
        _ => throw new ToolError($"Unknown kind '{kind}': use type, method, field or property, or omit it for all."),
    };

    /// <summary>
    /// Searches the metadata of every managed assembly in a container (or a plain assembly) by name, in memory: nothing
    /// is written or loaded. Matching is that of search_symbols (case-insensitive substring; '*' / '?' wildcards; queries
    /// with '.' or ':' also match full names). Best matches first (exact, then prefix, then substring); at most
    /// <paramref name="limit"/> are returned, and <see cref="ContainerSearch.Total"/> counts them all.
    /// </summary>
    public ContainerSearch Search(string path, string query, SymbolKind kind, int limit, AnalysisLimits limits, CancellationToken ct)
    {
        var matcher = SearchService.CreateMatcher(query, regex: false);
        bool matchFullName = query.Contains('.') || query.Contains(':');
        var managed = Managed(path, limits, ct);
        var notes = managed.Notes;
        // one bucket per rank, each capped at the limit: the best matches survive without holding every hit
        var buckets = Enumerable.Range(0, 4).Select(_ => new List<ContainerSymbol>()).ToArray();
        int total = 0, searched = 0;
        foreach (var a in managed.Assemblies)
        {
            ct.ThrowIfCancellationRequested();
            ModuleDefMD module;
            try { module = ModuleDefMD.Load(a.Bytes); }
            catch (Exception) { notes.Add($"{a.Path}: unreadable metadata, not searched."); continue; }
            using (module)
            {
                var assemblyName = module.Assembly?.Name.String ?? module.Name.String;
                try
                {
                    foreach (var type in module.GetTypes())
                    {
                        ct.ThrowIfCancellationRequested();
                        foreach (var member in SearchService.MembersOf(type, kind))
                        {
                            var name = member is TypeDef td ? Format.StripArity(td.Name) : member.Name.String;
                            if (!matcher(name) && !(matchFullName && matcher(Format.MemberLabel(member)))) continue;
                            total++;
                            var bucket = buckets[SearchService.Rank(name, query)];
                            if (bucket.Count < limit) bucket.Add(new ContainerSymbol(a.Path, assemblyName, Format.MemberLabel(member), KindName(member)));
                        }
                    }
                    searched++;
                }
                catch (Exception ex) when (ex is not OperationCanceledException) // dnlib reads rows lazily
                {
                    notes.Add($"{a.Path}: corrupt metadata, only partly searched ({ex.Message}).");
                }
            }
        }
        var matches = buckets.SelectMany(b => b).Take(limit).ToList();
        return new ContainerSearch(managed.Source, managed.Container, searched, matches, total, total > matches.Count, notes);
    }

    private static string KindName(IMemberDef m) => m switch
    {
        TypeDef => "type",
        MethodDef => "method",
        FieldDef => "field",
        PropertyDef => "property",
        EventDef => "event",
        _ => "member",
    };

    internal sealed record ManagedAssembly(string Path, byte[] Bytes, string Sha256, string Origin);

    /// <summary>The managed assemblies a file holds, found by <see cref="Walk"/>; a plain assembly is its own one.</summary>
    internal static (string Source, string Container, List<ManagedAssembly> Assemblies, List<string> Notes) Managed(string path, AnalysisLimits limits, CancellationToken ct)
    {
        var (source, data, sha) = ReadSource(path, limits);
        var walked = Walk(data, sha, Path.GetFileName(source), limits, ct);
        var assemblies = walked.Items.Where(i => i.Kind == DotNet)
            .Select(i => new ManagedAssembly(i.Relative.Replace(System.IO.Path.DirectorySeparatorChar, '/'), i.Bytes, i.Sha256, i.Origin)).ToList();
        var container = walked.Container;
        if (container == "none" && Blob.Identify(data) == DotNet)
        {
            // not a container: the file is the one managed assembly
            container = "none (plain .NET assembly)";
            assemblies = [new ManagedAssembly(Path.GetFileName(source), data, sha, "the file itself")];
            walked.Notes.RemoveAll(n => n.StartsWith("A plain .NET assembly", StringComparison.Ordinal));
        }
        return (source, container, assemblies, walked.Notes);
    }

    private static ContainedAssembly Describe(string path, byte[] bytes, string sha, string origin)
    {
        var info = Inspect(bytes);
        return new ContainedAssembly(path.Replace('\\', '/'), info?.Name, info?.Version, bytes.Length, sha, origin,
            AssemblyTraits.IsReadyToRun(bytes), info?.Merged);
    }

    /// <summary>Identity and merge note from the metadata; null when dnlib cannot read it.</summary>
    private static (string Name, string? Version, string? Merged)? Inspect(byte[] bytes)
    {
        try
        {
            using var module = ModuleDefMD.Load(bytes);
            return (module.Assembly?.FullName ?? module.Name.String, module.Assembly?.Version?.ToString(), AssemblyTraits.MergeNote(module));
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static (string Source, byte[] Data, string Sha) ReadSource(string path, AnalysisLimits limits)
    {
        var source = Path.GetFullPath(path);
        if (!File.Exists(source)) throw new ToolError($"File not found: {source}");
        var length = new FileInfo(source).Length;
        if (length > Math.Min(limits.MaxTotalBytes, Array.MaxLength)) throw new ToolError($"{source} is too large to unpack ({length:N0} bytes).");
        var data = File.ReadAllBytes(source);
        return (source, data, Blob.Sha256(data));
    }

    /// <summary>Opens the container and every container inside it, breadth first; duplicates (same hash) appear once.</summary>
    private static Walked Walk(byte[] data, string sha, string name, AnalysisLimits limits, CancellationToken ct)
    {
        var notes = new List<string>();
        var found = new List<Found>();
        var seen = new HashSet<string> { sha };
        long total = 0;

        var top = Containers.Open(data, name, limits, ct);
        notes.AddRange(top.Notes);
        var queue = new Queue<(ExtractedItem Item, string Prefix, int Depth)>(top.Items.Select(i => (i, "", 1)));
        while (queue.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (item, prefix, depth) = queue.Dequeue();
            var itemSha = Blob.Sha256(item.Bytes);
            if (!seen.Add(itemSha)) continue; // the same file in several places (e.g. per-ABI assembly stores)
            if (found.Count >= limits.MaxItems || (total += item.Bytes.Length) > limits.MaxTotalBytes)
            {
                notes.Add("Stopped: the extraction limit was reached; some files were not extracted.");
                break;
            }

            var kind = Blob.Identify(item.Bytes);
            // joined as text, not Path.Combine: a rooted item name would otherwise drop the prefix
            var relative = Blob.SafeRelativePath(prefix + "/" + item.Name, $"item_{found.Count}");
            if (kind == DotNet && !relative.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && !relative.EndsWith(".exe.bin", StringComparison.OrdinalIgnoreCase))
                relative += ".dll"; // carved / renamed assemblies get an extension so they resolve and open like assemblies
            found.Add(new Found(relative, item.Bytes, kind, itemSha, item.Origin));

            if (depth >= limits.MaxDepth || !MayContainMore(kind)) continue;
            try
            {
                var inner = Containers.Open(item.Bytes, item.Name, limits, ct);
                if (inner.Kind == "none") continue;
                notes.Add($"{item.Name}: {inner.Kind}.");
                notes.AddRange(inner.Notes.Select(n => $"{item.Name}: {n}"));
                var innerPrefix = prefix + "/" + item.Name + "_unpacked"; // next to the item, in its folder (sanitized when used)
                foreach (var i in inner.Items) queue.Enqueue((i, innerPrefix, depth + 1));
            }
            catch (ToolError ex)
            {
                notes.Add($"{item.Name}: {ex.Message}");
            }
        }
        return new Walked(top.Kind, found, notes);
    }

    private static bool MayContainMore(string kind) =>
        kind is "zip" or ".NET assembly" or "native PE" or "data" || kind.StartsWith("xa", StringComparison.Ordinal);

    private void LoadAssemblies(List<UnpackedFile> files, List<string> notes)
    {
        for (int i = 0; i < files.Count; i++)
        {
            if (files[i].Kind != DotNet) continue;
            try
            {
                var asm = workspace.Load(files[i].Path);
                files[i] = files[i] with { LoadedAs = asm.Id };
            }
            catch (ToolError ex)
            {
                notes.Add($"Could not load {Path.GetFileName(files[i].Path)}: {ex.Message}");
            }
        }
    }

    internal static string DefaultOutput(string source, string sha, string folder = "netdecomp-unpacked") =>
        Path.Combine(Path.GetTempPath(), folder, $"{Blob.SafeRelativePath(Path.GetFileNameWithoutExtension(source), "file")}-{sha[..12]}");

    /// <summary>Creates the output directory, or reuses it if it is empty or an earlier unpack of the same file.</summary>
    internal static string PrepareOutput(string directory, string source, string sha)
    {
        var root = Path.GetFullPath(directory);
        var marker = Path.Combine(root, Marker);
        if (Directory.Exists(root) && Directory.EnumerateFileSystemEntries(root).Any())
        {
            if (!File.Exists(marker) || !File.ReadAllText(marker).StartsWith(sha, StringComparison.Ordinal))
                throw new ToolError($"Output directory {root} is not empty and is not an earlier unpack of this file. Choose an empty or new directory.");
            return root;
        }
        Directory.CreateDirectory(root);
        File.WriteAllText(marker, $"{sha}\n{source}\n");
        return root;
    }
}
