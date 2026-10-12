using System.Text.Json.Serialization;
using dnlib.DotNet;
using Corvus.Core;
using Corvus.Services;

namespace Corvus.Services.Analysis;

/// <summary>
/// Recursively opens nested containers up to <see cref="AnalysisLimits.MaxDepth"/>. Output directories carry a marker
/// file so a repeat unpack of the same file reuses them and unrelated directories are never written into.
/// </summary>
public sealed class UnpackService(AssemblyWorkspace workspace)
{
    private const string Marker = ".corvus-unpack";
    private const string DotNet = ".NET assembly";
    internal const string HostOrigin = "the file itself (container host)";

    /// <summary>ReadyToRun and Merged are set for .NET assemblies only.</summary>
    public sealed record UnpackedFile(string Path, string Kind, long Size, string Sha256, string Origin, string? LoadedAs,
        bool? ReadyToRun = null,
        string? Merged = null);

    public sealed record UnpackReport(string Source, string Container, string OutputDirectory, List<UnpackedFile> Files, List<string> Notes);

    /// <summary>Path is relative to the container; nested items are under "x_unpacked/".</summary>
    public sealed record ContainedAssembly(string Path, string? Name, string? Version, long Size, string Sha256, string Origin, bool ReadyToRun,
        string? Merged);

    public sealed record ContainerListing(string Source, string Container, List<ContainedAssembly> Assemblies, List<string> Notes)
    {
        /// <summary>Assemblies in the container that match the filter; Assemblies holds one page.</summary>
        public int Total { get; init; }
    }

    private sealed record Found(string Relative, byte[] Bytes, string Kind, string Sha256, string Origin);

    private sealed record Walked(string Container, List<Found> Items, List<string> Notes);

    public UnpackReport Unpack(string path, string? outputDirectory, bool load, AnalysisLimits limits, CancellationToken ct)
    {
        string source, sha;
        byte[]? data = null;
        Walked walked;
        if (WebcilFolder(path, limits, ct) is { } folder) (source, sha, walked) = folder;
        else
        {
            (source, data, sha) = ReadSource(path, limits);
            walked = Walk(data, sha, Path.GetFileName(source), limits, ct);
        }
        var root = PrepareOutput(outputDirectory ?? DefaultOutput(source, sha), source, sha);
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

        // A managed host contains the app's own code; include it.
        if (data != null && Blob.Identify(data) == DotNet && walked.Container != "none")
            files.Insert(0, new UnpackedFile(source, DotNet, data.Length, sha, HostOrigin, null, AssemblyTraits.IsReadyToRun(data), Inspect(data)?.Merged));
        // For an apphost launcher, the application is the adjacent .dll.
        if (AppNextToApphost(source, walked.Container, limits) is { } app)
            files.Insert(0, new UnpackedFile(app.Path, DotNet, app.Bytes.Length, Blob.Sha256(app.Bytes), ApphostAppOrigin, null,
                AssemblyTraits.IsReadyToRun(app.Bytes), Inspect(app.Bytes)?.Merged));
        if (load) LoadAssemblies(files, notes);
        if (files.Count > MaxListed)
        {
            int total = files.Count;
            files = files.OrderBy(f => ListOrder(f.Origin, f.Path, f.Kind == DotNet)).Take(MaxListed).ToList();
            notes.Add($"{total} files written to {root}; {MaxListed} listed (the app's assemblies first, translations and other files last).");
        }
        return new UnpackReport(source, walked.Container, root, files, notes);
    }

    /// <summary>Maximum entries listed; the rest are counted in notes.</summary>
    internal const int MaxListed = 100;

    /// <summary>Order: host / apphost app, assemblies, satellite assemblies, other files.</summary>
    private static int ListOrder(string origin, string path, bool assembly) =>
        origin == HostOrigin || origin == ApphostAppOrigin ? 0
        : !assembly ? 3
        : Path.GetFileNameWithoutExtension(path).EndsWith(".resources", StringComparison.OrdinalIgnoreCase) ? 2 : 1;

    /// <summary>
    /// Lists managed assemblies without writing anything. Throws <see cref="ToolError"/> when the container is corrupt.
    /// </summary>
    public ContainerListing List(string path, AnalysisLimits limits, CancellationToken ct, string? filter = null, int offset = 0, int limit = MaxListed)
    {
        var managed = Managed(path, limits, ct);
        var assemblies = filter == null ? managed.Assemblies
            : managed.Assemblies.Where(a => a.Path.Contains(filter, StringComparison.OrdinalIgnoreCase)).ToList();
        int total = assemblies.Count, take = Math.Clamp(limit, 1, MaxListed);
        offset = Math.Max(0, offset);
        if (offset > 0 || total > take)
        {
            assemblies = assemblies.OrderBy(a => ListOrder(a.Origin, a.Path, true)).Skip(offset).Take(take).ToList();
            managed.Notes.Add($"{total} assemblies; {assemblies.Count} listed{(offset > 0 ? $" from {offset}" : "")} (the app's first, translations last; " +
                              "offset and limit page through them). search_container finds types and members in all of them; unpack_container extracts them.");
        }
        return new ContainerListing(managed.Source, managed.Container,
            assemblies.Select(a => Describe(a.Path, a.Bytes, a.Sha256, a.Origin)).ToList(), managed.Notes) { Total = total };
    }

    public sealed record ContainerSymbol(string Path, string Assembly, string Name, string Kind);

    public sealed record ContainerSearch(string Source, string Container, int AssembliesSearched, List<ContainerSymbol> Matches, int Total,
        bool Truncated, List<string> Notes);

    /// <summary>Null or "any" selects all kinds, events included.</summary>
    public static SymbolKind ParseSearchKind(string? kind) => kind?.Trim().ToLowerInvariant() switch
    {
        null or "" or "any" => SymbolKind.Any,
        "type" => SymbolKind.Type,
        "method" => SymbolKind.Method,
        "field" => SymbolKind.Field,
        "property" => SymbolKind.Property,
        _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown kind '{kind}': use type, method, field or property, or omit it for all."),
    };

    /// <summary>
    /// Searches symbol names in every contained assembly in memory, with search_symbols matching. Results are ranked
    /// exact, prefix, substring; Total counts all matches.
    /// </summary>
    public ContainerSearch Search(string path, string query, SymbolKind kind, int limit, AnalysisLimits limits, CancellationToken ct)
    {
        var matcher = SearchService.CreateMatcher(query, regex: false);
        bool matchFullName = query.Contains('.') || query.Contains(':');
        var managed = Managed(path, limits, ct);
        var notes = managed.Notes;
        // One bucket per rank, each capped at the limit, to keep the best matches with bounded memory.
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

    /// <summary>Managed assemblies in a file; a plain assembly yields itself.</summary>
    internal static (string Source, string Container, List<ManagedAssembly> Assemblies, List<string> Notes) Managed(string path, AnalysisLimits limits, CancellationToken ct)
    {
        if (WebcilFolder(path, limits, ct) is { } folder)
            return (folder.Source, folder.Walked.Container,
                folder.Walked.Items.Select(i => new ManagedAssembly(i.Relative, i.Bytes, i.Sha256, i.Origin)).ToList(), folder.Walked.Notes);
        var (source, data, sha) = ReadSource(path, limits);
        var walked = Walk(data, sha, Path.GetFileName(source), limits, ct);
        var assemblies = walked.Items.Where(i => i.Kind == DotNet)
            .Select(i => new ManagedAssembly(i.Relative.Replace(System.IO.Path.DirectorySeparatorChar, '/'), i.Bytes, i.Sha256, i.Origin)).ToList();
        var container = walked.Container;
        if (container == "none" && Blob.Identify(data) == DotNet)
        {
            container = "none (plain .NET assembly)";
            assemblies = [new ManagedAssembly(Path.GetFileName(source), data, sha, "the file itself")];
            walked.Notes.RemoveAll(n => n.StartsWith("A plain .NET assembly", StringComparison.Ordinal));
        }
        else if (Blob.Identify(data) == DotNet)
        {
            // A managed host's own code comes first.
            assemblies.Insert(0, new ManagedAssembly(Path.GetFileName(source), data, sha, HostOrigin));
        }
        else if (AppNextToApphost(source, container, limits) is { } app)
        {
            assemblies.Insert(0, new ManagedAssembly(Path.GetFileName(app.Path), app.Bytes, Blob.Sha256(app.Bytes), ApphostAppOrigin));
            walked.Notes.Add($"Using the application next to the launcher: {Path.GetFileName(app.Path)}.");
        }
        return (source, container, assemblies, walked.Notes);
    }

    internal const string ApphostAppOrigin = "the application next to the apphost launcher";

    /// <summary>For a non-bundled apphost, the managed .dll of the same name beside it.</summary>
    private static (string Path, byte[] Bytes)? AppNextToApphost(string source, string container, AnalysisLimits limits)
    {
        if (!container.StartsWith(".NET apphost", StringComparison.Ordinal)) return null;
        var dll = Path.ChangeExtension(source, ".dll");
        try
        {
            if (!File.Exists(dll) || new FileInfo(dll).Length > limits.MaxTotalBytes) return null;
            var bytes = File.ReadAllBytes(dll);
            return Blob.Identify(bytes) == DotNet ? (dll, bytes) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    private static ContainedAssembly Describe(string path, byte[] bytes, string sha, string origin)
    {
        var info = Inspect(bytes);
        return new ContainedAssembly(path.Replace('\\', '/'), info?.Name, info?.Version, bytes.Length, sha, origin,
            AssemblyTraits.IsReadyToRun(bytes), info?.Merged);
    }

    /// <summary>Identity and merge note; null when the metadata is unreadable.</summary>
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

    /// <summary>
    /// A Blazor WebAssembly folder (_framework, or the app folder above it) as one container: its Webcil assemblies as PEs
    /// named by assembly, so they unpack into one folder where they resolve each other. Null for anything else.
    /// </summary>
    private static (string Source, string Sha, Walked Walked)? WebcilFolder(string path, AnalysisLimits limits, CancellationToken ct)
    {
        string full;
        try { full = Path.GetFullPath(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
        if (!Directory.Exists(full) || Webcil.FolderFiles(full) is not { Count: > 0 } files) return null;
        var notes = new List<string>();
        var found = new List<Found>();
        var byName = new Dictionary<string, (string Sha, int Index, bool Named)>(StringComparer.OrdinalIgnoreCase);
        var manifest = Webcil.BootManifestEntries(Path.GetDirectoryName(files[0])!);
        long total = 0;
        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var bytes = File.ReadAllBytes(file);
            if (found.Count >= limits.MaxItems || (total += bytes.Length) > limits.MaxTotalBytes)
            {
                notes.Add("Stopped: the extraction limit was reached; some files were not extracted.");
                break;
            }
            bool named = manifest != null && (manifest.Contains(Path.GetFileName(file)) || manifest.Contains(Webcil.Integrity(bytes)));
            foreach (var item in Containers.Open(bytes, file, limits, ct).Items)
            {
                var itemSha = Blob.Sha256(item.Bytes);
                var entry = new Found(item.Name, item.Bytes, DotNet, itemSha, Path.GetFileName(file));
                // Fingerprinted copies of one assembly (App.abc.wasm, App.def.wasm) left by earlier publishes: the copy the boot
                // manifest lists is the one the app loads; without a manifest, the first is kept.
                if (byName.TryGetValue(item.Name, out var kept))
                {
                    if (kept.Sha == itemSha) continue;
                    if (named && !kept.Named)
                    {
                        notes.Add($"{found[kept.Index].Origin} holds another build of {item.Name}; {entry.Origin}, which the boot manifest lists, is used.");
                        found[kept.Index] = entry;
                        byName[item.Name] = (itemSha, kept.Index, true);
                    }
                    else
                        notes.Add($"{entry.Origin} holds another build of {item.Name}; " +
                                  (kept.Named ? $"{found[kept.Index].Origin}, which the boot manifest lists, is used." : "the first one found is used."));
                    continue;
                }
                byName[item.Name] = (itemSha, found.Count, named);
                found.Add(entry);
            }
        }
        var sha = Blob.Sha256(System.Text.Encoding.UTF8.GetBytes(string.Join("\n", found.Select(f => f.Relative + " " + f.Sha256))));
        return (Path.GetDirectoryName(files[0])!, sha, new Walked("Blazor WebAssembly folder (Webcil)", found, notes));
    }

    private static (string Source, byte[] Data, string Sha) ReadSource(string path, AnalysisLimits limits)
    {
        if (Directory.Exists(Path.GetFullPath(path))) throw new ToolError(ErrorCode.InvalidArgument, $"{Path.GetFullPath(path)} is a directory; pass a container file (single-file app, .nupkg, .apk, Costura host) or a Blazor _framework folder. To load a folder of assemblies, use load_assembly.");
        var source = InputFiles.RequireRegularFile(path, "container file");
        if (!File.Exists(source)) throw new ToolError(ErrorCode.NotFound, $"File not found: {source}");
        var length = new FileInfo(source).Length;
        if (length > Math.Min(limits.MaxTotalBytes, Array.MaxLength)) throw new ToolError(ErrorCode.LimitExceeded, $"{source} is too large to unpack ({length:N0} bytes).");
        var data = File.ReadAllBytes(source);
        return (source, data, Blob.Sha256(data));
    }

    /// <summary>Breadth-first walk of nested containers; duplicate content (same hash) appears once.</summary>
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
            if (!seen.Add(itemSha)) continue; // e.g. identical per-ABI assembly stores
            if (found.Count >= limits.MaxItems || (total += item.Bytes.Length) > limits.MaxTotalBytes)
            {
                notes.Add("Stopped: the extraction limit was reached; some files were not extracted.");
                break;
            }

            var kind = Blob.Identify(item.Bytes);
            // String concatenation, not Path.Combine: a rooted item name would drop the prefix.
            var relative = Blob.SafeRelativePath(prefix + "/" + item.Name, $"item_{found.Count}");
            if (kind == DotNet && !relative.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && !relative.EndsWith(".exe.bin", StringComparison.OrdinalIgnoreCase))
                relative += ".dll"; // so carved assemblies resolve by name
            found.Add(new Found(relative, item.Bytes, kind, itemSha, item.Origin));

            if (depth >= limits.MaxDepth || !MayContainMore(kind)) continue;
            try
            {
                var inner = Containers.Open(item.Bytes, item.Name, limits, ct);
                if (inner.Kind == "none") continue;
                notes.Add($"{item.Name}: {inner.Kind}.");
                notes.AddRange(inner.Notes.Select(n => $"{item.Name}: {n}"));
                var innerPrefix = prefix + "/" + item.Name + "_unpacked"; // sanitized when used
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

    internal static string DefaultOutput(string source, string sha, string folder = "corvus-unpacked") =>
        Path.Combine(Path.GetTempPath(), folder, $"{Blob.SafeRelativePath(Path.GetFileNameWithoutExtension(source), "file")}-{sha[..12]}");

    /// <summary>Creates the output directory, or reuses it if empty or marked as an earlier unpack of the same file.</summary>
    internal static string PrepareOutput(string directory, string source, string sha)
    {
        var root = SafeFile.FullPath(directory);
        var marker = Path.Combine(root, Marker);
        bool Ours() => File.Exists(marker) && File.ReadAllText(marker).StartsWith(sha, StringComparison.Ordinal);
        if (Directory.Exists(root) && Directory.EnumerateFileSystemEntries(root).Any())
            return Ours() ? root : throw new ToolError(ErrorCode.Conflict,
                $"Output directory {root} is not empty and is not an earlier unpack of this file. Choose an empty or new directory.");
        Directory.CreateDirectory(root);
        try { SafeFile.WriteUnderRoot(root, Marker, System.Text.Encoding.UTF8.GetBytes($"{sha}\n{source}\n"), overwrite: false); }
        catch (ToolError ex) when (ex.Code == ErrorCode.Conflict && Ours()) { } // a concurrent unpack of the same file
        return root;
    }
}
