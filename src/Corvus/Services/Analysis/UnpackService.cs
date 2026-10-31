using System.Text.Json;
using System.Text.Json.Serialization;
using dnlib.DotNet;
using Corvus.Core;
using Corvus.Services;

namespace Corvus.Services.Analysis;

/// <summary>Opens nested containers up to <see cref="AnalysisLimits.MaxDepth"/>; a marker file lets a repeat unpack reuse its output folder and keeps writes out of unrelated folders.</summary>
public sealed class UnpackService(AssemblyWorkspace workspace)
{
    internal const string Marker = ".corvus-unpack";
    private const string DotNet = ".NET assembly";
    internal const string HostOrigin = "the file itself (container host)";

    /// <summary>ReadyToRun and Merged are set for .NET assemblies only; Extracted is false for a file listed where it already is (host, apphost app).</summary>
    public sealed record UnpackedFile(string Path, string Kind, long Size, string Sha256, string Origin, string? LoadedAs,
        bool? ReadyToRun = null,
        string? Merged = null)
    {
        public bool? Extracted { get; init; }
    }

    /// <summary>The call that continues from a result with nothing extracted.</summary>
    public sealed record NextCall(string Tool, IReadOnlyDictionary<string, string> Arguments, string Reason);

    /// <summary>Every file, the app's assemblies first, translations and other files last.</summary>
    public sealed record UnpackReport(string Source, string Container, string OutputDirectory, List<UnpackedFile> Files, List<string> Notes)
    {
        public NextCall? Next { get; init; }
    }

    private static readonly string[] NativeKinds = ["native PE", "NativeAOT executable", "elf", "mach-o"];

    /// <summary>Path is relative to the container; nested items are under "x_unpacked/".</summary>
    public sealed record ContainedAssembly(string Path, string? Name, string? Version, long Size, string Sha256, string Origin, bool ReadyToRun,
        string? Merged);

    public sealed record ContainerListing(string Source, string Container, List<ContainedAssembly> Assemblies, List<string> Notes)
    {
        /// <summary>Assemblies in the container that match the filter; Assemblies holds one page.</summary>
        public int Total { get; init; }

        /// <summary>Archive containers (ASAR, WebPlayerData, HAR, flows): one page of the entries matching the filter, with size and flags.</summary>
        public List<ContainerEntry>? Files { get; init; }

        /// <summary>Entries of an archive container that match the filter.</summary>
        public int? FileTotal { get; init; }
    }

    private sealed record Found(string Relative, byte[] Bytes, string Kind, string Sha256, string Origin)
    {
        /// <summary>The path the container records; null when it is <see cref="Relative"/>.</summary>
        public string? Original { get; init; }
    }

    private sealed record Walked(string Container, List<Found> Items, List<string> Notes)
    {
        public List<ContainerEntry>? Entries { get; init; }

        public List<NameIssue> Names { get; init; } = [];
    }

    /// <param name="progress">Phase messages: reading, entries found, files written, assemblies loaded.</param>
    /// <param name="keyLog">A packet capture's TLS key log (SSLKEYLOGFILE format).</param>
    /// <param name="password">The password of an encrypted archive or document; the only one tried.</param>
    public UnpackReport Unpack(string path, string? outputDirectory, bool load, AnalysisLimits limits, CancellationToken ct, Action<string>? progress = null,
        string? keyLog = null, string? password = null) =>
        Finish(Extract(path, outputDirectory, limits, ct, progress, keyLog, password), load, progress);

    /// <summary>A container's files written to disk and not loaded: in walk order, with the input's kind for the next call.</summary>
    public sealed record Extraction(string Source, string Container, string Kind, string OutputDirectory, List<UnpackedFile> Files, List<string> Notes);

    /// <summary>Writes a container's files (the reading half of <see cref="Unpack"/>); nothing is loaded.</summary>
    public Extraction Extract(string path, string? outputDirectory, AnalysisLimits limits, CancellationToken ct, Action<string>? progress = null,
        string? keyLog = null, string? password = null)
    {
        using var _ = ContainerPassword.Enter(password);
        string source, sha;
        byte[]? data = null;
        Walked walked;
        progress?.Invoke($"reading {Path.GetFileName(path)}");
        string kind = DotNet;
        if (WebcilFolder(path, limits, ct) is { } folder) (source, sha, walked) = folder;
        else if (Deployment(path, limits, ct, allFiles: true) is { } deployment) (source, sha, walked) = deployment;
        else if (Capture(path, keyLog, limits, ct, progress) is { } capture)
        {
            (source, sha, walked) = capture;
            kind = "packet capture";
        }
        else
        {
            if (keyLog != null) throw new ToolError(ErrorCode.InvalidArgument, "keyLog applies to a pcap or pcapng capture.", "omit keyLog, or pass a packet capture as path");
            (source, data, sha) = ReadSource(path, limits);
            walked = Walk(data, sha, source, limits, ct, allFiles: true, progress);
            kind = Blob.Identify(data);
        }
        if (walked.Container == "none" && walked.Items.Count == 0 && kind != DotNet && !NativeKinds.Contains(kind))
            throw new ToolError(ErrorCode.Unsupported, $"{source} is not a known container ({kind}): nothing to unpack.",
                $"summarize_file path={source} says what the file holds");
        var root = PrepareOutput(outputDirectory ?? DefaultOutput(source, sha), source, sha);
        var notes = walked.Notes;
        var files = new List<UnpackedFile>();
        var zone = new ZoneMark();
        var names = new UniqueNames();
        int index = 0;
        foreach (var item in walked.Items)
        {
            ct.ThrowIfCancellationRequested();
            if (++index % 200 == 0) progress?.Invoke($"{index} of {walked.Items.Count} files written");
            string written;
            // An archive can hold both "a.dll" and "a.dll/b.dll".
            try { written = Blob.WriteUnique(root, item.Relative, item.Bytes, zone, names); }
            // A refused name (.git/, CLAUDE.md) skips that entry, not the extraction.
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException || ex is ToolError t && OutputGuard.IsRefusal(t))
            {
                notes.Add($"Could not write {item.Relative}: {ex.Message}");
                continue;
            }
            var file = new UnpackedFile(written, item.Kind, item.Bytes.Length, item.Sha256, item.Origin, null);
            if (item.Kind == DotNet)
                file = file with { ReadyToRun = AssemblyTraits.IsReadyToRun(item.Bytes), Merged = Inspect(item.Bytes)?.Merged };
            files.Add(file);
        }
        if (zone.Note is { } unmarked) notes.Add(unmarked);

        // A managed host contains the app's own code; include it.
        if (data != null && kind == DotNet && walked.Container != "none")
            files.Insert(0, new UnpackedFile(source, DotNet, data.Length, sha, HostOrigin, null, AssemblyTraits.IsReadyToRun(data), Inspect(data)?.Merged) { Extracted = false });
        // For an apphost launcher, the application is the adjacent .dll.
        if (AppNextToApphost(source, walked.Container, limits) is { } app)
            files.Insert(0, new UnpackedFile(app.Path, DotNet, app.Bytes.Length, Blob.Sha256(app.Bytes), ApphostAppOrigin, null,
                AssemblyTraits.IsReadyToRun(app.Bytes), Inspect(app.Bytes)?.Merged) { Extracted = false });
        return new Extraction(source, walked.Container, kind, root, files, notes);
    }

    /// <summary>The report of an extraction: its .NET assemblies loaded in walk order when <paramref name="load"/>, then the files listed in report order.</summary>
    public UnpackReport Finish(Extraction extraction, bool load, Action<string>? progress = null)
    {
        var files = new List<UnpackedFile>(extraction.Files);
        var notes = new List<string>(extraction.Notes);
        if (load) LoadAssemblies(files, notes, progress);
        files = [.. files.OrderBy(f => ListOrder(f.Origin, f.Path, f.Kind == DotNet))];
        return new UnpackReport(extraction.Source, extraction.Container, extraction.OutputDirectory, files, notes)
            { Next = NextOf(extraction.Source, extraction.Container, extraction.Kind, files) };
    }

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    /// <summary>A capture's HTTP objects and TCP streams, with tls.json listing each TLS connection; null for another file.</summary>
    private static (string Source, string Sha, Walked Walked)? Capture(string path, string? keyLog, AnalysisLimits limits, CancellationToken ct, Action<string>? progress)
    {
        string source;
        try { source = Path.GetFullPath(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
        if (!File.Exists(source)) return null;
        var head = new byte[4];
        using (var probe = File.OpenRead(source)) if (probe.ReadAtLeast(head, 4, throwOnEndOfStream: false) < 4 || !Core.Pcap.PcapReader.Looks(head)) return null;
        source = InputFiles.RequireRegularFile(source, "capture file");
        Core.Pcap.TlsKeyLog? keys = null;
        if (keyLog != null)
        {
            var log = InputFiles.RequireRegularFile(keyLog, "keyLog");
            if (!File.Exists(log)) throw Targets.FileNotFound(log);
            keys = new Core.Pcap.TlsKeyLog();
            keys.Add(File.ReadAllText(log));
            if (keys.Sessions == 0) throw new ToolError(ErrorCode.InvalidArgument, $"{log} holds no key log lines.", "pass an SSLKEYLOGFILE: CLIENT_RANDOM or *_TRAFFIC_SECRET lines");
        }
        string sha;
        using (var s = File.OpenRead(source)) sha = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(s));
        progress?.Invoke("reassembling TCP");
        Core.Pcap.CaptureObjects.Result result;
        using (var s = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16)) result = Core.Pcap.CaptureObjects.Read(s, keys, limits, ct);
        var top = result.Contents;
        if (result.Tls.Count > 0)
            top = top with { Items = [.. top.Items, new ExtractedItem("tls.json", JsonSerializer.SerializeToUtf8Bytes(result.Tls, Indented), "TLS connections")] };
        return (source, sha, Walk(top, sha, limits, ct, allFiles: true, progress));
    }

    /// <summary>Where to go when nothing was extracted: the apphost's app, the native image, or the file's summary.</summary>
    private static NextCall? NextOf(string source, string container, string kind, List<UnpackedFile> files)
    {
        if (files.Any(f => f.Extracted != false)) return null;
        if (files.FirstOrDefault(f => f.Origin == ApphostAppOrigin) is { } app)
            return new NextCall("load_assembly", new Dictionary<string, string> { ["path"] = app.Path }, "an apphost launcher: the application is the .dll beside it");
        if (container == "NativeAOT executable")
            return new NextCall("get_nativeaot_info", new Dictionary<string, string> { ["image"] = source }, "NativeAOT: compiled to native code, no IL to extract");
        if (kind == DotNet)
            return new NextCall("load_assembly", new Dictionary<string, string> { ["path"] = source }, "a plain .NET assembly: nothing is bundled in it");
        if (NativeKinds.Contains(kind))
            return new NextCall("load_assembly", new Dictionary<string, string> { ["path"] = source }, "a native image without .NET assemblies: analyze it as native code");
        return new NextCall("summarize_file", new Dictionary<string, string> { ["path"] = source }, "no assemblies or nested packages inside");
    }

    /// <summary>Largest page of list_assemblies.</summary>
    internal const int MaxListed = 100;

    /// <summary>Order: host / apphost app, assemblies, satellite assemblies, other files.</summary>
    private static int ListOrder(string origin, string path, bool assembly) =>
        origin == HostOrigin || origin == ApphostAppOrigin ? 0
        : !assembly ? 3
        : Path.GetFileNameWithoutExtension(path).EndsWith(".resources", StringComparison.OrdinalIgnoreCase) ? 2 : 1;

    /// <summary>Lists managed assemblies without writing anything; throws <see cref="ToolError"/> when the container is corrupt.</summary>
    public ContainerListing List(string path, AnalysisLimits limits, CancellationToken ct, string? filter = null, int offset = 0, int limit = MaxListed)
    {
        var managed = Managed(path, limits, ct);
        // One order for every page: the budget may cut the first page, and the next one starts from its count.
        var assemblies = managed.Assemblies.Where(a => filter == null || a.Path.Contains(filter, StringComparison.OrdinalIgnoreCase))
            .OrderBy(a => ListOrder(a.Origin, a.Path, true)).ToList();
        int total = assemblies.Count, take = Math.Clamp(limit, 1, MaxListed);
        offset = Math.Max(0, offset);
        List<ContainerEntry>? files = null;
        int? fileTotal = null;
        if (managed.Entries is { } entries)
        {
            var matching = filter == null ? entries : entries.Where(e => e.Path.Contains(filter, StringComparison.OrdinalIgnoreCase)).ToList();
            fileTotal = matching.Count;
            files = matching.Skip(offset).Take(take).ToList();
            if (offset + files.Count < matching.Count)
                managed.Notes.Add($"{matching.Count} entries; {files.Count} listed from {offset}; offset and limit page, filter matches paths; unpack_container extracts them all.");
        }
        if (offset > 0 || total > take)
        {
            assemblies = assemblies.Skip(offset).Take(take).ToList();
            managed.Notes.Add($"{total} assemblies; {assemblies.Count} listed{(offset > 0 ? $" from {offset}" : "")}, the app's first; offset and limit page; " +
                              "search_container searches all of them, unpack_container extracts them.");
        }
        return new ContainerListing(managed.Source, managed.Container,
            assemblies.Select(a => Describe(a.Path, a.Bytes, a.Sha256, a.Origin)).ToList(), managed.Notes) { Total = total, Files = files, FileTotal = fileTotal };
    }

    /// <summary>One page of matches ranked exact, prefix, substring; Searched counts the assemblies (or files) searched.</summary>
    public sealed record ContainerSearch(string Source, string Container, int Searched, List<ContainerMatch> Items, int Offset, int Total, List<string> Notes)
    {
        [JsonIgnore] public bool Truncated => Offset + Items.Count < Total;
    }

    /// <summary>The managed kinds; providers (<see cref="IContainerSearchKind"/>) add theirs.</summary>
    public static readonly string[] ManagedKinds = ["type", "method", "field", "property"];

    /// <summary>Every kind= value: the managed kinds, then each provider's.</summary>
    public static IReadOnlyList<string> SearchKinds => [.. ManagedKinds, .. Providers.Of<IContainerSearchKind>().SelectMany(p => p.Kinds)];

    /// <summary>Null or "any" selects all managed kinds, events included.</summary>
    public static SymbolKind ParseSearchKind(string? kind) => kind?.Trim().ToLowerInvariant() switch
    {
        null or "" or "any" => SymbolKind.Any,
        "type" => SymbolKind.Type,
        "method" => SymbolKind.Method,
        "field" => SymbolKind.Field,
        "property" => SymbolKind.Property,
        _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown kind '{kind}'.", $"pass kind as one of {string.Join(", ", SearchKinds)}, or omit it for all members"),
    };

    /// <summary>A search by a kind= value: a provider's kind, else the managed symbols.</summary>
    public ContainerSearch Search(string path, string query, string? kind, int limit, AnalysisLimits limits, CancellationToken ct, int offset = 0, string? capture = null,
        bool values = false)
    {
        var name = kind?.Trim().ToLowerInvariant();
        if (capture != null && name != "endpoint")
            throw new ToolError(ErrorCode.InvalidArgument, "capture applies to kind=endpoint only.", "pass kind=endpoint, or omit capture");
        if (values && name != "request")
            throw new ToolError(ErrorCode.InvalidArgument, "values applies to kind=request only.", "pass kind=request, or omit values");
        if (capture != null) capture = InputFiles.RequireRegularFile(capture, "capture");
        var provider = name is null or "" ? null : Providers.Of<IContainerSearchKind>().FirstOrDefault(p => p.Kinds.Contains(name));
        if (provider == null) return Search(path, query, ParseSearchKind(kind), limit, limits, ct, offset);
        return provider.SearchFile(path, query, Math.Max(0, offset), limit, new ContainerSearchArgs(capture, values), ct)
               ?? SearchFiles(path, query, provider, name!, limit, limits, ct, offset, capture);
    }

    private static ContainerSearch SearchFiles(string path, string query, IContainerSearchKind provider, string kind, int limit, AnalysisLimits limits,
        CancellationToken ct, int offset, string? capture)
    {
        var (scope0, notes0) = Scope(path, limits, ct);
        var scope = (Scope: scope0 with { Capture = capture }, Notes: notes0);
        var matcher = SearchService.CreateMatcher(query, regex: false);
        var all = provider.Search(scope.Scope, kind, matcher, ct).ToList();
        var tally = scope.Scope.Tally;
        if (tally.Note != null) scope.Notes.Insert(0, tally.Note);
        return Ranked(scope.Scope.Source, scope.Scope.Container, tally.Files ?? scope.Scope.Items.Count, all, query, offset, limit, scope.Notes);
    }

    /// <summary>A search kind's rows ranked on the last part of the name (a file name, a member name), as the managed search ranks short names, and paged.</summary>
    internal static ContainerSearch Ranked(string source, string container, int searched, List<ContainerMatch> all, string query, int offset, int limit, List<string> notes)
    {
        static string Short(string name) => name[(name.LastIndexOfAny(['/', '\\', ':']) + 1)..];
        var ranked = all.Select((m, i) => (m, i, Rank: SearchService.Rank(Short(m.Name), query)))
            .OrderBy(x => x.Rank).ThenBy(x => x.i).Select(x => x.m).ToList();
        return new ContainerSearch(source, container, searched, ranked.Skip(Math.Max(0, offset)).Take(limit).ToList(), Math.Max(0, offset), ranked.Count, notes);
    }

    /// <summary>Every file of a container (nested containers opened), for search kinds.</summary>
    internal static (ContainerScope Scope, List<string> Notes) Scope(string path, AnalysisLimits limits, CancellationToken ct)
    {
        string source;
        Walked walked;
        List<ContainerEntry>? entries;
        if (WebcilFolder(path, limits, ct) is { } folder)
        {
            (source, _, walked) = folder;
            entries = walked.Entries;
        }
        else if (Deployment(path, limits, ct, allFiles: true) is { } deployment)
        {
            (source, _, walked) = deployment;
            entries = walked.Entries;
        }
        else
        {
            (source, var data, var sha) = ReadSource(path, limits);
            walked = Walk(data, sha, source, limits, ct, allFiles: true);
            entries = walked.Entries ?? (Blob.Identify(data) == "zip" ? ZipEntries(data) : null);
        }
        var items = walked.Items.Select(i => new ContainerItem(i.Relative.Replace(System.IO.Path.DirectorySeparatorChar, '/'), i.Kind, i.Origin, i.Bytes) { Original = i.Original }).ToList();
        return (new ContainerScope(source, walked.Container, items, entries), walked.Notes);
    }

    /// <summary>A zip's directory (names and sizes, nothing read); null when it has none (the opener recovered local headers).</summary>
    private static List<ContainerEntry>? ZipEntries(byte[] data)
    {
        try
        {
            using var zip = new System.IO.Compression.ZipArchive(new MemoryStream(data, writable: false), System.IO.Compression.ZipArchiveMode.Read);
            return [.. zip.Entries.Where(e => !e.FullName.EndsWith('/')).Select(e => new ContainerEntry(e.FullName, e.Length))];
        }
        catch (InvalidDataException) { return null; }
    }

    /// <summary>Searches symbol names in every contained assembly, ranked exact, prefix, substring; Total counts all matches.</summary>
    public ContainerSearch Search(string path, string query, SymbolKind kind, int limit, AnalysisLimits limits, CancellationToken ct, int offset = 0)
    {
        offset = Math.Max(0, offset);
        var matcher = SearchService.CreateMatcher(query, regex: false);
        bool matchFullName = query.Contains('.') || query.Contains(':');
        var managed = Managed(path, limits, ct);
        var notes = managed.Notes;
        // One bucket per rank, each capped at the page end, to keep the best matches with bounded memory.
        int end = (int)Math.Min(int.MaxValue, (long)offset + limit);
        var buckets = Enumerable.Range(0, 4).Select(_ => new List<ContainerMatch>()).ToArray();
        int total = 0, searched = 0;
        foreach (var a in managed.Assemblies)
        {
            ct.ThrowIfCancellationRequested();
            ModuleDefMD module;
            try { module = MetadataRows.Load(a.Bytes); }
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
                            if (bucket.Count < end) bucket.Add(new ContainerMatch(a.Path, Format.MemberLabel(member), KindName(member)) { Assembly = assemblyName });
                        }
                    }
                    searched++;
                }
                // dnlib reads rows lazily, so a corrupt row throws mid-walk.
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    notes.Add($"{a.Path}: corrupt metadata, only partly searched ({ex.Message}).");
                }
            }
        }
        var matches = buckets.SelectMany(b => b).Skip(offset).Take(limit).ToList();
        return new ContainerSearch(managed.Source, managed.Container, searched, matches, offset, total, notes);
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
    internal static (string Source, string Container, List<ManagedAssembly> Assemblies, List<string> Notes, List<ContainerEntry>? Entries,
        List<ManagedAssembly> Manifests, List<NameIssue> Names) Managed(
        string path, AnalysisLimits limits, CancellationToken ct)
    {
        if (WebcilFolder(path, limits, ct) is { } folder)
            return (folder.Source, folder.Walked.Container,
                folder.Walked.Items.Select(i => new ManagedAssembly(i.Relative, i.Bytes, i.Sha256, i.Origin)).ToList(), folder.Walked.Notes, null, [], []);
        if (Deployment(path, limits, ct, allFiles: false) is { } deployment)
            return Managed(deployment.Source, null, deployment.Sha, deployment.Walked, limits);
        var (source, data, sha) = ReadSource(path, limits);
        return Managed(source, data, sha, Walk(data, sha, source, limits, ct), limits);
    }

    /// <summary>Managed assemblies in a file summarize_file has open; a streamed file's top level is read as a stream when its format allows.</summary>
    internal static (string Source, string Container, List<ManagedAssembly> Assemblies, List<string> Notes, List<ContainerEntry>? Entries,
        List<ManagedAssembly> Manifests, List<NameIssue> Names) Managed(
        FileInput input, string sha, AnalysisLimits limits, CancellationToken ct)
    {
        if (!input.Streamed) return Script(input, Managed(input.Path, input.Bytes, sha, Walk(input.Bytes, sha, input.Path, limits, ct), limits), ct);
        var name = Path.GetFileName(input.Path);
        if (Containers.OpenStream(input.OpenRead, input.Head, name, limits, ct) is { } top)
            return Managed(input.Path, null, sha, Walk(top, sha, limits, ct), limits);
        // A native image is held without its overlay; anything else is carved in windows.
        bool native = Native.NativeImageLoader.Detect(input.Head) is not (Native.NativeFileKind.Unknown or Native.NativeFileKind.Wasm);
        var large = Containers.OpenLarge(input.OpenRead, input.Head, native ? input.Image : null, input.Length, name, limits, ct);
        return Managed(input.Path, native ? input.Image : null, sha, Walk(large, sha, limits, ct), limits);
    }

    /// <summary>
    /// The summary of a script that unpack_container opens: the container it
    /// names, with counts, in place of none.
    /// </summary>
    private static (string Source, string Container, List<ManagedAssembly> Assemblies, List<string> Notes, List<ContainerEntry>? Entries,
        List<ManagedAssembly> Manifests, List<NameIssue> Names) Script(FileInput input,
        (string Source, string Container, List<ManagedAssembly> Assemblies, List<string> Notes, List<ContainerEntry>? Entries, List<ManagedAssembly> Manifests, List<NameIssue> Names) managed,
        CancellationToken ct)
    {
        if (managed.Container != "none" || !Web.JsBundleFiles.Looks(input.Bytes, input.Path)
            || Web.JsBundleFiles.Describe(input.Bytes, input.Path, ct) is not { } container) return managed;
        managed.Notes.RemoveAll(n => n.StartsWith("Not a known container", StringComparison.Ordinal));
        managed.Notes.Insert(0, $"{container}: unpack_container writes its files.");
        return managed with { Container = container };
    }

    private static (string Source, string Container, List<ManagedAssembly> Assemblies, List<string> Notes, List<ContainerEntry>? Entries,
        List<ManagedAssembly> Manifests, List<NameIssue> Names) Managed(
        string source, byte[]? data, string sha, Walked walked, AnalysisLimits limits)
    {
        var assemblies = walked.Items.Where(i => i.Kind == DotNet)
            .Select(i => new ManagedAssembly(i.Relative.Replace(System.IO.Path.DirectorySeparatorChar, '/'), i.Bytes, i.Sha256, i.Origin)).ToList();
        var container = walked.Container;
        bool dotNet = data != null && Blob.Identify(data) == DotNet;
        if (container == "none" && dotNet)
        {
            container = "none (plain .NET assembly)";
            assemblies = [new ManagedAssembly(Path.GetFileName(source), data!, sha, "the file itself")];
            walked.Notes.RemoveAll(n => n.StartsWith("A plain .NET assembly", StringComparison.Ordinal));
        }
        else if (dotNet)
        {
            // A managed host's own code comes first.
            assemblies.Insert(0, new ManagedAssembly(Path.GetFileName(source), data!, sha, HostOrigin));
        }
        else if (AppNextToApphost(source, container, limits) is { } app)
        {
            assemblies.Insert(0, new ManagedAssembly(Path.GetFileName(app.Path), app.Bytes, Blob.Sha256(app.Bytes), ApphostAppOrigin));
            walked.Notes.Add($"Using the application next to the launcher: {Path.GetFileName(app.Path)}.");
        }
        return (source, container, assemblies, walked.Notes, walked.Entries, Manifests(source, walked, limits), walked.Names);
    }

    /// <summary>The dependency manifests (.deps.json) inside the file, else the one beside it (App.deps.json next to App.exe or App.dll).</summary>
    private static List<ManagedAssembly> Manifests(string source, Walked walked, AnalysisLimits limits)
    {
        var inside = walked.Items.Where(i => i.Relative.EndsWith(".deps.json", StringComparison.OrdinalIgnoreCase))
            .Select(i => new ManagedAssembly(i.Relative.Replace(System.IO.Path.DirectorySeparatorChar, '/'), i.Bytes, i.Sha256, i.Origin)).ToList();
        if (inside.Count > 0) return inside;
        var beside = Path.ChangeExtension(source, ".deps.json");
        try
        {
            if (beside == source || !File.Exists(beside) || new FileInfo(beside).Length > limits.MaxItemBytes) return [];
            var bytes = File.ReadAllBytes(beside);
            return [new ManagedAssembly(beside, bytes, Blob.Sha256(bytes), "the file beside it")];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { return []; }
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
            using var module = MetadataRows.Load(bytes);
            return (module.Assembly?.FullName ?? module.Name.String, module.Assembly?.Version?.ToString(), AssemblyTraits.MergeNote(module));
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>A Blazor WebAssembly folder as one container of its Webcil assemblies as PEs named by assembly; null for anything else.</summary>
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
                // Of fingerprinted copies left by earlier publishes, keep the one the boot manifest lists, else the first.
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

    /// <summary>A ClickOnce deployment (a .application file or its publish folder) read from the files beside its manifests; null for anything else.</summary>
    private static (string Source, string Sha, Walked Walked)? Deployment(string path, AnalysisLimits limits, CancellationToken ct, bool allFiles)
    {
        if (Core.Installers.ClickOnceDeployment.Find(path) is not { } manifest) return null;
        var top = Core.Installers.ClickOnceDeployment.Open(manifest, limits, ct);
        var sha = Blob.Sha256(System.Text.Encoding.UTF8.GetBytes(string.Join("\n", top.Items.Select(i => i.Name + " " + Blob.Sha256(i.Bytes)))));
        var walked = Walk(top, sha, limits, ct, allFiles);
        // The manifests' own listings repeat the deployment's.
        var manifests = top.Items.Take(2).Select(i => i.Name + ": ").ToList();
        walked.Notes.RemoveAll(n => manifests.Any(m => n.StartsWith(m, StringComparison.Ordinal)));
        return (manifest, sha, walked);
    }

    /// <summary>A Blazor folder whose boot manifest lists assemblies of which none is on disk; null otherwise.</summary>
    private static (string Folder, int Listed)? BootManifestWithoutAssemblies(string folder)
    {
        foreach (var dir in new[] { folder, Path.Combine(folder, "_framework"), Path.Combine(folder, "wwwroot", "_framework") })
        {
            if (!Directory.Exists(dir) || Webcil.BootManifestEntries(dir) is not { } entries) continue;
            // The runtime's own module (dotnet.native.wasm) is not an assembly.
            var listed = entries.Where(e => e.EndsWith(".wasm", StringComparison.OrdinalIgnoreCase) && !e.StartsWith("dotnet.", StringComparison.OrdinalIgnoreCase)).ToList();
            if (listed.Count == 0) return null;
            bool present = listed.Any(e => File.Exists(Path.Combine(dir, e)) || File.Exists(Path.Combine(dir, Path.ChangeExtension(e, ".dll"))));
            return present ? null : (dir, listed.Count);
        }
        return null;
    }

    private static (string Source, byte[] Data, string Sha) ReadSource(string path, AnalysisLimits limits)
    {
        if (Directory.Exists(Path.GetFullPath(path)) && BootManifestWithoutAssemblies(Path.GetFullPath(path)) is { } boot)
            throw new ToolError(ErrorCode.NotFound, $"the boot manifest in {boot.Folder} lists {boot.Listed} assemblies; none is present, so the copy is incomplete.",
                "copy the app's _framework folder with its .wasm (or .dll) files and pass it again");
        if (Directory.Exists(Path.GetFullPath(path))) throw new ToolError(ErrorCode.InvalidArgument, $"{Path.GetFullPath(path)} is a directory.",
            "pass a container file (single-file app, .nupkg, .apk), a Blazor _framework folder or a ClickOnce publish folder; load_assembly loads a folder of assemblies");
        var source = InputFiles.RequireRegularFile(path, "container file");
        if (!File.Exists(source)) throw Targets.FileNotFound(source);
        var length = new FileInfo(source).Length;
        if (length > Math.Min(limits.MaxTotalBytes, Array.MaxLength)) throw new ToolError(ErrorCode.LimitExceeded, $"{source} is too large to unpack ({length:N0} bytes).");
        var data = File.ReadAllBytes(source);
        return (source, data, Blob.Sha256(data));
    }

    /// <summary>Breadth-first walk of nested containers; duplicate content appears once, except archive files, which keep their paths.</summary>
    /// <remarks>A JavaScript bundle opens as one file per module only when every file is asked for (unpack, listing), never nested.</remarks>
    private static Walked Walk(byte[] data, string sha, string source, AnalysisLimits limits, CancellationToken ct, bool allFiles = false, Action<string>? progress = null) =>
        Walk((allFiles && Web.JsBundleFiles.Looks(data, source) ? Web.JsBundleFiles.Open(data, source, ct) : null)
             ?? Containers.Open(data, Path.GetFileName(source), limits, ct, source, allFiles), sha, limits, ct, allFiles, progress);

    /// <summary>The walk below a top level already opened (from the bytes or a stream).</summary>
    private static Walked Walk(ContainerContents top, string sha, AnalysisLimits limits, CancellationToken ct, bool allFiles = false, Action<string>? progress = null)
    {
        var notes = new List<string>();
        var found = new List<Found>();
        var seen = new HashSet<string> { sha };
        long total = 0;

        notes.AddRange(top.Notes);
        var names = new List<NameIssue>(top.Names ?? []);
        var queue = new Queue<(ExtractedItem Item, string Prefix, int Depth, bool Archived, int Archives)>(top.Items.Select(i => (i, "", 1, top.Entries != null, IsArchive(top.Kind) ? 1 : 0)));
        while (queue.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (item, prefix, depth, archived, archives) = queue.Dequeue();
            var itemSha = Blob.Sha256(item.Bytes);
            bool repeat = !seen.Add(itemSha);
            // Skips identical decoded content such as per-ABI assembly stores.
            if (repeat && !archived && !item.Member) continue;
            if (found.Count >= limits.MaxItems || (total += item.Bytes.Length) > limits.MaxTotalBytes)
            {
                notes.Add("Stopped: the extraction limit was reached; some files were not extracted.");
                break;
            }

            var kind = Blob.Identify(item.Bytes);
            // String concatenation, not Path.Combine: a rooted item name would drop the prefix.
            var relative = Blob.SafeRelativePath(prefix + "/" + item.Name, $"item_{found.Count}", archived ? MaxArchiveDepth : 8);
            // Carved assemblies get .dll so they resolve by name.
            if (kind == DotNet && !relative.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && !relative.EndsWith(".exe.bin", StringComparison.OrdinalIgnoreCase))
                relative += ".dll";
            var recorded = (prefix + "/" + item.Name).Replace('\\', '/').TrimStart('/');
            if (archives >= NestedExecutableDepth && IsExecutable(kind, item.Name))
                names.Add(new NameIssue("nested-executable", recorded, $"an executable {archives} archives deep"));
            found.Add(new Found(relative, item.Bytes, kind, itemSha, item.Origin)
            {
                Original = recorded == relative.Replace(System.IO.Path.DirectorySeparatorChar, '/') ? null : recorded,
            });
            if (found.Count % 200 == 0) progress?.Invoke($"{found.Count} entries read ({total / (1024 * 1024):N0} MB)");
            // A repeated member was opened at its first path.
            if (repeat && item.Member) continue;

            bool opens = MayContainMore(kind) && !(archived && kind == "data") || Containers.ReaderFor(item.Bytes, item.Name) != null;
            if (!opens) continue;
            if (depth >= limits.MaxDepth)
            {
                if (Containers.ReaderFor(item.Bytes, item.Name) != null || kind == "zip") notes.Add($"{item.Name}: a container {depth} levels deep, not opened (the nesting limit).");
                continue;
            }
            try
            {
                var inner = Containers.Open(item.Bytes, item.Name, limits, ct, allFiles: allFiles);
                if (inner.Kind == "none") continue;
                notes.Add($"{item.Name}: {inner.Kind}.");
                notes.AddRange(inner.Notes.Select(n => $"{item.Name}: {n}"));
                names.AddRange((inner.Names ?? []).Select(n => n with { Name = $"{item.Name}: {n.Name}" }));
                // Sanitized when used.
                var innerPrefix = prefix + "/" + item.Name + "_unpacked";
                foreach (var i in inner.Items) queue.Enqueue((i, innerPrefix, depth + 1, inner.Entries != null, archives + (IsArchive(inner.Kind) ? 1 : 0)));
            }
            catch (ToolError ex)
            {
                notes.Add($"{item.Name}: {ex.Message}");
            }
        }
        return new Walked(top.Kind, found, notes) { Entries = top.Entries, Names = names };
    }

    /// <summary>Path components kept for an archive file (node_modules trees run deep).</summary>
    private const int MaxArchiveDepth = 48;

    /// <summary>The archive depth (an archive inside an archive) from which an executable is reviewed; files carved from a program do not count.</summary>
    private const int NestedExecutableDepth = 2;

    // A compressed file (gzip, xz, bzip2) wraps one archive: a .tar.gz is one level.
    private static bool IsArchive(string kind) => kind is "zip archive" or "7z" or "rar" or "tar";

    private static bool IsExecutable(string kind, string name) =>
        kind is DotNet or "native PE" or "NativeAOT executable" or "elf" or "mach-o" || Blob.IsRunnableExtension(System.IO.Path.GetExtension(name));

    private static bool MayContainMore(string kind) =>
        kind is "zip" or ".NET assembly" or "native PE" or "data" or "asar" || kind.StartsWith("xa", StringComparison.Ordinal);

    private void LoadAssemblies(List<UnpackedFile> files, List<string> notes, Action<string>? progress)
    {
        int assemblies = files.Count(f => f.Kind == DotNet), loaded = 0;
        // Identical bytes at a second path load once.
        var ids = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = 0; i < files.Count; i++)
        {
            if (files[i].Kind != DotNet) continue;
            if (ids.TryGetValue(files[i].Sha256, out var id))
            {
                files[i] = files[i] with { LoadedAs = id };
                continue;
            }
            if (++loaded % 20 == 0) progress?.Invoke($"{loaded} of {assemblies} assemblies loaded");
            try
            {
                var asm = workspace.Load(files[i].Path);
                files[i] = files[i] with { LoadedAs = asm.Id };
                ids[files[i].Sha256] = asm.Id;
            }
            catch (ToolError ex)
            {
                notes.Add($"Could not load {Path.GetFileName(files[i].Path)}: {ex.Message}");
            }
        }
    }

    internal static string DefaultOutput(string source, string sha, string folder = "corvus-unpacked") =>
        Native.Providers.PrivateFolder.Temp(folder, $"{Blob.SafeRelativePath(Path.GetFileNameWithoutExtension(source), "file")}-{sha[..12]}");

    /// <summary>
    /// Creates the output directory, or reuses it if empty or marked as an
    /// earlier unpack of the same file by this data folder.
    /// </summary>
    internal static string PrepareOutput(string directory, string source, string sha)
    {
        var root = SafeFile.Output(directory);
        var marker = Path.Combine(root, Marker);
        // A marker without this data folder's id may have been planted: the
        // folder is not reused.
        bool Ours() => File.Exists(marker) && File.ReadAllText(marker).Split('\n') is [var s, _, var id, ..] && s == sha && id == MarkerId.Current;
        if (Directory.Exists(root) && Directory.EnumerateFileSystemEntries(root).Any())
            return Ours() ? root : throw new ToolError(ErrorCode.Conflict,
                $"Output directory {root} is not empty and is not an earlier unpack of this file by this data folder. Choose an empty or new directory.");
        Directory.CreateDirectory(root);
        // A conflict from a concurrent unpack of the same file is accepted.
        try { SafeFile.WriteUnderRoot(root, Marker, System.Text.Encoding.UTF8.GetBytes($"{sha}\n{source}\n{MarkerId.Current}\n"), overwrite: false); }
        catch (ToolError ex) when (ex.Code == ErrorCode.Conflict && Ours()) { }
        return root;
    }
}
