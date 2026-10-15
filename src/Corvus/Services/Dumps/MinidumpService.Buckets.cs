using System.Collections.Concurrent;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Managed;

namespace Corvus.Services;

public sealed partial class MinidumpService
{
    public const int DefaultMaxDumps = 1000;
    /// <summary>Windows minidumps, then Linux and Android core files.</summary>
    public const string DefaultDumpPatterns = "*.dmp;*.mdmp;*.core;core.*";
    private const int BucketWalkFrames = 64;
    /// <summary>Overrides the folder of the incremental bucketing cache.</summary>
    public const string BucketCacheVariable = "CORVUS_DUMP_BUCKET_CACHE";

    /// <summary>Frames that say how an exception was raised, not where: skipped in signatures.</summary>
    private static readonly string[] NoiseFrames =
        ["ntdll!KiUserExceptionDispatcher", "ntdll!RtlRaiseException", "KERNELBASE!RaiseException", "ucrtbase!abort", "ucrtbase!raise", "*!_CxxThrowException"]; // any module: the CRT may be linked statically

    /// <summary>Where signatures of already bucketed dumps are kept (per folder; keyed by path, size and write time).</summary>
    internal string BucketCache { get; set; } = Environment.GetEnvironmentVariable(BucketCacheVariable) is { Length: > 0 } custom ? custom
        : Native.Providers.DataFolder.Combine("dumpbuckets");

    public sealed record DumpCounts(
        [property: Description("Dump files found.")] int Seen,
        [property: Description("Parsed in this call.")] int Parsed,
        [property: Description("Taken from the cache of an earlier call (same path, size and write time).")] int Cached,
        int Failed,
        [property: Description("More files than maxDumps: the newest were bucketed.")] bool LimitReached);

    public sealed record DumpBucket(
        [property: Description("exception code | faulting module!function | the next frames; hang | top frames; clr | exception type | top managed frames.")] string Signature,
        [property: Description("exception, clr_exception or no_exception.")] string Kind,
        int Count, string FirstTime, string LastTime,
        [property: Description("Faulting module versions: dumps per version.")] IReadOnlyDictionary<string, int> ModuleVersions,
        [property: Description("Offsets inside the faulting function: dumps per offset.")] IReadOnlyDictionary<string, int> Offsets,
        [property: Description("Dump ids (open_minidump, dump_stack) of up to five members.")] IReadOnlyList<string> Sample,
        [property: Description("The newest member's dump id.")] string Representative);

    public sealed record FailedDump(string Path, string Reason);

    public sealed record DumpBuckets(
        string Folder, DumpCounts Dumps, IReadOnlyList<DumpBucket> Items, int Offset, int Total, IReadOnlyList<FailedDump> Failed, IReadOnlyList<string> Notes);

    /// <summary>One dump's signature parts (cached between calls).</summary>
    internal sealed record DumpSignature(string Kind, string Key, string? Version, string? Offset, DateTime Time);

    private sealed record CacheEntry(string Path, long Size, long Ticks, DumpSignature? Signature, string? Failure);

    public async Task<DumpBuckets> Bucket(string folder, bool recursive, string? pattern, int topFrames, string? skipModules, bool splitByVersion, bool managed,
        int maxDumps, string? imageDirectories, int offset, int limit, Action<int, int>? progress, CancellationToken ct)
    {
        string root;
        try { root = Path.GetFullPath((folder ?? "").Trim()); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ToolError(ErrorCode.InvalidArgument, $"'{folder}' is not a valid folder path: {ex.Message}");
        }
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(root))
            throw Targets.DirectoryNotFound(folder ?? "");
        topFrames = Math.Clamp(topFrames, 0, 16);
        maxDumps = Math.Clamp(maxDumps, 1, 100_000);
        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, MaxListLimit);
        var skip = NoiseFrames.Concat((skipModules ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).ToList();
        var patterns = (string.IsNullOrWhiteSpace(pattern) ? DefaultDumpPatterns : pattern).Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var notes = new List<string>();

        var files = new List<FileInfo>();
        try
        {
            var options = new EnumerationOptions { RecurseSubdirectories = recursive, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
            foreach (var p in patterns)
            {
                var found = new DirectoryInfo(root).EnumerateFiles(p, options);
                // the default core patterns also match other files (core.c, app.core.json): only ELF cores are kept
                files.AddRange(string.IsNullOrWhiteSpace(pattern) && p is "*.core" or "core.*" ? found.Where(f => ElfCoreFile.IsCore(f.FullName)) : found);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            throw new ToolError(ErrorCode.IoError, $"cannot list {root}: {ex.Message}");
        }
        files = files.DistinctBy(f => f.FullName, StringComparer.OrdinalIgnoreCase).OrderByDescending(f => f.LastWriteTimeUtc).ThenBy(f => f.FullName, StringComparer.Ordinal).ToList();
        int seen = files.Count;
        bool limited = files.Count > maxDumps;
        if (limited)
        {
            files = files.Take(maxDumps).ToList();
            notes.Add($"{seen} dump files: only the newest {maxDumps} (maxDumps) were bucketed.");
        }

        string settings = Settings(topFrames, skip, managed, imageDirectories);
        var cachePath = Path.Combine(BucketCache, Hash(root.ToUpperInvariant()) + ".json");
        var cache = ReadCache(cachePath, settings, notes);
        var results = new ConcurrentDictionary<string, CacheEntry>(StringComparer.OrdinalIgnoreCase);
        int done = 0, parsed = 0, cached = 0;
        await Parallel.ForEachAsync(files, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, Environment.ProcessorCount / 2), CancellationToken = ct }, async (f, token) =>
        {
            long ticks = f.LastWriteTimeUtc.Ticks;
            if (cache.TryGetValue(f.FullName, out var hit) && hit.Size == f.Length && hit.Ticks == ticks)
            {
                results[f.FullName] = hit;
                Interlocked.Increment(ref cached);
            }
            else
            {
                CacheEntry entry;
                try { entry = new CacheEntry(f.FullName, f.Length, ticks, await Signature(f.FullName, imageDirectories, topFrames, skip, managed, token), null); }
                catch (ToolError e) { entry = new CacheEntry(f.FullName, f.Length, ticks, null, e.Message); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { entry = new CacheEntry(f.FullName, f.Length, ticks, null, e.Message); }
                results[f.FullName] = entry;
                Interlocked.Increment(ref parsed);
            }
            progress?.Invoke(Interlocked.Increment(ref done), files.Count);
        });
        WriteCache(cachePath, settings, results.Values, notes);

        var failed = results.Values.Where(r => r.Signature == null).OrderBy(r => r.Path, StringComparer.Ordinal)
            .Select(r => new FailedDump(r.Path, r.Failure ?? "unreadable")).ToList();
        var buckets = results.Values.Where(r => r.Signature != null)
            .GroupBy(r => splitByVersion ? $"{r.Signature!.Key} | version {r.Signature.Version ?? "?"}" : r.Signature!.Key)
            .Select(g =>
            {
                var members = g.OrderByDescending(r => r.Signature!.Time).ThenBy(r => r.Path, StringComparer.Ordinal).ToList();
                var ids = members.Select(r => Register(r.Path)).ToList();
                return new DumpBucket(g.Key, members[0].Signature!.Kind, members.Count,
                    members.Min(r => r.Signature!.Time).ToString("u"), members.Max(r => r.Signature!.Time).ToString("u"),
                    Tally(members.Select(r => r.Signature!.Version ?? "?")), Tally(members.Where(r => r.Signature!.Offset != null).Select(r => r.Signature!.Offset!)),
                    ids.Take(5).ToList(), ids[0]);
            })
            .OrderByDescending(b => b.Count).ThenByDescending(b => b.LastTime, StringComparer.Ordinal).ThenBy(b => b.Signature, StringComparer.Ordinal).ToList();
        if (files.Count == 0) notes.Add($"No file in {root} matches {string.Join(";", patterns)}{(recursive ? "" : " (recursive=false)")}.");
        var page = buckets.Skip(offset).Take(limit).ToList();
        return new DumpBuckets(root, new DumpCounts(seen, parsed, cached, failed.Count, limited), page, offset, buckets.Count, failed.Take(100).ToList(), notes);
    }

    private static Dictionary<string, int> Tally(IEnumerable<string> values) =>
        values.GroupBy(v => v).OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.Ordinal).Take(20).ToDictionary(g => g.Key, g => g.Count());

    /// <summary>What a cached signature depends on: the options and the names the loaded images give.</summary>
    private string Settings(int topFrames, List<string> skip, bool managed, string? imageDirectories)
    {
        var images = workspace?.Read(() => string.Join(",", workspace.Natives.Select(n => $"{Path.GetFileName(n.FilePath)}:{n.Pe?.Coff.TimeDateStamp:X}").Order(StringComparer.Ordinal))) ?? "";
        return Hash($"2|{topFrames}|{string.Join(";", skip)}|{managed}|{imageDirectories}|{images}");
    }

    private static string Hash(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)))[..16].ToLowerInvariant();

    private static Dictionary<string, CacheEntry> ReadCache(string path, string settings, List<string> notes)
    {
        var result = new Dictionary<string, CacheEntry>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (!File.Exists(path)) return result;
            using var doc = JsonDocument.Parse(File.ReadAllBytes(path));
            if (doc.RootElement.GetProperty("settings").GetString() != settings) return result;
            foreach (var e in doc.RootElement.GetProperty("entries").Deserialize<List<CacheEntry>>() ?? [])
                result[e.Path] = e;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or KeyNotFoundException or InvalidOperationException)
        {
            notes.Add($"The bucketing cache {path} was not read ({ex.Message}): every dump was parsed.");
        }
        return result;
    }

    private static void WriteCache(string path, string settings, IEnumerable<CacheEntry> entries, List<string> notes)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var json = JsonSerializer.Serialize(new { settings, entries = entries.OrderBy(e => e.Path, StringComparer.Ordinal).ToList() });
            SafeFile.WriteAllText(path, json, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ToolError)
        {
            notes.Add($"The bucketing cache {path} was not written: {ex.Message}");
        }
    }

    /// <summary>
    /// A dump's signature. Exception: code | the first frame that is not raising machinery (module!function, or
    /// module+function start) | the next frames. CLR exception (with a local DAC): clr | exception type | top managed
    /// frames. No exception: hang | the first thread's top frames. Function names, not addresses, so rebases and
    /// offsets inside one function do not split a bucket; the offset is kept apart.
    /// </summary>
    internal async Task<DumpSignature> Signature(string path, string? imageDirectories, int topFrames, IReadOnlyList<string> skip, bool managed, CancellationToken ct)
    {
        using var s = Open(path, imageDirectories);
        if (s.Core is { } core) return await CoreSignature(s, core, topFrames, skip, ct);
        var d = s.Dump;
        if (d.Exception is { } e && d.ThreadById(e.ThreadId) is { } thread)
        {
            string code = $"0x{e.Code:X8}";
            if (e.Code == ExceptionCodes.ClrException && managed && await ManagedSignature(s, e.ThreadId, topFrames, ct) is { } clr) return clr;
            var ctx = d.ReadContext(e.Context) ?? d.ReadContext(thread.Context);
            var frames = ctx == null ? [] : await SignatureFrames(s, thread, ctx, skip, ct);
            if (frames.Count == 0)
            {
                var at = await Locate(s, e.Address, false, ct);
                frames.Add((Label(at, e.Address), at.Module?.FileVersion, Offset(at, e.Address)));
            }
            var fault = frames[0];
            return new DumpSignature("exception", $"{code} | {fault.Label} | {string.Join(" > ", frames.Skip(1).Take(topFrames).Select(f => f.Label))}",
                fault.Version, fault.Offset, d.Time);
        }
        // the runtime's own dump writer records no exception stream: the exception in flight is the signature
        if (managed && ClrDecoder.RuntimeModule(d) != null && await ManagedSignature(s, null, topFrames, ct) is { } inFlight) return inFlight;
        if (d.Threads.Count == 0) throw new ToolError(ErrorCode.MalformedInput, "the dump has no threads and no exception.");
        var first = d.Threads[0];
        var context = d.ReadContext(first.Context) ?? throw new ToolError(ErrorCode.MalformedInput, "the first thread has no readable context.");
        var hang = await SignatureFrames(s, first, context, skip, ct);
        return new DumpSignature("no_exception", $"hang | {string.Join(" > ", hang.Take(Math.Max(1, topFrames)).Select(f => f.Label))}", null, null, d.Time);
    }

    private async Task<DumpSignature?> ManagedSignature(Session s, uint? threadId, int topFrames, CancellationToken ct)
    {
        try
        {
            var decoder = await Decoder(s, new DacRequest(), ct);
            if (decoder is not { Loaded: true }) return null;
            ManagedException? ex;
            using (AssemblyWorkspace.Lock(decoder.Gate)) ex = decoder.Exception(threadId) ?? decoder.Exception(null);
            if (ex == null) return null;
            var frames = ex.Stack.Where(f => f.IsMethod).Select(f => MethodOnly(f.Name)).ToList();
            if (frames.Count == 0 && (threadId ?? ex.ThreadId) is { } thread)
            {
                // an exception trace the DAC does not resolve (32-bit runtimes): the thread's own walk from the raise down
                ulong raisedAt = s.Dump.Exception is { } e && e.ThreadId == thread && s.Dump.ReadContext(e.Context) is { } c ? c.Sp : 0;
                using (AssemblyWorkspace.Lock(decoder.Gate))
                    frames = decoder.Frames(thread, BucketWalkFrames).Where(f => f.IsMethod && f.Sp >= raisedAt).Select(f => MethodOnly(f.Name)).ToList();
            }
            var version = ClrDecoder.RuntimeModule(s.Dump)?.FileVersion;
            return new DumpSignature("clr_exception", $"clr | {ex.Type} | {string.Join(" > ", frames.Take(Math.Max(1, topFrames)))}", version, null, s.Dump.Time);
        }
        catch (ToolError) { return null; }
    }

    /// <summary>Ns.Type.Method(args) to Ns.Type.Method.</summary>
    private static string MethodOnly(string name)
    {
        int paren = name.IndexOf('(');
        return paren > 0 ? name[..paren] : name;
    }

    private async Task<List<(string Label, string? Version, string? Offset)>> SignatureFrames(Session s, DumpThread thread, DumpContext ctx, IReadOnlyList<string> skip, CancellationToken ct)
    {
        // a WoW64 thread's own code is its 32-bit side
        var walk = Wow64.Thread(s.Dump, thread.Teb) is { } wow
            ? s.Walker(Wow64.View(s.Dump)).Walk(wow.Context, wow.StackLow, wow.StackHigh, BucketWalkFrames, ct)
            : s.Walker().Walk(ctx, thread.StackStart, thread.StackStart + thread.StackSize, BucketWalkFrames, ct);
        return await SignatureFrames(s, walk, skip, ct);
    }

    private async Task<List<(string Label, string? Version, string? Offset)>> SignatureFrames(Session s, WalkResult walk, IReadOnlyList<string> skip, CancellationToken ct)
    {
        var frames = new List<(string, string?, string?)>();
        foreach (var f in walk.Frames)
        {
            if (f.Heuristic) continue;
            var at = await Locate(s, f.Ip, f.IsReturnAddress, ct);
            var label = Label(at, f.Ip);
            if (skip.Any(p => Noise(label, p))) continue;
            // below the fault, a place without a name (JIT code, unknown memory) depends on what memory the dump holds
            if (frames.Count > 0 && label.StartsWith('<')) continue;
            frames.Add((label, at.Module?.FileVersion, Offset(at, f.Ip)));
        }
        return frames;
    }

    /// <summary>module!function, module+function start, module+offset, or the kind of place (unloaded module, JIT code).</summary>
    private static string Label(Location at, ulong address)
    {
        if (at.Module is not { } m) return at.Kind == "managed" ? "<jit code>" : $"<{at.Kind}>";
        string module = ModuleLabel(m);
        if (at.Function != null) return $"{module}!{at.Function}";
        if (at.FunctionAddress is { } start) return $"{module}+0x{start - m.Base:X}";
        return $"{module}+0x{address - m.Base:X}";
    }

    private static string? Offset(Location at, ulong address) =>
        at.FunctionAddress is { } start && address >= start ? $"+0x{address - start:X}" : at.Rva is { } rva ? $"0x{rva:X}" : null;

    /// <summary>A pattern without '!' names a whole module; with one, module!function (wildcards in either part).</summary>
    private static bool Noise(string label, string pattern) =>
        pattern.Contains('!') ? Wildcard.Matches(label, pattern) : label.Split('!', '+')[0] is var module && Wildcard.Matches(module, pattern);
}
