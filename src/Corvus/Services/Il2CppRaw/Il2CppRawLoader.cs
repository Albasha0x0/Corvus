using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Corvus.Core;

namespace Corvus.Services;

/// <summary>
/// Loads a raw Il2Cpp game (its binary + global-metadata.dat) without an external dumper:
/// <see cref="Il2CppMetadataReader"/> writes <c>root/&lt;key&gt;/DummyDll/*.dll</c>, <c>il2cpp-model.bin</c> and the
/// marker <see cref="MarkerFileName"/> into a per-user cache (or <c>cacheRoot</c>), and the dummy assemblies load like an Il2CppDumper
/// DummyDll folder. The key is the game files' paths, sizes and write times. The Il2Cpp tools find the model through the marker
/// (<see cref="Il2CppDumpFiles.Locate"/>). At most <see cref="MaxEntries"/> games are kept, evicting the least recently
/// used entry that is not loaded.
/// </summary>
public sealed class Il2CppRawLoader(AssemblyWorkspace workspace, string? cacheRoot = null)
{
    private static readonly JsonSerializerOptions IndentedJson = new() { WriteIndented = true };

    public const string MarkerFileName = "il2cpp-source.json";
    public const string RootVariable = "CORVUS_IL2CPP_CACHE";
    public const string DummyFolder = "DummyDll";
    public const int MaxEntries = 8;
    private const int CacheFormat = 2; // bump when the reader's output changes: older entries are then read again

    public static string DefaultRoot =>
        Environment.GetEnvironmentVariable(RootVariable) is { Length: > 0 } custom
            ? custom
            : Native.Providers.DataFolder.Combine("il2cpp");

    /// <summary>What a cache folder was made from; <see cref="BinaryIdentity"/> is the binary's build id or SHA-256, to match a copy loaded from elsewhere.</summary>
    public sealed record Marker(string Binary, string Metadata, string BinaryStamp, string MetadataStamp, int Format, string Reader, DateTime Created,
        string? Slice = null, string? BinaryIdentity = null, string? Package = null);

    public sealed record Result(Il2CppGameFiles Files, string CacheDirectory, string DummyDirectory, bool FromCache, Il2CppGameModel Model,
        AssemblyWorkspace.LoadReport Load, LoadedNative? Binary, string? BinaryProblem, TimeSpan ReadTime, TimeSpan Elapsed, IReadOnlyList<string> Notes);

    private static readonly object CacheGate = new();
    private static readonly Dictionary<string, WeakReference<Il2CppGameModel>> Models = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The marker in <paramref name="directory"/>, or null when there is none or it cannot be read.</summary>
    public static Marker? ReadMarker(string directory)
    {
        var path = Path.Combine(directory, MarkerFileName);
        if (!File.Exists(path) || !File.Exists(Path.Combine(directory, Il2CppGameModel.FileName))) return null;
        try { return JsonSerializer.Deserialize<Marker>(File.ReadAllText(path)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { return null; }
    }

    /// <summary>The model at <paramref name="path"/>: the one just built when still in memory, else read from the file.</summary>
    public static Il2CppGameModel Model(string path)
    {
        var full = Path.GetFullPath(path);
        lock (Models)
            if (Models.TryGetValue(full, out var weak) && weak.TryGetTarget(out var model)) return model;
        var read = Il2CppGameModel.Read(full);
        lock (Models) Models[full] = new WeakReference<Il2CppGameModel>(read);
        return read;
    }

    private static string Stamp(string path) => new FileInfo(path) is { Exists: true } f ? $"{f.Length}:{f.LastWriteTimeUtc.Ticks}" : "-";

    private static string Key(Il2CppGameFiles files)
    {
        var text = $"{CacheFormat}|{Path.GetFullPath(files.Binary).ToLowerInvariant()}|{Stamp(files.Binary)}|{Path.GetFullPath(files.Metadata).ToLowerInvariant()}|{Stamp(files.Metadata)}|{files.Slice}";
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)))[..16];
    }

    private static string ReaderVersion => typeof(LibCpp2IL.LibCpp2IlMain).Assembly.GetName().Version?.ToString() ?? "?";

    /// <summary>
    /// Reads (or finds in the cache) the game at <paramref name="files"/>, loads its dummy assemblies and, with
    /// <paramref name="loadBinary"/>, GameAssembly.dll as a native image.
    /// </summary>
    public Result Load(Il2CppGameFiles files, bool loadBinary, Action<string>? progress, CancellationToken ct, string? root = null)
    {
        var watch = Stopwatch.StartNew();
        var notes = new List<string>();
        var entries = Path.GetFullPath(root ?? cacheRoot ?? DefaultRoot);
        var dir = Path.Combine(entries, Key(files));
        var dummy = Path.Combine(dir, DummyFolder);
        Il2CppGameModel model;
        bool fromCache;
        TimeSpan readTime;
        lock (CacheGate)
        {
            if (ReadMarker(dir) is { } marker && marker.Format == CacheFormat && marker.Reader == ReaderVersion
                && marker.BinaryStamp == Stamp(files.Binary) && marker.MetadataStamp == Stamp(files.Metadata)
                && Directory.Exists(dummy) && Directory.EnumerateFiles(dummy, "*.dll").Any())
            {
                try
                {
                    model = Model(Path.Combine(dir, Il2CppGameModel.FileName));
                    fromCache = true;
                    readTime = model.ReadTime;
                    Touch(dir);
                    goto loaded;
                }
                catch (IOException ex) { notes.Add($"cache entry {dir} unreadable ({ex.Message}); read again"); }
            }
            Il2CppMetadataReader.CheckHeader(files.Metadata);
            var staging = dir + ".tmp-" + Environment.ProcessId;
            TryDelete(staging);
            try
            {
                Directory.CreateDirectory(staging);
                var output = Il2CppMetadataReader.Read(files, Path.Combine(staging, DummyFolder), progress, ct);
                model = output.Model;
                notes.AddRange(output.Notes);
                progress?.Invoke("saving the model");
                model.Write(Path.Combine(staging, Il2CppGameModel.FileName));
                var newMarker = new Marker(files.Binary, files.Metadata, Stamp(files.Binary), Stamp(files.Metadata), CacheFormat, ReaderVersion, DateTime.UtcNow,
                    files.Slice, output.BinaryIdentity, files.Package);
                File.WriteAllText(Path.Combine(staging, MarkerFileName), JsonSerializer.Serialize(newMarker, IndentedJson));
                if (Directory.Exists(dir))
                {
                    if (workspace.Read(() => workspace.Assemblies.Any(a => a.FilePath.StartsWith(dir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))))
                        throw new ToolError(ErrorCode.Conflict, $"An older read of this game is loaded from {dir}.", "unload its assemblies first, then load the game again");
                    Directory.Delete(dir, true);
                }
                Directory.Move(staging, dir);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                TryDelete(staging);
                throw new ToolError(ErrorCode.IoError, $"Cannot write the Il2Cpp cache under {entries}: {ex.Message}", $"set {RootVariable} to a writable folder");
            }
            catch
            {
                TryDelete(staging);
                throw;
            }
            lock (Models) Models[Path.Combine(dir, Il2CppGameModel.FileName)] = new WeakReference<Il2CppGameModel>(model);
            fromCache = false;
            readTime = model.ReadTime;
            Trim(entries, dir);
        }
        loaded:
        progress?.Invoke("loading the dummy assemblies");
        var report = workspace.LoadDirectory(dummy, recursive: false);
        LoadedNative? native = null;
        string? binaryProblem = null;
        if (loadBinary)
        {
            try { native = workspace.LoadAny(files.Binary, files.Slice).Native; }
            catch (ToolError ex) { binaryProblem = ex.Message; }
        }
        return new Result(files, dir, dummy, fromCache, model, report, native, binaryProblem, readTime, watch.Elapsed, notes);
    }

    private static void Touch(string dir)
    {
        try { Directory.SetLastWriteTimeUtc(dir, DateTime.UtcNow); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>Removes the least recently used entries beyond <see cref="MaxEntries"/>, except <paramref name="keep"/> and loaded ones.</summary>
    private void Trim(string root, string keep)
    {
        try
        {
            var loaded = workspace.Read(() => workspace.Assemblies.Select(a => a.FilePath).ToList());
            var entries = Directory.EnumerateDirectories(root)
                .Where(d => File.Exists(Path.Combine(d, MarkerFileName)) && !d.Equals(keep, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(Directory.GetLastWriteTimeUtc).ToList();
            foreach (var old in entries.Skip(MaxEntries - 1))
                if (!loaded.Any(p => p.StartsWith(old + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))) TryDelete(old);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static void TryDelete(string dir)
    {
        try { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>Unreadable items grouped by reason, with up to <paramref name="examples"/> items each.</summary>
    public static List<(string Reason, int Count, List<Il2CppGameModel.Unreadable> Examples)> UnreadableSummary(Il2CppGameModel model, int examples = 3) =>
        model.Unreadables.GroupBy(u => u.Reason).OrderByDescending(g => g.Count())
            .Select(g => (g.Key, g.Count(), g.Take(examples).ToList())).ToList();

    /// <summary>A text report of a load for load_assembly.</summary>
    public static string Describe(Result r)
    {
        var m = r.Model;
        var sb = new StringBuilder();
        sb.AppendLine($"Read Il2Cpp game {r.Files.Binary}{(r.Files.Slice != null ? $" [{r.Files.Slice}]" : "")} + {r.Files.Metadata} with the built-in reader (LibCpp2IL){(r.FromCache ? " — from the cache" : "")}:");
        if (r.Files.Package != null) sb.AppendLine($"  {r.Files.Platform} build extracted from {r.Files.Package}");
        else if (r.Files.Platform != "windows") sb.AppendLine($"  {r.Files.Platform} build");
        sb.AppendLine($"  metadata v{m.HeaderVersion} (read as {m.MetadataVersion:0.##}), Unity {m.UnityVersion} ({m.UnityVersionSource}); image base 0x{m.ImageBase:X}{(m.MemoryImage ? " (memory image)" : "")}");
        sb.AppendLine($"  {m.Images} images, {m.Types} types, {m.MethodDefinitions} methods ({m.MethodsWithCode} with code), {m.Fields} fields; " +
                      $"{m.Methods.Count} ScriptMethod entries, {m.Metadata.Count} metadata and {m.MethodInfos.Count} MethodInfo slots, " +
                      $"{m.LiteralSlots.Count(s => s != 0)} of {m.LiteralValues.Length} string literals with a slot");
        sb.AppendLine($"  read in {r.ReadTime.TotalSeconds:0.0} s; this call {r.Elapsed.TotalSeconds:0.0} s; cache {r.CacheDirectory}");
        sb.AppendLine($"  dummy assemblies: loaded {r.Load.Loaded.Count} from {r.DummyDirectory}" + (r.Load.Skipped.Count > 0 ? $", {r.Load.Skipped.Count} not loaded: " +
                      string.Join("; ", r.Load.Skipped.Take(5).Select(s => $"{Path.GetFileName(s.Path)}: {Format.Clip(s.Error, 120)}")) : ""));
        if (r.Binary != null) sb.AppendLine($"  native image: {r.Binary.Id} (apply_il2cpp_names names its functions and data)");
        else if (r.BinaryProblem != null) sb.AppendLine($"  native image not loaded: {r.BinaryProblem}");
        var summary = UnreadableSummary(m);
        if (summary.Count == 0) sb.AppendLine("  unreadable items: none");
        else
        {
            sb.AppendLine($"  unreadable items: {m.Unreadables.Count}, by reason:");
            foreach (var (reason, count, examples) in summary.Take(12))
                sb.AppendLine($"    {reason}: {count} (e.g. {string.Join("; ", examples.Select(e => $"{e.Item}: {Format.Clip(e.Detail, 120)}"))})");
        }
        sb.AppendLine("  not covered: the original custom attributes; C prototypes of script.json (instantiations are matched to their definitions by token instead)");
        foreach (var note in r.Notes.Take(12)) sb.AppendLine($"  note: {Format.Clip(note, 400)}");
        sb.Append("Next: get_il2cpp_info / find_method_by_address / search_strings on these assemblies; apply_il2cpp_names to name the native image.");
        return sb.ToString();
    }
}
