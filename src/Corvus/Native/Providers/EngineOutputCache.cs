using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Corvus.Native.Providers;

/// <summary>
/// Engine output kept across server processes (EL-1): an engine's answer to a read request (pseudocode, a frame with
/// its decompiler locals) stored under the engine's build, the input's SHA-256, the database state and the request.
/// The database state is a chain of the requests that changed the database since it was created (see
/// <see cref="WorkerSessionBase"/>), saved beside the database when it is saved; so any change makes new keys, and a
/// stale answer cannot be served. A change confined to one function's output chains that function only: entries carry
/// their function's chain, and other functions' answers stay valid. Entries are files under <c>root/engine-output</c>, written whole (temporary file,
/// then rename) with a checksum: a damaged entry is a miss. The least recently used go beyond <see cref="MaxBytes"/>.
/// </summary>
/// <summary>What the output cache keeps: pseudocode and frames with decompiler locals, by the address asked.</summary>
public static class OutputCacheKinds
{
    public const string Decompile = "decompile", Frame = "frame";

    public static string At(uint rva) => rva.ToString("X", System.Globalization.CultureInfo.InvariantCulture);
}

public sealed class EngineOutputCache
{
    public const string MaxMegabytesVariable = "CORVUS_ENGINE_OUTPUT_MB";
    public const long DefaultMaxMegabytes = 1024;

    /// <summary>Saved beside an IDA database, inside a Ghidra project directory: the state of the database as saved.</summary>
    internal const string StateFileSuffix = ".corvus-state.json", StateFileName = "corvus-state.json";

    private readonly object _evictLock = new();
    private int _writes;

    public EngineOutputCache(string root, long? maxBytes = null)
    {
        Root = Path.Combine(Path.GetFullPath(root), "engine-output");
        MaxBytes = maxBytes ?? (long.TryParse(Environment.GetEnvironmentVariable(MaxMegabytesVariable), out var mb) && mb > 0 ? mb : DefaultMaxMegabytes) << 20;
    }

    public string Root { get; }
    public long MaxBytes { get; }

    /// <summary>Entries served and stored by this process.</summary>
    public int Hits => Volatile.Read(ref _hits);
    public int Stores => Volatile.Read(ref _stores);
    private int _hits, _stores;

    /// <summary>A key from its parts (SHA-256, hex).</summary>
    public static string Key(params object?[] parts)
    {
        var sb = new StringBuilder();
        foreach (var p in parts) sb.Append(p switch { null => "", JsonNode n => n.ToJsonString(), _ => Convert.ToString(p, System.Globalization.CultureInfo.InvariantCulture) }).Append('\0');
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString())));
    }

    /// <summary>Output entries are this layout's: a change of what is stored changes the version.</summary>
    private const string Layout = "engine-output-2";

    /// <summary>The key of an engine answer: what was asked (decompile, frame) and of what, in a database state of an engine build and input.</summary>
    public static string OutputKey(string? identity, string engine, string sha256, string state, string what, string key) =>
        Key(Layout, identity, engine, sha256.ToLowerInvariant(), state, what, key);

    /// <summary>The serializer of stored answers (records round-trip through their constructors).</summary>
    internal static readonly JsonSerializerOptions Json = new() { IncludeFields = false };

    private string PathOf(string key) => Path.Combine(Root, key[..2], key + ".json");

    /// <summary>The value stored under <paramref name="key"/>, or null (absent, damaged or unreadable).</summary>
    public string? Get(string key)
    {
        var path = PathOf(key);
        try
        {
            if (!File.Exists(path)) return null;
            var text = File.ReadAllText(path, Encoding.UTF8);
            int nl = text.IndexOf('\n');
            if (nl != 64 || text[..64] != Hash(text[(nl + 1)..])) return null;
            try { File.SetLastWriteTimeUtc(path, DateTime.UtcNow); } catch (IOException) { } // recently used
            Interlocked.Increment(ref _hits);
            return text[(nl + 1)..];
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>Stores <paramref name="value"/> under <paramref name="key"/>; failures are ignored (the cache is an optimization).</summary>
    public void Put(string key, string value)
    {
        var path = PathOf(key);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var temp = path + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp";
            File.WriteAllText(temp, Hash(value) + "\n" + value, new UTF8Encoding(false));
            File.Move(temp, path, overwrite: true);
            Interlocked.Increment(ref _stores);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return; }
        if (Interlocked.Increment(ref _writes) % 64 == 1) Evict();
    }

    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    /// <summary>Deletes the least recently used entries beyond <see cref="MaxBytes"/>.</summary>
    public void Evict()
    {
        lock (_evictLock)
        {
            try
            {
                if (!Directory.Exists(Root)) return;
                var files = new DirectoryInfo(Root).EnumerateFiles("*", SearchOption.AllDirectories).ToList();
                long total = files.Sum(f => f.Length);
                foreach (var f in files.OrderBy(f => f.LastWriteTimeUtc))
                {
                    if (total <= MaxBytes) break;
                    try
                    {
                        long length = f.Length; // a deleted FileInfo has none
                        f.Delete();
                        total -= length;
                    }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>Size and entry count, for server_status.</summary>
    public (int Entries, long Bytes) Size()
    {
        try
        {
            if (!Directory.Exists(Root)) return (0, 0);
            var files = new DirectoryInfo(Root).EnumerateFiles("*.json", SearchOption.AllDirectories).ToList();
            return (files.Count, files.Sum(f => f.Length));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return (0, 0); }
    }

    // ---- the saved state of a database ----

    /// <summary>The state file of a database file (IDA) or project directory (Ghidra).</summary>
    internal static string StateFile(string database) =>
        Directory.Exists(database) ? Path.Combine(database, StateFileName) : database + StateFileSuffix;

    /// <summary>
    /// What identifies the saved bytes of a database: a file's length and write time; a project directory's files (lock
    /// files and the state file left out) by count, total length and latest write time. Null when it does not exist.
    /// </summary>
    internal static string? Identity(string database)
    {
        try
        {
            if (File.Exists(database))
            {
                var f = new FileInfo(database);
                return $"{f.Length}:{f.LastWriteTimeUtc.Ticks}";
            }
            if (!Directory.Exists(database)) return null;
            long count = 0, length = 0, latest = 0;
            foreach (var f in new DirectoryInfo(database).EnumerateFiles("*", SearchOption.AllDirectories))
            {
                if (f.Name == StateFileName || f.Name.EndsWith(".lock", StringComparison.OrdinalIgnoreCase) || f.Name.EndsWith(".lock~", StringComparison.OrdinalIgnoreCase)) continue;
                count++;
                length += f.Length;
                latest = Math.Max(latest, f.LastWriteTimeUtc.Ticks);
            }
            return $"{count}:{length}:{latest}";
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>The state saved with <paramref name="database"/>, or null when there is none or the database changed after it was written.</summary>
    internal static string? ReadState(string database)
    {
        try
        {
            var file = StateFile(database);
            if (!File.Exists(file)) return null;
            var o = JsonNode.Parse(File.ReadAllText(file)) as JsonObject;
            var state = (string?)o?["state"];
            return state != null && (string?)o!["identity"] == Identity(database) ? state : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException or FormatException) { return null; }
    }

    /// <summary>The saved global chain and per-function chains (see <see cref="WriteState"/>), or null.</summary>
    internal static (string Global, Dictionary<uint, string> Functions)? ReadChains(string database)
    {
        try
        {
            if (ReadState(database) is not { } state) return null;
            var o = (JsonObject)JsonNode.Parse(File.ReadAllText(StateFile(database)))!;
            var functions = new Dictionary<uint, string>();
            if (o["functions"] is JsonObject f)
                foreach (var (k, v) in f) functions[uint.Parse(k, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture)] = (string)v!;
            return ((string?)o["global"] ?? state, functions);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException or FormatException or InvalidCastException) { return null; }
    }

    /// <summary>Forgets the saved state (the database was saved in a state that cannot be named).</summary>
    internal static void ClearState(string database)
    {
        try { File.Delete(StateFile(database)); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>
    /// Records <paramref name="state"/> as the state of the database as saved now, with the global and per-function chains
    /// it combines when there are function chains.
    /// </summary>
    internal static void WriteState(string database, string state, string? global = null, IReadOnlyDictionary<uint, string>? functions = null)
    {
        try
        {
            if (Identity(database) is not { } identity) return;
            var file = StateFile(database);
            var temp = file + ".tmp";
            var o = new JsonObject { ["state"] = state, ["identity"] = identity };
            if (functions is { Count: > 0 })
            {
                o["global"] = global;
                o["functions"] = new JsonObject(functions.OrderBy(f => f.Key).Select(f => KeyValuePair.Create(OutputCacheKinds.At(f.Key), (JsonNode?)f.Value)));
            }
            File.WriteAllText(temp, o.ToJsonString());
            File.Move(temp, file, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }
}
