using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Core.Mobile;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Jadx;

namespace NetDecompilerMcp.Services.Mobile;

/// <summary>
/// Java / Kotlin source through the JADX headless server, one session per package file kept while it is unchanged (two at most).
/// Classes and methods are resolved by the DEX index first, so a method is one exact overload: it is matched to the server's
/// overload list by its parameter types.
/// </summary>
public sealed class JavaDecompilerService(DexService dex) : IDisposable
{
    public static readonly TimeSpan LoadTimeout = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan CallTimeout = TimeSpan.FromMinutes(3);
    private const int MaxSessions = 2;

    private readonly LinkedList<(string Key, JadxServer Server)> _sessions = new();
    private readonly object _lock = new();

    /// <summary>Extra environment for the server process (tests).</summary>
    internal IReadOnlyDictionary<string, string?>? Environment { get; init; }

    public async Task<string> Decompile(string path, string symbol, bool smaliFallback, CancellationToken ct)
    {
        var index = dex.Index(path, ct);
        symbol = symbol.Trim();
        bool member = symbol.Contains("->", StringComparison.Ordinal) || symbol.Contains("::", StringComparison.Ordinal) || symbol.Contains('(', StringComparison.Ordinal);
        DexClassEntry? cls = member ? null : index.FindClass(symbol);
        DexMethodEntry? method = null;
        if (cls == null)
        {
            var id = index.ResolveMethod(symbol);
            method = index.Methods.GetValueOrDefault(id) ?? throw new ToolError(ErrorCode.NotFound,
                $"{id} is called by the package but not defined in it (a framework or library method): nothing to decompile.");
            cls = new DexClassEntry(method.File, method.Class);
        }
        var className = DexFile.JavaName(cls.Class.Descriptor);
        var server = await Session(index.Path, ct).ConfigureAwait(false);
        try
        {
            if (method == null)
            {
                var source = await Call(server, "get_class_source", new JsonObject { ["class_name"] = className, ["smali_fallback"] = smaliFallback }, ct).ConfigureAwait(false);
                return $"// {cls.Class.Descriptor} (JADX)\n{source}";
            }
            var (overload, basis, count) = await Overload(server, index, method, className, ct).ConfigureAwait(false);
            var body = await Call(server, "get_method_body", new JsonObject
            {
                ["class_name"] = className, ["method_name"] = method.Ref.Name, ["overload_index"] = overload, ["smali_fallback"] = smaliFallback,
            }, ct).ConfigureAwait(false);
            string mode = "java", text = body;
            try
            {
                if (JsonNode.Parse(body) is JsonObject envelope)
                {
                    mode = (string?)envelope["mode"] ?? mode;
                    text = (string?)envelope["body"] ?? body;
                }
            }
            catch (JsonException) { }
            var note = count > 1 ? $", overload {overload + 1} of {count} matched by {basis}" : "";
            return $"// {method.Descriptor} (JADX, {mode}{note})\n{text}";
        }
        catch (JadxExitedException ex)
        {
            Drop(index.Path);
            throw new ToolError(ErrorCode.ProviderUnavailable, ex.Message, "call again to restart the JADX server; disassemble_dex gives the smali without it");
        }
    }

    /// <summary>The server's overload index of <paramref name="method"/>: by Java parameter types, or by DEX order among equal ones.</summary>
    private static async Task<(int Index, string Basis, int Count)> Overload(JadxServer server, DexIndex index, DexMethodEntry method, string className, CancellationToken ct)
    {
        var sameName = index.Methods.Values.Where(m => m.Class.Descriptor == method.Class.Descriptor && m.Ref.Name == method.Ref.Name)
            .OrderBy(m => m.Encoded.IsDirect ? 0 : 1).ThenBy(m => m.Encoded.MethodIndex).ToList();
        if (sameName.Count <= 1) return (0, "name", 1);
        var listing = await Call(server, "get_methods_of_class", new JsonObject { ["class_name"] = className, ["filter"] = method.Ref.Name, ["limit"] = 1000 }, ct).ConfigureAwait(false);
        var signatures = new List<string>();
        try
        {
            foreach (var item in JsonNode.Parse(listing)?["items"] as JsonArray ?? [])
                if ((string?)item?["name"] == method.Ref.Name) signatures.Add((string?)item?["signature"] ?? "");
        }
        catch (JsonException) { }
        string Key(DexMethodEntry m) => string.Join(",", m.Ref.Proto.Parameters.Select(p => Short(DexFile.JavaName(p))));
        var wanted = Key(method);
        var theirs = signatures.Select(ParameterKey).ToList();
        var matches = theirs.Select((k, i) => (k, i)).Where(x => x.k == wanted).Select(x => x.i).ToList();
        if (matches.Count == 1) return (matches[0], "parameter types", theirs.Count);
        // Equal short types (same simple names from different packages): the server lists methods in DEX order.
        var ours = sameName.Where(m => Key(m) == wanted).ToList();
        int rank = ours.FindIndex(m => m.Descriptor == method.Descriptor);
        if (matches.Count > rank && rank >= 0) return (matches[rank], "DEX order among equal parameter names", theirs.Count);
        return (sameName.FindIndex(m => m.Descriptor == method.Descriptor), "DEX order", sameName.Count);
    }

    /// <summary>"name(int, String): void" to "int,String", generic arguments dropped.</summary>
    private static string ParameterKey(string signature)
    {
        int open = signature.IndexOf('('), close = signature.LastIndexOf(')');
        if (open < 0 || close < open) return "";
        var inner = new StringBuilder();
        int depth = 0;
        foreach (var c in signature[(open + 1)..close])
        {
            if (c == '<') depth++;
            else if (c == '>') depth--;
            else if (depth == 0 && c != ' ') inner.Append(c);
        }
        return string.Join(",", inner.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries).Select(Short));
    }

    private static string Short(string type)
    {
        var dims = type.EndsWith("[]", StringComparison.Ordinal) ? type[type.IndexOf('[')..] : "";
        var element = dims.Length > 0 ? type[..type.IndexOf('[')] : type;
        return element[(Math.Max(element.LastIndexOf('.'), element.LastIndexOf('$')) + 1)..] + dims;
    }

    private static async Task<string> Call(JadxServer server, string tool, JsonObject arguments, CancellationToken ct)
    {
        JadxResult result;
        try { result = await server.Call(tool, arguments, CallTimeout, ct).ConfigureAwait(false); }
        catch (TimeoutException ex) { throw new ToolError(ErrorCode.Timeout, ex.Message + "; the session stays loaded.", "call again, or disassemble_dex for the smali"); }
        catch (InvalidOperationException ex) { throw new ToolError(ErrorCode.Failed, $"the JADX server refused {tool}: {ex.Message}"); }
        if (result.IsError) throw new ToolError(ErrorCode.NotFound, $"JADX: {result.Text}", "list_dex_classes and get_dex_class show what the package defines");
        return result.Text;
    }

    private async Task<JadxServer> Session(string path, CancellationToken ct)
    {
        var info = new FileInfo(path);
        var key = $"{path}|{info.Length}|{info.LastWriteTimeUtc.Ticks}";
        JadxServer? server = null;
        lock (_lock)
        {
            for (var n = _sessions.First; n != null; n = n.Next)
                if (n.Value.Key == key)
                {
                    if (n.Value.Server.HasExited || n.Value.Server.Loaded.IsFaulted) { n.Value.Server.Dispose(); _sessions.Remove(n); break; }
                    _sessions.Remove(n);
                    _sessions.AddFirst(n);
                    server = n.Value.Server;
                    break;
                }
            if (server == null)
            {
                var java = ExternalTools.Probe(ExternalTools.Java);
                var jadx = ExternalTools.Probe(ExternalTools.JavaDecompiler);
                if (!jadx.Usable) throw Unavailable($"the JADX server is not available: {jadx.Problem}", jadx.Remediation);
                if (!java.Usable) throw Unavailable($"Java is not available: {java.Problem}", java.Remediation);
                try { server = JadxServer.Start(java.Path!, jadx.Path!, path, LoadTimeout, Environment); }
                catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
                {
                    throw Unavailable($"the JADX server could not be started: {ex.Message}", jadx.Remediation);
                }
                _sessions.AddFirst((key, server));
                while (_sessions.Count > MaxSessions)
                {
                    _sessions.Last!.Value.Server.Dispose();
                    _sessions.RemoveLast();
                }
            }
        }
        try { await server.Loaded.WaitAsync(ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is JadxExitedException or InvalidOperationException or TimeoutException)
        {
            Drop(path);
            throw new ToolError(ErrorCode.ProviderUnavailable, $"JADX could not load {path}: {ex.Message}", "disassemble_dex gives the smali without JADX");
        }
        return server;
    }

    private static ToolError Unavailable(string message, string remediation) =>
        new(ErrorCode.ProviderUnavailable, message + ". disassemble_dex gives the smali without it.", remediation);

    private void Drop(string path)
    {
        lock (_lock)
            for (var n = _sessions.First; n != null; n = n.Next)
                if (n.Value.Key.StartsWith(path + "|", StringComparison.Ordinal))
                {
                    n.Value.Server.Dispose();
                    _sessions.Remove(n);
                    return;
                }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            foreach (var (_, s) in _sessions) s.Dispose();
            _sessions.Clear();
        }
    }
}
