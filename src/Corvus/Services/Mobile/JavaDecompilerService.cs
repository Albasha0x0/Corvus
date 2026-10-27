using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Jadx;

namespace Corvus.Services.Mobile;

/// <summary>Java source through the JADX server (one session per unchanged package, two at most); overloads matched by parameter types.</summary>
public sealed class JavaDecompilerService(DexService dex) : IDisposable
{
    public static readonly TimeSpan LoadTimeout = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan CallTimeout = TimeSpan.FromMinutes(3);
    private const int MaxSessions = 2;

    private readonly LinkedList<(string Key, JadxServer Server)> _sessions = new();
    private readonly object _lock = new();

    /// <summary>Extra environment for the server process (tests).</summary>
    internal IReadOnlyDictionary<string, string?>? Environment { get; init; }

    /// <summary>Output kept on disk across servers; null keeps nothing.</summary>
    internal JavaSourceCache? Cache { get; init; } = JavaSourceCache.Default();

    public const string Jadx = "jadx", Vineflower = "vineflower";

    public async Task<string> Decompile(string path, string symbol, bool smaliFallback, CancellationToken ct, string? mapping = null, string engine = Jadx)
    {
        symbol = symbol.Trim();
        bool vineflower = engine == Vineflower;
        // Keyed by the symbol as asked, so a warm call needs no DEX index either.
        var entry = Cache != null && JavaSourceCache.Engine(vineflower ? ExternalTools.JavaDecompiler2 : ExternalTools.JavaDecompiler) is { } build
            ? Cache.Entry(path, build, $"{symbol}|{smaliFallback}", mapping) : null;
        if (JavaSourceCache.Read(entry) is { } cached) return cached;
        var text = vineflower ? await Task.Run(() => DecompileClassFiles(path, symbol, ct), ct).ConfigureAwait(false)
            : await DecompileUncached(path, symbol, smaliFallback, ct, mapping).ConfigureAwait(false);
        JavaSourceCache.Write(entry, text);
        return text;
    }

    /// <summary>A class of a jar or .class through Vineflower, the jar as a library; a nested class or method returns its whole top-level class.</summary>
    private string DecompileClassFiles(string path, string symbol, CancellationToken ct)
    {
        if (!JvmClasses.IsClassInput(path))
            throw new ToolError(ErrorCode.InvalidArgument, "Vineflower reads class files (a jar of .class files or a .class); DEX code goes to engine=jadx.");
        var full = InputFiles.RequireRegularFile(path, "class file or jar");
        var (owner, member) = JvmClasses.Split(symbol);
        var cls = JvmClasses.Read(full, owner, ct);
        owner = cls.Name;
        var top = owner;
        if (owner.IndexOf('$') is var dollar and > 0)
            try { top = JvmClasses.Read(full, owner[..dollar], ct).Name; }
            catch (ToolError e) when (e.Code == ErrorCode.NotFound) { }
        var java = ExternalTools.Probe(ExternalTools.Java);
        var tool = ExternalTools.Probe(ExternalTools.JavaDecompiler2);
        if (!tool.Usable) throw NotConfigured($"Vineflower is not available: {tool.Problem}", tool.Remediation);
        if (!java.Usable) throw NotConfigured($"Java is not available: {java.Problem}", java.Remediation);
        var work = Path.Combine(Path.GetTempPath(), "corvus-vineflower-" + Guid.NewGuid().ToString("N"));
        try
        {
            string input = Path.Combine(work, "in"), output = Path.Combine(work, "out");
            Native.Providers.PrivateFolder.Create(work);
            Directory.CreateDirectory(output);
            foreach (var (name, bytes) in JvmClasses.WithNested(full, top, ct))
            {
                var file = Path.Combine(input, name.Replace('/', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(file)!);
                File.WriteAllBytes(file, bytes);
            }
            bool single = JvmClasses.IsClassFile(full);
            var args = (single ? [] : ExternalTools.Arguments(ExternalTools.JavaDecompiler2, "library", ("jar", full)))
                .Concat(ExternalTools.Arguments(ExternalTools.JavaDecompiler2, "decompile", ("input", input), ("output", output))).ToList();
            var (exe, command) = ExternalTools.Command(ExternalTools.JavaDecompiler2, tool.Path!, args)
                ?? throw NotConfigured("Java is not available", java.Remediation);
            var run = ExternalTools.Run(exe, command, CallTimeout, 16 << 20, ct, Environment);
            if (run.StartError != null) throw Unavailable($"Vineflower could not be started: {run.StartError}", tool.Remediation);
            if (run.TimedOut) throw new ToolError(ErrorCode.Timeout, $"Vineflower took longer than {CallTimeout.TotalMinutes:0} minutes on {top}.", "engine=jadx, or disassemble_dex for the bytecode");
            var source = Path.Combine(output, top.Replace('/', Path.DirectorySeparatorChar) + ".java");
            if (!File.Exists(source))
                throw new ToolError(ErrorCode.Failed, $"Vineflower wrote no source for {top.Replace('/', '.')} (exit {run.ExitCode}): {run.Stderr.Trim()[..Math.Min(run.Stderr.Trim().Length, 2000)]}",
                    "engine=jadx, or disassemble_dex for the bytecode");
            var head = $"// {top.Replace('/', '.')} (Vineflower)\n";
            if (top != owner) head += $"// {owner.Replace('/', '.')} is written inside {top.Replace('/', '.')}\n";
            if (member != null) head += $"// {owner.Replace('/', '.')}::{member}: Vineflower writes whole classes; the class follows\n";
            return head + Lf(File.ReadAllText(source));
        }
        finally
        {
            try { Directory.Delete(work, recursive: true); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
    }

    private async Task<string> DecompileUncached(string path, string symbol, bool smaliFallback, CancellationToken ct, string? mapping)
    {
        DexIndex index;
        try { index = dex.Index(path, ct); }
        catch (ToolError e) when (e.Code == ErrorCode.NotFound && ClassFileJar(path) is { } jar) { return await DecompileJar(jar, symbol, smaliFallback, ct).ConfigureAwait(false); }
        var names = dex.Names(index, mapping, ct);
        symbol = DexService.Resolve(index, names, symbol);
        var source = await DecompileDex(index, symbol, smaliFallback, ct).ConfigureAwait(false);
        return names == null || names.IsEmpty ? source : WithNames(source, names, index, symbol, ct);
    }

    /// <summary>The source with original names applied, since the JADX server takes no mapping, under a line counting them.</summary>
    private static string WithNames(string source, DexNames names, DexIndex index, string symbol, CancellationToken ct)
    {
        bool member = symbol.Contains("->", StringComparison.Ordinal) || symbol.Contains("::", StringComparison.Ordinal) || symbol.Contains('(', StringComparison.Ordinal);
        var descriptor = member ? index.Methods.GetValueOrDefault(index.ResolveMethod(symbol, ct))?.Class.Descriptor : index.FindClass(symbol)?.Class.Descriptor;
        if (descriptor == null) return source;
        var r = JavaSourceNames.Apply(source, names, index, descriptor, ct);
        var basis = names.Mapping is { } m ? Path.GetFileName(m) : "Kotlin metadata";
        var head = $"// original names from {basis}: {r.Renamed} identifier(s) replaced";
        if (r.Undecided.Count > 0) head += $"; kept as JADX wrote them (ambiguous): {string.Join(", ", r.Undecided.Take(20))}";
        return head + "\n" + r.Text;
    }

    private async Task<string> DecompileDex(DexIndex index, string symbol, bool smaliFallback, CancellationToken ct)
    {
        bool member = symbol.Contains("->", StringComparison.Ordinal) || symbol.Contains("::", StringComparison.Ordinal) || symbol.Contains('(', StringComparison.Ordinal);
        DexClassEntry? cls = member ? null : index.FindClass(symbol);
        DexMethodEntry? method = null;
        if (cls == null)
        {
            var id = index.ResolveMethod(symbol, ct);
            method = index.Methods.GetValueOrDefault(id) ?? throw new ToolError(ErrorCode.NotFound,
                $"{id} is called by the package but not defined in it (a framework or library method): nothing to decompile.");
        }
        var server = await Session(index.Path, ct).ConfigureAwait(false);
        try
        {
            return method == null ? await ClassSource(server, index, cls!, smaliFallback, 0, ct).ConfigureAwait(false)
                : await MethodSource(server, index, method, smaliFallback, 0, ct).ConfigureAwait(false);
        }
        catch (JadxExitedException ex)
        {
            Drop(index.Path);
            throw new ToolError(ErrorCode.ProviderUnavailable, ex.Message, "call again to restart the JADX server; disassemble_dex gives the smali without it");
        }
    }

    private const int MaxHostDepth = 4;

    /// <summary>A class's source, read from its outer class or creating method when JADX writes it there.</summary>
    private async Task<string> ClassSource(JadxServer server, DexIndex index, DexClassEntry cls, bool smaliFallback, int depth, CancellationToken ct)
    {
        var descriptor = cls.Class.Descriptor;
        var nesting = Nesting(index, cls, ct);
        string? source = null;
        try { source = await Call(server, "get_class_source", new JsonObject { ["class_name"] = DexFile.JavaName(descriptor), ["smali_fallback"] = smaliFallback }, ct).ConfigureAwait(false); }
        catch (ToolError e) when (e.Code == ErrorCode.NotFound && nesting.Kind != null && depth < MaxHostDepth) { }
        if (source != null && (source.Trim().Length > 0 || nesting.Kind == null || depth >= MaxHostDepth)) return $"// {descriptor} (JADX)\n{Lf(source)}";
        if (nesting.HostMethod is { } host && index.Methods.TryGetValue(host, out var hostMethod))
            return $"// {descriptor} is {nesting.Kind} inside {host}; JADX writes it there:\n"
                   + await MethodSource(server, index, hostMethod, smaliFallback, depth + 1, ct).ConfigureAwait(false);
        var (top, path) = TopLevel(index, cls, ct);
        var outer = top == cls ? source ?? "" : await ClassSource(server, index, top, smaliFallback, depth + 1, ct).ConfigureAwait(false);
        if (top != cls && path is { Count: > 0 } && MemberBlock(outer, path) is { } block)
            return $"// {descriptor} (JADX, from the source of {top.Class.Descriptor})\n{block}";
        return $"// {descriptor} is written inside {top.Class.Descriptor}; its whole source follows:\n{outer}";
    }

    private async Task<string> MethodSource(JadxServer server, DexIndex index, DexMethodEntry method, bool smaliFallback, int depth, CancellationToken ct)
    {
        var className = DexFile.JavaName(method.Class.Descriptor);
        string body;
        (int Index, string Basis, int Count) overload;
        try
        {
            overload = await Overload(server, index, method, className, ct).ConfigureAwait(false);
            body = await Call(server, "get_method_body", new JsonObject
            {
                ["class_name"] = className, ["method_name"] = method.Ref.Name, ["overload_index"] = overload.Index, ["smali_fallback"] = smaliFallback,
            }, ct).ConfigureAwait(false);
        }
        catch (ToolError e) when (e.Code == ErrorCode.NotFound && depth < MaxHostDepth && Nesting(index, new DexClassEntry(method.File, method.Class), ct).Kind != null)
        {
            // JADX does not resolve an anonymous or lambda class by name: its methods are read where it is written.
            return $"// {method.Descriptor}: in a class JADX writes elsewhere\n"
                   + await ClassSource(server, index, new DexClassEntry(method.File, method.Class), smaliFallback, depth + 1, ct).ConfigureAwait(false);
        }
        var (mode, text) = Envelope(body);
        var note = overload.Count > 1 ? $", overload {overload.Index + 1} of {overload.Count} matched by {overload.Basis}" : "";
        return $"// {method.Descriptor} (JADX, {mode}{note})\n{Lf(text)}";
    }

    private static (string Mode, string Text) Envelope(string body)
    {
        try
        {
            if (JsonNode.Parse(body) is JsonObject envelope) return ((string?)envelope["mode"] ?? "java", (string?)envelope["body"] ?? body);
        }
        catch (JsonException) { }
        return ("java", body);
    }

    private static string Lf(string text) => text.Replace("\r\n", "\n");

    /// <summary>How JADX places a class: Kind null when written on its own, else the nesting kind with its host method or outer class.</summary>
    internal static (string? Kind, string? HostMethod, string? OuterClass, string? InnerName) Nesting(DexIndex index, DexClassEntry cls, CancellationToken ct)
    {
        var system = cls.File.Annotations(cls.Class).Class;
        DexAnnotation? Find(string type) => system.FirstOrDefault(a => a.Type == type);
        string? Value(DexAnnotation? a, string name) => a?.Elements.FirstOrDefault(e => e.Name == name).Value?.Value?.ToString();
        var inner = Find("Ldalvik/annotation/InnerClass;");
        var innerName = Value(inner, "name");
        if (Value(Find("Ldalvik/annotation/EnclosingMethod;"), "value") is { } method)
            return (inner != null && innerName == null ? "an anonymous class" : "a local class", method, null, innerName);
        if (Value(Find("Ldalvik/annotation/EnclosingClass;"), "value") is { } outer)
            return inner != null && innerName == null ? ("an anonymous class", null, outer, null) : ("a member class", null, outer, innerName);
        if ((cls.Class.Access & 0x1000) != 0 && Creator(index, cls.Class.Descriptor, ct) is { } creator) return ("a lambda class", creator, null, null);
        return (null, null, null, null);
    }

    /// <summary>The first method that instantiates <paramref name="descriptor"/> (new-instance), the home of a synthetic lambda class.</summary>
    private static string? Creator(DexIndex index, string descriptor, CancellationToken ct)
    {
        index.EnsureCode(ct);
        if (index.FindKey(descriptor) is not { } key) return null;
        foreach (var r in index.Refs)
            if (r.Target == key && r.Kind == DexRefKind.Type && r.Opcode == 0x22) return index.KeyText(r.From);
        return null;
    }

    /// <summary>The top-level class holding a nested class and the member path to it; path null when an anonymous or local class is on the way.</summary>
    private static (DexClassEntry Top, List<string>? Path) TopLevel(DexIndex index, DexClassEntry cls, CancellationToken ct)
    {
        var path = new List<string>();
        bool named = true;
        var current = cls;
        for (int i = 0; i < 16; i++)
        {
            var n = Nesting(index, current, ct);
            var outerName = n.OuterClass ?? (n.HostMethod?.IndexOf("->", StringComparison.Ordinal) is > 0 and var arrow ? n.HostMethod[..arrow] : null);
            if (n.Kind == null || outerName == null || !index.Classes.TryGetValue(outerName, out var outer) || outer == current) break;
            var desc = current.Class.Descriptor;
            if (n.Kind == "a member class") path.Insert(0, n.InnerName ?? desc[(desc.LastIndexOf('$') + 1)..].TrimEnd(';'));
            else named = false;
            current = outer;
        }
        return (current, named ? path : null);
    }

    /// <summary>The block of member class <paramref name="path"/> (outermost first) in Java source, dedented; null when not found.</summary>
    internal static string? MemberBlock(string source, IReadOnlyList<string> path)
    {
        int from = 0, to = source.Length;
        Match? declaration = null;
        foreach (var name in path)
        {
            declaration = new Regex(@"(?m)^[ \t]*(?:(?:public|protected|private|static|final|abstract|strictfp|sealed|non-sealed|/\*[^*\n]*\*/)\s+)*(?:class|interface|enum|@interface|record)\s+"
                                    + Regex.Escape(name) + @"\b", RegexOptions.NonBacktracking).Match(source, from, to - from);
            if (!declaration.Success) return null;
            int open = source.IndexOf('{', declaration.Index + declaration.Length);
            if (open < 0 || open >= to || CloseOf(source, open) is not { } close) return null;
            (from, to) = (declaration.Index, close + 1);
        }
        if (declaration == null) return null;
        // Comments and annotations right above the declaration belong to it.
        int start = from;
        while (start > 0)
        {
            int prev = source.LastIndexOf('\n', start - 2) + 1;
            var line = source[prev..(start - 1)].Trim();
            if (!(line.StartsWith("/*", StringComparison.Ordinal) || line.StartsWith("//", StringComparison.Ordinal) || line.StartsWith('@'))) break;
            start = prev;
        }
        int indent = source.AsSpan(from).IndexOfAnyExcept(' ', '\t');
        var lines = source[start..to].Split('\n');
        return string.Join('\n', lines.Select(l => l.Length >= indent && l[..indent].Trim().Length == 0 ? l[indent..] : l.TrimStart()));
    }

    /// <summary>The index of the brace closing the one at <paramref name="open"/>, skipping strings, characters and comments.</summary>
    private static int? CloseOf(string s, int open)
    {
        int depth = 0;
        for (int i = open; i < s.Length; i++)
        {
            char c = s[i];
            if (c == '"' || c == '\'')
            {
                for (i++; i < s.Length && s[i] != c && s[i] != '\n'; i++) if (s[i] == '\\') i++;
            }
            else if (c == '/' && i + 1 < s.Length && s[i + 1] == '/') i = s.IndexOf('\n', i) is var e and >= 0 ? e : s.Length;
            else if (c == '/' && i + 1 < s.Length && s[i + 1] == '*') i = s.IndexOf("*/", i + 2, StringComparison.Ordinal) is var e and >= 0 ? e + 1 : s.Length;
            else if (c == '{') depth++;
            else if (c == '}' && --depth == 0) return i;
        }
        return null;
    }

    /// <summary>The full path of a jar or zip of .class files without classes*.dex (JADX reads those directly); else null.</summary>
    private static string? ClassFileJar(string path)
    {
        try
        {
            var full = InputFiles.RequireRegularFile(path, "jar");
            using var zip = System.IO.Compression.ZipFile.OpenRead(full);
            return zip.Entries.Any(e => e.FullName.EndsWith(".class", StringComparison.Ordinal)) ? full : null;
        }
        catch (Exception e) when (e is IOException or InvalidDataException or UnauthorizedAccessException or ToolError) { return null; }
    }

    /// <summary>A class or method of a jar of .class files: names go to JADX as given (no DEX index to resolve them).</summary>
    private async Task<string> DecompileJar(string jar, string symbol, bool smaliFallback, CancellationToken ct)
    {
        var arrow = symbol.IndexOf("->", StringComparison.Ordinal);
        var colons = symbol.IndexOf("::", StringComparison.Ordinal);
        int sep = arrow >= 0 ? arrow : colons;
        string owner = sep >= 0 ? symbol[..sep] : symbol, member = sep >= 0 ? symbol[(sep + 2)..] : "";
        if (sep < 0 && symbol.IndexOf('(') is var paren and > 0)
        {
            int dot = symbol.LastIndexOf('.', paren);
            (owner, member) = dot > 0 ? (symbol[..dot], symbol[(dot + 1)..]) : (symbol, "");
        }
        var className = owner.StartsWith('L') && owner.EndsWith(';') ? DexFile.JavaName(owner) : owner.Replace('/', '.');
        var server = await Session(jar, ct).ConfigureAwait(false);
        try
        {
            if (member.Length == 0)
                return $"// {className} (JADX)\n{Lf(await Call(server, "get_class_source", new JsonObject { ["class_name"] = className, ["smali_fallback"] = smaliFallback }, ct).ConfigureAwait(false))}";
            int open = member.IndexOf('(');
            var name = open >= 0 ? member[..open] : member;
            int overload = 0, count = 1;
            if (open >= 0)
            {
                var inner = member[(open + 1)..(member.IndexOf(')') is var close and > 0 ? close : member.Length)].Trim();
                bool descriptors = !inner.Contains(',') && !inner.Contains(' ') && (inner.Contains(';') || inner.All(ch => "ZBSCIJFD[".Contains(ch)));
                var wanted = string.Join(",", descriptors ? DexIndex.SplitParameters(inner).Select(p => Short(DexFile.JavaName(p)))
                    : inner.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Select(Short));
                var listing = await Call(server, "get_methods_of_class", new JsonObject { ["class_name"] = className, ["filter"] = name, ["limit"] = 1000 }, ct).ConfigureAwait(false);
                var signatures = new List<string>();
                try
                {
                    foreach (var item in JsonNode.Parse(listing)?["items"] as JsonArray ?? [])
                        if ((string?)item?["name"] == name) signatures.Add((string?)item?["signature"] ?? "");
                }
                catch (JsonException) { }
                count = signatures.Count;
                overload = signatures.Select(ParameterKey).ToList().IndexOf(wanted);
                if (overload < 0) throw new ToolError(ErrorCode.NotFound, $"{className} has no method {name} with parameters ({wanted}).", "decompile the class to see its methods");
            }
            var (mode, text) = Envelope(await Call(server, "get_method_body", new JsonObject
            {
                ["class_name"] = className, ["method_name"] = name, ["overload_index"] = overload, ["smali_fallback"] = smaliFallback,
            }, ct).ConfigureAwait(false));
            return $"// {className}::{member} (JADX, {mode}{(count > 1 ? $", overload {overload + 1} of {count}" : "")})\n{Lf(text)}";
        }
        catch (JadxExitedException ex)
        {
            Drop(jar);
            throw new ToolError(ErrorCode.ProviderUnavailable, ex.Message, "call again to restart the JADX server");
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
        // The server's hints name its own argument; decompile_java's is the inverse, javaOnly.
        var text = result.Text.Replace("smali_fallback=false", "javaOnly=true", StringComparison.Ordinal).Replace("smali_fallback=true", "javaOnly=false", StringComparison.Ordinal);
        if (result.IsError) throw new ToolError(ErrorCode.NotFound, $"JADX: {text}", "list_dex_classes and get_dex_class show what the package defines");
        return text;
    }

    private async Task<JadxServer> Session(string path, CancellationToken ct)
    {
        var info = new FileInfo(path);
        var key = $"{path}|{info.Length}|{info.LastWriteTimeUtc.Ticks}";
        JadxServer? Find()
        {
            for (var n = _sessions.First; n != null; n = n.Next)
                if (n.Value.Key == key)
                {
                    if (n.Value.Server.HasExited || n.Value.Server.Loaded.IsFaulted) { n.Value.Server.Dispose(); _sessions.Remove(n); return null; }
                    _sessions.Remove(n);
                    _sessions.AddFirst(n);
                    return n.Value.Server;
                }
            return null;
        }
        JadxServer? server;
        lock (_lock) server = Find();
        if (server == null)
        {
            // Probing runs java -version: outside the lock, so other calls wait for it only through their own probe.
            var java = ExternalTools.Probe(ExternalTools.Java);
            var jadx = ExternalTools.Probe(ExternalTools.JavaDecompiler);
            ct.ThrowIfCancellationRequested();
            if (!jadx.Usable) throw NotConfigured($"the JADX server is not available: {jadx.Problem}", jadx.Remediation);
            if (!java.Usable) throw NotConfigured($"Java is not available: {java.Problem}", java.Remediation);
            lock (_lock)
                if ((server = Find()) == null)
                {
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

    /// <summary>A missing tool or setting: calling again cannot help until the configuration changes.</summary>
    internal static ToolError NotConfigured(string message, string remediation) =>
        new(ErrorCode.ProviderUnavailable, message + ". disassemble_dex gives the smali without it.", remediation)
        { Retryable = false, Details = new { reason = "not_configured" } };

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
