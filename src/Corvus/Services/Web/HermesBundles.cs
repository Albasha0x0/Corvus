using System.ComponentModel;
using System.Globalization;
using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Hermes;

namespace Corvus.Services.Web;

/// <summary>analyze_js on Hermes bytecode: version (read with the nearest older opcode table when it has none, see Notes), the bundle inside a package, counts, Metro modules.</summary>
public sealed record HermesFacts(int Version, string? Bundle, int Functions, int Strings, int MetroModules, IReadOnlyList<string> Notes);

/// <summary>A function of a Hermes bundle or method of an Ark file: id, name, bytecode size (-1 for none), and the Metro module it belongs to (null for none).</summary>
public sealed record HermesFunctionRow(int Id, string Name, int Size, long? Module);

/// <summary>A Hermes bytecode bundle opened for analyze_js: the file read, its index and its source map, cached by path.</summary>
public sealed class HermesBundle
{
    private readonly Lazy<HermesIndex> _index;
    private readonly Lazy<SourceMap?> _map;
    private int[]? _virtual;

    public string Path { get; }
    public string? Inner { get; }
    public HermesFile File { get; }
    public HermesIndex Index => _index.Value;

    /// <summary>The source map beside the bundle (bundle.map or bundle.hbc.map), or null.</summary>
    public SourceMap? Map => _map.Value;

    internal HermesBundle(string path, string? inner, HermesFile file, byte[] bytes)
    {
        Path = path;
        Inner = inner;
        File = file;
        _index = new(() => new HermesIndex(file));
        _map = new(() =>
        {
            if (inner != null) return null;
            try { return SourceMap.Locate(path, bytes)?.Map; }
            catch (Exception ex) when (ex is ToolError or FormatException or IOException) { return null; }
        });
    }

    /// <summary>The virtual offset of a function, the column Hermes source maps use (line 1): the sizes of the functions before it.</summary>
    public int VirtualOffset(int function)
    {
        if (_virtual == null)
        {
            var v = new int[File.Functions.Count + 1];
            for (int i = 0; i < File.Functions.Count; i++) v[i + 1] = v[i] + File.Functions[i].Size;
            _virtual = v;
        }
        return function >= 0 && function < _virtual.Length ? _virtual[function] : 0;
    }

    /// <summary>The original position of an instruction through the source map: "file:line:column (name)", or null.</summary>
    public string? Original(int function, int offset)
    {
        if (Map is not { } map || map.Find(0, VirtualOffset(function) + offset) is not { Source: >= 0 } seg) return null;
        var source = seg.Source < map.Sources.Count ? map.Sources[seg.Source] : "?";
        return $"{source}:{seg.OriginalLine + 1}:{seg.OriginalColumn + 1}" + (seg.Name >= 0 && seg.Name < map.Names.Count ? $" ({map.Names[seg.Name]})" : "");
    }
}

/// <summary>Hermes bytecode bundles (React Native): found in a file, an APK / AAB or an .ipa, read once and kept by path, size and write time.</summary>
public static class HermesBundles
{
    private static readonly List<((string Path, long Size, DateTime Written) Key, HermesBundle Bundle)> Recent = [];

    /// <summary>Whether <paramref name="path"/> is Hermes bytecode, or a package holding a Hermes bundle.</summary>
    public static bool Applies(string path)
    {
        try
        {
            var full = InputFiles.RequireRegularFile(path, "file");
            using var s = System.IO.File.OpenRead(full);
            Span<byte> head = stackalloc byte[12];
            int n = s.ReadAtLeast(head, 12, throwOnEndOfStream: false);
            if (HermesFile.Looks(head[..n])) return true;
            if (n < 4 || !Blob.StartsWith(head, "PK\x03\x04"u8)) return false;
            s.Position = 0;
            using var zip = new ZipArchive(s, ZipArchiveMode.Read);
            return Entry(zip) != null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or ToolError) { return false; }
    }

    /// <summary>The bundle entry of a package: index.android.bundle, main.jsbundle, then any *.bundle, *.jsbundle or *.hbc with the HBC magic.</summary>
    internal static ZipArchiveEntry? Entry(ZipArchive zip)
    {
        static int Rank(string name) =>
            name.EndsWith("assets/index.android.bundle", StringComparison.Ordinal) ? 0
            : name.EndsWith(".app/main.jsbundle", StringComparison.Ordinal) ? 1
            : name.EndsWith(".bundle", StringComparison.Ordinal) || name.EndsWith(".jsbundle", StringComparison.Ordinal) || name.EndsWith(".hbc", StringComparison.Ordinal) ? 2 : 3;
        Span<byte> head = stackalloc byte[12];
        foreach (var e in zip.Entries.Where(e => Rank(e.FullName) < 3).OrderBy(e => Rank(e.FullName)).ThenBy(e => e.FullName, StringComparer.Ordinal).Take(64))
        {
            try
            {
                using var s = e.Open();
                if (s.ReadAtLeast(head, 12, throwOnEndOfStream: false) == 12 && HermesFile.Looks(head)) return e;
            }
            catch (InvalidDataException) { }
        }
        return null;
    }

    /// <summary>The bundle bytes of a package's bytes, or null; <paramref name="inner"/> names the entry.</summary>
    public static byte[]? FromPackage(byte[] package, out string? inner, long maxBytes = JsAnalysis.MaxFileBytes)
    {
        inner = null;
        if (HermesFile.Looks(package)) return package;
        if (!Blob.StartsWith(package, "PK\x03\x04"u8)) return null;
        try
        {
            using var zip = new ZipArchive(new MemoryStream(package, false), ZipArchiveMode.Read);
            if (Entry(zip) is not { } entry || entry.Length > maxBytes) return null;
            inner = entry.FullName;
            using var s = entry.Open();
            return Blob.ReadBounded(s, maxBytes);
        }
        catch (InvalidDataException) { return null; }
    }

    public static HermesBundle Open(string path, CancellationToken ct = default)
    {
        var info = new FileInfo(InputFiles.RequireRegularFile(path, "Hermes bundle"));
        if (!info.Exists) throw Targets.FileNotFound(path);
        var key = (info.FullName, info.Length, info.LastWriteTimeUtc);
        lock (Recent)
            if (Recent.FirstOrDefault(r => r.Key == key) is { Bundle: not null } hit) return hit.Bundle;
        ct.ThrowIfCancellationRequested();
        string? inner = null;
        byte[] bytes;
        using (var s = info.OpenRead())
        {
            Span<byte> head = stackalloc byte[4];
            int n = s.ReadAtLeast(head, 4, throwOnEndOfStream: false);
            s.Position = 0;
            if (n == 4 && Blob.StartsWith(head, "PK\x03\x04"u8))
            {
                using var zip = new ZipArchive(s, ZipArchiveMode.Read);
                var entry = Entry(zip) ?? throw new ToolError(ErrorCode.NotFound, $"{System.IO.Path.GetFileName(path)} holds no Hermes bytecode bundle.",
                    "a React Native app keeps it in assets/index.android.bundle (APK) or Payload/*.app/main.jsbundle (.ipa); a plain JavaScript bundle reads with analyze_js directly");
                if (entry.Length > JsAnalysis.MaxFileBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{entry.FullName} is {entry.Length:N0} bytes; bundles up to {JsAnalysis.MaxFileBytes:N0} bytes are read.");
                inner = entry.FullName;
                using var es = entry.Open();
                bytes = Blob.ReadBounded(es, JsAnalysis.MaxFileBytes) ?? throw new ToolError(ErrorCode.LimitExceeded, $"{entry.FullName} is over {JsAnalysis.MaxFileBytes:N0} bytes.");
            }
            else bytes = JsAnalysis.Read(path);
        }
        var bundle = new HermesBundle(info.FullName, inner, HermesFile.Read(bytes), bytes);
        lock (Recent)
        {
            Recent.RemoveAll(r => r.Key == key);
            Recent.Insert(0, (key, bundle));
            if (Recent.Count > 4) Recent.RemoveAt(Recent.Count - 1);
        }
        return bundle;
    }

    // ---- views ----

    public static (string Text, HermesFacts Facts) Summary(HermesBundle b)
    {
        var f = b.File;
        var notes = new List<string>(f.Issues);
        var sb = new StringBuilder();
        sb.Append(CultureInfo.InvariantCulture, $"{System.IO.Path.GetFileName(b.Path)}{(b.Inner != null ? "!" + b.Inner : "")}: Hermes bytecode version {f.Version} (React Native), {f.Bytes.Length:N0} bytes, source hash {f.SourceHash}\n");
        if (f.Opcodes == null)
        {
            sb.Append("Only the header is read: the opcode tables cover versions ").Append(HermesOpcodes.Oldest).Append('–').Append(HermesOpcodes.Newest).Append('\n');
            return (sb.ToString().TrimEnd(), new HermesFacts(f.Version, b.Inner, f.Functions.Count, f.StringCount, 0, notes));
        }
        var index = b.Index;
        sb.Append(CultureInfo.InvariantCulture, $"Functions: {f.Functions.Count:N0} ({index.Instructions:N0} instructions); strings: {f.StringCount:N0} ({f.IdentifierCount:N0} identifiers); regexps: {f.RegExpCount}; bigints: {f.BigIntCount}\n");
        sb.Append(CultureInfo.InvariantCulture, $"Global code: function #{f.GlobalCodeIndex}; Metro modules: {index.Modules.Count:N0}")
          .Append(index.EntryModules.Count > 0 ? ", run first: " + string.Join(", ", index.EntryModules.Take(8)) : "").Append('\n');
        if (f.CjsModules.Count > 0) sb.Append(CultureInfo.InvariantCulture, $"CommonJS modules: {f.CjsModules.Count}{(f.CjsModulesStaticallyResolved ? " (statically resolved)" : "")}\n");
        if (f.FunctionSources.Count > 0) sb.Append(CultureInfo.InvariantCulture, $"Function sources kept (toString): {f.FunctionSources.Count}\n");
        sb.Append(f.DebugFiles.Count > 0 ? $"Debug info: positions in {string.Join(", ", f.DebugFiles.Take(4))}\n" : "Debug info: none\n");
        if (b.Map != null) sb.Append(CultureInfo.InvariantCulture, $"Source map: {b.Map.Sources.Count} sources; positions are line 1, column = virtual bytecode offset + 1\n");
        foreach (var n in notes) sb.Append("Note: ").Append(n).Append('\n');
        foreach (var n in index.Issues.Take(5)) sb.Append("Note: ").Append(n).Append('\n');
        sb.Append("Views: functions, decompile and disassemble (query=#id or a name), modules and module (Metro), search, refs, xrefs (query=#id or a string).");
        return (sb.ToString(), new HermesFacts(f.Version, b.Inner, f.Functions.Count, f.StringCount, index.Modules.Count, [.. notes, .. index.Issues.Take(5)]));
    }

    public static (string Text, List<JsModule> Modules) Modules(HermesBundle b, string? filter)
    {
        var f = b.File;
        var rows = new List<JsModule>();
        foreach (var m in b.Index.Modules)
        {
            var id = m.Id.ToString(CultureInfo.InvariantCulture);
            if (filter != null && !id.Equals(filter, StringComparison.Ordinal) && m.Name?.Contains(filter, StringComparison.OrdinalIgnoreCase) != true) continue;
            var fn = m.Function < f.Functions.Count ? f.Functions[m.Function] : null;
            rows.Add(new JsModule(id, m.Name ?? HermesDecompiler.ClosureName(f, m.Function), "hermes_global_code", "metro", fn?.Offset ?? 0, (fn?.Offset ?? 0) + (fn?.Size ?? 0),
                [.. m.Dependencies.Select(d => d.ToString(CultureInfo.InvariantCulture))]));
        }
        var text = $"{rows.Count} Metro module(s):\n" + string.Join("\n", rows.Select(m => $"  {m.Id} {m.Name}  {m.End - m.Start:N0} bytes, {m.Requires.Count} dependencies"));
        return (text, rows);
    }

    /// <summary>A function by "#id", a bare id, or an exact name (the first function with it).</summary>
    public static int Function(HermesBundle b, string? query)
    {
        var q = query?.Trim() ?? "";
        if (q.Length == 0) throw new ToolError(ErrorCode.InvalidArgument, "this view needs query: a function (#id or a name).", "analyze_js view=functions lists them");
        var f = b.File;
        if (int.TryParse(q.TrimStart('#'), NumberStyles.None, CultureInfo.InvariantCulture, out var id) && id < f.Functions.Count) return id;
        for (int i = 0; i < f.Functions.Count; i++)
            if (f.FunctionName(i) == q || HermesDecompiler.ClosureName(f, i) == q) return i;
        throw new ToolError(ErrorCode.NotFound, $"no function '{q}' in the bundle ({f.Functions.Count:N0} functions).", "analyze_js view=functions query=<part of a name> lists them");
    }

    public static (string Text, List<HermesFunctionRow> Rows, int Total) Functions(HermesBundle b, string? filter, int max = 500)
    {
        var f = b.File;
        var sb = new StringBuilder();
        var rows = new List<HermesFunctionRow>();
        int total = 0;
        foreach (var fn in f.Functions)
        {
            var name = f.FunctionName(fn.Index);
            if (filter != null && !name.Contains(filter, StringComparison.OrdinalIgnoreCase) && $"#{fn.Index}" != filter) continue;
            total++;
            var module = b.Index.ModuleOf(fn.Index)?.Id;
            if (rows.Count < max) rows.Add(new HermesFunctionRow(fn.Index, name, fn.Size, module));
            sb.Append(CultureInfo.InvariantCulture, $"  #{fn.Index} {(name.Length > 0 ? name : "(anonymous)")}  {fn.ParamCount - 1} params, {fn.Size:N0} bytes at 0x{fn.Offset:x}")
              .Append(module is { } m ? $", module {m}" : "").Append('\n');
        }
        return ($"{total:N0} function(s){(filter != null ? $" matching '{filter}'" : "")}:\n" + sb, rows, total);
    }

    /// <summary>A function and the closures created inside it, decompiled; at most <paramref name="max"/> functions.</summary>
    public static string Decompile(HermesBundle b, int function, CancellationToken ct, int max = 200)
    {
        var sb = new StringBuilder();
        var queue = new Queue<int>([function]);
        var children = ChildrenOf(b.Index);
        int done = 0, left = 0;
        while (queue.Count > 0)
        {
            int at = queue.Dequeue();
            if (done >= max) { left++; continue; }
            if (b.Original(at, 0) is { } original) sb.Append("// source: ").Append(original).Append('\n');
            sb.Append(HermesDecompiler.Function(b.Index, at, ct)).Append('\n');
            done++;
            foreach (var c in children.GetValueOrDefault(at) ?? []) queue.Enqueue(c);
        }
        if (left > 0) sb.Append(CultureInfo.InvariantCulture, $"// {left} more nested function(s): decompile them by id (view=decompile query=#id)\n");
        return sb.ToString();
    }

    private static Dictionary<int, List<int>> ChildrenOf(HermesIndex index)
    {
        var map = new Dictionary<int, List<int>>();
        for (int i = 0; i < index.File.Functions.Count; i++)
            if (index.Parent(i) is >= 0 and var p) (map.TryGetValue(p, out var l) ? l : map[p] = []).Add(i);
        return map;
    }

    public static string Disassemble(HermesBundle b, int function)
    {
        var f = b.File;
        var fn = f.Functions[function];
        var sb = new StringBuilder();
        sb.Append(CultureInfo.InvariantCulture, $"// #{function} {HermesDecompiler.ClosureName(f, function)}: {fn.ParamCount - 1} params, {fn.FrameSize} registers, {fn.Size} bytes at 0x{fn.Offset:x}" +
                                                $"{(fn.Strict ? ", strict" : "")}\n");
        var issues = new List<string>();
        var code = HermesCode.Decode(f, fn, issues);
        var locations = f.Locations(fn).ToDictionary(l => l.Offset, l => l);
        var targets = new HashSet<int>(code.Where(i => i.Op.IsJump).Select(i => (int)i.A));
        foreach (var ins in code)
        {
            if (locations.TryGetValue(ins.Offset, out var loc)) sb.Append(CultureInfo.InvariantCulture, $"  ; {loc.File}:{loc.Line}:{loc.Column}\n");
            if (targets.Contains(ins.Offset)) sb.Append(HermesCode.Label(ins.Offset)).Append(":\n");
            sb.Append(CultureInfo.InvariantCulture, $"  {ins.Offset:x4}  {HermesCode.Text(f, ins)}\n");
        }
        var handlers = f.Handlers(fn);
        if (handlers.Count > 0)
        {
            sb.Append("Exception handlers:\n");
            foreach (var h in handlers) sb.Append(CultureInfo.InvariantCulture, $"  [{HermesCode.Label(h.Start)}, {HermesCode.Label(h.End)}) -> {HermesCode.Label(h.Target)}\n");
        }
        foreach (var i in issues) sb.Append("Note: ").Append(i).Append('\n');
        return sb.ToString();
    }

    /// <summary>Strings containing <paramref name="query"/> (case-insensitive) with their users, and functions whose name contains it.</summary>
    public static (string Text, int Total) Search(HermesBundle b, string query, CancellationToken ct, int max = JsSearch.MaxHits)
    {
        var f = b.File;
        var sb = new StringBuilder();
        int hits = 0;
        for (int i = 0; i < f.StringCount && hits < max; i++)
        {
            if ((i & 4095) == 0) ct.ThrowIfCancellationRequested();
            var s = f.String(i);
            if (s == null || !s.Contains(query, StringComparison.OrdinalIgnoreCase)) continue;
            hits++;
            var users = b.Index.StringRefs(i);
            sb.Append(CultureInfo.InvariantCulture, $"  string #{i} {HermesCode.Quote(s, 200)}{(f.IsIdentifier(i) ? " (identifier)" : "")}: {users.Length} use(s)");
            if (users.Length > 0) sb.Append(" in ").AppendJoin(", ", Users(b, users, 5));
            sb.Append('\n');
        }
        for (int i = 0; i < f.Functions.Count && hits < max; i++)
        {
            var name = f.FunctionName(i);
            if (name.Length == 0 || !name.Contains(query, StringComparison.OrdinalIgnoreCase)) continue;
            hits++;
            sb.Append(CultureInfo.InvariantCulture, $"  function #{i} {name}{(b.Index.ModuleOf(i) is { } m ? $" (module {m.Id})" : "")}\n");
        }
        return ($"{hits}{(hits >= max ? "+" : "")} hit(s) for '{query}':\n" + sb, hits);
    }

    private static IEnumerable<string> Users(HermesBundle b, ReadOnlySpan<HermesRef> refs, int max)
    {
        var list = new List<string>();
        foreach (var r in refs)
        {
            if (list.Count == max) { list.Add($"+{refs.Length - max} more"); break; }
            list.Add($"#{r.Function} {HermesDecompiler.ClosureName(b.File, r.Function)}+0x{r.Offset:x}");
        }
        return list;
    }

    /// <summary>Who uses a function (closures made from it, direct calls, the function that creates it) or a string (exact text).</summary>
    public static (string Text, int Total) Xrefs(HermesBundle b, string query)
    {
        var f = b.File;
        var q = query.Trim();
        var sb = new StringBuilder();
        if (q.StartsWith('#') && int.TryParse(q[1..], NumberStyles.None, CultureInfo.InvariantCulture, out var id) && id < f.Functions.Count)
        {
            var refs = b.Index.FunctionRefs(id);
            sb.Append(CultureInfo.InvariantCulture, $"#{id} {HermesDecompiler.ClosureName(f, id)}: {refs.Length} reference(s)\n");
            if (b.Index.ModuleOf(id) is { } module) sb.Append(CultureInfo.InvariantCulture, $"  in Metro module {module.Id}{(module.Function == id ? " (its factory)" : "")}\n");
            foreach (var r in refs)
                sb.Append(CultureInfo.InvariantCulture, $"  {(r.Kind == HermesRefKind.Call ? "called" : "closure created")} in #{r.Function} {HermesDecompiler.ClosureName(f, r.Function)} at 0x{r.Offset:x4}\n");
            return (sb.ToString(), refs.Length);
        }
        int total = 0;
        for (int i = 0; i < f.StringCount; i++)
        {
            if (f.String(i) != q) continue;
            var refs = b.Index.StringRefs(i);
            total += refs.Length;
            sb.Append(CultureInfo.InvariantCulture, $"string #{i} {HermesCode.Quote(q, 200)}: {refs.Length} use(s)\n");
            foreach (var r in refs)
            {
                var fn = f.Functions[r.Function];
                var ins = HermesCode.Decode(f, fn).FirstOrDefault(x => x.Offset == r.Offset);
                sb.Append(CultureInfo.InvariantCulture, $"  #{r.Function} {HermesDecompiler.ClosureName(f, r.Function)} at 0x{r.Offset:x4}  {(ins.Op != null ? HermesCode.Text(f, ins) : "")}\n");
                if (sb.Length > 200_000) { sb.Append("  ...\n"); break; }
            }
        }
        if (sb.Length == 0) throw new ToolError(ErrorCode.NotFound, $"no function '{q}' and no string equal to it.", "pass #<function id>, or a whole string (view=search finds strings by part)");
        return (sb.ToString(), total);
    }

    /// <summary>A Metro module's dependencies and the modules that depend on it.</summary>
    public static (string Text, JsModule Module, int RequiredBy) Refs(HermesBundle b, string query)
    {
        var modules = Modules(b, null).Modules;
        var target = modules.FirstOrDefault(m => m.Id == query.Trim() || m.Name == query.Trim())
                     ?? throw new ToolError(ErrorCode.NotFound, $"no Metro module '{query}'.", "analyze_js view=modules lists them");
        var by = modules.Where(m => m.Requires.Contains(target.Id)).Select(m => m.Id).ToList();
        var text = $"module {target.Id} ({target.Name})\nrequires ({target.Requires.Count}): {(target.Requires.Count > 0 ? string.Join(", ", target.Requires) : "none")}\n" +
                   $"required by ({by.Count}): {(by.Count > 0 ? string.Join(", ", by) : "none found")}";
        return (text, target, by.Count);
    }

    public static int ModuleFunction(HermesBundle b, string? query)
    {
        var q = query?.Trim() ?? "";
        if (q.Length == 0) throw new ToolError(ErrorCode.InvalidArgument, "view=module needs query (the module id).", "pass query=<id> (view=modules lists them)");
        var m = b.Index.Modules.FirstOrDefault(x => x.Id.ToString(CultureInfo.InvariantCulture) == q || x.Name == q)
                ?? throw new ToolError(ErrorCode.NotFound, $"no Metro module '{q}' ({b.Index.Modules.Count:N0} modules).", "analyze_js view=modules lists them");
        return m.Function;
    }
}
