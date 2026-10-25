using System.Globalization;
using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Ark;

namespace Corvus.Services.Web;

/// <summary>An Ark bytecode file opened for analyze_js: the file read and its methods in class order, kept by path.</summary>
internal sealed class ArkBundle
{
    public string Path { get; }
    public string? Inner { get; }
    public ArkFile File { get; }
    public IReadOnlyList<ArkMethod> Methods { get; }

    private List<(char Kind, int Target, int Method, int Offset)>? _references;

    internal ArkBundle(string path, string? inner, ArkFile file)
    {
        Path = path;
        Inner = inner;
        File = file;
        Methods = [.. file.Classes.SelectMany(c => c.Methods)];
    }

    /// <summary>Every string and method an instruction names: kind ('s' or 'm'), the target's offset, the user's method id and instruction offset.</summary>
    public IReadOnlyList<(char Kind, int Target, int Method, int Offset)> References(CancellationToken ct)
    {
        if (_references != null) return _references;
        var list = new List<(char, int, int, int)>();
        for (int i = 0; i < Methods.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            if (Methods[i].Code is not { } at) continue;
            byte[] code;
            try { code = File.Code(at).Instructions; }
            catch (InvalidDataException) { continue; }
            foreach (var ins in ArkOpcodes.Decode(code, out _))
                for (int k = 0; k < ins.Operation.Operands.Length; k++)
                    if (ins.Operation.Operands[k].Kind is 's' or 'm')
                        try { list.Add((ins.Operation.Operands[k].Kind, File.MethodRegionId(Methods[i].Offset, (int)ins.Values[k]), i, ins.Offset)); }
                        catch (InvalidDataException) { }
        }
        return _references = list;
    }
}

/// <summary>Ark bytecode files (.abc): read alone or from a HarmonyOS module or bundle, once, and kept by path, size and write time.</summary>
internal static class ArkBundles
{
    private static readonly List<((string Path, long Size, DateTime Written) Key, ArkBundle Bundle)> Recent = [];

    /// <summary>Whether <paramref name="path"/> is Ark bytecode, or a HarmonyOS package holding some.</summary>
    public static bool Applies(string path)
    {
        try
        {
            var full = InputFiles.RequireRegularFile(path, "file");
            using var s = System.IO.File.OpenRead(full);
            Span<byte> head = stackalloc byte[60];
            int n = s.ReadAtLeast(head, 60, throwOnEndOfStream: false);
            if (ArkFile.Looks(head[..n])) return true;
            if (n < 4 || !Blob.StartsWith(head, "PK\x03\x04"u8)) return false;
            s.Position = 0;
            using var zip = new ZipArchive(s, ZipArchiveMode.Read);
            return Entry(zip) != null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or ToolError) { return false; }
    }

    /// <summary>The bytecode entry of a package: a stage module's ets/modules.abc, then the first other .abc (FA modules, nested modules not read).</summary>
    internal static ZipArchiveEntry? Entry(ZipArchive zip)
    {
        if (!HarmonyPackage.IsPackage(zip.Entries.Select(e => e.FullName))) return null;
        return zip.GetEntry("ets/modules.abc")
            ?? zip.Entries.Where(e => e.FullName.EndsWith(".abc", StringComparison.Ordinal)).OrderBy(e => e.FullName, StringComparer.Ordinal).FirstOrDefault();
    }

    public static ArkBundle Open(string path, CancellationToken ct = default)
    {
        var info = new FileInfo(InputFiles.RequireRegularFile(path, "Ark bytecode"));
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
                var entry = Entry(zip) ?? throw new ToolError(ErrorCode.NotFound, $"{System.IO.Path.GetFileName(path)} holds no Ark bytecode.",
                    "a HarmonyOS module keeps it in ets/modules.abc; summarize_file view=harmony lists an application bundle's modules");
                if (entry.Length > JsAnalysis.MaxFileBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{entry.FullName} is {entry.Length:N0} bytes; files up to {JsAnalysis.MaxFileBytes:N0} bytes are read.");
                inner = entry.FullName;
                using var es = entry.Open();
                bytes = Blob.ReadBounded(es, JsAnalysis.MaxFileBytes) ?? throw new ToolError(ErrorCode.LimitExceeded, $"{entry.FullName} is over {JsAnalysis.MaxFileBytes:N0} bytes.");
            }
            else bytes = JsAnalysis.Read(path);
        }
        ArkFile file;
        try { file = new ArkFile(bytes); }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{System.IO.Path.GetFileName(path)}{(inner != null ? "!" + inner : "")}: not readable Ark bytecode: {ex.Message}."); }
        var bundle = new ArkBundle(info.FullName, inner, file);
        lock (Recent)
        {
            Recent.RemoveAll(r => r.Key == key);
            Recent.Insert(0, (key, bundle));
            if (Recent.Count > 4) Recent.RemoveAt(Recent.Count - 1);
        }
        return bundle;
    }

    public static string Summary(ArkBundle b)
    {
        var f = b.File;
        var sb = new StringBuilder();
        int withCode = b.Methods.Count(m => m.Code != null);
        sb.Append(CultureInfo.InvariantCulture, $"{System.IO.Path.GetFileName(b.Path)}{(b.Inner != null ? "!" + b.Inner : "")}: Ark bytecode version {f.Version}, ")
          .Append(CultureInfo.InvariantCulture, $"{f.Classes.Count:N0} classes, {b.Methods.Count:N0} methods ({withCode:N0} with code)\n");
        var sources = f.Classes.Select(c => c.SourceFile).OfType<string>().Distinct(StringComparer.Ordinal).ToList();
        if (sources.Count > 0) sb.Append(CultureInfo.InvariantCulture, $"Source files: {sources.Count:N0} ({string.Join(", ", sources.Take(6))}{(sources.Count > 6 ? ", ..." : "")})\n");
        foreach (var n in f.Issues) sb.Append("Note: ").Append(n).Append('\n');
        sb.Append("Views: functions (query filters names), disassemble (query=#id or a name), search (strings), xrefs (query=#id or a whole string).");
        return sb.ToString();
    }

    /// <summary>
    /// A method by "#id", a bare id, its full name (class.name), its name alone or its source name (after the last '#')
    /// when one method has it.
    /// </summary>
    public static int Function(ArkBundle b, string? query)
    {
        var q = query?.Trim() ?? "";
        if (q.Length == 0) throw new ToolError(ErrorCode.InvalidArgument, "this view needs query: a method (#id or a name).", "analyze_js view=functions lists them");
        if (int.TryParse(q.TrimStart('#'), NumberStyles.None, CultureInfo.InvariantCulture, out var id) && id < b.Methods.Count) return id;
        for (int i = 0; i < b.Methods.Count; i++)
            if (b.Methods[i].FullName == q) return i;
        var named = Enumerable.Range(0, b.Methods.Count).Where(i => b.Methods[i].Name == q).Take(2).ToList();
        if (named.Count == 0) named = [.. Enumerable.Range(0, b.Methods.Count).Where(i => SourceName(b.Methods[i].Name) == q).Take(2)];
        if (named.Count == 1) return named[0];
        throw new ToolError(ErrorCode.NotFound, named.Count > 1 ? $"several methods are named '{q}'." : $"no method '{q}' ({b.Methods.Count:N0} methods).",
            "analyze_js view=functions query=<part of a name> lists them with their ids");
    }

    // The compiler's names carry scope markers before the last '#' ("#~@0>#add"); the source name follows it.
    private static string SourceName(string name) => name[(name.LastIndexOf('#') + 1)..];

    public static (string Text, List<HermesFunctionRow> Rows, int Total) Functions(ArkBundle b, string? filter, int max = 500)
    {
        var sb = new StringBuilder();
        var rows = new List<HermesFunctionRow>();
        int total = 0;
        for (int i = 0; i < b.Methods.Count; i++)
        {
            var m = b.Methods[i];
            if (filter != null && !m.FullName.Contains(filter, StringComparison.OrdinalIgnoreCase) && $"#{i}" != filter) continue;
            total++;
            ArkCode? code = null;
            if (m.Code is { } at)
                try { code = b.File.Code(at); }
                catch (InvalidDataException) { }
            if (rows.Count < max) rows.Add(new HermesFunctionRow(i, m.FullName, code?.Instructions.Length ?? -1, null));
            sb.Append(CultureInfo.InvariantCulture, $"  #{i} {m.FullName}  ")
              .Append(code != null ? $"{code.Arguments} args, {code.Registers} registers, {code.Instructions.Length:N0} bytes" : m.Code != null ? "code unreadable" : "no code")
              .Append('\n');
        }
        return ($"{total:N0} method(s){(filter != null ? $" matching '{filter}'" : "")}:\n" + sb, rows, total);
    }

    public static string Disassemble(ArkBundle b, int function)
    {
        var m = b.Methods[function];
        var sb = new StringBuilder();
        if (m.Code is not { } at) return $"// #{function} {m.FullName}: no code (abstract or native).\n";
        var code = b.File.Code(at);
        sb.Append(CultureInfo.InvariantCulture, $"// #{function} {m.FullName}: {code.Arguments} args, {code.Registers} registers, {code.Instructions.Length:N0} bytes\n");
        var list = ArkOpcodes.Decode(code.Instructions, out int stopped);
        var targets = new HashSet<int>(list.Where(i => i.Operation.IsJump).Select(i => i.Offset + (int)i.Values[0]));
        foreach (var t in code.Tries) { targets.Add(t.Start); foreach (var c in t.Catches) targets.Add(c.Handler); }
        foreach (var ins in list)
        {
            if (targets.Contains(ins.Offset)) sb.Append(Label(ins.Offset)).Append(":\n");
            sb.Append(CultureInfo.InvariantCulture, $"  {ins.Offset:x4}  {Text(b.File, m, ins, code.Arguments, code.Registers)}\n");
        }
        if (stopped >= 0) sb.Append(CultureInfo.InvariantCulture, $"Note: decoding stopped at 0x{stopped:x}: an opcode outside the instruction set or an instruction cut short.\n");
        foreach (var t in code.Tries)
            foreach (var (type, handler) in t.Catches)
                sb.Append(CultureInfo.InvariantCulture, $"  try [{Label(t.Start)}, {Label(t.Start + t.Length)}) catch {type ?? "all"} -> {Label(handler)}\n");
        return sb.ToString();
    }

    /// <summary>Strings code names that contain <paramref name="query"/> (case-insensitive), with their users, and methods whose name contains it.</summary>
    public static (string Text, int Total) Search(ArkBundle b, string query, CancellationToken ct, int max = JsSearch.MaxHits)
    {
        var sb = new StringBuilder();
        int hits = 0;
        foreach (var g in b.References(ct).Where(r => r.Kind == 's').GroupBy(r => r.Target).OrderBy(g => g.Key))
        {
            string text;
            try { text = b.File.String(g.Key); }
            catch (InvalidDataException) { continue; }
            if (!text.Contains(query, StringComparison.OrdinalIgnoreCase)) continue;
            if (++hits > max) break;
            sb.Append(CultureInfo.InvariantCulture, $"  {Quote(text)}  used by ")
              .Append(string.Join(", ", g.Take(8).Select(r => $"#{r.Method} {b.Methods[r.Method].FullName}+0x{r.Offset:x}")))
              .Append(g.Count() > 8 ? $" and {g.Count() - 8} more" : "").Append('\n');
        }
        for (int i = 0; i < b.Methods.Count && hits <= max; i++)
            if (b.Methods[i].FullName.Contains(query, StringComparison.OrdinalIgnoreCase))
            {
                hits++;
                sb.Append(CultureInfo.InvariantCulture, $"  method #{i} {b.Methods[i].FullName}\n");
            }
        return ($"{Math.Min(hits, max):N0} match(es) for '{query}'{(hits > max ? $" (first {max})" : "")}:\n" + sb, Math.Min(hits, max));
    }

    /// <summary>The instructions that name a method (#id) or a string (its whole text).</summary>
    public static (string Text, int Total) Xrefs(ArkBundle b, string query, CancellationToken ct)
    {
        IEnumerable<(char Kind, int Target, int Method, int Offset)> refs;
        string what;
        if (query.StartsWith('#'))
        {
            int id = Function(b, query);
            what = $"#{id} {b.Methods[id].FullName}";
            refs = b.References(ct).Where(r => r.Kind == 'm' && r.Target == b.Methods[id].Offset);
        }
        else
        {
            what = Quote(query);
            refs = b.References(ct).Where(r => r.Kind == 's' && Same(b.File, r.Target, query));
        }
        var list = refs.ToList();
        var sb = new StringBuilder($"{list.Count:N0} reference(s) to {what}:\n");
        foreach (var r in list.Take(500)) sb.Append(CultureInfo.InvariantCulture, $"  #{r.Method} {b.Methods[r.Method].FullName}+0x{r.Offset:x}\n");
        if (list.Count > 500) sb.Append(CultureInfo.InvariantCulture, $"  ... {list.Count - 500:N0} more\n");
        return (sb.ToString(), list.Count);
    }

    private static bool Same(ArkFile file, int offset, string text)
    {
        try { return file.String(offset) == text; }
        catch (InvalidDataException) { return false; }
    }

    internal static string Label(int offset) => $"L{offset:x4}";

    /// <summary>
    /// One instruction as text: mnemonic and operands; registers past the locals are the arguments (a0, a1, ...),
    /// strings quoted, methods named, literal arrays by offset, jumps by label.
    /// </summary>
    internal static string Text(ArkFile file, ArkMethod method, ArkInstruction ins, int arguments, int registers)
    {
        var parts = new List<string>();
        var op = ins.Operation;
        for (int i = 0; i < op.Operands.Length; i++)
        {
            long v = ins.Values[i];
            var t = op.Operands[i];
            parts.Add(t.Kind switch
            {
                'v' => v >= registers ? $"a{v - registers}" : $"v{v}",
                'j' => Label(ins.Offset + (int)v),
                'f' => (ins.Double ?? 0).ToString("0.000000e+00", CultureInfo.InvariantCulture),
                's' => Resolve(() => Quote(file.String(file.MethodRegionId(method.Offset, (int)v)))),
                'm' => Resolve(() => Signature(file, file.MethodRegionId(method.Offset, (int)v))),
                'l' => Resolve(() => LiteralArray(file, file.MethodRegionId(method.Offset, (int)v))),
                // Signed immediates print as their two's complement in the operand's width.
                _ => $"0x{(t.Bits >= 64 ? v : v & ((1L << t.Bits) - 1)):x}",
            });
        }
        return parts.Count == 0 ? op.Name : $"{op.Name} {string.Join(", ", parts)}";
    }

    // A method operand: its full name and one "any" per argument, as the dynamic signature has no other types.
    private static string Signature(ArkFile file, int offset) =>
        file.ArgumentCount(offset) is { } n ? $"{file.MethodName(offset)}:({string.Join(',', Enumerable.Repeat("any", n))})" : file.MethodName(offset);

    /// <summary>A literal array inline: its tag and value pairs, strings quoted.</summary>
    internal static string LiteralArray(ArkFile file, int offset)
    {
        var literals = file.Literals(offset);
        var sb = new StringBuilder().Append(CultureInfo.InvariantCulture, $"{{ {literals.Count} [ ");
        foreach (var l in literals)
        {
            string value = l.Value switch
            {
                null => "0",
                string s when l.Tag == 0x05 => Quote(s),
                string s => s,
                bool b => b ? "1" : "0",
                double d => Shortest(d),
                float f => Shortest(f),
                IFormattable x => x.ToString(null, CultureInfo.InvariantCulture),
                var x => x.ToString() ?? "",
            };
            sb.Append(ArkFile.LiteralTagName(l.Tag)).Append(':').Append(value).Append(", ");
        }
        return sb.Append("]}").ToString();
    }

    private static string Resolve(Func<string> read)
    {
        try { return read(); }
        catch (InvalidDataException ex) { return $"<{ex.Message}>"; }
    }

    // A literal array's number as ark_disasm prints it: six significant digits, like C's %g.
    private static string Shortest(double d) =>
        double.IsNaN(d) ? "nan" : double.IsInfinity(d) ? (d > 0 ? "inf" : "-inf") : d.ToString("G6", CultureInfo.InvariantCulture).Replace('E', 'e');

    // Text is kept raw as ark_disasm prints it; line breaks and NUL are escaped so each instruction stays one line of text.
    internal static string Quote(string s) =>
        $"\"{s.Replace("\r", "\\r", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal).Replace("\0", "\\0", StringComparison.Ordinal)}\"";
}
