using System.ComponentModel;
using System.Text;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class SearchTools(AssemblyWorkspace workspace, SearchService search, Il2CppService il2cpp, Il2CppStringService il2cppStrings, OutputPager pager)
{
    [McpServerTool(Name = "search_symbols", Title = "Search symbols by name")]
    [Description("Find types and members by name across loaded assemblies. Query is a case-insensitive substring, a wildcard pattern (Get*Value?) or a regex (regex=true). " +
                 "Queries containing '.' or '::' also match full names. Exact matches are listed first.")]
    public Task<string> SearchSymbols(
        [Description("Name, substring, wildcard or regex.")] string query,
        [Description("Restrict to: any, type, method, field, property, event, member.")] string? kind = null,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Only types in namespaces starting with this.")] string? @namespace = null,
        [Description("Treat query as a regular expression.")] bool regex = false,
        [Description("Max results (default 100).")] int limit = 100,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var r = search.SearchSymbols(query, regex, SymbolResolver.ParseKind(kind), workspace.Scope(assembly), @namespace, ClampLimit(limit), cancellationToken);
        if (r.Total == 0) return $"No symbols match '{query}'.";
        var sb = new StringBuilder($"{Plural(r.Total, "match")}{TruncationNote(r.Items.Count, r.Total)}:\n");
        foreach (var s in r.Items)
            sb.AppendLine($"  {s.Kind,-8} {s.Label}  [{s.Assembly.Id}] {Format.Token(s.Member)}");
        return pager.Page(sb.ToString());
    }, cancellationToken);

    [McpServerTool(Name = "search_strings", Title = "Search string literals")]
    [Description("Find string literals (ldstr in method bodies, and string constants) by substring, wildcard or regex, with the method and IL offset using each. Locates code from UI text, log messages, URLs, keys. " +
                 "For Il2CppDumper dummy DLLs (empty bodies) it searches the dump's stringliteral.json instead: each literal with its slot RVA and, when GameAssembly.dll is next to the dump, " +
                 "the native functions that load it, named by their dummy-DLL method (or script.json name for generic instantiations).")]
    public Task<string> SearchStrings(
        [Description("Substring, wildcard or regex.")] string query,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Treat query as a regular expression.")] bool regex = false,
        [Description("Max results (default 200).")] int limit = 200,
        [Description("Index of the first result to return.")] int offset = 0,
        [Description("Il2Cpp literals: max functions listed per literal (default 10).")] int usesPerLiteral = 10,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        limit = ClampLimit(limit);
        offset = Math.Clamp(offset, 0, int.MaxValue - limit); // offset + limit must not overflow
        var scope = workspace.Scope(assembly);
        var r = search.SearchStrings(query, regex, scope, offset + limit, cancellationToken);
        var literals = il2cppStrings.Search(SearchService.CreateMatcher(query, regex), scope, cancellationToken);
        int total = r.Total + literals.Count;
        if (total == 0)
            return SkippedBodiesNote(scope) + $"No string literals match '{query}'." + (il2cppStrings.DumpsFor(scope).Count == 0 && scope.Any(a => il2cpp.GetIndex(a).Count > 0)
                ? $" Il2Cpp dummy DLLs have empty bodies: put the dump's {Il2CppDumpFiles.StringLiteralFileName} and {Il2CppDumpFiles.ScriptFileName} in the DummyDll folder or its parent to search the game's literals."
                : "");

        var shown = Math.Min(limit, Math.Max(0, total - offset));
        var sb = new StringBuilder(Plural(total, "occurrence"));
        if (literals.Count > 0) sb.Append($" ({r.Total} in IL and constants, {Plural(literals.Count, "Il2Cpp string literal")})");
        sb.Append(offset >= total ? $" (none from offset {offset})" : offset > 0 ? $" (showing {offset + 1}-{offset + shown})" : TruncationNote(shown, total)).AppendLine(":");
        foreach (var dump in literals.Select(l => l.Dump).Distinct())
            sb.AppendLine($"  [Il2Cpp: {dump.Describe()}]");
        foreach (var h in r.Items.Skip(offset))
            sb.AppendLine($"  {Format.Literal(Format.Clip(h.Value, 200))}\n      in {Format.MemberLabel(h.Owner)}" +
                          $"{(h.ILOffset is { } o ? $" @IL_{o:X4}" : " (constant)")}  [{h.Assembly.Id}] {Format.Token(h.Owner)}");
        var inScope = scope.ToHashSet();
        foreach (var l in literals.Skip(Math.Max(0, offset - r.Total)).Take(offset + limit - Math.Max(offset, r.Total)))
            AppendLiteral(sb, l, inScope, Math.Max(0, usesPerLiteral));
        if (offset + shown < total) sb.AppendLine($"[More: call again with offset={offset + shown}]");
        sb.Append(SkippedBodiesNote(scope));
        return pager.Page(sb.ToString());
    }, cancellationToken);

    private static void AppendLiteral(StringBuilder sb, Il2CppStringService.LiteralMatch l, HashSet<LoadedAssembly> scope, int maxUses)
    {
        sb.AppendLine($"  {Format.Literal(Format.Clip(l.Value, 200))}");
        sb.Append($"      Il2Cpp literal, slot RVA 0x{l.Address:X}");
        if (l.Uses == null) { sb.AppendLine(); return; }
        if (l.Uses.Count == 0) { sb.AppendLine("; no code loads it"); return; }
        sb.AppendLine($"; loaded by {Plural(l.Uses.Count, "function")}:");
        var ordered = l.Uses.OrderBy(u => u.Methods.Any(m => scope.Contains(m.Assembly)) ? 0 : u.Methods.Count > 0 ? 1 : 2).ThenBy(u => u.Function);
        foreach (var u in ordered.Take(maxUses))
            AppendFunction(sb, l.Dump, u.Function, u.Sites, u.Methods, "      in ");
        if (l.Uses.Count > maxUses) sb.AppendLine($"      … {l.Uses.Count - maxUses} more functions (raise usesPerLiteral)");
    }

    /// <summary>One line per method starting at a native function: dummy-DLL methods, else script.json names, else the bare address.</summary>
    internal static void AppendFunction(StringBuilder sb, Il2CppStringIndex dump, uint function, int sites, IReadOnlyList<Il2CppService.MethodAddress> methods, string prefix)
    {
        var count = sites > 1 ? $" x{sites}" : "";
        if (methods.Count > 0)
        {
            foreach (var m in methods.Take(3))
                sb.AppendLine($"{prefix}{Format.MemberLabel(m.Method)}  RVA 0x{function:X}{count}  [{m.Assembly.Id}] {Format.Token(m.Method)}");
            if (methods.Count > 3) sb.AppendLine($"{prefix}… {methods.Count - 3} more methods sharing this code");
            return;
        }
        var (first, names) = dump.Script?.MethodRange(function) ?? (0, 0);
        if (names == 0) { sb.AppendLine($"{prefix}function at RVA 0x{function:X}{count} (no method name in the dump)"); return; }
        sb.AppendLine($"{prefix}{dump.Script!.MethodName(first)}  RVA 0x{function:X}{count} (script.json; no dummy method starts here)" +
                      (names > 1 ? $" and {names - 1} more names sharing this code" : ""));
    }

    [McpServerTool(Name = "search_constants", Title = "Search numeric constants")]
    [Description("Find a numeric constant (magic number, packet/opcode id, flag, hash seed, crypto constant) wherever it appears: IL literals (ldc.*), const and enum field values, attribute arguments, and static array data (lookup tables, S-boxes, CRC and crypto tables), read element by element as the array's own type. Accepts decimal, 0x hex, negative and floating-point values.")]
    public Task<string> SearchConstants(
        [Description("Number, e.g. 1337, 0xDEADBEEF, -1, 3.14.")] string value,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Max results (default 200).")] int limit = 200,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var scope = workspace.Scope(assembly);
        var r = search.SearchConstants(value, scope, ClampLimit(limit), cancellationToken);
        if (r.Total == 0) return SkippedBodiesNote(scope) + $"Constant {value} not found.";
        var sb = new StringBuilder($"{Plural(r.Total, "occurrence")} of {value}{TruncationNote(r.Items.Count, r.Total)}:\n");
        foreach (var h in r.Items)
            sb.AppendLine($"  {Format.MemberLabel(h.Owner)}{(h.ILOffset is { } o ? $" @IL_{o:X4}" : "")}  {h.Kind} {h.Value}  [{h.Assembly.Id}] {Format.Token(h.Owner)}");
        sb.Append(SkippedBodiesNote(scope));
        return pager.Page(sb.ToString());
    }, cancellationToken);

    [McpServerTool(Name = "search_il", Title = "Search IL instruction patterns")]
    [Description("Find methods containing an IL instruction sequence. Elements separated by ';' or newlines, each 'opcode [operand]' with * and ? wildcards; '...' skips up to 16 instructions. " +
                 "Operands match member labels/full names, type names, strings and numbers (decimal or 0x hex). " +
                 "Examples: 'ldstr *password*; ...; call *::Hash*' | 'callvirt *Socket::Send*' | 'ldc.i4 0x1F4; call *' | 'newobj *Exception::.ctor*; throw'.")]
    public Task<string> SearchIL(
        [Description("Instruction pattern.")] string pattern,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Max matches (default 100).")] int limit = 100,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var scope = workspace.Scope(assembly);
        var r = search.SearchIL(pattern, scope, ClampLimit(limit), cancellationToken);
        if (r.Total == 0) return SkippedBodiesNote(scope) + "No methods match the IL pattern.";
        var sb = new StringBuilder($"{Plural(r.Total, "match")}{TruncationNote(r.Items.Count, r.Total)}:\n");
        foreach (var m in r.Items)
        {
            sb.AppendLine($"  {Format.MemberLabel(m.Method)} @IL_{m.Offset:X4}  [{m.Assembly.Id}] {Format.Token(m.Method)}");
            foreach (var line in m.Instructions.Take(24)) sb.AppendLine("      " + line);
            if (m.Instructions.Count > 24) sb.AppendLine($"      … {m.Instructions.Count - 24} more instructions");
        }
        sb.Append(SkippedBodiesNote(scope));
        return pager.Page(sb.ToString());
    }, cancellationToken);
}
