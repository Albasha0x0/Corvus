using System.ComponentModel;
using System.Text;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class SearchTools(AssemblyWorkspace workspace, SearchService search, Il2CppService il2cpp, Il2CppStringService il2cppStrings, OutputPager pager)
{
    [McpServerTool(Name = "search_symbols", Title = "Search symbols by name", UseStructuredContent = true, OutputSchemaType = typeof(SymbolList))]
    [Description("Find types and members by name across loaded assemblies: a case-insensitive substring, wildcard (Get*Value?) or regex; queries with '.' or '::' " +
                 "also match full names; exact matches first.")]
    public Task<string> SearchSymbols(
        [Description("Name, substring, wildcard or regex.")] string query,
        [Description("Restrict to this kind.")] string? kind = null,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Only types in namespaces starting with this.")] string? @namespace = null,
        [Description("Treat query as a regular expression.")] bool regex = false,
        [Description("Max results.")] int limit = 100,
        [Description("Index of the first result.")] int offset = 0,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        limit = ClampLimit(limit);
        offset = Math.Clamp(offset, 0, int.MaxValue - limit);
        var timeouts = new RegexTimeouts();
        var r = search.SearchSymbols(query, regex, SymbolResolver.ParseKind(kind), workspace.Scope(assembly), @namespace, offset + limit, cancellationToken, timeouts);
        var page = r.Items.Skip(offset).ToList();
        var result = new SymbolList(page.Select(s => BrowseTools.Match(s)).ToList(), offset, r.Total, offset + page.Count < r.Total) { NotEvaluated = timeouts.Count };
        if (r.Total == 0) return StructuredOutput.With(timeouts.Note("name") + $"No symbols match '{query}'.", result);
        var sb = new StringBuilder(timeouts.Note("name") + $"{Plural(r.Total, "match")}" +
                                   (offset >= r.Total ? $" (none from offset {offset})" : offset > 0 ? $" (showing {offset + 1}-{offset + page.Count})" : TruncationNote(page.Count, r.Total)) + ":\n");
        foreach (var s in page)
            sb.AppendLine($"  {s.Kind,-8} {s.Label}  [{s.Assembly.Id}] {Format.Token(s.Member)}");
        if (offset > 0 && result.Truncated) sb.AppendLine($"[More: call again with offset={offset + page.Count}]");
        return StructuredOutput.With(pager.Page(sb.ToString()), result);
    }, cancellationToken);

    [McpServerTool(Name = "search_strings", Title = "Search string literals", UseStructuredContent = true, OutputSchemaType = typeof(StringList))]
    [Description("Find string literals (ldstr and string constants) by substring, wildcard or regex, with the method and IL offset using each: code from UI text, " +
                 "log messages, URLs, keys. For Il2Cpp dummy DLLs: the game's literals with their slot RVA and, with the binary, the native functions that load them, by method name.")]
    public Task<string> SearchStrings(
        [Description("Substring, wildcard or regex.")] string query,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Treat query as a regular expression.")] bool regex = false,
        [Description("Max results.")] int limit = 200,
        [Description("Index of the first result.")] int offset = 0,
        [Description("Il2Cpp: max functions listed per literal.")] int usesPerLiteral = 10,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        limit = ClampLimit(limit);
        offset = Math.Clamp(offset, 0, int.MaxValue - limit); // offset + limit must not overflow
        var scope = workspace.Scope(assembly);
        var timeouts = new RegexTimeouts();
        var r = search.SearchStrings(query, regex, scope, offset + limit, cancellationToken, timeouts);
        var literals = il2cppStrings.Search(SearchService.CreateMatcher(query, regex, timeouts), scope, cancellationToken);
        int total = r.Total + literals.Count;
        var shown = Math.Min(limit, Math.Max(0, total - offset));
        var items = new List<StringEntry>();
        var result = new StringList(items, offset, total, offset + shown < total) { NotEvaluated = timeouts.Count };
        if (total == 0)
            return StructuredOutput.With(timeouts.Note("string") + SkippedBodiesNote(scope) + $"No string literals match '{query}'." + (il2cppStrings.DumpsFor(scope).Count == 0 && scope.Any(a => il2cpp.GetIndex(a).Count > 0)
                ? $" Il2Cpp dummy DLLs have empty bodies: put the dump's {Il2CppDumpFiles.StringLiteralFileName} and {Il2CppDumpFiles.ScriptFileName} in the DummyDll folder or its parent to search the game's literals."
                : ""), result);

        var sb = new StringBuilder(timeouts.Note("string") + Plural(total, "occurrence"));
        if (literals.Count > 0) sb.Append($" ({r.Total} in IL and constants, {Plural(literals.Count, "Il2Cpp string literal")})");
        sb.Append(offset >= total ? $" (none from offset {offset})" : offset > 0 ? $" (showing {offset + 1}-{offset + shown})" : TruncationNote(shown, total)).AppendLine(":");
        foreach (var dump in literals.Select(l => l.Dump).Distinct())
            sb.AppendLine($"  [Il2Cpp: {dump.Describe()}]");
        foreach (var h in r.Items.Skip(offset))
        {
            sb.AppendLine($"  {Format.Literal(Format.Clip(h.Value, 200))}\n      in {Format.MemberLabel(h.Owner)}" +
                          $"{(h.ILOffset is { } o ? $" @IL_{o:X4}" : " (constant)")}  [{h.Assembly.Id}] {Format.Token(h.Owner)}");
            items.Add(new StringEntry(Format.Clip(h.Value, 2000), h.ILOffset != null ? "il" : "constant", SymbolRef.Of(h.Assembly, h.Owner), (int?)h.ILOffset, null, null));
        }
        var inScope = scope.ToHashSet();
        foreach (var l in literals.Skip(Math.Max(0, offset - r.Total)).Take(offset + limit - Math.Max(offset, r.Total)))
        {
            AppendLiteral(sb, l, inScope, Math.Max(0, usesPerLiteral));
            items.Add(new StringEntry(Format.Clip(l.Value, 2000), "il2cpp", null, null, $"0x{l.Address:X}",
                l.Uses?.SelectMany(u => u.Methods.Count > 0 ? u.Methods.Take(3).Select(m => Format.MemberLabel(m.Method)) : [$"RVA 0x{u.Function:X}"])
                    .Take(Math.Max(0, usesPerLiteral)).ToList()));
        }
        if (offset + shown < total) sb.AppendLine($"[More: call again with offset={offset + shown}]");
        sb.Append(SkippedBodiesNote(scope));
        return StructuredOutput.With(pager.Page(sb.ToString()), result);
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

    [McpServerTool(Name = "search_constants", Title = "Search numeric constants", UseStructuredContent = true, OutputSchemaType = typeof(ConstantList))]
    [Description("Find a numeric constant (magic number, opcode id, flag, crypto constant) in IL literals, const and enum values, attribute arguments and static array data (lookup and crypto tables, read as the array's element type).")]
    public Task<string> SearchConstants(
        [Description("Decimal, 0x hex, negative or floating-point.")] string value,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Max results.")] int limit = 200,
        [Description("Index of the first result.")] int offset = 0,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        limit = ClampLimit(limit);
        offset = Math.Clamp(offset, 0, int.MaxValue - limit);
        var scope = workspace.Scope(assembly);
        var r = search.SearchConstants(value, scope, offset + limit, cancellationToken);
        var page = r.Items.Skip(offset).ToList();
        var result = new ConstantList(value, page.Select(h => new ConstantEntry(SymbolRef.Of(h.Assembly, h.Owner), (int?)h.ILOffset, h.Kind, h.Value)).ToList(),
            offset, r.Total, offset + page.Count < r.Total);
        if (r.Total == 0) return StructuredOutput.With(SkippedBodiesNote(scope) + $"Constant {value} not found.", result);
        var sb = new StringBuilder($"{Plural(r.Total, "occurrence")} of {value}" +
                                   (offset >= r.Total ? $" (none from offset {offset})" : offset > 0 ? $" (showing {offset + 1}-{offset + page.Count})" : TruncationNote(page.Count, r.Total)) + ":\n");
        foreach (var h in page)
            sb.AppendLine($"  {Format.MemberLabel(h.Owner)}{(h.ILOffset is { } o ? $" @IL_{o:X4}" : "")}  {h.Kind} {h.Value}  [{h.Assembly.Id}] {Format.Token(h.Owner)}");
        if (offset > 0 && result.Truncated) sb.AppendLine($"[More: call again with offset={offset + page.Count}]");
        sb.Append(SkippedBodiesNote(scope));
        return StructuredOutput.With(pager.Page(sb.ToString()), result);
    }, cancellationToken);

    [McpServerTool(Name = "search_il", Title = "Search IL instruction patterns", UseStructuredContent = true, OutputSchemaType = typeof(IlMatchList))]
    [Description("Find methods containing an IL instruction sequence: elements separated by ';' or newlines, each 'opcode [operand]' with * and ? wildcards " +
                 "(operands match member and type names, strings, numbers); '...' skips up to 16 instructions. Example: 'ldstr *password*; ...; call *::Hash*'.")]
    public Task<string> SearchIL(
        [Description("Instruction pattern.")] string pattern,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Max matches.")] int limit = 100,
        [Description("Index of the first match.")] int offset = 0,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        limit = ClampLimit(limit);
        offset = Math.Clamp(offset, 0, int.MaxValue - limit);
        var scope = workspace.Scope(assembly);
        var r = search.SearchIL(pattern, scope, offset + limit, cancellationToken);
        var page = r.Items.Skip(offset).ToList();
        var result = new IlMatchList(page.Select(m => new IlMatchEntry(SymbolRef.Of(m.Assembly, m.Method), (int)m.Offset, m.Instructions.Take(24).ToList())).ToList(),
            offset, r.Total, offset + page.Count < r.Total);
        if (r.Total == 0) return StructuredOutput.With(SkippedBodiesNote(scope) + "No methods match the IL pattern.", result);
        var sb = new StringBuilder($"{Plural(r.Total, "match")}" +
                                   (offset >= r.Total ? $" (none from offset {offset})" : offset > 0 ? $" (showing {offset + 1}-{offset + page.Count})" : TruncationNote(page.Count, r.Total)) + ":\n");
        foreach (var m in page)
        {
            sb.AppendLine($"  {Format.MemberLabel(m.Method)} @IL_{m.Offset:X4}  [{m.Assembly.Id}] {Format.Token(m.Method)}");
            foreach (var line in m.Instructions.Take(24)) sb.AppendLine("      " + line);
            if (m.Instructions.Count > 24) sb.AppendLine($"      … {m.Instructions.Count - 24} more instructions");
        }
        if (offset > 0 && result.Truncated) sb.AppendLine($"[More: call again with offset={offset + page.Count}]");
        sb.Append(SkippedBodiesNote(scope));
        return StructuredOutput.With(pager.Page(sb.ToString()), result);
    }, cancellationToken);
}
