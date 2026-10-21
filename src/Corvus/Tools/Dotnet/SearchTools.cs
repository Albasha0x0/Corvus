using System.ComponentModel;
using System.Text;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class SearchTools(AssemblyWorkspace workspace, SearchService search, Il2CppService il2cpp, Il2CppStringService il2cppStrings)
{
    [McpServerTool(Name = "search_symbols", Title = "Search symbols by name", UseStructuredContent = true, OutputSchemaType = typeof(SymbolList))]
    [Description("Find types and members by name across loaded assemblies: case-insensitive substring, wildcard (Get*Value?) or regex; queries with . " +
                 "or :: match full names. Exact matches first, then by name length, assembly and token.")]
    public Task<string> SearchSymbols(
        [Description("Name, substring, wildcard or regex.")] string query,
        [Description("Restrict to this kind.")] string? kind = null,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Only namespaces starting with this.")] string? @namespace = null,
        [Description("query is a regex.")] bool regex = false,
        [Description(LimitDescription)] int limit = 100,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        [Description(RowOffsetDescription)] int offset = 0,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var timeouts = new RegexTimeouts();
        var r = search.SearchSymbols(query, regex, SymbolResolver.ParseKind(kind), workspace.Scope(assembly), @namespace, End(offset, limit), cancellationToken, timeouts);
        var page = r.Items.Skip(offset).Select(s => BrowseTools.Match(s)).ToList();
        return ToolOutput.List(page, offset, limit, r.Total, s => $"{s.Kind,-8} {s.Label}  [{s.Assembly}] {s.Token}",
            rows => new SymbolList(rows, offset, r.Total) { NotEvaluated = timeouts.Count, TotalExact = timeouts.Count > 0 ? false : null }, "match",
            BrowseTools.Header(timeouts.Note("name"), r.Total == 0 ? $"No symbols match '{query}'.\n" : null), totalExact: timeouts.Count == 0);
    }, cancellationToken);

    private const int ValueClip = 200;

    [McpServerTool(Name = "search_strings", Title = "Search string literals", UseStructuredContent = true, OutputSchemaType = typeof(StringList))]
    [Description("Find string literals (ldstr, string constants) by substring, wildcard or regex, with the method and IL offset using each. Il2Cpp " +
                 "dummy DLLs: the game literals with slot RVAs and, with the binary, the functions loading them.")]
    public Task<string> SearchStrings(
        [Description("Substring, wildcard or regex.")] string query,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("query is a regex.")] bool regex = false,
        [Description(LimitDescription)] int limit = 100,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Il2Cpp: max functions per literal.")] int usesPerLiteral = 10,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var scope = workspace.Scope(assembly);
        var timeouts = new RegexTimeouts();
        var r = search.SearchStrings(query, regex, scope, End(offset, limit), cancellationToken, timeouts);
        var literals = il2cppStrings.Search(SearchService.CreateMatcher(query, regex, timeouts), scope, cancellationToken);
        int total = r.Total + literals.Count;
        var inScope = scope.ToHashSet();
        int uses = Math.Max(0, usesPerLiteral);
        // IL and constant hits first, then the Il2Cpp literals: one row sequence.
        var page = new List<(StringEntry Entry, string Text)>();
        for (int i = offset; i < Math.Min(total, End(offset, limit)); i++)
        {
            if (i < r.Total)
            {
                var h = r.Items[i];
                page.Add((new StringEntry(Format.Clip(h.Value, ValueClip), h.ILOffset != null ? "il" : "constant")
                {
                    Owner = SymbolRef.Of(h.Assembly, h.Owner),
                    IlOffset = (int?)h.ILOffset,
                    Clipped = h.Value.Length > ValueClip ? true : null,
                }, $"{Format.Literal(Format.Clip(h.Value, ValueClip))}\n  in {Format.MemberLabel(h.Owner)}{(h.ILOffset is { } o ? $" @IL_{o:X4}" : " (constant)")}  [{h.Assembly.Id}] {Format.Token(h.Owner)}"));
                continue;
            }
            var l = literals[i - r.Total];
            var text = new StringBuilder();
            AppendLiteral(text, l, inScope, uses);
            page.Add((new StringEntry(Format.Clip(l.Value, ValueClip), "il2cpp")
            {
                SlotRva = l.Address != 0 ? $"0x{l.Address:X}" : null,
                Clipped = l.Value.Length > ValueClip ? true : null,
                LoadedBy = l.Uses?.SelectMany(u => u.Methods.Count > 0 ? u.Methods.Take(3).Select(m => Format.MemberLabel(m.Method)) : [$"RVA 0x{u.Function:X}"]).Take(uses).ToList(),
            }, text.ToString().ReplaceLineEndings("\n").TrimEnd('\n').TrimStart(' ').Replace("\n      ", "\n  ")));
        }
        var header = new StringBuilder(timeouts.Note("string") + SkippedBodiesNote(scope));
        if (total == 0)
        {
            header.Append($"No string literals match '{query}'.");
            if (il2cppStrings.DumpsFor(scope).Count == 0 && scope.Any(a => il2cpp.GetIndex(a).Count > 0))
                header.Append($" Il2Cpp dummy DLLs have empty bodies: put the dump's {Il2CppDumpFiles.StringLiteralFileName} and {Il2CppDumpFiles.ScriptFileName} in the DummyDll folder or its parent to search the game's literals.");
            header.Append('\n');
        }
        else if (literals.Count > 0)
        {
            header.Append($"{r.Total} in IL and constants, {Plural(literals.Count, "Il2Cpp string literal")}\n");
            foreach (var dump in literals.Select(x => x.Dump).Distinct()) header.Append($"[Il2Cpp: {dump.Describe()}]\n");
        }
        return ToolOutput.List(page, offset, limit, total, x => x.Text,
            rows => new StringList(rows.Select(x => x.Entry).ToList(), offset, total) { NotEvaluated = timeouts.Count, TotalExact = timeouts.Count > 0 ? false : null },
            "occurrence", header.Length > 0 ? header.ToString() : null, totalExact: timeouts.Count == 0);
    }, cancellationToken);

    private static void AppendLiteral(StringBuilder sb, Il2CppStringService.LiteralMatch l, HashSet<LoadedAssembly> scope, int maxUses)
    {
        sb.AppendLine($"  {Format.Literal(Format.Clip(l.Value, 200))}");
        sb.Append(l.Address != 0 ? $"      Il2Cpp literal, slot RVA 0x{l.Address:X}" : "      Il2Cpp literal (metadata read without the binary: no slot)");
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
    [Description("Find a number (magic, opcode id, flag, crypto constant) in IL literals, const and enum values, attribute arguments and static arrays (read as their element type).")]
    public Task<string> SearchConstants(
        [Description("Decimal, 0x hex, negative or floating-point.")] string value,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(LimitDescription)] int limit = 100,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        [Description(RowOffsetDescription)] int offset = 0,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var scope = workspace.Scope(assembly);
        var r = search.SearchConstants(value, scope, End(offset, limit), cancellationToken);
        var page = r.Items.Skip(offset).Select(h => new ConstantEntry(Format.MemberLabel(h.Owner), Format.Token(h.Owner), h.Assembly.Id, h.Kind, h.Value) { IlOffset = (int?)h.ILOffset }).ToList();
        return ToolOutput.List(page, offset, limit, r.Total,
            h => $"{h.Owner}{(h.IlOffset is { } o ? $" @IL_{o:X4}" : "")}  {h.Kind} {h.Value}  [{h.Assembly}] {h.Token}",
            rows => new ConstantList(value, rows, offset, r.Total), "occurrence",
            SkippedBodiesNote(scope) + (r.Total == 0 ? $"Constant {value} not found.\n" : $"Occurrences of {value}: "));
    }, cancellationToken);

    [McpServerTool(Name = "search_il", Title = "Search IL instruction patterns", UseStructuredContent = true, OutputSchemaType = typeof(IlMatchList))]
    [Description("Find methods containing an IL instruction sequence: ;-separated opcode [operand] elements with * and ? wildcards (operands match " +
                 "names, strings, numbers); ... skips up to 16 instructions, e.g. \"ldstr *password*; ...; call *::Hash*\".")]
    public Task<string> SearchIL(
        [Description("Instruction pattern.")] string pattern,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(LimitDescription)] int limit = 100,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Instructions shown per match (1-24).")] int context = 8,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        int shown = Math.Clamp(context, 1, 24);
        var scope = workspace.Scope(assembly);
        var r = search.SearchIL(pattern, scope, End(offset, limit), cancellationToken);
        var page = r.Items.Skip(offset).Select(m => (Entry: new IlMatchEntry(SymbolRef.Of(m.Assembly, m.Method), (int)m.Offset, m.Instructions.Take(shown).ToList()), More: m.Instructions.Count - shown)).ToList();
        return ToolOutput.List(page, offset, limit, r.Total,
            m => $"{m.Entry.Method.Label} @IL_{m.Entry.IlOffset:X4}  [{m.Entry.Method.Assembly}] {m.Entry.Method.Token}\n" + string.Join("\n", m.Entry.Instructions.Select(i => "  " + i)) +
                 (m.More > 0 ? $"\n  … {m.More} more instructions" : ""),
            rows => new IlMatchList(rows.Select(x => x.Entry).ToList(), offset, r.Total), "match",
            BrowseTools.Header(SkippedBodiesNote(scope), r.Total == 0 ? "No methods match the IL pattern.\n" : null));
    }, cancellationToken);
}
