using System.ComponentModel;
using System.Text;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class SearchTools(AssemblyWorkspace workspace, SearchService search, OutputPager pager)
{
    [McpServerTool(Name = "search_symbols", Title = "Search symbols by name", ReadOnly = true, OpenWorld = false)]
    [Description("Find types and members by name across loaded assemblies. Query is a case-insensitive substring, a wildcard pattern (Get*Player?) or a regex (regex=true). " +
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

    [McpServerTool(Name = "search_strings", Title = "Search string literals", ReadOnly = true, OpenWorld = false)]
    [Description("Find string literals (ldstr in method bodies, and string constants) by substring, wildcard or regex, with the method and IL offset using each. Locates code from UI text, log messages, URLs, keys.")]
    public Task<string> SearchStrings(
        [Description("Substring, wildcard or regex.")] string query,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Treat query as a regular expression.")] bool regex = false,
        [Description("Max results (default 200).")] int limit = 200,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var r = search.SearchStrings(query, regex, workspace.Scope(assembly), ClampLimit(limit), cancellationToken);
        if (r.Total == 0) return $"No string literals match '{query}'.";
        var sb = new StringBuilder($"{Plural(r.Total, "occurrence")}{TruncationNote(r.Items.Count, r.Total)}:\n");
        foreach (var h in r.Items)
            sb.AppendLine($"  {Format.Literal(Format.Clip(h.Value, 200))}\n      in {Format.MemberLabel(h.Owner)}" +
                          $"{(h.ILOffset is { } o ? $" @IL_{o:X4}" : " (constant)")}  [{h.Assembly.Id}] {Format.Token(h.Owner)}");
        return pager.Page(sb.ToString());
    }, cancellationToken);

    [McpServerTool(Name = "search_constants", Title = "Search numeric constants", ReadOnly = true, OpenWorld = false)]
    [Description("Find a numeric constant (magic number, packet/opcode id, flag, hash seed, crypto constant) wherever it appears: IL literals (ldc.*), const and enum field values, attribute arguments. Accepts decimal, 0x hex, negative and floating-point values.")]
    public Task<string> SearchConstants(
        [Description("Number, e.g. 1337, 0xDEADBEEF, -1, 3.14.")] string value,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Max results (default 200).")] int limit = 200,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var r = search.SearchConstants(value, workspace.Scope(assembly), ClampLimit(limit), cancellationToken);
        if (r.Total == 0) return $"Constant {value} not found.";
        var sb = new StringBuilder($"{Plural(r.Total, "occurrence")} of {value}{TruncationNote(r.Items.Count, r.Total)}:\n");
        foreach (var h in r.Items)
            sb.AppendLine($"  {Format.MemberLabel(h.Owner)}{(h.ILOffset is { } o ? $" @IL_{o:X4}" : "")}  {h.Kind} {h.Value}  [{h.Assembly.Id}] {Format.Token(h.Owner)}");
        return pager.Page(sb.ToString());
    }, cancellationToken);

    [McpServerTool(Name = "search_il", Title = "Search IL instruction patterns", ReadOnly = true, OpenWorld = false)]
    [Description("Find methods containing an IL instruction sequence. Elements separated by ';' or newlines, each 'opcode [operand]' with * and ? wildcards; '...' skips up to 16 instructions. " +
                 "Operands match member labels/full names, type names, strings and numbers (decimal or 0x hex). " +
                 "Examples: 'ldstr *password*; ...; call *::Hash*' | 'callvirt *Socket::Send*' | 'ldc.i4 0x1F4; call *' | 'newobj *Exception::.ctor*; throw'.")]
    public Task<string> SearchIL(
        [Description("Instruction pattern.")] string pattern,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Max matches (default 100).")] int limit = 100,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var r = search.SearchIL(pattern, workspace.Scope(assembly), ClampLimit(limit), cancellationToken);
        if (r.Total == 0) return $"No methods match the IL pattern.";
        var sb = new StringBuilder($"{Plural(r.Total, "match")}{TruncationNote(r.Items.Count, r.Total)}:\n");
        foreach (var m in r.Items)
        {
            sb.AppendLine($"  {Format.MemberLabel(m.Method)} @IL_{m.Offset:X4}  [{m.Assembly.Id}] {Format.Token(m.Method)}");
            foreach (var line in m.Instructions.Take(24)) sb.AppendLine("      " + line);
            if (m.Instructions.Count > 24) sb.AppendLine($"      … {m.Instructions.Count - 24} more instructions");
        }
        return pager.Page(sb.ToString());
    }, cancellationToken);
}
