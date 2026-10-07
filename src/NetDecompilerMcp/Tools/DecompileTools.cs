using System.ComponentModel;
using dnlib.DotNet;
using ModelContextProtocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class DecompileTools(AssemblyWorkspace workspace, DecompilerService decompiler, OutputPager pager)
{
    private const int MaxMembersPerCall = 25;

    [McpServerTool(Name = "decompile_type", Title = "Decompile type to C#", ReadOnly = true, OpenWorld = false)]
    [Description("Decompile a whole type (class/struct/interface/enum/delegate, including nested types) to C#. Long output is paged: call again with the offset from the footer. " +
                 "If one method breaks the decompiler, the rest is still returned with IL for the broken part.")]
    public Task<string> DecompileType(
        [Description("Type name or token. " + SymbolDescription)] string type,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, type, SymbolKind.Type);
        return pager.Page(TypeSource(sym, cancellationToken), offset, maxChars);
    }, cancellationToken);

    [McpServerTool(Name = "decompile_member", Title = "Decompile member to C#", ReadOnly = true, OpenWorld = false)]
    [Description("Decompile a method, property, field, event or constructor to C#. When a name has several overloads all are returned, unless a parameter list narrows it ('Ns.Type::Foo(int, string)'). " +
                 "Async/iterator state machines and lambdas are folded back into the original method. A type name decompiles the whole type.")]
    public Task<string> DecompileMember(
        [Description(SymbolDescription)] string member,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Restrict to: method, field, property, event (default any).")] string? kind = null,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var all = SymbolResolver.Resolve(workspace, assembly, member, SymbolResolver.ParseKind(kind));
        if (all.Count == 1 && all[0].Member is TypeDef)
            return pager.Page(TypeSource(all[0], cancellationToken), offset, maxChars);
        RequireFew(all, member);

        var text = pager.GetOrCreate(CacheKey("member", all), () => string.Join("\n", all.GroupBy(a => a.Assembly).Select(g =>
            $"// [{g.Key.Id}]\n" + decompiler.DecompileMembers(g.Key, g.Select(s => s.Member), cancellationToken))));
        return pager.Page(text, offset, maxChars);
    }, cancellationToken);

    [McpServerTool(Name = "get_il", Title = "IL disassembly", ReadOnly = true, OpenWorld = false)]
    [Description("IL disassembly (ildasm style, with /* metadata token */ comments, IL offsets and structured try/catch blocks) of a method, field, property, event, or a whole type. " +
                 "Use it when the C# looks wrong, for obfuscated code, or as the starting point for patch_method_il.")]
    public Task<string> GetIL(
        [Description(SymbolDescription)] string symbol,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var all = SymbolResolver.Resolve(workspace, assembly, symbol);
        RequireFew(all, symbol);
        var text = pager.GetOrCreate(CacheKey("il", all), () => string.Join("\n", all.Select(s =>
            $"// [{s.Assembly.Id}] {s.Label}\n{decompiler.Disassemble(s.Assembly, s.Member, cancellationToken)}")));
        return pager.Page(text, offset, maxChars);
    }, cancellationToken);

    [McpServerTool(Name = "decompile_assembly_attributes", Title = "Decompile assembly attributes", ReadOnly = true, OpenWorld = false)]
    [Description("Decompile assembly- and module-level attributes (InternalsVisibleTo, versions, TargetFramework...) to C#.")]
    public Task<string> DecompileAssemblyAttributes(
        [Description(AssemblyDescription)] string assembly,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
            pager.Page(decompiler.DecompileAssemblyAttributes(workspace.Get(assembly), cancellationToken)), cancellationToken);

    [McpServerTool(Name = "export_project", Title = "Export C# project", OpenWorld = false)]
    [Description("Decompile an entire assembly into a C# project on disk (one .cs file per type, a .csproj, and resources). Best way to grep or browse a large codebase with normal file tools. Reports progress.")]
    public Task<string> ExportProject(
        [Description(AssemblyDescription)] string assembly,
        [Description("Empty or new output directory.")] string outputDirectory,
        IProgress<ProgressNotificationValue>? progress = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var asm = workspace.Get(assembly);
        var result = decompiler.ExportProject(asm, outputDirectory, (done, total, status) => Report(progress, done, total, status), cancellationToken);
        var summary = $"Exported {asm.Id} to {result.Directory}: {result.FileCount} files.{(result.ProjectFile != null ? $" Project: {result.ProjectFile}" : "")}";
        if (result.FailedTypes.Count > 0)
            summary += $"\n{Plural(result.FailedTypes.Count, "type")} failed to decompile (their files contain the error):\n  " +
                       string.Join("\n  ", result.FailedTypes.Take(20));
        return summary;
    }, cancellationToken);

    private string TypeSource(ResolvedSymbol sym, CancellationToken ct) =>
        pager.GetOrCreate(CacheKey("type", [sym]), () => $"// [{sym.Assembly.Id}] {sym.Label}\n" + decompiler.DecompileType(sym.Assembly, (TypeDef)sym.Member, ct));

    private string CacheKey(string kind, IEnumerable<ResolvedSymbol> symbols) =>
        $"{workspace.Generation}|{kind}|{string.Join(",", symbols.Select(s => s.Assembly.Id + Format.Token(s.Member)))}";

    private static void RequireFew(IReadOnlyList<ResolvedSymbol> all, string query)
    {
        if (all.Count > MaxMembersPerCall)
            throw new ToolError($"'{query}' matches {all.Count} symbols; narrow it with a type name, parameter list or token. First matches:\n" +
                                string.Join("\n", all.Take(MaxMembersPerCall).Select(a => "  " + a)));
    }
}
