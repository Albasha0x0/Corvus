using System.ComponentModel;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class DecompileTools(AssemblyWorkspace workspace, DecompilerService decompiler, OutputPager pager)
{
    [McpServerTool(Name = "decompile_type", ReadOnly = true)]
    [Description("Decompile a whole type (class/struct/interface/enum/delegate, including nested types) to C#. " +
                 "Large output is paged: call again with the offset from the footer. If one method breaks the decompiler, the rest is still returned with IL for the broken part.")]
    public Task<string> DecompileType(
        [Description("Type name or token. " + SymbolDescription)] string type,
        [Description(AssemblyDescription)] string? assembly = null,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveType(workspace, assembly, type);
        var text = pager.GetOrCreate($"{workspace.Generation}|type|{sym.Assembly.Id}|{Format.Token(sym.Member)}",
            () => $"// [{sym.Assembly.Id}] {sym.Label}\n" + decompiler.DecompileType(sym.Assembly, (TypeDef)sym.Member, cancellationToken));
        return pager.Page(text, offset, maxChars);
    }, cancellationToken);

    [McpServerTool(Name = "decompile_member", ReadOnly = true)]
    [Description("Decompile a method, property, field, event or constructor to C#. When a name has several overloads, all of them are returned unless a parameter list narrows it, e.g. 'Ns.Type::Foo(int, string)'. " +
                 "Async/iterator state machines and lambdas are folded back into the original method.")]
    public Task<string> DecompileMember(
        [Description(SymbolDescription)] string member,
        [Description(AssemblyDescription)] string? assembly = null,
        [Description("Restrict to: method, field, property, event (default any).")] string? kind = null,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var parsedKind = SymbolResolver.ParseKind(kind);
        var all = SymbolResolver.Resolve(workspace, assembly, member, parsedKind == SymbolKind.Any ? SymbolKind.Any : parsedKind);
        if (all.Count == 1 && all[0].Member is TypeDef td)
        {
            var typeText = pager.GetOrCreate($"{workspace.Generation}|type|{all[0].Assembly.Id}|{Format.Token(td)}",
                () => $"// [{all[0].Assembly.Id}] {all[0].Label}\n" + decompiler.DecompileType(all[0].Assembly, td, cancellationToken));
            return pager.Page(typeText, offset, maxChars);
        }
        if (all.Count > 25)
            throw new ToolError($"'{member}' matches {all.Count} members; narrow it with a type name, parameter list or token. First matches:\n" +
                                string.Join("\n", all.Take(25).Select(a => "  " + a)));

        var key = $"{workspace.Generation}|member|{string.Join(",", all.Select(a => a.Assembly.Id + Format.Token(a.Member)))}";
        var text = pager.GetOrCreate(key, () => string.Join("\n", all.GroupBy(a => a.Assembly).Select(g =>
            $"// [{g.Key.Id}]\n" + decompiler.DecompileMembers(g.Key, g.Select(s => s.Member), cancellationToken))));
        return pager.Page(text, offset, maxChars);
    }, cancellationToken);

    [McpServerTool(Name = "get_il", ReadOnly = true)]
    [Description("IL disassembly (ildasm style, with metadata tokens and structured try/catch blocks) of a method, or of a whole type when a type is given. Use when the C# looks wrong, for obfuscated code, or to get IL offsets.")]
    public Task<string> GetIL(
        [Description(SymbolDescription)] string symbol,
        [Description(AssemblyDescription)] string? assembly = null,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var all = SymbolResolver.Resolve(workspace, assembly, symbol);
        if (all.Count > 25)
            throw new ToolError($"'{symbol}' matches {all.Count} symbols; narrow it down.");
        var key = $"{workspace.Generation}|il|{string.Join(",", all.Select(a => a.Assembly.Id + Format.Token(a.Member)))}";
        var text = pager.GetOrCreate(key, () => string.Join("\n", all.Select(s =>
            $"// [{s.Assembly.Id}] {s.Label}\n{decompiler.Disassemble(s.Assembly, s.Member, cancellationToken)}")));
        return pager.Page(text, offset, maxChars);
    }, cancellationToken);

    [McpServerTool(Name = "decompile_assembly_attributes", ReadOnly = true)]
    [Description("Decompile assembly- and module-level attributes (InternalsVisibleTo, versions, TargetFramework, etc.) to C#.")]
    public Task<string> DecompileAssemblyAttributes(
        [Description("Assembly id, name or path.")] string assembly,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var asm = workspace.Get(assembly);
        return pager.Page(decompiler.DecompileAssemblyAttributes(asm, cancellationToken));
    }, cancellationToken);

    [McpServerTool(Name = "export_project")]
    [Description("Decompile an entire assembly into a C# project on disk (one .cs file per type plus a .csproj and resources). Best way to grep or browse a large codebase with normal file tools afterwards.")]
    public Task<string> ExportProject(
        [Description("Assembly id, name or path.")] string assembly,
        [Description("Empty or new output directory.")] string outputDirectory,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var asm = workspace.Get(assembly);
        var result = decompiler.ExportProject(asm, outputDirectory, cancellationToken);
        return $"Exported {asm.Id} to {result.Directory}: {result.FileCount} files.{(result.ProjectFile != null ? $" Project: {result.ProjectFile}" : "")}";
    }, cancellationToken);
}
