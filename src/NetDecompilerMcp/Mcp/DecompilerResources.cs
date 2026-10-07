using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Mcp;

/// <summary>
/// MCP resources: let a client attach decompiled code, IL or an assembly overview as context by URI.
/// Template values are URL-decoded, so ids like "Game#2" can be passed as "Game%232".
/// Nested types use '+' (Ns.Outer+Inner) because '/' separates URI segments.
/// </summary>
[McpServerResourceType]
public sealed class DecompilerResources(AssemblyWorkspace workspace, DecompilerService decompiler, AssemblyReport report)
{
    public const string Scheme = "netdecomp";

    [McpServerResource(UriTemplate = Scheme + "://assemblies", Name = "assemblies", Title = "Loaded assemblies", MimeType = "text/plain")]
    [Description("The loaded assemblies, with ids, paths and unsaved edits.")]
    public string Assemblies() => workspace.Read(() =>
    {
        var sb = new StringBuilder();
        foreach (var a in workspace.Assemblies)
            sb.AppendLine($"{a.Id}\t{a.FullAssemblyName}\t{a.FilePath}{(a.IsDirty ? $"\t[{a.Edits.Count} unsaved edits]" : "")}");
        return sb.Length == 0 ? "No assemblies loaded." : sb.ToString();
    });

    [McpServerResource(UriTemplate = Scheme + "://assembly/{assembly}/info", Name = "assembly_info", Title = "Assembly overview", MimeType = "text/plain")]
    [Description("Overview of one assembly: identity, references, PE layout, attributes.")]
    public string AssemblyInfo([Description("Assembly id.")] string assembly) =>
        workspace.Read(() => report.Build(workspace.Get(Decode(assembly))));

    [McpServerResource(UriTemplate = Scheme + "://assembly/{assembly}/type/{type}", Name = "type_source", Title = "Decompiled type (C#)", MimeType = "text/x-csharp")]
    [Description("Full decompiled C# source of a type (nested types as Ns.Outer+Inner).")]
    public string TypeSource([Description("Assembly id.")] string assembly, [Description("Full type name.")] string type, CancellationToken cancellationToken) =>
        workspace.Read(() =>
        {
            var sym = SymbolResolver.ResolveOne(workspace, Decode(assembly), Decode(type), SymbolKind.Type);
            return decompiler.DecompileType(sym.Assembly, (TypeDef)sym.Member, cancellationToken);
        });

    [McpServerResource(UriTemplate = Scheme + "://assembly/{assembly}/il/{symbol}", Name = "il", Title = "IL disassembly", MimeType = "text/plain")]
    [Description("IL disassembly of a type or member (symbol syntax as in the tools, e.g. Ns.Type::Method).")]
    public string IL([Description("Assembly id.")] string assembly, [Description("Type or member.")] string symbol, CancellationToken cancellationToken) =>
        workspace.Read(() =>
        {
            var sym = SymbolResolver.ResolveOne(workspace, Decode(assembly), Decode(symbol));
            return decompiler.Disassemble(sym.Assembly, sym.Member, cancellationToken);
        });

    private static string Decode(string value) => Uri.UnescapeDataString(value);
}
