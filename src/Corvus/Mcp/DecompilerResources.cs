using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Services;

namespace Corvus.Mcp;

/// <summary>
/// MCP resources exposing decompiled code, IL and assembly overviews by URI. Template values are URL-decoded
/// (e.g. "App%232" for id "App#2"); nested types use '+' because '/' separates URI segments.
/// </summary>
[McpServerResourceType]
public sealed class DecompilerResources(AssemblyWorkspace workspace, DecompilerService decompiler, AssemblyReport report)
{
    public const string Scheme = "corvus";

    [McpServerResource(UriTemplate = Scheme + "://assemblies", Name = "assemblies", Title = "Loaded assemblies", MimeType = "text/plain")]
    [Description("The loaded assemblies and native images, with ids, paths, unsaved edits and patches.")]
    public string Assemblies() => workspace.Read(() =>
    {
        var sb = new StringBuilder();
        foreach (var a in workspace.Assemblies)
            sb.AppendLine($"{a.Id}\t{a.FullAssemblyName}\t{a.FilePath}{(a.IsDirty ? $"\t[{a.Edits.Count} unsaved edits]" : "")}");
        foreach (var n in workspace.Natives)
            sb.AppendLine($"{n.Id}\tnative\t{n.FilePath}{(n.HasPatches ? $"\t[{n.Patches.Patches.Count} unsaved patches]" : "")}");
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
            // All overloads, matching get_il.
            return string.Join("\n", SymbolResolver.Resolve(workspace, Decode(assembly), Decode(symbol))
                .Select(s => $"// [{s.Assembly.Id}] {s.Label}\n{decompiler.Disassemble(s.Assembly, s.Member, cancellationToken)}"));
        });

    [McpServerResource(UriTemplate = Scheme + "://guide/{topic}", Name = "guide", Title = "Guide topic", MimeType = "text/plain")]
    [Description("The full guidance on one area: dotnet, native, il2cpp, containers, edits, builds, idapython, dumps or errors.")]
    public static string GuideTopic([Description("Topic name.")] string topic) =>
        Guide.Topic(Decode(topic)) ?? throw WorkflowPrompts.UnknownTopic(Decode(topic));

    private static string Decode(string value) => Uri.UnescapeDataString(value);
}
