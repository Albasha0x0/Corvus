using System.ComponentModel;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class AssemblyInfoTools(AssemblyWorkspace workspace, AssemblyReport report)
{
    [McpServerTool(Name = "get_assembly_info", Title = "Assembly overview", UseStructuredContent = true, OutputSchemaType = typeof(AssemblyReport.Summary))]
    [Description("Assembly overview: identity (MVID, SHA-256), target framework, entry point, counts, references (resolved or not), PE headers and sections, metadata streams, tables and heaps, metadata problems with file offsets, attributes, Il2Cpp detection, invalid IL bodies, unsaved edits.")]
    public Task<string> GetAssemblyInfo([Description(AssemblyDescription)] string assembly, CancellationToken cancellationToken = default) =>
        Read(workspace, () =>
        {
            var text = report.Build(workspace.Get(assembly), out var summary);
            return StructuredOutput.With(text, summary);
        }, cancellationToken);
}
