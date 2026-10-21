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
    [Description("Assembly overview: identity (MVID, SHA-256), framework, entry point, counts, Il2Cpp, invalid IL, protection product, edits; " +
                 "view=references: where references resolve; metadata: PE headers, streams, tables, heaps, metadata problems, attributes.")]
    public Task<string> GetAssemblyInfo(
        [Description(AssemblyDescription)] string assembly,
        [Description("What to show.")] string view = "summary",
        CancellationToken cancellationToken = default) =>
        Read(workspace, () =>
        {
            view = (view ?? "summary").Trim().ToLowerInvariant();
            if (!AssemblyReport.Views.Contains(view))
                throw new ToolError(ErrorCode.InvalidArgument, $"Unknown view '{view}'.", "pass view as one of " + string.Join(", ", AssemblyReport.Views));
            var text = report.Build(workspace.Get(assembly), view, out var summary);
            return ToolOutput.Report(text, summary);
        }, cancellationToken);
}
