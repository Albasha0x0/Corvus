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
    [Description("Assembly overview: identity, framework, entry point, counts, invalid IL, transformer, edits. " +
                 "view=references, metadata (headers, streams, tables, heaps) or transforms (dry-run layers).")]
    public Task<string> GetAssemblyInfo(
        [Description(AssemblyDescription)] string assembly,
        [Description("What to show.")] string view = "summary",
        CancellationToken cancellationToken = default) =>
        Read(workspace, () =>
        {
            view = (view ?? "summary").Trim().ToLowerInvariant();
            if (!AssemblyReport.Views.Contains(view))
                throw new ToolError(ErrorCode.InvalidArgument, $"Unknown view '{view}'.", "pass view as one of " + string.Join(", ", AssemblyReport.Views));
            var text = report.Build(workspace.Get(assembly), view, out var summary, cancellationToken);
            return ToolOutput.Report(text, summary);
        }, cancellationToken);
}
