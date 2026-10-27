using System.ComponentModel;
using ModelContextProtocol.Server;
using Corvus.Mcp;
using Corvus.Services.Analysis;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class BuildSummaryTools
{
    [McpServerTool(Name = "summarize_build", Title = "Build summary", UseStructuredContent = true, OutputSchemaType = typeof(BuildSummary.Report))]
    [Description("Summarize an application build without loading it: engine version, scripting backend (aot or mono), metadata version, " +
                 "platform, architecture and next calls.")]
    public async Task<string> SummarizeBuild(
        [Description("Folder, executable, *_Data, global-metadata.dat, or package (.apk, .ipa, .app, zip).")] string path,
        [Description("Also run Detect It Easy (CORVUS_DIE or PATH) on the main binaries; about 1 s each.")] bool detectItEasy = false,
        CancellationToken cancellationToken = default)
    {
        var report = await Task.Run(() => BuildSummary.Inspect(path, detectItEasy, cancellationToken), cancellationToken);
        return ToolOutput.Report(ContainerText.Build(report), report);
    }
}
