using System.ComponentModel;
using ModelContextProtocol.Server;
using Corvus.Mcp;
using Corvus.Services.Analysis;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class UnityTools
{
    [McpServerTool(Name = "unity_overview", Title = "Unity title overview", UseStructuredContent = true, OutputSchemaType = typeof(UnityOverview.Report))]
    [Description("Overview of a Unity title in seconds, without loading it: engine version per source, scripting backend (il2cpp / mono) with " +
                 "evidence, metadata version and state (readable, encrypted, header_tampered, unsupported_version, missing), toolchain, middleware, " +
                 "platform, architecture, folders, next calls.")]
    public async Task<string> UnityOverviewTool(
        [Description("Game folder, executable, *_Data, GameAssembly, global-metadata.dat, .apk, .ipa, zip, WebGL, .app.")] string path,
        [Description("Also run Detect It Easy (CORVUS_DIE or PATH) on the main binaries; about 1 s per file.")] bool detectItEasy = false,
        CancellationToken cancellationToken = default)
    {
        var report = await Task.Run(() => UnityOverview.Inspect(path, detectItEasy, cancellationToken), cancellationToken);
        return ToolOutput.Report(ContainerText.Unity(report), report);
    }
}
