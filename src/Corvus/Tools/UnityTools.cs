using System.ComponentModel;
using ModelContextProtocol.Server;
using Corvus.Mcp;
using Corvus.Services.Analysis;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class UnityTools
{
    [McpServerTool(Name = "unity_overview", Title = "Unity title overview", UseStructuredContent = true, OutputSchemaType = typeof(UnityOverview.Report))]
    [Description("Overview of a Unity title in seconds, without loading it (listings, headers and version resources only): engine version per source with " +
                 "their agreement, scripting backend (il2cpp / mono) with evidence, metadata version and state (readable, encrypted, header_tampered, " +
                 "unsupported_version, missing), toolchain and middleware markers, platform, architecture, notable folders, and the next calls " +
                 "(load_assembly the Managed folder or the metadata, or dump from memory). Not Unity: unsupported, reason not_a_unity_title.")]
    public async Task<string> UnityOverviewTool(
        [Description("The title's folder, executable, *_Data folder, UnityPlayer.dll, GameAssembly.dll or global-metadata.dat; an extracted APK folder or a macOS / iOS .app.")] string path,
        [Description("Also run Detect It Easy (diec, CORVUS_DIE or PATH) on the main binaries; launches it, about a second per file.")] bool detectItEasy = false,
        CancellationToken cancellationToken = default)
    {
        var report = await Task.Run(() => UnityOverview.Inspect(path, detectItEasy, cancellationToken), cancellationToken);
        return ToolOutput.Report(ContainerText.Unity(report), report);
    }
}
