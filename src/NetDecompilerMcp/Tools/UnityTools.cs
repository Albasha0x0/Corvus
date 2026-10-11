using System.ComponentModel;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Services.Analysis;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class UnityTools
{
    [McpServerTool(Name = "unity_overview", Title = "Unity title overview", UseStructuredContent = true)]
    [Description("One-call overview of a Unity game, in seconds and without loading it: engine version from each source (UnityPlayer / executable " +
                 "version resources, globalgamemanagers / mainData / level0 serialized-file header, data.unity3d bundle header) with their agreement " +
                 "and an Il2Cpp metadata-version cross-check; scripting backend (il2cpp / mono) with its evidence, metadata version and state " +
                 "(readable by the built-in reader, encrypted, header_tampered, unsupported_version, missing), Mono runtime and .NET profile; toolchain " +
                 "and middleware markers from file, assembly, section and identifier names, each with its category (Detect It Easy detections with " +
                 "detectItEasy=true); platform and architecture; " +
                 "notable folders (Managed, il2cpp_data, StreamingAssets, aa Addressables catalogs, Plugins); and the next tool calls with their " +
                 "arguments (load_assembly the Managed folder or the metadata, or dump from memory with the reason). Reads directory listings, " +
                 "headers and version resources only. Not a Unity title: an unsupported error with reason not_a_unity_title and what was looked for.")]
    public Task<UnityOverview.Report> UnityOverviewTool(
        [Description("The game folder, its executable, its <Game>_Data folder, UnityPlayer.dll, GameAssembly.dll or global-metadata.dat; also an extracted " +
                     "Android APK folder or a macOS or iOS .app.")] string path,
        [Description("Also run Detect It Easy (diec, from NDM_DIE or PATH) on the executable, GameAssembly.dll or Assembly-CSharp.dll: launches it, about a second per file.")] bool detectItEasy = false,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => UnityOverview.Inspect(path, detectItEasy, cancellationToken), cancellationToken);
}
