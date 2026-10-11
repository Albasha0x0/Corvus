using System.ComponentModel;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Services.Analysis;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class UnpackTools(UnpackService unpacker)
{
    [McpServerTool(Name = "unpack_container", Title = "Unpack container", UseStructuredContent = true)]
    [Description("Extract the .NET assemblies inside a container and load them: single-file bundles, Costura.Fody, NuGet packages, Xamarin / MAUI .apk / .aab " +
                 "(compressed assemblies and assembly stores, per ABI), zips, and .NET images embedded elsewhere; nested containers too. Nothing is executed; " +
                 "names cannot escape the output directory and runnable extensions get .bin. NativeAOT executables (no IL) are reported.")]
    public Task<UnpackService.UnpackReport> UnpackContainer(
        [Description("Absolute path to the container file.")] string path,
        [Description("New or empty directory, or an earlier unpack of the same file; default under temp.")] string? outputDirectory = null,
        [Description("Load the extracted assemblies (ids in loadedAs).")] bool load = true,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => unpacker.Unpack(path, outputDirectory, load, AnalysisLimits.Default, cancellationToken), cancellationToken);

    [McpServerTool(Name = "search_container", Title = "Search inside a container", UseStructuredContent = true)]
    [Description("Find types and members by name in every managed assembly inside a container (bundle, .nupkg, .apk / .aab, Costura, zip, nested) or an assembly, " +
                 "without extracting or loading: a case-insensitive substring with * / ? wildcards ('.' or ':' also match full names); each match with its inner path, assembly, full name and kind.")]
    public Task<UnpackService.ContainerSearch> SearchContainer(
        [Description("Absolute path to the container or assembly file.")] string path,
        [Description("Name or part of a name.")] string query,
        [Description("Restrict to this kind; omit for all (events included).")] string? kind = null,
        [Description("Max matches (max 5000).")] int limit = 200,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => unpacker.Search(path, query, UnpackService.ParseSearchKind(kind), ClampLimit(limit), AnalysisLimits.Default, cancellationToken),
            cancellationToken);
}
