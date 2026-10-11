using System.ComponentModel;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services.Analysis;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class UnpackTools(UnpackService unpacker)
{
    [McpServerTool(Name = "unpack_container", Title = "Unpack container", UseStructuredContent = true)]
    [Description("Extract the .NET assemblies shipped inside a container and (by default) load them: .NET single-file bundles " +
                 "(apphost .exe / Linux / macOS, compressed or not), Costura.Fody embedded assemblies, NuGet packages, Xamarin / MAUI " +
                 ".apk / .aab (XALZ / XAZS compressed assemblies, assembly stores v1-v3 with real names, per ABI), plain zips, and .NET images embedded anywhere " +
                 "else. Nested containers are opened too. Nothing is executed; extracted names cannot escape the output directory and " +
                 "runnable extensions get a .bin suffix. Reports NativeAOT executables, which have no IL to extract.")]
    public Task<UnpackService.UnpackReport> UnpackContainer(
        [Description("Absolute path to the container file.")] string path,
        [Description("Directory to extract into: new, empty, or an earlier unpack of the same file. Default: a folder under the temp directory named after the file and its hash.")] string? outputDirectory = null,
        [Description("Load the extracted .NET assemblies into the workspace (their ids are in loadedAs).")] bool load = true,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => unpacker.Unpack(path, outputDirectory, load, AnalysisLimits.Default, cancellationToken), cancellationToken);

    [McpServerTool(Name = "search_container", Title = "Search inside a container", UseStructuredContent = true)]
    [Description("Find types and members by name in every managed assembly inside a container (single-file bundle, .nupkg, .apk / .aab, " +
                 "Costura host, zip; nested containers too) or a plain assembly, without extracting or loading anything. " +
                 "Query is a case-insensitive substring ('*' / '?' wildcards; a query with '.' or ':' also matches full names). " +
                 "Each match gives the assembly's path inside the container, the assembly name, the full member name and its kind; " +
                 "best matches first. truncated=true means more than limit matched (total has the full count).")]
    public Task<UnpackService.ContainerSearch> SearchContainer(
        [Description("Absolute path to the container or assembly file.")] string path,
        [Description("Name or part of a name.")] string query,
        [Description("Restrict to: type, method, field, property. Omit for all (events included).")] string? kind = null,
        [Description("Max matches returned (default 200, max 5000).")] int limit = 200,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => unpacker.Search(path, query, UnpackService.ParseSearchKind(kind), ClampLimit(limit), AnalysisLimits.Default, cancellationToken),
            cancellationToken);
}
