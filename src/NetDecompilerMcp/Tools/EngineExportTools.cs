using System.ComponentModel;
using System.Text.Json.Nodes;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ida;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tools;

/// <summary>export_engine_database: the engine's analysis database of an image, written for the engine's own GUI.</summary>
[McpServerToolType]
public sealed class EngineExportTools(AssemblyWorkspace workspace, NativeEngineService engines, NativeCodeService? nativeCode = null,
    NativeNamePush? names = null, NativeTypePush? types = null, NativeUserTypePush? userTypes = null)
{
    public sealed record DatabaseExport(string Image, string Engine, [property: Description("The file written.")] string Path, long Bytes, string Note);

    [McpServerTool(Name = "export_engine_database", Title = "Export the engine database", UseStructuredContent = true)]
    [Description("Write a native image's IDA database (analysis plus the names, comments and types pushed from here) as a compressed .i64 copy " +
                 "for the IDA GUI; the worker keeps its own. force=true replaces an existing file. Ghidra projects are not exported.")]
    public Task<DatabaseExport> ExportEngineDatabase(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("The .i64 file to write.")] string outputPath,
        [Description("Replace outputPath if it exists.")] bool force = false,
        [Description("Engine: auto (default) or ida.")] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var id = string.IsNullOrWhiteSpace(engine) || engine.Trim().Equals("auto", StringComparison.OrdinalIgnoreCase) ? "ida" : engine.Trim().ToLowerInvariant();
        if (id == "ghidra")
            throw new ToolError(ErrorCode.Unsupported, "Ghidra projects are not exported.", "export_native_annotations format=ghidra writes a script with the names and comments");
        if (id != "ida") throw new ToolError(ErrorCode.InvalidArgument, $"Unknown engine '{engine}'.", "omit engine or pass engine=ida");
        var full = SafeFile.FullPath(outputPath);
        if (Path.GetExtension(full).Length == 0) full += ".i64";
        if (!Path.GetExtension(full).Equals(".i64", StringComparison.OrdinalIgnoreCase))
            throw new ToolError(ErrorCode.InvalidArgument, $"{full} is not an .i64 file.", "name the output file *.i64");
        if (File.Exists(full) && !force)
            throw new ToolError(ErrorCode.Conflict, $"{full} already exists. Pass force=true to replace it.");
        engines.Provider(id);
        var (native, _) = await Task.Run(() => NativeAnalysisTools.Resolve(workspace, nativeCode, image, "rva:0"), cancellationToken);
        var session = await engines.Session(native, id, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
        if (session is not IdaSession ida) throw new ToolError(ErrorCode.Unsupported, $"The {session.ProviderId} engine does not export its database.");
        // the database as the other engine tools leave it
        if (names != null) await names.EnsureAsync(native, ida, cancellationToken);
        if (types != null) await types.EnsureAsync(native, ida, cancellationToken);
        if (userTypes != null) await userTypes.EnsureAsync(native, ida, cancellationToken);
        if (FileIdentity.Same(full, ida.DatabasePath))
            throw new ToolError(ErrorCode.InvalidArgument, $"{full} is the worker's own database.", "pick another path");
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        if (File.Exists(full)) File.Delete(full);
        var r = await ida.CallAsync("save_as", new JsonObject { ["path"] = full }, cancellationToken);
        return new DatabaseExport(native.Id, id, r.GetProperty("path").GetString() ?? full, r.GetProperty("size").GetInt64(),
            "open it in IDA; the server's own database is unchanged and stays in its analysis cache");
    });
}
