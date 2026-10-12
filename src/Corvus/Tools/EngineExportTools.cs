using System.ComponentModel;
using System.Text.Json.Nodes;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>export_engine_database: the engine's analysis database of an image, written for the engine's own GUI.</summary>
[McpServerToolType]
public sealed class EngineExportTools(AssemblyWorkspace workspace, NativeEngineService engines, NativeCodeService? nativeCode = null,
    NativeNamePush? names = null, NativeTypePush? types = null, NativeUserTypePush? userTypes = null)
{
    public sealed record DatabaseExport(string Image, string Engine, [property: Description("The file written.")] string Path, long Bytes, string Note);

    [McpServerTool(Name = "export_engine_database", Title = "Export the engine database", UseStructuredContent = true)]
    [Description("Write a native image's engine database (analysis plus names, comments and types pushed from here) for the engine's GUI: " +
                 "IDA a compressed .i64, Ghidra a packed .gzf; Ghidra's own types also as .h or .gdt.")]
    public Task<DatabaseExport> ExportEngineDatabase(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("The .i64 (IDA), .gzf, .h or .gdt (Ghidra) file to write.")] string outputPath,
        [Description("Replace outputPath if it exists.")] bool force = false,
        [Description("Default: the extension's engine, else IDA.")] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var full = SafeFile.FullPath(outputPath);
        bool auto = string.IsNullOrWhiteSpace(engine) || engine.Trim().Equals("auto", StringComparison.OrdinalIgnoreCase);
        var given = Path.GetExtension(full).ToLowerInvariant();
        var id = !auto ? engine!.Trim().ToLowerInvariant() : given is ".gzf" or ".h" or ".gdt" ? "ghidra" : "ida";
        if (id is not ("ida" or "ghidra")) throw new ToolError(ErrorCode.InvalidArgument, $"Unknown engine '{engine}'.", "omit engine or pass engine=ida or ghidra");
        // Ghidra also writes its types alone: a C header or a data type archive
        var extension = id == "ghidra" ? given is ".h" or ".gdt" ? given : ".gzf" : ".i64";
        if (Path.GetExtension(full).Length == 0) full += extension;
        if (!Path.GetExtension(full).Equals(extension, StringComparison.OrdinalIgnoreCase))
            throw new ToolError(ErrorCode.InvalidArgument, $"{full} is not a {extension} file.", $"name the output file *{extension} for {NativeEngineService.DisplayName(id)}");
        if (File.Exists(full) && !force)
            throw new ToolError(ErrorCode.Conflict, $"{full} already exists. Pass force=true to replace it.");
        engines.Provider(id);
        var (native, _) = await Task.Run(() => NativeAnalysisTools.Resolve(workspace, nativeCode, image, "rva:0"), cancellationToken);
        var session = await engines.Session(native, id, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
        if (session is Native.Providers.Ghidra.GhidraSession ghidra) return await ExportGhidra(native, ghidra, full, cancellationToken);
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

    /// <summary>The Ghidra program, with everything pushed, packed outside the worker's project.</summary>
    private async Task<DatabaseExport> ExportGhidra(LoadedNative native, Native.Providers.Ghidra.GhidraSession ghidra, string full, CancellationToken ct)
    {
        if (names != null) await names.EnsureAsync(native, ghidra, ct);
        if (types != null) await types.EnsureAsync(native, ghidra, ct);
        if (userTypes != null) await userTypes.EnsureAsync(native, ghidra, ct);
        var project = Path.GetFullPath(ghidra.ProjectDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (full.StartsWith(project, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new ToolError(ErrorCode.InvalidArgument, $"{full} is inside the worker's own project.", "pick a path outside it");
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        if (File.Exists(full)) File.Delete(full);
        var kind = Path.GetExtension(full).ToLowerInvariant();
        if (kind is ".h" or ".gdt")
        {
            var (typesPath, typesBytes, count) = await ghidra.ExportTypesAsync(full, kind[1..], ct);
            return new DatabaseExport(native.Id, "ghidra", typesPath, typesBytes, $"{count} type(s) of the program (declared, pushed, from the PDB or the analysis; " +
                (kind == ".gdt" ? "open the archive in Ghidra's Data Type Manager)" : "a C header)"));
        }
        var (path, bytes) = await ghidra.ExportPackedAsync(full, ct);
        return new DatabaseExport(native.Id, "ghidra", path, bytes,
            "open it in Ghidra (File > Open File System or Import into a project); the server's own project is unchanged and stays in its analysis cache");
    }
}
