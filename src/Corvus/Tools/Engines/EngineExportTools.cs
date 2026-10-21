using System.ComponentModel;
using System.Text.Json.Nodes;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
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

    [McpServerTool(Name = "export_engine_database", Title = "Export the engine database", UseStructuredContent = true, OutputSchemaType = typeof(DatabaseExport))]
    [Description("Write the engine database of a native image (analysis plus names, comments and types from here) for the engine GUI: IDA " +
                 ".i64, Ghidra .gzf; Ghidra types also as .h or .gdt. Written whole or not at all.")]
    public Task<string> ExportEngineDatabase(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("The .i64 (IDA), .gzf, .h or .gdt (Ghidra) to write.")] string outputPath,
        [Description("Overwrite outputPath.")] bool overwrite = false,
        [Description("Default: the engine of the extension, else IDA.")] string? engine = null,
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
        if (File.Exists(full) && !overwrite)
            throw new ToolError(ErrorCode.Conflict, $"{full} already exists.", "pass overwrite=true to replace it, or another outputPath");
        engines.Provider(id);
        // the target is checked before the engine works: a path the system cannot write fails now, not after the export
        var staging = Staging(full);
        var (native, _) = await Task.Run(() => NativeAnalysisTools.Resolve(workspace, nativeCode, image, "rva:0"), cancellationToken);
        var session = await engines.Session(native, id, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
        EngineReport.Answered(new EngineChoice(id, auto ? $"auto: the {extension} file is {NativeEngineService.DisplayName(id)}'s" : $"engine={id}"), engines, session);
        if (names != null) await names.EnsureAsync(native, session, cancellationToken);
        if (types != null) await types.EnsureAsync(native, session, cancellationToken);
        if (userTypes != null) await userTypes.EnsureAsync(native, session, cancellationToken);
        // the engine writes a short private path (IDA opens at most 259 characters on Windows); the file moves to the target whole
        var temp = Path.Combine(Path.GetTempPath(), $"corvus-export-{Guid.NewGuid().ToString("N")[..12]}{extension}");
        try
        {
            DatabaseExport export;
            if (session is Native.Providers.Ghidra.GhidraSession ghidra) export = await ExportGhidra(native, ghidra, full, temp, cancellationToken);
            else if (session is IdaSession ida)
            {
                if (FileIdentity.Same(full, ida.DatabasePath)) throw new ToolError(ErrorCode.InvalidArgument, $"{full} is the worker's own database.", "pick another path");
                IdaProvider.CheckPathLength(temp, "temporary export", Path.GetTempPath(), OperatingSystem.IsWindows());
                var r = await ida.CallAsync("save_as", new JsonObject { ["path"] = temp }, cancellationToken);
                export = new DatabaseExport(native.Id, id, full, r.GetProperty("size").GetInt64(),
                    "open it in IDA; the server's own database is unchanged and stays in its analysis cache");
            }
            else throw new ToolError(ErrorCode.Unsupported, $"The {session.ProviderId} engine does not export its database.");
            Publish(temp, staging, full);
            var text = $"Wrote {export.Path} ({export.Bytes:N0} bytes, {NativeEngineService.DisplayName(id)}): {export.Note}.\n";
            return ToolOutput.Report(text, export);
        }
        finally
        {
            TryDelete(temp);
            TryDelete(staging);
        }
    });

    /// <summary>A file beside <paramref name="full"/> the export moves through, written and removed once to prove the folder takes it.</summary>
    private static string Staging(string full)
    {
        var staging = Path.Combine(Path.GetDirectoryName(full)!, $".{Path.GetFileName(full)}.{Guid.NewGuid().ToString("N")[..8]}.tmp");
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllBytes(staging, []);
            File.Delete(staging);
            return staging;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or PathTooLongException or NotSupportedException)
        {
            throw new ToolError(ErrorCode.IoError, $"{full} cannot be written ({full.Length} characters): {e.Message}",
                "pick a shorter or writable outputPath (long paths need the system's long path support)");
        }
    }

    /// <summary>Moves the export into place whole: beside the target first, then over it in one rename.</summary>
    private static void Publish(string temp, string staging, string full)
    {
        File.Move(temp, staging);
        File.Move(staging, full, overwrite: true);
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>The Ghidra program, with everything pushed, packed outside the worker's project to <paramref name="temp"/>.</summary>
    private static async Task<DatabaseExport> ExportGhidra(LoadedNative native, Native.Providers.Ghidra.GhidraSession ghidra, string full, string temp, CancellationToken ct)
    {
        var project = Path.GetFullPath(ghidra.ProjectDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (full.StartsWith(project, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new ToolError(ErrorCode.InvalidArgument, $"{full} is inside the worker's own project.", "pick a path outside it");
        var kind = Path.GetExtension(full).ToLowerInvariant();
        if (kind is ".h" or ".gdt")
        {
            var (_, typesBytes, count) = await ghidra.ExportTypesAsync(temp, kind[1..], ct);
            return new DatabaseExport(native.Id, "ghidra", full, typesBytes, $"{count} type(s) of the program (declared, pushed, from the PDB or the analysis; " +
                (kind == ".gdt" ? "open the archive in Ghidra's Data Type Manager)" : "a C header)"));
        }
        var (_, bytes) = await ghidra.ExportPackedAsync(temp, ct);
        return new DatabaseExport(native.Id, "ghidra", full, bytes,
            "open it in Ghidra (File > Open File System or Import into a project); the server's own project is unchanged and stays in its analysis cache");
    }
}
