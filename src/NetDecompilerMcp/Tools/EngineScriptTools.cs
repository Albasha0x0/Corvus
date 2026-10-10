using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tools;

/// <summary>Scripts in the decompiler engine's worker: off unless the server is started with it allowed.</summary>
[McpServerToolType]
public sealed class EngineScriptTools(AssemblyWorkspace workspace, NativeEngineService engines, ServerOptions options, NativeCodeService? nativeCode = null,
    NativeNamePush? names = null, NativeTypePush? types = null, NativeUserTypePush? userTypes = null)
{
    [McpServerTool(Name = "ida_python", Title = "Run IDAPython on a native image")]
    [Description("Run Python in the IDA worker that holds a native image's database (idalib): IDAPython modules are imported, base is the image " +
                 "base, globals persist between calls (reset=true clears them), and the value of a final expression is returned with stdout and " +
                 "stderr. Disabled unless the server runs with --ida-scripting or NDM_IDA_SCRIPTING=1: the code runs with the server's rights and " +
                 "can change or destroy the analysis database. Changes are not journaled or saved in the annotation sidecar: a worker restart " +
                 "loses unsaved ones (ida_loader.save_database keeps them).")]
    public Task<string> IdaPython(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Python source; a final expression's value is returned.")] string code,
        [Description("Clear the globals earlier calls left.")] bool reset = false,
        [Description("Engine: auto (default) or ida.")] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        if (!options.IdaScripting)
            throw new ToolError(ErrorCode.Unsupported, "ida_python is disabled on this server.",
                $"start the server with --ida-scripting or set {ServerOptions.IdaScriptingVariable}=1 to allow scripts");
        engines.Provider(engine);
        var (native, _) = await Task.Run(() => NativeAnalysisTools.Resolve(workspace, nativeCode, image, "rva:0"), cancellationToken);
        var session = await engines.Session(native, engine, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
        // the database as the other engine tools leave it
        if (names != null) await names.EnsureAsync(native, session, cancellationToken);
        if (types != null) await types.EnsureAsync(native, session, cancellationToken);
        if (userTypes != null) await userTypes.EnsureAsync(native, session, cancellationToken);
        var r = await session.RunScriptAsync(code ?? "", reset, cancellationToken);
        NativeUserTypePush.Touch(session); // cached engine output may be stale now
        var sb = new StringBuilder();
        if (r.Error != null) sb.Append("Error:\n").Append(r.Error.TrimEnd()).Append('\n');
        if (r.Result != null) sb.Append("Result: ").Append(r.Result).Append('\n');
        if (r.Stdout.Length > 0) sb.Append("stdout:\n").Append(r.Stdout.TrimEnd()).Append('\n');
        if (r.Stderr.Length > 0) sb.Append("stderr:\n").Append(r.Stderr.TrimEnd()).Append('\n');
        return sb.Length == 0 ? "Done (no result or output)." : sb.ToString();
    });
}
