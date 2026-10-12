using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>Scripts in the decompiler engine's worker: off unless the server is started with it allowed.</summary>
[McpServerToolType]
public sealed class EngineScriptTools(AssemblyWorkspace workspace, NativeEngineService engines, ServerOptions options, NativeCodeService? nativeCode = null,
    NativeNamePush? names = null, NativeTypePush? types = null, NativeUserTypePush? userTypes = null)
{
    [McpServerTool(Name = "ida_python", Title = "Run IDAPython on a native image")]
    [Description("Run Python in the IDA worker holding a native image's database (idalib): IDAPython modules imported, base = image base, " +
                 "globals persist (reset=true clears); returns a final expression's value, stdout and stderr. Off unless --ida-scripting " +
                 "(CORVUS_IDA_SCRIPTING=1): the code has the server's rights. Not journaled: a worker restart loses changes unless persist=true.")]
    public Task<string> IdaPython(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Python source (or pass file).")] string? code = null,
        [Description("Clear the globals earlier calls left.")] bool reset = false,
        [Description("Default auto.")] string? engine = null,
        [Description("A .py file to run instead of code.")] string? file = null,
        [Description("Characters kept of the result, stdout and stderr each (100-200000).")] int maxOutput = 20_000,
        [Description("Save the database after the script.")] bool persist = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        bool hasCode = !string.IsNullOrEmpty(code);
        if (hasCode == !string.IsNullOrWhiteSpace(file))
            throw new ToolError(ErrorCode.InvalidArgument, hasCode ? "Pass code or file, not both." : "Pass code or file.");
        if (maxOutput is < 100 or > 200_000) throw new ToolError(ErrorCode.InvalidArgument, $"maxOutput must be 100-200000, not {maxOutput}.");
        if (!options.IdaScripting)
            throw new ToolError(ErrorCode.Unsupported, "ida_python is disabled on this server.",
                $"start the server with --ida-scripting or set {ServerOptions.IdaScriptingVariable}=1 to allow scripts");
        if (file != null)
        {
            var path = Path.GetFullPath(file.Trim());
            if (!File.Exists(path)) throw new ToolError(ErrorCode.NotFound, $"No file {path}.");
            if (new FileInfo(path).Length > MaxScriptBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{path} is over {MaxScriptBytes / 1024} KB.");
            code = await File.ReadAllTextAsync(path, cancellationToken);
        }
        // IDAPython runs in IDA only, whatever the server's default engine
        var ida = string.IsNullOrWhiteSpace(engine) || engine.Trim().Equals("auto", StringComparison.OrdinalIgnoreCase) ? "ida" : engine.Trim();
        if (!ida.Equals("ida", StringComparison.OrdinalIgnoreCase))
            throw new ToolError(ErrorCode.InvalidArgument, $"ida_python runs in IDA, not in '{ida}'.", "omit engine or pass engine=ida");
        engines.Provider(ida);
        var (native, _) = await Task.Run(() => NativeAnalysisTools.Resolve(workspace, nativeCode, image, "rva:0"), cancellationToken);
        var session = await engines.Session(native, ida, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
        // the database as the other engine tools leave it
        if (names != null) await names.EnsureAsync(native, session, cancellationToken);
        if (types != null) await types.EnsureAsync(native, session, cancellationToken);
        if (userTypes != null) await userTypes.EnsureAsync(native, session, cancellationToken);
        var r = await session.RunScriptAsync(code ?? "", reset, cancellationToken);
        NativeUserTypePush.Touch(session); // cached engine output may be stale now
        if (persist) await session.SaveAsync(cancellationToken);
        string Clip(string text) => text.Length <= maxOutput ? text : text[..maxOutput] + $"\n[clipped at {maxOutput} of {text.Length} characters]";
        var sb = new StringBuilder();
        if (r.Error != null) sb.Append("Error:\n").Append(Clip(r.Error.TrimEnd())).Append('\n');
        if (r.Result != null) sb.Append("Result: ").Append(Clip(r.Result)).Append('\n');
        if (r.Stdout.Length > 0) sb.Append("stdout:\n").Append(Clip(r.Stdout.TrimEnd())).Append('\n');
        if (r.Stderr.Length > 0) sb.Append("stderr:\n").Append(Clip(r.Stderr.TrimEnd())).Append('\n');
        if (persist) sb.Append("Database saved.\n");
        return sb.Length == 0 ? "Done (no result or output)." : sb.ToString();
    });

    /// <summary>Largest script file=; a bigger one is data, not a script.</summary>
    private const int MaxScriptBytes = 1 << 20;

    [McpServerTool(Name = "ghidra_script", Title = "Run a Ghidra script on a native image")]
    [Description("Run Java in the Ghidra worker holding a native image's program: a GhidraScript class, or run()'s body with imports first " +
                 "(currentProgram, println, FlatProgramAPI). One transaction, committed when the script returns, then saved. Off unless the server " +
                 "runs with --ghidra-scripting (CORVUS_GHIDRA_SCRIPTING=1): the code has the server's rights. Changes are not in the annotation sidecar.")]
    public Task<string> GhidraScript(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Java source: a class extending GhidraScript, or statements for run().")] string code,
        [Description("Seconds before the script is cancelled (1-3600).")] int timeout = 120,
        [Description("Default auto.")] string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        if (!options.GhidraScripting)
            throw new ToolError(ErrorCode.Unsupported, "ghidra_script is disabled on this server.",
                $"start the server with {ServerOptions.GhidraScriptingOption} or set {ServerOptions.GhidraScriptingVariable}=1 to allow scripts");
        var id = string.IsNullOrWhiteSpace(engine) || engine.Trim().Equals("auto", StringComparison.OrdinalIgnoreCase) ? "ghidra" : engine.Trim();
        if (!id.Equals("ghidra", StringComparison.OrdinalIgnoreCase))
            throw new ToolError(ErrorCode.InvalidArgument, $"ghidra_script runs in Ghidra, not in '{id}'.", "omit engine or pass engine=ghidra");
        engines.Provider("ghidra");
        var (native, _) = await Task.Run(() => NativeAnalysisTools.Resolve(workspace, nativeCode, image, "rva:0"), cancellationToken);
        var session = await engines.Session(native, "ghidra", new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
        if (names != null) await names.EnsureAsync(native, session, cancellationToken);
        if (types != null) await types.EnsureAsync(native, session, cancellationToken);
        if (userTypes != null) await userTypes.EnsureAsync(native, session, cancellationToken);
        var r = session is Native.Providers.Ghidra.GhidraSession ghidra
            ? await ghidra.RunJavaAsync(code ?? "", Math.Clamp(timeout, 1, 3600), cancellationToken)
            : await session.RunScriptAsync(code ?? "", false, cancellationToken);
        NativeUserTypePush.Touch(session);
        var sb = new StringBuilder();
        if (r.Error != null) sb.Append("Error (changes rolled back):\n").Append(r.Error.TrimEnd()).Append('\n');
        if (r.Stdout.Length > 0) sb.Append("stdout:\n").Append(r.Stdout.TrimEnd()).Append('\n');
        if (r.Stderr.Length > 0) sb.Append("stderr:\n").Append(r.Stderr.TrimEnd()).Append('\n');
        return sb.Length == 0 ? "Done (no output); changes committed and saved." : sb.ToString();
    });
}
