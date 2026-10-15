using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Providers;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>Scripts in the decompiler engine's worker: off unless the server is started with it allowed.</summary>
[McpServerToolType]
public sealed class EngineScriptTools(AssemblyWorkspace workspace, NativeEngineService engines, ServerOptions options, NativeCodeService? nativeCode = null,
    NativeNamePush? names = null, NativeTypePush? types = null, NativeUserTypePush? userTypes = null)
{
    [Description("A script's outcome; past the page the whole text is kept under resultId.")]
    public sealed record ScriptReport(string Image, string Engine,
        string? Result,
        string? Stdout, string? Stderr,
        string? Error,
        bool Saved);

    [McpServerTool(Name = "ida_python", Title = "Run IDAPython on a native image", UseStructuredContent = true, OutputSchemaType = typeof(ScriptReport))]
    [Description("Run Python in the IDA worker holding a native image's database (idalib): IDAPython modules imported, base = image base, " +
                 "globals persist (reset=true clears); returns a final expression's value, stdout and stderr. " +
                 "Off unless --ida-scripting (CORVUS_IDA_SCRIPTING=1): the code has the server's rights. Not journaled: persist=true saves.")]
    public Task<string> IdaPython(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Python source (or pass scriptPath).")] string? code = null,
        [Description("Clear the globals earlier calls left.")] bool reset = false,
        [Description("Default auto.")] string? engine = null,
        [Description("A .py file to run instead of code.")] string? scriptPath = null,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        [Description("Save the database after the script.")] bool persist = false,
        [Description("Return an exception as the result instead of an error.")] bool allowError = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        bool hasCode = !string.IsNullOrEmpty(code);
        if (hasCode == !string.IsNullOrWhiteSpace(scriptPath))
            throw new ToolError(ErrorCode.InvalidArgument, hasCode ? "Pass code or scriptPath, not both." : "Pass code or scriptPath.");
        if (!options.IdaScripting)
            throw new ToolError(ErrorCode.Unsupported, "ida_python is disabled on this server.",
                $"start the server with --ida-scripting or set {ServerOptions.IdaScriptingVariable}=1 to allow scripts");
        if (scriptPath != null)
        {
            var path = Path.GetFullPath(scriptPath.Trim());
            if (!File.Exists(path)) throw Targets.FileNotFound(path);
            if (new FileInfo(path).Length > MaxScriptBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{path} is over {MaxScriptBytes / 1024} KB.");
            code = await File.ReadAllTextAsync(path, cancellationToken);
        }
        // IDAPython runs in IDA only, whatever the server's default engine
        var ida = string.IsNullOrWhiteSpace(engine) || engine.Trim().Equals("auto", StringComparison.OrdinalIgnoreCase) ? "ida" : engine.Trim();
        if (!ida.Equals("ida", StringComparison.OrdinalIgnoreCase))
            throw new ToolError(ErrorCode.InvalidArgument, $"ida_python runs in IDA, not in '{ida}'.", "omit engine or pass engine=ida");
        engines.Provider(ida);
        var (native, _) = await Task.Run(() => NativeAnalysisTools.Resolve(workspace, nativeCode, image, "rva:0"), cancellationToken);
        var session = await engines.Session(native, "ida", new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
        EngineReport.Answered(new EngineChoice("ida", "IDAPython runs in IDA"), engines, session);
        // the database as the other engine tools leave it
        if (names != null) await names.EnsureAsync(native, session, cancellationToken);
        if (types != null) await types.EnsureAsync(native, session, cancellationToken);
        if (userTypes != null) await userTypes.EnsureAsync(native, session, cancellationToken);
        var r = await session.RunScriptAsync(code ?? "", reset, cancellationToken);
        NativeUserTypePush.Touch(session); // cached engine output may be stale now
        if (persist) await session.SaveAsync(cancellationToken);
        return Outcome(native.Id, "ida", r, persist, allowError, "the script raised");
    });

    /// <summary>
    /// A script's outcome in both parts; the text past the call's budget is kept whole under a resultId. An exception is an
    /// error (its output in partial) unless <paramref name="allowError"/>.
    /// </summary>
    private static string Outcome(string image, string engine, NativeScriptResult r, bool saved, bool allowError, string what)
    {
        var sb = new StringBuilder();
        if (r.Error != null) sb.Append("Error:\n").Append(r.Error.TrimEnd()).Append('\n');
        if (r.Result != null) sb.Append("Result: ").Append(r.Result).Append('\n');
        if (r.Stdout.Length > 0) sb.Append("stdout:\n").Append(r.Stdout.TrimEnd()).Append('\n');
        if (r.Stderr.Length > 0) sb.Append("stderr:\n").Append(r.Stderr.TrimEnd()).Append('\n');
        if (saved) sb.Append("Database saved.\n");
        var text = sb.Length == 0 ? "Done (no result or output).\n" : sb.ToString();
        if (r.Error != null && !allowError)
        {
            var head = r.Error.TrimEnd().Split('\n') is var lines && lines.Length > 0 ? lines[^1].Trim() : "an exception";
            throw new ToolError(ErrorCode.Failed, $"{what}: {Format.Clip(head, 300)}", "fix the script and run it again; allowError=true returns the traceback as the result")
                { Partial = Format.Clip(text, 8_000) };
        }
        return ToolOutput.Report(text, new ScriptReport(image, engine, r.Result, r.Stdout.Length > 0 ? r.Stdout : null, r.Stderr.Length > 0 ? r.Stderr : null, r.Error, saved));
    }

    /// <summary>Largest script file=; a bigger one is data, not a script.</summary>
    private const int MaxScriptBytes = 1 << 20;

    [McpServerTool(Name = "ghidra_script", Title = "Run a Ghidra script on a native image", UseStructuredContent = true, OutputSchemaType = typeof(ScriptReport))]
    [Description("Run Java in the Ghidra worker holding a native image's program: a GhidraScript class, run()'s body with imports first " +
                 "(currentProgram, println, FlatProgramAPI), or name= an installed script (Ghidra's script folders, then <data>/ghidra_scripts) " +
                 "with args. One transaction, committed when the script returns, then saved; an exception rolls it back; a repeat skips compiling. " +
                 "Off unless --ghidra-scripting (CORVUS_GHIDRA_SCRIPTING=1): the code has the server's rights.")]
    public Task<string> GhidraScript(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Java source: a class extending GhidraScript, or statements for run().")] string? code = null,
        [Description("Instead of code: an installed script's file name, e.g. CountFunctions.java.")] string? name = null,
        [Description("With name: the script's arguments (getScriptArgs).")] string[]? args = null,
        [Description("Seconds before the script is cancelled (1-3600).")] int timeoutSeconds = 120,
        [Description("Default auto.")] string? engine = null,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        [Description("Return an exception as the result instead of an error.")] bool allowError = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        if (!options.GhidraScripting)
            throw new ToolError(ErrorCode.Unsupported, "ghidra_script is disabled on this server.",
                $"start the server with {ServerOptions.GhidraScriptingOption} or set {ServerOptions.GhidraScriptingVariable}=1 to allow scripts");
        if (string.IsNullOrWhiteSpace(code) == string.IsNullOrWhiteSpace(name))
            throw new ToolError(ErrorCode.InvalidArgument, "Pass code or name.", "code=<Java>, or name=<installed script file>");
        if (timeoutSeconds is < 1 or > 3600)
            throw new ToolError(ErrorCode.InvalidArgument, $"timeoutSeconds {timeoutSeconds} is outside 1-3600.", "timeoutSeconds=120");
        var id = string.IsNullOrWhiteSpace(engine) || engine.Trim().Equals("auto", StringComparison.OrdinalIgnoreCase) ? "ghidra" : engine.Trim();
        if (!id.Equals("ghidra", StringComparison.OrdinalIgnoreCase))
            throw new ToolError(ErrorCode.InvalidArgument, $"ghidra_script runs in Ghidra, not in '{id}'.", "omit engine or pass engine=ghidra");
        engines.Provider("ghidra");
        var (native, _) = await Task.Run(() => NativeAnalysisTools.Resolve(workspace, nativeCode, image, "rva:0"), cancellationToken);
        var session = await engines.Session(native, "ghidra", new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
        EngineReport.Answered(new EngineChoice("ghidra", "Ghidra scripts run in Ghidra"), engines, session);
        if (names != null) await names.EnsureAsync(native, session, cancellationToken);
        if (types != null) await types.EnsureAsync(native, session, cancellationToken);
        if (userTypes != null) await userTypes.EnsureAsync(native, session, cancellationToken);
        var r = session is Native.Providers.Ghidra.GhidraSession ghidra
            ? await ghidra.RunJavaAsync(code ?? "", timeoutSeconds, cancellationToken, name, args, Native.Providers.DataFolder.Combine("ghidra_scripts"))
            : await session.RunScriptAsync(code ?? "", false, cancellationToken);
        NativeUserTypePush.Touch(session);
        return Outcome(native.Id, "ghidra", r, r.Error == null, allowError, "the script failed (changes rolled back)");
    });
}
