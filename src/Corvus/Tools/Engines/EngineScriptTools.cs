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
    NativeNamePush? names = null, NativeTypePush? types = null, NativeUserTypePush? userTypes = null, ResourceSubscriptions? subscriptions = null)
{
    [Description("A script's outcome; past the page the whole text is kept under resultId.")]
    public sealed record ScriptReport(string Image, string Engine,
        string? Result,
        string? Stdout, string? Stderr,
        string? Error,
        bool Saved);

    [McpServerTool(Name = "ida_python", Title = "Run IDAPython on a native image", UseStructuredContent = true, OutputSchemaType = typeof(ScriptReport))]
    [Description("Run IDAPython on the image database; returns the last expression's value, stdout and stderr. Off unless " +
                 "--ida-scripting (CORVUS_IDA_SCRIPTING=1); runs with server rights, not undoable.")]
    public Task<string> IdaPython(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Python source (or scriptPath); base is the image base.")] string? code = null,
        [Description("Clear globals kept from earlier calls.")] bool reset = false,
        [Description("Default auto.")] string? engine = null,
        [Description("A .py file to run instead of code.")] string? scriptPath = null,
        [Description("Save the database afterwards.")] bool persist = false,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        [Description("Return the exception as the result.")] bool allowError = false,
        [Description(TimeoutDescription)] int? timeoutSeconds = null,
        [Description(BackgroundDescription)] bool background = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        CheckBackground(background, allowError, timeoutSeconds);
        bool hasCode = !string.IsNullOrEmpty(code);
        if (hasCode == !string.IsNullOrWhiteSpace(scriptPath))
            throw new ToolError(ErrorCode.InvalidArgument, hasCode ? "Pass code or scriptPath, not both." : "Pass code or scriptPath.");
        if (!options.IdaScripting)
            throw new ToolError(ErrorCode.Unsupported, "ida_python is disabled on this server.",
                $"ask the user to start the server with --ida-scripting (or {ServerOptions.IdaScriptingVariable}=1) to allow scripts");
        if (scriptPath != null)
        {
            var path = Path.GetFullPath(scriptPath.Trim());
            if (!File.Exists(path)) throw Targets.FileNotFound(path);
            if (new FileInfo(path).Length > MaxScriptBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{path} is over {MaxScriptBytes / 1024} KB.");
            code = await File.ReadAllTextAsync(path, cancellationToken);
        }
        // IDAPython runs in IDA only, whatever the server's default engine.
        var ida = string.IsNullOrWhiteSpace(engine) || engine.Trim().Equals("auto", StringComparison.OrdinalIgnoreCase) ? "ida" : engine.Trim();
        if (!ida.Equals("ida", StringComparison.OrdinalIgnoreCase))
            throw new ToolError(ErrorCode.InvalidArgument, $"ida_python runs in IDA, not in '{ida}'.", "omit engine or pass engine=ida");
        engines.Provider(ida);
        var (native, _) = await Task.Run(() => NativeAnalysisTools.Resolve(workspace, nativeCode, image, "rva:0"), cancellationToken);
        var session = await engines.Session(native, "ida", new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
        EngineReport.Answered(new EngineChoice("ida", "IDAPython runs in IDA"), engines, session);
        if (RunningScript(session) != null) return Joined(native.Id, "ida", session, background);
        // Push first, so the script sees the database as the other engine tools leave it.
        if (names != null) await names.EnsureAsync(native, session, cancellationToken);
        if (types != null) await types.EnsureAsync(native, session, cancellationToken);
        if (userTypes != null) await userTypes.EnsureAsync(native, session, cancellationToken);
        async Task<NativeScriptResult> Run(CancellationToken ct)
        {
            var r = await session.RunScriptAsync(code ?? "", reset, ct);
            // Cached engine output may be stale now.
            NativeUserTypePush.Touch(session);
            if (persist) await session.SaveAsync(ct);
            return r;
        }
        if (background) return StartBackground(native.Id, "ida", session, timeoutSeconds, persist, Run);
        using var limit = EngineRequestLimit.Use(timeoutSeconds is { } t ? TimeSpan.FromSeconds(t) : null);
        return Outcome(native.Id, "ida", await Timed(() => Run(cancellationToken), timeoutSeconds), persist, allowError, "the script raised");
    });

    private const string TimeoutDescription = "Seconds before it is cancelled; default 120.";

    private const string BackgroundDescription = "Return at once; a notice reports the end.";

    private static void CheckBackground(bool background, bool allowError, int? seconds)
    {
        if (seconds is < 1)
            throw new ToolError(ErrorCode.InvalidArgument, $"timeoutSeconds {seconds} is below 1.", $"timeoutSeconds={SuggestedSeconds(null)}, or background=true for no time limit");
        if (background && allowError)
            throw new ToolError(ErrorCode.InvalidArgument, "allowError does not apply with background.", "omit allowError; get_engine_status shows the traceback of a failed script");
    }

    // Doubling clears a limit that was just missed; the floor keeps a short limit from inviting a second miss.
    private static int SuggestedSeconds(int? seconds) => Math.Max(600, 2 * (seconds ?? 120));

    /// <summary>Runs a foreground script; a timeout names the larger limit and the background call.</summary>
    private static async Task<NativeScriptResult> Timed(Func<Task<NativeScriptResult>> run, int? seconds)
    {
        try { return await run(); }
        catch (ToolError e) when (e.Code == ErrorCode.Timeout)
        {
            throw new ToolError(e.Code, e.Message, $"timeoutSeconds={SuggestedSeconds(seconds)} allows longer; background=true runs it until it ends or stalls")
                { Details = e.Details, Partial = e.Partial };
        }
    }

    private static BackgroundJob? RunningScript(INativeDecompilerSession session) =>
        session is IBackgroundJobs { Jobs.Job: { What: "script", Task.IsCompleted: false } running } ? running : null;

    /// <summary>A call made while a script runs: background=true reports it and starts nothing; a foreground call is a conflict.</summary>
    private static string Joined(string image, string engine, INativeDecompilerSession session, bool background)
    {
        var running = RunningScript(session)!;
        var elapsed = (DateTime.UtcNow - running.Started).TotalSeconds;
        var wait = $"get_engine_status image={image} waitSeconds=60 waits for the end; cancel=true stops it";
        if (!background)
            throw new ToolError(ErrorCode.Conflict, $"A {engine} script of {image} is already running ({elapsed:0} s).", $"background=true reports it; {wait}");
        return ToolOutput.Report($"// {image}: {engine} script already running ({elapsed:0} s); this call's script was not started\n{wait}.\n",
            new ScriptReport(image, engine, null, null, null, null, false));
    }

    /// <summary>Starts the script as the session's background job; the end is a workspace notice.</summary>
    private string StartBackground(string image, string engine, INativeDecompilerSession session, int? timeoutSeconds, bool saved,
        Func<CancellationToken, Task<NativeScriptResult>> run)
    {
        if (session is not IBackgroundJobs { Jobs: var jobs })
            throw new ToolError(ErrorCode.Unsupported, $"{session.ProviderId} runs no background scripts.", "omit background");
        var wait = $"get_engine_status image={image} waitSeconds=60";
        var report = new ScriptReport(image, engine, null, null, null, null, false);
        TimeSpan? budget = timeoutSeconds is { } s ? TimeSpan.FromSeconds(s) : null;
        jobs.Start("script", image, budget, async ct =>
        {
            // With no budget only the stall check ends the request.
            using var limit = EngineRequestLimit.Use(budget ?? Timeout.InfiniteTimeSpan);
            NativeScriptResult r;
            try { r = await run(ct); }
            catch (ToolError e) when (e.Code == ErrorCode.Timeout)
            {
                return ("partial", "partial; " + e.Message);
            }
            var kind = r.Error == null ? "complete" : "failed";
            return (kind, $"{kind}; " + Format.Clip(ScriptText(r, saved && r.Error == null).TrimEnd(), 8_000));
        }, end =>
        {
            workspace.Notify(NativeEngineControlTools.BackgroundEndNotice(end.File, image, engine, end.Kind, end.Text, end.Remediation, ScriptNext(end.Kind, image, end.Text)));
            subscriptions?.Announce($"{end.File}: {end.Text}");
        });
        return ToolOutput.Report($"// {image}: {engine} script started in the background ({(budget is { } b ? $"{b.TotalSeconds:0} s budget" : "no time limit")})\n" +
                                 $"{wait} waits for the end and shows its output; cancel=true stops it. Other engine calls on this image get a conflict error until it ends.\n", report);
    }

    /// <summary>The call a script's end notice names, by outcome.</summary>
    private static string ScriptNext(string kind, string image, string text) => kind switch
    {
        "complete" => $"get_engine_status image={image} shows the output",
        "failed" => $"get_engine_status image={image} shows the error; fix the script and call again with background=true",
        "partial" when text.Contains(StallRule.MessagePrefix, StringComparison.Ordinal) =>
            $"get_engine_status image={image} shows the engine state; check the engine, then call again with background=true",
        "partial" => "call again with background=true and a larger timeoutSeconds, or without it to end on the stall check",
        _ => $"call again with background=true; get_engine_status image={image} shows the state",
    };

    private static string ScriptText(NativeScriptResult r, bool saved)
    {
        var sb = new StringBuilder();
        if (r.Error != null) sb.Append("Error:\n").Append(r.Error.TrimEnd()).Append('\n');
        if (r.Result != null) sb.Append("Result: ").Append(r.Result).Append('\n');
        if (r.Stdout.Length > 0) sb.Append("stdout:\n").Append(r.Stdout.TrimEnd()).Append('\n');
        if (r.Stderr.Length > 0) sb.Append("stderr:\n").Append(r.Stderr.TrimEnd()).Append('\n');
        if (saved) sb.Append("Database saved.\n");
        return sb.Length == 0 ? "Done (no result or output).\n" : sb.ToString();
    }

    /// <summary>A script's outcome; an exception is an error with the output as partial, unless <paramref name="allowError"/>.</summary>
    private static string Outcome(string image, string engine, NativeScriptResult r, bool saved, bool allowError, string what)
    {
        var text = ScriptText(r, saved);
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
    [Description("Run a Java or Python Ghidra script on the image in one transaction: saved on return, rolled back on an exception. " +
                 "Off unless --ghidra-scripting (CORVUS_GHIDRA_SCRIPTING=1); runs with server rights.")]
    public Task<string> GhidraScript(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Java (a GhidraScript class, or a run() body with imports first) or Python source.")] string? code = null,
        [Description("Instead of code: a script in the Ghidra script folders or DATA/ghidra_scripts.")] string? name = null,
        [Description("With name: script arguments (getScriptArgs).")] string[]? args = null,
        [Description(TimeoutDescription)] int? timeoutSeconds = null,
        [Description("java (default) or python (needs CORVUS_GHIDRA_PYTHON); name *.py is Python.")] string? language = null,
        [Description("Default auto.")] string? engine = null,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        [Description("Return the exception as the result.")] bool allowError = false,
        [Description(BackgroundDescription)] bool background = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        CheckBackground(background, allowError, timeoutSeconds);
        if (!options.GhidraScripting)
            throw new ToolError(ErrorCode.Unsupported, "ghidra_script is disabled on this server.",
                $"ask the user to start the server with {ServerOptions.GhidraScriptingOption} (or {ServerOptions.GhidraScriptingVariable}=1) to allow scripts");
        if (string.IsNullOrWhiteSpace(code) == string.IsNullOrWhiteSpace(name))
            throw new ToolError(ErrorCode.InvalidArgument, "Pass code or name.", "code=<Java>, or name=<installed script file>");
        var id = string.IsNullOrWhiteSpace(engine) || engine.Trim().Equals("auto", StringComparison.OrdinalIgnoreCase) ? "ghidra" : engine.Trim();
        if (!id.Equals("ghidra", StringComparison.OrdinalIgnoreCase))
            throw new ToolError(ErrorCode.InvalidArgument, $"ghidra_script runs in Ghidra, not in '{id}'.", "omit engine or pass engine=ghidra");
        bool python = (language?.Trim().ToLowerInvariant() switch
        {
            null or "" or "java" => false,
            "python" or "py" => true,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"unknown language '{language}'.", "language=java or language=python"),
        }) || name?.Trim().EndsWith(".py", StringComparison.OrdinalIgnoreCase) == true;
        var provider = engines.Provider("ghidra");
        if (python && provider is Native.Providers.Ghidra.GhidraProvider { PythonHost: null } plain)
            throw new ToolError(ErrorCode.Unsupported,
                "Python scripts need PyGhidra; the Ghidra workers here run in a plain JVM" +
                (plain.PythonProblem is { } problem ? $" ({problem})." : "."),
                $"set {Native.Providers.Ghidra.GhidraOptions.PythonVariable} to a Python 3.9+ with PyGhidra (python -m pip install --no-index -f <ghidra>/Ghidra/Features/PyGhidra/pypkg/dist pyghidra) and restart the server; or write the script in Java");
        var (native, _) = await Task.Run(() => NativeAnalysisTools.Resolve(workspace, nativeCode, image, "rva:0"), cancellationToken);
        var session = await engines.Session(native, "ghidra", new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
        EngineReport.Answered(new EngineChoice("ghidra", "Ghidra scripts run in Ghidra"), engines, session);
        if (RunningScript(session) != null) return Joined(native.Id, "ghidra", session, background);
        if (names != null) await names.EnsureAsync(native, session, cancellationToken);
        if (types != null) await types.EnsureAsync(native, session, cancellationToken);
        if (userTypes != null) await userTypes.EnsureAsync(native, session, cancellationToken);
        async Task<NativeScriptResult> Run(double? seconds, CancellationToken ct)
        {
            var r = session is Native.Providers.Ghidra.GhidraSession ghidra
                ? await ghidra.RunJavaAsync(code ?? "", seconds, ct, name, args, Native.Providers.DataFolder.Combine("ghidra_scripts"), python ? "python" : null)
                : await session.RunScriptAsync(code ?? "", false, ct);
            NativeUserTypePush.Touch(session);
            return r;
        }
        if (background) return StartBackground(native.Id, "ghidra", session, timeoutSeconds, true, ct => Run(timeoutSeconds, ct));
        var r = await Timed(() => Run(timeoutSeconds ?? 120, cancellationToken), timeoutSeconds ?? 120);
        return Outcome(native.Id, "ghidra", r, r.Error == null, allowError, "the script failed (changes rolled back)");
    });
}
