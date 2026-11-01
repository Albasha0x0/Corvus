using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>Control of the engine's own analysis: its analyzer settings and a new auto-analysis run.</summary>
[McpServerToolType]
public sealed class NativeEngineControlTools(AssemblyWorkspace workspace, NativeEngineService engines, NativeCodeService? code = null, ResourceSubscriptions? subscriptions = null)
{
    public sealed record AnalyzerEntry(string Name, string Value, string Type);

    [Description("A started reanalysis, or with analyzers=true the analyzer options (items).")]
    public sealed record ReanalysisReport(string Image, string Engine,
        string? Scope,
        IReadOnlyList<string>? Options,
        IReadOnlyList<AnalyzerEntry>? Items,
        int? Offset,
        int? Total);

    /// <summary>The workspace notice for a background job that ended: its outcome, then the next call that outcome calls for (<paramref name="next"/> replaces the analysis default).</summary>
    internal static string BackgroundEndNotice(string file, string imageId, string engine, string kind, string result, string? remediation = null, string? next = null) =>
        $"{file}: {engine} {result}; next: {next ?? NativeEngineService.EndNext(kind, imageId, engine)}" + (remediation is { Length: > 0 } ? $"; {remediation}" : "");

    [McpServerTool(Name = "reanalyze_native", Title = "Re-run native auto-analysis", UseStructuredContent = true, OutputSchemaType = typeof(ReanalysisReport))]
    [Description("Start IDA or Ghidra auto-analysis over an image or range in the background and save; completes a cut-short analysis. analyzers=true lists the options.")]
    public Task<string> ReanalyzeNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(EngineChoice.EngineOnlyDescription)] string? engine = null,
        [Description("List analyzer options instead of running.")] bool analyzers = false,
        [Description("With analyzers: name filter.")] string? filter = null,
        [Description("name=value per analyzer option for this run (AF_FLIRT=false).")] string[]? options = null,
        [Description("full (Ghidra defaults) or a preset in analysis-presets.json.")] string? preset = null,
        [Description("Range start (default: whole image).")] string? from = null,
        [Description("Range end (exclusive).")] string? to = null,
        [Description("Budget in seconds; omit to run until done or stalled. Other engine calls conflict until done.")] int? timeoutSeconds = null,
        [Description("With analyzers: rows to skip.")] int offset = 0,
        [Description("With analyzers: max rows.")] int limit = 200,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        if (timeoutSeconds is < 1)
            throw new ToolError(ErrorCode.InvalidArgument, $"timeoutSeconds {timeoutSeconds} is below 1.", "timeoutSeconds=600; what is left runs on the next reanalysis, or omit it to run until done");
        var nameFilter = NameFilter.Parse(filter);
        var pairs = new List<KeyValuePair<string, string>>();
        foreach (var o in options ?? [])
        {
            int eq = o.IndexOf('=');
            if (eq <= 0) throw new ToolError(ErrorCode.InvalidArgument, $"option '{o}' is not name=value.", "options=[\"AF_FLIRT=false\"]");
            pairs.Add(new(o[..eq].Trim(), o[(eq + 1)..].Trim()));
        }
        if (analyzers && (pairs.Count > 0 || from != null || to != null || preset != null))
            throw new ToolError(ErrorCode.InvalidArgument, "analyzers=true lists the options; it takes no options, preset, from or to.");
        if (to != null && from == null) throw new ToolError(ErrorCode.InvalidArgument, "to needs from.");
        EngineChoice.Mode(engine, engines);
        var native = await Task.Run(() => NativeAnalysisTools.ResolveImage(workspace, image), cancellationToken);
        var index = code?.Ready(native);
        uint? Address(string? text) => string.IsNullOrWhiteSpace(text) ? null : NativeAddress.Parse(native.Image, text, index != null ? index.AddressesOfName : null);
        uint? start = Address(from), end = Address(to);
        if (start is { } f && end is { } t && t <= f) throw new ToolError(ErrorCode.InvalidArgument, "to is not after from.");
        var choice = EngineChoice.EngineOnly(engine, engines, native);
        var session = await engines.Session(native, choice.Engine, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
        EngineReport.Answered(choice, engines, session);
        var control = EngineControl.Require(session, "analysis control");

        if (analyzers)
        {
            var all = (await control.AnalyzersAsync(cancellationToken)).Where(a => nameFilter == null || nameFilter.IsMatch(a.Name))
                .ToList();
            offset = Math.Max(0, offset);
            var header = $"// {native.Id}: {session.ProviderId} analysis options" + (nameFilter != null ? $" matching '{nameFilter.Text}'" : "") + "\n" +
                         (nameFilter?.Note("option name") ?? "");
            return ToolOutput.List(all.Skip(offset).ToList(), offset, limit, all.Count,
                a => $"{a.Name} = {a.Value}  ({a.Type}){(string.IsNullOrWhiteSpace(a.Description) ? "" : "  " + Format.Clip(a.Description.ReplaceLineEndings(" "), 160))}",
                page => new ReanalysisReport(native.Id, session.ProviderId, null, null,
                    [.. page.Select(a => new AnalyzerEntry(a.Name, a.Value, a.Type))], offset, all.Count), "option", header);
        }

        if (preset != null)
            pairs = [.. AnalysisPresets.Options(preset, session.ProviderId).Where(p => !pairs.Any(o => o.Key == p.Key)), .. pairs];
        var scope = start is { } a ? $"{NativeAddress.Va(native.Image, a)}-{NativeAddress.Va(native.Image, end ?? a + 1)}" : null;
        uint? stop = start is { } s ? end ?? s + 1 : null;
        if (session is not IBackgroundJobs { Jobs: var jobs }) throw new ToolError(ErrorCode.Unsupported, $"{session.ProviderId} has no reanalysis.", $"engine=ida or engine=ghidra; get_engine_status image={native.Id} lists the sessions");
        var optionTexts = pairs.Count > 0 ? (IReadOnlyList<string>)[.. pairs.Select(p => $"{p.Key}={p.Value}")] : null;
        var wait = $"get_engine_status image={native.Id} waitSeconds=60";
        // A repeat of the running reanalysis joins it.
        if (jobs.Job is { What: "reanalysis", Task.IsCompleted: false } running)
        {
            var age = (DateTime.UtcNow - running.Started).TotalSeconds;
            return ToolOutput.Report($"// {native.Id}: {session.ProviderId} reanalysis already running ({age:0} s)\n{wait} waits for the end; cancel=true stops it.\n",
                new ReanalysisReport(native.Id, session.ProviderId, scope, optionTexts, null, null, null));
        }
        jobs.Start("reanalysis", native.Id, timeoutSeconds is { } budget ? TimeSpan.FromSeconds(budget) : null, async job =>
        {
            var done = await control.ReanalyzeAsync(pairs, start, stop, timeoutSeconds, job);
            EngineControl.Advance(session);
            var warnings = done.Warnings.Count > 0 ? $"; {done.Warnings.Count} warning(s), first: {Format.Clip(done.Warnings[0], 160)}" : "";
            return (done.Complete ? "complete" : "partial",
                $"{(done.Complete ? "complete" : "partial, the budget ran out")}; functions {done.FunctionsBefore:N0} before, {done.FunctionsAfter:N0} after{warnings}");
        }, end =>
        {
            // The notice reaches the model on its next reply; Announce
            // reaches subscribed clients only.
            workspace.Notify(BackgroundEndNotice(end.File, native.Id, session.ProviderId, end.Kind, end.Text, end.Remediation));
            subscriptions?.Announce($"{end.File}: {end.Text}");
        });
        var budgetText = timeoutSeconds is { } secs ? $"{secs} s budget" : "no time limit";
        return ToolOutput.Report($"// {native.Id}: {session.ProviderId} reanalysis of {scope ?? "the whole image"} started in the background ({budgetText})\n" +
                                 (pairs.Count > 0 ? $"Options for this run: {string.Join(", ", pairs.Select(p => $"{p.Key}={p.Value}"))} (restored afterwards)\n" : "") +
                                 $"{wait} waits for the end; cancel=true stops it. Other engine calls on this image get conflict with retryAfterMs until it ends.\n",
            new ReanalysisReport(native.Id, session.ProviderId, scope, optionTexts, null, null, null));
    });
}
