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
public sealed class NativeEngineControlTools(AssemblyWorkspace workspace, NativeEngineService engines, NativeCodeService? code = null)
{
    public sealed record AnalyzerEntry(string Name, string Value, string Type);

    [Description("A reanalysis run, or with analyzers=true the analyzer options (items).")]
    public sealed record ReanalysisReport(string Image, string Engine,
        string? Scope,
        bool? Complete,
        int? FunctionsBefore, int? FunctionsAfter,
        IReadOnlyList<string>? Options,
        IReadOnlyList<string>? Warnings,
        IReadOnlyList<AnalyzerEntry>? Items,
        int? Offset,
        int? Total)
    {
        [Description("Seconds the run took (moved to _meta).")] public double? ElapsedSeconds { get; init; }
    }

    [McpServerTool(Name = "reanalyze_native", Title = "Re-run native auto-analysis", UseStructuredContent = true, OutputSchemaType = typeof(ReanalysisReport))]
    [Description("Re-run IDA's or Ghidra's auto-analysis over an image (or from-to) and save; a full run also completes a Ghidra " +
                 "analysis the open's budget cut short. options= sets analyzers for this run; analyzers=true lists them.")]
    public Task<string> ReanalyzeNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(EngineChoice.EngineOnlyDescription)] string? engine = null,
        [Description("List the analyzer options and values instead of running.")] bool analyzers = false,
        [Description("With analyzers: name filter.")] string? filter = null,
        [Description("name=value per option (AF_FLIRT=false, 'Decompiler Parameter ID=true').")] string[]? options = null,
        [Description("full (Ghidra defaults) or a preset in analysis-presets.json (data folder).")] string? preset = null,
        [Description("Run with no caller waiting; other engine calls get conflict until it ends.")] bool background = false,
        [Description("Range start (default: the whole image).")] string? from = null,
        [Description("Range end (exclusive).")] string? to = null,
        [Description("Seconds (1-3600); what is left runs on the next run.")] int timeoutSeconds = 600,
        [Description("With analyzers: rows to skip.")] int offset = 0,
        [Description("With analyzers: max rows.")] int limit = 200,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        if (timeoutSeconds is < 1 or > 3600)
            throw new ToolError(ErrorCode.InvalidArgument, $"timeoutSeconds {timeoutSeconds} is outside 1-3600.", "timeoutSeconds=600; what is left runs on the next reanalysis");
        var nameFilter = NameFilter.Parse(filter);
        var pairs = new List<KeyValuePair<string, string>>();
        foreach (var o in options ?? [])
        {
            int eq = o.IndexOf('=');
            if (eq <= 0) throw new ToolError(ErrorCode.InvalidArgument, $"option '{o}' is not name=value.", "options=[\"AF_FLIRT=false\"]");
            pairs.Add(new(o[..eq].Trim(), o[(eq + 1)..].Trim()));
        }
        if (analyzers && (pairs.Count > 0 || from != null || to != null || preset != null || background))
            throw new ToolError(ErrorCode.InvalidArgument, "analyzers=true lists the options; it takes no options, preset, background, from or to.");
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
                page => new ReanalysisReport(native.Id, session.ProviderId, null, null, null, null, null, null,
                    [.. page.Select(a => new AnalyzerEntry(a.Name, a.Value, a.Type))], offset, all.Count), "option", header);
        }

        if (preset != null)
            pairs = [.. AnalysisPresets.Options(preset, session.ProviderId).Where(p => !pairs.Any(o => o.Key == p.Key)), .. pairs];
        var scope = start is { } a ? $"{NativeAddress.Va(native.Image, a)}-{NativeAddress.Va(native.Image, end ?? a + 1)}" : null;
        uint? stop = start is { } s ? end ?? s + 1 : null;
        if (background)
        {
            if (session is not WorkerSessionBase worker) throw new ToolError(ErrorCode.Unsupported, $"{session.ProviderId} has no background reanalysis.", "omit background");
            worker.StartBackground("reanalysis", TimeSpan.FromSeconds(timeoutSeconds), async () =>
            {
                var done = await control.ReanalyzeAsync(pairs, start, stop, timeoutSeconds, CancellationToken.None);
                EngineControl.Advance(session);
                return $"{(done.Complete ? "complete" : "partial, the budget ran out")}; functions {done.FunctionsBefore:N0} before, {done.FunctionsAfter:N0} after";
            });
            return ToolOutput.Report($"// {native.Id}: {session.ProviderId} reanalysis of {scope ?? "the whole image"} started in the background ({timeoutSeconds} s budget)\n" +
                                     (pairs.Count > 0 ? $"Options for this run: {string.Join(", ", pairs.Select(p => $"{p.Key}={p.Value}"))} (restored afterwards)\n" : "") +
                                     "server_status shows the session busy, then the result; other engine calls on this image get conflict with retryAfterMs until it ends.\n",
                new ReanalysisReport(native.Id, session.ProviderId, scope, null, null, null, pairs.Count > 0 ? [.. pairs.Select(p => $"{p.Key}={p.Value}")] : null,
                    null, null, null, null));
        }
        var r = await control.ReanalyzeAsync(pairs, start, stop, timeoutSeconds, cancellationToken);
        EngineControl.Advance(session);
        var sb = new StringBuilder($"// {native.Id}: {session.ProviderId} reanalysis of {scope ?? "the whole image"}; database saved\n");
        sb.Append(r.Complete ? "Complete: the analysis queue ran empty.\n" : $"Partial: the {timeoutSeconds} s budget ran out; run again to continue.\n");
        sb.Append($"Functions: {r.FunctionsBefore:N0} before, {r.FunctionsAfter:N0} after ({r.FunctionsAfter - r.FunctionsBefore:+#;-#;0})\n");
        if (pairs.Count > 0) sb.Append($"Options for this run: {string.Join(", ", pairs.Select(p => $"{p.Key}={p.Value}"))} (restored afterwards)\n");
        foreach (var w in r.Warnings) sb.Append("Warning: " + w + "\n");
        sb.Append("Cached pseudocode of this image is discarded; list_functions engine=" + session.ProviderId + " shows the functions now.\n");
        return ToolOutput.Report(sb.ToString(), new ReanalysisReport(native.Id, session.ProviderId, scope, r.Complete, r.FunctionsBefore, r.FunctionsAfter,
            pairs.Count > 0 ? [.. pairs.Select(p => $"{p.Key}={p.Value}")] : null, r.Warnings.Count > 0 ? r.Warnings : null, null, null, null)
            { ElapsedSeconds = Math.Round(r.Elapsed.TotalSeconds, 1) });
    });
}
