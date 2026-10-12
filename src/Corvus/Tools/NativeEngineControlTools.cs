using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>Control of the engine's own analysis: its analyzer settings and a new auto-analysis run.</summary>
[McpServerToolType]
public sealed class NativeEngineControlTools(AssemblyWorkspace workspace, NativeEngineService engines, NativeCodeService? code = null)
{
    [McpServerTool(Name = "reanalyze_native", Title = "Re-run native auto-analysis")]
    [Description("Re-run IDA's or Ghidra's auto-analysis over an image (or start-end) and save; a full run also completes a Ghidra " +
                 "analysis the open's budget cut short. options= sets analyzers for this run; analyzers=true lists them.")]
    public Task<string> ReanalyzeNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Default: the engine with this image open, else IDA, else Ghidra.")] string? engine = null,
        [Description("List the analyzer options and values instead of running.")] bool analyzers = false,
        [Description("With analyzers: name filter.")] string? filter = null,
        [Description("name=value per option (AF_FLIRT=false, 'Decompiler Parameter ID=true').")] string[]? options = null,
        [Description("Range start (default: the whole image).")] string? start = null,
        [Description("Range end (exclusive).")] string? end = null,
        [Description("Seconds (max 3600); what is left runs on the next run.")] int seconds = 600,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var nameFilter = NameFilter.Parse(filter);
        var pairs = new List<KeyValuePair<string, string>>();
        foreach (var o in options ?? [])
        {
            int eq = o.IndexOf('=');
            if (eq <= 0) throw new ToolError(ErrorCode.InvalidArgument, $"option '{o}' is not name=value.", "options=[\"AF_FLIRT=false\"]");
            pairs.Add(new(o[..eq].Trim(), o[(eq + 1)..].Trim()));
        }
        if (analyzers && (pairs.Count > 0 || start != null || end != null))
            throw new ToolError(ErrorCode.InvalidArgument, "analyzers=true lists the options; it takes no options, start or end.");
        if (end != null && start == null) throw new ToolError(ErrorCode.InvalidArgument, "end needs start.");
        var native = await Task.Run(() => NativeAnalysisTools.ResolveImage(workspace, image), cancellationToken);
        var index = code?.Ready(native);
        uint? Address(string? text) => string.IsNullOrWhiteSpace(text) ? null : NativeAddress.Parse(native.Image, text, index != null ? index.AddressesOfName : null);
        uint? from = Address(start), to = Address(end);
        if (from is { } f && to is { } t && t <= f) throw new ToolError(ErrorCode.InvalidArgument, "end is not after start.");
        var session = await engines.Session(native, engine, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = p.Stage })), cancellationToken);
        var control = EngineControl.Require(session, "analysis control");

        if (analyzers)
        {
            var all = await control.AnalyzersAsync(cancellationToken);
            var rows = all.Where(a => nameFilter == null || nameFilter.IsMatch(a.Name))
                .Select(a => $"{a.Name} = {a.Value}  ({a.Type}){(string.IsNullOrWhiteSpace(a.Description) ? "" : "  " + Format.Clip(a.Description.ReplaceLineEndings(" "), 160))}")
                .ToList();
            // No offset: the whole list; past the page the call filter keeps it for read_result.
            return $"// {native.Id}: {session.ProviderId} analysis options" + (nameFilter != null ? $" matching '{nameFilter.Text}'" : "") + "\n" +
                   $"{Plural(rows.Count, "option")}:\n" + string.Concat(rows.Select(r => "  " + r + "\n")) + (nameFilter?.Note("option name") ?? "");
        }

        progress.Report(new ProgressNotificationValue { Progress = 0, Message = $"{session.ProviderId} reanalysis" });
        var r = await control.ReanalyzeAsync(pairs, from, from is { } s ? to ?? s + 1 : null, Math.Clamp(seconds, 1, 3600), cancellationToken);
        EngineControl.Advance(session);
        var sb = new StringBuilder($"// {native.Id}: {session.ProviderId} reanalysis of " +
                                   (from is { } a ? $"{NativeAddress.Va(native.Image, a)}-{NativeAddress.Va(native.Image, to ?? a + 1)}" : "the whole image") +
                                   $" in {r.Elapsed.TotalSeconds:0.0} s; database saved\n");
        sb.AppendLine(r.Complete ? "Complete: the analysis queue ran empty." : $"Partial: the {Math.Clamp(seconds, 1, 3600)} s budget ran out; run again to continue.");
        sb.AppendLine($"Functions: {r.FunctionsBefore:N0} before, {r.FunctionsAfter:N0} after ({r.FunctionsAfter - r.FunctionsBefore:+#;-#;0})");
        if (pairs.Count > 0) sb.AppendLine($"Options for this run: {string.Join(", ", pairs.Select(p => $"{p.Key}={p.Value}"))} (restored afterwards)");
        foreach (var w in r.Warnings) sb.AppendLine("Warning: " + w);
        sb.AppendLine("Cached pseudocode of this image is discarded; list_functions engine=" + session.ProviderId + " shows the functions now.");
        return sb.ToString();
    });
}
