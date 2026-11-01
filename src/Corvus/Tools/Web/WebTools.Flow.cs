using System.Text;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services.Web;

namespace Corvus.Tools;

public sealed partial class WebTools
{
    /// <summary>view=flow (forward) and view=origins (back): the flows of a query, sinks or origins first, each step with its position.</summary>
    private async Task<string> Flow(string path, string? query, int line, int column, bool back, int limit, int offset, int? maxTokens, CancellationToken cancellationToken)
    {
        var view = back ? "origins" : "flow";
        if (string.IsNullOrWhiteSpace(query) && (line < 1 || column < 1))
            throw new ToolError(ErrorCode.InvalidArgument, $"view={view} needs query or line and column.",
                "pass query=<name>, a quoted literal, sinks, sink:<kind> or module:<id>, or line and column of an expression");
        var args = new FileWork.JsFlowArgs(path, line > 0 && column > 0 ? null : query!.Trim(), line, column, back, Math.Clamp(limit, 1, 500), Math.Max(0, offset));
        var r = await FileIsolation.RunAsync(serverOptions, workers, FileWork.JsFlow, args, path, () => FileWork.JsFlowWith(args, cancellationToken), cancellationToken);
        var blocks = new List<string>();
        int n = args.Offset;
        foreach (var f in r.Flows)
        {
            var sb = new StringBuilder().AppendLine($"flow {++n} ({f.End}):");
            foreach (var s in f.Steps)
                sb.AppendLine($"  {(back ? "<- " : "")}{s.Kind} {s.Text} at {s.Site}" + (s.Module != null ? $" [module {s.Module}]" : "") + (s.Original != null ? $" <- {s.Original}" : "") +
                              (s.Endpoint is { } e ? $"; endpoint {e.Verb} {e.Url} [{e.Client}]" : "") + (s.Link != null ? $"; {s.Link}" : ""));
            blocks.Add(sb.ToString());
        }
        int shown = blocks.Count == 0 ? 0 : Math.Max(1, pager.FitRows(blocks, 600, maxTokens));
        var head = new StringBuilder($"{view} of {r.Query}: {r.Seeds} seed(s), {r.Steps:N0} step(s); {r.Total} flow(s): {r.Sinks} to a sink, {r.Origins} from an origin, {r.Unknowns} unknown");
        head.AppendLine(r.Partial != null ? $"; partial: {r.Partial}" : "; complete");
        if (r.Partial != null)
            head.AppendLine($"Next: analyze_js path={path} view={view} query=module:<id> or sink:<kind> narrows the walk; line and column seed one expression.");
        if (shown == 0 && r.Total > 0) head.AppendLine($"No flow at offset {args.Offset}: {r.Total} flow(s) in all.");
        var text = head + string.Concat(blocks.Take(shown));
        int next = args.Offset + shown;
        if (next < r.Total) text += $"{r.Total - next} more flow(s): {OutputPager.More(next)}" + "\n";
        return ToolOutput.With(text.TrimEnd(), new JsResult(view, Total: r.Total) { Flow = r with { Flows = r.Flows.Take(shown).ToList() } });
    }
}
