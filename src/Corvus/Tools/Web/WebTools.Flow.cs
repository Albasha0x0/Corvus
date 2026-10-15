using System.Text;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services.Web;

namespace Corvus.Tools;

public sealed partial class WebTools
{
    /// <summary>view=flow (forward) and view=origins (back): the flows of a query, sinks or origins first, each step with its position.</summary>
    private string Flow(string path, string? query, int line, int column, bool back, int limit, int offset, int? maxTokens)
    {
        var view = back ? "origins" : "flow";
        if (string.IsNullOrWhiteSpace(query) && (line < 1 || column < 1))
            throw new ToolError(ErrorCode.InvalidArgument, $"view={view} needs query or line and column.",
                "pass query=<name>, a quoted literal, sinks, sink:<kind> or module:<id>, or line and column of an expression");
        var program = JsAnalysis.Program(path, default);
        var flow = new JsFlow(program, JsAnalysis.TryMap(path), path, default);
        var r = flow.Run(line > 0 && column > 0 ? null : query!.Trim(), line, column, back, Math.Clamp(limit, 1, 500), JsFlow.Budget.Default, default);
        var sb = new StringBuilder();
        sb.Append($"{view} of {r.Query}: {r.Seeds} seed(s), {r.Steps:N0} step(s); {r.Total} flow(s): {r.Sinks} to a sink, {r.Origins} from an origin, {r.Unknowns} unknown");
        sb.AppendLine(r.Partial != null ? $"; partial: {r.Partial}" : "; complete");
        int n = 0;
        foreach (var f in r.Flows)
        {
            sb.AppendLine($"flow {++n} ({f.End}):");
            foreach (var s in f.Steps)
                sb.AppendLine($"  {(back ? "<- " : "")}{s.Kind} {s.Text} at {s.Site}" + (s.Module != null ? $" [module {s.Module}]" : "") + (s.Original != null ? $" <- {s.Original}" : "") +
                              (s.Endpoint is { } e ? $"; endpoint {e.Verb} {e.Url} [{e.Client}]" : "") + (s.Link != null ? $"; {s.Link}" : ""));
        }
        if (r.Total > r.Flows.Count) sb.AppendLine($"{r.Total - r.Flows.Count} more flow(s): raise limit (up to 500) or narrow the query.");
        return ToolOutput.With(pager.Page(sb.ToString().TrimEnd(), offset, maxTokens), new JsResult(view, Total: r.Total) { Flow = r });
    }
}
