using System.ComponentModel;
using System.Text;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services.Web;

namespace Corvus.Tools;

/// <summary>JavaScript bundles and their source maps, read statically.</summary>
[McpServerToolType]
public sealed class WebTools(OutputPager pager)
{
    /// <summary>analyze_js's record: the view's part is set, the others are null.</summary>
    public sealed record JsResult(string View, JsSummary? Summary = null, JsPosition? Position = null, IReadOnlyList<string>? Sources = null, JsSource? Source = null);

    [McpServerTool(Name = "analyze_js", Title = "Analyze a JavaScript bundle", UseStructuredContent = true, OutputSchemaType = typeof(JsResult))]
    [Description("Bundler signatures and the source map of a JavaScript file, read statically. view=summary: bundlers (webpack, esbuild, Vite, " +
                 "Parcel, Metro...), lines, the map (inline, sourceMappingURL or sibling .map); position: line:column to the original source; " +
                 "sources lists them; source pages one.")]
    public string AnalyzeJs(
        [Description("Absolute path to a .js file.")] string path,
        [Description("summary, position, sources or source.")] string view = "summary",
        [Description("position: generated line and column, 1-based.")] int line = 0,
        [Description("position: see line.")] int column = 0,
        [Description("source: a source path (or its end) or index.")] string? source = null,
        [Description(ToolSupport.CharOffsetDescription)] int offset = 0,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null)
    {
        switch (view.Trim().ToLowerInvariant())
        {
            case "summary":
            {
                var s = JsAnalysis.Summary(path);
                var sb = new StringBuilder();
                sb.AppendLine($"{Path.GetFileName(path)}: {s.Bytes:N0} bytes, {s.Lines:N0} lines (longest {s.LongestLine:N0})");
                sb.AppendLine(s.Bundlers.Count > 0
                    ? "Bundlers: " + string.Join("; ", s.Bundlers.GroupBy(b => b.Family).Select(g => $"{g.Key} ({string.Join(", ", g.Select(b => $"{b.Evidence} x{b.Count}"))})"))
                    : "Bundlers: no runtime signature");
                if (s.SourceMap is { } m)
                    sb.AppendLine($"Source map: {m.Location}; {m.Sources} sources ({m.SourcesWithContent} with content), {m.Segments:N0} segments" +
                                  (m.Issues.Count > 0 ? $"; {m.Issues.Count} issue(s): {m.Issues[0]}" : ""));
                if (s.Banners > 0) sb.AppendLine($"License banners: {s.Banners}");
                foreach (var n in s.Notes) sb.AppendLine("Note: " + n);
                return ToolOutput.With(sb.ToString().TrimEnd(), new JsResult("summary", Summary: s));
            }
            case "position":
            {
                var p = JsAnalysis.Position(path, line, column);
                var text = p.Source == null
                    ? $"{line}:{column} has no mapping."
                    : $"{line}:{column} -> {p.Source}:{p.OriginalLine}:{p.OriginalColumn}" + (p.Name != null ? $" ({p.Name})" : "");
                return ToolOutput.With(text, new JsResult("position", Position: p));
            }
            case "sources":
            {
                var map = JsAnalysis.Map(path);
                var rows = map.Sources.Select((s, i) => $"  [{i}] {s}{(i < map.SourcesContent.Count && map.SourcesContent[i] != null ? "" : " (no content)")}");
                return ToolOutput.With(pager.Page($"{map.Sources.Count} sources:\n" + string.Join("\n", rows), offset, maxTokens),
                    new JsResult("sources", Sources: map.Sources));
            }
            case "source":
            {
                if (string.IsNullOrWhiteSpace(source)) throw new ToolError(ErrorCode.InvalidArgument, "view=source needs source.", "pass source=<path or index> (view=sources lists them)");
                var s = JsAnalysis.Source(path, source.Trim());
                if (s.Content == null)
                    throw new ToolError(ErrorCode.NotFound, $"the map names {s.Source} but carries no sourcesContent for it.", "the original file is not in the map");
                return ToolOutput.With(pager.Page($"// {s.Source}\n{s.Content}", offset, maxTokens), new JsResult("source", Source: s with { Content = null }));
            }
            default:
                throw new ToolError(ErrorCode.InvalidArgument, $"unknown view '{view}'.", "pass view=summary, position, sources or source");
        }
    }
}
