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
    /// <summary>analyze_js's record: the view's part is set (sources and source carry their text only).</summary>
    public sealed record JsResult(string View, JsSummary? Summary = null, JsPosition? Position = null, IReadOnlyList<JsModule>? Modules = null, int? Total = null);

    [McpServerTool(Name = "analyze_js", Title = "Analyze a JavaScript bundle", UseStructuredContent = true, OutputSchemaType = typeof(JsResult))]
    [Description("Bundler signatures, modules and source map of a JavaScript file, statically. view=summary; modules: its module table " +
                 "(webpack, esbuild, Browserify, Metro) with requires; module: one's code; search: strings and names; refs: a module's users; " +
                 "position: line:column to the original source; sources, source.")]
    public string AnalyzeJs(
        [Description("Absolute path to a .js file.")] string path,
        [Description("View; default summary.")] string view = "summary",
        [Description("position: generated line and column, 1-based.")] int line = 0,
        [Description("position: see line.")] int column = 0,
        [Description("source: path or index.")] string? source = null,
        [Description("module, refs: a module id; modules, search: a filter.")] string? query = null,
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
                    sb.AppendLine($"Source map: {m.Location}; {m.Sources} sources ({m.WithContent} with content), {m.Segments:N0} segments" +
                                  (m.Issues.Count > 0 ? $"; {m.Issues.Count} issue(s): {m.Issues[0]}" : ""));
                if (s.Banners > 0) sb.AppendLine($"License banners: {s.Banners}");
                foreach (var n in s.Notes) sb.AppendLine("Note: " + n);
                return ToolOutput.With(sb.ToString().TrimEnd(), new JsResult("summary", Summary: s));
            }
            case "modules":
            {
                var (all, notes) = JsModules.Find(Encoding.UTF8.GetString(JsAnalysis.Read(path)), default);
                var rows = all.Where(m => query == null || m.Id.Contains(query, StringComparison.OrdinalIgnoreCase)
                                          || m.Name?.Contains(query, StringComparison.OrdinalIgnoreCase) == true).ToList();
                var text = $"{rows.Count} module(s)" + (rows.Count > 0 ? $" ({string.Join(", ", rows.GroupBy(m => m.Family).Select(g => $"{g.Count()} {g.Key}"))})" : "") + ":\n" +
                           string.Join("\n", rows.Select(m => $"  {m.Id}{(m.Name != null && m.Name != m.Id ? " " + m.Name : "")}  [{m.Provenance}] {m.End - m.Start:N0} bytes, " +
                                                              $"{m.Requires.Count} require(s)")) +
                           string.Concat(notes.Select(n => "\nNote: " + n));
                return ToolOutput.With(pager.Page(text, offset, maxTokens), new JsResult("modules", Modules: rows.Take(500).ToList(), Total: rows.Count));
            }
            case "module":
            {
                if (string.IsNullOrWhiteSpace(query)) throw new ToolError(ErrorCode.InvalidArgument, "view=module needs query (the module id).", "pass query=<id> (view=modules lists them)");
                var code = Encoding.UTF8.GetString(JsAnalysis.Read(path));
                var m = JsModules.Find(code, default).Modules.FirstOrDefault(x => x.Id == query.Trim() || x.Name == query.Trim())
                        ?? throw new ToolError(ErrorCode.NotFound, $"no module '{query}' in {Path.GetFileName(path)}.", "analyze_js view=modules lists them");
                var head = $"// module {m.Id}{(m.Name != null && m.Name != m.Id ? " (" + m.Name + ")" : "")}, {m.Family}, bytes {m.Start}-{m.End}" +
                           (m.Requires.Count > 0 ? $"\n// requires: {string.Join(", ", m.Requires.Take(50))}" : "");
                return ToolOutput.With(pager.Page(head + "\n" + code[m.Start..m.End], offset, maxTokens), new JsResult("module", Modules: [m]));
            }
            case "search":
            {
                if (string.IsNullOrWhiteSpace(query)) throw new ToolError(ErrorCode.InvalidArgument, "view=search needs query.", "pass query=<text>");
                var code = Encoding.UTF8.GetString(JsAnalysis.Read(path));
                var notes = new List<string>();
                if (JsModules.Parse(code, notes) is not { } script) throw new ToolError(ErrorCode.MalformedInput, $"{Path.GetFileName(path)} could not be searched: {string.Join("; ", notes)}");
                SourceMap? map = null;
                try { map = SourceMap.Locate(path, JsAnalysis.Read(path))?.Map; } catch (ToolError) { } catch (FormatException) { }
                var hits = JsSearch.Find(code, script, JsModules.Find(code, script, default), map, query.Trim(), default);
                var text = $"{hits.Count}{(hits.Count >= JsSearch.MaxHits ? "+" : "")} hit(s) for '{query.Trim()}':\n" +
                           string.Join("\n", hits.Select(h => $"  {h.Line}:{h.Column} {h.Kind} {h.Value}" + (h.Module != null ? $"  [module {h.Module}]" : "") +
                                                              (h.Original != null ? $"  <- {h.Original}" : "")));
                return ToolOutput.With(pager.Page(text, offset, maxTokens), new JsResult("search", Total: hits.Count));
            }
            case "refs":
            {
                if (string.IsNullOrWhiteSpace(query)) throw new ToolError(ErrorCode.InvalidArgument, "view=refs needs query (the module id).", "pass query=<id> (view=modules lists them)");
                var all = JsModules.Find(Encoding.UTF8.GetString(JsAnalysis.Read(path)), default).Modules;
                var target = all.FirstOrDefault(x => x.Id == query.Trim() || x.Name == query.Trim())
                             ?? throw new ToolError(ErrorCode.NotFound, $"no module '{query}' in {Path.GetFileName(path)}.", "analyze_js view=modules lists them");
                var (requires, by) = JsSearch.Refs(all, target);
                var text = $"module {target.Id}{(target.Name != null && target.Name != target.Id ? " (" + target.Name + ")" : "")}\n" +
                           $"requires ({requires.Count}): {(requires.Count > 0 ? string.Join(", ", requires) : "none")}\n" +
                           $"required by ({by.Count}): {(by.Count > 0 ? string.Join(", ", by) : "none found")}";
                return ToolOutput.With(pager.Page(text, offset, maxTokens), new JsResult("refs", Modules: [target], Total: by.Count));
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
                    new JsResult("sources", Total: map.Sources.Count));
            }
            case "source":
            {
                if (string.IsNullOrWhiteSpace(source)) throw new ToolError(ErrorCode.InvalidArgument, "view=source needs source.", "pass source=<path or index> (view=sources lists them)");
                var s = JsAnalysis.Source(path, source.Trim());
                if (s.Content == null)
                    throw new ToolError(ErrorCode.NotFound, $"the map names {s.Source} but carries no sourcesContent for it.", "the original file is not in the map");
                return ToolOutput.With(pager.Page($"// {s.Source}\n{s.Content}", offset, maxTokens), new JsResult("source"));
            }
            default:
                throw new ToolError(ErrorCode.InvalidArgument, $"unknown view '{view}'.", "pass view=summary, modules, module, search, refs, position, sources or source");
        }
    }
}
