using System.ComponentModel;
using System.Text;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services.Web;

namespace Corvus.Tools;

/// <summary>JavaScript bundles and their source maps, read statically.</summary>
[McpServerToolType]
public sealed partial class WebTools(OutputPager pager)
{
    /// <summary>analyze_js's record: the view's part is set (sources and source carry their text only).</summary>
    public sealed record JsResult(string View, JsSummary? Summary = null, JsPosition? Position = null, IReadOnlyList<JsModule>? Modules = null, int? Total = null,
        HermesFacts? Hermes = null, IReadOnlyList<HermesFunctionRow>? Functions = null)
    {
        public IReadOnlyList<JsEndpoint>? Endpoints { get; init; }
        public IReadOnlyList<JsSecret>? Secrets { get; init; }
        public JsDiffResult? Diff { get; init; }
        public JsRuntimeFacts? Runtime { get; init; }
        public JsFlowResult? Flow { get; init; }
    }

    [McpServerTool(Name = "analyze_js", Title = "Analyze a JavaScript bundle", UseStructuredContent = true, OutputSchemaType = typeof(JsResult))]
    [Description("Bundler, modules, source map of JS, statically. position: to original; diff: with source=; runtime: " +
                 "webpack chunks; flow: values to effects; origins: back; unknowns marked; beautify: " +
                 "layout, scope renames. Hermes, Ark too.")]
    public string AnalyzeJs(
        [Description("A .js, Hermes or Ark file, or a package.")] string path,
        [Description("View.")] string view = "summary",
        [Description("position, flow: 1-based generated line.")] int? line = null,
        [Description("See line.")] int? column = null,
        [Description("source: path or index; diff: old bundle.")] string? source = null,
        [Description("Module id; search filter; function #id or name; flow: name, quoted literal, sinks, sink:KIND, module:ID; beautify: a=b, a@line:col=b, auto.")] string? query = null,
        [Description("flow: max flows (50).")] int? limit = null,
        [Description(ToolSupport.CharOffsetDescription)] int offset = 0,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null)
    {
        if (view.Trim().ToLowerInvariant() is not ("position" or "sources" or "source") && HermesBundles.Applies(path)) return AnalyzeHermes(path, view, query, offset, maxTokens);
        if (ArkBundles.Applies(path)) return AnalyzeArk(path, view, query, offset, maxTokens);
        switch (view.Trim().ToLowerInvariant())
        {
            case "flow" or "origins":
                return Flow(path, query, line ?? 0, column ?? 0, view.Trim().Equals("origins", StringComparison.OrdinalIgnoreCase), limit ?? 50, offset, maxTokens);
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
                var (all, notes) = JsModules.Of(path, default);
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
                var m = JsModules.Of(path, default).Modules.FirstOrDefault(x => x.Id == query.Trim() || x.Name == query.Trim())
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
                var all = JsModules.Of(path, default).Modules;
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
                var p = JsAnalysis.Position(path, line ?? 0, column ?? 0);
                var text = p.Source == null
                    ? $"{line ?? 0}:{column ?? 0} has no mapping."
                    : $"{line ?? 0}:{column ?? 0} -> {p.Source}:{p.OriginalLine}:{p.OriginalColumn}" + (p.Name != null ? $" ({p.Name})" : "");
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
            case "endpoints":
            {
                var program = JsAnalysis.Program(path, default);
                var map = JsAnalysis.TryMap(path);
                var found = new List<Corvus.Services.Analysis.Endpoints.CodeEndpoint>();
                Corvus.Services.Analysis.Endpoints.JsEndpoints.Scan(program, program.Path, found, default);
                var rows = found.Select(e => JsAnalysis.Endpoint(e, map)).Where(e => query == null || e.Url.Contains(query, StringComparison.OrdinalIgnoreCase) || e.Client.Contains(query, StringComparison.OrdinalIgnoreCase)).ToList();
                var text = $"{rows.Count} endpoint(s)" + (rows.Count > 0 ? $" ({string.Join(", ", rows.GroupBy(e => e.Client.Split(' ')[0]).Select(g => $"{g.Count()} {g.Key}"))})" : "") + ":\n" +
                           string.Join("\n", rows.Select(e => $"  {e.Verb} {e.Url}  [{e.Client}] {e.Site}" + (e.Module != null ? $" {e.Module}" : "") + (e.Original != null ? $"  <- {e.Original}" : ""))) +
                           "\nsearch_container kind=endpoint capture=<HAR or pcap> joins these to a capture (seen in code, in the capture, or both).";
                return ToolOutput.With(pager.Page(text, offset, maxTokens), new JsResult("endpoints", Total: rows.Count) { Endpoints = rows.Take(500).ToList() });
            }
            case "diff":
            {
                if (string.IsNullOrWhiteSpace(source)) throw new ToolError(ErrorCode.InvalidArgument, "view=diff needs source (the old bundle).", "pass source=<old .js path>; path is the new one");
                var d = JsDiff.Compare(source.Trim(), path, string.IsNullOrWhiteSpace(query) ? null : query.Trim(), default);
                int paired = d.Identical + d.Changed;
                var text = $"{d.OldModules} -> {d.NewModules} module(s): {d.Identical} identical, {d.Changed} changed, {d.Added} added, {d.Removed} removed; " +
                           $"{paired} paired ({(d.OldModules > 0 ? 100.0 * paired / d.OldModules : 0):0.#}% of the old), {d.Renumbered} renumbered\n" +
                           string.Join("\n", d.Rows.Select(r => $"  {r.Change} {r.OldId ?? "-"} -> {r.NewId ?? "-"}" + (r.Name != null ? $" {r.Name}" : "") +
                                                                 (r.Tier != null ? $" [{r.Tier}]" : "") + $" {r.OldBytes:N0} -> {r.NewBytes:N0} bytes" + (r.Detail != null ? "; " + r.Detail : ""))) +
                           (d.TokenDiff != null ? "\n" + d.TokenDiff : "");
                return ToolOutput.With(pager.Page(text, offset, maxTokens), new JsResult("diff", Total: d.Rows.Count) { Diff = d with { Rows = d.Rows.Take(500).ToList() } });
            }
            case "runtime":
            {
                var r = JsRuntime.Read(JsAnalysis.Program(path, default), default);
                var sb = new StringBuilder();
                sb.AppendLine(r.Require != null ? $"Runtime require: {r.Require} (module table {r.ModuleTable ?? "?"})" : "No webpack runtime require function in this file.");
                if (r.ChunkGlobals.Count > 0) sb.AppendLine("Chunk loading global: " + string.Join(", ", r.ChunkGlobals));
                if (r.ChunkIds.Count > 0) sb.AppendLine($"Chunks pushed by this file: {string.Join(", ", r.ChunkIds.Take(50))}{(r.ChunkIds.Count > 50 ? ", ..." : "")}");
                if (r.PublicPath != null) sb.AppendLine($"Public path: {r.PublicPath}");
                if (r.Helpers.Count > 0) sb.AppendLine("Helpers: " + string.Join("; ", r.Helpers));
                if (r.Chunks.Count > 0) sb.AppendLine($"{r.Chunks.Count} chunk file(s):\n" + string.Join("\n", r.Chunks.Where(c => query == null || c.Id == query || c.File?.Contains(query, StringComparison.OrdinalIgnoreCase) == true).Select(c => $"  {c.Id} -> {c.File ?? "(not folded)"}")));
                if (r.AsyncLoads.Count > 0) sb.AppendLine($"{r.AsyncLoads.Count} async load(s):\n" + string.Join("\n", r.AsyncLoads.Select(l => $"  {l.Site}: chunks {string.Join(", ", l.Chunks)}" + (l.Module != null ? $" then module {l.Module}" : ""))));
                return ToolOutput.With(pager.Page(sb.ToString().TrimEnd(), offset, maxTokens), new JsResult("runtime", Total: r.Chunks.Count) { Runtime = r with { Chunks = r.Chunks.Take(500).ToList(), AsyncLoads = r.AsyncLoads.Take(500).ToList() } });
            }
            case "secrets":
            {
                var program = JsAnalysis.Program(path, default);
                var rows = JsSecrets.Find(program, default).Where(s => query == null || s.Kind.Contains(query, StringComparison.OrdinalIgnoreCase)
                                                                          || s.Name?.Contains(query, StringComparison.OrdinalIgnoreCase) == true).ToList();
                var text = $"{rows.Count} key-like literal(s), values masked:\n" +
                           string.Join("\n", rows.Select(s => $"  {s.Kind}{(s.Name != null ? " " + s.Name : "")} = {s.Masked} ({s.Length} chars, {s.Entropy} bits/char) at {s.Line}:{s.Column}" +
                                                              (s.Module != null ? $" [module {s.Module}]" : "")));
                return ToolOutput.With(pager.Page(text, offset, maxTokens), new JsResult("secrets", Total: rows.Count) { Secrets = rows.Take(500).ToList() });
            }
            case "beautify":
            {
                var text = System.Text.Encoding.UTF8.GetString(JsAnalysis.Read(path));
                var words = (query ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                bool auto = words.Contains("auto", StringComparer.OrdinalIgnoreCase);
                var requested = string.Join(",", words.Where(w => !w.Equals("auto", StringComparison.OrdinalIgnoreCase)));
                JsBeautify.Result r;
                try { r = JsBeautify.Format(text, requested.Length > 0 ? requested : null, auto, default); }
                catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{Path.GetFileName(path)}: {ex.Message}"); }
                var lines = JsBeautify.LineStarts(text);
                // Lines end in \n alone: the pager counts offsets in that form.
                var sb = new StringBuilder();
                int originalLines = lines.Count - (text.EndsWith('\n') ? 1 : 0);
                sb.Append($"// {Path.GetFileName(path)}: {originalLines:N0} lines -> {r.Origins.Count:N0}; {r.Renames.Count} binding(s) renamed\n");
                foreach (var n in r.Renames)
                {
                    var (l, c) = JsBeautify.Position(lines, n.Declared);
                    sb.Append($"//   {n.From} -> {n.To} ({l}:{c}, {n.Reason})\n");
                }
                foreach (var note in r.Notes.Take(50)) sb.Append("// " + note + "\n");
                int header = sb.Length;
                sb.Append(r.Text);
                int start = offset;
                if (line is int wanted && wanted > 0)
                {
                    // Start the page at the output line holding the original position.
                    int target = lines[Math.Min(wanted, lines.Count) - 1] + Math.Max(0, (column ?? 1) - 1);
                    start = header + Nth(r.Text, Math.Max(0, r.Origins.Count(o => o <= target) - 1));
                }
                return ToolOutput.With(pager.Page(sb.ToString(), start, maxTokens), new JsResult("beautify", Total: r.Origins.Count));
            }
            default:
                throw new ToolError(ErrorCode.InvalidArgument, $"unknown view '{view}'.", "pass view=summary, modules, module, search, refs, position, sources, source, endpoints, secrets, diff, runtime, flow, origins or beautify");
        }
    }

    // The character offset of line n (0-based) of s.
    private static int Nth(string s, int n)
    {
        int at = 0;
        for (int i = 0; i < n; i++)
        {
            int nl = s.IndexOf('\n', at);
            if (nl < 0) return s.Length;
            at = nl + 1;
        }
        return at;
    }
}
