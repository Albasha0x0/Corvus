using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services.Web;

namespace Corvus.Tools;

public sealed partial class WebTools
{
    /// <summary>analyze_js on Hermes bytecode (a bundle, or the one inside an APK, AAB or .ipa); the source map views take the JavaScript path.</summary>
    private string AnalyzeHermes(string path, string view, string? query, int offset, int? maxTokens)
    {
        var b = HermesBundles.Open(path);
        var v = view.Trim().ToLowerInvariant();
        if (b.File.Opcodes == null && v != "summary")
            throw new ToolError(ErrorCode.Unsupported, $"Hermes bytecode version {b.File.Version}: only its header is read (opcode tables cover versions 59–96).", "analyze_js view=summary shows the header");
        switch (v)
        {
            case "summary":
            {
                var (text, facts) = HermesBundles.Summary(b);
                return ToolOutput.With(text, new JsResult("summary", Hermes: facts));
            }
            case "functions":
            {
                var (text, rows, total) = HermesBundles.Functions(b, string.IsNullOrWhiteSpace(query) ? null : query.Trim());
                return ToolOutput.With(pager.Page(text, offset, maxTokens), new JsResult("functions", Functions: rows, Total: total));
            }
            case "decompile":
                return ToolOutput.With(pager.Page(HermesBundles.Decompile(b, HermesBundles.Function(b, query), default), offset, maxTokens), new JsResult("decompile"));
            case "disassemble":
                return ToolOutput.With(pager.Page(HermesBundles.Disassemble(b, HermesBundles.Function(b, query)), offset, maxTokens), new JsResult("disassemble"));
            case "modules":
            {
                var (text, rows) = HermesBundles.Modules(b, string.IsNullOrWhiteSpace(query) ? null : query.Trim());
                return ToolOutput.With(pager.Page(text, offset, maxTokens), new JsResult("modules", Modules: [.. rows.Take(500)], Total: rows.Count));
            }
            case "module":
                return ToolOutput.With(pager.Page(HermesBundles.Decompile(b, HermesBundles.ModuleFunction(b, query), default), offset, maxTokens), new JsResult("module"));
            case "search":
            {
                if (string.IsNullOrWhiteSpace(query)) throw new ToolError(ErrorCode.InvalidArgument, "view=search needs query.", "pass query=<text>");
                var (text, total) = HermesBundles.Search(b, query.Trim(), default);
                return ToolOutput.With(pager.Page(text, offset, maxTokens), new JsResult("search", Total: total));
            }
            case "xrefs":
            {
                if (string.IsNullOrWhiteSpace(query)) throw new ToolError(ErrorCode.InvalidArgument, "view=xrefs needs query: #<function id> or a whole string.", "pass query=#12 or query=<text>");
                var (text, total) = HermesBundles.Xrefs(b, query);
                return ToolOutput.With(pager.Page(text, offset, maxTokens), new JsResult("xrefs", Total: total));
            }
            case "refs":
            {
                if (string.IsNullOrWhiteSpace(query)) throw new ToolError(ErrorCode.InvalidArgument, "view=refs needs query (the module id).", "pass query=<id> (view=modules lists them)");
                var (text, module, by) = HermesBundles.Refs(b, query);
                return ToolOutput.With(text, new JsResult("refs", Modules: [module], Total: by));
            }
            default:
                throw new ToolError(ErrorCode.InvalidArgument, $"unknown view '{view}' for Hermes bytecode.",
                    "pass view=summary, functions, decompile, disassemble, modules, module, search, xrefs or refs (position, sources and source read its source map)");
        }
    }
}
