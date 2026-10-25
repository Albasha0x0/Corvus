using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services.Web;

namespace Corvus.Tools;

public sealed partial class WebTools
{
    /// <summary>analyze_js on Ark bytecode (an .abc file, or the one inside a HarmonyOS module).</summary>
    private string AnalyzeArk(string path, string view, string? query, int offset, int? maxTokens)
    {
        var b = ArkBundles.Open(path);
        switch (view.Trim().ToLowerInvariant())
        {
            case "summary":
                return ToolOutput.With(ArkBundles.Summary(b), new JsResult("summary"));
            case "functions":
            {
                var (text, rows, total) = ArkBundles.Functions(b, string.IsNullOrWhiteSpace(query) ? null : query.Trim());
                return ToolOutput.With(pager.Page(text, offset, maxTokens), new JsResult("functions", Total: total, Functions: rows));
            }
            case "disassemble":
                return ToolOutput.With(pager.Page(ArkBundles.Disassemble(b, ArkBundles.Function(b, query)), offset, maxTokens), new JsResult("disassemble"));
            case "search":
            {
                if (string.IsNullOrWhiteSpace(query)) throw new ToolError(ErrorCode.InvalidArgument, "view=search needs query.", "pass query=<text>");
                var (text, total) = ArkBundles.Search(b, query.Trim(), default);
                return ToolOutput.With(pager.Page(text, offset, maxTokens), new JsResult("search", Total: total));
            }
            case "xrefs":
            {
                if (string.IsNullOrWhiteSpace(query)) throw new ToolError(ErrorCode.InvalidArgument, "view=xrefs needs query: #<method id> or a whole string.", "pass query=#12 or query=<text>");
                var (text, total) = ArkBundles.Xrefs(b, query.Trim(), default);
                return ToolOutput.With(pager.Page(text, offset, maxTokens), new JsResult("xrefs", Total: total));
            }
            default:
                throw new ToolError(ErrorCode.InvalidArgument, $"unknown view '{view}' for Ark bytecode.", "pass view=summary, functions, disassemble, search or xrefs");
        }
    }
}
