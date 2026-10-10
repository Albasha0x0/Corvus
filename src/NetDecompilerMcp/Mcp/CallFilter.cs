using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Mcp;

/// <summary>
/// The tools/call pipeline around every tool: argument checks, structured content, errors as results, the response
/// budget (errors included) and workspace notices.
/// </summary>
internal static partial class CallFilter
{
    public static McpRequestHandler<CallToolRequestParams, CallToolResult> Wrap(McpRequestHandler<CallToolRequestParams, CallToolResult> next) =>
        (context, cancellationToken) => Run(context.Params, (context.MatchedPrimitive as McpServerTool)?.ProtocolTool.InputSchema,
            context.Services, token => next(context, token), cancellationToken);

    /// <summary>One call: <paramref name="next"/> runs the tool.</summary>
    public static async ValueTask<CallToolResult> Run(CallToolRequestParams? request, JsonElement? inputSchema, IServiceProvider? services,
        Func<CancellationToken, ValueTask<CallToolResult>> next, CancellationToken cancellationToken)
    {
        var tool = request?.Name;
        var result = await Execute(request, inputSchema, services, next, cancellationToken);
        if (services?.GetService<ServerOptions>() is { } options && services.GetService<ResultStore>() is { } store)
            result = ResponseBudget.Enforce(result, tool, options, store, request);
        // Pending workspace notices; trailing blank line because clients join content blocks without a separator.
        var notices = services?.GetService<AssemblyWorkspace>()?.DrainNotices();
        if (notices is { Count: > 0 })
            result.Content.Insert(0, new TextContentBlock { Text = string.Join("\n", notices.Select(n => "[workspace] " + n)) + "\n\n" });
        return result;
    }

    private static async ValueTask<CallToolResult> Execute(CallToolRequestParams? request, JsonElement? inputSchema, IServiceProvider? services,
        Func<CancellationToken, ValueTask<CallToolResult>> next, CancellationToken cancellationToken)
    {
        var tool = request?.Name;
        try
        {
            if (inputSchema is { } schema) ArgumentCheck.Apply(schema, request?.Arguments);
            var structured = StructuredOutput.Begin();
            var result = await next(cancellationToken);
            // An error object never matches the tool's output schema, and clients validate whatever structuredContent is present.
            if (result.IsError == true) result.StructuredContent = null;
            // A tool that keeps its readable text hands its record over separately; bounded to the page size.
            else if (structured.Value is { } value && services?.GetService<ServerOptions>() is { } options)
                result.StructuredContent = StructuredOutput.Serialize(value, ResponseBudget.Budget(options, request) - ResponseBudget.Slack);
            // Transformed names made of zero-width and bidi characters would print as nothing or scramble the line.
            foreach (var block in result.Content.OfType<TextContentBlock>())
                block.Text = Format.EscapeInvisible(block.Text);
            return result;
        }
        catch (ToolError ex)
        {
            return ErrorResult.From(ex, tool);
        }
        catch (ArgumentException ex) when (ex.ParamName == "arguments" && MissingParameter().Match(ex.Message) is { Success: true } m)
        {
            // Argument binding: a required parameter is missing.
            return ErrorResult.From(new ToolError(ErrorCode.InvalidArgument, $"missing required parameter '{m.Groups[1].Value}'.")
                { Details = new { parameter = m.Groups[1].Value } }, tool);
        }
        catch (Exception ex) when (ArgumentCheck.FileSystemError(ex) is { } error)
        {
            // A path argument System.IO rejected or could not reach.
            return ErrorResult.From(error, tool);
        }
        catch (Exception ex) when (ex is not McpException && ex is not OperationCanceledException)
        {
            // Unexpected exceptions become a descriptive tool error instead of a generic protocol error.
            services?.GetService<ILogger<AssemblyWorkspace>>()?.LogError(ex, "Tool {Tool} failed", tool);
            return ErrorResult.Internal(ex, tool);
        }
    }

    [GeneratedRegex("required parameter '([^']+)'")]
    private static partial Regex MissingParameter();
}
