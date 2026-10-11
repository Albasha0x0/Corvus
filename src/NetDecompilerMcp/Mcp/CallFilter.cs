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
/// budget (errors included), workspace notices and resource update notifications.
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
        var log = services?.GetService<ILoggerFactory>()?.CreateLogger("NetDecompilerMcp.Calls") is { } l && l.IsEnabled(LogLevel.Debug) ? l : null;
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        CallToolResult result;
        try
        {
            result = await Execute(request, inputSchema, services, next, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            log?.LogDebug("Tool {Tool} cancelled after {Ms} ms", tool, (long)System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds);
            CallTrace.For(services?.GetService<ServerOptions>())?.Record(tool, request?.Arguments, System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds, "cancelled", null);
            throw;
        }
        CallTrace.For(services?.GetService<ServerOptions>())?.Record(tool, request?.Arguments, System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds,
            result.IsError == true ? ErrorCodeOf(result).Replace("error ", "") : null, result);
        // Tool, time and outcome only: arguments can hold paths and code.
        log?.LogDebug("Tool {Tool} {Status} in {Ms} ms", tool, result.IsError == true ? ErrorCodeOf(result) : "ok",
            (long)System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds);
        services?.GetService<ResourceSubscriptions>()?.Check();
        if (tool != null && !ToolEffects.Of(tool).ReadOnly) services?.GetService<Services.EditJournal>()?.Sync();
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
        var deadline = services?.GetService<ServerOptions>() is { } serverOptions ? Deadline(tool, serverOptions) : null;
        using var call = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (deadline is { } limit) call.CancelAfter(limit);
        try
        {
            if (inputSchema is { } schema) ArgumentCheck.Apply(schema, request?.Arguments, tool);
            var structured = StructuredOutput.Begin();
            using var waits = AssemblyWorkspace.CancelWaitsWith(call.Token);
            var result = await WithinDeadline(next(call.Token).AsTask(), call.Token, deadline, cancellationToken);
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
        catch (OperationCanceledException) when (call.IsCancellationRequested && !cancellationToken.IsCancellationRequested && deadline != null)
        {
            return DeadlineError(tool, deadline.Value, stillRunning: false);
        }
        catch (DeadlinePassedException ex)
        {
            return DeadlineError(tool, ex.Limit, stillRunning: true);
        }
        catch (OperationCanceledException) when (!call.IsCancellationRequested)
        {
            // Neither the client nor the deadline: the server cancelled the work (an unload, reload or newer request).
            return ErrorResult.From(new ToolError(ErrorCode.Cancelled, "the work was cancelled by the server before it finished.",
                "call again; if the target was unloaded or reloaded, check list_assemblies first"), tool);
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

    private static string ErrorCodeOf(CallToolResult result)
    {
        if (ErrorResult.JsonOf(result) is not { } json) return "error";
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty("code", out var code) ? "error " + code.GetString() : "error";
        }
        catch (JsonException)
        {
            return "error";
        }
    }

    /// <summary>Multiple of --timeout after which a call not marked long-running in <see cref="ToolEffects"/> ends.</summary>
    public const int DeadlineFactor = 2;

    /// <summary>How long a tool that ignores the deadline's cancellation is waited for before the call returns without it.</summary>
    public static readonly TimeSpan DeadlineGrace = TimeSpan.FromSeconds(1);

    /// <summary>The call deadline, or null for long-running tools (they keep their own limits).</summary>
    public static TimeSpan? Deadline(string? tool, ServerOptions options) =>
        tool != null && ToolEffects.Of(tool).LongRunning ? null : TimeSpan.FromSeconds((double)options.TimeoutSeconds * DeadlineFactor);

    private sealed class DeadlinePassedException(TimeSpan limit) : Exception
    {
        public TimeSpan Limit { get; } = limit;
    }

    /// <summary>The tool's result; past the deadline plus <see cref="DeadlineGrace"/>, the call returns while the work finishes in the background.</summary>
    private static async Task<CallToolResult> WithinDeadline(Task<CallToolResult> work, CancellationToken call, TimeSpan? deadline, CancellationToken client)
    {
        if (deadline is not { } limit) return await work;
        var expired = new TaskCompletionSource();
        using var registration = call.Register(() => expired.TrySetResult());
        if (await Task.WhenAny(work, expired.Task) == work) return await work;
        if (client.IsCancellationRequested || await Task.WhenAny(work, Task.Delay(DeadlineGrace, client)) == work) return await work;
        _ = work.ContinueWith(t => t.Exception, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
        throw new DeadlinePassedException(limit);
    }

    private static CallToolResult DeadlineError(string? tool, TimeSpan limit, bool stillRunning) =>
        ErrorResult.From(new ToolError(ErrorCode.Timeout,
            $"the call did not finish within {limit.TotalSeconds:0} s ({DeadlineFactor}x --timeout){(stillRunning ? "; its work is still finishing in the background" : "")}.",
            "narrow the call (one member instead of a type, a smaller limit or scope), or start the server with a larger --timeout")
        {
            Details = new { deadlineSeconds = limit.TotalSeconds, stillRunning },
        }, tool);

    [GeneratedRegex("required parameter '([^']+)'")]
    private static partial Regex MissingParameter();
}
