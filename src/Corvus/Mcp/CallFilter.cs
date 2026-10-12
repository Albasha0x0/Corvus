using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;

namespace Corvus.Mcp;

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
        var log = CallLog.Begin(request, services);
        CallToolResult result;
        try
        {
            result = await Execute(request, inputSchema, services, next, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            log.Cancelled();
            throw;
        }
        services?.GetService<ResourceSubscriptions>()?.Check();
        if (tool != null && !ToolEffects.Of(tool).ReadOnly) services?.GetService<Services.EditJournal>()?.Sync();
        if (services?.GetService<ServerOptions>() is { } options && services.GetService<ResultStore>() is { } store)
            result = ResponseBudget.Enforce(result, tool, options, store, request);
        if (services?.GetService<AssemblyWorkspace>()?.DrainNotices() is { } notices) ErrorResult.AddNotices(result, notices);
        log.Completed(result);
        return result;
    }

    private static async ValueTask<CallToolResult> Execute(CallToolRequestParams? request, JsonElement? inputSchema, IServiceProvider? services,
        Func<CancellationToken, ValueTask<CallToolResult>> next, CancellationToken cancellationToken)
    {
        var tool = request?.Name;
        var serverOptions = services?.GetService<ServerOptions>();
        var deadline = serverOptions != null ? Deadline(tool, serverOptions) : null;
        var leftovers = serverOptions != null ? LeftoverWork.For(serverOptions) : null;
        using var call = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (deadline is { } limit) call.CancelAfter(limit);
        // at the cap a call with a deadline waits for room until that deadline; session tools (server_status) never wait
        if (leftovers != null && deadline != null && tool != null && Toolsets.FamilyOf(tool) != Toolsets.Session && !await leftovers.WaitForRoom(call.Token))
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ErrorResult.From(new ToolError(ErrorCode.ProviderUnavailable,
                $"the server is busy: {leftovers.Running} cancelled or timed-out calls are still finishing in the background (at most {leftovers.Max}); this call waited {deadline.Value.TotalSeconds:0} s and was not started.",
                "retry after details.retryAfterMs; server_status shows when they are done")
            { Details = new { retryAfterMs = (long)LeftoverWork.RetryAfter.TotalMilliseconds, leftoverCalls = leftovers.Running, max = leftovers.Max } }, tool);
        }
        using var waits = AssemblyWorkspace.CancelWaitsWith(call.Token, tool);
        try
        {
            if (inputSchema is { } schema)
            {
                ArgumentCheck.Apply(schema, request?.Arguments, tool);
                ArgumentCheck.RequireAll(schema, request?.Arguments, tool);
            }
            var structured = StructuredOutput.Begin();
            var result = await WithinDeadline(next(call.Token).AsTask(), call.Token, deadline, cancellationToken, leftovers);
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
            return ErrorResult.From(ex, tool, services?.GetService<ResultStore>());
        }
        catch (OperationCanceledException) when (call.IsCancellationRequested && !cancellationToken.IsCancellationRequested && deadline != null)
        {
            return DeadlineError(tool, deadline.Value, stillRunning: false, waits.BlockedBy);
        }
        catch (DeadlinePassedException ex)
        {
            return DeadlineError(tool, ex.Limit, stillRunning: true, waits.BlockedBy);
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
            return ErrorResult.From(ArgumentCheck.MissingParameter(inputSchema ?? default, m.Groups[1].Value, tool), tool);
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

    /// <summary>
    /// The tool's result; cancelled by the client or past the deadline, the work gets <see cref="DeadlineGrace"/> to stop, then
    /// the call returns while it finishes in the background, counted in <paramref name="leftovers"/>.
    /// </summary>
    private static async Task<CallToolResult> WithinDeadline(Task<CallToolResult> work, CancellationToken call, TimeSpan? deadline, CancellationToken client,
        LeftoverWork? leftovers)
    {
        var stopped = new TaskCompletionSource();
        using (call.Register(() => stopped.TrySetResult()))
            if (await Task.WhenAny(work, stopped.Task) == work) return await work;
        if (await Task.WhenAny(work, Task.Delay(DeadlineGrace, CancellationToken.None)) == work) return await work;
        leftovers?.Track(work);
        _ = work.ContinueWith(t => t.Exception, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
        client.ThrowIfCancellationRequested();
        throw new DeadlinePassedException(deadline!.Value);
    }

    /// <param name="blockedBy">The workspace lock holders the call was still waiting for, else null.</param>
    private static CallToolResult DeadlineError(string? tool, TimeSpan limit, bool stillRunning, string? blockedBy) =>
        ErrorResult.From(new ToolError(ErrorCode.Timeout,
            $"the call did not finish within {limit.TotalSeconds:0} s ({DeadlineFactor}x --timeout)" +
            (blockedBy != null ? $": it was waiting for the workspace lock, held by {blockedBy}" : "") +
            $"{(stillRunning ? "; its work is still finishing in the background" : "")}.",
            blockedBy != null
                ? "call again once that call has finished (server_status lists the lock holders); a long-running call can be cancelled by its client"
                : "narrow the call (one member instead of a type, a smaller limit or scope)" + (stillRunning ? "; or retry after details.retryAfterMs, once the background work is done" : ""))
        {
            Details = new { deadlineSeconds = limit.TotalSeconds, stillRunning, blockedBy },
            RetryAfter = stillRunning ? LeftoverWork.RetryAfter : null,
        }, tool);

    [GeneratedRegex("required parameter '([^']+)'")]
    private static partial Regex MissingParameter();
}

/// <summary>
/// Calls of one server that were cancelled by the client or passed their deadline and still run in the background (their
/// token is cancelled; the work ignored it). At <see cref="Max"/> of them, a new call with a deadline waits for one to
/// finish until that deadline, then is refused as busy.
/// </summary>
public sealed class LeftoverWork
{
    public const string MaxVariable = "CORVUS_MAX_LEFTOVER_CALLS";
    public const int DefaultMax = 2;

    /// <summary>The retry hint of a busy refusal.</summary>
    public static readonly TimeSpan RetryAfter = TimeSpan.FromSeconds(10);

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<ServerOptions, LeftoverWork> Servers = new();
    private int _running;
    private long _total;
    private TaskCompletionSource _finished = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public int Max { get; set; } = int.TryParse(Environment.GetEnvironmentVariable(MaxVariable), out var max) && max > 0 ? max : DefaultMax;
    public int Running => Volatile.Read(ref _running);
    /// <summary>Calls that ever outlived their cancellation or deadline.</summary>
    public long Total => Interlocked.Read(ref _total);

    public static LeftoverWork For(ServerOptions options) => Servers.GetValue(options, _ => new LeftoverWork());

    public void Track(Task work)
    {
        Interlocked.Increment(ref _running);
        Interlocked.Increment(ref _total);
        work.ContinueWith(_ =>
        {
            Interlocked.Decrement(ref _running);
            Interlocked.Exchange(ref _finished, new(TaskCreationOptions.RunContinuationsAsynchronously)).TrySetResult();
        }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    /// <summary>True once fewer than <see cref="Max"/> run; false when <paramref name="ct"/> ends the wait first.</summary>
    public async Task<bool> WaitForRoom(CancellationToken ct)
    {
        while (true)
        {
            var finished = Volatile.Read(ref _finished).Task;
            if (Running < Max) return true;
            try { await finished.WaitAsync(ct); }
            catch (OperationCanceledException) { return false; }
        }
    }
}
