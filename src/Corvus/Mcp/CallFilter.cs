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
            context.Services, token => next(context, token), cancellationToken, context.Server?.ClientInfo?.Name);

    /// <summary>One call: <paramref name="next"/> runs the tool; <paramref name="clientName"/> is the handshake's clientInfo.name.</summary>
    public static async ValueTask<CallToolResult> Run(CallToolRequestParams? request, JsonElement? inputSchema, IServiceProvider? services,
        Func<CancellationToken, ValueTask<CallToolResult>> next, CancellationToken cancellationToken, string? clientName = null)
    {
        var tool = request?.Name;
        var log = CallLog.Begin(request, services);
        CallToolResult result;
        try
        {
            result = await Execute(request, inputSchema, services, next, cancellationToken, clientName);
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
        Func<CancellationToken, ValueTask<CallToolResult>> next, CancellationToken cancellationToken, string? clientName)
    {
        var tool = request?.Name;
        var serverOptions = services?.GetService<ServerOptions>();
        var client = serverOptions != null ? ClientProfiles.Resolve(serverOptions, clientName) : null;
        var effects = ToolEffects.Of(tool ?? "");
        var deadline = serverOptions != null ? Deadlines.Effective(effects.LongRunning, serverOptions, client!) : null;
        var leftovers = serverOptions != null ? LeftoverWork.For(serverOptions) : null;
        var joinKey = serverOptions != null ? CallJoin.Key(tool, effects.ReadOnly, request?.Arguments) : null;
        var joins = joinKey != null ? CallJoin.For(serverOptions!) : null;
        using var call = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        // Stopped one grace period early, so even work that ignores its token is answered for by the deadline.
        if (deadline is { } limit) call.CancelAfter(Early(limit));
        // at the cap a call with a deadline waits for room until that deadline; session tools (server_status) and joins never wait
        if (leftovers != null && deadline != null && tool != null && Toolsets.FamilyOf(tool) != Toolsets.Session && joins?.IsRunning(joinKey!) != true
            && !await leftovers.WaitForRoom(call.Token))
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ErrorResult.From(new ToolError(ErrorCode.ProviderUnavailable,
                $"the server is busy: {leftovers.Running} cancelled or timed-out calls are still finishing in the background (at most {leftovers.Max}); this call waited {deadline.Value.TotalSeconds:0} s and was not started.",
                "retry after details.retryAfterMs; server_status shows when they are done")
            { Details = new { retryAfterMs = (long)LeftoverWork.RetryAfter.TotalMilliseconds, leftoverCalls = leftovers.Running, max = leftovers.Max } }, tool);
        }
        using var waits = AssemblyWorkspace.CancelWaitsWith(call.Token, tool);
        var joinStopped = CancellationToken.None;
        try
        {
            if (inputSchema is { } schema)
            {
                ArgumentCheck.Apply(schema, request?.Arguments, tool);
                ArgumentCheck.RequireAll(schema, request?.Arguments, tool);
            }
            if (services?.GetService<AssemblyWorkspace>() is { } workspace) await Task.Run(() => Targets.PreResolve(workspace, tool, request?.Arguments?.AsReadOnly()), call.Token);
            async Task<(CallToolResult Result, object? Structured)> Work(CancellationToken token)
            {
                var structured = StructuredOutput.Begin();
                var r = await next(token);
                return (r, structured.Value);
            }
            (CallToolResult Result, object? Structured) outcome;
            if (joins != null)
            {
                // The shared run keeps the server's deadline only, so a caller that left at the client's deadline can pick it up again.
                var joined = joins.Run(joinKey!, Work, cancellationToken, Deadline(tool, serverOptions!) is { } server ? Early(server) : null,
                    o => (Copy(o.Result), o.Structured));
                joinStopped = joined.Stopped;
                outcome = await WithinDeadline(joined.Result, joined.Work, call.Token, deadline, cancellationToken, leftovers);
            }
            else
            {
                var work = Work(call.Token);
                outcome = await WithinDeadline(work, work, call.Token, deadline, cancellationToken, leftovers);
            }
            var result = outcome.Result;
            // An error object never matches the tool's output schema, and clients validate whatever structuredContent is present.
            if (result.IsError == true) result.StructuredContent = null;
            // A tool that keeps its readable text hands its record over separately; bounded to the page size.
            else if (outcome.Structured is { } value && services?.GetService<ServerOptions>() is { } options)
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
        // A joined run stops at its own copy of the server deadline, possibly a moment before this call's timer.
        catch (OperationCanceledException) when ((call.IsCancellationRequested || joinStopped.IsCancellationRequested) && !cancellationToken.IsCancellationRequested && deadline != null)
        {
            return DeadlineError(tool, deadline.Value, stillRunning: false, waits.BlockedBy, client, joined: false);
        }
        catch (DeadlinePassedException ex)
        {
            return DeadlineError(tool, ex.Limit, stillRunning: true, waits.BlockedBy, client, joins != null);
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
    public const int DeadlineFactor = Deadlines.ServerFactor;

    /// <summary>How long a tool that ignores the deadline's cancellation is waited for before the call returns without it.</summary>
    public static readonly TimeSpan DeadlineGrace = TimeSpan.FromSeconds(1);

    /// <summary>The call deadline without a client limit, or null for long-running tools (they keep their own limits).</summary>
    public static TimeSpan? Deadline(string? tool, ServerOptions options) =>
        tool != null && ToolEffects.Of(tool).LongRunning ? null : Deadlines.Server(options);

    /// <summary>Kept free at the end of a deadline for the answer itself (timers and a busy pool run late).</summary>
    private static readonly TimeSpan AnswerSlack = TimeSpan.FromMilliseconds(500);

    /// <summary>When work is told to stop: grace and slack before <paramref name="deadline"/>, or halfway for a short one.</summary>
    private static TimeSpan Early(TimeSpan deadline) => deadline - DeadlineGrace - AnswerSlack > deadline / 2 ? deadline - DeadlineGrace - AnswerSlack : deadline / 2;

    /// <summary>How long stopped work is waited for before the call answers without it, so the answer lands before <paramref name="deadline"/>.</summary>
    private static TimeSpan Grace(TimeSpan deadline)
    {
        var left = deadline - Early(deadline);
        return left - AnswerSlack > left / 2 ? left - AnswerSlack : left / 2;
    }

    /// <summary>A joined caller's own copy of the shared result (the pipeline changes content blocks in place).</summary>
    private static CallToolResult Copy(CallToolResult result) =>
        JsonSerializer.Deserialize<CallToolResult>(JsonSerializer.SerializeToUtf8Bytes(result, McpJsonUtilities.DefaultOptions), McpJsonUtilities.DefaultOptions)!;

    private sealed class DeadlinePassedException(TimeSpan limit) : Exception
    {
        public TimeSpan Limit { get; } = limit;
    }

    /// <summary>
    /// The tool's result; cancelled by the client or past the deadline, the work gets <see cref="DeadlineGrace"/> to stop, then
    /// the call returns while <paramref name="shared"/> (the run behind <paramref name="work"/>) finishes in the background,
    /// counted in <paramref name="leftovers"/>.
    /// </summary>
    private static async Task<T> WithinDeadline<T>(Task<T> work, Task shared, CancellationToken call, TimeSpan? deadline, CancellationToken client,
        LeftoverWork? leftovers)
    {
        var stopped = new TaskCompletionSource();
        using (call.Register(() => stopped.TrySetResult()))
            if (await Task.WhenAny(work, stopped.Task) == work) return await work;
        var grace = !client.IsCancellationRequested && deadline is { } d ? Grace(d) : DeadlineGrace;
        if (await Task.WhenAny(work, Task.Delay(grace, CancellationToken.None)) == work) return await work;
        leftovers?.Track(shared);
        _ = work.ContinueWith(t => t.Exception, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
        client.ThrowIfCancellationRequested();
        throw new DeadlinePassedException(deadline!.Value);
    }

    /// <param name="blockedBy">The workspace lock holders the call was still waiting for, else null.</param>
    /// <param name="joined">The work runs on under a join key: the same call made again picks it up.</param>
    private static CallToolResult DeadlineError(string? tool, TimeSpan limit, bool stillRunning, string? blockedBy, ClientLimits? client, bool joined)
    {
        bool byClient = client?.DeadlineSeconds is { } seconds && limit < TimeSpan.FromSeconds(seconds);
        return ErrorResult.From(new ToolError(ErrorCode.Timeout,
            $"the call did not finish within {limit.TotalSeconds:0} s ({(byClient ? $"the client waits {client!.DeadlineSeconds} s" : $"{DeadlineFactor}x --timeout")})" +
            (blockedBy != null ? $": it was waiting for the workspace lock, held by {blockedBy}" : "") +
            $"{(stillRunning ? "; its work is still finishing in the background" : "")}.",
            blockedBy != null
                ? "call again once that call has finished (server_status lists the lock holders); a long-running call can be cancelled by its client"
                : stillRunning && joined ? "call again with the same arguments to pick up the running work"
                : "narrow the call (one member instead of a type, a smaller limit or scope)" + (stillRunning ? "; or retry after details.retryAfterMs, once the background work is done" : ""))
        {
            Details = new { deadlineSeconds = limit.TotalSeconds, stillRunning, partial = false, blockedBy, deadlineSource = byClient ? client!.DeadlineSource : "server" },
            RetryAfter = stillRunning ? LeftoverWork.RetryAfter : null,
        }, tool);
    }

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

    private readonly HashSet<Task> _tracked = [];

    /// <summary>Counts <paramref name="work"/> until it ends; a joined run left by several callers counts once.</summary>
    public void Track(Task work)
    {
        lock (_tracked)
            if (!_tracked.Add(work)) return;
        Interlocked.Increment(ref _running);
        Interlocked.Increment(ref _total);
        work.ContinueWith(_ =>
        {
            lock (_tracked) _tracked.Remove(work);
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
