using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;

namespace Corvus.Mcp;

/// <summary>
/// The tools/call pipeline around every tool: argument checks and clamps, the output budget per part, structured content,
/// errors as results, notices, provenance, the frame safety net and resource update notifications.
/// </summary>
internal static partial class CallFilter
{
    /// <summary>CORVUS_RESULT_MODE=json: the text block is the compact structured JSON (the spec's SHOULD) instead of readable text.</summary>
    public const string ResultModeVariable = "CORVUS_RESULT_MODE";

    /// <summary>Largest limit a list tool takes; larger values are clamped and reported.</summary>
    public const int MaxLimit = 5_000;

    /// <summary>Smallest maxTokens a call can ask for.</summary>
    public const int MinTokens = 500;

    public static McpRequestHandler<CallToolRequestParams, CallToolResult> Wrap(McpRequestHandler<CallToolRequestParams, CallToolResult> next) =>
        (context, cancellationToken) => Run(context.Params, (context.MatchedPrimitive as McpServerTool)?.ProtocolTool.InputSchema,
            context.Services, token => next(context, token), cancellationToken, context.Server?.ClientInfo?.Name);

    /// <summary>One call: <paramref name="next"/> runs the tool; <paramref name="clientName"/> is the handshake's clientInfo.name.</summary>
    public static async ValueTask<CallToolResult> Run(CallToolRequestParams? request, JsonElement? inputSchema, IServiceProvider? services,
        Func<CancellationToken, ValueTask<CallToolResult>> next, CancellationToken cancellationToken, string? clientName = null)
    {
        // The deadline is a promise to the client, so its clock starts at receipt, before any of the call's own work.
        var time = services?.GetService<TimeProvider>() ?? TimeProvider.System;
        long received = time.GetTimestamp();
        var tool = request?.Name;
        var log = CallLog.Begin(request, services);
        var options = services?.GetService<ServerOptions>();
        var client = options != null ? ClientProfiles.Resolve(options, clientName) : null;
        CallToolResult result;
        OutputCall output;
        try
        {
            (result, output) = await Execute(request, inputSchema, services, next, cancellationToken, client, time, received);
        }
        catch (OperationCanceledException)
        {
            log.Cancelled();
            throw;
        }
        catch
        {
            log.Failed();
            throw;
        }
        // The bookkeeping below keeps the client's cancellation: Execute's scope, deadline included, has ended.
        using var waits = AssemblyWorkspace.CancelWaitsWith(cancellationToken, tool);
        services?.GetService<ResourceSubscriptions>()?.Check();
        if (tool != null && !ToolEffects.Of(tool).ReadOnly) services?.GetService<Services.EditJournal>()?.Sync();
        // the whole content, before the budget cuts it; read_result's own pages are not findings
        if (tool is not (null or "read_result") && result.IsError != true && services?.GetService<RecentCalls>() is { } recent)
            recent.Add(CallLog.Origin(tool, request?.Arguments) with { Inputs = ToolOutput.Inputs(request?.Arguments, services.GetService<AssemblyWorkspace>()) }, result);
        if (options != null && services!.GetService<ResultStore>() is { } store)
            result = ResponseBudget.Enforce(result, tool, output.Tokens > 0 ? output.Tokens : Budget(tool, null, client), store, request);
        string? answerSha256 = null;
        if (services?.GetService<AssemblyWorkspace>()?.DrainNotices() is { Count: > 0 } notices)
        {
            // An error's own text stays first; on a success the notices are the last block and notices[] in the record.
            if (result.IsError == true) ErrorResult.AddNotices(result, notices);
            else
            {
                // Hashed before the notices join it: the newline added to the block before them is no part of the answer.
                answerSha256 = ToolOutput.ResultSha256(result);
                if (result.Content.LastOrDefault() is TextContentBlock last && !last.Text.EndsWith('\n')) last.Text += "\n";
                result.Content.Add(new TextContentBlock { Text = string.Join("\n", notices.Select(n => ToolOutput.NoticePrefix + Format.EscapeInvisible(n))) });
                if (result.StructuredContent is { } s && JsonNode.Parse(s.GetRawText()) is JsonObject record)
                {
                    record["notices"] = new JsonArray(notices.Select(n => (JsonNode)JsonValue.Create(n)!).ToArray());
                    result.StructuredContent = JsonSerializer.SerializeToElement(record, ToolOutput.Json);
                }
            }
        }
        if (tool != null)
        {
            result.Meta ??= new JsonObject();
            result.Meta[ToolOutput.ProvenanceKey] = ToolOutput.Provenance(tool, request?.Arguments, services?.GetService<AssemblyWorkspace>(), log.Engine, result, output, answerSha256);
        }
        log.Completed(result);
        return result;
    }

    /// <summary>
    /// The estimate parts are fitted to: 5% under the budget, as the estimate runs up to 10% low on rare names and packed
    /// string tables (against o200k) and the budget allows 5% over.
    /// </summary>
    public static int FitTokens(int budget) => budget - budget / 20;

    /// <summary>The call's token budget per part: maxTokens, else the class default; within the client's ceiling.</summary>
    public static int Budget(string? tool, IDictionary<string, JsonElement>? arguments, ClientLimits? client)
    {
        int ceiling = client?.MaxTokens ?? ClientProfiles.DefaultMaxTokens;
        int tokens = OutputClasses.Budget(tool != null ? ToolContract.Of(tool).Output : OutputClass.Report);
        if (arguments != null && arguments.TryGetValue("maxTokens", out var m) && m.ValueKind == JsonValueKind.Number && m.TryGetInt32(out var asked))
        {
            if (asked < MinTokens)
                throw new ToolError(ErrorCode.InvalidArgument, $"maxTokens must be at least {MinTokens}, not {asked}.",
                    $"pass maxTokens from {MinTokens} to {ceiling}, or leave it out for the default page")
                { Details = new { parameter = "maxTokens", minimum = MinTokens } };
            tokens = asked;
        }
        return Math.Min(tokens, ceiling);
    }

    /// <summary>
    /// limit below 1 or offset below 0: invalid_argument naming the range; limit above <see cref="MaxLimit"/>: clamped and
    /// reported. Returns the limit the call applies (the schema default when not given), or null without a limit parameter.
    /// </summary>
    private static int? Clamp(JsonElement? inputSchema, CallToolRequestParams? request, List<string> warnings)
    {
        if (inputSchema is not { } schema || !schema.TryGetProperty("properties", out var properties)) return null;
        var args = request?.Arguments;
        if (properties.TryGetProperty("offset", out _) && args != null && args.TryGetValue("offset", out var o) && o.ValueKind == JsonValueKind.Number
            && o.TryGetInt64(out var offset) && offset < 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"offset must be 0 or more, not {offset}.", "pass offset=0 for the first page, or the nextOffset of the previous page")
                { Details = new { parameter = "offset", minimum = 0 } };
        if (!properties.TryGetProperty("limit", out var limitSchema)) return null;
        if (args != null && args.TryGetValue("limit", out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var limit))
        {
            if (limit < 1)
                throw new ToolError(ErrorCode.InvalidArgument, $"limit must be from 1 to {MaxLimit}, not {limit}.", $"pass limit from 1 to {MaxLimit}, or leave it out for the default")
                    { Details = new { parameter = "limit", minimum = 1, maximum = MaxLimit } };
            if (limit <= MaxLimit) return (int)limit;
            args["limit"] = JsonSerializer.SerializeToElement(MaxLimit);
            warnings.Add($"limit {limit} is above the maximum; {MaxLimit} applied.");
            return MaxLimit;
        }
        return limitSchema.TryGetProperty("default", out var d) && d.TryGetInt32(out var def) ? def : null;
    }

    private static async ValueTask<(CallToolResult, OutputCall)> Execute(CallToolRequestParams? request, JsonElement? inputSchema, IServiceProvider? services,
        Func<CancellationToken, ValueTask<CallToolResult>> next, CancellationToken cancellationToken, ClientLimits? client, TimeProvider time, long received)
    {
        var tool = request?.Name;
        var serverOptions = services?.GetService<ServerOptions>();
        var store = services?.GetService<ResultStore>();
        var output = new OutputCall(tool, 0, null);
        var effects = ToolEffects.Of(tool ?? "");
        var deadline = serverOptions != null ? Deadlines.Effective(effects.LongRunning, serverOptions, client!) : null;
        var leftovers = serverOptions != null ? LeftoverWork.For(serverOptions) : null;
        var joinKey = serverOptions != null ? CallJoin.Key(tool, effects.ReadOnly, request?.Arguments) : null;
        var joins = joinKey != null ? CallJoin.For(serverOptions!) : null;
        // Stopped one grace period early, so even work that ignores its token is answered for by the deadline.
        using var expiry = deadline is { } limit ? new CancellationTokenSource(Remaining(Early(limit), time.GetElapsedTime(received)), time) : null;
        using var call = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, expiry?.Token ?? CancellationToken.None);
        // at the cap a call with a deadline waits for room until that deadline; session tools (server_status) and joins never wait
        if (leftovers != null && deadline != null && tool != null && Toolsets.FamilyOf(tool) != Toolsets.Session && joins?.IsRunning(joinKey!) != true
            && !await leftovers.WaitForRoom(call.Token))
        {
            cancellationToken.ThrowIfCancellationRequested();
            return (ErrorResult.From(new ToolError(ErrorCode.ProviderUnavailable,
                $"the server is busy: {leftovers.Running} cancelled or timed-out calls are still finishing in the background (at most {leftovers.Max}); this call waited {deadline.Value.TotalSeconds:0} s and was not started.",
                "retry after details.retryAfterMs; server_status shows when they are done")
            { Details = new { retryAfterMs = (long)LeftoverWork.RetryAfter.TotalMilliseconds, leftoverCalls = leftovers.Running, max = leftovers.Max } }, tool), output);
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
            int tokens = Budget(tool, request?.Arguments, client);
            bool json = string.Equals(Environment.GetEnvironmentVariable(ResultModeVariable), "json", StringComparison.OrdinalIgnoreCase);
            var warnings = new List<string>();
            var applied = Clamp(inputSchema, request, warnings);
            bool canRetry = effects.ReadOnly && applied != null && request?.Arguments != null;
            for (int attempt = 0; ; attempt++)
            {
                async Task<(CallToolResult Result, OutputCall Output)> Work(CancellationToken token)
                {
                    var o = OutputCall.Begin(new OutputCall(tool, FitTokens(tokens), client?.MaxChars, json) { Limit = applied, ClientCancel = cancellationToken });
                    o.Warnings.AddRange(warnings);
                    return (await next(token), o);
                }
                (CallToolResult Result, OutputCall Output) outcome;
                if (joins != null)
                {
                    // The shared run keeps the server's deadline only, so a caller that left at the client's deadline can pick it up again.
                    var joined = joins.Run(joinKey!, Work, cancellationToken, Deadline(tool, serverOptions!) is { } server ? Early(server) : null,
                        o => (Copy(o.Result), o.Output), time);
                    joinStopped = joined.Stopped;
                    outcome = await WithinDeadline(joined.Result, joined.Work, call.Token, deadline, cancellationToken, leftovers, time);
                }
                else
                {
                    var work = Work(call.Token);
                    outcome = await WithinDeadline(work, work, call.Token, deadline, cancellationToken, leftovers, time);
                }
                var result = outcome.Result;
                output = outcome.Output;
                // An error object never matches the tool's output schema, and clients validate whatever structuredContent is present.
                if (result.IsError == true)
                {
                    result.StructuredContent = null;
                    return (result, output);
                }
                var finished = ToolOutput.Finish(output, result, effects.ReadOnly, canRetry && attempt < 2, store, result.Meta ??= new JsonObject(),
                    CallLog.Origin(tool, request?.Arguments));
                if (finished.RetryLimit is { } smaller)
                {
                    // The tool's text and record could not be cut to the same rows: it is asked for fewer (not joined: other arguments).
                    request!.Arguments!["limit"] = JsonSerializer.SerializeToElement(smaller);
                    applied = smaller;
                    joins = null;
                    continue;
                }
                result = finished.Result;
                // Transformed names made of zero-width and bidi characters would print as nothing or scramble the line.
                foreach (var block in result.Content.OfType<TextContentBlock>())
                    block.Text = Format.EscapeInvisible(block.Text);
                return (result, output);
            }
        }
        catch (ToolError ex)
        {
            return (ErrorResult.From(ex, tool, store), output);
        }
        // A joined run stops at its own copy of the server deadline, possibly a moment before this call's timer.
        catch (OperationCanceledException) when ((call.IsCancellationRequested || joinStopped.IsCancellationRequested) && !cancellationToken.IsCancellationRequested && deadline != null)
        {
            return (DeadlineError(tool, deadline.Value, stillRunning: false, waits.BlockedBy, client, joined: false), output);
        }
        catch (DeadlinePassedException ex)
        {
            return (DeadlineError(tool, ex.Limit, stillRunning: true, waits.BlockedBy, client, joins != null), output);
        }
        catch (OperationCanceledException) when (!call.IsCancellationRequested)
        {
            // Neither the client nor the deadline: the server cancelled the work (an unload, reload or newer request).
            return (ErrorResult.From(new ToolError(ErrorCode.Cancelled, "the work was cancelled by the server before it finished.",
                "call again; if the target was unloaded or reloaded, check list_assemblies first"), tool), output);
        }
        catch (ArgumentException ex) when (ex.ParamName == "arguments" && MissingParameter().Match(ex.Message) is { Success: true } m)
        {
            // Argument binding: a required parameter is missing.
            return (ErrorResult.From(ArgumentCheck.MissingParameter(inputSchema ?? default, m.Groups[1].Value, tool), tool), output);
        }
        catch (Exception ex) when (ArgumentCheck.FileSystemError(ex) is { } error)
        {
            // A path argument System.IO rejected or could not reach.
            return (ErrorResult.From(error, tool), output);
        }
        catch (Exception ex) when (ex is not McpException && ex is not OperationCanceledException)
        {
            // Unexpected exceptions become a descriptive tool error instead of a generic protocol error.
            services?.GetService<ILogger<AssemblyWorkspace>>()?.LogError(ex, "Tool {Tool} failed", tool);
            return (ErrorResult.Internal(ex, tool), output);
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
    internal static TimeSpan Early(TimeSpan deadline) => deadline - DeadlineGrace - AnswerSlack > deadline / 2 ? deadline - DeadlineGrace - AnswerSlack : deadline / 2;

    /// <summary>What is left of <paramref name="limit"/> after <paramref name="spent"/>; zero once it is used up.</summary>
    internal static TimeSpan Remaining(TimeSpan limit, TimeSpan spent) => spent < limit ? limit - spent : TimeSpan.Zero;

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
        LeftoverWork? leftovers, TimeProvider time)
    {
        var stopped = new TaskCompletionSource();
        using (call.Register(() => stopped.TrySetResult()))
            if (await Task.WhenAny(work, stopped.Task) == work) return await work;
        var grace = !client.IsCancellationRequested && deadline is { } d ? Grace(d) : DeadlineGrace;
        if (await Task.WhenAny(work, Task.Delay(grace, time, CancellationToken.None)) == work) return await work;
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
