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

/// <summary>The tools/call pipeline: argument checks, output budget, structured content, errors as results, notices, provenance and resource notifications.</summary>
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
        var audit = CallAudit.For(options);
        void Audit(string outcome, CallToolResult? r)
        {
            if (audit == null) return;
            var inputs = ToolOutput.Inputs(request?.Arguments, services?.GetService<AssemblyWorkspace>());
            audit.Record(tool, request?.Arguments, clientName, outcome, inputs.Count == 1 ? inputs[0].Sha256 : null, r);
        }
        CallToolResult result;
        OutputCall output;
        try
        {
            (result, output) = await Execute(request, inputSchema, services, next, cancellationToken, client, time, received);
        }
        catch (OperationCanceledException)
        {
            log.Cancelled();
            Audit("cancelled", null);
            throw;
        }
        catch
        {
            log.Failed();
            Audit("exception", null);
            throw;
        }
        // The bookkeeping below keeps the client's cancellation: Execute's scope, deadline included, has ended.
        using var waits = AssemblyWorkspace.CancelWaitsWith(cancellationToken, tool);
        services?.GetService<ResourceSubscriptions>()?.Check();
        if (tool != null && !ToolEffects.Of(tool).ReadOnly) services?.GetService<Services.EditJournal>()?.Sync();
        // Recorded whole, before the budget cuts it; read_result's own pages are not findings.
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
                    record["notices"] = new JsonArray(notices.Select(n => (JsonNode)JsonValue.Create(Format.EscapeInvisible(n))!).ToArray());
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
        Audit(result.IsError == true ? CallLog.CodeOf(result) : "ok", result);
        return result;
    }

    /// <summary>The token estimate parts are fitted to: 5% under the budget.</summary>
    // The estimate runs up to 10% low on rare names and packed string tables (against o200k); the budget allows 5% over.
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

    /// <summary>The limit the call applies (schema default when not given), or null without a limit; out of range is invalid_argument, over MaxLimit is clamped and reported.</summary>
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

    private static bool Writes(bool readOnly, CallToolRequestParams? request) =>
        !readOnly || request?.Arguments?.Keys.Any(ArgumentCheck.OutputPathParameters.Contains) == true;

    // Roots are deprecated as of protocol 2026-07-28 (SEP-2577); clients of
    // earlier versions still offer them, and a client that does not adds none.
#pragma warning disable MCP9005
    /// <summary>Whether the client offers roots.</summary>
    private static bool OffersRoots(IServiceProvider? services) => services?.GetService<McpServer>() is { ClientCapabilities.Roots: not null };

    /// <summary>
    /// The client's roots as local folders; none when it offers no roots or
    /// does not answer in 5 s.
    /// </summary>
    private static async Task<IReadOnlyList<string>> ClientRoots(IServiceProvider? services, CancellationToken ct)
    {
        if (services?.GetService<McpServer>() is not { ClientCapabilities.Roots: not null } server) return [];
        using var bound = CancellationTokenSource.CreateLinkedTokenSource(ct);
        bound.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            var answer = await server.RequestRootsAsync(new ListRootsRequestParams(), bound.Token);
            return [.. answer.Roots.Select(r => Uri.TryCreate(r.Uri, UriKind.Absolute, out var u) && u.IsFile ? u.LocalPath : null).OfType<string>()];
        }
        catch (Exception ex) when (ex is McpException or JsonException || ex is OperationCanceledException && !ct.IsCancellationRequested) { return []; }
    }
#pragma warning restore MCP9005

    private static async ValueTask<(CallToolResult, OutputCall)> Execute(CallToolRequestParams? request, JsonElement? inputSchema, IServiceProvider? services,
        Func<CancellationToken, ValueTask<CallToolResult>> next, CancellationToken cancellationToken, ClientLimits? client, TimeProvider time, long received)
    {
        var tool = request?.Name;
        var serverOptions = services?.GetService<ServerOptions>();
        var store = services?.GetService<ResultStore>();
        var output = new OutputCall(tool, 0, null);
        var effects = ToolEffects.Of(tool ?? "");
        var deadline = serverOptions != null ? Deadlines.Effective(effects.LongRunning, serverOptions, client!) : null;
        var ceiling = serverOptions != null ? Ceiling(tool, serverOptions) : null;
        bool byCeiling = ceiling is { } bound && (deadline == null || bound < deadline);
        if (byCeiling) deadline = ceiling;
        var leftovers = serverOptions != null ? LeftoverWork.For(serverOptions) : null;
        var joinKey = serverOptions != null ? CallJoin.Key(tool, effects.ReadOnly, request?.Arguments) : null;
        var joins = joinKey != null ? CallJoin.For(serverOptions!) : null;
        // Stopped one grace period early, so even work that ignores its token is answered for by the deadline.
        using var expiry = deadline != null ? new CancellationTokenSource() : null;
        using var stopTimer = deadline is { } limit ? StopTimers.After(Remaining(Early(limit), time.GetElapsedTime(received)), time, expiry!.Cancel) : null;
        using var call = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, expiry?.Token ?? CancellationToken.None);
        // At the cap a call that reads files in process waits for room until its
        // deadline, at most the server deadline; other calls and joins never wait.
        var wait = byCeiling ? Deadlines.Server(serverOptions!) : deadline;
        using var waitLimit = byCeiling ? new CancellationTokenSource(wait!.Value, time) : null;
        using var waitToken = CancellationTokenSource.CreateLinkedTokenSource(call.Token, waitLimit?.Token ?? CancellationToken.None);
        if (leftovers != null && deadline != null && tool != null && ReadsFiles(tool) && joins?.IsRunning(joinKey!) != true
            && !await leftovers.WaitForRoom(waitToken.Token))
        {
            cancellationToken.ThrowIfCancellationRequested();
            return (ErrorResult.From(new ToolError(ErrorCode.ProviderUnavailable,
                $"the server is busy: {leftovers.Running} cancelled or timed-out calls are still finishing (at most {leftovers.Max}); this call reads files and waited {wait!.Value.TotalSeconds:0} s without starting.",
                "retry after details.retryAfterMs; server_status shows when they are done")
            { Details = new { retryAfterMs = (long)LeftoverWork.RetryAfter.TotalMilliseconds, leftoverCalls = leftovers.Running, max = leftovers.Max } }, tool), output);
        }
        using var waits = AssemblyWorkspace.CancelWaitsWith(call.Token, tool);
        using var spent = Spent.Enter(new Spent(call.Token));
        var joinStopped = CancellationToken.None;
        string? phase = null;
        try
        {
            // The deadline covers the argument check and the client's roots: a
            // path check can probe the file system for seconds, and the roots
            // request waits up to 5 s for the client.
            phase = "checking its arguments";
            var workspace = services?.GetService<AssemblyWorkspace>();
            bool confine = serverOptions is { ConfineOutputs: true };
            // Only a client that offers roots is asked; without one the roots
            // resolve here.
            bool askClient = confine && serverOptions!.OutputDirs == null && Writes(effects.ReadOnly, request) && OffersRoots(services);
            IReadOnlyList<string>? roots = confine && !askClient ? OutputRoots.Resolve(serverOptions!.OutputDirs, []) : null;
            if (inputSchema != null || workspace != null || askClient)
            {
                var prepare = Task.Run(async () =>
                {
                    if (askClient) roots = OutputRoots.Resolve(null, await ClientRoots(services, call.Token));
                    // The output check refuses a path outside the roots, so
                    // they are in force.
                    using (OutputRoots.Enter(roots))
                    {
                        if (inputSchema is { } schema)
                        {
                            ArgumentCheck.Apply(schema, request?.Arguments, tool);
                            ArgumentCheck.RequireAll(schema, request?.Arguments, tool);
                        }
                        if (workspace != null) Targets.PreResolve(workspace, tool, request?.Arguments?.AsReadOnly());
                    }
                    return true;
                }, call.Token);
                await WithinDeadline(prepare, prepare, call.Token, deadline, cancellationToken, leftovers, time, tool);
            }
            phase = null;
            using var confined = OutputRoots.Enter(roots);
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
                    var joined = joins.Run(joinKey!, Work, cancellationToken, (Deadline(tool, serverOptions!) ?? ceiling) is { } server ? Early(server) : null,
                        o => (Copy(o.Result), o.Output), time);
                    joinStopped = joined.Stopped;
                    outcome = await WithinDeadline(joined.Result, joined.Work, call.Token, deadline, cancellationToken, leftovers, time, tool);
                }
                else
                {
                    var work = Work(call.Token);
                    outcome = await WithinDeadline(work, work, call.Token, deadline, cancellationToken, leftovers, time, tool);
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
                return (finished.Result, output);
            }
        }
        catch (ToolError ex)
        {
            return (ErrorResult.From(ex, tool, store), output);
        }
        // A joined run stops at its own copy of the server deadline, possibly a moment before this call's timer.
        catch (OperationCanceledException) when ((call.IsCancellationRequested || joinStopped.IsCancellationRequested) && !cancellationToken.IsCancellationRequested && deadline != null)
        {
            return (DeadlineError(tool, deadline.Value, stillRunning: false, waits.BlockedBy, client, joined: false, byCeiling, phase), output);
        }
        catch (DeadlinePassedException ex)
        {
            return (DeadlineError(tool, ex.Limit, stillRunning: true, waits.BlockedBy, client, joins != null && phase == null, byCeiling, phase), output);
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

    /// <summary>
    /// Families whose calls run in a worker or session with limits of their
    /// own: no ceiling.
    /// </summary>
    private static readonly HashSet<string> OwnLimits = new(StringComparer.Ordinal) { "engine", "live" };

    /// <summary>
    /// The ceiling of <paramref name="tool"/>'s work
    /// (<see cref="ServerOptions.CallCeiling"/>); null for engine and live tools
    /// or when off.
    /// </summary>
    public static TimeSpan? Ceiling(string? tool, ServerOptions options) =>
        tool == null || OwnLimits.Contains(Toolsets.FamilyOf(tool) ?? "") ? null : options.CallCeiling;

    /// <summary>
    /// Whether <paramref name="tool"/> reads input files in process, as its
    /// contract declares; an unknown tool counts as one that does.
    /// </summary>
    public static bool ReadsFiles(string tool) => ToolContract.Of(tool).Reads.HasFlag(FileReads.Server);

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

    /// <summary>The tool's result; on cancel or deadline the work gets <see cref="DeadlineGrace"/> to stop, then finishes in the background, counted in <paramref name="leftovers"/>.</summary>
    private static async Task<T> WithinDeadline<T>(Task<T> work, Task shared, CancellationToken call, TimeSpan? deadline, CancellationToken client,
        LeftoverWork? leftovers, TimeProvider time, string? tool)
    {
        var stopped = new TaskCompletionSource();
        using (call.Register(() => stopped.TrySetResult()))
            if (await Task.WhenAny(work, stopped.Task) == work) return await work;
        var grace = !client.IsCancellationRequested && deadline is { } d ? Grace(d) : DeadlineGrace;
        if (await Task.WhenAny(work, StopTimers.Delay(grace, time)) == work) return await work;
        leftovers?.Track(shared, tool);
        _ = work.ContinueWith(t => t.Exception, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
        client.ThrowIfCancellationRequested();
        throw new DeadlinePassedException(deadline!.Value);
    }

    /// <param name="blockedBy">The workspace lock holders the call was still waiting for, else null.</param>
    /// <param name="joined">The work runs on under a join key: the same call made again picks it up.</param>
    /// <param name="byCeiling">The limit is <see cref="ServerOptions.CallCeiling"/>.</param>
    /// <param name="phase">The step the call was in before its work started ("checking its arguments"), else null.</param>
    private static CallToolResult DeadlineError(string? tool, TimeSpan limit, bool stillRunning, string? blockedBy, ClientLimits? client, bool joined, bool byCeiling,
        string? phase = null)
    {
        bool byClient = !byCeiling && client?.DeadlineSeconds is { } seconds && limit < TimeSpan.FromSeconds(seconds);
        var source = byCeiling ? $"the {ServerOptions.MaxCallMinutesVariable} ceiling" : byClient ? $"the client waits {client!.DeadlineSeconds} s" : $"{DeadlineFactor}x --timeout";
        return ErrorResult.From(new ToolError(ErrorCode.Timeout,
            $"the call did not finish within {limit.TotalSeconds:0} s ({source})" +
            (phase != null ? $" while {phase}" : "") +
            (blockedBy != null ? $": it was waiting for the workspace lock, held by {blockedBy}" : "") +
            $"{(stillRunning ? "; its work is still finishing in the background" : "")}.",
            blockedBy != null
                ? "call again once that call has finished (server_status lists the lock holders); a long-running call can be cancelled by its client"
                : stillRunning && joined ? "call again with the same arguments to pick up the running work"
                : "narrow the call (one member instead of a type, a smaller limit or scope)" + (stillRunning ? "; or retry after details.retryAfterMs, once the background work is done" : ""))
        {
            Details = new { deadlineSeconds = limit.TotalSeconds, stillRunning, partial = false, blockedBy, deadlineSource = byCeiling ? "ceiling" : byClient ? client!.DeadlineSource : "server" },
            RetryAfter = stillRunning ? LeftoverWork.RetryAfter : null,
        }, tool);
    }

    [GeneratedRegex("required parameter '([^']+)'")]
    private static partial Regex MissingParameter();
}

/// <summary>Cancelled or timed-out calls still running in the background; at <see cref="Max"/>, a new call waits until its deadline, then is refused as busy.</summary>
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

    private readonly Dictionary<Task, (string Tool, DateTime Since)> _tracked = [];

    /// <summary>
    /// The calls still running, oldest first: tool name (or "a tool") and when
    /// they were left.
    /// </summary>
    public IReadOnlyList<(string Tool, DateTime Since)> Calls
    {
        get { lock (_tracked) return [.. _tracked.Values.OrderBy(c => c.Since)]; }
    }

    /// <summary>Counts <paramref name="work"/> until it ends; a joined run left by several callers counts once.</summary>
    public void Track(Task work, string? tool = null)
    {
        lock (_tracked)
            if (!_tracked.TryAdd(work, (tool ?? "a tool", DateTime.UtcNow))) return;
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
