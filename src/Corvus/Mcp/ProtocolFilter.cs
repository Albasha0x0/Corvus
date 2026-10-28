using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;

namespace Corvus.Mcp;

/// <summary>
/// The resources/read, prompts/get and completion/complete pipeline: the
/// deadline, escaping, budget and provenance tool results get.
/// </summary>
internal static class ProtocolFilter
{
    public static McpRequestHandler<ReadResourceRequestParams, ReadResourceResult> ReadResource(McpRequestHandler<ReadResourceRequestParams, ReadResourceResult> next) =>
        async (context, cancellationToken) =>
        {
            const string method = "resources/read";
            var uri = context.Params?.Uri ?? "";
            var result = await Within(context.Services, context.Server?.ClientInfo?.Name, method, t => next(context, t), cancellationToken);
            int tokens = Tokens(context.Services, context.Server?.ClientInfo?.Name);
            var store = context.Services?.GetService<ResultStore>();
            foreach (var text in result.Contents.OfType<TextResourceContents>()) text.Text = Fit(Format.EscapeInvisible(text.Text), method, tokens, store);
            // The guide is the server's own text; every other resource reads
            // the analyzed files.
            bool fromFile = !uri.StartsWith(DecompilerResources.Scheme + "://guide/", StringComparison.Ordinal);
            result.Meta ??= new JsonObject();
            result.Meta[ToolOutput.ProvenanceKey] = Provenance(method, uri, fromFile, result.Contents.OfType<TextResourceContents>().Select(c => c.Text));
            return result;
        };

    public static McpRequestHandler<GetPromptRequestParams, GetPromptResult> GetPrompt(McpRequestHandler<GetPromptRequestParams, GetPromptResult> next) =>
        async (context, cancellationToken) =>
        {
            const string method = "prompts/get";
            var result = await Within(context.Services, context.Server?.ClientInfo?.Name, method, t => next(context, t), cancellationToken);
            int tokens = Tokens(context.Services, context.Server?.ClientInfo?.Name);
            var store = context.Services?.GetService<ResultStore>();
            foreach (var message in result.Messages)
                if (message.Content is TextContentBlock text) text.Text = Fit(Format.EscapeInvisible(text.Text), method, tokens, store);
            result.Meta ??= new JsonObject();
            result.Meta[ToolOutput.ProvenanceKey] = Provenance(method, context.Params?.Name, fromFile: false,
                result.Messages.Select(m => (m.Content as TextContentBlock)?.Text ?? ""));
            return result;
        };

    public static McpRequestHandler<CompleteRequestParams, CompleteResult> Complete(McpRequestHandler<CompleteRequestParams, CompleteResult> next) =>
        async (context, cancellationToken) =>
        {
            var result = await Within(context.Services, context.Server?.ClientInfo?.Name, "completion/complete", t => next(context, t), cancellationToken);
            // Type names come from the files; an escaped name resolves when passed back.
            result.Completion.Values = [.. result.Completion.Values.Select(Format.EscapeInvisible)];
            return result;
        };

    /// <summary>
    /// The handler's result within the call deadline; past it the work is told
    /// to stop, counted as leftover work, and the request fails.
    /// </summary>
    /// <remarks>An error message, which can quote file text, is escaped as a
    /// result is.</remarks>
    private static async ValueTask<T> Within<T>(IServiceProvider? services, string? clientName, string method,
        Func<CancellationToken, ValueTask<T>> work, CancellationToken cancellationToken)
    {
        try { return await Bounded(services, clientName, method, work, cancellationToken); }
        catch (McpProtocolException ex) { throw new McpProtocolException(Format.EscapeMarkers(ex.Message), ex.ErrorCode); }
        catch (McpException ex) { throw new McpException(Format.EscapeMarkers(ex.Message)); }
    }

    private static async ValueTask<T> Bounded<T>(IServiceProvider? services, string? clientName, string method,
        Func<CancellationToken, ValueTask<T>> work, CancellationToken cancellationToken)
    {
        var options = services?.GetService<ServerOptions>();
        var limit = options != null ? Deadlines.Effective(false, options, ClientProfiles.Resolve(options, clientName)) : null;
        if (limit == null) return await work(cancellationToken);
        var time = services!.GetService<TimeProvider>() ?? TimeProvider.System;
        using var call = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var task = work(call.Token).AsTask();
        try
        {
            return await task.WaitAsync(limit.Value, time, cancellationToken);
        }
        catch (TimeoutException)
        {
            await call.CancelAsync();
            LeftoverWork.For(options!).Track(task);
            throw new McpProtocolException($"{method} did not finish within {limit.Value.TotalSeconds:0} s; the work was told to stop.", McpErrorCode.InternalError);
        }
    }

    private static int Tokens(IServiceProvider? services, string? clientName)
    {
        var options = services?.GetService<ServerOptions>();
        int ceiling = options != null ? ClientProfiles.Resolve(options, clientName).MaxTokens : ClientProfiles.DefaultMaxTokens;
        return Math.Min(OutputClasses.Budget(OutputClass.Code), ceiling);
    }

    /// <summary>
    /// <paramref name="text"/> cut to the response frame of
    /// <paramref name="tokens"/>; the whole text is kept for read_result.
    /// </summary>
    private static string Fit(string text, string method, int tokens, ResultStore? store)
    {
        if (store == null || text.Length <= ResponseBudget.Frame(tokens)) return text;
        var cut = ResponseBudget.Enforce(new CallToolResult { Content = [new TextContentBlock { Text = text }] }, method, tokens, store);
        return string.Concat(cut.Content.OfType<TextContentBlock>().Select(b => b.Text));
    }

    private static JsonObject Provenance(string method, string? target, bool fromFile, IEnumerable<string> texts)
    {
        var p = new JsonObject { ["method"] = method, ["target"] = target, ["corvus"] = ServerIdentity.InformationalVersion };
        if (fromFile)
        {
            p["untrustedContent"] = true;
            p["source"] = "analysis_target";
        }
        p["resultSha256"] = ResultHashes.Sha256(string.Concat(texts));
        return p;
    }
}
