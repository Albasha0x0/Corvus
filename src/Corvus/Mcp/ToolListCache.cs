using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;

namespace Corvus.Mcp;

/// <summary>
/// tools/list answered from a serialized copy per listed profile, built once and dropped when the tool collection changes
/// (listChanged). The SDK otherwise turns every tool into a JSON tree on each request (≈ 200 ms for the full catalog).
/// </summary>
public static class ToolListCache
{
    /// <summary>One profile's tools/list result as UTF-8 JSON, and the catalog digest of what it lists.</summary>
    public sealed record Listing(byte[] Result, string Digest, int Count);

    private sealed class State
    {
        public readonly ConcurrentDictionary<string, Lazy<Listing>> ByProfile = new(StringComparer.Ordinal);
        public int Built, Served;
    }

    private static readonly ConditionalWeakTable<McpServerOptions, State> States = new();

    /// <summary>Answers a first-page tools/list from the cache; every other message goes on.</summary>
    public static McpMessageFilter Filter => next => async (context, ct) =>
    {
        if (context.JsonRpcMessage is JsonRpcRequest { Method: RequestMethods.ToolsList } request && request.Params?["cursor"] is null
            && context.Server?.ServerOptions is { ToolCollection: not null } options)
        {
            var listing = For(options, Profile(context.Services, context.Server.ClientInfo?.Name));
            Interlocked.Increment(ref StateOf(options).Served);
            // The server routes the response by the request's own transport; only transports set Context.
            await context.Server.SendMessageAsync(new JsonRpcResponse { Id = request.Id, Result = JsonNode.Parse(listing.Result) }, ct).ConfigureAwait(false);
            return;
        }
        await next(context, ct).ConfigureAwait(false);
    };

    /// <summary>The digest of what this server lists to <paramref name="server"/>'s client.</summary>
    public static string Digest(McpServer server) =>
        For(server.ServerOptions, Profile(server.Services, server.ClientInfo?.Name)).Digest;

    /// <summary>
    /// The profile listed to a client: its default from <see cref="ClientProfiles.Resolve"/> (lean for clients that cap tool
    /// counts) when the server was started without --toolsets, else null (every registered tool).
    /// </summary>
    internal static string? Profile(IServiceProvider? services, string? clientName)
    {
        if (services?.GetService<ServerOptions>() is not { } options || options.ToolsetsText != null) return null;
        var profile = ClientProfiles.Resolve(options, clientName).Toolsets;
        return profile == ClientProfiles.Full ? null : profile;
    }

    /// <summary>The cached listing of <paramref name="options"/>' tools in <paramref name="profile"/> (null: all registered).</summary>
    public static Listing For(McpServerOptions options, string? profile)
    {
        var state = StateOf(options);
        return state.ByProfile.GetOrAdd(profile ?? "", _ => new Lazy<Listing>(() =>
        {
            Interlocked.Increment(ref state.Built);
            return Build(options, profile);
        })).Value;
    }

    /// <summary>Listings built and tools/list requests answered from the cache for <paramref name="options"/>.</summary>
    internal static (int Built, int Served) Counts(McpServerOptions options)
    {
        var state = StateOf(options);
        return (Volatile.Read(ref state.Built), Volatile.Read(ref state.Served));
    }

    private static State StateOf(McpServerOptions options) => States.GetValue(options, o =>
    {
        var s = new State();
        if (o.ToolCollection is { } tools) tools.Changed += (_, _) => s.ByProfile.Clear();
        return s;
    });

    private static Listing Build(McpServerOptions options, string? profile)
    {
        var enabled = profile is null ? null : Toolsets.Parse(profile);
        var tools = (options.ToolCollection ?? []).Where(t => enabled is null || Profiles.Registers(enabled, t.ProtocolTool.Name)).Select(t => t.ProtocolTool).ToList();
        var result = new ListToolsResult { Tools = tools };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(result, McpJsonUtilities.DefaultOptions);
        var digest = Catalog.Digest(tools.Select(t => JsonSerializer.SerializeToNode(t, McpJsonUtilities.DefaultOptions)),
            (options.PromptCollection ?? []).Select(p => JsonSerializer.SerializeToNode(p.ProtocolPrompt, McpJsonUtilities.DefaultOptions)));
        return new Listing(bytes, digest, tools.Count);
    }
}
