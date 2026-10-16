using System.ComponentModel;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tools;

/// <summary>
/// Sessions on local programs: open, stop points, typed reads and the event ring. Observation only; every tool refuses
/// calls unless the server starts with --allow-live, and starting a program also needs --allow-live-spawn.
/// </summary>
[McpServerToolType]
public sealed class LiveSessionTools(ServerOptions options)
{
    private const string SessionDescription = "Session id from live_session.";

    /// <summary>A module of the observed program and the loaded image it matched (null when none did).</summary>
    public sealed record LiveModule(string Name, string Base, string? Image, string? Sha256);

    /// <summary>An address a result names, as saved records carry it for read_result format=verify.</summary>
    public sealed record LiveNamedAddress(string Image, string Sha256, string Rva, string Name);

    public sealed record LiveSessionRow(string Session, string Backend, string Program, int ProcessId, string State);

    public sealed record LiveSessionReport(string Action,
        [property: Description("Session id; null for action=list.")] string? Session,
        string? Backend, string? Program, int? ProcessId,
        [property: Description("open, stopped, running, closed or failed.")] string? State,
        IReadOnlyList<LiveModule> Modules, IReadOnlyList<LiveSessionRow> Sessions);

    public sealed record LiveStopPoint(string Id,
        [property: Description("As given: a name, module!export, address or file:line.")] string Where,
        string? Address, int Hits);

    public sealed record LiveFrame(string Address, string? Image, string? Name, string? Source);

    public sealed record LiveStop(string Thread,
        [property: Description("stop point, exception, exit or pause.")] string Reason,
        string? StopPoint, IReadOnlyList<LiveFrame> Frames);

    public sealed record LiveStopPointReport(string Session, IReadOnlyList<LiveStopPoint> StopPoints, LiveStop? Stop)
    {
        public IReadOnlyList<LiveNamedAddress>? NamedAddresses { get; init; }
    }

    public sealed record LiveValue(string Name, string Type, string Value, string? Address);

    public sealed record LiveReadReport(string Session, string Thread, IReadOnlyList<LiveValue> Registers, IReadOnlyList<LiveValue> Memory)
    {
        public IReadOnlyList<LiveNamedAddress>? NamedAddresses { get; init; }
    }

    public sealed record LiveEvent(long Sequence,
        [property: Description("stop, exception, module, thread or exit.")] string Kind,
        string? Thread, string? Address, string? Name, string Text);

    public sealed record LiveEventPage(string Session, IReadOnlyList<LiveEvent> Items,
        [property: Description("Cursor for the next page; null at the end of the ring.")] string? Cursor,
        [property: Description("Events the ring dropped before this page (oldest first).")] int Dropped)
    {
        public IReadOnlyList<LiveNamedAddress>? NamedAddresses { get; init; }
    }

    [McpServerTool(Name = "live_session", Title = "Session on a local program", UseStructuredContent = true, OutputSchemaType = typeof(LiveSessionReport))]
    [Description("Open, list, inspect or close a session on a local program. Returns the session id, the backend, and the program's modules matched to loaded images.")]
    public Task<string> LiveSession(
        [Description("list, attach, spawn, status or close.")] string action = "list",
        [Description("attach: process id or name; spawn: program path.")] string? program = null,
        [Description("spawn: command-line arguments.")] string? arguments = null,
        [Description(SessionDescription)] string? session = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            Require(action.Trim().Equals("spawn", StringComparison.OrdinalIgnoreCase));
            return NoBackend();
        }, cancellationToken);

    [McpServerTool(Name = "live_break", Title = "Stop points in a session", UseStructuredContent = true, OutputSchemaType = typeof(LiveStopPointReport))]
    [Description("Set, list or clear stop points in a session, by name, address or file:line. With wait, returns the next stop with a named stack.")]
    public Task<string> LiveBreak(
        [Description(SessionDescription)] string session,
        [Description("list, set or clear.")] string action = "list",
        [Description("set: a name, module!export, address or file:line.")] string? at = null,
        [Description("clear: stop point id.")] string? stopPoint = null,
        [Description("Wait for the next stop.")] bool wait = false,
        [Description("wait: seconds (1-300).")] int waitSeconds = 30,
        CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            Require(spawn: false);
            return NoBackend();
        }, cancellationToken);

    [McpServerTool(Name = "live_read", Title = "Read a stopped thread", UseStructuredContent = true, OutputSchemaType = typeof(LiveReadReport))]
    [Description("Read a stopped thread's registers and memory as typed values, using the image's types and names.")]
    public Task<string> LiveRead(
        [Description(SessionDescription)] string session,
        [Description("Thread id; default the stopped one.")] string? thread = null,
        [Description("Register names, comma-separated; default the general ones.")] string? registers = null,
        [Description("An address or name to read.")] string? memory = null,
        [Description("memory: a type name from the image's types.")] string? type = null,
        [Description("memory: bytes without a type (max 4096).")] int length = 64,
        CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            Require(spawn: false);
            return NoBackend();
        }, cancellationToken);

    [McpServerTool(Name = "live_events", Title = "Session events", UseStructuredContent = true, OutputSchemaType = typeof(LiveEventPage))]
    [Description("Page a session's event ring with a cursor and filters, so polling never re-sends earlier events.")]
    public Task<string> LiveEvents(
        [Description(SessionDescription)] string session,
        [Description("Cursor from an earlier page; default the oldest event kept.")] string? cursor = null,
        [Description("Only this kind: stop, exception, module, thread or exit.")] string? kind = null,
        [Description("Only this thread id.")] string? thread = null,
        [Description(ToolSupport.LimitDescription)] int limit = 100,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            Require(spawn: false);
            return NoBackend();
        }, cancellationToken);

    /// <summary>The opt-in flags: sessions need --allow-live, starting a program --allow-live-spawn as well.</summary>
    private void Require(bool spawn)
    {
        if (!options.AllowLive)
            throw new ToolError(ErrorCode.Unsupported, "Sessions on running programs are off in this server.",
                $"start the server with {ServerOptions.AllowLiveOption} (or {ServerOptions.AllowLiveVariable}=1)");
        if (spawn && !options.AllowLiveSpawn)
            throw new ToolError(ErrorCode.Unsupported, "Starting a program under a session is off in this server.",
                $"start the server with {ServerOptions.AllowLiveSpawnOption} (or {ServerOptions.AllowLiveSpawnVariable}=1) as well");
    }

    private static string NoBackend() =>
        throw new ToolError(ErrorCode.ProviderUnavailable, "No session backend is set up in this server.", "check server_status for the session backend");
}
