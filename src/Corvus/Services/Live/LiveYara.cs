using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Services;

/// <summary>A live YARA scan: the worker's result, whether the rules came from query text, and notes on what the capture left out.</summary>
public sealed record LiveYaraScan(YaraScanResult Result, bool FromQuery, IReadOnlyList<string> Notes);

public sealed partial class LiveSessionService
{
    /// <summary>Most bytes of a program's memory one scan saves; ranges past it are left out and counted.</summary>
    public const long MaxCaptureBytes = 1L << 30;

    private static readonly TimeSpan CaptureTimeout = TimeSpan.FromMinutes(10);

    // The memory goes to a private temporary file deleted after the scan.
    /// <summary>Matches of the YARA rules <paramref name="query"/> names in the program's writable memory; refuses macOS and backends without capture.</summary>
    public async Task<LiveYaraScan> ScanMemoryAsync(LiveSession session, string query, CancellationToken ct)
    {
        Live(session);
        NativeOnly(session, "A memory scan");
        if (session.Platform == "darwin")
            throw new ToolError(ErrorCode.Unsupported, "a live YARA scan is not supported on macOS.", "search_container kind=yara scans the program's files");
        var dir = Path.Combine(Path.GetTempPath(), "corvus-live-yara", $"{Environment.ProcessId}-{Guid.NewGuid():N}");
        // The capture holds the program's memory: readable by this user only, and deleted after the scan.
        Native.Providers.PrivateFolder.Create(dir);
        try
        {
            var capture = Path.Combine(dir, "memory.bin");
            JsonElement saved;
            try
            {
                saved = await session.Worker.RequestAsync("capture_memory",
                    new JsonObject { ["path"] = capture, ["protection"] = "rw-", ["limit"] = MaxCaptureBytes }, CaptureTimeout, ct).ConfigureAwait(false);
            }
            catch (ToolError e) when (e.Code is ErrorCode.InvalidArgument or ErrorCode.NotFound && e.Message.StartsWith("unknown op", StringComparison.Ordinal))
            {
                throw new ToolError(ErrorCode.Unsupported, $"the {session.Backend} session worker cannot save program memory; the scan is not checked.",
                    "start the session again with this server's worker (live_session action=close, then start)");
            }
            List<LiveModuleState> modules;
            lock (session.Modules) modules = [.. session.Modules];
            var index = Path.Combine(dir, "memory.json");
            File.WriteAllText(index, new JsonObject
            {
                ["ranges"] = JsonNode.Parse(saved.GetProperty("ranges").GetRawText()),
                ["modules"] = new JsonArray([.. modules.Select(m => (JsonNode)new JsonObject { ["base"] = $"0x{m.Base:X}", ["size"] = (uint)Math.Min(m.Size, uint.MaxValue), ["path"] = m.Path })]),
            }.ToJsonString());
            var request = new JsonObject { ["path"] = capture, ["capture"] = index };
            var fromQuery = YaraSearchKind.WithRules(request, query);
            var result = await Task.Run(() => YaraSearchKind.Run(request, session.Program, ct), ct).ConfigureAwait(false);
            long bytes = saved.GetProperty("bytes").GetInt64(), unread = saved.GetProperty("unread").GetInt64();
            int listed = saved.GetProperty("listed").GetInt32(), left = saved.GetProperty("left").GetInt32();
            var notes = new List<string>
            {
                $"Writable memory: {listed:N0} ranges, {bytes:N0} bytes saved while the program ran; changes meanwhile may be missed. " +
                "Image code and read-only data are not scanned (search_container kind=yara scans a module's file).",
            };
            if (unread > 0) notes.Add($"{unread:N0} bytes could not be read (freed or protected meanwhile); they are unknown, not clean.");
            if (left > 0) notes.Add($"{left:N0} ranges past the {MaxCaptureBytes >> 20:N0} MB capture limit were not scanned.");
            return new LiveYaraScan(result, fromQuery, notes);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
    }
}
