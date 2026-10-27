using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tools;

/// <summary>Evidence bundles: kept results with their calls and content hashes; verifying re-runs each call and names each record that differs.</summary>
public static partial class EvidenceBundle
{
    public const string FormatName = "corvus-evidence/1";

    public sealed record Record(string Id, string Tool, string? Arguments, IReadOnlyList<KeptInput> Inputs, string ContentSha256, string Text, string? Structured);

    public sealed record Bundle(string Format, string Corvus, DateTimeOffset Created, IReadOnlyList<Record> Records);

    /// <summary>One record's verdict: match, or what differs; a skipped record was not re-run.</summary>
    public sealed record Check(string Id, string Tool, bool Matches, string Detail)
    {
        [System.Text.Json.Serialization.JsonIgnore]
        public bool Skipped => !Matches && Detail.StartsWith(SkippedPrefix, StringComparison.Ordinal);
    }

    private const string SkippedPrefix = "skipped: ";

    /// <summary>Whether a recorded call may be made again from inside another call: only tools that change and write nothing.</summary>
    // A bundle file is input: re-running a tool that writes, exports or edits would act without the user approving that call.
    public static bool Rerunnable(string tool) => ToolEffects.Of(tool).ReadOnly;

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>The hash a record's content is compared by: its record (canonical JSON) when kept, else its text.</summary>
    public static string ContentSha256(string text, string? structured) =>
        ResultHashes.Sha256(structured != null ? ResultHashes.Canonical(JsonNode.Parse(structured)) : text);

    /// <summary>Records of kept results (r-…) and of this session's latest calls (last:N), in the order named.</summary>
    public static Bundle Build(ResultStore store, RecentCalls? recent, IEnumerable<string> ids)
    {
        var kept = new List<KeptResult>();
        foreach (var id in ids)
            if (id.StartsWith("last:", StringComparison.OrdinalIgnoreCase))
            {
                if (!int.TryParse(id[5..], out int n) || n < 1)
                    throw new ToolError(ErrorCode.InvalidArgument, $"'{id}' is not last:N with N of 1 or more.", "id=last:10");
                kept.AddRange(recent?.Last(n) ?? []);
            }
            else kept.Add(store.Read(id));
        if (kept.Count == 0) throw new ToolError(ErrorCode.NotFound, "No results to bundle: no call has succeeded in this session yet.", "make the calls, then id=last:N");
        return new(FormatName, ServerIdentity.InformationalVersion, DateTimeOffset.UtcNow,
            [.. kept.Select(k => new Record(k.Id, k.Info.Tool, k.Info.Arguments, k.Info.Inputs, ContentSha256(k.Text, k.Record), k.Text, k.Record))]);
    }

    public static string Serialize(Bundle bundle) => JsonSerializer.Serialize(bundle, Json);

    /// <summary>What format=verify checks: a bundle file, one entry of it (path#id), or a kept result or recent call as a one-record bundle.</summary>
    public static Bundle Of(string id, ResultStore store, RecentCalls? recent)
    {
        var r = id.Trim();
        if (File.Exists(r)) return Load(r);
        var item = EvidenceInput.Resolve(r, store, recent);
        var record = new Record(item.Source.Ref, item.Source.Tool, item.Source.Arguments, item.Source.Inputs, ContentSha256(item.Text, item.Record), item.Text, item.Record);
        return new(FormatName, ServerIdentity.InformationalVersion, item.Source.Created ?? DateTimeOffset.UtcNow, [record]);
    }

    /// <summary>One record against another result, without running either: the call, its inputs and the content compared.</summary>
    public static Check Compare(Record r, EvidenceInput.Item other)
    {
        var differs = new List<string>();
        if (other.Source.Tool != r.Tool) differs.Add($"another tool ({other.Source.Tool})");
        else if (other.Source.Arguments != r.Arguments) differs.Add("other arguments");
        foreach (var i in r.Inputs)
            if (other.Source.Inputs.FirstOrDefault(x => x.Id == i.Id) is { } o && o.Sha256 != i.Sha256)
                differs.Add($"input {i.Id} SHA-256 {i.Sha256[..12]}… here, {o.Sha256[..12]}… there");
        var hash = ContentSha256(other.Text, other.Record);
        if (hash != r.ContentSha256) differs.Add($"the content differs: SHA-256 {r.ContentSha256[..12]}… here, {hash[..12]}… there");
        return differs.Count == 0 ? new(r.Id, r.Tool, true, $"same call, inputs and content as {other.Source.Ref}") : new(r.Id, r.Tool, false, string.Join("; ", differs));
    }

    public static Bundle Load(string path)
    {
        var full = InputFiles.RequireRegularFile(path, "evidence bundle");
        try
        {
            var bundle = JsonSerializer.Deserialize<Bundle>(File.ReadAllText(full), Json);
            if (bundle?.Format != FormatName || bundle.Records == null)
                throw new ToolError(ErrorCode.MalformedInput, $"{full} is not a {FormatName} bundle.", "pass a file written by read_result format=evidence");
            return bundle;
        }
        catch (JsonException e)
        {
            throw new ToolError(ErrorCode.MalformedInput, $"{full} is not an evidence bundle: {e.Message}", "pass a file written by read_result format=evidence");
        }
    }

    /// <summary>Re-runs every record through <see cref="CallFilter.Run"/> as a client call would and compares.</summary>
    public static async Task<List<Check>> Verify(Bundle bundle, RequestContext<CallToolRequestParams> context, ResultStore store, AssemblyWorkspace workspace, CancellationToken ct)
    {
        var checks = new List<Check>();
        foreach (var r in bundle.Records)
        {
            ct.ThrowIfCancellationRequested();
            var changed = workspace.Read(() => r.Inputs.Select(i => (i, now: (string?)ToolOutput.Input(i.Id, workspace)?["sha256"])).Where(x => x.now != x.i.Sha256).ToList());
            if (changed.Count > 0)
            {
                checks.Add(new(r.Id, r.Tool, false, string.Join("; ", changed.Select(x => x.now == null
                    ? $"input {x.i.Id} is not available here" : $"input {x.i.Id} changed: SHA-256 {x.i.Sha256[..12]}… then, {x.now[..12]}… now"))));
                continue;
            }
            if (ObservationTools.Contains(r.Tool))
            {
                var code = context.Services?.GetService(typeof(Services.NativeCodeService)) as Services.NativeCodeService;
                checks.Add(CheckObservation(r, a => workspace.Read(() => workspace.Natives.FirstOrDefault(n => n.Id == a.Image) is { } native
                    ? (native.OriginalSha256, code?.Ready(native)?.NameAt(a.Rva))
                    : ((string?)null, (string?)null))));
                continue;
            }
            if (ToolEffects.Table.ContainsKey(r.Tool) && !Rerunnable(r.Tool))
            {
                checks.Add(new(r.Id, r.Tool, false, $"{SkippedPrefix}{r.Tool} is not read-only; make the call again to check it"));
                continue;
            }
            var result = await Invoke(r.Tool, r.Arguments != null ? JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(r.Arguments) : null, context, ct);
            if (result == null)
            {
                checks.Add(new(r.Id, r.Tool, false, $"{r.Tool} is not a tool of this server"));
                continue;
            }
            var (text, record) = Whole(result, store);
            if (result.IsError == true)
            {
                checks.Add(new(r.Id, r.Tool, false, $"the call failed now: {Format.Clip(text, 200)}"));
                continue;
            }
            var hash = ContentSha256(text, record);
            checks.Add(hash == r.ContentSha256
                ? new(r.Id, r.Tool, true, "same content")
                : new(r.Id, r.Tool, false, $"the content differs: SHA-256 {r.ContentSha256[..12]}… then, {hash[..12]}… now"));
        }
        return checks;
    }

    /// <summary>Calls one of this server's read-only tools from inside a call, through the same argument checks; null when there is no such tool.</summary>
    internal static async Task<CallToolResult?> Invoke(string toolName, Dictionary<string, JsonElement>? arguments, RequestContext<CallToolRequestParams> context, CancellationToken ct)
    {
        if (context.Server.ServerOptions.ToolCollection?.FirstOrDefault(t => t.ProtocolTool.Name == toolName) is not { } tool) return null;
        if (!Rerunnable(toolName))
            throw new ToolError(ErrorCode.AccessDenied, $"{toolName} is not read-only: a recorded call to it is not made again from inside another call.", $"call {toolName} directly");
        var request = new CallToolRequestParams { Name = toolName, Arguments = arguments };
        return await CallFilter.Run(request, tool.ProtocolTool.InputSchema, context.Services,
            token => tool.InvokeAsync(new RequestContext<CallToolRequestParams>(context.Server, context.JsonRpcRequest, request)
                { Services = context.Services, MatchedPrimitive = tool }, token), ct, context.Server.ClientInfo?.Name);
    }

    /// <summary>A call's whole text and record: a result past the response budget was kept, and the kept copy holds all of it.</summary>
    internal static (string Text, string? Record) Whole(CallToolResult result, ResultStore? store)
    {
        var text = string.Concat(result.Content.OfType<TextContentBlock>().Select(b => b.Text));
        return KeptMarker().Match(text) is { Success: true } m && store?.Read(m.Groups[1].Value) is { } kept
            ? (kept.Text, kept.Record)
            : (text, result.StructuredContent?.GetRawText());
    }

    [GeneratedRegex(@"is kept as (r-[0-9a-f]+); read_result")]
    private static partial Regex KeptMarker();
}
