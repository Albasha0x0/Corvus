using System.Text.RegularExpressions;
using ModelContextProtocol;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Providers;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>find_xrefs on a struct member: the engine's types, so through IDA or Ghidra.</summary>
public sealed partial class NativeCodeTools
{
    /// <summary>A struct member as Type::member, Type.member or Type+offset, or null for anything else.</summary>
    internal static (string Type, string? Member, int? Offset)? FieldTarget(string text)
    {
        var t = (text ?? "").Trim();
        if (FieldByName().Match(t) is { Success: true } n) return (n.Groups["type"].Value, n.Groups["member"].Value, null);
        if (FieldByOffset().Match(t) is { Success: true } o && NativeAddress.Number(o.Groups["offset"].Value) is { } off && off <= int.MaxValue)
            return (o.Groups["type"].Value, null, (int)off);
        return null;
    }

    [GeneratedRegex(@"^(?<type>[A-Za-z_][\w:<>]*?)(?:::|\.)(?<member>[A-Za-z_]\w*)$")]
    private static partial Regex FieldByName();

    [GeneratedRegex(@"^(?<type>[A-Za-z_][\w:<>]*?)\s*\+\s*(?<offset>(?:0x)?[0-9A-Fa-f]+h?)$")]
    private static partial Regex FieldByOffset();

    /// <summary>The next step after a struct-member miss: the type's members when the type exists, else a search for its engine name.</summary>
    internal static string FieldMissRemediation(string type, bool typeExists)
    {
        var shortName = type.Contains("::", StringComparison.Ordinal) ? type[(type.LastIndexOf("::", StringComparison.Ordinal) + 2)..] : type;
        return typeExists
            ? $"list_native_types name={type} lists its members with offsets; pass Type::member or Type+offset"
            : $"list_native_types filter={shortName} kind=struct finds the type's name in the engine (C++ names may use __ for ::), then list_native_types name=<it> lists its members";
    }

    /// <summary>Why an engine scan stopped early, in words.</summary>
    internal static string PartialReason(string reason) => reason switch
    {
        "cancelled" => "cancelled",
        "deadline" => "the request time limit was reached",
        _ => "the time budget ran out",
    };

    private static bool IsAddress(NativeCodeIndex index, string text)
    {
        try { Address(index, text); return true; }
        catch (ToolError) { return false; }
    }

    /// <summary>scope for a struct member: false typed (functions whose prototype names the type), true all functions.</summary>
    internal static bool FieldScope(string? scope) => scope?.Trim().ToLowerInvariant() switch
    {
        null or "" or "typed" => false,
        "all" => true,
        _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown scope '{scope}'.", "use typed or all"),
    };

    /// <summary>A scope=all scan of one member: the accesses found so far and where the next call continues (null: done).</summary>
    private sealed record FieldScan(List<NativeFieldAccess> Accesses, uint? Next, int Scanned, int Failed);

    private readonly Dictionary<string, FieldScan> _fieldScans = [];

    private async Task<string> FieldXrefs(LoadedNative native, (string Type, string? Member, int? Offset) field, EngineMode mode, int offset, int limit,
        IProgress<ProgressNotificationValue> progress, CancellationToken ct, bool all = false)
    {
        if (engines == null || mode == EngineMode.Ours)
            throw new ToolError(ErrorCode.Unsupported, $"Struct members are known from the engine's types; engine=ours has none.",
                "use engine=auto or engine=ida for Type::member");
        // auto: IDA, else Ghidra when only it is installed; an explicit engine is taken as asked
        var engine = EngineModes.ProviderId(mode) ?? (engines.UnavailabilityOf(Native.Providers.Ida.IdaProvider.ProviderId) == null
            ? Native.Providers.Ida.IdaProvider.ProviderId : engines.FirstAvailable() ?? Native.Providers.Ida.IdaProvider.ProviderId);
        if (engines.UnavailabilityOf(engine) is { } u)
            throw new ToolError(ErrorCode.ProviderUnavailable, $"Struct member references need {NativeEngineService.DisplayName(engine)}, which is not available: {u.Reason}", u.Remediation);
        var session = await engines.Session(native, engine, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = $"{NativeEngineService.DisplayName(engine)} {p.Stage}" })), ct);
        // the recovered and the user's types must be in the database for their members to be found
        if (names != null) await names.EnsureAsync(native, session, ct);
        if (types != null) await types.EnsureAsync(native, session, ct);
        if (userTypes != null) await userTypes.EnsureAsync(native, session, ct);
        // C++ names were pushed as identifiers (A::B as A__B)
        IReadOnlyList<string> candidates = field.Type.Contains("::", StringComparison.Ordinal) ? [field.Type, field.Type.Replace("::", "__", StringComparison.Ordinal)] : [field.Type];
        // scope=all continues where the previous call on the same member stopped, in this session's database
        var scanKey = $"{native.Id}|{session.ProviderId}|{EngineControl.Generation(session)}|{field.Type}|{field.Member}|{field.Offset}";
        FieldScan? before = null;
        if (all) lock (_fieldScans) _fieldScans.TryGetValue(scanKey, out before);
        NativeFieldXrefs r;
        try { r = await session.GetFieldXrefsAsync(candidates, field.Member, field.Offset, [], 60, all ? before?.Next ?? 0 : null, ct); }
        catch (ToolError e) when (e.Code == ErrorCode.NotFound)
        {
            // the engine's generic next step (list the functions) does not apply to a type or member miss
            throw new ToolError(ErrorCode.NotFound, e.Message, FieldMissRemediation(field.Type, e.Message.Contains("has no member", StringComparison.Ordinal)));
        }
        if (all)
        {
            // a finished scan restarts: the database may have changed since
            var kept = before is { Next: not null } ? before : null;
            var merged = (kept?.Accesses ?? []).Concat(r.Accesses).DistinctBy(a => (a.Rva, a.Kind)).OrderBy(a => a.Rva).ThenBy(a => a.Kind, StringComparer.Ordinal).ToList();
            var progressed = new FieldScan(merged, r.Partial != null ? r.Next : null, (kept?.Scanned ?? 0) + r.Scanned, (kept?.Failed ?? 0) + r.Failed);
            lock (_fieldScans) _fieldScans[scanKey] = progressed;
            r = r with { Accesses = merged, Scanned = progressed.Scanned, Failed = progressed.Failed };
        }
        var index = await code.Index(native, null, ct);
        string Where(NativeFieldAccess a) => a.FunctionRva is { } f
            ? $"{index.Sourced.NameAt(f)?.Name ?? index.FunctionByStart(f)?.KnownName ?? $"sub_{f:X}"}+0x{a.Rva - f:X}"
            : "(no function)";
        var rows = r.Accesses.Select(a => $"{NativeAddress.Va(native.Image, a.Rva)}  {a.Kind}  {Where(a)}").ToList();
        var target = $"{r.Type}::{r.Member}";
        var scan = !r.DecompilerAvailable ? "the decompiler is not available, so only typed operands are listed"
            : all ? $"pseudocode of all functions scanned: {r.Scanned} so far" + (r.Skipped > 0 ? $", {r.Skipped} left" : "") + (r.Failed > 0 ? $", {r.Failed} failed to decompile" : "") +
                    (r.Partial != null ? $"; PARTIAL ({PartialReason(r.Partial)}): call again with scope=all to continue from {(r.Next is { } a ? NativeAddress.Va(native.Image, a) : "the next function")}" : "; complete")
            : $"pseudocode of {r.Scanned} of {r.Candidates} function(s) naming {r.Type} scanned" +
              (r.Skipped > 0 ? $", {r.Skipped} not reached in time" : "") + (r.Failed > 0 ? $", {r.Failed} failed to decompile" : "") +
              (r.Partial != null ? $"; PARTIAL ({PartialReason(r.Partial)}): call again to scan the rest, the first not scanned is {(r.Next is { } n ? NativeAddress.Va(native.Image, n) : "unknown")}" : "");
        var choice = new EngineChoice(session.ProviderId, $"struct members come from the engine's types; {scan}");
        var header = $"References to member {target} (+0x{r.Offset:X}, {r.MemberType}, {r.Size} bytes):\n{choice.Line}\n";
        return ToolOutput.With(header + pager.PageRows(rows, offset, limit, "reference"), Xrefs(native.Id, target, rows, offset, limit, null, choice));
    }
}
