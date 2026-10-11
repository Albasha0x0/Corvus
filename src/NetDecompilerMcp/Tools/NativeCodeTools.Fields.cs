using System.Text.RegularExpressions;
using ModelContextProtocol;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tools;

/// <summary>find_xrefs on a struct member: the engine's types, so always through IDA.</summary>
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

    private async Task<string> FieldXrefs(LoadedNative native, (string Type, string? Member, int? Offset) field, EngineMode mode, int offset, int limit,
        IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        if (engines == null || mode == EngineMode.Ours)
            throw new ToolError(ErrorCode.Unsupported, $"Struct members are known from the engine's types; engine=ours has none.",
                "use engine=auto or engine=ida for Type::member");
        // IDA answers member references; an explicit engine is taken as asked
        var engine = EngineModes.ProviderId(mode) ?? Native.Providers.Ida.IdaProvider.ProviderId;
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
        NativeFieldXrefs r;
        try { r = await session.GetFieldXrefsAsync(candidates, field.Member, field.Offset, [], 60, ct); }
        catch (ToolError e) when (e.Code == ErrorCode.NotFound)
        {
            // the engine's generic next step (list the functions) does not apply to a type or member miss
            throw new ToolError(ErrorCode.NotFound, e.Message, FieldMissRemediation(field.Type, e.Message.Contains("has no member", StringComparison.Ordinal)));
        }
        var index = await code.Index(native, null, ct);
        string Where(NativeFieldAccess a) => a.FunctionRva is { } f
            ? $"{index.Sourced.NameAt(f)?.Name ?? index.FunctionByStart(f)?.KnownName ?? $"sub_{f:X}"}+0x{a.Rva - f:X}"
            : "(no function)";
        var rows = r.Accesses.Select(a => $"{NativeAddress.Va(native.Image, a.Rva)}  {a.Kind}  {Where(a)}").ToList();
        var target = $"{r.Type}::{r.Member}";
        var scan = !r.DecompilerAvailable ? "the decompiler is not available, so only typed operands are listed"
            : $"pseudocode of {r.Scanned} of {r.Candidates} function(s) naming {r.Type} scanned" +
              (r.Skipped > 0 ? $", {r.Skipped} not reached in time" : "") + (r.Failed > 0 ? $", {r.Failed} failed to decompile" : "") +
              (r.Partial != null ? $"; PARTIAL ({PartialReason(r.Partial)}): call again to scan the rest, the first not scanned is {(r.Next is { } n ? NativeAddress.Va(native.Image, n) : "unknown")}" : "");
        var choice = new EngineChoice(session.ProviderId, $"struct members come from the engine's types; {scan}");
        var header = $"References to member {target} (+0x{r.Offset:X}, {r.MemberType}, {r.Size} bytes):\n{choice.Line}\n";
        return StructuredOutput.With(header + pager.PageRows(rows, offset, limit, "reference"), Xrefs(native.Id, target, rows, offset, limit, null, choice));
    }
}
