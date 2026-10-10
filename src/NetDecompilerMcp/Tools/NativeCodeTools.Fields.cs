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
        if (engines.Unavailability is { } u)
            throw new ToolError(ErrorCode.ProviderUnavailable, $"Struct member references need IDA, which is not available: {u.Reason}", u.Remediation);
        var session = await engines.Session(native, null, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = $"IDA {p.Stage}" })), ct);
        // the recovered and the user's types must be in the database for their members to be found
        if (names != null) await names.EnsureAsync(native, session, ct);
        if (types != null) await types.EnsureAsync(native, session, ct);
        if (userTypes != null) await userTypes.EnsureAsync(native, session, ct);
        // C++ names were pushed as identifiers (A::B as A__B)
        IReadOnlyList<string> candidates = field.Type.Contains("::", StringComparison.Ordinal) ? [field.Type, field.Type.Replace("::", "__", StringComparison.Ordinal)] : [field.Type];
        var r = await session.GetFieldXrefsAsync(candidates, field.Member, field.Offset, [], 60, ct);
        var index = await code.Index(native, null, ct);
        string Where(NativeFieldAccess a) => a.FunctionRva is { } f
            ? $"{index.Sourced.NameAt(f)?.Name ?? index.FunctionByStart(f)?.KnownName ?? $"sub_{f:X}"}+0x{a.Rva - f:X}"
            : "(no function)";
        var rows = r.Accesses.Select(a => $"{NativeAddress.Va(native.Image, a.Rva)}  {a.Kind}  {Where(a)}").ToList();
        var target = $"{r.Type}::{r.Member}";
        var scan = !r.DecompilerAvailable ? "the decompiler is not available, so only typed operands are listed"
            : $"pseudocode of {r.Scanned} of {r.Candidates} function(s) naming {r.Type} scanned" +
              (r.Skipped > 0 ? $", {r.Skipped} not reached in time" : "") + (r.Failed > 0 ? $", {r.Failed} failed to decompile" : "");
        var choice = new EngineChoice(true, $"struct members come from the engine's types; {scan}");
        var header = $"References to member {target} (+0x{r.Offset:X}, {r.MemberType}, {r.Size} bytes):\n{choice.Line}\n";
        return StructuredOutput.With(header + pager.PageRows(rows, offset, limit, "reference"), Xrefs(native.Id, target, rows, offset, limit, null, choice));
    }
}
