using System.ComponentModel;
using System.Globalization;
using System.Text;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Tools;

/// <summary>get_cfg's structured result.</summary>
public sealed record CfgReport(
    string Image,
    [property: Description("Function name.")] string Function,
    [property: Description("Function start (VA).")] string Address,
    [property: Description("ours, ida or ghidra.")] string Engine,
    IReadOnlyList<CfgBlock> Blocks,
    IReadOnlyList<CfgSwitch> Switches,
    IReadOnlyList<CfgUnresolvedJump> UnresolvedJumps,
    [property: Description("Targets of tail calls (VA).")] IReadOnlyList<string> TailCalls,
    [property: Description("The function was cut at the instruction limit.")] bool Truncated);

public sealed record CfgBlock(
    [property: Description("VA.")] string Start,
    [property: Description("Exclusive end (VA).")] string End,
    int Instructions,
    [property: Description("How the block ends: Return, Jump, ConditionalJump, Switch, IndirectJump, TailCall, NoReturnCall, FallThrough, ...")] string EndKind,
    IReadOnlyList<CfgSuccessor> Successors);

public sealed record CfgSuccessor([property: Description("VA.")] string To, [property: Description("FallThrough, Jump, ConditionalTaken, ConditionalFallThrough, Switch or TailCall.")] string Kind);

public sealed record CfgSwitch(
    [property: Description("The indirect jump (VA).")] string Jump,
    [property: Description("Jump table (VA); null when the engine does not say.")] string? Table,
    [property: Description("absolute, rva or table_relative entries.")] string? TableKind,
    int? EntrySize,
    int? Entries,
    [property: Description("Byte index table in front of the jump table (VA).")] string? IndexTable,
    int? IndexEntries,
    [property: Description("Switched value = table index + bias.")] long Bias,
    [property: Description("Target of out-of-range values (VA); null when the index is masked rather than compared.")] string? Default,
    [property: Description("Values whose table entry is the default target, as ranges (\"5..9\").")] IReadOnlyList<string> DefaultValues,
    [property: Description("False when the values are table indexes not bounded by a compare (masked index or assumed base).")] bool ValuesExact,
    IReadOnlyList<CfgCase> Cases);

public sealed record CfgCase([property: Description("VA.")] string Target, string? TargetName, [property: Description("Switched values as ranges (\"5..9\").")] IReadOnlyList<string> Values);

public sealed record CfgUnresolvedJump([property: Description("VA.")] string Address, string Reason);

/// <summary>A switch as both engines report it, for one rendering.</summary>
internal sealed record SwitchView(uint Jump, uint? Table, string? TableKind, int? EntrySize, int? Entries, uint? IndexTable, int? IndexEntries, long Bias,
    uint? Default, IReadOnlyList<long> DefaultValues, bool ValuesExact, IReadOnlyList<(uint Target, IReadOnlyList<long> Values)> Cases)
{
    public static SwitchView Of(SwitchTable t) => new(t.JumpRva, t.TableRva, t.Kind switch
        {
            SwitchTableKind.Absolute => "absolute",
            SwitchTableKind.TableRelative => "table_relative",
            _ => "rva",
        }, t.EntrySize, t.EntryCount, t.IndexTableRva, t.IndexTableRva != null ? t.IndexEntryCount : null, t.Bias, t.Default, t.DefaultValues, t.ValuesExact,
        [.. t.Cases.Select(c => (c.Target, c.Values))]);
}

public sealed partial class NativeCodeTools
{
    /// <summary>Case lines shown per switch; the structured result has them all.</summary>
    private const int MaxCaseLines = 256;

    /// <summary>"3, 4, 10..12": sorted values with runs of three or more joined.</summary>
    internal static List<string> ValueRanges(IEnumerable<long> values)
    {
        var sorted = values.Distinct().Order().ToList();
        var result = new List<string>();
        for (int i = 0; i < sorted.Count;)
        {
            int j = i;
            while (j + 1 < sorted.Count && sorted[j + 1] == sorted[j] + 1) j++;
            string V(long v) => v.ToString(CultureInfo.InvariantCulture);
            if (j - i >= 2) result.Add($"{V(sorted[i])}..{V(sorted[j])}");
            else for (int k = i; k <= j; k++) result.Add(V(sorted[k]));
            i = j + 1;
        }
        return result;
    }

    /// <summary>The switch lines of get_cfg (shared by both engines).</summary>
    internal static void RenderSwitch(StringBuilder sb, SwitchView s, Func<uint, string> va, Func<uint, string?> name, string? instruction)
    {
        var head = new StringBuilder($"  switch at {va(s.Jump)}{(instruction != null ? $" ({instruction})" : "")}:");
        if (s.Table is { } table)
            head.Append($" {s.TableKind ?? ""} table {va(table)}".Replace("  ", " ") + (s.EntrySize != null || s.Entries != null
                ? $" ({(s.EntrySize is { } size ? $"{size}-byte entries, " : "")}{s.Entries})" : ""));
        if (s.IndexTable is { } index) head.Append($", byte index {va(index)} ({s.IndexEntries})");
        if (s.Bias != 0) head.Append($"; value = index {(s.Bias > 0 ? "+" : "-")} {Math.Abs(s.Bias)}");
        head.Append(s.Default is { } d ? $"; default {va(d)}" : s.ValuesExact ? "" : "; no default (the index is masked, values are table indexes)");
        sb.AppendLine(head.ToString());
        foreach (var (target, values) in s.Cases.Take(MaxCaseLines))
            sb.AppendLine($"    case {string.Join(", ", ValueRanges(values))}: {va(target)}{(name(target) is { } n ? $" ({n})" : "")}");
        if (s.Cases.Count > MaxCaseLines) sb.AppendLine($"    ... {s.Cases.Count - MaxCaseLines} more targets (the structured result lists them all)");
        if (s.Default is { } dt)
            sb.AppendLine($"    default{(s.DefaultValues.Count > 0 ? $" (also {string.Join(", ", ValueRanges(s.DefaultValues))})" : "")}: {va(dt)}");
    }

    internal static CfgSwitch SwitchEntry(SwitchView s, Func<uint, string> va, Func<uint, string?> name) =>
        new(va(s.Jump), s.Table is { } t ? va(t) : null, s.TableKind, s.EntrySize, s.Entries, s.IndexTable is { } i ? va(i) : null, s.IndexEntries, s.Bias,
            s.Default is { } d ? va(d) : null, ValueRanges(s.DefaultValues), s.ValuesExact,
            [.. s.Cases.Select(c => new CfgCase(va(c.Target), name(c.Target), ValueRanges(c.Values)))]);

    /// <summary>get_cfg on the built-in index: text and the structured report.</summary>
    private static (string Text, CfgReport Report) OurCfg(LoadedNative native, NativeCodeIndex index, NativeFunction fn, FunctionGraph graph)
    {
        string Va(uint rva) => NativeAddress.Va(index.Image, rva);
        string? Label(uint rva) => index.NameAt(rva);
        var sb = new StringBuilder($"{fn.Name} at {Va(fn.Start)}: {ToolSupport.Plural(graph.Blocks.Count, "block")}{(graph.Truncated ? " (truncated)" : "")}\n");
        foreach (var b in graph.Blocks)
            sb.AppendLine($"  {Va(b.Start)}-{Va(b.End)}  {b.InstructionCount,4} insn  {b.EndKind}" +
                          (b.Successors.Count > 0 ? "  -> " + string.Join(", ", b.Successors.Select(e => $"{Va(e.To)}{(e.Kind is EdgeKind.FallThrough or EdgeKind.Jump ? "" : " " + e.Kind)}")) : ""));
        var dis = graph.Switches.Count > 0 ? index.CreateDisassembler() : null;
        var switches = new List<CfgSwitch>();
        foreach (var sw in graph.Switches)
        {
            var view = SwitchView.Of(sw);
            RenderSwitch(sb, view, Va, Label, dis?.DecodeOne(sw.JumpRva) is { } line ? string.Join(' ', line.Text.Split(' ', StringSplitOptions.RemoveEmptyEntries)) : null);
            switches.Add(SwitchEntry(view, Va, Label));
        }
        foreach (var j in graph.UnresolvedJumps) sb.AppendLine($"  unresolved indirect jump at {Va(j.Rva)}: {j.Reason}");
        foreach (var t in graph.TailCalls) sb.AppendLine($"  tail call to {index.NameAt(t) ?? Va(t)}");
        var report = new CfgReport(native.Id, fn.Name, Va(fn.Start), "ours",
            [.. graph.Blocks.Select(b => new CfgBlock(Va(b.Start), Va(b.End), b.InstructionCount, b.EndKind.ToString(),
                [.. b.Successors.Select(e => new CfgSuccessor(Va(e.To), e.Kind.ToString()))]))],
            switches, [.. graph.UnresolvedJumps.Select(j => new CfgUnresolvedJump(Va(j.Rva), j.Reason))], [.. graph.TailCalls.Select(Va)], graph.Truncated);
        return (sb.ToString(), report);
    }
}
