using System.ComponentModel;
using System.Globalization;
using System.Text;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Code;

namespace Corvus.Tools;

/// <summary>get_cfg's structured result: the function's blocks paged in address order, with the switches and unresolved jumps of the page's blocks.</summary>
public sealed record CfgReport(
    string Image,
    [property: Description("Function name.")] string Function,
    [property: Description("Function start (VA).")] string Address,
    [property: Description("ours, ida or ghidra.")] string Engine,
    [property: Description("Blocks of this page.")] IReadOnlyList<CfgBlock> Items,
    int Offset, int Total,
    [property: Description("Switches ending a block of this page.")] IReadOnlyList<CfgSwitch> Switches,
    IReadOnlyList<CfgUnresolvedJump> UnresolvedJumps,
    [property: Description("Targets of tail calls (VA); first page.")] IReadOnlyList<string> TailCalls,
    [property: Description("The function was cut at the instruction limit.")] bool Cut,
    [property: Description("Whole function: edges, switches, unresolved jumps, cyclomatic complexity.")] CfgSummary Summary);

public sealed record CfgSummary(int Blocks, int Edges, int Switches, int UnresolvedJumps, int Cyclomatic);

public sealed record CfgBlock(
    [property: Description("VA.")] string Start,
    [property: Description("Exclusive end (VA).")] string End,
    int Instructions,
    [property: Description("Return, Jump, ConditionalJump, Switch, IndirectJump, TailCall, NoReturnCall, FallThrough...")] string EndKind,
    IReadOnlyList<CfgSuccessor> Successors);

public sealed record CfgSuccessor([property: Description("VA.")] string To, [property: Description("FallThrough, Jump, ConditionalTaken, ConditionalFallThrough, Switch or TailCall.")] string Kind);

public sealed record CfgSwitch(
    [property: Description("The indirect jump (VA).")] string Jump,
    [property: Description("Jump table (VA); null when the engine does not say.")] string? Table,
    [property: Description("absolute, rva, table_relative, base_relative (ARM: base + entry << shift), indexed (ARM32: base + index * 4).")] string? TableKind,
    int? EntrySize,
    int? Entries,
    [property: Description("Byte index table in front of the jump table (VA).")] string? IndexTable,
    int? IndexEntries,
    [property: Description("Switched value = table index + bias.")] long Bias,
    [property: Description("VA for out-of-range values; null when the index is masked, not compared.")] string? Default,
    [property: Description("Values whose table entry is the default target, as ranges (\"5..9\").")] IReadOnlyList<string> DefaultValues,
    [property: Description("False: table indexes not bounded by a compare (masked or assumed base).")] bool ValuesExact,
    IReadOnlyList<CfgCase> Cases);

public sealed record CfgCase([property: Description("VA.")] string Target, string? TargetName, [property: Description("Switched values as ranges (\"5..9\").")] IReadOnlyList<string> Values);

public sealed record CfgUnresolvedJump([property: Description("VA.")] string Address, string Reason);

/// <summary>A switch as both engines report it, for one rendering.</summary>
internal sealed record SwitchView(uint Jump, uint? Table, string? TableKind, int? EntrySize, int? Entries, uint? IndexTable, int? IndexEntries, long Bias,
    uint? Default, IReadOnlyList<long> DefaultValues, bool ValuesExact, IReadOnlyList<(uint Target, IReadOnlyList<long> Values)> Cases)
{
    /// <summary>Base-relative tables: target = Base + (entry &lt;&lt; Shift).</summary>
    public uint? Base { get; init; }
    public int Shift { get; init; }

    public static SwitchView Of(SwitchTable t) => new(t.JumpRva, t.TableRva, t.Kind switch
        {
            SwitchTableKind.Absolute => "absolute",
            SwitchTableKind.TableRelative => "table_relative",
            SwitchTableKind.BaseRelative => "base_relative",
            SwitchTableKind.Indexed => "indexed",
            _ => "rva",
        }, t.EntrySize, t.EntryCount, t.IndexTableRva, t.IndexTableRva != null ? t.IndexEntryCount : null, t.Bias, t.Default, t.DefaultValues, t.ValuesExact,
        [.. t.Cases.Select(c => (c.Target, c.Values))]) { Base = t.Base, Shift = t.Shift };
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

    /// <summary>A block of get_cfg: its row (with its switch and unresolved jump lines) and its record.</summary>
    internal sealed record CfgRow(CfgBlock Block, uint Start, uint End, string Line);

    /// <summary>get_cfg's page for both engines: block rows from offset, their switches and unresolved jumps, and a function summary.</summary>
    internal static string CfgPage(string image, string function, string address, EngineChoice choice, string title, List<CfgRow> rows,
        List<(uint Jump, CfgSwitch Switch)> switches, List<(uint At, CfgUnresolvedJump Jump)> unresolved, IReadOnlyList<string> tailCalls, bool cut,
        int offset, int limit)
    {
        int edges = rows.Sum(r => r.Block.Successors.Count);
        var summary = new CfgSummary(rows.Count, edges, switches.Count, unresolved.Count, Math.Max(1, edges - rows.Count + 2));
        var head = $"{choice.Line}\n{title}: {ToolSupport.Plural(rows.Count, "block")}, {ToolSupport.Plural(edges, "edge")}, " +
                   $"{ToolSupport.Plural(switches.Count, "switch")}, {ToolSupport.Plural(unresolved.Count, "unresolved indirect jump")}, cyclomatic {summary.Cyclomatic}" +
                   (cut ? " (cut at the instruction limit)" : "") + "\n" +
                   (offset == 0 && tailCalls.Count > 0 ? $"tail calls to {string.Join(", ", tailCalls.Take(20))}{(tailCalls.Count > 20 ? ", ..." : "")}\n" : "");
        offset = Math.Max(0, offset);
        var page = rows.Skip(offset).Take(Math.Max(1, limit)).ToList();
        return ToolOutput.List(page, offset, limit, rows.Count, r => r.Line, shown =>
            {
                bool In(uint at) => shown.Any(r => at >= r.Start && at < r.End);
                return new CfgReport(image, function, address, choice.Engine, shown.Select(r => r.Block).ToList(), offset, rows.Count,
                    switches.Where(s => In(s.Jump)).Select(s => s.Switch).ToList(), unresolved.Where(u => In(u.At)).Select(u => u.Jump).ToList(),
                    offset == 0 ? tailCalls : [], cut, summary);
            }, "block", head);
    }

    /// <summary>The switch lines of get_cfg (shared by both engines).</summary>
    internal static void RenderSwitch(StringBuilder sb, SwitchView s, Func<uint, string> va, Func<uint, string?> name, string? instruction)
    {
        var head = new StringBuilder($"  switch at {va(s.Jump)}{(instruction != null ? $" ({instruction})" : "")}:");
        if (s.Table is { } table)
            head.Append($" {s.TableKind ?? ""} table {va(table)}".Replace("  ", " ") + (s.EntrySize != null || s.Entries != null
                ? $" ({(s.EntrySize is { } size ? $"{size}-byte entries, " : "")}{s.Entries})" : ""));
        if (s.IndexTable is { } index) head.Append($", byte index {va(index)} ({s.IndexEntries})");
        if (s.Base is { } b) head.Append($"; target = {va(b)} + entry" + (s.Shift > 0 ? $" * {1 << s.Shift}" : ""));
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

    /// <summary>get_cfg on the built-in index: one page of blocks with their switches.</summary>
    private static string OurCfg(LoadedNative native, NativeCodeIndex index, NativeFunction fn, FunctionGraph graph, EngineChoice choice, int offset, int limit)
    {
        string Va(uint rva) => NativeAddress.Va(index.Image, rva);
        string? Label(uint rva) => index.NameAt(rva);
        var dis = graph.Switches.Count > 0 ? index.CreateDisassembler() : null;
        var switchText = new Dictionary<uint, string>();
        var switches = new List<(uint, CfgSwitch)>();
        foreach (var sw in graph.Switches)
        {
            var view = SwitchView.Of(sw);
            var sb = new StringBuilder();
            RenderSwitch(sb, view, Va, Label, dis?.DecodeOne(sw.JumpRva) is { } line ? string.Join(' ', line.Text.Split(' ', StringSplitOptions.RemoveEmptyEntries)) : null);
            switchText[sw.JumpRva] = sb.ToString();
            switches.Add((sw.JumpRva, SwitchEntry(view, Va, Label)));
        }
        var unresolved = graph.UnresolvedJumps.Select(j => (j.Rva, new CfgUnresolvedJump(Va(j.Rva), j.Reason))).ToList();
        var rows = graph.Blocks.Select(b =>
        {
            var line = new StringBuilder($"{Va(b.Start)}-{Va(b.End)}  {b.InstructionCount,4} insn  {b.EndKind}" +
                (b.Successors.Count > 0 && b.EndKind != BlockEnd.Switch ? "  -> " + string.Join(", ", b.Successors.Select(e => $"{Va(e.To)}{(e.Kind is EdgeKind.FallThrough or EdgeKind.Jump ? "" : " " + e.Kind)}"))
                : b.Successors.Count > 0 ? $"  -> {ToolSupport.Plural(b.Successors.Count, "target")}" : ""));
            if (switchText.TryGetValue(b.LastInstruction, out var sw)) line.Append('\n').Append(sw.TrimEnd('\n'));
            foreach (var u in graph.UnresolvedJumps.Where(u => u.Rva >= b.Start && u.Rva < b.End)) line.Append($"\n  unresolved indirect jump at {Va(u.Rva)}: {u.Reason}");
            return new CfgRow(new CfgBlock(Va(b.Start), Va(b.End), b.InstructionCount, b.EndKind.ToString(),
                [.. b.Successors.Select(e => new CfgSuccessor(Va(e.To), e.Kind.ToString()))]), b.Start, b.End, line.ToString());
        }).ToList();
        return CfgPage(native.Id, fn.Name, Va(fn.Start), choice, $"{fn.Name} at {Va(fn.Start)}", rows, switches, unresolved,
            [.. graph.TailCalls.Select(t => Label(t) ?? Va(t))], graph.Truncated, offset, limit);
    }
}
