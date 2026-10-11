using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Calls;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

public sealed record InstructionReport(string Image, string Engine, string? EngineNote, IReadOnlyList<InstructionItem> Items, IReadOnlyList<string> Notes);

public sealed record InstructionItem(
    [property: Description("decoded, mid_instruction, data, not_in_function, unmapped, outside_image or invalid.")] string Status,
    string Address,
    string Rva,
    [property: Description("Containing function as name+0xN.")] string? Function,
    string? Block,
    [property: Description("mid_instruction: start of the instruction that covers the address.")] string? ContainingInstruction,
    string? Section,
    InstructionDataItem? DataItem,
    InstructionEntry? Instruction,
    string? Note);

public sealed record InstructionDataItem(
    [property: Description("string, iat_slot, jump_table, index_table, pointer, pe_directory, headers or section.")] string Kind,
    string Start,
    [property: Description("Exclusive.")] string End,
    string Text);

public sealed record InstructionEntry(
    string Bytes,
    int Length,
    string Text,
    string? Comment,
    string Mnemonic,
    string? Encoding,
    IReadOnlyList<string>? Prefixes,
    IReadOnlyList<string>? Cpuid,
    bool Privileged,
    IReadOnlyList<OperandEntry> Operands,
    IReadOnlyList<string>? RegistersRead,
    IReadOnlyList<string>? RegistersWritten,
    IReadOnlyList<MemoryUse>? MemoryAccesses,
    IReadOnlyList<string>? FlagsRead,
    IReadOnlyList<string>? FlagsWritten,
    IReadOnlyList<string>? FlagsUndefined,
    int? StackPointerDelta,
    InstructionFlow Flow,
    IReadOnlyList<InstructionReference> ReferencesFrom,
    int ReferencesToCount,
    [property: Description("The first 8.")] IReadOnlyList<InstructionReference> ReferencesTo,
    [property: Description("A call with its recovered arguments: CreateFileW(L\"a.ini\", GENERIC_READ, ...).")] string? Call,
    InstructionSwitch? Switch,
    string? Name,
    string? UserComment);

public sealed record OperandEntry(
    int Index,
    [property: Description("register, immediate, memory, near_branch or far_branch.")] string Kind,
    string Text,
    [property: Description("Bytes accessed.")] int? Size,
    [property: Description("read, write, read_write, cond_read, cond_write, read_cond_write or none.")] string? Access,
    string? Register,
    string? FullRegister,
    string? Value,
    long? SignedValue,
    string? Segment,
    string? Base,
    string? IndexRegister,
    int? Scale,
    [property: Description("Signed hex; RIP-relative: from the next instruction.")] string? Displacement,
    bool RipRelative,
    [property: Description("Branch target or effective address (absolute or RIP-relative) inside the image, as a VA.")] string? Target,
    string? TargetName,
    [property: Description("The data item or function at the target, with its read / write reference counts for data.")] string? TargetItem);

public sealed record InstructionFlow(
    [property: Description("next, call, indirect_call, jump, indirect_jump, conditional_jump, return, trap or invalid.")] string Kind,
    string? Condition,
    string? Target,
    string? TargetName,
    [property: Description("The next instruction when control can continue there.")] string? Fallthrough);

public sealed record InstructionReference(string From, string To, string Kind, string? Name);

public sealed record InstructionSwitch(string Table, int Entries, IReadOnlyList<string> Targets);

public sealed partial class NativeCodeTools
{
    private const int MaxInspectCount = 64;

    [McpServerTool(Name = "inspect_instruction", Title = "Inspect native instructions", UseStructuredContent = true, OutputSchemaType = typeof(InstructionReport))]
    [Description("What is at an address of a native image (x86 / x64), instruction by instruction: decoded (an instruction start in a known function), " +
                 "mid_instruction (with the instruction covering it), data (string, IAT slot, switch table, relocated pointer, PE directory; with its " +
                 "start and end), not_in_function, unmapped (bss, zero-filled at load), outside_image or invalid. For an instruction: bytes, prefixes, " +
                 "encoding, CPUID features; each operand's kind, size and access, registers with their full register, memory operands as base, index, " +
                 "scale and displacement with the effective address named; registers and flags read and written, memory accesses, stack pointer change; " +
                 "flow with branch target and fallthrough; references from and to; a call's recovered arguments; a switch's table. count > 1 walks " +
                 "forward from the address (from the covering instruction when it is mid-instruction), skipping data items. With IDA (the only engine " +
                 "for ARM64 and ARM): IDA's items, operands with base, index, scale and displacement, access, flow and references; fields IDA does not " +
                 "supply are null. " + IndexNote)]
    public Task<string> InspectInstruction(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description("Instructions to inspect from the address (1-64, default 1).")] int count = 1,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        [Description("Engine: auto (default: the built-in decoder for x86 / x64, IDA for other instruction sets when it is installed), ours or ida.")]
        string? engine = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var mode = Mode(engine);
        var (native, index) = await Open(image, context, progress, cancellationToken);
        var rva = Address(index, address);
        int n = Math.Clamp(count, 1, MaxInspectCount);
        bool undecoded = index.Support == CodeSupport.DeclaredFunctionsOnly;
        var origin = mode.Named ? $"engine={EngineModes.Name(mode.Mode)}" : $"server default {EngineModes.Name(mode.Mode)}";
        var choice = mode.Mode switch
        {
            EngineMode.Ida => NativeEngineCode.Choose(EngineMode.Ida, mode.Named, engines, native, index),
            _ when !undecoded => new EngineChoice(false, $"{origin}: the built-in decoder"),
            EngineMode.Auto when engines?.IsAvailable == true => new EngineChoice(true, $"{origin}: the built-in analysis does not decode {index.Image.Arch} instructions"),
            _ => throw NativeEngineCode.Unsupported(index, engines),
        };
        var (text, report) = choice.Ida
            ? await InspectWithEngine(native, index, rva, n, choice, progress, cancellationToken)
            : await Task.Run(() => Inspect(native.Id, index, rva, n, choice, cancellationToken), cancellationToken);
        return StructuredOutput.With(choice.Line + "\n" + Coverage(index) + pager.Page(text, offset, maxChars), report);
    });

    internal static (string Text, InstructionReport Report) Inspect(string imageId, NativeCodeIndex index, uint rva, int count, EngineChoice choice, CancellationToken ct)
    {
        var image = index.Image;
        var classifier = new AddressClassifier(index);
        var disassembler = index.CreateDisassembler();
        var calls = CallAnalysis.For(index);
        var items = new List<InstructionItem>();
        var notes = new List<string>();
        var sb = new StringBuilder();
        string Va(uint r) => NativeAddress.Va(image, r);
        uint at = rva;
        for (int n = 0; n < count; n++)
        {
            ct.ThrowIfCancellationRequested();
            var c = classifier.Classify(at, ct);
            if (n == 0 && c.Status == AddressStatus.MidInstruction && count > 1)
            {
                notes.Add($"{Va(at)} is inside the instruction at {Va(c.InstructionStart!.Value)}; the walk starts there");
                AppendItem(sb, items, index, classifier, disassembler, calls, c, ct);
                at = c.InstructionStart!.Value;
                c = classifier.Classify(at, ct);
            }
            AppendItem(sb, items, index, classifier, disassembler, calls, c, ct);
            uint? next = c.Status switch
            {
                AddressStatus.Decoded or AddressStatus.NotInFunction when c.InstructionLength > 0 => at + (uint)c.InstructionLength,
                AddressStatus.MidInstruction => c.InstructionStart!.Value + (uint)c.InstructionLength,
                AddressStatus.Data when c.Item is { Kind: not ("section" or "headers" or "pe_directory") } item => item.End,
                _ => null,
            };
            if (next == null || next <= at)
            {
                if (n + 1 < count) notes.Add($"the walk stops at {Va(at)} ({c.StatusName})");
                break;
            }
            at = next.Value;
        }
        if (notes.Count > 0) sb.Append("Notes:\n").AppendJoin("", notes.Select(x => $"  {x}\n"));
        return (sb.ToString(), new InstructionReport(imageId, choice.Engine, choice.Note, items, notes));
    }

    /// <summary>inspect_instruction through the engine session: its items, operands, flow and references; what it does not supply stays null.</summary>
    private async Task<(string Text, InstructionReport Report)> InspectWithEngine(LoadedNative native, NativeCodeIndex index, uint rva, int count, EngineChoice choice,
        IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var session = await engines!.Session(native, null, new Progress<NativeProviderProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = (float)p.Elapsed.TotalSeconds, Message = $"IDA {p.Stage}" })), ct);
        if (names != null) await names.EnsureAsync(native, session, ct);
        var found = await session.InspectAsync(rva, count, ct);
        return EngineReport(native.Id, index, found, choice, ct);
    }

    internal static (string Text, InstructionReport Report) EngineReport(string imageId, NativeCodeIndex index, IReadOnlyList<EngineInstructionItem> found, EngineChoice choice,
        CancellationToken ct)
    {
        var image = index.Image;
        string Va(uint r) => NativeAddress.Va(image, r);
        var classifier = index.Support == CodeSupport.Full ? new AddressClassifier(index) : null;
        var sb = new StringBuilder();
        var items = new List<InstructionItem>();
        var notes = new List<string> { "IDA does not report prefixes, encoding, CPUID features, register and flag use, memory accesses or the stack pointer change: those fields are null" };
        foreach (var e in found)
        {
            ct.ThrowIfCancellationRequested();
            string? function = e.Function is { } f ? (index.NameAt(f) ?? $"sub_{f:X}") + (e.Rva != f ? $"+0x{e.Rva - f:X}" : "") : null;
            var status = AddressClass.Name(e.Status);
            var section = image.SectionAt(e.Rva)?.Name;
            sb.Append($"{Va(e.Rva)}  {status}").Append(function != null ? $"  in {function}" : "").Append(section != null ? $"  section {section}" : "").AppendLine();
            if (e.Note != null) sb.AppendLine($"  {e.Note}");
            InstructionDataItem? data = null;
            if (e.Item is { } item)
            {
                data = new InstructionDataItem(item.Kind, Va(item.Start), Va(item.End), item.Text);
                sb.AppendLine($"  {item.Kind} {Va(item.Start)}-{Va(item.End)} ({item.End - item.Start} bytes): {item.Text}");
            }
            string? containing = e.Status == AddressStatus.MidInstruction && e.Head is { } h ? Va(h) : null;
            if (containing != null) sb.AppendLine($"  covered by the instruction at {containing}; use address={containing}");
            InstructionEntry? entry = null;
            if (e.Instruction is { } insn)
            {
                sb.AppendLine($"  {insn.Bytes,-24} {insn.Text}");
                var operands = Operands(sb, index, classifier, insn, ct);
                var flow = Flow(sb, index, insn);
                var from = e.References.Select(r => new InstructionReference(Va(e.Rva), Va(r.To), r.Kind, index.NameAt(r.To))).ToList();
                if (from.Count > 0) sb.AppendLine("  references from: " + string.Join("; ", from.Select(r => $"{r.Kind} {r.To}{(r.Name != null ? " " + r.Name : "")}")));
                entry = new InstructionEntry(insn.Bytes, insn.Length, insn.Text, null, insn.Mnemonic, null, null, null, false, operands, null, null, null, null, null, null,
                    null, flow, from, 0, [], null, null, index.Sourced.NameAt(e.Rva)?.Name, index.Sourced.CommentAt(e.Rva)?.Text);
            }
            items.Add(new InstructionItem(status, Va(e.Rva), $"0x{e.Rva:X}", function, null, containing, section, data, entry, e.Note));
        }
        sb.Append("Notes:\n").AppendJoin("", notes.Select(x => $"  {x}\n"));
        return (sb.ToString(), new InstructionReport(imageId, choice.Engine, choice.Note, items, notes));
    }

    private static void AppendItem(StringBuilder sb, List<InstructionItem> items, NativeCodeIndex index, AddressClassifier classifier, NativeDisassembler disassembler,
        CallAnalysis calls, AddressClass c, CancellationToken ct)
    {
        var image = index.Image;
        string Va(uint r) => NativeAddress.Va(image, r);
        string? function = c.Function is { } f ? (c.Rva == f.Start ? f.Name : $"{f.Name}+0x{c.Rva - f.Start:X}") : null;
        sb.Append($"{Va(c.Rva)}  {c.StatusName}");
        if (function != null) sb.Append($"  in {function}");
        if (c.Block is { } block) sb.Append($"  block {Va(block)}");
        if (c.Section != null) sb.Append($"  section {c.Section.Name}");
        sb.AppendLine();
        if (c.Note != null) sb.AppendLine($"  {c.Note}");
        InstructionDataItem? data = null;
        if (c.Item is { } item)
        {
            data = new InstructionDataItem(item.Kind, Va(item.Start), Va(item.End), item.Text);
            sb.AppendLine($"  {item.Kind} {Va(item.Start)}-{Va(item.End)} ({item.End - item.Start} bytes): {item.Text}");
        }
        string? containing = null;
        InstructionEntry? entry = null;
        if (c.Status == AddressStatus.MidInstruction)
        {
            containing = Va(c.InstructionStart!.Value);
            if (disassembler.DecodeOne(c.InstructionStart.Value) is { } covering)
                sb.AppendLine($"  covered by {containing}  {covering.Bytes}  {covering.Text}; use address={containing}");
        }
        else if (c.Status is AddressStatus.Decoded or AddressStatus.NotInFunction or AddressStatus.Invalid
                 && InstructionInspector.Inspect(index, c.Rva, disassembler) is { } insn)
            entry = Describe(sb, index, classifier, calls, c, insn, ct);
        items.Add(new InstructionItem(c.StatusName, Va(c.Rva), $"0x{c.Rva:X}", function, c.Block is { } b ? Va(b) : null, containing, c.Section?.Name, data, entry, c.Note));
    }

    private static InstructionEntry Describe(StringBuilder sb, NativeCodeIndex index, AddressClassifier classifier, CallAnalysis calls, AddressClass c,
        InspectedInstruction insn, CancellationToken ct)
    {
        var image = index.Image;
        string Va(uint r) => NativeAddress.Va(image, r);
        static string List(IReadOnlyList<string>? list) => list is { Count: > 0 } ? string.Join(", ", list) : "-";
        sb.AppendLine($"  {insn.Bytes,-24} {insn.Text}{(insn.Comment != null ? "  ; " + insn.Comment : "")}");
        if (insn.Flow == "invalid")
            return new InstructionEntry(insn.Bytes, insn.Length, insn.Text, null, insn.Mnemonic, null, null, null, false, [], null, null, null, null, null, null, null,
                new InstructionFlow("invalid", null, null, null, null), [], 0, [], null, null, null, null);
        sb.AppendLine($"  {insn.Mnemonic}, {insn.Encoding} encoding" + (insn.Prefixes is { Count: > 0 } p ? $", prefixes {string.Join(" ", p)}" : "") +
                      $", cpuid {List(insn.Cpuid)}" + (insn.Privileged ? ", privileged" : ""));
        var operands = Operands(sb, index, classifier, insn, ct);
        if (insn.RegistersRead is { Count: > 0 } || insn.RegistersWritten is { Count: > 0 })
            sb.AppendLine($"  registers read {List(insn.RegistersRead)}; written {List(insn.RegistersWritten)}");
        if (insn.MemoryAccesses is { Count: > 0 } memory)
            sb.AppendLine("  memory " + string.Join("; ", memory.Select(m => $"{m.Access} {m.Size} bytes at [{MemoryText(m)}]")));
        if (insn.FlagsRead is { Count: > 0 } || insn.FlagsWritten is { Count: > 0 } || insn.FlagsUndefined is { Count: > 0 })
            sb.AppendLine($"  flags read {List(insn.FlagsRead)}; written {List(insn.FlagsWritten)}; undefined {List(insn.FlagsUndefined)}");
        if (insn.StackPointerDelta is { } delta and not 0) sb.AppendLine($"  stack pointer {(delta > 0 ? "+" : "")}{delta}");
        var flow = Flow(sb, index, insn);

        string? Name(uint r) => index.NameAt(r) ?? (index.StringAt(r) != null ? index.CommentFor(r) : null);
        var from = index.RefsFrom(c.Rva, c.Rva + (uint)insn.Length).Select(x => new InstructionReference(Va(x.From), Va(x.To), x.Kind.ToString(), Name(x.To))).ToList();
        if (from.Count > 0) sb.AppendLine("  references from: " + string.Join("; ", from.Select(r => $"{r.Kind} {r.To}{(r.Name != null ? " " + r.Name : "")}")));
        int toCount = index.CountRefsTo(c.Rva);
        string Where(uint r) => index.FunctionAt(r) is { } fn ? $"{fn.Name}+0x{r - fn.Start:X}" : Va(r);
        var to = index.RefsTo(c.Rva, 8).Select(x => new InstructionReference(Va(x.From), Va(x.To), x.Kind.ToString(), Where(x.From))).ToList();
        if (toCount > 0) sb.AppendLine($"  references to: {toCount} (" + string.Join("; ", to.Select(r => $"{r.Kind} from {r.Name}")) + (toCount > to.Count ? "; ..." : "") + ")");

        string? call = null;
        if (c.Function != null && insn.Flow is "call" or "indirect_call" or "jump" or "indirect_jump" && calls.CallAt(c.Rva, ct) is { } site)
        {
            call = site.Display;
            sb.AppendLine($"  call {call} [{site.Kind.ToString().ToLowerInvariant()}{(site.Guessed ? ", arguments guessed" : "")}]");
        }
        InstructionSwitch? sw = null;
        if (c.Function != null && insn.Flow == "indirect_jump" && classifier.Graph(c.Function, ct).Switches.FirstOrDefault(s => s.JumpRva == c.Rva) is { } table)
        {
            sw = new InstructionSwitch(Va(table.TableRva), table.EntryCount, table.Targets.Take(256).Select(Va).ToList());
            sb.AppendLine($"  switch table {sw.Table}, {table.EntryCount} entries, {Plural(table.Targets.Count, "distinct target")}: " +
                          string.Join(", ", table.Targets.Take(16).Select(Va)) + (table.Targets.Count > 16 ? ", ..." : ""));
        }
        var named = index.Sourced.NameAt(c.Rva);
        var comment = index.Sourced.CommentAt(c.Rva);
        if (named is { } nm) sb.AppendLine($"  name {nm.Name} ({nm.Source.Id()})");
        if (comment is { } cm) sb.AppendLine($"  comment ({cm.Source.Id()}): {cm.Text}");
        return new InstructionEntry(insn.Bytes, insn.Length, insn.Text, insn.Comment, insn.Mnemonic, insn.Encoding, insn.Prefixes, insn.Cpuid, insn.Privileged, operands,
            insn.RegistersRead, insn.RegistersWritten, insn.MemoryAccesses, insn.FlagsRead, insn.FlagsWritten, insn.FlagsUndefined, insn.StackPointerDelta, flow,
            from, toCount, to, call, sw, named?.Name, comment?.Text);
    }

    private static List<OperandEntry> Operands(StringBuilder sb, NativeCodeIndex index, AddressClassifier? classifier, InspectedInstruction insn, CancellationToken ct)
    {
        string Va(uint r) => NativeAddress.Va(index.Image, r);
        var operands = new List<OperandEntry>();
        foreach (var o in insn.Operands)
        {
            string? targetName = null, targetItem = null;
            if (o.Target is { } t)
            {
                targetName = index.NameAt(t);
                targetItem = TargetItem(index, classifier, t, o.Kind == "memory", ct);
            }
            var line = new StringBuilder($"  op{o.Index} {o.Kind} {o.Text}");
            var facts = new List<string>();
            if (o.Size is { } size and > 0) facts.Add($"{size} bytes");
            if (o.Access is { } access) facts.Add(access);
            if (o.FullRegister is { } full && full != o.Register) facts.Add($"part of {full}");
            if (o.Kind == "immediate" && o.Value is { } v) facts.Add($"0x{v:X}" + (o.SignedValue < 0 ? $" ({o.SignedValue})" : ""));
            if (o.Base != null || o.IndexRegister != null || o.RipRelative || o.Displacement is not null and not 0)
            {
                if (o.RipRelative) facts.Add("rip-relative");
                if (o.Base != null) facts.Add($"base {o.Base}");
                if (o.IndexRegister != null) facts.Add($"index {o.IndexRegister}, scale {o.Scale}");
                if (o.Displacement is { } d and not 0) facts.Add($"displacement {Signed(d)}");
            }
            line.Append($" ({string.Join(", ", facts)})");
            if (o.Target is { } target)
                line.Append($" -> {Va(target)}" + (targetName != null ? $" {targetName}" : "") + (targetItem != null ? $" [{targetItem}]" : ""));
            sb.AppendLine(line.ToString());
            operands.Add(new OperandEntry(o.Index, o.Kind, o.Text, o.Size, o.Access, o.Register, o.FullRegister, o.Value is { } value ? $"0x{value:X}" : null,
                o.SignedValue, o.Segment, o.Base, o.IndexRegister, o.Scale, o.Displacement is { } disp ? Signed(disp) : null, o.RipRelative,
                o.Target is { } tt ? Va(tt) : null, targetName, targetItem));
        }
        return operands;
    }

    private static InstructionFlow Flow(StringBuilder sb, NativeCodeIndex index, InspectedInstruction insn)
    {
        string Va(uint r) => NativeAddress.Va(index.Image, r);
        string? branchName = insn.BranchTarget is { } bt ? index.NameAt(bt) : null;
        var flow = new InstructionFlow(insn.Flow, insn.Condition?.ToLowerInvariant(), insn.BranchTarget is { } b ? Va(b) : null, branchName,
            insn.Fallthrough is { } ft ? Va(ft) : null);
        sb.AppendLine($"  flow {flow.Kind}" + (flow.Condition != null ? $" if {flow.Condition}" : "") +
                      (flow.Target != null ? $", target {flow.Target}{(branchName != null ? " " + branchName : "")}" : "") +
                      (flow.Fallthrough != null ? $", fallthrough {flow.Fallthrough}" : ", no fallthrough"));
        return flow;
    }

    /// <summary>The data item or function at an operand target; for data, its read and write reference counts.</summary>
    private static string? TargetItem(NativeCodeIndex index, AddressClassifier? classifier, uint target, bool memory, CancellationToken ct)
    {
        var parts = new List<string>();
        if (index.FunctionAt(target) is { } f) parts.Add(target == f.Start ? "function" : $"inside {f.Name}+0x{target - f.Start:X}");
        else if (classifier?.DataItemAt(target, null, ct) is { } item)
            parts.Add(item.Start == target ? $"{item.Kind}: {item.Text}" : $"{item.Kind} at +0x{target - item.Start:X}: {item.Text}");
        else if (index.Image.SectionAt(target) is { } s) parts.Add($"{s.Name} data");
        if (memory)
        {
            var kinds = index.RefsTo(target).GroupBy(x => x.Kind).Where(g => g.Key is XrefKind.Read or XrefKind.Write or XrefKind.Address)
                .Select(g => $"{g.Count()} {g.Key.ToString().ToLowerInvariant()}").ToList();
            if (kinds.Count > 0) parts.Add(string.Join(", ", kinds));
        }
        return parts.Count > 0 ? string.Join("; ", parts) : null;
    }

    private static string MemoryText(MemoryUse m)
    {
        var parts = new List<string>();
        if (m.Base != null) parts.Add(m.Base);
        if (m.Index != null) parts.Add(m.Scale > 1 ? $"{m.Index}*{m.Scale}" : m.Index);
        if (m.Displacement != 0 || parts.Count == 0) parts.Add(Signed(m.Displacement));
        var text = string.Join("+", parts).Replace("+-", "-");
        return m.Segment is { } seg and not ("ds" or "ss") ? $"{seg}:{text}" : text;
    }

    private static string Signed(long value) => value < 0 ? $"-0x{(ulong)(-value):X}" : $"0x{value:X}";
}
