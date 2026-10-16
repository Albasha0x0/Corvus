using System.Text;
using Corvus.Core.WebAssembly;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Services;

namespace Corvus.Tools;

public sealed partial class NativeCodeTools
{
    /// <summary>
    /// inspect_instruction on a WebAssembly image: each instruction from the address with its bytes, text (as in the WAT),
    /// operand stack effect, flow and references; an address inside an instruction names the one covering it.
    /// </summary>
    private static (string Text, InstructionReport Report) InspectWasm(string imageId, NativeCodeIndex index, WasmImage w, uint rva, int count, EngineChoice choice)
    {
        var m = w.Module;
        string Va(uint r) => NativeAddress.Va(w, r);
        var sb = new StringBuilder();
        var items = new List<InstructionItem>();
        var texts = new List<string>();
        var notes = new List<string>();
        if (w.FunctionAt(rva) is not { } function || m.BodyOf(function) is not { } body)
        {
            var section = w.SectionAt(rva)?.Name;
            sb.AppendLine($"{Va(rva)}  not_in_function" + (section != null ? $"  section {section}" : ""));
            items.Add(new InstructionItem("not_in_function", Va(rva), $"0x{rva:X}", null, null, null, section, null, null, "WebAssembly code is in function bodies only"));
            return (sb.ToString(), new InstructionReport(imageId, choice.Engine, choice.Note, items, notes) { Total = 1, Texts = [sb.ToString()] });
        }
        string name = w.FunctionNames[(int)function];
        var code = new WasmCode(m.Bytes, body.CodeStart, body.End);
        int done = 0;
        while (done < count && code.Next(out var ins))
        {
            uint at = (uint)ins.Offset, end = at + (uint)ins.Length;
            if (end <= rva) continue;
            string where = $"{name}+0x{at - body.Start:X}";
            int mark = sb.Length;
            if (at < rva)
            {
                sb.AppendLine($"{Va(rva)}  mid_instruction  in {name}+0x{rva - body.Start:X}\n  covered by the instruction at {Va(at)}; use address={Va(at)}");
                items.Add(new InstructionItem("mid_instruction", Va(rva), $"0x{rva:X}", $"{name}+0x{rva - body.Start:X}", null, Va(at), "code", null, null, null));
                texts.Add(sb.ToString(mark, sb.Length - mark));
                mark = sb.Length;
                if (count == 1) break;
                notes.Add($"{Va(rva)} is inside the instruction at {Va(at)}; the walk starts there");
            }
            string bytes = Convert.ToHexString(m.Bytes, ins.Offset, Math.Min(ins.Length, 32));
            string text = WatWriter.Instruction(m, function, ins);
            var info = ins.Info;
            var from = index.RefsFrom(at, end).Select(x => new InstructionReference(Va(at), Va(x.To), x.Kind.ToString(), index.NameAt(x.To)))
                .Concat(index.VirtualEdgesFrom(at, end).Take(8).Select(x => new InstructionReference(Va(at), Va(x.To), x.Kind.ToString(), index.NameAt(x.To)))).ToList();
            var flow = Flow(ins, end < body.End ? Va(end) : null, from.FirstOrDefault(r => r.Kind is "Call" or "TailCall" or "ImportCall" or "ImportJump"));
            string stack = info.Signature == "*" ? "by its immediates" : $"[{Letters(info.Signature[..info.Signature.IndexOf(':')])}] -> [{Letters(info.Signature[(info.Signature.IndexOf(':') + 1)..])}]";
            sb.AppendLine($"{Va(at)}  decoded  in {where}  section code");
            sb.AppendLine($"  {bytes,-24} {text}");
            sb.AppendLine($"  operand stack: {stack}; flow {flow.Kind}" + (flow.TargetName != null ? $" to {flow.TargetName}" : ""));
            if (from.Count > 0) sb.AppendLine("  references from: " + string.Join("; ", from.Select(r => $"{r.Kind} {r.To}{(r.Name != null ? " " + r.Name : "")}")));
            var entry = new InstructionEntry(bytes, ins.Length, text, $"operand stack {stack}", info.Name, null, null, null, false, [], null, null, null, null, null, null, null,
                flow, from, 0, [], null, null, index.Sourced.NameAt(at)?.Name, index.Sourced.CommentAt(at)?.Text);
            items.Add(new InstructionItem("decoded", Va(at), $"0x{at:X}", where, null, null, "code", null, entry, null));
            texts.Add(sb.ToString(mark, sb.Length - mark));
            done++;
        }
        if (notes.Count > 0) sb.Append("Notes:\n").AppendJoin("", notes.Select(x => $"  {x}\n"));
        return (sb.ToString(), new InstructionReport(imageId, choice.Engine, choice.Note, items, notes) { Total = items.Count, Texts = texts });
    }

    private static string Letters(string s) => string.Join(", ", s.Select(c => c switch
    {
        'i' => "i32", 'l' => "i64", 'f' => "f32", 'd' => "f64", 'v' => "v128", 'a' => "address", _ => c.ToString(),
    }));

    private static InstructionFlow Flow(in WasmInstr ins, string? next, InstructionReference? call) => ins.Op switch
    {
        0x10 => new InstructionFlow("call", null, call?.To, call?.Name, next),
        0x11 => new InstructionFlow("indirect_call", null, null, null, next),
        0x12 or 0x13 => new InstructionFlow("jump", null, call?.To, call?.Name, null),
        0x0C => new InstructionFlow("jump", null, null, $"label {ins.A}", null),
        0x0D or 0x04 or 0xD4 or 0xD6 => new InstructionFlow("conditional_jump", null, null, ins.Op == 0x04 ? null : $"label {ins.A}", next),
        0x0E => new InstructionFlow("indirect_jump", null, null, "br_table", null),
        0x0F => new InstructionFlow("return", null, null, null, null),
        0x00 or 0x08 or 0x09 or 0x0A => new InstructionFlow("trap", null, null, null, null),
        _ => new InstructionFlow("next", null, null, null, next),
    };
}
