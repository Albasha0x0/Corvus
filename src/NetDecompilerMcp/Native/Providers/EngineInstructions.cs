using System.Text.Json;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Native.Providers;

/// <summary>
/// One address as an engine sees it (see <see cref="INativeDecompilerSession.InspectAsync"/>). <see cref="Head"/> is the start of the
/// item covering the address; <see cref="References"/> are the engine's references from the instruction (target RVA and kind).
/// </summary>
public sealed record EngineInstructionItem(uint Rva, AddressStatus Status, uint? Head, uint? End, uint? Function, DataItem? Item,
    InspectedInstruction? Instruction, IReadOnlyList<(uint To, string Kind)> References, string? Note);

/// <summary>Parses the worker's "insn" reply into <see cref="EngineInstructionItem"/>; fields the engine leaves out stay null.</summary>
internal static class EngineInstructions
{
    public static List<EngineInstructionItem> Parse(JsonElement r)
    {
        var items = new List<EngineInstructionItem>();
        foreach (var e in r.GetProperty("items").EnumerateArray())
        {
            uint rva = e.GetProperty("rva").GetUInt32();
            var status = Str(e, "status") switch
            {
                "decoded" => AddressStatus.Decoded,
                "mid_instruction" => AddressStatus.MidInstruction,
                "data" => AddressStatus.Data,
                "not_in_function" => AddressStatus.NotInFunction,
                "unmapped" => AddressStatus.Unmapped,
                _ => AddressStatus.Invalid,
            };
            uint? head = U32(e, "head"), end = U32(e, "end");
            DataItem? item = status == AddressStatus.Data && head is { } h && end is { } x ? new DataItem(Str(e, "kind") ?? "data", h, x, Str(e, "text") ?? "") : null;
            InspectedInstruction? insn = null;
            var references = new List<(uint, string)>();
            if (e.TryGetProperty("insn", out var i) && i.ValueKind == JsonValueKind.Object)
            {
                insn = Instruction(rva, i);
                foreach (var row in i.GetProperty("references").EnumerateArray()) references.Add((row[0].GetUInt32(), row[1].GetString() ?? ""));
            }
            items.Add(new EngineInstructionItem(rva, status, head, end, U32(e, "function"), item, insn, references, Str(e, "note")));
        }
        return items;
    }

    private static InspectedInstruction Instruction(uint rva, JsonElement i)
    {
        var operands = new List<InspectedOperand>();
        foreach (var o in i.GetProperty("operands").EnumerateArray())
        {
            int size = o.TryGetProperty("size", out var s) && s.ValueKind == JsonValueKind.Number ? s.GetInt32() : 0;
            operands.Add(new InspectedOperand(o.GetProperty("index").GetInt32(), Str(o, "kind") ?? "other", Str(o, "text") ?? "")
            {
                Size = size > 0 ? size : null,
                Access = Str(o, "access"),
                Register = Str(o, "register"),
                Base = Str(o, "base"),
                IndexRegister = Str(o, "index_register"),
                Scale = o.TryGetProperty("scale", out var sc) && sc.ValueKind == JsonValueKind.Number ? sc.GetInt32() : null,
                Displacement = o.TryGetProperty("displacement", out var d) && d.ValueKind == JsonValueKind.Number ? d.GetInt64() : null,
                Value = o.TryGetProperty("value", out var v) && v.ValueKind == JsonValueKind.Number ? v.GetUInt64() : null,
                Target = U32(o, "target"),
            });
        }
        return new InspectedInstruction(rva, i.GetProperty("size").GetInt32(), (Str(i, "bytes") ?? "").ToUpperInvariant(), Str(i, "text") ?? "", null,
            Str(i, "mnemonic") ?? "", operands)
        {
            Flow = Str(i, "flow") ?? "next",
            BranchTarget = U32(i, "target"),
            Fallthrough = U32(i, "fallthrough"),
        };
    }

    private static string? Str(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static uint? U32(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetUInt32(out var u) ? u : null;
}
