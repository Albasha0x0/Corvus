using Iced.Intel;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.NativeAot;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Disassembly comments from NativeAOT metadata (x64): string literal loads (an instruction addressing a frozen String
/// object) and virtual calls through a MethodTable's vtable, "mov r, [obj]; call [r + 24 + 8k]", or the slot loaded into a
/// register first and called directly or through the CFG dispatch helper (target in rax); tracked linearly within a block.
/// The receiver's type is known when obj is this of an instance method (rcx before it is overwritten, or a callee-saved
/// register copied from it once and never written again); slot k then names the method in the type's vtable, which a
/// derived type may override.
/// </summary>
public static class NativeAotCode
{
    /// <summary>Offset of vtable slot 0 in an x64 MethodTable (.NET 7–10).</summary>
    private const int VtableOffset = 24;
    private static readonly Register[] Volatile = [Register.RAX, Register.RCX, Register.RDX, Register.R8, Register.R9, Register.R10, Register.R11];

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<NativeAotImage, Lookup> Lookups = new();

    /// <summary>Frozen strings by object RVA; MethodTables with a vtable by name (the first by address when a name repeats).</summary>
    private sealed class Lookup(NativeAotImage aot)
    {
        public readonly Dictionary<uint, string> Strings = aot.Frozen.Objects.Where(o => o.Text != null).ToDictionary(o => o.Rva, o => o.Text!);
        public readonly Dictionary<string, NativeAotMethodTable> ByName = aot.Types.ByRva.Values.Where(t => t.Vtable.Count > 0).OrderBy(t => t.Rva)
            .GroupBy(t => t.Name, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
    }

    /// <summary>Comments by instruction RVA for <paramref name="fn"/>; empty for other images and architectures.</summary>
    public static Dictionary<uint, string> Comments(LoadedNative native, NativeCodeIndex index, NativeFunction fn, CancellationToken ct = default)
    {
        var comments = new Dictionary<uint, string>();
        var image = index.Image;
        if (image.Arch != NativeArch.X64 || NativeAotNames.View(native, ct) is not { } aot) return comments;
        var lookup = Lookups.GetValue(aot, a => new Lookup(a));
        var strings = lookup.Strings;
        var owner = aot.Names.MethodAt.TryGetValue(fn.Start, out var m) && m.Name.HasThis == true ? lookup.ByName.GetValueOrDefault(m.Name.Owner) : null;
        var obj = lookup.ByName.GetValueOrDefault("System.Object");

        var instructions = Decode(image, index.Ranges(fn), ct);
        ulong entry = image.ImageBase + fn.Start;
        var thisHolders = owner != null ? ThisHolders(instructions, entry) : [];
        var info = new InstructionInfoFactory();
        bool rcxIsThis = false;
        var tables = new Dictionary<Register, NativeAotMethodTable?>(); // register -> the MethodTable it holds (null: of an unknown type)
        var slots = new Dictionary<Register, (NativeAotMethodTable? Table, int Slot)>(); // register -> the vtable slot it was loaded from
        foreach (var ins in instructions)
        {
            ct.ThrowIfCancellationRequested();
            uint rva = (uint)(ins.IP - image.ImageBase);
            if (ins.IP == entry) rcxIsThis = owner != null;
            if (ins.IsIPRelativeMemoryOperand && ins.IPRelativeMemoryAddress - image.ImageBase is var target and < uint.MaxValue
                && strings.TryGetValue((uint)target, out var text))
                comments[rva] = Il2CppNativeNames.Quote(text);

            int? slot = ins.Op0Kind == OpKind.Memory || ins.Op1Kind == OpKind.Memory ? Slot(ins) : null;
            if (ins.Mnemonic == Mnemonic.Call)
            {
                // call [mt + slot]; call reg holding a slot; a CFG dispatch call (call [__guard_dispatch_icall_fptr]) on rax holding one
                if (ins.Op0Kind == OpKind.Memory && slot is { } k && tables.TryGetValue(ins.MemoryBase, out var mt)) comments[rva] = Virtual(index, mt, obj, k);
                else if (ins.Op0Kind == OpKind.Register && slots.TryGetValue(ins.Op0Register, out var held)) comments[rva] = Virtual(index, held.Table, obj, held.Slot);
                else if (ins.Op0Kind == OpKind.Memory && ins.IsIPRelativeMemoryOperand && slots.TryGetValue(Register.RAX, out held)) comments[rva] = Virtual(index, held.Table, obj, held.Slot);
            }

            // mov r64, [obj]: a MethodTable (the object header precedes the reference); mov r64, [mt + 24 + 8k]: vtable slot k.
            Register loaded = Register.None, slotted = Register.None;
            NativeAotMethodTable? slotTable = null;
            if (ins.Mnemonic == Mnemonic.Mov && ins.Op0Kind == OpKind.Register && ins.Op0Register.IsGPR64() && ins.Op1Kind == OpKind.Memory
                && ins.MemoryBase.IsGPR64() && ins.MemoryIndex == Register.None)
            {
                if (ins.MemoryDisplacement64 == 0) loaded = ins.Op0Register;
                else if (slot != null && tables.TryGetValue(ins.MemoryBase, out slotTable)) slotted = ins.Op0Register;
            }
            bool fromThis = loaded != Register.None && (ins.MemoryBase == Register.RCX && rcxIsThis || thisHolders.Contains(ins.MemoryBase));

            foreach (var used in info.GetInfo(ins).GetUsedRegisters())
                if (used.Access is OpAccess.Write or OpAccess.ReadWrite or OpAccess.CondWrite or OpAccess.ReadCondWrite)
                {
                    var full = used.Register.GetFullRegister();
                    tables.Remove(full);
                    slots.Remove(full);
                    if (full == Register.RCX) rcxIsThis = false;
                }
            if (loaded != Register.None) tables[loaded] = fromThis ? owner : null;
            if (slotted != Register.None) slots[slotted] = (slotTable, slot!.Value);
            if (ins.FlowControl is FlowControl.Call or FlowControl.IndirectCall)
            {
                foreach (var r in Volatile) { tables.Remove(r); slots.Remove(r); }
                rcxIsThis = false;
            }
            else if (ins.FlowControl != FlowControl.Next)
            {
                tables.Clear(); // another path may reach the next instruction
                slots.Clear();
                rcxIsThis = false;
            }
        }
        return comments;
    }

    /// <summary>The vtable slot a [base + 24 + 8k] memory operand addresses, or null.</summary>
    private static int? Slot(in Instruction ins) =>
        ins.MemoryIndex == Register.None && ins.MemoryBase.IsGPR64() && ins.MemoryBase != Register.RIP && (long)ins.MemoryDisplacement64 is var disp and >= VtableOffset
        && (disp - VtableOffset) % 8 == 0 && disp < VtableOffset + 8 * 4096 ? (int)((disp - VtableOffset) / 8) : null;

    private static string Virtual(NativeCodeIndex index, NativeAotMethodTable? mt, NativeAotMethodTable? obj, int slot)
    {
        string Target(uint code) => index.NameAt(code) ?? $"0x{index.Image.ImageBase + code:X}";
        if (mt != null && slot < mt.Vtable.Count && mt.Vtable[slot] != 0)
            return $"virtual {mt.Name} slot {slot}: {Target(mt.Vtable[slot])} (or an override)";
        if (obj != null && slot < obj.Vtable.Count && obj.Vtable[slot] != 0)
            return $"virtual call, vtable slot {slot}: {Target(obj.Vtable[slot])} or an override";
        return $"virtual call, vtable slot {slot}";
    }

    /// <summary>The function's instructions in address order.</summary>
    private static List<Instruction> Decode(INativeImage image, IEnumerable<(uint Start, uint End)> ranges, CancellationToken ct)
    {
        var result = new List<Instruction>();
        foreach (var (start, end) in ranges.OrderBy(r => r.Start))
        {
            ct.ThrowIfCancellationRequested();
            if (end <= start || end - start > 1 << 20) continue;
            var bytes = new byte[end - start];
            int n = image.Read(start, bytes);
            var decoder = Decoder.Create(64, new ByteArrayCodeReader(bytes, 0, n));
            decoder.IP = image.ImageBase + start;
            while (decoder.IP < image.ImageBase + start + (ulong)n)
            {
                decoder.Decode(out var ins);
                if (ins.IsInvalid) break;
                result.Add(ins);
            }
        }
        return result;
    }

    /// <summary>
    /// Callee-saved registers that hold this for the whole function: copied from rcx while rcx is still this (before any
    /// call, branch or write to rcx) and never written otherwise (pops in epilogues aside).
    /// </summary>
    private static HashSet<Register> ThisHolders(List<Instruction> instructions, ulong entry)
    {
        var holders = new HashSet<Register>();
        var info = new InstructionInfoFactory();
        var copies = new HashSet<Register>();
        var copyAt = new HashSet<ulong>();
        bool rcx = true;
        foreach (var ins in instructions.SkipWhile(i => i.IP != entry))
        {
            if (!rcx) break;
            if (ins.Mnemonic == Mnemonic.Mov && ins.Op0Kind == OpKind.Register && ins.Op1Kind == OpKind.Register && ins.Op1Register == Register.RCX
                && ins.Op0Register is Register.RBX or Register.RSI or Register.RDI or Register.RBP or Register.R12 or Register.R13 or Register.R14 or Register.R15)
            {
                copies.Add(ins.Op0Register);
                copyAt.Add(ins.IP);
                continue;
            }
            if (ins.FlowControl != FlowControl.Next || info.GetInfo(ins).GetUsedRegisters().Any(u => u.Register.GetFullRegister() == Register.RCX && u.Access is not OpAccess.Read))
                rcx = false;
        }
        var written = new HashSet<Register>();
        foreach (var ins in instructions)
        {
            if (copyAt.Contains(ins.IP) || ins.Mnemonic == Mnemonic.Pop) continue;
            foreach (var u in info.GetInfo(ins).GetUsedRegisters())
                if (u.Access is not (OpAccess.Read or OpAccess.CondRead or OpAccess.None or OpAccess.NoMemAccess))
                    written.Add(u.Register.GetFullRegister());
        }
        foreach (var r in copies) if (!written.Contains(r)) holders.Add(r);
        return holders;
    }
}
