using System.Runtime.CompilerServices;
using dnlib.DotNet;
using Iced.Intel;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;

namespace Corvus.Services;

/// <summary>
/// Names the method behind each call to a slot-indexed virtual call helper.
/// </summary>
public static class AotSlotNotes
{
    private abstract record Value;

    private sealed record Constant(long Number) : Value;

    private sealed record Receiver(TypeDef Type) : Value;

    private sealed record ClassPointer(TypeDef Type) : Value;

    private sealed record SlotEntry(TypeDef Type, long Slot) : Value;

    /// <summary>A slot call: its address, the slot, the method found there and the receiver type (each null when unknown).</summary>
    public sealed record SlotCall(uint Rva, long Slot, MethodDef? Method, TypeDef? Receiver, string Note);

    private const int SlotSize = 16;

    // Metadata version assumed when the build has no model; the current layout.
    private const float CurrentMetadataVersion = 29f;

    // Offset of the first vtable entry in the class record on x64. The 0x138
    // start is tested at metadata 24.2 and later; 0x128 before it is
    // source-derived from the earlier class record layout, not tested.
    internal static int VtableStart(float metadataVersion) => metadataVersion >= 24.2f ? 0x138 : 0x128;

    /// <summary>
    /// Notes keyed by call RVA for the helper(slot, object) calls and the
    /// direct call [class + offset] vtable calls of
    /// <paramref name="fn"/>. Empty on non-x64 images and on images without
    /// metadata; a call whose slot is not a constant, whose base is not a known
    /// class pointer, or whose offset is outside the vtable has no entry.
    /// </summary>
    public static Dictionary<uint, string> Comments(LoadedNative native, NativeCodeIndex index, NativeFunction fn, CancellationToken ct = default) =>
        Calls(native, index, fn, ct).ToDictionary(c => c.Rva, c => c.Note);

    /// <summary>
    /// The calls <see cref="Comments"/> names, with slot and method, ordered by
    /// address. Empty on the same conditions.
    /// </summary>
    public static List<SlotCall> Calls(LoadedNative native, NativeCodeIndex index, NativeFunction fn, CancellationToken ct = default)
    {
        var calls = new Dictionary<uint, SlotCall>();
        if (index.Image.Arch != NativeArch.X64 || AotNativeNames.Of(native) is not { } applied) return [];
        bool windows = native.Image.Format == ImageFormat.Pe;
        Register[] args = windows
            ? [Register.RCX, Register.RDX, Register.R8, Register.R9]
            : [Register.RDI, Register.RSI, Register.RDX, Register.RCX, Register.R8, Register.R9];
        Register[] clobbered = windows
            ? [Register.RAX, Register.RCX, Register.RDX, Register.R8, Register.R9, Register.R10, Register.R11]
            : [Register.RAX, Register.RCX, Register.RDX, Register.RSI, Register.RDI,
               Register.R8, Register.R9, Register.R10, Register.R11];
        ulong imageBase = index.Image.ImageBase;
        var instructions = NativeAotCode.Decode(index.Image, index.Ranges(fn), ct);
        var helpers = new Dictionary<uint, (Register Object, Register Slot)?>();
        (Register Object, Register Slot)? Helper(uint start)
        {
            if (helpers.TryGetValue(start, out var known)) return known;
            (Register, Register)? shape = null;
            if (index.FunctionByStart(start) is { Size: > 0 and <= 0x40 } target)
            {
                var bytes = new byte[target.Size];
                if (index.Image.Read(start, bytes) >= bytes.Length)
                    shape = VirtualInvokerShape.Arguments(bytes, true, imageBase + start);
            }
            helpers[start] = shape;
            return shape;
        }
        bool IsHelperCall(in Instruction i) =>
            i.FlowControl == FlowControl.Call && i.Op0Kind == OpKind.NearBranch64
            && Helper((uint)(i.NearBranchTarget - imageBase)) != null;
        int vtableStart = VtableStart(applied.Image.Model?.MetadataVersion ?? CurrentMetadataVersion);
        // A direct call needs the class pointer, loaded from a receiver's first field.
        // A jump through a register, or through [class + offset], is a call in
        // tail position; a jump with an index or a segment is a jump table.
        bool IsVtableCall(in Instruction i) =>
            (i.FlowControl == FlowControl.IndirectCall && i.Op0Kind is OpKind.Memory or OpKind.Register)
            || (i.FlowControl == FlowControl.IndirectBranch && (i.Op0Kind == OpKind.Register || IsClassOffset(i)));
        // A register call needs a vtable entry loaded from memory in the function.
        bool LoadsEntry = instructions.Any(i => i.Mnemonic == Mnemonic.Mov && i.Op0Kind == OpKind.Register && i.Op1Kind == OpKind.Memory);
        if (!instructions.Any(i => IsHelperCall(i) || (IsVtableCall(i) && (i.Op0Kind == OpKind.Memory || LoadsEntry)))) return [];
        // A jump table or computed jump has targets this scan cannot see; a
        // register jump is checked against the slot entries when reached.
        for (int k = 0; k < instructions.Count - 1; k++)
            if (instructions[k].FlowControl == FlowControl.IndirectBranch && instructions[k].Op0Kind != OpKind.Register && !IsClassOffset(instructions[k])) return [];

        var state = new Dictionary<Register, Value>();
        if (Owner(applied.Image.MethodsAt(fn.Start)) is { } method) Entry(method, args, windows, state);
        var branches = instructions
            .Where(i => i.FlowControl is FlowControl.ConditionalBranch or FlowControl.UnconditionalBranch
                && i.Op0Kind == OpKind.NearBranch64).ToList();
        var targets = branches.Select(i => i.NearBranchTarget).ToHashSet();
        // A backward branch reaches its target with a state not yet seen.
        var backward = branches
            .Where(i => i.NearBranchTarget <= i.IP)
            .Select(i => i.NearBranchTarget)
            .ToHashSet();
        var pending = new Dictionary<ulong, Dictionary<Register, Value>>();
        var info = new InstructionInfoFactory();
        bool blockStart = false;
        foreach (var ins in instructions)
        {
            ct.ThrowIfCancellationRequested();
            // Join the fall-through state with the state of each branch to this
            // address; code only a branch reaches starts from those states.
            if (blockStart || targets.Contains(ins.IP))
            {
                bool seen = pending.Remove(ins.IP, out var arrived);
                if (backward.Contains(ins.IP)) state.Clear();
                else if (blockStart) state = arrived ?? [];
                else if (seen) Intersect(state, arrived!);
            }
            blockStart = ins.FlowControl is FlowControl.UnconditionalBranch or FlowControl.IndirectBranch
                or FlowControl.Return or FlowControl.Exception;
            if (ins.FlowControl is FlowControl.ConditionalBranch or FlowControl.UnconditionalBranch
                && ins.Op0Kind == OpKind.NearBranch64 && ins.NearBranchTarget > ins.IP)
            {
                if (pending.TryGetValue(ins.NearBranchTarget, out var recorded)) Intersect(recorded, state);
                else pending[ins.NearBranchTarget] = new Dictionary<Register, Value>(state);
            }
            if (ins.FlowControl == FlowControl.Call)
            {
                if (IsHelperCall(ins) && Helper((uint)(ins.NearBranchTarget - imageBase)) is { } h
                    && state.GetValueOrDefault(h.Slot) is Constant slot
                    && Describe(applied.Image, slot.Number, state.GetValueOrDefault(h.Object) as Receiver) is { } note)
                    calls[(uint)(ins.IP - imageBase)] = note with { Rva = (uint)(ins.IP - imageBase) };
                foreach (var r in clobbered) state.Remove(r);
                continue;
            }
            if (IsVtableCall(ins))
            {
                if (ins.FlowControl == FlowControl.IndirectBranch && VtableSlot(ins, vtableStart, state) == null) return [];
                if (VtableSlot(ins, vtableStart, state) is { } direct
                    && Describe(applied.Image, direct.Slot, new Receiver(direct.Type)) is { } directNote)
                    calls[(uint)(ins.IP - imageBase)] = directNote with { Rva = (uint)(ins.IP - imageBase) };
                foreach (var r in clobbered) state.Remove(r);
                continue;
            }
            var loaded = Load(ins, state, vtableStart);
            foreach (var u in info.GetInfo(ins).GetUsedRegisters())
                if (u.Access is OpAccess.Write or OpAccess.ReadWrite or OpAccess.CondWrite or OpAccess.ReadCondWrite)
                    state.Remove(u.Register.GetFullRegister());
            if (loaded != null) state[ins.Op0Register.GetFullRegister()] = loaded;
        }
        return [.. calls.Values.OrderBy(c => c.Rva)];
    }

    // Mutates into: removes registers whose value differs or is missing in other.
    private static void Intersect(Dictionary<Register, Value> into, Dictionary<Register, Value> other)
    {
        foreach (var r in into.Keys.ToList())
            if (!other.TryGetValue(r, out var v) || !v.Equals(into[r])) into.Remove(r);
    }

    // A memory operand of one base register and a displacement.
    private static bool IsClassOffset(in Instruction i) =>
        i.Op0Kind == OpKind.Memory && i.MemoryIndex == Register.None && i.SegmentPrefix == Register.None
        && i.MemoryBase.IsGPR64() && i.MemoryBase != Register.RIP;

    // The slot a call [class + offset] addresses, or a call through a register
    // loaded from one, when the base holds the class pointer of a known type;
    // null for others.
    private static (TypeDef Type, long Slot)? VtableSlot(
        in Instruction ins, int start, Dictionary<Register, Value> state)
    {
        if (ins.Op0Kind == OpKind.Register)
            return state.GetValueOrDefault(ins.Op0Register.GetFullRegister()) is SlotEntry e ? (e.Type, e.Slot) : null;
        if (ins.MemoryIndex != Register.None || ins.SegmentPrefix != Register.None
            || !ins.MemoryBase.IsGPR64() || ins.MemoryBase == Register.RIP
            || state.GetValueOrDefault(ins.MemoryBase) is not ClassPointer klass) return null;
        return SlotAt((long)ins.MemoryDisplacement64, start) is { } slot ? (klass.Type, slot) : null;
    }

    // The slot index of a class record offset; null outside the vtable.
    private static long? SlotAt(long offset, int start) =>
        offset >= start && (offset - start) % SlotSize == 0 ? (offset - start) / SlotSize : null;

    // Shared, generic and value-type methods have no single receiver type.
    private static MethodDef? Owner(IReadOnlyList<AotMetadataService.MethodAddress> methods)
    {
        if (methods.Count == 0) return null;
        var first = methods[0].Method;
        return methods.All(m => ReferenceEquals(m.Method, first)) && !first.HasGenericParameters
            && first.DeclaringType is { HasGenericParameters: false } ? first : null;
    }

    // Reference-typed parameters start as receivers; Windows counts every
    // parameter, System V only integer ones.
    private static void Entry(MethodDef method, Register[] args, bool windows, Dictionary<Register, Value> state)
    {
        // A struct return takes a hidden buffer pointer in the first register.
        if (IsStruct(method.MethodSig.RetType)) return;
        int next = 0;
        if (!method.IsStatic)
        {
            if (method.DeclaringType.IsValueType) next++;
            else state[args[next++]] = new Receiver(method.DeclaringType);
        }
        foreach (var p in method.MethodSig.Params)
        {
            bool floating = p.ElementType is ElementType.R4 or ElementType.R8;
            if (floating && !windows) continue;
            if (next >= args.Length) break;
            // System V splits a struct over registers or the stack.
            if (IsStruct(p) && !windows) break;
            if (p is ClassSig cs && cs.TypeDefOrRef?.ResolveTypeDef() is { HasGenericParameters: false } t)
                state[args[next]] = new Receiver(t);
            next++;
        }
    }

    private static bool IsStruct(TypeSig sig) =>
        sig.RemovePinnedAndModifiers() is { ElementType: ElementType.ValueType }
        or GenericInstSig { GenericType: ValueTypeSig };

    // The value a mov, xor or field load leaves in its destination; null for
    // others. A narrow destination keeps the old upper bits, so it is unknown.
    private static Value? Load(in Instruction ins, Dictionary<Register, Value> state, int vtableStart)
    {
        if (ins.OpCount == 0 || ins.Op0Kind != OpKind.Register) return null;
        var dest = ins.Op0Register;
        if (!dest.IsGPR32() && !dest.IsGPR64()) return null;
        if (ins.Mnemonic == Mnemonic.Xor && ins.Op1Kind == OpKind.Register
            && dest.GetFullRegister() == ins.Op1Register.GetFullRegister())
            return new Constant(0);
        if (ins.Mnemonic != Mnemonic.Mov) return null;
        switch (ins.Op1Kind)
        {
            case OpKind.Immediate8 or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate64
                or OpKind.Immediate8to32 or OpKind.Immediate8to64 or OpKind.Immediate32to64:
                return new Constant((long)ins.GetImmediate(1));
            case OpKind.Register when dest.IsGPR64() == ins.Op1Register.IsGPR64()
                && (ins.Op1Register.IsGPR64() || ins.Op1Register.IsGPR32()):
                var copied = state.GetValueOrDefault(ins.Op1Register.GetFullRegister());
                // A 32-bit copy truncates a pointer.
                return copied is Receiver or ClassPointer or SlotEntry && !dest.IsGPR64() ? null : copied;
            case OpKind.Memory when dest.IsGPR64() && ins.SegmentPrefix == Register.None
                && ins.MemoryIndex == Register.None && ins.MemoryBase.IsGPR64() && ins.MemoryBase != Register.RIP
                && state.GetValueOrDefault(ins.MemoryBase) is ClassPointer klass:
                return SlotAt((long)ins.MemoryDisplacement64, vtableStart) is { } entry ? new SlotEntry(klass.Type, entry) : null;
            case OpKind.Memory when dest.IsGPR64() && ins.SegmentPrefix == Register.None
                && ins.MemoryIndex == Register.None && ins.MemoryBase.IsGPR64() && ins.MemoryBase != Register.RIP
                && state.GetValueOrDefault(ins.MemoryBase) is Receiver r:
                // A receiver is always a reference type, so offset 0 is its class pointer.
                if (ins.MemoryDisplacement64 == 0) return new ClassPointer(r.Type);
                return FieldType(r.Type, (long)ins.MemoryDisplacement64) is { } t ? new Receiver(t) : null;
            default:
                return null;
        }
    }

    // The class a reference-typed field at the offset is declared as, searching
    // base types; null when not a known class.
    private static TypeDef? FieldType(TypeDef type, long offset)
    {
        int depth = 0;
        for (var t = type; t != null && depth++ < 64; t = MetadataUtil.Try(() => t.BaseType?.ResolveTypeDef()))
            foreach (var f in t.Fields)
                if (!f.IsStatic && AotLayout.OffsetOf(f) is { } at && (long)at == offset)
                    return f.FieldType is ClassSig cs && cs.TypeDefOrRef?.ResolveTypeDef() is { HasGenericParameters: false } found
                        ? found : null;
        return null;
    }

    // Distinct methods per vtable slot, built once per image.
    private static readonly ConditionalWeakTable<AotNavigator.Image, Dictionary<int, int>> SlotCounts = new();

    private static Dictionary<int, int> CountSlots(AotNavigator.Image image) =>
        SlotCounts.GetValue(image, img =>
        {
            var methods = new Dictionary<int, HashSet<MethodDef>>();
            foreach (var asm in img.Assemblies)
                foreach (var t in asm.Module.GetTypes())
                    foreach (var (slot, m) in AotNavigator.VTable(t))
                    {
                        if (!methods.TryGetValue(slot, out var set)) methods[slot] = set = [];
                        set.Add(m);
                    }
            return methods.ToDictionary(e => e.Key, e => e.Value.Count);
        });

    // Null for a value outside the vtable index range: it is not a slot index.
    private static SlotCall? Describe(AotNavigator.Image image, long slot, Receiver? receiver)
    {
        if (slot < 0 || slot > int.MaxValue) return null;
        if (receiver != null)
            return AotNavigator.SlotMethod(receiver.Type, (int)slot) is { } m
                ? new SlotCall(0, slot, m, receiver.Type, $"{m.DeclaringType.Name}::{m.Name} (slot {slot})")
                : new SlotCall(0, slot, null, receiver.Type, $"{receiver.Type.Name} slot {slot}: method unknown");
        int count = CountSlots(image).GetValueOrDefault((int)slot);
        return new SlotCall(0, slot, null, null, count == 0
            ? $"virtual call, slot {slot}, receiver unknown, no metadata method in slot {slot}"
            : $"virtual call, slot {slot}, receiver unknown, {count} candidates");
    }
}
