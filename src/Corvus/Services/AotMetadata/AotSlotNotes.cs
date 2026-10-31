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

    /// <summary>
    /// Notes keyed by call RVA for the helper(slot, object) calls of
    /// <paramref name="fn"/>. Empty on non-x64 images and on images without
    /// metadata; a call whose slot is not a constant has no entry.
    /// </summary>
    public static Dictionary<uint, string> Comments(LoadedNative native, NativeCodeIndex index, NativeFunction fn, CancellationToken ct = default)
    {
        var notes = new Dictionary<uint, string>();
        if (index.Image.Arch != NativeArch.X64 || AotNativeNames.Of(native) is not { } applied) return notes;
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
        if (!instructions.Any(i => IsHelperCall(i))) return notes;
        // A jump table or computed jump has targets this scan cannot see.
        for (int k = 0; k < instructions.Count - 1; k++)
            if (instructions[k].FlowControl == FlowControl.IndirectBranch) return notes;

        var state = new Dictionary<Register, Value>();
        if (Owner(applied.Image.MethodsAt(fn.Start)) is { } method) Entry(method, args, windows, state);
        var targets = instructions
            .Where(i => i.FlowControl is FlowControl.ConditionalBranch or FlowControl.UnconditionalBranch
                && i.Op0Kind == OpKind.NearBranch64)
            .Select(i => i.NearBranchTarget).ToHashSet();
        var info = new InstructionInfoFactory();
        bool blockStart = false;
        foreach (var ins in instructions)
        {
            ct.ThrowIfCancellationRequested();
            // Code after a jump, return or trap is only reached by a branch.
            if (blockStart || targets.Contains(ins.IP)) state.Clear();
            blockStart = ins.FlowControl is FlowControl.UnconditionalBranch or FlowControl.IndirectBranch
                or FlowControl.Return or FlowControl.Exception;
            if (ins.FlowControl == FlowControl.Call)
            {
                if (IsHelperCall(ins) && Helper((uint)(ins.NearBranchTarget - imageBase)) is { } h
                    && state.GetValueOrDefault(h.Slot) is Constant slot
                    && Describe(applied.Image, slot.Number, state.GetValueOrDefault(h.Object) as Receiver) is { } note)
                    notes[(uint)(ins.IP - imageBase)] = note;
                foreach (var r in clobbered) state.Remove(r);
                continue;
            }
            var loaded = Load(ins, state);
            foreach (var u in info.GetInfo(ins).GetUsedRegisters())
                if (u.Access is OpAccess.Write or OpAccess.ReadWrite or OpAccess.CondWrite or OpAccess.ReadCondWrite)
                    state.Remove(u.Register.GetFullRegister());
            if (loaded != null) state[ins.Op0Register.GetFullRegister()] = loaded;
        }
        return notes;
    }

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
    private static Value? Load(in Instruction ins, Dictionary<Register, Value> state)
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
                return copied is Receiver && !dest.IsGPR64() ? null : copied;
            case OpKind.Memory when dest.IsGPR64() && ins.SegmentPrefix == Register.None
                && ins.MemoryIndex == Register.None && ins.MemoryBase.IsGPR64() && ins.MemoryBase != Register.RIP
                && state.GetValueOrDefault(ins.MemoryBase) is Receiver r:
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
    private static string? Describe(AotNavigator.Image image, long slot, Receiver? receiver)
    {
        if (slot < 0 || slot > int.MaxValue) return null;
        if (receiver != null)
            return AotNavigator.SlotMethod(receiver.Type, (int)slot) is { } m
                ? $"{m.DeclaringType.Name}::{m.Name} (slot {slot})"
                : $"{receiver.Type.Name} slot {slot}: method unknown";
        int count = CountSlots(image).GetValueOrDefault((int)slot);
        return count == 0
            ? $"virtual call, slot {slot}, receiver unknown, no metadata method in slot {slot}"
            : $"virtual call, slot {slot}, receiver unknown, {count} candidates";
    }
}
