using System.Runtime.CompilerServices;
using dnlib.DotNet;
using Iced.Intel;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Calls;
using AsmArm64;
using Corvus.Native.Code;

namespace Corvus.Services;

/// <summary>
/// Names the method behind each call to a slot-indexed virtual call helper.
/// </summary>
public static class AotSlotNotes
{
    private sealed record Receiver(TypeDef Type);

    /// <summary>
    /// A slot call: its address, the slot, the method found there and the
    /// receiver type (each null when unknown).
    /// </summary>
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
        if (index.Image.Arch is not (NativeArch.X64 or NativeArch.Arm64) || AotNativeNames.Of(native) is not { } applied) return [];
        if (index.Image.Arch == NativeArch.Arm64) return Arm64Calls(native, index, fn, applied, ct);
        bool windows = native.Image.Format == ImageFormat.Pe;
        ulong imageBase = index.Image.ImageBase;
        var instructions = FunctionInstructions.Decode(index.Image, index.Ranges(fn), ct);
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
        // A direct call needs the class pointer, loaded from a receiver's
        // first field. A jump through a register, or through [class + offset],
        // is a call in tail position; a jump with an index or a segment is a
        // jump table.
        bool IsVtableCall(in Instruction i) =>
            (i.FlowControl == FlowControl.IndirectCall && i.Op0Kind is OpKind.Memory or OpKind.Register)
            || (i.FlowControl == FlowControl.IndirectBranch && (i.Op0Kind == OpKind.Register || IsClassOffset(i)));
        // A register call needs a vtable entry loaded from memory in the function.
        bool LoadsEntry = instructions.Any(i =>
            i.Mnemonic == Mnemonic.Mov && i.Op0Kind == OpKind.Register && i.Op1Kind == OpKind.Memory);
        if (!instructions.Any(i => IsHelperCall(i) || (IsVtableCall(i) && (i.Op0Kind == OpKind.Memory || LoadsEntry)))) return [];
        // A jump table or computed jump has targets this scan cannot see; a
        // register jump is checked against the slot entries when reached.
        for (int k = 0; k < instructions.Count - 1; k++)
            if (instructions[k].FlowControl == FlowControl.IndirectBranch
                && instructions[k].Op0Kind != OpKind.Register && !IsClassOffset(instructions[k])) return [];

        var argTypes = Owner(applied.Image.MethodsAt(fn.Start)) is { } method ? ArgumentTypes(method, windows, ValueProvenance.ArgumentRegisters(windows).Length, true) : [];
        bool unreadable = false;
        if (index.FactsOf(fn, ct) is not { } facts) return [];
        var argumentRegisters = ValueProvenance.ArgumentRegisters(windows);
        Origin? Argument(CallFact call, Register register) =>
            Array.IndexOf(argumentRegisters, register) is >= 0 and var at ? call.Arguments[at] : null;
        foreach (var call in facts.Calls)
        {
            var ins = instructions[call.At];
            uint rva = (uint)(ins.IP - imageBase);
            if (call.Flow == FlowControl.Call)
            {
                if (call.Target != 0 && Helper((uint)(call.Target - imageBase)) is { } h
                    && Argument(call, h.Slot) is ConstOrigin slot
                    && Describe(applied.Image, slot.Number,
                        ReceiverOf(Argument(call, h.Object), argTypes) is { } r ? new Receiver(r) : null) is { } note)
                    calls[rva] = note with { Rva = rva };
                continue;
            }
            if (!IsVtableCall(ins)) continue;
            var direct = SlotEntryOf(call.Entry, argTypes, vtableStart);
            // A block no path reaches has no state to judge a jump by.
            if (ins.FlowControl == FlowControl.IndirectBranch && direct == null && call.Reached) unreadable = true;
            if (direct is { } d && Describe(applied.Image, d.Slot, new Receiver(d.Type)) is { } directNote)
                calls[rva] = directNote with { Rva = rva };
        }
        return unreadable ? [] : [.. calls.Values.OrderBy(c => c.Rva)];
    }

    // The same notes for an AArch64 function: blr and br through a register
    // loaded from a class pointer. A br the pass cannot read may be a jump
    // table, so the function then has no notes.
    private static List<SlotCall> Arm64Calls(LoadedNative native, NativeCodeIndex index, NativeFunction fn, AotNativeNames.Applied applied, CancellationToken ct)
    {
        var calls = new Dictionary<uint, SlotCall>();
        A64Function code;
        try { code = new A64Function(index, fn, ct); }
        catch (NotSupportedException) { return []; }
        if (!code.Blocks.Any(b => b.Any(s => IsIndirect(s.I)))) return [];
        var argTypes = Owner(applied.Image.MethodsAt(fn.Start)) is { } method
            ? ArgumentTypes(method, false, ValueProvenance.Arm64ArgumentCount, false) : [];
        int vtableStart = VtableStart(applied.Image.Model?.MetadataVersion ?? CurrentMetadataVersion);
        bool unreadable = false;
        ValueProvenance.WalkArm64(code, index.Image.ImageBase, (step, state) =>
        {
            if (!IsIndirect(step.I)) return;
            var entry = A64Function.Gpr(step.I, 0) is var r and >= 0 and < 31 ? state.GetReg(r) : null;
            var direct = SlotEntryOf(entry, argTypes, vtableStart);
            if (step.I.Mnemonic == Arm64Mnemonic.BR && direct == null && state.Reached) unreadable = true;
            if (direct is { } d && Describe(applied.Image, d.Slot, new Receiver(d.Type)) is { } note)
                calls[step.Rva] = note with { Rva = step.Rva };
        }, ct);
        return unreadable ? [] : [.. calls.Values.OrderBy(c => c.Rva)];
    }

    private static bool IsIndirect(in Arm64Instruction i) =>
        A64Function.IsCall(in i) && i.Mnemonic != Arm64Mnemonic.BL || i.Mnemonic == Arm64Mnemonic.BR;

    // A memory operand of one base register and a displacement.
    private static bool IsClassOffset(in Instruction i) =>
        i.Op0Kind == OpKind.Memory && i.MemoryIndex == Register.None && i.SegmentPrefix == Register.None
        && i.MemoryBase.IsGPR64() && i.MemoryBase != Register.RIP;

    // The slot index of a class record offset; null outside the vtable.
    private static long? SlotAt(long offset, int start) =>
        offset >= start && (offset - start) % SlotSize == 0 ? (offset - start) / SlotSize : null;

    // The vtable entry a value loads from the class pointer of a known type.
    private static (TypeDef Type, long Slot)? SlotEntryOf(Origin? value, Dictionary<int, TypeDef> args, int start) =>
        value is LoadOrigin { Base: { } klass, Size: 8 } entry && ClassOf(klass, args) is { } type
            && SlotAt(entry.Disp, start) is { } slot
            ? (type, slot) : null;

    // The type whose class pointer a value is: a load at offset 0 of a known receiver.
    private static TypeDef? ClassOf(Origin value, Dictionary<int, TypeDef> args) =>
        value is LoadOrigin { Disp: 0, Size: 8 } load ? ReceiverOf(load.Base, args) : null;

    // The class a value is declared as: a reference-typed argument, or a field of one.
    private static TypeDef? ReceiverOf(Origin? value, Dictionary<int, TypeDef> args) => value switch
    {
        ArgOrigin a => args.GetValueOrDefault(a.Index),
        LoadOrigin { Disp: not 0, Size: 8 } l when ReceiverOf(l.Base, args) is { } t => FieldType(t, l.Disp),
        _ => null,
    };

    // Shared, generic and value-type methods have no single receiver type.
    private static MethodDef? Owner(IReadOnlyList<AotMetadataService.MethodAddress> methods)
    {
        if (methods.Count == 0) return null;
        var first = methods[0].Method;
        return methods.All(m => ReferenceEquals(m.Method, first)) && !first.HasGenericParameters
            && first.DeclaringType is { HasGenericParameters: false } ? first : null;
    }

    // Reference-typed parameters by argument register index; Windows counts
    // every parameter, System V only integer ones.
    private static Dictionary<int, TypeDef> ArgumentTypes(MethodDef method, bool windows, int count, bool hiddenReturnRegister)
    {
        var types = new Dictionary<int, TypeDef>();
        // A struct return takes a hidden buffer pointer in the first register
        // on x64 and in x8 on AArch64.
        if (hiddenReturnRegister && IsStruct(method.MethodSig.RetType)) return types;
        int next = 0;
        if (!method.IsStatic)
        {
            if (method.DeclaringType.IsValueType) next++;
            else types[next++] = method.DeclaringType;
        }
        foreach (var p in method.MethodSig.Params)
        {
            bool floating = p.ElementType is ElementType.R4 or ElementType.R8;
            if (floating && !windows) continue;
            if (next >= count) break;
            // System V splits a struct over registers or the stack.
            if (IsStruct(p) && !windows) break;
            if (p is ClassSig cs && cs.TypeDefOrRef?.ResolveTypeDef() is { HasGenericParameters: false } t)
                types[next] = t;
            next++;
        }
        return types;
    }

    private static bool IsStruct(TypeSig sig) =>
        sig.RemovePinnedAndModifiers() is { ElementType: ElementType.ValueType }
        or GenericInstSig { GenericType: ValueTypeSig };

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
