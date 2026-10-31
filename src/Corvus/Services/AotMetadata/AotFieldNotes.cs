using AsmArm64;
using Iced.Intel;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;

namespace Corvus.Services;

/// <summary>Names [this+offset] operands after the owner's instance fields; empty means not applicable or unknown.</summary>
public static class AotFieldNotes
{
    private enum Flow : byte { Next, Call, Branch, Conditional, End }

    // Restore marks a reload of a saved value, which does not make a register impure.
    private sealed record Step(uint Rva, int[] Writes, bool Restore, (int Dst, int Src)? Copy, (int Base, long Disp)? Memory, Flow Flow, uint? Target);

    private sealed record Registers(int This, HashSet<int> Saved, HashSet<int> Volatile);

    /// <summary>Notes by instruction RVA for the this-based operands of <paramref name="fn"/>; empty when unknown or not applicable.</summary>
    public static Dictionary<uint, string> Comments(LoadedNative native, NativeCodeIndex index, NativeFunction fn, CancellationToken ct = default)
    {
        var notes = new Dictionary<uint, string>();
        if (index.Image.Arch is not (NativeArch.X64 or NativeArch.Arm64) || AotNativeNames.Of(native) is not { } applied) return notes;
        if (Owner(applied.Image.MethodsAt(fn.Start)) is not { } owner || new AotLayout().Of(owner) is not { } layout) return notes;
        var members = layout.Members.Where(m => m.Size > 0).OrderBy(m => m.Offset).ToList();
        if (members.Count == 0) return notes;
        var (steps, registers) = index.Image.Arch == NativeArch.X64 ? X64Steps(index, fn, native.Image.Format == ImageFormat.Pe, ct) : Arm64Steps(index, fn, ct);
        foreach (var (rva, disp) in Track(steps, registers, fn.Start))
            if (Field(members, disp) is { } field) notes[rva] = $"this->{field} ({owner.Name}+0x{disp:X})";
        return notes;
    }

    // Shared, static, generic and value-type methods have no single this layout.
    private static dnlib.DotNet.TypeDef? Owner(IReadOnlyList<AotMetadataService.MethodAddress> methods)
    {
        if (methods.Count == 0 || methods.Any(m => m.Method.IsStatic)) return null;
        var type = methods[0].Method.DeclaringType;
        return type == null || type.IsValueType || type.HasGenericParameters || methods.Any(m => !ReferenceEquals(m.Method.DeclaringType, type)) ? null : type;
    }

    // The member name, with +0xN when the offset lands inside it.
    private static string? Field(List<AotLayout.Member> members, long disp)
    {
        if (disp < 0) return null;
        var m = members.FirstOrDefault(x => (long)x.Offset == disp) ?? members.LastOrDefault(x => (long)x.Offset < disp && disp < (long)(x.Offset + x.Size));
        return m == null ? null : (long)m.Offset == disp ? m.Name : $"{m.Name}+0x{disp - (long)m.Offset:X}";
    }

    // Registers in pure survive a branch target; other copies are dropped there, as another path may reach it.
    private static List<(uint Rva, long Disp)> Track(List<Step> steps, Registers abi, uint entry)
    {
        var found = new List<(uint, long)>();
        var pure = PureHolders(steps, abi);
        var targets = steps.Where(s => s.Flow is Flow.Branch or Flow.Conditional && s.Target != null).Select(s => s.Target!.Value).ToHashSet();
        var held = new HashSet<int> { abi.This };
        bool afterJump = false;
        foreach (var s in steps)
        {
            // Code after a jump or return is reached only through a target, so it starts from the pure holders.
            if (afterJump) held = new HashSet<int>(pure);
            else if (s.Rva != entry && targets.Contains(s.Rva)) held.IntersectWith(pure);
            afterJump = false;
            if (s.Memory is { } m && held.Contains(m.Base)) found.Add((s.Rva, m.Disp));
            bool copied = s.Copy is { } c && held.Contains(c.Src);
            foreach (var w in s.Writes) held.Remove(w);
            if (copied) held.Add(s.Copy!.Value.Dst);
            if (s.Flow == Flow.Call) held.ExceptWith(abi.Volatile);
            else if (s.Flow is Flow.Branch or Flow.End) afterJump = true;
        }
        return found;
    }

    // Callee-saved copies of this made before any call or branch and never rewritten; this itself when no step writes it and no call clobbers it.
    private static HashSet<int> PureHolders(List<Step> steps, Registers abi)
    {
        var copies = new HashSet<int>();
        var copyAt = new HashSet<uint>();
        foreach (var s in steps)
        {
            if (s.Copy is { } c && c.Src == abi.This && abi.Saved.Contains(c.Dst) && s.Flow == Flow.Next)
            {
                copies.Add(c.Dst);
                copyAt.Add(s.Rva);
                continue;
            }
            if (s.Flow != Flow.Next || s.Writes.Contains(abi.This)) break;
        }
        var written = steps.Where(s => !copyAt.Contains(s.Rva) && !s.Restore).SelectMany(s => s.Writes).ToHashSet();
        copies.ExceptWith(written);
        if (!written.Contains(abi.This) && steps.All(s => s.Flow != Flow.Call)) copies.Add(abi.This);
        return copies;
    }

    private static (List<Step>, Registers) X64Steps(NativeCodeIndex index, NativeFunction fn, bool windows, CancellationToken ct)
    {
        Register[] saved = windows ? [Register.RBX, Register.RSI, Register.RDI, Register.RBP, Register.R12, Register.R13, Register.R14, Register.R15]
            : [Register.RBX, Register.RBP, Register.R12, Register.R13, Register.R14, Register.R15];
        Register[] clobbered = windows ? [Register.RAX, Register.RCX, Register.RDX, Register.R8, Register.R9, Register.R10, Register.R11]
            : [Register.RAX, Register.RCX, Register.RDX, Register.RSI, Register.RDI, Register.R8, Register.R9, Register.R10, Register.R11];
        var abi = new Registers((int)(windows ? Register.RCX : Register.RDI), saved.Select(r => (int)r).ToHashSet(), clobbered.Select(r => (int)r).ToHashSet());
        var info = new InstructionInfoFactory();
        var steps = new List<Step>();
        ulong imageBase = index.Image.ImageBase;
        foreach (var ins in NativeAotCode.Decode(index.Image, index.Ranges(fn), ct))
        {
            var writes = info.GetInfo(ins).GetUsedRegisters()
                .Where(u => u.Access is OpAccess.Write or OpAccess.ReadWrite or OpAccess.CondWrite or OpAccess.ReadCondWrite)
                .Select(u => (int)u.Register.GetFullRegister()).Distinct().ToArray();
            (int, int)? copy = ins.Mnemonic == Mnemonic.Mov && ins.Op0Kind == OpKind.Register && ins.Op1Kind == OpKind.Register
                && ins.Op0Register.IsGPR64() && ins.Op1Register.IsGPR64() ? ((int)ins.Op0Register, (int)ins.Op1Register) : null;
            // A segment-prefixed operand is not based on this.
            bool memoryOperand = Enumerable.Range(0, ins.OpCount).Any(k => ins.GetOpKind(k) == OpKind.Memory);
            (int, long)? memory = memoryOperand && ins.SegmentPrefix == Register.None && ins.MemoryBase.IsGPR64() && ins.MemoryBase != Register.RIP && ins.MemoryIndex == Register.None
                ? ((int)ins.MemoryBase, (long)ins.MemoryDisplacement64) : null;
            // Pops and stack reloads of saved registers restore the caller's value, not a new one.
            bool restore = ins.Mnemonic == Mnemonic.Pop || ins.Mnemonic == Mnemonic.Mov && ins.Op0Kind == OpKind.Register && ins.Op1Kind == OpKind.Memory
                && ins.MemoryBase is Register.RSP or Register.RBP && saved.Contains(ins.Op0Register.GetFullRegister());
            var flow = ins.FlowControl switch
            {
                FlowControl.Next => Flow.Next,
                FlowControl.Call or FlowControl.IndirectCall => Flow.Call,
                FlowControl.ConditionalBranch => Flow.Conditional,
                FlowControl.UnconditionalBranch => Flow.Branch,
                _ => Flow.End,
            };
            uint? target = flow is Flow.Branch or Flow.Conditional && ins.Op0Kind is OpKind.NearBranch64 or OpKind.NearBranch32 or OpKind.NearBranch16
                ? (uint)(ins.NearBranchTarget - imageBase) : null;
            steps.Add(new Step((uint)(ins.IP - imageBase), writes, restore, copy, memory, flow, target));
        }
        return (steps, abi);
    }

    private static (List<Step>, Registers) Arm64Steps(NativeCodeIndex index, NativeFunction fn, CancellationToken ct)
    {
        var abi = new Registers(0, Enumerable.Range(19, 10).ToHashSet(), Enumerable.Range(0, 19).Append(30).ToHashSet());
        var steps = new List<Step>();
        if (index.NewDecoder() is not Arm64Decoder dec) return (steps, abi);
        dec.BeginFunction();
        foreach (var (start, end) in index.Ranges(fn).OrderBy(r => r.Start))
        {
            dec.BeginRun(IndexBound.None);
            for (uint at = start; at < end; at += 4)
            {
                ct.ThrowIfCancellationRequested();
                if (!dec.DecodeMapped(at, out var insn) || insn.Flow == FlowKind.Invalid) break;
                var i = dec.Last;
                var writes = new List<int>();
                int? source = null;
                (int, long)? memory = null;
                bool restore = false;
                for (int k = 0; k < i.OperandCount; k++)
                {
                    var op = i.GetOperand(k);
                    if (op.Kind == Arm64OperandKind.Register)
                    {
                        var r = ((Arm64RegisterOperand)op).Value;
                        if (r.Kind is not (Arm64RegisterKind.X or Arm64RegisterKind.W) || r.Index == 31) continue;
                        if ((op.Flags & Arm64OperandFlags.Write) != 0) writes.Add(r.Index);
                        // A W-register copy truncates, so only X sources are followed.
                        else if (k == 1 && i.Mnemonic == Arm64Mnemonic.MOV && r.Kind == Arm64RegisterKind.X) source = r.Index;
                    }
                    else if (op.Kind == Arm64OperandKind.Memory)
                    {
                        var a = ((Arm64MemoryOperand)op).Accessor;
                        bool post = a.OffsetKind == Arm64MemoryOffsetKind.None && k + 1 < i.OperandCount && i.GetOperand(k + 1).Kind == Arm64OperandKind.Immediate;
                        // An SP-based access is a spill or reload of a saved register.
                        if (a.BaseRegister.Kind == Arm64RegisterKind.SP) restore = true;
                        else if (a.BaseRegister.Kind != Arm64RegisterKind.X) continue;
                        else if (a.IsPreIncrement || post) writes.Add(a.BaseRegister.Index);
                        else if (!a.HasIndexRegister) memory = (a.BaseRegister.Index, a.HasImmediate ? a.Immediate : 0);
                    }
                }
                (int, int)? copy = source is { } s && writes.Count == 1 ? (writes[0], s) : null;
                var flow = insn.Flow switch
                {
                    FlowKind.Next => Flow.Next,
                    FlowKind.Call or FlowKind.IndirectCall => Flow.Call,
                    FlowKind.ConditionalJump => Flow.Conditional,
                    FlowKind.Jump => Flow.Branch,
                    _ => Flow.End,
                };
                steps.Add(new Step(at, writes.ToArray(), restore && writes.Count > 0, copy, memory, flow, insn.HasTarget ? insn.Target : null));
            }
        }
        return (steps, abi);
    }
}
