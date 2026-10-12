using Iced.Intel;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.NativeAot;

namespace Corvus.Services;

/// <summary>
/// Disassembly comments and virtual call edges from NativeAOT metadata (x64): string literal loads (an instruction addressing a frozen String
/// object), interface calls (an instruction addressing a dispatch cell)
/// and virtual calls through a MethodTable's vtable, "mov r, [obj]; call [r + 24 + 8k]", or the slot loaded into a
/// register first and called directly or through the CFG dispatch helper (target in rax); tracked linearly within a block.
/// The receiver's type is known when obj is this of an instance method (rcx, rdi in ELF and Mach-O, before it is overwritten, or a callee-saved
/// register copied from it once and never written again); slot k then names the method in the type's vtable, which a
/// derived type may override.
/// </summary>
public static class NativeAotCode
{
    /// <summary>Offset of vtable slot 0 in an x64 MethodTable (.NET 7–10).</summary>
    private const int VtableOffset = 24;

    /// <summary>The calling convention's this register, the registers a call clobbers and the callee-saved ones.</summary>
    private sealed record Abi(Register This, Register[] Volatile, Register[] Saved)
    {
        public static readonly Abi Windows = new(Register.RCX, [Register.RAX, Register.RCX, Register.RDX, Register.R8, Register.R9, Register.R10, Register.R11],
            [Register.RBX, Register.RSI, Register.RDI, Register.RBP, Register.R12, Register.R13, Register.R14, Register.R15]);
        /// <summary>ELF and Mach-O images.</summary>
        public static readonly Abi SystemV = new(Register.RDI, [Register.RAX, Register.RCX, Register.RDX, Register.RSI, Register.RDI, Register.R8, Register.R9, Register.R10, Register.R11],
            [Register.RBX, Register.RBP, Register.R12, Register.R13, Register.R14, Register.R15]);
    }

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<NativeAotImage, Lookup> Lookups = new();

    /// <summary>Most implementations of one site given as edges; more makes it unresolved (too_many_targets).</summary>
    private const int MaxTargets = 64;

    /// <summary>
    /// Frozen strings by object RVA; MethodTables with a vtable by name (the first by address when a name repeats); classes
    /// by base type.
    /// </summary>
    private sealed class Lookup(NativeAotImage aot)
    {
        public readonly Dictionary<uint, string> Strings = aot.Frozen.Objects.Where(o => o.Text != null).ToDictionary(o => o.Rva, o => o.Text!);
        public readonly Dictionary<string, NativeAotMethodTable> ByName = aot.Types.ByRva.Values.Where(t => t.Vtable.Count > 0).OrderBy(t => t.Rva)
            .GroupBy(t => t.Name, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        public readonly Dictionary<uint, List<NativeAotMethodTable>> Derived = aot.Types.ByRva.Values
            .Where(t => t.Kind == "class" && t.RelatedType != 0 && t.RelatedType != t.Rva).GroupBy(t => t.RelatedType).ToDictionary(g => g.Key, g => g.ToList());
    }

    /// <summary>One instruction the scan explains: a string literal load, an interface dispatch call or a vtable call.</summary>
    private readonly record struct Site(uint Rva, string? Literal, NativeAotDispatchCell? Cell, bool Call, bool Virtual, NativeAotMethodTable? Table, int Slot);

    /// <summary>Comments by instruction RVA for <paramref name="fn"/>; empty for other images and architectures.</summary>
    public static Dictionary<uint, string> Comments(LoadedNative native, NativeCodeIndex index, NativeFunction fn, CancellationToken ct = default)
    {
        var comments = new Dictionary<uint, string>();
        if (index.Image.Arch != NativeArch.X64 || NativeAotNames.View(native, ct) is not { } aot) return comments;
        var lookup = Lookups.GetValue(aot, a => new Lookup(a));
        var obj = lookup.ByName.GetValueOrDefault("System.Object");
        foreach (var s in Scan(aot, lookup, index, fn, ct))
            comments[s.Rva] = s.Literal != null ? Il2CppNativeNames.Quote(s.Literal)
                : s.Virtual ? Virtual(index, s.Table, obj, s.Slot)
                : $"interface call {s.Cell!.Target} (dispatch cell; {aot.Dispatch.Implementers(s.Cell.Interface, s.Cell.Slot).Count} implementations known)";
        return comments;
    }

    /// <summary>
    /// Call edges from the MethodTables (x64): a vtable call on this goes to the slot's code in the owner's MethodTable and in
    /// every class derived from it (one distinct body: exact, else possible); an interface call through a dispatch cell to the
    /// implementations the dispatch maps list (possible). Adds them to the index's virtual calls; nothing for other images
    /// or an index that already has them (a saved one).
    /// </summary>
    public static int AddVirtualCalls(LoadedNative native, NativeCodeIndex index, CancellationToken ct = default)
    {
        if (index.Image.Arch != NativeArch.X64 || index.MetadataVirtualCallsAdded || NativeAotNames.View(native, ct) is not { } aot) return 0;
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var lookup = Lookups.GetValue(aot, a => new Lookup(a));
        var sites = new List<VirtualCallSite>();
        var edges = new List<CodeXref>();
        var gate = new object();
        Parallel.ForEach(index.Functions, new ParallelOptions { CancellationToken = ct }, () => (Sites: new List<VirtualCallSite>(), Edges: new List<CodeXref>()), (fn, _, local) =>
        {
            foreach (var s in Scan(aot, lookup, index, fn, ct))
            {
                if (!s.Call || s.Literal != null) continue;
                var (site, targets) = Resolve(aot, lookup, fn, s);
                local.Sites.Add(site);
                if (site.Status == VirtualCallStatus.Unresolved) continue;
                var kind = site.Status == VirtualCallStatus.Exact ? XrefKind.VirtualExact : XrefKind.VirtualPossible;
                local.Edges.AddRange(targets.Select(t => new CodeXref(s.Rva, t, kind)));
            }
            return local;
        }, local => { lock (gate) { sites.AddRange(local.Sites); edges.AddRange(local.Edges); } });
        if (sites.Count == 0)
        {
            index.MarkMetadataVirtualCalls();
            return 0;
        }
        int resolved = sites.Count(s => s.Status != VirtualCallStatus.Unresolved);
        index.AddVirtualCalls(sites.GroupBy(s => s.Rva).Select(g => g.MinBy(s => (s.Status, s.Function))).ToList(), edges,
            $"NativeAOT: {sites.Count:N0} vtable and interface call sites, {resolved:N0} resolved from the MethodTables and dispatch maps in {clock.Elapsed.TotalSeconds:0.0} s");
        return sites.Count;
    }

    /// <summary>
    /// A vtable call on a known type: the slot's code in it and its derived classes (one: exact). An interface call: the
    /// implementations the dispatch maps list, never exact as they omit inherited and default implementations.
    /// </summary>
    private static (VirtualCallSite Site, List<uint> Targets) Resolve(NativeAotImage aot, Lookup lookup, NativeFunction fn, Site s)
    {
        if (s.Virtual)
        {
            var targets = s.Table == null ? [] : Implementations(aot, lookup, s.Table, s.Slot);
            var reason = s.Table == null ? VirtualCallReason.ReceiverUnknown
                : targets.Count == 0 ? VirtualCallReason.SlotOutOfRange : targets.Count > MaxTargets ? VirtualCallReason.TooManyTargets : VirtualCallReason.None;
            var status = reason != VirtualCallReason.None ? VirtualCallStatus.Unresolved : targets.Count == 1 ? VirtualCallStatus.Exact : VirtualCallStatus.Possible;
            return (new VirtualCallSite(s.Rva, fn.Start, s.Slot, 0, status, reason, s.Table == null ? VirtualReceiver.Unknown : VirtualReceiver.This,
                0, s.Table?.Rva ?? 0, targets.Count, false, false), targets);
        }
        var implementations = aot.Dispatch.Implementers(s.Cell!.Interface, s.Cell.Slot).Select(i => i.Code).Distinct().ToList();
        var why = implementations.Count == 0 ? VirtualCallReason.ReceiverUnknown : implementations.Count > MaxTargets ? VirtualCallReason.TooManyTargets : VirtualCallReason.None;
        return (new VirtualCallSite(s.Rva, fn.Start, s.Cell.Slot, 0, why == VirtualCallReason.None ? VirtualCallStatus.Possible : VirtualCallStatus.Unresolved,
            why, VirtualReceiver.Unknown, 0, s.Cell.Interface, implementations.Count, false, false), implementations);
    }

    /// <summary>The distinct code of <paramref name="slot"/> in <paramref name="mt"/> and the classes derived from it; stops past <see cref="MaxTargets"/>.</summary>
    private static List<uint> Implementations(NativeAotImage aot, Lookup lookup, NativeAotMethodTable mt, int slot)
    {
        var found = new List<uint>();
        var seen = new HashSet<uint>();
        var visited = new HashSet<uint>();
        var queue = new Queue<NativeAotMethodTable>([mt]);
        while (queue.TryDequeue(out var t) && found.Count <= MaxTargets)
        {
            if (!visited.Add(t.Rva)) continue;
            if (aot.Types.SlotCode(t, slot) is var code and not 0 && seen.Add(code)) found.Add(code);
            foreach (var d in lookup.Derived.GetValueOrDefault(t.Rva) ?? []) queue.Enqueue(d);
        }
        return found;
    }

    /// <summary>The instructions of <paramref name="fn"/> the NativeAOT metadata explains, in address order.</summary>
    private static List<Site> Scan(NativeAotImage aot, Lookup lookup, NativeCodeIndex index, NativeFunction fn, CancellationToken ct)
    {
        var result = new List<Site>();
        var image = index.Image;
        var strings = lookup.Strings;
        var owner = aot.Names.MethodAt.TryGetValue(fn.Start, out var m) && m.Name.HasThis == true ? lookup.ByName.GetValueOrDefault(m.Name.Owner) : null;

        var instructions = Decode(image, index.Ranges(fn), ct);
        ulong entry = image.ImageBase + fn.Start;
        var abi = image.Format == ImageFormat.Pe ? Abi.Windows : Abi.SystemV;
        var thisHolders = owner != null ? ThisHolders(instructions, entry, abi) : [];
        var info = new InstructionInfoFactory();
        bool thisLive = false;
        var tables = new Dictionary<Register, NativeAotMethodTable?>(); // register -> the MethodTable it holds (null: of an unknown type)
        var slots = new Dictionary<Register, (NativeAotMethodTable? Table, int Slot)>(); // register -> the vtable slot it was loaded from
        var cells = new Dictionary<Register, NativeAotDispatchCell>(); // register -> a dispatch cell's address (lea r11, [cell]; call [r11] or call rax)
        foreach (var ins in instructions)
        {
            ct.ThrowIfCancellationRequested();
            uint rva = (uint)(ins.IP - image.ImageBase);
            bool call = ins.Mnemonic == Mnemonic.Call;
            if (ins.IP == entry) thisLive = owner != null;
            NativeAotDispatchCell? leaCell = null;
            if (ins.IsIPRelativeMemoryOperand && ins.IPRelativeMemoryAddress - image.ImageBase is var target and < uint.MaxValue
                && strings.TryGetValue((uint)target, out var text))
                result.Add(new Site(rva, text, null, call, false, null, 0));
            else if (ins.IsIPRelativeMemoryOperand && ins.IPRelativeMemoryAddress - image.ImageBase is var at and < uint.MaxValue
                     && aot.Dispatch.CellAt((uint)at) is { } cell)
            {
                result.Add(new Site(rva, null, cell, call, false, null, 0));
                if (ins.Mnemonic == Mnemonic.Lea && ins.Op0Register.IsGPR64()) leaCell = cell;
            }

            int? slot = ins.Op0Kind == OpKind.Memory || ins.Op1Kind == OpKind.Memory ? Slot(ins) : null;
            if (call)
            {
                // call [mt + slot]; call reg holding a slot; a CFG dispatch call (call [__guard_dispatch_icall_fptr]) on rax holding one; call [cell register]
                if (ins.Op0Kind == OpKind.Memory && slot is { } k && tables.TryGetValue(ins.MemoryBase, out var mt)) result.Add(new Site(rva, null, null, true, true, mt, k));
                else if (ins.Op0Kind == OpKind.Register && slots.TryGetValue(ins.Op0Register, out var held)) result.Add(new Site(rva, null, null, true, true, held.Table, held.Slot));
                else if (ins.Op0Kind == OpKind.Memory && ins.IsIPRelativeMemoryOperand && slots.TryGetValue(Register.RAX, out held))
                    result.Add(new Site(rva, null, null, true, true, held.Table, held.Slot));
                else if (ins.Op0Kind == OpKind.Memory && ins.MemoryDisplacement64 == 0 && ins.MemoryIndex == Register.None && cells.TryGetValue(ins.MemoryBase, out var viaCell))
                    result.Add(new Site(rva, null, viaCell, true, false, null, 0));
                // .NET 10: the cell's resolved target called with the cell in r11 (mov rcx, [cell]; call [resolver]; mov rax, rcx; lea r11, [cell]; call rax)
                else if ((ins.Op0Kind == OpKind.Register || ins.IsIPRelativeMemoryOperand) && cells.TryGetValue(Register.R11, out viaCell))
                    result.Add(new Site(rva, null, viaCell, true, false, null, 0));
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
            bool fromThis = loaded != Register.None && (ins.MemoryBase == abi.This && thisLive || thisHolders.Contains(ins.MemoryBase));

            foreach (var used in info.GetInfo(ins).GetUsedRegisters())
                if (used.Access is OpAccess.Write or OpAccess.ReadWrite or OpAccess.CondWrite or OpAccess.ReadCondWrite)
                {
                    var full = used.Register.GetFullRegister();
                    tables.Remove(full);
                    slots.Remove(full);
                    cells.Remove(full);
                    if (full == abi.This) thisLive = false;
                }
            if (loaded != Register.None) tables[loaded] = fromThis ? owner : null;
            if (slotted != Register.None) slots[slotted] = (slotTable, slot!.Value);
            if (leaCell != null) cells[ins.Op0Register] = leaCell;
            if (ins.FlowControl is FlowControl.Call or FlowControl.IndirectCall)
            {
                foreach (var r in abi.Volatile) { tables.Remove(r); slots.Remove(r); cells.Remove(r); }
                thisLive = false;
            }
            else if (ins.FlowControl != FlowControl.Next)
            {
                tables.Clear(); // another path may reach the next instruction
                slots.Clear();
                cells.Clear();
                thisLive = false;
            }
        }
        return result;
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
    /// Callee-saved registers that hold this for the whole function: copied from the this register while it holds this (before any
    /// call, branch or write to it) and never written otherwise (pops in epilogues aside).
    /// </summary>
    private static HashSet<Register> ThisHolders(List<Instruction> instructions, ulong entry, Abi abi)
    {
        var holders = new HashSet<Register>();
        var info = new InstructionInfoFactory();
        var copies = new HashSet<Register>();
        var copyAt = new HashSet<ulong>();
        bool rcx = true;
        foreach (var ins in instructions.SkipWhile(i => i.IP != entry))
        {
            if (!rcx) break;
            if (ins.Mnemonic == Mnemonic.Mov && ins.Op0Kind == OpKind.Register && ins.Op1Kind == OpKind.Register && ins.Op1Register == abi.This
                && abi.Saved.Contains(ins.Op0Register))
            {
                copies.Add(ins.Op0Register);
                copyAt.Add(ins.IP);
                continue;
            }
            if (ins.FlowControl != FlowControl.Next || info.GetInfo(ins).GetUsedRegisters().Any(u => u.Register.GetFullRegister() == abi.This && u.Access is not OpAccess.Read))
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
