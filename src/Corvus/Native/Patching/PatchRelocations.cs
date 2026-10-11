using System.Buffers.Binary;
using Iced.Intel;
using Corvus.Core;
using Corvus.Native.Pe;

namespace Corvus.Native.Patching;

/// <summary>How a patch treats the base relocations under it: plan them from the new bytes, keep them all, or neutralize them all.</summary>
public enum RelocationMode { Auto, Keep, Neutralize }

/// <summary>
/// A displacement or immediate inside patch bytes: its byte offset and size, the raw value, and what the operand is
/// (memory displacement with or without base/index registers, immediate) and whether it was written as a symbol or
/// with 'offset' (an explicit address).
/// </summary>
public readonly record struct OperandConstant(int Offset, int Size, ulong Value, bool IsDisplacement, bool HasBase, bool HasIndex, bool FromSymbol);

/// <summary>A 2-byte rewrite of one relocation entry inside the relocation directory.</summary>
public readonly record struct RelocationEdit(uint SlotRva, long FileOffset, ushort Original, ushort Replacement);

/// <summary>
/// One relocation consequence of a patch: <see cref="Action"/> is kept (the entry still covers an address in the new
/// bytes), neutralized (set to ABSOLUTE so the loader no longer adds the load delta into the new bytes), added (a new
/// entry written into an ABSOLUTE slot of the page's block) or unrelocated (an address with no entry: only correct at
/// the preferred base).
/// </summary>
public sealed record RelocationChange(string Action, uint TargetRva, PeRelocationType Type, uint? SlotRva, string? Note);

/// <summary>The relocation side of a patch: the entry rewrites, the per-entry report and notes.</summary>
public sealed record RelocationPlan(IReadOnlyList<RelocationEdit> Edits, IReadOnlyList<RelocationChange> Changes, IReadOnlyList<string> Notes)
{
    public static readonly RelocationPlan None = new([], [], []);
}

/// <summary>
/// Base-relocation planning for byte patches. The Windows loader adds (actual base - preferred base) to every location
/// a HIGHLOW / DIR64 entry names, whatever bytes are there, so a patch must (1) neutralize entries that now point into
/// bytes that are not an address and (2) give new absolute addresses an entry. Entries are rewritten in place: a
/// neutralized entry becomes IMAGE_REL_BASED_ABSOLUTE (type 0), and a new one reuses an ABSOLUTE slot (a neutralized
/// entry or the block's alignment padding) in the block of the same 4 KB page. The directory never grows.
/// </summary>
public static class PatchRelocations
{
    /// <summary>A relocation entry slot in the directory: where it is and its current 16-bit value.</summary>
    public readonly record struct Slot(uint SlotRva, long FileOffset, uint PageRva, ushort Value, bool IsParameter)
    {
        public PeRelocationType Type => (PeRelocationType)(Value >> 12);
        public uint TargetRva => PageRva + (uint)(Value & 0xFFF);
    }

    private const int MaxSlots = 1 << 23;

    /// <summary>Bytes a relocation of <paramref name="type"/> rewrites (0 for ABSOLUTE).</summary>
    public static int Width(PeRelocationType type) => type switch
    {
        PeRelocationType.Absolute => 0,
        PeRelocationType.High or PeRelocationType.Low or PeRelocationType.HighAdj => 2,
        PeRelocationType.Dir64 or PeRelocationType.ArmMov32 or PeRelocationType.ThumbMov32 => 8,
        _ => 4,
    };

    /// <summary>Whether the loader can move the image: it has a relocation directory and relocations are not stripped.</summary>
    public static bool IsRelocatable(PeFile image) =>
        (image.Coff.Characteristics & 0x0001) == 0 && image.Directory(PeDirectory.BaseRelocation) is { Rva: not 0, Size: not 0 };

    /// <summary>
    /// Every entry slot of the relocation directory, walked as the loader walks it (a block smaller than its header
    /// ends the walk). Slots that are not backed by file bytes are skipped (they cannot be rewritten).
    /// </summary>
    public static List<Slot> ReadSlots(PeFile image)
    {
        var slots = new List<Slot>();
        var dir = image.Directory(PeDirectory.BaseRelocation);
        if (dir.Rva == 0 || dir.Size == 0) return slots;
        long at = dir.Rva, end = (long)dir.Rva + dir.Size;
        Span<byte> head = stackalloc byte[8];
        Span<byte> two = stackalloc byte[2];
        while (at + 8 <= end && slots.Count < MaxSlots)
        {
            if (image.Read((uint)at, head) < 8) break;
            uint page = BinaryPrimitives.ReadUInt32LittleEndian(head);
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(head[4..]);
            if (size < 8) break;
            long blockEnd = Math.Min(at + size, end);
            for (long e = at + 8; e + 2 <= blockEnd && slots.Count < MaxSlots; e += 2)
            {
                if (image.Read((uint)e, two) < 2) break;
                ushort value = BinaryPrimitives.ReadUInt16LittleEndian(two);
                bool backed = image.TryRvaToFileOffset((uint)e, out long off) && image.TryRvaToFileOffset((uint)e + 1, out long off2) && off2 == off + 1;
                var slot = new Slot((uint)e, backed ? off : -1, page, value, false);
                slots.Add(slot);
                // HIGHADJ takes the next slot as its parameter: not an entry.
                if (slot.Type == PeRelocationType.HighAdj && e + 4 <= blockEnd)
                {
                    e += 2;
                    if (image.Read((uint)e, two) < 2) break;
                    bool pb = image.TryRvaToFileOffset((uint)e, out long poff);
                    slots.Add(new Slot((uint)e, pb ? poff : -1, page, BinaryPrimitives.ReadUInt16LittleEndian(two), true));
                }
            }
            at += size;
        }
        return slots;
    }

    /// <summary>
    /// The displacements and immediates of the instructions in <paramref name="bytes"/> decoded at <paramref name="ip"/>:
    /// linearly from offset 0 (stopping at an invalid instruction), or at the given instruction offsets. Branch
    /// displacements and RIP-relative operands are relative, so they are left out.
    /// </summary>
    public static List<OperandConstant> Decode(int bitness, ulong ip, byte[] bytes, IReadOnlyList<(int Offset, bool ImmSymbol, bool DispSymbol)>? at = null)
    {
        var result = new List<OperandConstant>();
        var points = at ?? Linear(bitness, ip, bytes);
        foreach (var (offset, immSym, dispSym) in points)
        {
            if (offset < 0 || offset >= bytes.Length) continue;
            var decoder = Iced.Intel.Decoder.Create(bitness, new ByteArrayCodeReader(bytes, offset, bytes.Length - offset), ip + (ulong)offset);
            decoder.Decode(out var instr);
            if (instr.IsInvalid) continue;
            var co = decoder.GetConstantOffsets(instr);
            if (co.HasDisplacement && !instr.IsIPRelativeMemoryOperand && co.DisplacementSize >= 4)
                result.Add(new OperandConstant(offset + co.DisplacementOffset, co.DisplacementSize,
                    Read(bytes, offset + co.DisplacementOffset, co.DisplacementSize), true,
                    instr.MemoryBase != Register.None, instr.MemoryIndex != Register.None, dispSym));
            if (co.HasImmediate && co.ImmediateSize >= 4 && HasImmediateOperand(instr))
                result.Add(new OperandConstant(offset + co.ImmediateOffset, co.ImmediateSize,
                    Read(bytes, offset + co.ImmediateOffset, co.ImmediateSize), false, false, false, immSym));
        }
        return result;
    }

    private static List<(int, bool, bool)> Linear(int bitness, ulong ip, byte[] bytes)
    {
        var list = new List<(int, bool, bool)>();
        var decoder = Iced.Intel.Decoder.Create(bitness, new ByteArrayCodeReader(bytes), ip);
        int offset = 0;
        while (offset < bytes.Length)
        {
            decoder.Decode(out var instr);
            if (instr.IsInvalid || instr.Length == 0) break;
            list.Add((offset, false, false));
            offset += instr.Length;
        }
        return list;
    }

    private static bool HasImmediateOperand(in Instruction instr)
    {
        for (int i = 0; i < instr.OpCount; i++)
            if (instr.GetOpKind(i) is OpKind.Immediate32 or OpKind.Immediate64 or OpKind.Immediate32to64) return true;
        return false;
    }

    private static ulong Read(byte[] bytes, int offset, int size) => size switch
    {
        8 when offset + 8 <= bytes.Length => BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(offset)),
        4 when offset + 4 <= bytes.Length => BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset)),
        _ => 0,
    };

    /// <summary>
    /// Plans the relocation side of overwriting <paramref name="original"/> with <paramref name="replacement"/> at
    /// <paramref name="rva"/>. <paramref name="operands"/> are the constants of the new bytes when they are code (null for
    /// data, where the new value at each entry decides); <paramref name="inferImmediates"/> treats an in-image 32-bit
    /// immediate as an address (raw bytes, where there is no symbol intent). Throws no_relocation_slot when a new address
    /// has no ABSOLUTE slot in its page's block, unless <paramref name="force"/>.
    /// </summary>
    public static RelocationPlan Plan(PeFile image, uint rva, byte[] original, byte[] replacement,
        IReadOnlyList<OperandConstant>? operands, bool inferImmediates, RelocationMode mode, bool force)
    {
        var notes = new List<string>();
        if (!IsRelocatable(image))
        {
            bool any = operands?.Any(o => InImage(image, o.Value, o.Size)) == true;
            if (any) notes.Add("image is not relocatable: absolute addresses are fixed (no action needed).");
            return new RelocationPlan([], [], notes);
        }

        uint end = rva + (uint)replacement.Length;
        var slots = ReadSlots(image);
        var pointerType = image.Is64Bit ? PeRelocationType.Dir64 : PeRelocationType.HighLow;
        var overlapping = new List<int>();
        for (int i = 0; i < slots.Count; i++)
        {
            var s = slots[i];
            if (s.IsParameter || s.Type == PeRelocationType.Absolute) continue;
            uint t = s.TargetRva;
            if (t < end && t + (uint)Width(s.Type) > rva) overlapping.Add(i);
        }

        // Addresses the new bytes hold, by RVA, with the relocation type they need.
        var needed = new SortedDictionary<uint, (PeRelocationType Type, string Why)>();
        var existingAt = overlapping.Select(i => slots[i]).GroupBy(s => s.TargetRva).ToDictionary(g => g.Key, g => g.First().Type);
        if (operands != null)
        {
            foreach (var o in operands)
            {
                if (o.Offset < 0 || o.Offset + o.Size > replacement.Length) continue;
                uint at = rva + (uint)o.Offset;
                var type = o.Size == 8 ? PeRelocationType.Dir64 : PeRelocationType.HighLow;
                if (!InImage(image, o.Value, o.Size))
                    continue;
                bool copied = existingAt.TryGetValue(at, out var et) && et == type && SameBytes(original, replacement, o.Offset, o.Size);
                string? why =
                    o.FromSymbol ? "symbol" :
                    copied ? "same address as before" :
                    o.IsDisplacement && !o.HasBase && o.Size == 4 && !image.Is64Bit ? "absolute memory operand" :
                    o.Size == 8 ? "64-bit address" :
                    existingAt.TryGetValue(at, out et) && et == type ? "address at a relocated position" :
                    inferImmediates && o.Size == 4 && !image.Is64Bit ? "immediate inside the image" : null;
                if (why != null) needed[at] = (type, why);
                else if (o.Size == 4 && !image.Is64Bit)
                    notes.Add($"the value 0x{o.Value:X} at {Va(image, at)} lies inside the image but was written as a number, so it is not relocated (write 'offset 0x{o.Value:X}' or a name to relocate it).");
            }
        }
        else
        {
            // Data: an entry stays when the new bytes still hold an in-image address there.
            foreach (var i in overlapping)
            {
                var s = slots[i];
                int w = Width(s.Type);
                if (s.Type != pointerType || s.TargetRva < rva || s.TargetRva + (uint)w > end) continue;
                int off = (int)(s.TargetRva - rva);
                ulong v = w == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(replacement.AsSpan(off)) : BinaryPrimitives.ReadUInt32LittleEndian(replacement.AsSpan(off));
                if (InImage(image, v, w)) needed[s.TargetRva] = (s.Type, "pointer inside the image");
            }
        }

        var changes = new List<RelocationChange>();
        var edits = new Dictionary<int, ushort>(); // slot index -> new value
        var freed = new List<int>();               // neutralized slots, reusable for new entries
        foreach (var i in overlapping)
        {
            var s = slots[i];
            uint t = s.TargetRva;
            bool inside = t >= rva && t + (uint)Width(s.Type) <= end;
            if (mode == RelocationMode.Keep)
            {
                changes.Add(new RelocationChange("kept", t, s.Type, s.SlotRva, "relocations=keep: left as it is; the loader still adds the load delta here"));
                continue;
            }
            if (mode == RelocationMode.Auto && inside && needed.TryGetValue(t, out var n) && n.Type == s.Type)
            {
                changes.Add(new RelocationChange("kept", t, s.Type, s.SlotRva, n.Why));
                needed.Remove(t);
                continue;
            }
            if (s.FileOffset < 0)
                throw new ToolError(ErrorCode.Unsupported, $"The relocation entry for {Va(image, t)} is not backed by file bytes, so it cannot be neutralized.");
            edits[i] = (ushort)(s.Value & 0x0FFF);
            freed.Add(i);
            changes.Add(new RelocationChange("neutralized", t, s.Type, s.SlotRva,
                !inside ? "the entry straddles the patch boundary" : mode == RelocationMode.Neutralize ? "relocations=neutralize" : "the new bytes hold no address here"));
        }

        if (mode != RelocationMode.Auto)
        {
            foreach (var (at, n) in needed)
                if (mode == RelocationMode.Neutralize || !existingAt.ContainsKey(at))
                    changes.Add(new RelocationChange("unrelocated", at, n.Type, null, $"relocations={mode.ToString().ToLowerInvariant()}: no entry added; only correct at the preferred base"));
            needed.Clear();
        }

        // New entries: reuse an ABSOLUTE slot in the block of the same page (a slot freed above first).
        var used = new HashSet<int>();
        foreach (var (at, n) in needed)
        {
            uint page = at & ~0xFFFu;
            int pick = freed.FirstOrDefault(i => slots[i].PageRva == page && !used.Contains(i), -1);
            if (pick < 0)
                for (int i = 0; i < slots.Count; i++)
                {
                    var s = slots[i];
                    if (s.PageRva == page && !s.IsParameter && s.Type == PeRelocationType.Absolute && s.FileOffset >= 0 && !used.Contains(i) && !edits.ContainsKey(i)) { pick = i; break; }
                }
            if (pick < 0)
            {
                if (!force)
                    throw new ToolError(ErrorCode.Conflict,
                        $"no_relocation_slot: the new address at {Va(image, at)} ({n.Why}) needs a base relocation, and the relocation block of page 0x{page:X} has no free (ABSOLUTE) slot to hold one; under ASLR or a rebase the loader would leave it pointing at the preferred base.",
                        (image.Is64Bit ? "write the reference RIP-relative (e.g. 'lea rax, [target]' / 'mov rax, [target]'); " : "") +
                        "or load the address from data that is already relocated (an existing pointer or IAT slot); or pass force=true to accept a patch that is only correct at the preferred base. " +
                        "Clearing DYNAMIC_BASE would also avoid it but weakens the binary's ASLR; it is not done automatically.");
                changes.Add(new RelocationChange("unrelocated", at, n.Type, null, "force=true: no free slot in the page's block; only correct at the preferred base"));
                continue;
            }
            used.Add(pick);
            var slot = slots[pick];
            edits[pick] = (ushort)(((int)n.Type << 12) | (int)(at - page));
            bool wasFreed = freed.Contains(pick);
            changes.Add(new RelocationChange("added", at, n.Type, slot.SlotRva,
                (wasFreed ? $"reused the neutralized entry slot" : "reused an ABSOLUTE slot of the page's block") + $" ({n.Why})"));
        }

        var editList = edits.OrderBy(e => slots[e.Key].SlotRva)
            .Select(e => new RelocationEdit(slots[e.Key].SlotRva, slots[e.Key].FileOffset, slots[e.Key].Value, e.Value))
            .Where(e => e.Original != e.Replacement)
            .ToList();
        // An edit inside the patched bytes would be overwritten by the patch itself.
        if (editList.Any(e => e.SlotRva + 2 > rva && e.SlotRva < end))
            throw new ToolError(ErrorCode.Conflict, "The patch overwrites the relocation entries it would need to rewrite.", "patch the relocation directory and the code in separate calls with relocations=keep");
        return new RelocationPlan(editList, changes.OrderBy(c => c.TargetRva).ToList(), notes);
    }

    private static bool SameBytes(byte[] a, byte[] b, int offset, int size) =>
        offset + size <= a.Length && offset + size <= b.Length && a.AsSpan(offset, size).SequenceEqual(b.AsSpan(offset, size));

    private static bool InImage(PeFile image, ulong value, int size)
    {
        if (size == 4) value &= 0xFFFFFFFF;
        return value >= image.ImageBase && value - image.ImageBase < image.SizeOfImage;
    }

    private static string Va(PeFile image, uint rva) => NativeAddress.Va(image, rva);
}
