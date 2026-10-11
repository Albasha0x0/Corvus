using System.Buffers.Binary;
using Corvus.Native.Pe;

namespace Corvus.Native.Elf;

public sealed partial class ElfFile
{
    private ImageArea<List<DeclaredFunction>> unwind = null!;

    /// <summary>
    /// Function starts in code from .eh_frame_hdr (or a walk of .eh_frame), .ARM.exidx, function symbols and the
    /// initializer and finalizer arrays, one per address (the first source in that order wins), sorted. ARM Thumb bits
    /// are cleared.
    /// </summary>
    public IReadOnlyList<DeclaredFunction> DeclaredFunctions => unwind.Value;

    private List<DeclaredFunction> ParseUnwind(IssueLog log)
    {
        var found = new Dictionary<uint, DeclaredFunction>();
        void Add(ulong va, ulong? size, DeclaredSource source)
        {
            if (Machine == ElfNames.EmArm) va &= ~1UL;
            // Starts outside code are dropped: the linker ends .ARM.exidx with a sentinel at the end of .text.
            if (!TryVaToRva(va, out uint rva) || SectionAt(rva) is not { IsExecutable: true } || found.Count >= PeLimits.MaxRuntimeFunctions) return;
            uint? sz = size is { } s and > 0 and <= uint.MaxValue ? (uint)s : null;
            if (found.TryGetValue(rva, out var existing))
            {
                if (existing.Size == null && sz != null) found[rva] = existing with { Size = sz };
                return;
            }
            found[rva] = new DeclaredFunction(rva, sz, source);
        }

        foreach (var (start, range) in ReadEhFrame(log)) Add(start, range, DeclaredSource.Unwind);
        foreach (var (start, size) in ReadExidx(log)) Add(start, size, DeclaredSource.Unwind);
        foreach (var s in DynamicSymbols.Concat(StaticSymbols))
            if (s.IsDefined && s.IsFunction && s.Value != 0) Add(s.Value, s.Size, DeclaredSource.Symbol);
        foreach (var va in Initializers(log)) Add(va, null, DeclaredSource.Initializer);
        if (found.Count >= PeLimits.MaxRuntimeFunctions) log.Add($"more than {PeLimits.MaxRuntimeFunctions} declared functions; the rest are not listed");
        var list = found.Values.ToList();
        list.Sort((a, b) => a.Rva.CompareTo(b.Rva));
        return list;
    }

    private List<EhFrame.Fde> ReadEhFrame(IssueLog log)
    {
        var hdrSegment = segments.FirstOrDefault(s => s.Type == 0x6474E550);
        ulong hdrVa = hdrSegment?.VirtualAddress ?? Section(".eh_frame_hdr")?.Address ?? 0;
        var ehSection = Section(".eh_frame");
        ulong walkVa = ehSection is { IsAllocated: true, Size: > 0 } ? ehSection.Address : 0;
        if (hdrVa != 0)
        {
            var hdr = ViewAt(hdrVa, Math.Max(hdrSegment?.MemorySize ?? 0, Section(".eh_frame_hdr")?.Size ?? 0));
            if (hdr.Length >= 4 && hdr.U8(0) == 1)
            {
                byte ptrEnc = hdr.U8(1), countEnc = hdr.U8(2), tableEnc = hdr.U8(3);
                long pos = 4;
                if (EhFrame.TryReadPointer(hdr, ref pos, ptrEnc, hdrVa, hdrVa, Is64Bit, out ulong ehVa)
                    && EhFrame.TryReadPointer(hdr, ref pos, countEnc, hdrVa, hdrVa, Is64Bit, out ulong count) && tableEnc != EhFrame.Omit)
                {
                    var eh = ViewAt(ehVa, ehSection is { } sec && sec.Address == ehVa ? sec.Size : ulong.MaxValue);
                    var cache = EhFrame.NewCache();
                    var result = new List<EhFrame.Fde>();
                    var budget = new WorkBudget(log);
                    for (ulong i = 0; i < count && budget.Step(); i++)
                    {
                        if (!EhFrame.TryReadPointer(hdr, ref pos, tableEnc, hdrVa, hdrVa, Is64Bit, out ulong start)
                            || !EhFrame.TryReadPointer(hdr, ref pos, tableEnc, hdrVa, hdrVa, Is64Bit, out ulong fdeVa))
                        {
                            log.Add($".eh_frame_hdr table ends after {i} of {count} entries");
                            break;
                        }
                        if (result.Count >= PeLimits.MaxRuntimeFunctions) break;
                        var fde = fdeVa >= ehVa ? EhFrame.ReadFdeAt(eh, (long)(fdeVa - ehVa), ehVa, Is64Bit, cache) : null;
                        result.Add(new EhFrame.Fde(start, fde is { } f && f.Start == start ? f.Range : 0));
                    }
                    return result;
                }
                log.Add($".eh_frame_hdr encodings 0x{ptrEnc:X2}/0x{countEnc:X2}/0x{tableEnc:X2} have no usable search table; .eh_frame is walked");
                pos = 4;
                if (walkVa == 0 && EhFrame.TryReadPointer(hdr, ref pos, ptrEnc, hdrVa, hdrVa, Is64Bit, out ulong fromHeader)) walkVa = fromHeader;
            }
            else log.Add($".eh_frame_hdr at 0x{hdrVa:X} has version {hdr.U8(0)}; .eh_frame is walked");
        }
        if (walkVa == 0) return [];
        var view = ViewAt(walkVa, ehSection is { } section && section.Address == walkVa ? section.Size : ulong.MaxValue);
        return EhFrame.Walk(view, walkVa, Is64Bit, log, PeLimits.MaxRuntimeFunctions);
    }

    /// <summary>.ARM.exidx: prel31 function starts, each ending where the next begins (EXIDX_CANTUNWIND entries included).</summary>
    private List<(ulong Start, ulong? Size)> ReadExidx(IssueLog log)
    {
        var seg = segments.FirstOrDefault(s => s.Type == 0x70000001);
        ulong va = seg?.VirtualAddress ?? Section(".ARM.exidx")?.Address ?? 0;
        ulong size = seg?.MemorySize ?? Section(".ARM.exidx")?.Size ?? 0;
        if (va == 0 || size == 0) return [];
        var t = ViewAt(va, size);
        if ((ulong)t.Length < size) log.Add($".ARM.exidx at 0x{va:X}+0x{size:X} is only partly in the file");
        var starts = new List<ulong>();
        for (long at = 0; at + 8 <= t.Length && starts.Count < PeLimits.MaxRuntimeFunctions; at += 8)
        {
            uint w = t.U32(at);
            long offset = ((long)(w << 1)) << 32 >> 33; // sign-extended prel31
            starts.Add((va + (ulong)at + (ulong)offset) & 0xFFFFFFFE);
        }
        var result = new List<(ulong, ulong?)>(starts.Count);
        for (int i = 0; i < starts.Count; i++)
            result.Add((starts[i], i + 1 < starts.Count && starts[i + 1] > starts[i] ? starts[i + 1] - starts[i] : null));
        return result;
    }

    /// <summary>DT_INIT, DT_FINI and the entries of the init, fini and preinit arrays, read through the relocated view.</summary>
    private List<ulong> Initializers(IssueLog log)
    {
        var d = dynamic.Value;
        var result = new List<ulong>();
        foreach (long tag in new long[] { 12, 13 })
            if (d.Tag(tag) is { } va and not 0) result.Add(va);
        int word = Is64Bit ? 8 : 4;
        Span<byte> buffer = stackalloc byte[8];
        foreach (var (arrayTag, sizeTag) in new (long, long)[] { (32, 33), (25, 27), (26, 28) })
        {
            if (d.Tag(arrayTag) is not { } va || d.Tag(sizeTag) is not { } size || !TryVaToRva(va, out uint rva)) continue;
            ulong count = Math.Min(size / (ulong)word, 1 << 16);
            for (ulong i = 0; i < count; i++)
            {
                if (Read(rva + (uint)(i * (ulong)word), buffer[..word]) != word) break;
                ulong value = word == 8
                    ? (BigEndian ? BinaryPrimitives.ReadUInt64BigEndian(buffer) : BinaryPrimitives.ReadUInt64LittleEndian(buffer))
                    : BigEndian ? BinaryPrimitives.ReadUInt32BigEndian(buffer) : BinaryPrimitives.ReadUInt32LittleEndian(buffer);
                if (value is 0 || value == (Is64Bit ? ulong.MaxValue : uint.MaxValue)) continue;
                if (!TryVaToRva(value & ~1UL, out _)) log.Add($"initializer 0x{value:X} lies outside the image");
                else result.Add(value);
            }
        }
        return result;
    }
}
