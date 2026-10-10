using System.Buffers.Binary;
using NetDecompilerMcp.Native.Elf;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.MachO;

/// <summary>An LC_DATA_IN_CODE entry (offset from the image base): data inside code. Kinds: 1 data, 2-4 jump tables, 5 absolute jump table.</summary>
public readonly record struct MachODataInCode(uint Rva, ushort Length, ushort Kind);

public sealed partial class MachOFile
{
    private sealed record UnwindInfo(List<DeclaredFunction> Functions, List<uint> FunctionStarts, List<MachODataInCode> DataInCode)
    {
        public static readonly UnwindInfo Empty = new([], [], []);
    }

    private ImageArea<UnwindInfo> unwindArea = null!;

    /// <summary>
    /// Function starts in code from LC_FUNCTION_STARTS, compact unwind (__unwind_info), __eh_frame, function symbols
    /// and the initializer lists (__mod_init_func, __init_offsets), one per address (the first source in that order
    /// wins), sorted. ARM Thumb bits are cleared.
    /// </summary>
    public IReadOnlyList<DeclaredFunction> DeclaredFunctions => unwindArea.Value.Functions;
    /// <summary>LC_FUNCTION_STARTS as RVAs, in table order.</summary>
    public IReadOnlyList<uint> FunctionStarts => unwindArea.Value.FunctionStarts;
    public IReadOnlyList<MachODataInCode> DataInCode => unwindArea.Value.DataInCode;

    private UnwindInfo ParseUnwind(IssueLog log)
    {
        var info = new UnwindInfo([], [], []);
        var found = new Dictionary<uint, DeclaredFunction>();
        void Add(ulong va, ulong? size, DeclaredSource source)
        {
            if (Arch == NativeArch.Arm) va &= ~1UL;
            if (!TryVaToRva(va, out uint rva) || SectionAt(rva) is not { IsExecutable: true } || found.Count >= PeLimits.MaxRuntimeFunctions) return;
            uint? sz = size is { } s and > 0 and <= uint.MaxValue ? (uint)s : null;
            if (found.TryGetValue(rva, out var existing))
            {
                if (existing.Size == null && sz != null) found[rva] = existing with { Size = sz };
                return;
            }
            found[rva] = new DeclaredFunction(rva, sz, source);
        }

        var budget = new WorkBudget(log);
        if (commands.OfType<MachOLinkEditCommand>().FirstOrDefault(c => c.Command == 0x26) is { } starts)
        {
            var w = FileWindow(starts.DataOffset, starts.DataSize);
            var r = new LebReader(w.Span(0, w.Length));
            ulong address = ImageBase;
            while (!r.AtEnd && budget.Step() && info.FunctionStarts.Count < PeLimits.MaxRuntimeFunctions)
            {
                ulong delta = r.Uleb();
                if (r.Failed || delta == 0) break;
                address += delta;
                if (TryVaToRva(Arch == NativeArch.Arm ? address & ~1UL : address, out uint rva)) info.FunctionStarts.Add(rva);
            }
            if (r.Failed) log.Add("LC_FUNCTION_STARTS ends inside a delta");
        }
        for (int i = 0; i < info.FunctionStarts.Count; i++)
        {
            uint start = info.FunctionStarts[i];
            Add(ImageBase + start, i + 1 < info.FunctionStarts.Count && info.FunctionStarts[i + 1] > start ? info.FunctionStarts[i + 1] - start : null, DeclaredSource.FunctionStarts);
        }
        foreach (var (start, size) in CompactUnwind(log, budget)) Add(ImageBase + start, size, DeclaredSource.Unwind);
        if (Section("__TEXT", "__eh_frame") is { } eh && !eh.IsZeroFill)
            foreach (var fde in EhFrame.Walk(FileWindow(eh.Offset, (long)Math.Min(eh.Size, int.MaxValue)), eh.Address, Is64Bit, log, PeLimits.MaxRuntimeFunctions))
                Add(fde.Start, fde.Range, DeclaredSource.Unwind);
        foreach (var s in SymbolTable)
            if (s.IsDefined && (s.Type & 0x0E) == 0x0E && s.Section > 0 && s.Section <= AllSections.Count && AllSections[s.Section - 1].HasInstructions)
                Add(s.Value, null, DeclaredSource.Symbol);
        foreach (var va in Initializers(log)) Add(va, null, DeclaredSource.Initializer);
        info.Functions.AddRange(found.Values);
        info.Functions.Sort((a, b) => a.Rva.CompareTo(b.Rva));

        if (commands.OfType<MachOLinkEditCommand>().FirstOrDefault(c => c.Command == 0x29) is { } dic)
        {
            var w = FileWindow(dic.DataOffset, dic.DataSize);
            for (long at = 0; at + 8 <= w.Length && info.DataInCode.Count < PeLimits.MaxRuntimeFunctions; at += 8)
                if (w.U32(at) < SizeOfImage) info.DataInCode.Add(new MachODataInCode(w.U32(at), w.U16(at + 4), w.U16(at + 6)));
                else log.Add($"data-in-code entry at +0x{w.U32(at):X} lies outside the image");
        }
        return info;
    }

    /// <summary>
    /// __TEXT,__unwind_info: the first-level index and its regular or compressed second-level pages. Entries with
    /// encoding 0 (no unwind information) are not function starts. Sizes run to the next entry.
    /// </summary>
    private List<(uint Start, uint? Size)> CompactUnwind(IssueLog log, WorkBudget budget)
    {
        var result = new List<(uint, uint?)>();
        if (Section("__TEXT", "__unwind_info") is not { } section || section.IsZeroFill) return result;
        var u = FileWindow(section.Offset, (long)Math.Min(section.Size, int.MaxValue));
        if (u.Length < 28 || u.U32(0) != 1)
        {
            log.Add($"__unwind_info version {u.U32(0)} is not 1");
            return result;
        }
        uint commonAt = u.U32(4), commonCount = u.U32(8), indexAt = u.U32(20), indexCount = u.U32(24);
        var entries = new List<(uint Start, uint Encoding)>();
        for (uint i = 0; i + 1 < indexCount && budget.Step(); i++)
        {
            long e = indexAt + 12L * i;
            if (!u.Has(e, 24))
            {
                log.Add($"__unwind_info index ends after {i} of {indexCount} entries");
                break;
            }
            uint first = u.U32(e), page = u.U32(e + 4);
            if (page == 0) continue;
            uint kind = u.U32(page);
            if (kind == 2)
            {
                uint entriesAt = page + u.U16(page + 4), count = u.U16(page + 6);
                for (uint k = 0; k < count && u.Has(entriesAt + 8L * k, 8); k++)
                    entries.Add((u.U32(entriesAt + 8L * k), u.U32(entriesAt + 8L * k + 4)));
            }
            else if (kind == 3)
            {
                uint entriesAt = page + u.U16(page + 4), count = u.U16(page + 6), encodingsAt = page + u.U16(page + 8), encodingsCount = u.U16(page + 10);
                for (uint k = 0; k < count && u.Has(entriesAt + 4L * k, 4); k++)
                {
                    uint word = u.U32(entriesAt + 4L * k), index = word >> 24;
                    uint encoding = index < commonCount ? u.U32(commonAt + 4L * index)
                        : index - commonCount < encodingsCount ? u.U32(encodingsAt + 4L * (index - commonCount)) : 0;
                    entries.Add((first + (word & 0xFFFFFF), encoding));
                }
            }
            else log.Add($"__unwind_info second-level page at +0x{page:X} has kind {kind}");
        }
        uint end = indexCount > 0 ? u.U32(indexAt + 12L * (indexCount - 1)) : 0;
        for (int i = 0; i < entries.Count; i++)
        {
            if (entries[i].Encoding == 0) continue;
            uint next = i + 1 < entries.Count ? entries[i + 1].Start : end;
            result.Add((entries[i].Start, next > entries[i].Start ? next - entries[i].Start : null));
        }
        return result;
    }

    /// <summary>Initializer and terminator pointers (__mod_init_func, __mod_term_func) and __init_offsets entries.</summary>
    private List<ulong> Initializers(IssueLog log)
    {
        var result = new List<ulong>();
        int pointer = Is64Bit ? 8 : 4;
        Span<byte> buffer = stackalloc byte[8];
        foreach (var s in AllSections)
        {
            if (!TryVaToRva(s.Address, out uint rva)) continue;
            if (s.Type is 0x9 or 0xA)
            {
                for (ulong i = 0; i < Math.Min(s.Size / (ulong)pointer, 1 << 16); i++)
                {
                    if (Read(rva + (uint)(i * (ulong)pointer), buffer[..pointer]) != pointer) break;
                    ulong value = pointer == 8 ? Load64(buffer) : Load32(buffer);
                    if (value != 0) result.Add(value);
                }
            }
            else if (s.Type == 0x16)
            {
                for (ulong i = 0; i < Math.Min(s.Size / 4, 1 << 16); i++)
                {
                    if (ReadRaw(rva + (uint)(i * 4), buffer[..4]) != 4) break;
                    result.Add(ImageBase + (BigEndian ? BinaryPrimitives.ReadUInt32BigEndian(buffer) : BinaryPrimitives.ReadUInt32LittleEndian(buffer)));
                }
            }
        }
        foreach (var va in result.Where(v => !TryVaToRva(v & ~1UL, out _)).Take(10)) log.Add($"initializer 0x{va:X} lies outside the image");
        return result;
    }
}
