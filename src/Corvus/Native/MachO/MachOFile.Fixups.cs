using System.Buffers.Binary;
using System.IO.Compression;
using Corvus.Native.Pe;

namespace Corvus.Native.MachO;

public sealed partial class MachOFile
{
    private const int MaxFixups = 1 << 23;
    private const int MaxImports = 1 << 20;
    private const int MaxSymbolPool = 64 << 20;

    private sealed record FixupInfo(MachOFixups Fixups, FixupOverlay Overlay, List<NativeImport> Imports, List<uint> Rvas)
    {
        public static readonly FixupInfo Empty = new(MachOFixups.Empty, FixupOverlay.Empty, [], []);
    }

    private ImageArea<FixupInfo> fixupArea = null!;

    /// <summary>What each fixed-up pointer slot holds (rebase target or bound symbol).</summary>
    public MachOFixups Fixups => fixupArea.Value.Fixups;
    /// <summary>Bound slots (non-weak binds), plus undefined symbols of pointer sections the bind information does not cover.</summary>
    public IReadOnlyList<NativeImport> Imports => fixupArea.Value.Imports;
    /// <summary>Locations of every rebased pointer, sorted.</summary>
    public IReadOnlyList<uint> RelocationRvas => fixupArea.Value.Rvas;

    private FixupInfo ParseFixups(IssueLog log)
    {
        var list = new List<MachOFixup>();
        var weak = new List<MachOFixup.Bind>();
        var overlay = new List<(uint, ulong, byte)>();
        string source = "none";
        ushort? format = null;
        var budget = new WorkBudget(log);
        if (commands.OfType<MachOLinkEditCommand>().FirstOrDefault(c => c.Command == 0x80000034) is { } chained)
        {
            source = "chained fixups";
            format = WalkChains(FileWindow(chained.DataOffset, chained.DataSize), list, overlay, log, budget);
        }
        else if (commands.OfType<MachODyldInfoCommand>().FirstOrDefault() is { } info)
        {
            source = "dyld info";
            var dylibs = Dependencies;
            RunRebase(FileWindow(info.RebaseOffset, info.RebaseSize), list, log, budget);
            bool threaded = RunBind(FileWindow(info.BindOffset, info.BindSize), "bind", false, list, overlay, dylibs, log, budget);
            if (threaded) source = "threaded";
            var weakList = new List<MachOFixup>();
            RunBind(FileWindow(info.WeakBindOffset, info.WeakBindSize), "weak bind", false, weakList, null, dylibs, log, budget);
            weak.AddRange(weakList.OfType<MachOFixup.Bind>().Select(b => b with { Weak = true }));
            RunBind(FileWindow(info.LazyBindOffset, info.LazyBindSize), "lazy bind", true, list, overlay, dylibs, log, budget);
        }

        var imports = new List<NativeImport>();
        var rvas = new List<uint>();
        var slots = new HashSet<uint>();
        int width = Is64Bit ? 8 : 4;
        foreach (var f in list)
        {
            if (!TryVaToRva(f.Location, out uint rva)) continue;
            switch (f)
            {
                case MachOFixup.Rebase:
                    rvas.Add(rva);
                    break;
                case MachOFixup.Bind b:
                    if (source == "dyld info") overlay.Add((rva, 0, (byte)width)); // chains wrote their own
                    if (slots.Add(rva)) imports.Add(new NativeImport(b.Dylib ?? $"ordinal {b.Ordinal}", b.Symbol, null, 0, rva, b.Lazy));
                    break;
            }
        }
        foreach (var slot in symbolArea.Value.SlotImports)
            if (slots.Add(slot.SlotRva)) imports.Add(slot);
        rvas.Sort();
        return new FixupInfo(new MachOFixups(list, weak, source, format), new FixupOverlay(overlay, BigEndian), imports, [.. rvas.Distinct()]);
    }

    /// <summary>
    /// Follows every chain of LC_DYLD_CHAINED_FIXUPS from its page starts (including DYLD_CHAINED_PTR_START_MULTI
    /// lists). Returns the pointer format of the first segment with fixups.
    /// </summary>
    private ushort? WalkChains(ByteView blob, List<MachOFixup> list, List<(uint, ulong, byte)> overlay, IssueLog log, WorkBudget budget)
    {
        if (blob.Length < 28)
        {
            log.Add("LC_DYLD_CHAINED_FIXUPS data is truncated");
            return null;
        }
        uint version = blob.U32(0), startsOffset = blob.U32(4), importsOffset = blob.U32(8), symbolsOffset = blob.U32(12);
        uint importsCount = blob.U32(16), importsFormat = blob.U32(20), symbolsFormat = blob.U32(24);
        if (version != 0) log.Add($"chained fixups version {version} is not 0; read as version 0");
        var imports = ReadChainedImports(blob, importsOffset, symbolsOffset, importsCount, importsFormat, symbolsFormat, log);

        ushort? firstFormat = null;
        uint segCount = blob.U32(startsOffset);
        if (segCount > segments.Count) log.Add($"chained starts list {segCount} segments; the image has {segments.Count}");
        Span<byte> raw = stackalloc byte[8];
        for (uint i = 0; i < Math.Min(segCount, (uint)segments.Count); i++)
        {
            uint infoOffset = blob.U32(startsOffset + 4 + i * 4L);
            if (infoOffset == 0) continue;
            long at = startsOffset + (long)infoOffset;
            uint size = blob.U32(at);
            ushort pageSize = blob.U16(at + 4), format = blob.U16(at + 6);
            ulong segmentOffset = blob.U64(at + 8);
            uint maxValid = blob.U32(at + 16);
            ushort pageCount = blob.U16(at + 20);
            if (!ChainedPointer.IsKnown(format) || pageSize == 0 || !blob.Has(at, 22 + 2L * pageCount))
            {
                log.Add($"chained starts for segment {segments[(int)i].SegmentName}: pointer format {format}, page size {pageSize}, {pageCount} pages; not read");
                continue;
            }
            firstFormat ??= format;
            int stride = ChainedPointer.Stride(format), width = ChainedPointer.Width(format);
            for (int page = 0; page < pageCount; page++)
            {
                ushort start = blob.U16(at + 22 + 2L * page);
                if (start == 0xFFFF) continue; // DYLD_CHAINED_PTR_START_NONE
                var chainStarts = new List<ushort>();
                if ((start & 0x8000) != 0)
                {
                    // DYLD_CHAINED_PTR_START_MULTI: an overflow list after the page starts, ended by DYLD_CHAINED_PTR_START_LAST.
                    for (long k = start & 0x7FFF; k < (size - 22) / 2 && chainStarts.Count < pageSize / 4 + 1; k++)
                    {
                        ushort s = blob.U16(at + 22 + 2 * k);
                        chainStarts.Add((ushort)(s & 0x7FFF));
                        if ((s & 0x8000) != 0) break;
                    }
                }
                else chainStarts.Add(start);
                foreach (var chainStart in chainStarts)
                {
                    ulong location = ImageBase + segmentOffset + (ulong)page * pageSize + chainStart;
                    for (int steps = 0; steps <= pageSize / stride + 1; steps++)
                    {
                        if (!budget.Step() || list.Count >= MaxFixups) return firstFormat;
                        if (!TryVaToRva(location, out uint rva) || ReadRaw(rva, raw[..width]) != width)
                        {
                            log.Add($"chained fixup at 0x{location:X} is outside the mapped image");
                            break;
                        }
                        ulong value = width == 8 ? Load64(raw) : Load32(raw);
                        var e = ChainedPointer.Decode(format, value, ImageBase, maxValid);
                        if (e.IsBind)
                        {
                            if (e.Ordinal < imports.Count)
                            {
                                var imp = imports[(int)e.Ordinal];
                                list.Add(new MachOFixup.Bind(location, imp.Ordinal, imp.Dylib, imp.Name, imp.Addend + e.Addend, imp.Weak, false, e.Authenticated));
                            }
                            else log.Add($"chained bind at 0x{location:X} names import {e.Ordinal} of {imports.Count}");
                            overlay.Add((rva, 0, (byte)width));
                        }
                        else
                        {
                            if (e.IsPointer) list.Add(new MachOFixup.Rebase(location, e.Target, e.Authenticated));
                            overlay.Add((rva, width == 8 ? e.Target : e.Target & 0xFFFFFFFF, (byte)width));
                        }
                        if (e.Next == 0) break;
                        location += e.Next * (ulong)stride;
                    }
                }
            }
        }
        return firstFormat;
    }

    private ulong Load64(ReadOnlySpan<byte> b) => BigEndian ? BinaryPrimitives.ReadUInt64BigEndian(b) : BinaryPrimitives.ReadUInt64LittleEndian(b);
    private uint Load32(ReadOnlySpan<byte> b) => BigEndian ? BinaryPrimitives.ReadUInt32BigEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);

    private readonly record struct ChainedImport(int Ordinal, string? Dylib, string Name, long Addend, bool Weak);

    private List<ChainedImport> ReadChainedImports(ByteView blob, uint importsOffset, uint symbolsOffset, uint count, uint format, uint symbolsFormat, IssueLog log)
    {
        var result = new List<ChainedImport>();
        if (count == 0) return result;
        if (format is not (1 or 2 or 3))
        {
            log.Add($"chained imports format {format} is unknown; binds are not named");
            return result;
        }
        var pool = blob.Slice(symbolsOffset, blob.Length - symbolsOffset);
        if (symbolsFormat == 1)
        {
            try
            {
                using var input = new MemoryStream(pool.Span(0, pool.Length).ToArray());
                using var z = new ZLibStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();
                var buffer = new byte[81920];
                int n;
                while ((n = z.Read(buffer)) > 0)
                {
                    output.Write(buffer, 0, n);
                    if (output.Length > MaxSymbolPool) throw new InvalidDataException($"more than {MaxSymbolPool} bytes");
                }
                pool = new ByteView(output.ToArray(), BigEndian);
            }
            catch (InvalidDataException ex)
            {
                log.Add($"the compressed import names do not decompress: {ex.Message}");
                pool = new ByteView([], BigEndian);
            }
        }
        else if (symbolsFormat != 0) log.Add($"chained symbols format {symbolsFormat} is unknown");
        var dylibs = Dependencies;
        int entry = format switch { 1 => 4, 2 => 8, _ => 16 };
        for (uint i = 0; i < Math.Min(count, MaxImports); i++)
        {
            long at = importsOffset + (long)i * entry;
            if (!blob.Has(at, entry))
            {
                log.Add($"chained imports end after {i} of {count}");
                break;
            }
            int ordinal;
            bool weakImport;
            uint nameOffset;
            long addend = 0;
            if (format == 3)
            {
                ulong v = blob.U64(at);
                ordinal = (short)(ushort)(v & 0xFFFF);
                weakImport = ((v >> 16) & 1) != 0;
                nameOffset = (uint)(v >> 32);
                addend = (long)blob.U64(at + 8);
            }
            else
            {
                uint v = blob.U32(at);
                ordinal = (sbyte)(byte)(v & 0xFF); // 0xFF, 0xFE, 0xFD: the special negative ordinals
                weakImport = ((v >> 8) & 1) != 0;
                nameOffset = v >> 9;
                if (format == 2) addend = (int)blob.U32(at + 4);
            }
            string name = pool.CString(nameOffset, MaxNameLength) ?? $"<name 0x{nameOffset:X}>";
            result.Add(new ChainedImport(ordinal, MachONames.Library(ordinal, dylibs), name, addend, weakImport));
        }
        return result;
    }

    /// <summary>Rebase opcodes: each location keeps the link-time address the file holds (no slide).</summary>
    private void RunRebase(ByteView stream, List<MachOFixup> list, IssueLog log, WorkBudget budget)
    {
        if (stream.Length == 0) return;
        var r = new LebReader(stream.Span(0, stream.Length));
        int pointer = Is64Bit ? 8 : 4;
        int seg = -1;
        ulong offset = 0;
        var raw = new byte[8];
        void Rebase()
        {
            if (seg < 0 || seg >= segments.Count) return;
            ulong location = segments[seg].VmAddress + offset;
            ulong value = 0;
            if (TryVaToRva(location, out uint rva) && ReadRaw(rva, raw.AsSpan(0, pointer)) == pointer) value = pointer == 8 ? Load64(raw) : Load32(raw);
            if (list.Count < MaxFixups) list.Add(new MachOFixup.Rebase(location, value));
        }
        while (!r.AtEnd && !r.Failed && budget.Step())
        {
            byte b = r.Byte();
            int imm = b & 0x0F;
            switch (b & 0xF0)
            {
                case 0x00: return;
                case 0x10: break;
                case 0x20: seg = imm; offset = r.Uleb(); break;
                case 0x30: offset += r.Uleb(); break;
                case 0x40: offset += (ulong)(imm * pointer); break;
                case 0x50: for (int i = 0; i < imm; i++) { Rebase(); offset += (ulong)pointer; } break;
                case 0x60:
                {
                    ulong count = r.Uleb();
                    for (ulong i = 0; i < count && budget.Step(); i++) { Rebase(); offset += (ulong)pointer; }
                    break;
                }
                case 0x70: Rebase(); offset += r.Uleb() + (ulong)pointer; break;
                case 0x80:
                {
                    ulong count = r.Uleb(), skip = r.Uleb();
                    for (ulong i = 0; i < count && budget.Step(); i++) { Rebase(); offset += skip + (ulong)pointer; }
                    break;
                }
                default:
                    log.Add($"rebase opcode 0x{b:X2} at +0x{r.Position - 1:X} is unknown; the rest is not read");
                    return;
            }
        }
        if (r.Failed) log.Add("the rebase opcodes end inside an operand");
    }

    /// <summary>
    /// Bind, weak-bind and lazy-bind opcodes. With BIND_OPCODE_THREADED the binds form an ordinal table and
    /// THREADED_APPLY walks arm64e-style chains (rebases and binds). Returns whether the stream was threaded.
    /// </summary>
    private bool RunBind(ByteView stream, string what, bool lazy, List<MachOFixup> list, List<(uint, ulong, byte)>? overlay, IReadOnlyList<string> dylibs,
        IssueLog log, WorkBudget budget)
    {
        if (stream.Length == 0) return false;
        var r = new LebReader(stream.Span(0, stream.Length));
        int pointer = Is64Bit ? 8 : 4;
        int seg = -1, ordinal = 0;
        ulong offset = 0;
        long addend = 0;
        string? symbol = null;
        bool weakImport = false, threaded = false;
        var table = new List<MachOFixup.Bind>();
        Span<byte> raw = stackalloc byte[8];
        void Bind()
        {
            if (symbol == null) return;
            if (threaded)
            {
                table.Add(new MachOFixup.Bind(0, ordinal, MachONames.Library(ordinal, dylibs), symbol, addend, weakImport));
                return;
            }
            if (seg < 0 || seg >= segments.Count || list.Count >= MaxFixups) return;
            list.Add(new MachOFixup.Bind(segments[seg].VmAddress + offset, ordinal, MachONames.Library(ordinal, dylibs), symbol, addend, weakImport, lazy));
        }
        while (!r.AtEnd && !r.Failed && budget.Step())
        {
            byte b = r.Byte();
            int imm = b & 0x0F;
            switch (b & 0xF0)
            {
                case 0x00:
                    if (!lazy) return threaded;
                    break; // lazy binds end each entry with DONE
                case 0x10: ordinal = imm; break;
                case 0x20: ordinal = (int)Math.Min(r.Uleb(), int.MaxValue); break;
                case 0x30: ordinal = imm == 0 ? 0 : (sbyte)(0xF0 | imm); break;
                case 0x40: symbol = r.CString(); weakImport = (imm & 1) != 0; break;
                case 0x50: break;
                case 0x60: addend = r.Sleb(); break;
                case 0x70: seg = imm; offset = r.Uleb(); break;
                case 0x80: offset += r.Uleb(); break;
                case 0x90: Bind(); offset += (ulong)pointer; break;
                case 0xA0: Bind(); offset += r.Uleb() + (ulong)pointer; break;
                case 0xB0: Bind(); offset += (ulong)(imm * pointer + pointer); break;
                case 0xC0:
                {
                    ulong count = r.Uleb(), skip = r.Uleb();
                    for (ulong i = 0; i < count && budget.Step(); i++) { Bind(); offset += skip + (ulong)pointer; }
                    break;
                }
                case 0xD0 when imm == 0:
                    threaded = true;
                    table.Clear();
                    r.Uleb();
                    break;
                case 0xD0 when imm == 1:
                    if (seg >= 0 && seg < segments.Count) ApplyThreaded(segments[seg].VmAddress + offset, table, list, overlay, log, budget, raw);
                    break;
                default:
                    log.Add($"{what} opcode 0x{b:X2} at +0x{r.Position - 1:X} is unknown; the rest is not read");
                    return threaded;
            }
        }
        if (r.Failed) log.Add($"the {what} opcodes end inside an operand");
        return threaded;
    }

    /// <summary>A threaded chain: arm64e pointer layout, binds indexing the ordinal table, stride 8.</summary>
    private void ApplyThreaded(ulong location, List<MachOFixup.Bind> table, List<MachOFixup> list, List<(uint, ulong, byte)>? overlay, IssueLog log, WorkBudget budget, Span<byte> raw)
    {
        for (int steps = 0; steps < 1 << 20 && budget.Step() && list.Count < MaxFixups; steps++)
        {
            if (!TryVaToRva(location, out uint rva) || ReadRaw(rva, raw[..8]) != 8)
            {
                log.Add($"threaded fixup at 0x{location:X} is outside the mapped image");
                return;
            }
            var e = ChainedPointer.Decode(1, Load64(raw), ImageBase, 0);
            if (e.IsBind)
            {
                if (e.Ordinal < table.Count) list.Add(table[(int)e.Ordinal] with { Location = location, Addend = table[(int)e.Ordinal].Addend + e.Addend, Authenticated = e.Authenticated });
                else log.Add($"threaded bind at 0x{location:X} names entry {e.Ordinal} of {table.Count}");
                overlay?.Add((rva, 0, 8));
            }
            else
            {
                list.Add(new MachOFixup.Rebase(location, e.Target, e.Authenticated));
                overlay?.Add((rva, e.Target, 8));
            }
            if (e.Next == 0) return;
            location += e.Next * 8UL;
        }
    }
}
