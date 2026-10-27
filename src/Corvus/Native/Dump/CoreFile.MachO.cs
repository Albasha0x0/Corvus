using System.Buffers.Binary;
using System.Text.Json;
using Corvus.Native.MachO;

namespace Corvus.Native.Dump;

/// <summary>A Mach-O core (MH_CORE): segments as memory, LC_THREAD registers, images from lldb's note or dyld_all_image_infos.</summary>
public sealed partial class CoreFile
{
    private const uint MhMagic64 = 0xFEEDFACF, MhCore = 4, MhExecute = 2, MhDylibInCache = 0x80000000;
    private const uint CpuArm64 = 0x0100000C, CpuX64 = 0x01000007;
    private const int MaxMachCommandBytes = 16 << 20;
    private const int MaxMachImages = 1 << 14;
    private const int MaxImageHeaderBytes = 0x8000;
    private const long MaxImageInfoScan = 256L << 20;
    /// <summary>Largest extent given to an image whose header the core does not hold.</summary>
    private const ulong MaxEstimatedExtent = 64 << 20;
    /// <summary>dyld_all_image_infos (64-bit) through dyldAllImageInfosAddress, the field that holds the structure's own address.</summary>
    private const int ImageInfosSize = 112, ImageInfosSelf = 104;

    // ARM_THREAD_STATE64 holds x0-x28, fp, lr, sp and pc as 64-bit words, then cpsr.
    private static readonly int[] ArmStateMap = [.. Enumerable.Range(0, 33)];
    // x86_THREAD_STATE64 holds rax, rbx, rcx, rdx, rdi, rsi, rbp, rsp, r8-r15, rip, rflags, cs, fs and gs.
    private static readonly int[] X64StateMap = [0, 3, 2, 1, 5, 4, 6, 7, .. Enumerable.Range(8, 8), 16, 17, -1, -1, -1];

    private sealed record MachImage(ulong Base, string Path, string? Uuid, IReadOnlyList<ulong> Segments);

    private CoreModule? _machMain;

    public bool IsMachO { get; private set; }

    /// <summary>Where a Mach-O core's modules came from (lldb's image list note or dyld_all_image_infos); null for an ELF core.</summary>
    public string? ImageList { get; private set; }

    public static bool IsMachOCore(ReadOnlySpan<byte> head) =>
        head.Length >= 16 && BinaryPrimitives.ReadUInt32LittleEndian(head) == MhMagic64 && BinaryPrimitives.ReadUInt32LittleEndian(head[12..]) == MhCore;

    private void ReadMachO(ByteView h)
    {
        IsMachO = true;
        Is64Bit = true;
        uint cpu = h.U32(4);
        Arch = MachONames.Arch(cpu);
        (Machine, Registers) = cpu switch { CpuArm64 => ((ushort)183, CoreArch.Arm64), CpuX64 => ((ushort)62, CoreArch.X64), _ => ((ushort)0, (CoreArch?)null) };
        if (Registers == null) Issue("header", $"registers of {MachONames.CpuName(cpu, h.U32(8))} are not read");
        uint ncmds = h.U32(16), size = h.U32(20);
        var cmds = new ByteView(Block(32, (int)Math.Min(size, MaxMachCommandBytes)), false);
        if (cmds.Length < size) Issue("load commands", $"the load commands are read for 0x{cmds.Length:X} of 0x{size:X} bytes", 32);
        var ranges = new List<DumpMemoryRange>();
        var notes = new Dictionary<string, (ulong Offset, ulong Size)>(StringComparer.Ordinal);
        long at = 0;
        for (uint i = 0; i < ncmds && at + 8 <= cmds.Length; i++)
        {
            uint cmd = cmds.U32(at), cmdsize = cmds.U32(at + 4);
            if (cmdsize < 8 || !cmds.Has(at, cmdsize))
            {
                Issue("load commands", $"load command {i} at 0x{32 + at:X} declares {cmdsize} bytes", 32 + at);
                break;
            }
            var c = cmds.Slice(at, cmdsize);
            if (cmd == 0x19 && cmdsize >= 72)
            {
                // VM_PROT_READ, WRITE and EXECUTE (1, 2, 4) become PF_R, PF_W and PF_X (4, 2, 1).
                uint prot = c.U32(60);
                AddSegment("LC_SEGMENT_64", c.U64(24), c.U64(32), c.U64(48), c.U64(40), ((prot & 1) << 2) | (prot & 2) | ((prot & 4) >> 2), ranges);
            }
            else if (cmd == 0x4) MachThread(c, 32 + at);
            else if (cmd == 0x31 && cmdsize >= 40 && c.CString(8, 16) is { } owner) notes.TryAdd(owner, (c.U64(24), c.U64(32)));
            at += cmdsize;
        }
        SetMemory(ranges);
        if (_threads.Count == 0) Issue("load commands", "no LC_THREAD: the core has no threads");
        if (notes.TryGetValue("process metadata", out var meta)) ThreadIds(meta.Offset, meta.Size);
        var images = notes.TryGetValue("all image infos", out var infos) ? NoteImages(infos.Offset) : null;
        if (images != null) ImageList = "lldb's all image infos note";
        else if ((images = DyldImages()) != null) ImageList = "dyld_all_image_infos";
        else Issue("modules", "no image list note and no dyld_all_image_infos in memory");
        if (images != null) MachModules(images);
        AddModulesAndRegions();
    }

    /// <summary>LC_THREAD: flavor, count (32-bit words) and state, repeated; the general registers of the core's CPU are kept.</summary>
    private void MachThread(ByteView c, long fileOffset)
    {
        CoreRegisters? regs = null;
        for (long p = 8; p + 8 <= c.Length;)
        {
            uint flavor = c.U32(p), count = c.U32(p + 4);
            long bytes = count * 4L;
            if (!c.Has(p + 8, bytes))
            {
                Issue("threads", $"LC_THREAD at 0x{fileOffset:X}: flavor {flavor} declares {count} words past the command", fileOffset);
                break;
            }
            var state = c.Slice(p + 8, bytes);
            if (Registers == CoreArch.Arm64 && flavor == 6)
            {
                regs = MachState(state, ArmStateMap);
                if (state.Has(264, 4)) regs.Set(33, state.U32(264));
                regs.Complete = state.Length >= 268;
            }
            else if (Registers == CoreArch.X64 && flavor == 4) regs = MachState(state, X64StateMap);
            // x86_THREAD_STATE puts an x86_state_hdr (flavor, count) before the state it names.
            else if (Registers == CoreArch.X64 && flavor == 7 && state.Length >= 8 && state.U32(0) == 4) regs = MachState(state.Slice(8, state.Length - 8), X64StateMap);
            p += 8 + bytes;
        }
        _threads.Add(new CoreThread(_threads.Count, (uint)_threads.Count, 0, regs));
    }

    private CoreRegisters MachState(ByteView state, int[] map)
    {
        var r = new CoreRegisters(Registers!) { Complete = state.Length >= map.Length * 8L };
        for (int i = 0; i < map.Length; i++)
            if (map[i] >= 0 && state.Has(i * 8L, 8)) r.Set(map[i], state.U64(i * 8L));
        return r;
    }

    /// <summary>lldb's process metadata note: {"threads":[{"thread_id":...}]}, in LC_THREAD order.</summary>
    private void ThreadIds(ulong offset, ulong size)
    {
        if (offset >= (ulong)FileSize || size > 1 << 20) return;
        var bytes = Block((long)offset, (int)size);
        int end = Array.IndexOf(bytes, (byte)0);
        try
        {
            using var doc = JsonDocument.Parse(bytes.AsMemory(0, end < 0 ? bytes.Length : end));
            if (doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("threads", out var threads) || threads.ValueKind != JsonValueKind.Array) return;
            int i = 0;
            foreach (var t in threads.EnumerateArray())
            {
                if (i >= _threads.Count) break;
                if (t.ValueKind == JsonValueKind.Object && t.TryGetProperty("thread_id", out var id) && id.TryGetUInt64(out ulong v) && v <= uint.MaxValue)
                    _threads[i] = _threads[i] with { Id = (uint)v };
                i++;
            }
        }
        catch (JsonException) { Issue("threads", "the process metadata note is not JSON", (long)offset); }
    }

    /// <summary>Images from lldb's all image infos note; null when the note is unreadable.</summary>
    private List<MachImage>? NoteImages(ulong offset)
    {
        var h = new ByteView(offset < (ulong)FileSize ? Block((long)offset, 24) : [], false);
        ulong entries = h.U64(8);
        uint entrySize = h.U32(16);
        if (h.Length < 24 || entrySize < 48 || entries >= (ulong)FileSize)
        {
            Issue("modules", $"the all image infos note at 0x{offset:X} is not readable");
            return null;
        }
        uint count = Math.Min(h.U32(4), MaxMachImages);
        var t = new ByteView(Block((long)entries, (int)Math.Min((long)count * entrySize, int.MaxValue / 2)), false);
        var list = new List<MachImage>();
        for (long at = 0; at + 48 <= t.Length; at += entrySize)
        {
            ulong pathAt = t.U64(at), load = t.U64(at + 24), segmentsAt = t.U64(at + 32);
            if (load == ulong.MaxValue) continue;
            string path = pathAt < (ulong)FileSize ? new ByteView(Block((long)pathAt, 1024), false).CString(0, 1024) ?? "" : "";
            // A segment_vmaddr is segname[16], vmaddr and an unused word.
            var segments = new ByteView(segmentsAt < (ulong)FileSize ? Block((long)segmentsAt, (int)Math.Min(t.U32(at + 40), 256u) * 32) : [], false);
            var addresses = new List<ulong>();
            for (long s = 0; s + 32 <= segments.Length; s += 32) addresses.Add(segments.U64(s + 16));
            var uuid = t.Span(at + 8, 16);
            list.Add(new MachImage(load, path, uuid.ContainsAnyExcept((byte)0) ? Convert.ToHexStringLower(uuid) : null, addresses));
        }
        return list;
    }

    /// <summary>The images dyld_all_image_infos lists (infoArray, with UUIDs from uuidArray), and dyld itself.</summary>
    private List<MachImage>? DyldImages()
    {
        if (FindAllImageInfos() is not { } address) return null;
        var head = new byte[ImageInfosSize];
        ReadMemory(address, head);
        var v = new ByteView(head, false);
        uint count = Math.Min(v.U32(4), MaxMachImages);
        ulong array = v.U64(8);
        var uuids = new Dictionary<ulong, string>();
        // A dyld_uuid_info is imageLoadAddress, then imageUUID.
        var u = new byte[(int)Math.Min(v.U64(88), MaxMachImages) * 24];
        int un = ReadMemory(v.U64(96), u);
        for (int at = 0; at + 24 <= un; at += 24) uuids.TryAdd(BinaryPrimitives.ReadUInt64LittleEndian(u.AsSpan(at)), Convert.ToHexStringLower(u.AsSpan(at + 8, 16)));
        if (array == 0 && count > 0) Issue("modules", "dyld_all_image_infos has no image array: dyld was updating it");
        // A dyld_image_info is imageLoadAddress, imageFilePath, then imageFileModDate.
        var e = new byte[array == 0 ? 0 : (int)count * 24];
        int n = ReadMemory(array, e);
        if (n < e.Length) Issue("modules", $"dyld_all_image_infos lists {count} images; the core holds {n / 24} of them");
        var list = new List<MachImage>();
        for (int at = 0; at + 24 <= n; at += 24)
        {
            ulong load = BinaryPrimitives.ReadUInt64LittleEndian(e.AsSpan(at));
            list.Add(new MachImage(load, ReadString(BinaryPrimitives.ReadUInt64LittleEndian(e.AsSpan(at + 8)), 1024) ?? "", uuids.GetValueOrDefault(load), []));
        }
        if (v.U64(32) is var dyld and not 0 && list.All(i => i.Base != dyld)) list.Add(new MachImage(dyld, "/usr/lib/dyld", uuids.GetValueOrDefault(dyld), []));
        return list;
    }

    /// <summary>dyld_all_image_infos in the core's writable memory: an 8-aligned version 1-30 whose dyldAllImageInfosAddress is its own address.</summary>
    private ulong? FindAllImageInfos()
    {
        const int Chunk = 1 << 20;
        long budget = MaxImageInfoScan;
        var buffer = new byte[Chunk + ImageInfosSize];
        foreach (var s in _segments.Where(s => (s.Flags & 2) != 0 && s.FileSize > 0))
        {
            ulong end = s.Start + s.FileSize;
            for (ulong start = s.Start; start < end && budget > 0; start += Chunk)
            {
                int n = ReadMemory(start, buffer.AsSpan(0, (int)Math.Min((ulong)buffer.Length, end - start)));
                budget -= Math.Min(n, Chunk);
                var v = new ByteView(buffer, 0, n, false);
                for (long at = 0; at + ImageInfosSize <= n && at < Chunk; at += 8)
                    if (v.U64(at + ImageInfosSelf) == start + (ulong)at && v.U32(at) is >= 1 and <= 30) return start + (ulong)at;
            }
        }
        return null;
    }

    /// <summary>Adds each image as a module; without a header in the core, the extent ends at the next segment or image.</summary>
    private void MachModules(List<MachImage> images)
    {
        var bases = images.Select(i => i.Base).Where(b => b != 0).Distinct().Order().ToArray();
        CoreModule? executable = null, first = null;
        foreach (var image in images.Where(i => i.Base != 0).DistinctBy(i => i.Base))
        {
            var header = MachHeader(image.Base);
            ulong size;
            if (header is { } known) size = known.Size;
            else
            {
                int k = Array.BinarySearch(bases, image.Base);
                ulong next = k + 1 < bases.Length ? bases[k + 1] : ulong.MaxValue;
                foreach (var s in image.Segments) if (s > image.Base && s < next) next = s;
                size = Math.Min(next - image.Base, MaxEstimatedExtent);
            }
            size = Math.Min(size, uint.MaxValue);
            var mapping = new CoreMapping(image.Base, image.Base + size, 0, image.Path);
            _files.Add(mapping);
            var module = new CoreModule(new DumpModule(image.Base, (uint)size, 0, 0, image.Path, null, null, null), header?.Uuid ?? image.Uuid, [mapping]);
            _coreModules.Add(module);
            first ??= module;
            if (header?.FileType == MhExecute) executable ??= module;
        }
        _machMain = executable ?? first;
    }

    /// <summary>Extent, LC_UUID and file type of the Mach-O header at <paramref name="address"/>; null when the core lacks it.</summary>
    private (ulong Size, string? Uuid, uint FileType)? MachHeader(ulong address)
    {
        var bytes = new byte[MaxImageHeaderBytes];
        int n = ReadMemory(address, bytes);
        var h = new ByteView(bytes, 0, n, false);
        if (n < 32 || h.U32(0) != MhMagic64) return null;
        uint ncmds = h.U32(16), flags = h.U32(24);
        string? uuid = null;
        ulong textVm = 0, textSize = 0, high = 0;
        long at = 32;
        for (uint i = 0; i < ncmds && h.Has(at, 8); i++)
        {
            uint cmd = h.U32(at), cmdsize = h.U32(at + 4);
            if (cmdsize < 8 || !h.Has(at, cmdsize)) break;
            if (cmd == 0x1B && cmdsize >= 24) uuid = Convert.ToHexStringLower(h.Span(at + 8, 16));
            else if (cmd == 0x19 && cmdsize >= 72 && h.CString(at + 8, 16) is { } name && name != "__PAGEZERO")
            {
                ulong vm = h.U64(at + 24), size = h.U64(at + 32);
                if (name == "__TEXT") (textVm, textSize) = (vm, size);
                high = Math.Max(high, vm + size);
            }
            at += cmdsize;
        }
        if (textSize == 0) return null;
        ulong extent = (flags & MhDylibInCache) != 0 || high <= textVm ? textSize : high - textVm;
        return (extent, uuid, h.U32(12));
    }
}
