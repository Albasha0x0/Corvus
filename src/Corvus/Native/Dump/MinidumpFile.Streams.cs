using System.Buffers.Binary;
using System.Text;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump;

public sealed partial class MinidumpFile
{
    public const uint ThreadListStream = 3, ModuleListStream = 4, MemoryListStream = 5, ExceptionStream = 6, SystemInfoStream = 7,
        ThreadExListStream = 8, Memory64ListStream = 9, CommentStreamA = 10, CommentStreamW = 11, HandleDataStream = 12,
        UnloadedModuleListStream = 14, MiscInfoStream = 15, MemoryInfoListStream = 16, ThreadInfoListStream = 17, ThreadNamesStream = 24;

    public static string StreamTypeName(uint type) => type switch
    {
        0 => "Unused",
        3 => "ThreadList",
        4 => "ModuleList",
        5 => "MemoryList",
        6 => "Exception",
        7 => "SystemInfo",
        8 => "ThreadExList",
        9 => "Memory64List",
        10 => "CommentA",
        11 => "CommentW",
        12 => "HandleData",
        13 => "FunctionTable",
        14 => "UnloadedModuleList",
        15 => "MiscInfo",
        16 => "MemoryInfoList",
        17 => "ThreadInfoList",
        18 => "HandleOperationList",
        19 => "Token",
        20 => "JavaScriptData",
        21 => "SystemMemoryInfo",
        22 => "ProcessVmCounters",
        23 => "IptTrace",
        24 => "ThreadNames",
        0x8000 => "ceStreamNull",
        >= 0xFFFF => "LastReserved",
        _ => $"0x{type:X}",
    };

    private static readonly (ulong Bit, string Name)[] TypeFlags =
    [
        (0x1, "WithDataSegs"), (0x2, "WithFullMemory"), (0x4, "WithHandleData"), (0x8, "FilterMemory"), (0x10, "ScanMemory"),
        (0x20, "WithUnloadedModules"), (0x40, "WithIndirectlyReferencedMemory"), (0x80, "FilterModulePaths"), (0x100, "WithProcessThreadData"),
        (0x200, "WithPrivateReadWriteMemory"), (0x400, "WithoutOptionalData"), (0x800, "WithFullMemoryInfo"), (0x1000, "WithThreadInfo"),
        (0x2000, "WithCodeSegs"), (0x4000, "WithoutAuxiliaryState"), (0x8000, "WithFullAuxiliaryState"), (0x10000, "WithPrivateWriteCopyMemory"),
        (0x20000, "IgnoreInaccessibleMemory"), (0x40000, "WithTokenInformation"), (0x80000, "WithModuleHeaders"), (0x100000, "FilterTriage"),
        (0x200000, "WithAvxXStateContext"), (0x400000, "WithIptTrace"), (0x800000, "ScanInaccessiblePartialPages"), (0x1000000, "FilterWriteCombinedMemory"),
    ];

    /// <summary>MINIDUMP_TYPE flag names of <see cref="Flags"/> ("Normal" when none).</summary>
    public IReadOnlyList<string> FlagNames
    {
        get
        {
            var names = TypeFlags.Where(f => (Flags & f.Bit) != 0).Select(f => f.Name).ToList();
            ulong unknown = Flags & ~TypeFlags.Aggregate(0UL, (a, f) => a | f.Bit);
            if (unknown != 0) names.Add($"0x{unknown:X}");
            return names.Count > 0 ? names : ["Normal"];
        }
    }

    private void ReadDirectory()
    {
        long count = StreamCount;
        if (count > MinidumpLimits.MaxStreams)
        {
            Issue("directory", $"{count} streams declared; the first {MinidumpLimits.MaxStreams} are read", 8);
            count = MinidumpLimits.MaxStreams;
        }
        var table = Block(DirectoryRva, (int)count * 12);
        if (table.Length < count * 12)
        {
            Issue("directory", $"the stream directory at 0x{DirectoryRva:X} runs past the end of the file; {table.Length / 12} of {StreamCount} entries read", DirectoryRva);
            count = table.Length / 12;
        }
        var streams = new List<DumpStream>();
        for (int i = 0; i < count; i++)
        {
            uint type = U32(table, i * 12), size = U32(table, i * 12 + 4), rva = U32(table, i * 12 + 8);
            streams.Add(new DumpStream(i, type, StreamTypeName(type), size, rva));
            if (type != 0 && size > 0 && (long)rva + size > FileSize)
                Issue("directory", $"stream {i} ({StreamTypeName(type)}) at 0x{rva:X}, 0x{size:X} bytes, runs past the end of the file ({FileSize} bytes)", DirectoryRva + i * 12L);
        }
        // overlapping streams: reported, each still read on its own
        var placed = streams.Where(s => s.Type != 0 && s.Size > 0).OrderBy(s => s.Rva).ToList();
        for (int i = 1; i < placed.Count; i++)
            if (placed[i].Rva < (long)placed[i - 1].Rva + placed[i - 1].Size)
                Issue("directory", $"stream {placed[i].Index} ({placed[i].TypeName}) overlaps stream {placed[i - 1].Index} ({placed[i - 1].TypeName})", placed[i].Rva);
        Streams = streams;
    }

    /// <summary>The first stream of <paramref name="type"/>'s bytes (capped), noting duplicates; null when absent.</summary>
    private byte[]? StreamData(uint type, out DumpStream? stream)
    {
        var all = Streams.Where(s => s.Type == type).ToList();
        stream = all.FirstOrDefault();
        if (stream == null) return null;
        if (all.Count > 1) Issue(stream.TypeName, $"{all.Count} {stream.TypeName} streams; the first is read");
        if (stream.Size > MinidumpLimits.MaxStreamBytes)
            Issue(stream.TypeName, $"stream is 0x{stream.Size:X} bytes; the first {MinidumpLimits.MaxStreamBytes} bytes are read", stream.Rva);
        return Block(stream.Rva, (int)Math.Min(stream.Size, (uint)MinidumpLimits.MaxStreamBytes));
    }

    private void ReadStreams()
    {
        Guard("SystemInfo", ReadSystemInfo);
        Guard("MiscInfo", ReadMiscInfo);
        Guard("ThreadList", ReadThreads);
        Arch = SystemInfo?.Arch is { } a and not NativeArch.Unknown ? a : GuessArch();
        Guard("ModuleList", ReadModules);
        Guard("Memory", ReadMemoryLists);
        Guard("Exception", ReadException);
        Guard("MemoryInfoList", ReadMemoryInfo);
        Guard("HandleData", ReadHandles);
        Guard("UnloadedModuleList", ReadUnloaded);
        Guard("ThreadInfoList", ReadThreadInfo);
        Guard("ThreadNames", ReadThreadNames);
        Guard("Comment", ReadComments);
    }

    /// <summary>A stream reader that fails on unexpected data loses that stream only.</summary>
    private void Guard(string area, Action read)
    {
        try { read(); }
        catch (Exception ex) when (ex is ArgumentException or IndexOutOfRangeException or OverflowException or InvalidOperationException or DecoderFallbackException)
        {
            Issue(area, $"stream could not be read: {ex.Message}");
        }
    }

    private NativeArch GuessArch()
    {
        var size = Threads.FirstOrDefault()?.Context.Size ?? 0;
        if (size >= 0x4D0) return NativeArch.X64;
        if (size >= 0x2CC) return NativeArch.X86;
        return NativeArch.Unknown;
    }

    private void ReadSystemInfo()
    {
        var d = StreamData(SystemInfoStream, out var s);
        if (d == null) return;
        if (d.Length < 56) Issue("SystemInfo", $"stream is {d.Length} bytes; 56 expected", s!.Rva);
        ushort arch = U16(d, 0);
        var nativeArch = arch switch
        {
            0 => NativeArch.X86,
            9 => NativeArch.X64,
            12 => NativeArch.Arm64,
            5 => NativeArch.Arm,
            _ => NativeArch.Unknown,
        };
        string? vendor = null;
        if (d.Length >= 44 && nativeArch is NativeArch.X86 or NativeArch.X64)
        {
            var v = Encoding.ASCII.GetString(d, 32, 12);
            if (v.All(c => c >= 0x20 && c < 0x7F)) vendor = v;
        }
        SystemInfo = new DumpSystemInfo(arch, nativeArch, U16(d, 2), U16(d, 4), d.Length > 6 ? d[6] : (byte)0, d.Length > 7 ? d[7] : (byte)0,
            U32(d, 8), U32(d, 12), U32(d, 16), U32(d, 20), ReadString(U32(d, 24)), vendor);
    }

    private void ReadMiscInfo()
    {
        var d = StreamData(MiscInfoStream, out _);
        if (d == null || d.Length < 24) return;
        uint size = Math.Min(U32(d, 0), (uint)d.Length);
        uint flags = U32(d, 4);
        bool Has(uint bit, int end) => (flags & bit) != 0 && size >= end;
        string? Wide(int at, int chars)
        {
            if (size < at + chars * 2) return null;
            var s = Encoding.Unicode.GetString(d, at, chars * 2);
            int nul = s.IndexOf('\0');
            s = nul >= 0 ? s[..nul] : s;
            return s.Length > 0 ? s : null;
        }
        MiscInfo = new DumpMiscInfo(size, flags,
            Has(1, 12) ? U32(d, 8) : null,
            Has(2, 24) && U32(d, 12) != 0 ? DateTimeOffset.FromUnixTimeSeconds(U32(d, 12)).UtcDateTime : null,
            Has(2, 24) ? U32(d, 16) : null,
            Has(2, 24) ? U32(d, 20) : null,
            Has(4, 44) ? U32(d, 24) : null,
            Has(0x10, 48) ? U32(d, 44) : null,
            Has(0x20, 52) ? U32(d, 48) : null,
            Has(0x80, 56) ? U32(d, 52) : null,
            (flags & 0x100) != 0 ? Wide(232, 260) : null,
            (flags & 0x100) != 0 ? Wide(752, 40) : null);
    }

    private void ReadThreads()
    {
        var d = StreamData(ThreadListStream, out var s);
        int entry = 48;
        if (d == null)
        {
            d = StreamData(ThreadExListStream, out s);
            entry = 64;
        }
        if (d == null || d.Length < 4) return;
        long count = U32(d, 0);
        count = Capped(count, (d.Length - 4) / entry, MinidumpLimits.MaxThreads, s!);
        var threads = new List<DumpThread>((int)count);
        for (int i = 0; i < count; i++)
        {
            int at = 4 + i * entry;
            threads.Add(new DumpThread(U32(d, at), U32(d, at + 4), U32(d, at + 8), U32(d, at + 12), U64(d, at + 16),
                U64(d, at + 24), U32(d, at + 32), U32(d, at + 36), new DumpLocation(U32(d, at + 40), U32(d, at + 44))));
        }
        Threads = threads;
    }

    /// <summary>
    /// Entries to read: the declared count, cut to what the stream holds (<paramref name="fit"/>) and to the limit.
    /// </summary>
    private long Capped(long declared, long fit, int limit, DumpStream stream)
    {
        long count = declared;
        if (count > fit)
        {
            Issue(stream.TypeName, $"{declared} entries declared, the stream holds {Math.Max(0, fit)}", stream.Rva);
            count = Math.Max(0, fit);
        }
        if (count > limit)
        {
            Issue(stream.TypeName, $"{count} entries; the first {limit} are read", stream.Rva);
            count = limit;
        }
        return count;
    }

    private void ReadModules()
    {
        var d = StreamData(ModuleListStream, out var s);
        if (d == null || d.Length < 4) return;
        const int entry = 108;
        long count = Capped(U32(d, 0), (d.Length - 4) / entry, MinidumpLimits.MaxModules, s!);
        var modules = new List<DumpModule>((int)count);
        for (int i = 0; i < count; i++)
        {
            int at = 4 + i * entry;
            ulong b = U64(d, at);
            uint size = U32(d, at + 8);
            string path = ReadString(U32(d, at + 20)) ?? $"module_{b:X}";
            string? fileVersion = null, productVersion = null;
            if (U32(d, at + 24) == 0xFEEF04BD)
            {
                fileVersion = VersionText(U32(d, at + 32), U32(d, at + 36));
                productVersion = VersionText(U32(d, at + 40), U32(d, at + 44));
            }
            var cv = new DumpLocation(U32(d, at + 76), U32(d, at + 80));
            modules.Add(new DumpModule(b, size, U32(d, at + 12), U32(d, at + 16), path, fileVersion, productVersion, ReadCodeView(cv)));
            if (size == 0) Issue("ModuleList", $"module {path} has a size of 0");
        }
        MainModule = modules.FirstOrDefault();
        modules.Sort((x, y) => x.Base.CompareTo(y.Base));
        for (int i = 1; i < modules.Count; i++)
            if (modules[i].Base < modules[i - 1].End)
                Issue("ModuleList", $"module {modules[i].FileName} at 0x{modules[i].Base:X} overlaps {modules[i - 1].FileName}");
        Modules = modules;

        static string VersionText(uint ms, uint ls) => $"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}";
    }

    private PeCodeView? ReadCodeView(DumpLocation cv)
    {
        if (cv.Size < 16 || cv.Rva == 0) return null;
        var b = Block(cv.Rva, (int)Math.Min(cv.Size, 24u + 4096));
        if (b.Length < 16) return null;
        uint signature = U32(b, 0);
        if (signature == 0x53445352 && b.Length >= 24) // RSDS
            return new PeCodeView("RSDS", new Guid(b.AsSpan(4, 16)), U32(b, 20), Utf8Z(b, 24));
        if (signature == 0x3031424E) // NB10
            return new PeCodeView("NB10", Guid.Empty, U32(b, 12), Utf8Z(b, 16), U32(b, 8));
        return null;

        static string Utf8Z(byte[] b, int at)
        {
            if (at >= b.Length) return "";
            var rest = b.AsSpan(at);
            int len = rest.IndexOf((byte)0);
            return Encoding.UTF8.GetString(len < 0 ? rest : rest[..len]);
        }
    }

    private void ReadMemoryLists()
    {
        var ranges = new List<DumpMemoryRange>();
        var d = StreamData(Memory64ListStream, out var s64);
        if (d != null && d.Length >= 16)
        {
            HasMemory64 = true;
            ulong declared = U64(d, 0);
            long count = Capped(declared > int.MaxValue ? int.MaxValue : (long)declared, (d.Length - 16) / 16, MinidumpLimits.MaxMemoryRanges, s64!);
            ulong fileOffset = U64(d, 8);
            int cut = 0;
            for (int i = 0; i < count; i++)
            {
                ulong start = U64(d, 16 + i * 16), size = U64(d, 16 + i * 16 + 8);
                if (fileOffset >= (ulong)FileSize) { cut++; break; }
                ulong available = Math.Min(size, (ulong)FileSize - fileOffset);
                if (available < size) cut++;
                if (available > 0 && start + available > start) ranges.Add(new DumpMemoryRange(start, available, (long)fileOffset));
                if (size > (ulong)FileSize) { cut++; break; } // a size past any file: the rest of the table is garbage
                fileOffset += size;
            }
            if (cut > 0) Issue("Memory64List", "captured memory runs past the end of the file (a truncated dump); later ranges are missing or cut", s64!.Rva);
        }
        d = StreamData(MemoryListStream, out var s32);
        if (d != null && d.Length >= 4)
        {
            long count = Capped(U32(d, 0), (d.Length - 4) / 16, MinidumpLimits.MaxMemoryRanges, s32!);
            int cut = 0;
            for (int i = 0; i < count; i++)
            {
                int at = 4 + i * 16;
                ulong start = U64(d, at);
                uint size = U32(d, at + 8), rva = U32(d, at + 12);
                long available = Math.Min(size, Math.Max(0, FileSize - rva));
                if (available < size) cut++;
                if (available > 0 && start + (ulong)available > start) ranges.Add(new DumpMemoryRange(start, (ulong)available, rva));
            }
            if (cut > 0) Issue("MemoryList", $"{cut} memory ranges run past the end of the file and are cut", s32!.Rva);
        }
        ranges.Sort((a, b) => a.Start.CompareTo(b.Start));
        var merged = new List<DumpMemoryRange>(ranges.Count);
        int overlaps = 0;
        foreach (var r in ranges)
        {
            if (merged.Count > 0 && r.Start < merged[^1].End)
            {
                overlaps++;
                if (r.End <= merged[^1].End) continue;
                ulong skip = merged[^1].End - r.Start;
                merged.Add(new DumpMemoryRange(merged[^1].End, r.Size - skip, r.FileOffset + (long)skip));
                continue;
            }
            merged.Add(r);
        }
        if (overlaps > 0) Issue("Memory", $"{overlaps} captured memory ranges overlap earlier ones; the first copy is used");
        _memory = [.. merged];
        CapturedBytes = merged.Aggregate(0UL, (sum, r) => sum + r.Size);
    }

    private void ReadException()
    {
        var d = StreamData(ExceptionStream, out var s);
        if (d == null) return;
        if (d.Length < 168) Issue("Exception", $"stream is {d.Length} bytes; 168 expected", s!.Rva);
        if (d.Length < 32) return;
        uint n = Math.Min(U32(d, 32), 15u);
        var parameters = new ulong[n];
        for (int i = 0; i < n; i++) parameters[i] = U64(d, 40 + i * 8);
        Exception = new DumpException(U32(d, 0), U32(d, 8), U32(d, 12), U64(d, 16), U64(d, 24), parameters, new DumpLocation(U32(d, 160), U32(d, 164)));
    }

    private void ReadMemoryInfo()
    {
        var d = StreamData(MemoryInfoListStream, out var s);
        if (d == null || d.Length < 16) return;
        uint header = U32(d, 0), entry = U32(d, 4);
        if (header < 16 || entry < 48 || header > d.Length)
        {
            Issue("MemoryInfoList", $"header size {header} / entry size {entry} are not valid", s!.Rva);
            return;
        }
        ulong declared = U64(d, 8);
        long count = Capped(declared > int.MaxValue ? int.MaxValue : (long)declared, (d.Length - header) / entry, MinidumpLimits.MaxMemoryRegions, s!);
        var list = new List<DumpMemoryRegion>((int)count);
        for (long i = 0; i < count; i++)
        {
            int at = (int)(header + i * entry);
            list.Add(new DumpMemoryRegion(U64(d, at), U64(d, at + 8), U32(d, at + 16), U64(d, at + 24), U32(d, at + 32), U32(d, at + 36), U32(d, at + 40)));
        }
        list.Sort((a, b) => a.Base.CompareTo(b.Base));
        MemoryRegions = list;
    }

    private void ReadHandles()
    {
        var d = StreamData(HandleDataStream, out var s);
        if (d == null || d.Length < 16) return;
        uint header = U32(d, 0), entry = U32(d, 4);
        if (header < 16 || entry < 32 || header > d.Length)
        {
            Issue("HandleData", $"header size {header} / descriptor size {entry} are not valid", s!.Rva);
            return;
        }
        long count = Capped(U32(d, 8), (d.Length - header) / entry, MinidumpLimits.MaxHandles, s!);
        var names = new Dictionary<uint, string?>();
        string? Name(uint rva) => rva == 0 ? null : names.TryGetValue(rva, out var n) ? n : names[rva] = ReadString(rva);
        var list = new List<DumpHandle>((int)count);
        for (long i = 0; i < count; i++)
        {
            int at = (int)(header + i * entry);
            list.Add(new DumpHandle(U64(d, at), Name(U32(d, at + 8)), Name(U32(d, at + 12)), U32(d, at + 16), U32(d, at + 20), U32(d, at + 24), U32(d, at + 28)));
        }
        Handles = list;
    }

    private void ReadUnloaded()
    {
        var d = StreamData(UnloadedModuleListStream, out var s);
        if (d == null || d.Length < 12) return;
        uint header = U32(d, 0), entry = U32(d, 4);
        if (header < 12 || entry < 24 || header > d.Length)
        {
            Issue("UnloadedModuleList", $"header size {header} / entry size {entry} are not valid", s!.Rva);
            return;
        }
        long count = Capped(U32(d, 8), (d.Length - header) / entry, MinidumpLimits.MaxModules, s!);
        var list = new List<DumpUnloadedModule>((int)count);
        for (long i = 0; i < count; i++)
        {
            int at = (int)(header + i * entry);
            ulong b = U64(d, at);
            list.Add(new DumpUnloadedModule(b, U32(d, at + 8), U32(d, at + 12), U32(d, at + 16), ReadString(U32(d, at + 20)) ?? $"module_{b:X}"));
        }
        UnloadedModules = list;
    }

    private void ReadThreadInfo()
    {
        var d = StreamData(ThreadInfoListStream, out var s);
        if (d == null || d.Length < 12) return;
        uint header = U32(d, 0), entry = U32(d, 4);
        if (header < 12 || entry < 64 || header > d.Length)
        {
            Issue("ThreadInfoList", $"header size {header} / entry size {entry} are not valid", s!.Rva);
            return;
        }
        long count = Capped(U32(d, 8), (d.Length - header) / entry, MinidumpLimits.MaxThreads, s!);
        var byId = new Dictionary<uint, (uint Flags, uint Exit, ulong Create, ulong Start)>();
        for (long i = 0; i < count; i++)
        {
            int at = (int)(header + i * entry);
            byId.TryAdd(U32(d, at), (U32(d, at + 4), U32(d, at + 12), U64(d, at + 16), U64(d, at + 48)));
        }
        Threads = Threads.Select(t => byId.TryGetValue(t.Id, out var info)
            ? t with
            {
                DumpFlags = info.Flags,
                ExitStatus = info.Exit,
                StartAddress = info.Start,
                CreateTime = info.Create is > 0 and < 0x24C85A5ED1C04000 ? DateTime.FromFileTimeUtc((long)info.Create) : null,
            }
            : t).ToList();
    }

    private void ReadThreadNames()
    {
        var d = StreamData(ThreadNamesStream, out var s);
        if (d == null || d.Length < 4) return;
        long count = Capped(U32(d, 0), (d.Length - 4) / 12, MinidumpLimits.MaxThreads, s!);
        var names = new Dictionary<uint, string>();
        for (int i = 0; i < count; i++)
        {
            int at = 4 + i * 12;
            ulong rva = U64(d, at + 4);
            if (rva < (ulong)FileSize && ReadString((long)rva) is { Length: > 0 } name) names.TryAdd(U32(d, at), name);
        }
        Threads = Threads.Select(t => names.TryGetValue(t.Id, out var n) ? t with { Name = n } : t).ToList();
    }

    private void ReadComments()
    {
        var list = new List<string>();
        foreach (var s in Streams.Where(s => s.Type is CommentStreamA or CommentStreamW).Take(8))
        {
            var b = Block(s.Rva, (int)Math.Min(s.Size, 64u * 1024));
            var text = s.Type == CommentStreamW ? Encoding.Unicode.GetString(b, 0, b.Length & ~1) : Encoding.Latin1.GetString(b);
            text = text.TrimEnd('\0');
            if (text.Length > 0) list.Add(text);
        }
        Comments = list;
    }
}
