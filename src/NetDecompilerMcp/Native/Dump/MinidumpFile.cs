using System.Buffers.Binary;
using System.Text;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.Dump;

/// <summary>Hard limits for dump parsing; reaching one records an issue.</summary>
public static class MinidumpLimits
{
    public const int MaxStreams = 4096;
    public const int MaxThreads = 1 << 16;
    public const int MaxModules = 1 << 14;
    public const int MaxMemoryRanges = 1 << 20;
    public const int MaxMemoryRegions = 1 << 20;
    public const int MaxHandles = 1 << 18;
    public const int MaxStringChars = 1 << 15;
    public const int MaxIssues = 200;
    /// <summary>Largest stream (descriptor table) read into memory at once; captured memory is read on demand.</summary>
    public const int MaxStreamBytes = 64 << 20;
}

/// <summary>
/// A Windows minidump (MINIDUMP_HEADER "MDMP"): the stream directory and the streams a crash analysis needs (threads,
/// modules with CodeView records, exception, system and process info, memory lists, memory regions, handles, unloaded
/// modules, thread info and names). Only the header check throws; every other problem (truncation, overlapping
/// streams, counts past the data, unknown versions) is recorded in <see cref="Issues"/> and the rest is still read.
/// The file is read with positional reads: captured memory is never loaded as a whole.
/// </summary>
public sealed partial class MinidumpFile : IDisposable
{
    public const uint Signature = 0x504D444D; // "MDMP"

    private readonly IDumpSource _source;
    private readonly List<ParseIssue> _issues = [];
    private DumpMemoryRange[] _memory = [];

    public static MinidumpFile Open(string path)
    {
        string full;
        try { full = System.IO.Path.GetFullPath(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ToolError(ErrorCode.InvalidArgument, $"invalid path '{path}': {ex.Message}");
        }
        if (Directory.Exists(full)) throw new ToolError(ErrorCode.InvalidArgument, $"{path} is a directory, not a dump file.");
        if (!File.Exists(full)) throw new ToolError(ErrorCode.NotFound, $"file not found: {path}");
        IDumpSource source;
        try { source = new FileDumpSource(full); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.IoError, $"cannot read {path}: {ex.Message}");
        }
        try { return new MinidumpFile(source, full); }
        catch
        {
            source.Dispose();
            throw;
        }
    }

    public static MinidumpFile FromBytes(byte[] bytes, string path = "") => new(new BytesDumpSource(bytes), path);

    private MinidumpFile(IDumpSource source, string path)
    {
        _source = source;
        Path = path;
        FileSize = source.Length;
        Span<byte> h = stackalloc byte[32];
        if (source.Read(0, h) >= 8 && BinaryPrimitives.ReadUInt32LittleEndian(h) == 0x45474150) // "PAGE": PAGEDUMP / PAGEDU64
            throw new ToolError(ErrorCode.Unsupported, $"{(path.Length > 0 ? path : "the file")} is a kernel-mode (blue screen) dump, not a user-mode minidump.",
                "open it with WinDbg or kd; this tool reads user-mode minidumps (MDMP)");
        if (source.Read(0, h) < 32 || BinaryPrimitives.ReadUInt32LittleEndian(h) != Signature)
            throw new ToolError(ErrorCode.MalformedInput, $"{(path.Length > 0 ? path : "the file")} is not a Windows minidump (no MDMP header).",
                "pass a .dmp file written by MiniDumpWriteDump, procdump, Task Manager or a debugger (.dump /m)");
        Version = BinaryPrimitives.ReadUInt32LittleEndian(h[4..]);
        StreamCount = BinaryPrimitives.ReadUInt32LittleEndian(h[8..]);
        DirectoryRva = BinaryPrimitives.ReadUInt32LittleEndian(h[12..]);
        TimeDateStamp = BinaryPrimitives.ReadUInt32LittleEndian(h[20..]);
        Flags = BinaryPrimitives.ReadUInt64LittleEndian(h[24..]);
        if ((Version & 0xFFFF) != 0xA793) Issue("header", $"unexpected version 0x{Version & 0xFFFF:X4} (0xA793 expected); read anyway");
        ReadDirectory();
        ReadStreams();
    }

    public string Path { get; }
    public long FileSize { get; }
    public uint Version { get; }
    public uint StreamCount { get; }
    public uint DirectoryRva { get; }
    public uint TimeDateStamp { get; }
    /// <summary>MINIDUMP_TYPE flags the dump was written with.</summary>
    public ulong Flags { get; }
    public DateTime Time => DateTimeOffset.FromUnixTimeSeconds(TimeDateStamp).UtcDateTime;

    public IReadOnlyList<DumpStream> Streams { get; private set; } = [];
    public DumpSystemInfo? SystemInfo { get; private set; }
    public DumpMiscInfo? MiscInfo { get; private set; }
    public DumpException? Exception { get; private set; }
    public IReadOnlyList<DumpThread> Threads { get; private set; } = [];
    /// <summary>Sorted by base address.</summary>
    public IReadOnlyList<DumpModule> Modules { get; private set; } = [];
    /// <summary>The first module of the list: the process executable.</summary>
    public DumpModule? MainModule { get; private set; }
    public IReadOnlyList<DumpUnloadedModule> UnloadedModules { get; private set; } = [];
    public IReadOnlyList<DumpMemoryRegion> MemoryRegions { get; private set; } = [];
    public IReadOnlyList<DumpHandle> Handles { get; private set; } = [];
    public IReadOnlyList<string> Comments { get; private set; } = [];
    /// <summary>Captured memory ranges, sorted by address, without overlaps.</summary>
    public IReadOnlyList<DumpMemoryRange> MemoryRanges => _memory;
    /// <summary>Whether the memory came from a Memory64ListStream (full-memory dumps).</summary>
    public bool HasMemory64 { get; private set; }
    public ulong CapturedBytes { get; private set; }
    /// <summary>Instruction set of the dumped process: system info, else the size of the first thread context.</summary>
    public NativeArch Arch { get; private set; }
    public IReadOnlyList<ParseIssue> Issues => _issues;

    public bool Is64Bit => Arch is NativeArch.X64 or NativeArch.Arm64;

    public void Dispose() => _source.Dispose();

    // ---- memory ----

    /// <summary>
    /// Copies captured memory starting at <paramref name="address"/>; stops at the first byte the dump does not hold
    /// and returns the number of bytes copied.
    /// </summary>
    public int ReadMemory(ulong address, Span<byte> destination)
    {
        int done = 0;
        int i = RangeIndex(address);
        while (done < destination.Length && i >= 0 && i < _memory.Length)
        {
            var r = _memory[i];
            ulong at = address + (ulong)done;
            if (at < r.Start || at >= r.End) break;
            ulong inRange = at - r.Start;
            int n = (int)Math.Min((ulong)(destination.Length - done), r.Size - inRange);
            int read = _source.Read(r.FileOffset + (long)inRange, destination.Slice(done, n));
            done += read;
            if (read < n) break;
            i++;
        }
        return done;
    }

    /// <summary>The captured range containing <paramref name="address"/>, or null.</summary>
    public DumpMemoryRange? RangeAt(ulong address)
    {
        int i = RangeIndex(address);
        return i >= 0 ? _memory[i] : null;
    }

    private int RangeIndex(ulong address)
    {
        int lo = 0, hi = _memory.Length - 1, best = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (_memory[mid].Start <= address) { best = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        return best >= 0 && address - _memory[best].Start < _memory[best].Size ? best : -1;
    }

    public bool TryReadU64(ulong address, out ulong value)
    {
        Span<byte> b = stackalloc byte[8];
        value = 0;
        if (ReadMemory(address, b) < 8) return false;
        value = BinaryPrimitives.ReadUInt64LittleEndian(b);
        return true;
    }

    public bool TryReadU32(ulong address, out uint value)
    {
        Span<byte> b = stackalloc byte[4];
        value = 0;
        if (ReadMemory(address, b) < 4) return false;
        value = BinaryPrimitives.ReadUInt32LittleEndian(b);
        return true;
    }

    /// <summary>A pointer-sized value of the dumped process.</summary>
    public bool TryReadPointer(ulong address, out ulong value)
    {
        if (Is64Bit) return TryReadU64(address, out value);
        bool ok = TryReadU32(address, out uint v);
        value = v;
        return ok;
    }

    /// <summary>The memory region (MemoryInfoList) containing <paramref name="address"/>, or null.</summary>
    public DumpMemoryRegion? RegionAt(ulong address)
    {
        var regions = MemoryRegions;
        int lo = 0, hi = regions.Count - 1, best = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (regions[mid].Base <= address) { best = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        return best >= 0 && regions[best].Contains(address) ? regions[best] : null;
    }

    public DumpModule? ModuleAt(ulong address)
    {
        var modules = Modules;
        int lo = 0, hi = modules.Count - 1, best = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (modules[mid].Base <= address) { best = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        // overlapping modules (malformed lists): a near one below that contains the address
        for (int i = best; i >= 0 && best - i < 4; i--)
            if (modules[i].Contains(address)) return modules[i];
        return null;
    }

    public DumpThread? ThreadById(uint id) => Threads.FirstOrDefault(t => t.Id == id);

    // ---- contexts ----

    /// <summary>Reads a CONTEXT record for the dump's architecture; null when the location holds nothing.</summary>
    public DumpContext? ReadContext(DumpLocation location)
    {
        if (location.Size == 0 || location.Rva == 0) return null;
        var bytes = Block(location.Rva, (int)Math.Min(location.Size, 0x4D0u + 0x100));
        if (bytes.Length < 8) return null;
        var arch = Arch;
        var c = new DumpContext(arch);
        switch (arch)
        {
            case NativeArch.X64:
                c.Complete = bytes.Length >= 0x2A0;
                c.ContextFlags = U32(bytes, 0x30);
                c.SegCs = U16(bytes, 0x38);
                c.Flags = U32(bytes, 0x44);
                for (int i = 0; i < 16; i++) c.Gpr[i] = U64(bytes, 0x78 + 8 * i);
                c.Ip = U64(bytes, 0xF8);
                if (bytes.Length >= 0x1A0 + 256) bytes.AsSpan(0x1A0, 256).CopyTo(c.Xmm);
                break;
            case NativeArch.X86:
                c.Complete = bytes.Length >= 0xCC;
                c.ContextFlags = U32(bytes, 0);
                c.Gpr[7] = U32(bytes, 0x9C);
                c.Gpr[6] = U32(bytes, 0xA0);
                c.Gpr[3] = U32(bytes, 0xA4);
                c.Gpr[2] = U32(bytes, 0xA8);
                c.Gpr[1] = U32(bytes, 0xAC);
                c.Gpr[0] = U32(bytes, 0xB0);
                c.Gpr[5] = U32(bytes, 0xB4);
                c.Ip = U32(bytes, 0xB8);
                c.SegCs = (ushort)U32(bytes, 0xBC);
                c.Flags = U32(bytes, 0xC0);
                c.Gpr[4] = U32(bytes, 0xC4);
                break;
            case NativeArch.Arm64:
                // ContextFlags, Cpsr, X0-X28, Fp, Lr, Sp, Pc: only the frame registers are kept
                c.Complete = bytes.Length >= 0x110;
                c.ContextFlags = U32(bytes, 0);
                c.Flags = U32(bytes, 4);
                c.Gpr[5] = U64(bytes, 0xF0);
                c.Gpr[4] = U64(bytes, 0x100);
                c.Ip = U64(bytes, 0x108);
                break;
            default:
                return null;
        }
        return c;
    }

    // ---- helpers ----

    private void Issue(string area, string message, long? offset = null)
    {
        if (_issues.Count < MinidumpLimits.MaxIssues) _issues.Add(new ParseIssue(area, message, offset));
        else if (_issues.Count == MinidumpLimits.MaxIssues) _issues.Add(new ParseIssue("dump", "further issues are not recorded"));
    }

    /// <summary>Up to <paramref name="size"/> bytes at file offset <paramref name="offset"/> (fewer at the end of the file).</summary>
    private byte[] Block(long offset, int size)
    {
        if (offset < 0 || offset >= FileSize || size <= 0) return [];
        size = (int)Math.Min(size, FileSize - offset);
        var buffer = new byte[size];
        int n = _source.Read(offset, buffer);
        return n == size ? buffer : buffer[..n];
    }

    /// <summary>A MINIDUMP_STRING (byte length, then UTF-16) at <paramref name="rva"/>; null when unreadable.</summary>
    private string? ReadString(long rva)
    {
        if (rva <= 0 || rva >= FileSize) return null;
        var len = Block(rva, 4);
        if (len.Length < 4) return null;
        uint bytes = BinaryPrimitives.ReadUInt32LittleEndian(len);
        int chars = (int)Math.Min(bytes / 2, (uint)MinidumpLimits.MaxStringChars);
        var data = Block(rva + 4, chars * 2);
        return Encoding.Unicode.GetString(data, 0, data.Length & ~1).TrimEnd('\0');
    }

    private static ushort U16(byte[] b, int at) => at >= 0 && at + 2 <= b.Length ? BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(at)) : (ushort)0;
    private static uint U32(byte[] b, int at) => at >= 0 && at + 4 <= b.Length ? BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at)) : 0;
    private static ulong U64(byte[] b, int at) => at >= 0 && at + 8 <= b.Length ? BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(at)) : 0;
}
