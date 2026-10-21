using System.Text;
using Corvus.Core;
using Corvus.Native.Elf;

namespace Corvus.Native.Dump;

/// <summary>A thread of a core: NT_PRSTATUS (the first is the thread that took the signal).</summary>
public sealed record CoreThread(int Index, uint Id, int Signal, CoreRegisters? Registers);

/// <summary>NT_SIGINFO: the signal that ended the process; <see cref="Address"/> for faults, <see cref="SenderPid"/> for kill and tkill.</summary>
public sealed record ElfCoreSignal(int Number, int Code, int Errno, ulong? Address, uint? SenderPid);

/// <summary>One NT_FILE entry: [Start, End) maps <see cref="Path"/> from byte <see cref="FileOffset"/>.</summary>
public sealed record CoreMapping(ulong Start, ulong End, ulong FileOffset, string Path);

/// <summary>A mapped ELF image of the process (grouped NT_FILE entries), with the GNU build id its header in the core holds.</summary>
public sealed record CoreModule(DumpModule Module, string? BuildId, IReadOnlyList<CoreMapping> Mappings);

/// <summary>NT_PRPSINFO.</summary>
public sealed record ElfCoreProcess(string? Name, string? Arguments, uint Pid, uint ParentPid, uint Uid, uint Gid, char State);

/// <summary>A PT_LOAD of the core: a mapping of the process, of which <see cref="FileSize"/> bytes are captured.</summary>
public sealed record CoreSegment(ulong Start, ulong MemorySize, ulong FileSize, long FileOffset, uint Flags)
{
    public ulong End => Start + MemorySize;
    public string Protection => $"{((Flags & 4) != 0 ? 'r' : '-')}{((Flags & 2) != 0 ? 'w' : '-')}{((Flags & 1) != 0 ? 'x' : '-')}";
    public bool Contains(ulong address) => address >= Start && address - Start < MemorySize;
}

/// <summary>
/// A Linux or Android ELF core dump (ET_CORE): PT_LOAD segments as the process memory, and the PT_NOTE notes
/// NT_PRSTATUS (threads and registers), NT_SIGINFO, NT_FILE (mapped files, grouped into modules), NT_AUXV and
/// NT_PRPSINFO; or a macOS Mach-O core (MH_CORE, see CoreFile.MachO.cs) in the same terms. Only the header check
/// throws; other problems are recorded in <see cref="Issues"/>. Memory is read on demand with positional reads.
/// </summary>
public sealed partial class CoreFile : IProcessMemory, IDisposable
{
    private const int MaxSegments = 1 << 16;
    private const int MaxNotesBytes = 64 << 20;
    private const int MaxNotes = 1 << 16;
    private const int MaxFileEntries = 1 << 18;
    private const int MaxHeaderBytes = 0x1000;

    public const uint NtPrstatus = 1, NtPrpsinfo = 3, NtAuxv = 6, NtSiginfo = 0x53494749, NtFile = 0x46494C45;

    private readonly IDumpSource _source;
    private readonly List<ParseIssue> _issues = [];
    private readonly List<CoreSegment> _segments = [];
    private DumpMemoryRange[] _memory = [];
    private readonly List<CoreThread> _threads = [];
    private readonly List<CoreMapping> _files = [];
    private readonly List<(ulong Type, ulong Value)> _auxv = [];
    private readonly List<DumpModule> _modules = [];
    private readonly List<CoreModule> _coreModules = [];
    private readonly List<DumpMemoryRegion> _regions = [];
    private readonly List<(ulong Offset, ulong Size, ulong Align)> _notes = [];

    /// <summary>The file starts with an ELF header of type ET_CORE, or a 64-bit Mach-O header of type MH_CORE.</summary>
    public static bool IsCore(ReadOnlySpan<byte> head) => IsMachOCore(head) ||
        head.Length >= 18 && head[0] == 0x7F && head[1] == 'E' && head[2] == 'L' && head[3] == 'F'
        && (head[5] == 2 ? head[16] == 0 && head[17] == 4 : head[16] == 4 && head[17] == 0);

    public static bool IsCore(string path)
    {
        try
        {
            using var f = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            Span<byte> head = stackalloc byte[18];
            return RandomAccess.Read(f, head, 0) == 18 && IsCore(head);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return false; }
    }

    public static CoreFile Open(string path)
    {
        var full = InputFiles.RequireRegularFile(path, "core file");
        if (!File.Exists(full)) throw Targets.FileNotFound(path);
        IDumpSource source;
        try { source = new FileDumpSource(full); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.IoError, $"cannot read {path}: {ex.Message}");
        }
        try { return new CoreFile(source, full); }
        catch
        {
            source.Dispose();
            throw;
        }
    }

    public static CoreFile FromBytes(byte[] bytes, string path = "") => new(new BytesDumpSource(bytes), path);

    private CoreFile(IDumpSource source, string path)
    {
        _source = source;
        Path = path;
        FileSize = source.Length;
        var head = Block(0, 64);
        if (IsMachOCore(head))
        {
            ReadMachO(new ByteView(head, false));
            return;
        }
        if (!IsCore(head))
            throw new ToolError(ErrorCode.MalformedInput, $"{(path.Length > 0 ? path : "the file")} is not an ELF core dump (no ELF header of type ET_CORE).",
                "pass a core file written by the Linux kernel, gcore or lldb process save-core");
        Is64Bit = head[4] == 2;
        BigEndian = head[5] == 2;
        var h = new ByteView(head, BigEndian);
        Machine = h.U16(18);
        Arch = ElfNames.Arch(Machine);
        Registers = CoreArch.For(Machine, Is64Bit, BigEndian);
        if (Registers == null) Issue("header", $"registers of {ElfNames.Machine(Machine)} ({(Is64Bit ? 64 : 32)}-bit) are not read");
        ReadSegments(h);
        ReadNotes();
        BuildModules();
    }

    public string Path { get; }
    public long FileSize { get; }
    public bool Is64Bit { get; private set; }
    public bool BigEndian { get; }
    /// <summary>e_machine (of a Mach-O core, the ELF value of its CPU).</summary>
    public ushort Machine { get; private set; }
    public NativeArch Arch { get; private set; }
    /// <summary>The register file of <see cref="Machine"/>; null when not known.</summary>
    public CoreArch? Registers { get; private set; }
    public string ArchName => Registers?.Name ?? ElfNames.Machine(Machine);
    public IReadOnlyList<ParseIssue> Issues => _issues;
    public IReadOnlyList<CoreSegment> Segments => _segments;
    public IReadOnlyList<CoreThread> Threads => _threads;
    public ElfCoreSignal? Signal { get; private set; }
    public ElfCoreProcess? Process { get; private set; }
    public IReadOnlyList<(ulong Type, ulong Value)> AuxVector => _auxv;
    /// <summary>NT_FILE entries in note order.</summary>
    public IReadOnlyList<CoreMapping> Files => _files;
    public IReadOnlyList<CoreModule> CoreModules => _coreModules;
    public IReadOnlyList<DumpModule> Modules => _modules;
    public IReadOnlyList<DumpUnloadedModule> UnloadedModules => [];
    public IReadOnlyList<DumpMemoryRange> MemoryRanges => _memory;
    public ulong CapturedBytes { get; private set; }
    public string Identity => $"core|{Path}|{FileSize}";

    /// <summary>The module holding AT_ENTRY (else AT_PHDR): the executable.</summary>
    public CoreModule? MainModule => _machMain ??
        ((Aux(9) is { } entry ? _coreModules.FirstOrDefault(m => m.Module.Contains(entry)) : null)
        ?? (Aux(3) is { } phdr ? _coreModules.FirstOrDefault(m => m.Module.Contains(phdr)) : null));

    /// <summary>The thread that took the signal: the first whose pr_cursig is set, else the first.</summary>
    public CoreThread? FaultingThread => _threads.FirstOrDefault(t => t.Signal != 0) ?? _threads.FirstOrDefault();

    public ulong? Aux(ulong type) => _auxv.FirstOrDefault(a => a.Type == type) is var (t, v) && t == type ? v : null;

    public CoreModule? CoreModule(DumpModule module) => _coreModules.FirstOrDefault(m => ReferenceEquals(m.Module, module));

    public void Dispose() => _source.Dispose();

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

    public CoreSegment? SegmentAt(ulong address)
    {
        int i = SegmentIndex(address);
        return i >= 0 && _segments[i].Contains(address) ? _segments[i] : null;
    }

    /// <summary>The last segment starting at or below <paramref name="address"/>, or -1.</summary>
    private int SegmentIndex(ulong address)
    {
        int lo = 0, hi = _segments.Count - 1, best = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (_segments[mid].Start <= address) { best = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        return best;
    }

    /// <summary>Some executable segment overlaps [start, end).</summary>
    private bool AnyExecutable(ulong start, ulong end)
    {
        for (int i = Math.Max(0, SegmentIndex(start)); i < _segments.Count && _segments[i].Start < end; i++)
            if ((_segments[i].Flags & 1) != 0 && _segments[i].End > start) return true;
        return false;
    }

    /// <summary>A PT_LOAD as a region: committed, with the page protection its flags give.</summary>
    public DumpMemoryRegion? RegionAt(ulong address) => ProcessMemoryExtensions.RegionAt(_regions, address);

    public DumpModule? ModuleAt(ulong address) => ProcessMemoryExtensions.ModuleAt(_modules, address);

    public ulong ReadableExtent(ulong start, ulong size)
    {
        ulong extent = 0;
        foreach (var r in _memory)
        {
            if (r.Start >= start + size) break;
            if (r.End > start) extent = Math.Max(extent, Math.Min(r.End, start + size) - start);
        }
        return extent;
    }

    public CoreThread? ThreadById(uint id) => _threads.FirstOrDefault(t => t.Id == id);

    /// <summary>A NUL-terminated string of process memory (at most <paramref name="max"/> bytes); null when unreadable.</summary>
    public string? ReadString(ulong address, int max = 4096)
    {
        var buffer = new byte[max];
        int n = ReadMemory(address, buffer);
        int end = Array.IndexOf(buffer, (byte)0, 0, n);
        return end < 0 ? null : Encoding.UTF8.GetString(buffer, 0, end);
    }

    private void ReadSegments(ByteView h)
    {
        long phoff = (long)Math.Min(Is64Bit ? h.U64(32) : h.U32(28), long.MaxValue / 2);
        int entry = Is64Bit ? 56 : 32;
        int phentsize = Math.Max(h.U16(Is64Bit ? 54 : 42), entry);
        int phnum = h.U16(Is64Bit ? 56 : 44);
        if (phnum == 0xFFFF)
        {
            // PN_XNUM: the count is section header 0's sh_info
            long shoff = (long)Math.Min(Is64Bit ? h.U64(40) : h.U32(32), long.MaxValue / 2);
            var sh = new ByteView(Block(shoff, 64), BigEndian);
            phnum = (int)Math.Min(sh.U32(Is64Bit ? 44 : 28), MaxSegments);
        }
        var table = new ByteView(Block(phoff, (int)Math.Min((long)phnum * phentsize, MaxSegments * 56L)), BigEndian);
        if (table.Length < (long)phnum * phentsize) Issue("headers", $"the program header table is truncated ({table.Length / phentsize} of {phnum})", phoff);
        var ranges = new List<DumpMemoryRange>();
        for (long at = 0; at + entry <= table.Length; at += phentsize)
        {
            uint type = table.U32(at);
            uint flags = Is64Bit ? table.U32(at + 4) : table.U32(at + 24);
            ulong offset = Is64Bit ? table.U64(at + 8) : table.U32(at + 4);
            ulong vaddr = Is64Bit ? table.U64(at + 16) : table.U32(at + 8);
            ulong filesz = Is64Bit ? table.U64(at + 32) : table.U32(at + 16);
            ulong memsz = Is64Bit ? table.U64(at + 40) : table.U32(at + 20);
            ulong align = Is64Bit ? table.U64(at + 48) : table.U32(at + 28);
            if (type == 4) _notes.Add((offset, filesz, align));
            if (type == 1) AddSegment("PT_LOAD", vaddr, memsz, filesz, offset, flags, ranges);
        }
        SetMemory(ranges);
    }

    /// <summary>A segment of the process: <paramref name="memsz"/> bytes at <paramref name="vaddr"/>, of which the file holds <paramref name="filesz"/>.</summary>
    private void AddSegment(string kind, ulong vaddr, ulong memsz, ulong filesz, ulong offset, uint flags, List<DumpMemoryRange> ranges)
    {
        if (memsz == 0) return;
        ulong captured = Math.Min(filesz, memsz);
        if (offset > (ulong)FileSize) captured = 0;
        else if (captured > (ulong)FileSize - offset)
        {
            Issue("memory", $"{kind} at 0x{vaddr:X} holds 0x{captured:X} bytes past the end of the file; the core is truncated", (long)Math.Min(offset, long.MaxValue));
            captured = (ulong)FileSize - offset;
        }
        _segments.Add(new CoreSegment(vaddr, memsz, captured, (long)Math.Min(offset, long.MaxValue), flags));
        if (captured > 0) ranges.Add(new DumpMemoryRange(vaddr, captured, (long)offset));
    }

    /// <summary>Sorts the segments and keeps the captured ranges without overlaps.</summary>
    private void SetMemory(List<DumpMemoryRange> ranges)
    {
        _segments.Sort((a, b) => a.Start.CompareTo(b.Start));
        ranges.Sort((a, b) => a.Start.CompareTo(b.Start));
        var clean = new List<DumpMemoryRange>(ranges.Count);
        foreach (var r in ranges)
        {
            if (clean.Count > 0 && r.Start < clean[^1].End)
            {
                Issue("memory", $"the segment at 0x{r.Start:X} overlaps the one below; the lower one owns the overlap");
                if (r.End <= clean[^1].End) continue;
                ulong skip = clean[^1].End - r.Start;
                clean.Add(new DumpMemoryRange(r.Start + skip, r.Size - skip, r.FileOffset + (long)skip));
                continue;
            }
            clean.Add(r);
        }
        _memory = [.. clean];
        CapturedBytes = (ulong)clean.Sum(r => (decimal)r.Size);
    }

    private void ReadNotes()
    {
        long budget = MaxNotesBytes;
        int count = 0;
        foreach (var (offset, size, align) in _notes)
        {
            if (offset >= (ulong)FileSize) { Issue("notes", $"PT_NOTE at 0x{offset:X} lies past the end of the file"); continue; }
            int length = (int)Math.Min(Math.Min(size, (ulong)FileSize - offset), (ulong)budget);
            if ((ulong)length < size) Issue("notes", $"PT_NOTE at 0x{offset:X} is read for 0x{length:X} of 0x{size:X} bytes");
            budget -= length;
            var t = new ByteView(Block((long)offset, length), BigEndian);
            long pad = align == 8 ? 8 : 4;
            long at = 0;
            while (at + 12 <= t.Length && count++ < MaxNotes)
            {
                long nameSize = t.U32(at), descSize = t.U32(at + 4);
                uint type = t.U32(at + 8);
                long name = at + 12, desc = Align(name + nameSize, pad), next = Align(desc + descSize, pad);
                if (desc + descSize > t.Length)
                {
                    Issue("notes", $"note at file offset 0x{(long)offset + at:X} extends past its segment");
                    break;
                }
                var nameBytes = t.Span(name, nameSize);
                int nul = nameBytes.IndexOf((byte)0);
                string owner = Encoding.UTF8.GetString(nul < 0 ? nameBytes : nameBytes[..nul]);
                if (owner is "CORE" or "LINUX") Note(type, t.Slice(desc, descSize), (long)offset + desc);
                at = next;
            }
        }
        if (_threads.Count == 0) Issue("notes", "no NT_PRSTATUS note: the core has no threads");
    }

    private static long Align(long v, long a) => (v + a - 1) & ~(a - 1);

    private void Note(uint type, ByteView d, long fileOffset)
    {
        switch (type)
        {
            case NtPrstatus: Prstatus(d, fileOffset); break;
            case NtPrpsinfo: Prpsinfo(d); break;
            case NtAuxv:
                int w = Is64Bit ? 8 : 4;
                for (long at = 0; at + 2 * w <= d.Length && _auxv.Count < 512; at += 2 * w)
                {
                    ulong t = d.Word(at, Is64Bit);
                    if (t == 0) break;
                    _auxv.Add((t, d.Word(at + w, Is64Bit)));
                }
                break;
            case NtSiginfo:
                if (d.Length < 12) break;
                int signo = (int)d.U32(0), errno = (int)d.U32(4), code = (int)d.U32(8);
                if (signo == 0) break; // a thread that took no signal
                long union = Is64Bit ? 16 : 12;
                bool fault = signo is 4 or 5 or 7 or 8 or 11 && code > 0; // SIGILL SIGTRAP SIGBUS SIGFPE SIGSEGV raised by the CPU
                Signal = new ElfCoreSignal(signo, code, errno, fault && d.Has(union, Is64Bit ? 8 : 4) ? d.Word(union, Is64Bit) : null,
                    code <= 0 && d.Has(union, 4) ? d.U32(union) : null);
                break;
            case NtFile: FileNote(d, fileOffset); break;
        }
    }

    private void Prstatus(ByteView d, long fileOffset)
    {
        long regAt = Is64Bit ? 112 : 72;
        if (d.Length < regAt)
        {
            Issue("notes", $"NT_PRSTATUS at 0x{fileOffset:X} has {d.Length} bytes; too short for a thread", fileOffset);
            return;
        }
        int signal = d.U16(12);
        uint pid = d.U32(Is64Bit ? 32 : 24);
        var regs = Registers != null ? CoreRegisters.Parse(Registers, d.Slice(regAt, d.Length - regAt)) : null;
        _threads.Add(new CoreThread(_threads.Count, pid, signal, regs));
    }

    private void Prpsinfo(ByteView d)
    {
        // 64-bit: 136 bytes, pr_fname at 40; 32-bit (16-bit uid and gid): 124 bytes, pr_fname at 28
        bool wide = Is64Bit;
        long pidAt = wide ? 24 : 12, nameAt = wide ? 40 : 28;
        if (d.Length < nameAt + 16) return;
        string? Text(long at, int max) => d.CString(at, max) is { Length: > 0 } s ? s.TrimEnd() : null;
        Process = new ElfCoreProcess(Text(nameAt, 16), Text(nameAt + 16, 80), d.U32(pidAt), d.U32(pidAt + 4),
            wide ? d.U32(16) : d.U16(8), wide ? d.U32(20) : d.U16(10), (char)d.U8(1));
    }

    private void FileNote(ByteView d, long fileOffset)
    {
        int w = Is64Bit ? 8 : 4;
        ulong count = d.Word(0, Is64Bit), page = d.Word(w, Is64Bit);
        if (count > MaxFileEntries || (long)count * 3 * w + 2 * w > d.Length)
        {
            Issue("notes", $"NT_FILE at 0x{fileOffset:X} declares {count} entries that do not fit its {d.Length} bytes", fileOffset);
            return;
        }
        if (page == 0) page = 1;
        long names = 2 * w + (long)count * 3 * w;
        for (ulong i = 0; i < count; i++)
        {
            long at = 2 * w + (long)i * 3 * w;
            string? path = d.CString(names, 4096);
            if (path == null)
            {
                Issue("notes", $"NT_FILE at 0x{fileOffset:X}: names end after {i} of {count} entries", fileOffset);
                break;
            }
            names += Encoding.UTF8.GetByteCount(path) + 1;
            _files.Add(new CoreMapping(d.Word(at, Is64Bit), d.Word(at + w, Is64Bit), d.Word(at + 2 * w, Is64Bit) * page, path));
        }
    }

    /// <summary>Mapped files grouped by path into modules: those whose first page reads as ELF, or with an executable mapping.</summary>
    private void BuildModules()
    {
        var byPath = new Dictionary<string, List<CoreMapping>>(StringComparer.Ordinal);
        foreach (var f in _files)
        {
            if (f.End <= f.Start) continue;
            if (!byPath.TryGetValue(f.Path, out var list)) byPath[f.Path] = list = [];
            list.Add(f);
        }
        Span<byte> magic = stackalloc byte[4];
        foreach (var (path, maps) in byPath)
        {
            var first = maps.Where(m => m.FileOffset == 0).OrderBy(m => m.Start).FirstOrDefault();
            ulong start = first?.Start ?? maps.Min(m => m.Start);
            ulong end = maps.Where(m => m.Start >= start).Select(m => m.End).DefaultIfEmpty(start).Max();
            bool elf = first != null && ReadMemory(start, magic) == 4 && magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F';
            bool executable = maps.Any(m => AnyExecutable(m.Start, m.End));
            if (!elf && !executable) continue;
            var module = new DumpModule(start, (uint)Math.Min(end - start, uint.MaxValue), 0, 0, path, null, null, null);
            _coreModules.Add(new CoreModule(module, elf ? MemoryBuildId(start) : null, maps));
        }
        AddModulesAndRegions();
    }

    /// <summary>Lists the modules by base, then each segment as a region: committed, with the page protection its flags give.</summary>
    private void AddModulesAndRegions()
    {
        _coreModules.Sort((a, b) => a.Module.Base.CompareTo(b.Module.Base));
        _modules.AddRange(_coreModules.Select(m => m.Module));
        foreach (var s in _segments)
        {
            uint protect = (s.Flags & 7) switch { 0 => 0x01, 4 => 0x02, 6 => 0x04, 1 => 0x10, 5 => 0x20, _ => 0x40 };
            _regions.Add(new DumpMemoryRegion(s.Start, s.Start, protect, s.MemorySize, 0x1000, protect, ModuleAt(s.Start) != null ? 0x1000000u : 0x20000u));
        }
    }

    /// <summary>NT_GNU_BUILD_ID of the ELF image whose header is at <paramref name="start"/> in process memory.</summary>
    private string? MemoryBuildId(ulong start)
    {
        var header = new byte[MaxHeaderBytes];
        int n = ReadMemory(start, header);
        if (n < 64) return null;
        var image = ElfMemoryHeader.Read(header.AsSpan(0, n).ToArray(), start);
        return image?.BuildId(this);
    }

    private void Issue(string area, string message, long? offset = null)
    {
        if (_issues.Count < MinidumpLimits.MaxIssues) _issues.Add(new ParseIssue(area, message, offset));
        else if (_issues.Count == MinidumpLimits.MaxIssues) _issues.Add(new ParseIssue("core", "further issues are not recorded"));
    }

    private byte[] Block(long offset, int size)
    {
        if (offset < 0 || offset >= FileSize || size <= 0) return [];
        size = (int)Math.Min(size, FileSize - offset);
        var buffer = new byte[size];
        int n = _source.Read(offset, buffer);
        return n == size ? buffer : buffer[..n];
    }

    /// <summary>Signal names (Linux numbering, as on x86, ARM and most others).</summary>
    public static string? SignalName(int signo) => signo switch
    {
        1 => "SIGHUP", 2 => "SIGINT", 3 => "SIGQUIT", 4 => "SIGILL", 5 => "SIGTRAP", 6 => "SIGABRT", 7 => "SIGBUS", 8 => "SIGFPE",
        9 => "SIGKILL", 10 => "SIGUSR1", 11 => "SIGSEGV", 12 => "SIGUSR2", 13 => "SIGPIPE", 14 => "SIGALRM", 15 => "SIGTERM",
        16 => "SIGSTKFLT", 17 => "SIGCHLD", 24 => "SIGXCPU", 25 => "SIGXFSZ", 31 => "SIGSYS",
        _ => null,
    };

    /// <summary>si_code in words for the signal (fault codes per signal; the generic sender codes otherwise).</summary>
    public static string? SignalCodeName(int signo, int code) => (signo, code) switch
    {
        (11, 1) => "SEGV_MAPERR: address not mapped",
        (11, 2) => "SEGV_ACCERR: invalid permissions for the mapping",
        (11, 3) => "SEGV_BNDERR: failed address bound checks",
        (11, 4) => "SEGV_PKUERR: protection key check failed",
        (11, 8) => "SEGV_MTESERR: memory tag check failed (synchronous)",
        (11, 9) => "SEGV_MTEAERR: memory tag check failed (asynchronous)",
        (7, 1) => "BUS_ADRALN: invalid address alignment",
        (7, 2) => "BUS_ADRERR: nonexistent physical address",
        (7, 3) => "BUS_OBJERR: object-specific hardware error",
        (4, 1) => "ILL_ILLOPC: illegal opcode",
        (4, 2) => "ILL_ILLOPN: illegal operand",
        (4, 4) => "ILL_ILLTRP: illegal trap",
        (4, 5) => "ILL_PRVOPC: privileged opcode",
        (8, 1) => "FPE_INTDIV: integer divide by zero",
        (8, 2) => "FPE_INTOVF: integer overflow",
        (8, 3) => "FPE_FLTDIV: floating-point divide by zero",
        (5, 1) => "TRAP_BRKPT: breakpoint",
        (5, 2) => "TRAP_TRACE: trace trap",
        (_, 0) => "SI_USER: sent by kill()",
        (_, 0x80) => "SI_KERNEL: sent by the kernel",
        (_, -1) => "SI_QUEUE: sent by sigqueue()",
        (_, -6) => "SI_TKILL: sent by tkill() or raise()",
        _ => null,
    };
}
