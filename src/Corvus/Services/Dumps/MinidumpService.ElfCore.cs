using System.Collections.Concurrent;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Elf;
using Corvus.Native.Itanium;

namespace Corvus.Services;

/// <summary>
/// The dump tools on a Linux or Android ELF core: threads and registers from NT_PRSTATUS, the signal from
/// NT_SIGINFO, modules from NT_FILE (matched to files on disk by GNU build id), stacks unwound by .eh_frame CFI.
/// </summary>
public sealed partial class MinidumpService
{
    private const int MaxCachedElfFiles = 64;
    private readonly ConcurrentDictionary<string, (ushort Machine, string? BuildId)?> _elfProbes = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, ElfFile> _elfFiles = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Frames that say how a signal was raised, not where: skipped in core signatures.</summary>
    private static readonly string[] CoreNoiseFrames =
        ["libc.so*!raise", "libc.so*!gsignal", "libc.so*!abort", "libc.so*!__GI_raise", "libc.so*!__GI_abort", "libc.so*!__pthread_kill*", "libc.so*!pthread_kill*", "libc.so*!tgkill",
         "*!__restore_rt"];

    private static string FileKey(string path)
    {
        var info = new FileInfo(path);
        return $"{info.FullName}|{(info.Exists ? info.Length : -1)}|{(info.Exists ? info.LastWriteTimeUtc.Ticks : 0)}";
    }

    private (ushort Machine, string? BuildId)? Probe(string path) => _elfProbes.GetOrAdd(FileKey(path), _ => ElfMemoryHeader.Probe(path));

    private (string? Path, bool Matches, string Detail) FindElf(ElfCoreFile core, ElfCoreModule module, IReadOnlyList<string> directories) =>
        ElfCoreImage.Find(module, directories, core.Machine, Probe);

    /// <summary>A core module's image: the matched file on disk, else the module as the core holds it.</summary>
    internal (ElfCoreImage? Image, string Detail) LoadElf(ElfCoreFile core, DumpModule module, IReadOnlyList<string> directories)
    {
        if (core.CoreModule(module) is not { } cm) return (null, "not a module of the core");
        var (path, matches, detail) = FindElf(core, cm, directories);
        if (matches && path != null)
        {
            try
            {
                string key = FileKey(path);
                if (!_elfFiles.TryGetValue(key, out var file))
                {
                    file = ElfFile.Open(path);
                    if (_elfFiles.Count >= MaxCachedElfFiles) _elfFiles.Clear();
                    _elfFiles[key] = file;
                }
                return (ElfCoreImage.FromFile(file, module, core, path, detail), detail);
            }
            catch (ToolError ex) { detail = $"{path}: {ex.Message}"; }
        }
        string local = path != null && !matches ? $"{path}: {detail}" : detail;
        var image = ElfCoreImage.FromMemory(core, module, $"from core memory; local file: {local}");
        return (image, image?.Detail ?? $"no image: {local}; the core does not hold its ELF header");
    }

    private Location LocateCore(Session s, ulong address, bool returnAddress)
    {
        var core = s.Core!;
        ulong lookup = returnAddress && address > 0 ? address - 1 : address;
        var module = core.ModuleAt(lookup);
        if (module == null)
        {
            var segment = core.SegmentAt(lookup);
            string what = segment == null ? "not in a module and not in any mapping of the core"
                : (segment.Flags & 1) != 0 ? "not in a module: generated code (an executable anonymous mapping)" : "not in a module and not executable memory";
            return new Location(null, null, null, null, null, null, "unknown", what);
        }
        uint shown = (uint)(address - module.Base);
        string label = module.FileName;
        var (image, detail) = s.Elf(module);
        if (image?.SymbolAt(lookup) is { } symbol)
        {
            string name = ItaniumDemangler.Demangle(symbol.Name) ?? symbol.Name;
            ulong off = address - symbol.Start;
            return new Location(module, shown, $"{label}!{name}" + (off != 0 ? $"+0x{off:X}" : ""), name, symbol.Source, symbol.Start, "native",
                symbol.Size == 0 ? "named after the nearest symbol below (it has no size)" : null);
        }
        return new Location(module, shown, $"{label}+0x{shown:X}", null, "none", null, "native", image == null ? detail : null);
    }

    private static bool IsAndroid(ElfCoreFile core) =>
        core.Files.Any(f => f.Path.StartsWith("/system/bin/linker", StringComparison.Ordinal) || f.Path.StartsWith("/apex/", StringComparison.Ordinal));

    private static string? CoreRuntime(ElfCoreFile core)
    {
        foreach (var m in core.CoreModules)
        {
            var n = m.Module.FileName;
            if (n == "libcoreclr.so") return ".NET (CoreCLR)";
            if (n.StartsWith("libmonosgen", StringComparison.Ordinal) || n.StartsWith("libmono-", StringComparison.Ordinal)) return "Mono";
            if (n == "libil2cpp.so") return "Il2Cpp (Unity)";
        }
        return null;
    }

    private static readonly Dictionary<ulong, string> AuxNames = new()
    {
        [3] = "AT_PHDR", [4] = "AT_PHENT", [5] = "AT_PHNUM", [6] = "AT_PAGESZ", [7] = "AT_BASE", [9] = "AT_ENTRY", [11] = "AT_UID", [12] = "AT_EUID",
        [15] = "AT_PLATFORM", [16] = "AT_HWCAP", [17] = "AT_CLKTCK", [23] = "AT_SECURE", [24] = "AT_BASE_PLATFORM", [25] = "AT_RANDOM", [26] = "AT_HWCAP2",
        [31] = "AT_EXECFN", [33] = "AT_SYSINFO_EHDR", [51] = "AT_MINSIGSTKSZ",
    };

    /// <summary>The auxiliary vector in words: known entries, strings (AT_EXECFN, AT_PLATFORM) read from the core.</summary>
    internal static string AuxText(ElfCoreFile core) => string.Join(", ", core.AuxVector.Where(a => AuxNames.ContainsKey(a.Type)).Select(a =>
        a.Type is 15 or 24 or 31 && core.ReadString(a.Value) is { } text ? $"{AuxNames[a.Type]}={text}" : $"{AuxNames[a.Type]}={Hex(core, a.Value)}"));

    private async Task<DumpReport> SummarizeCore(Session s, ElfCoreFile core, CancellationToken ct)
    {
        var notes = new List<string>();
        string os = IsAndroid(core) ? "Android" : "Linux";
        var runtime = CoreRuntime(core);
        string? execfn = core.Aux(31) is { } fn ? core.ReadString(fn) : null;
        var faulting = core.FaultingThread;
        var process = new ProcessSummary(core.Process?.Pid ?? faulting?.Id, execfn ?? core.MainModule?.Module.Path ?? core.Process?.Name, null, null, false, runtime);
        ExceptionSummary? exception = null;
        ModuleSummary? faultingModule = null;
        ThreadSummary? faultingThread = null;
        int signo = core.Signal?.Number ?? faulting?.Signal ?? 0;
        if (faulting != null)
        {
            faultingThread = (await CoreThreadRows(s, core, [faulting], ct))[0];
            if (signo != 0) exception = await DescribeSignal(s, core, faulting, signo, ct);
            if (faulting.Registers is { } r && core.CoreModules.FirstOrDefault(m => m.Module.Contains(r.Pc)) is { } fm) faultingModule = CoreModuleRow(s, fm);
        }
        notes.Add($"ELF core dump ({os}, {core.ArchName}).");
        if (core.Process is { } p)
            notes.Add($"process: {p.Name ?? "?"} (pid {p.Pid}, parent {p.ParentPid}, uid {p.Uid}, gid {p.Gid}, state {p.State})" + (p.Arguments != null ? $"; arguments: {p.Arguments}" : ""));
        if (core.AuxVector.Count > 0) notes.Add($"auxv: {AuxText(core)}");
        if (signo == 0) notes.Add("No signal: the core was written without one (gcore or a debugger). dump_stack walks any thread.");
        if (core.Registers is { Unwinds: false }) notes.Add($"unwinding not supported for {core.ArchName}: threads and registers only.");
        if (core.CoreModules.Any(m => core.ReadableExtent(m.Module.Base, m.Module.Size) < m.Module.Size / 2))
            notes.Add("The core holds little of the modules' code (by default only their first page): code, unwind data and symbols come from matching files on disk (imageDirectories), matched by GNU build id.");
        if (runtime is ".NET (CoreCLR)" or "Mono")
            notes.Add($"The process hosts {runtime}: managed frames and the managed heap need the Linux DAC, which is not supported; native frames are walked.");
        return new DumpReport(s.Id, "summary")
        {
            Path = core.Path,
            FileSize = core.FileSize,
            System = new SystemSummary(core.ArchName, os, 0, null),
            Process = process,
            Exception = exception,
            Counts = new DumpTotals(core.CoreModules.Count, core.Threads.Count, 0, core.MemoryRanges.Count, core.Segments.Count, core.CapturedBytes, false, 0),
            FaultingModule = faultingModule,
            FaultingThread = faultingThread,
            Issues = core.Issues.Select(i => $"{i.Area}: {i.Message}").ToList(),
            Notes = notes,
        };
    }

    private async Task<ExceptionSummary> DescribeSignal(Session s, ElfCoreFile core, ElfCoreThread thread, int signo, CancellationToken ct)
    {
        var sig = core.Signal;
        string name = ElfCoreFile.SignalName(signo) ?? $"signal {signo}";
        string? code = sig != null ? ElfCoreFile.SignalCodeName(signo, sig.Code) ?? $"si_code {sig.Code}" : null;
        string description = name + (code != null ? $" ({code})" : "");
        if (sig?.Address is { } fault) description += $" at address {Hex(core, fault)}" + (fault < 0x10000 ? " (a null or near-null pointer)" : "");
        if (sig?.SenderPid is { } sender && sig.Code <= 0) description += $", from pid {sender}";
        if (signo == 6) description += ": abort() (a failed assertion, std::terminate or a fatal runtime error)";
        ulong pc = thread.Registers?.Pc ?? 0;
        var location = await Locate(s, pc, false, ct);
        var (insn, bytes, source) = Instruction(s, pc);
        var parameters = sig == null ? new List<string>() : [$"si_signo={sig.Number}", $"si_code={sig.Code}", $"si_errno={sig.Errno}"];
        if (sig?.Address is { } a) parameters.Add($"si_addr={Hex(core, a)}");
        return new ExceptionSummary(signo.ToString(), name, description, Hex(core, pc), thread.Id, location.Module?.FileName, location.Symbol, location.Source,
            insn != null ? $"{insn} ({bytes})" : null, source, parameters, thread.Registers?.Format(), null, false);
    }

    internal ModuleSummary CoreModuleRow(Session s, ElfCoreModule m)
    {
        var core = s.Core!;
        var (path, matches, detail) = FindElf(core, m, s.Directories);
        string state = matches ? "matches" : path != null ? "mismatch" : "missing";
        return new ModuleSummary(m.Module.FileName, m.Module.Path, $"0x{m.Module.Base:X}", $"0x{m.Module.Size:X}", "", null, null, null, null, null,
            state, path, detail, null) { BuildId = m.BuildId };
    }

    private async Task<List<ThreadSummary>> CoreThreadRows(Session s, ElfCoreFile core, IReadOnlyList<ElfCoreThread> threads, CancellationToken ct)
    {
        var faulting = core.FaultingThread;
        var rows = new List<ThreadSummary>();
        foreach (var t in threads)
        {
            ct.ThrowIfCancellationRequested();
            var r = t.Registers;
            var stack = r != null ? core.SegmentAt(r.Sp) : null;
            string? where = r != null ? (await Locate(s, r.Pc, false, ct)).Symbol : null;
            rows.Add(new ThreadSummary(t.Id, null, ReferenceEquals(t, faulting) && (core.Signal != null || t.Signal != 0), 0, 0, "0x0",
                Hex(core, stack?.Start ?? 0), Hex(core, stack?.End ?? 0), r != null ? Hex(core, r.Pc) : null, r != null ? Hex(core, r.Sp) : null, where, null));
        }
        return rows;
    }

    private MemoryRow CoreMemoryRow(ElfCoreFile core, ElfCoreSegment g)
    {
        var module = core.ModuleAt(g.Start);
        bool mapped = core.Files.Any(f => f.Start < g.End && g.Start < f.End);
        return new MemoryRow(Hex(core, g.Start), Hex(core, g.End), $"0x{g.MemorySize:X}", "commit", g.Protection, module != null ? "image" : mapped ? "mapped" : "private",
            module?.FileName, g.FileSize);
    }

    private static ElfCoreThread PickCoreThread(ElfCoreFile core, string? thread)
    {
        if (core.Threads.Count == 0) throw new ToolError(ErrorCode.NotFound, "the core has no threads (no NT_PRSTATUS note).");
        var text = thread?.Trim();
        if (string.IsNullOrEmpty(text) || text.Equals("exception", StringComparison.OrdinalIgnoreCase)) return core.FaultingThread!;
        if (text.StartsWith('#') && int.TryParse(text[1..], out int index))
            return index >= 0 && index < core.Threads.Count ? core.Threads[index]
                : throw new ToolError(ErrorCode.NotFound, $"thread index {index} is out of range (0-{core.Threads.Count - 1}).");
        ulong? id = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? NativeAddress.Number(text) : ulong.TryParse(text, out var dec) ? dec : null;
        if (id is { } v && v <= uint.MaxValue && core.ThreadById((uint)v) is { } t) return t;
        throw new ToolError(ErrorCode.NotFound, $"no thread '{text}' in the core. Threads: {string.Join(", ", core.Threads.Take(40).Select(x => x.Id))}{(core.Threads.Count > 40 ? ", ..." : "")}.",
            "pass a thread id (the LWP id, decimal or 0x hex), '#index' or 'exception'");
    }

    private WalkResult CoreWalk(Session s, ElfCoreFile core, ElfCoreRegisters regs, int maxFrames, CancellationToken ct)
    {
        var stack = core.SegmentAt(regs.Sp);
        var unwinder = new ElfCoreUnwinder(core, regs.Arch, a => core.ModuleAt(a) is { } m ? s.Elf(m).Image : null);
        return unwinder.Walk(regs, stack?.Start ?? 0, stack?.End ?? 0, maxFrames, ct);
    }

    private async Task<StackReport> CoreStack(Session s, ElfCoreFile core, string? thread, int maxFrames, int offset, int limit, CancellationToken ct)
    {
        var t = PickCoreThread(core, thread);
        var regs = t.Registers ?? throw new ToolError(ErrorCode.Unsupported, $"thread {t.Id}: registers of {core.ArchName} are not read.");
        maxFrames = Math.Clamp(maxFrames, 1, StackWalker.MaxFramesLimit);
        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, StackWalker.MaxFramesLimit);
        var walk = await Task.Run(() => CoreWalk(s, core, regs, maxFrames, ct), ct);
        var frames = await Frames(s, walk, offset, limit, ct);
        var notes = new List<string>(walk.Notes);
        if (CoreRuntime(core) is ".NET (CoreCLR)" or "Mono") notes.Add("managed frames are not decoded in an ELF core (the Linux DAC is not supported); JIT code shows as unknown.");
        notes.AddRange(CoreModuleNotes(s));
        return new StackReport(s.Id, t.Id, null, "thread", core.ArchName, regs.Format(), frames, offset, walk.Frames.Count, walk.Stop, 0, null, notes);
    }

    /// <summary>Where each module's image and names came from, for the modules a core session resolved.</summary>
    private static IEnumerable<string> CoreModuleNotes(Session s)
    {
        foreach (var (m, image, detail) in s.ElfLoaded.OrderBy(x => x.Module.Base))
            yield return image == null ? $"{m.FileName}: {detail}"
                : $"{m.FileName}: image {image.Source}{(image.LocalPath != null ? $" ({image.LocalPath})" : "")}; {(image.HasCfi ? ".eh_frame" : "no .eh_frame")}; " +
                  $"{image.Symbols.Count} function symbols; {image.Detail}";
    }

    private async Task<MemoryBytes> CoreReadBytes(Session s, ElfCoreFile core, string address, int length, bool imageFallback, CancellationToken ct)
    {
        ulong va = ParseAddress(core, address);
        length = Math.Clamp(length, 1, MaxReadLength);
        var buffer = new byte[length];
        int n = core.ReadMemory(va, buffer);
        string source = n > 0 ? "dump_memory" : "none";
        string? note = null;
        if (n < length && imageFallback && core.ModuleAt(va + (ulong)n) is { } m && s.Elf(m).Image is { Source: "disk" } image)
        {
            var tmp = new byte[length];
            int k = image.Read(va, tmp);
            if (k > n)
            {
                note = n == 0 ? "not captured in the core; bytes from the module's file: code and read-only data match the process, writable data shows initial values"
                    : $"the core holds {n} bytes here; the rest is from the module's file";
                tmp.AsSpan(n, k - n).CopyTo(buffer.AsSpan(n));
                source = n > 0 ? "dump_memory + module_image (disk)" : "module_image (disk)";
                n = k;
            }
        }
        if (n < length && note == null) note = n == 0 ? "the core holds no memory at this address" : $"the core holds {n} of the {length} bytes; the rest is not captured";
        var location = await Locate(s, va, false, ct);
        var range = core.RangeAt(va);
        var head = new MemoryRead(s.Id, Hex(core, va), length, n, source, location.Symbol ?? location.Note,
            range is { } r ? $"{Hex(core, r.Start)}-{Hex(core, r.End)}" : null, core.SegmentAt(va)?.Protection, Convert.ToHexString(buffer, 0, n), 0, note);
        return new MemoryBytes(head, va, buffer[..n], core.Is64Bit);
    }

    /// <summary>A core's signature: signal name | the first frame that is not raising machinery | the next frames; no signal: hang | top frames.</summary>
    private async Task<DumpSignature> CoreSignature(Session s, ElfCoreFile core, int topFrames, IReadOnlyList<string> skip, CancellationToken ct)
    {
        var thread = core.FaultingThread ?? throw new ToolError(ErrorCode.MalformedInput, "the core has no threads.");
        var regs = thread.Registers ?? throw new ToolError(ErrorCode.Unsupported, $"registers of {core.ArchName} are not read.");
        DateTime time = core.Path.Length > 0 && File.Exists(core.Path) ? File.GetLastWriteTimeUtc(core.Path) : DateTime.UnixEpoch;
        var frames = await SignatureFrames(s, CoreWalk(s, core, regs, BucketWalkFrames, ct), [.. CoreNoiseFrames, .. skip], ct);
        int signo = core.Signal?.Number ?? thread.Signal;
        if (signo == 0)
            return new DumpSignature("no_exception", $"hang | {string.Join(" > ", frames.Take(Math.Max(1, topFrames)).Select(f => f.Label))}", null, null, time);
        if (frames.Count == 0)
        {
            var at = await Locate(s, regs.Pc, false, ct);
            frames.Add((Label(at, regs.Pc), null, Offset(at, regs.Pc)));
        }
        var fault = frames[0];
        string name = ElfCoreFile.SignalName(signo) ?? $"signal {signo}";
        return new DumpSignature("exception", $"{name} | {fault.Label} | {string.Join(" > ", frames.Skip(1).Take(topFrames).Select(f => f.Label))}", fault.Version, fault.Offset, time);
    }
}
