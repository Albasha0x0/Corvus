using System.ComponentModel;
using System.Text;
using Iced.Intel;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Dump;
using NetDecompilerMcp.Native.Dump.Managed;
using NetDecompilerMcp.Native.Msvc;

namespace NetDecompilerMcp.Services;

public sealed partial class MinidumpService
{
    public const int DefaultListLimit = 50;
    public const int MaxListLimit = 1000;
    public const int MaxReadLength = 64 * 1024;

    public sealed record SystemSummary(
        [property: Description("x64, x86, ARM64...")] string Architecture,
        string Os, uint MajorVersion, uint MinorVersion, uint BuildNumber,
        [property: Description("workstation, domain_controller or server.")] string ProductType,
        int Processors, ushort ProcessorLevel, string? CpuVendor, string? ServicePack, string? BuildString);

    public sealed record ProcessSummary(
        uint? ProcessId, string? MainModule, string? CreateTimeUtc, uint? UserSeconds, uint? KernelSeconds,
        [property: Description("Integrity level name (low, medium, high, system...) when recorded.")] string? Integrity,
        [property: Description("A 32-bit process dumped by a 64-bit tool: the 32-bit stacks are not walked.")] bool Wow64,
        [property: Description("Managed runtime loaded in the process (CoreCLR, CLR, Mono) or Il2Cpp; null for none.")] string? Runtime);

    public sealed record ExceptionSummary(
        string Code,
        [property: Description("Symbolic name, e.g. EXCEPTION_ACCESS_VIOLATION; null when unknown.")] string? Name,
        [property: Description("What happened, from the parameters: e.g. 'access violation writing 0x0000000000000000 (a null or near-null pointer)'.")] string Description,
        string Address, uint ThreadId, string? ThreadName,
        string? Module, string? ModuleOffset,
        [property: Description("module!function+0xoffset of the exception address.")] string? Symbol,
        [property: Description("Where the name came from: user, pdb, il2cpp, discovered, export, nearest_export, none.")] string? SymbolSource,
        [property: Description("The instruction at the exception address, disassembled.")] string? Instruction,
        string? InstructionBytes,
        [property: Description("dump_memory, module_image (disk) or module_image (dump_memory); null when the bytes are not available.")] string? InstructionSource,
        IReadOnlyList<string> Parameters,
        [property: Description("Registers of the exception context.")] string? Registers,
        [property: Description("C++ exceptions: the thrown type and its catchable base types, from the ThrowInfo.")] IReadOnlyList<string> ThrownTypes,
        bool Continuable, string? NestedRecord);

    public sealed record ModuleSummary(
        string Name, string Path, string Base, string End, string Size,
        string TimeDateStamp, string? Built, string CheckSum, string? FileVersion,
        string? PdbName, string? PdbGuid, uint? PdbAge,
        [property: Description("matches (a file with this timestamp and size was found), mismatch (a different build) or missing.")] string LocalImage,
        string? LocalPath, string LocalDetail,
        [property: Description("A .NET assembly (from the local file's header); null when unknown.")] bool? Managed);

    public sealed record ThreadSummary(
        uint Id, string? Name, bool Faulting, uint SuspendCount, uint Priority, string Teb,
        [property: Description("Lowest captured stack address.")] string StackStart,
        [property: Description("End of the captured stack.")] string StackEnd,
        uint StackBytes, string? InstructionPointer, string? StackPointer,
        [property: Description("module!function+0xoffset of the instruction pointer.")] string? Location,
        string? StartAddress);

    public sealed record UnloadedModuleSummary(string Name, string Base, string Size, string TimeDateStamp);

    public sealed record MemorySummary(
        [property: Description("Captured memory ranges.")] int Ranges, ulong CapturedBytes,
        [property: Description("A full-memory dump (Memory64List).")] bool FullMemory,
        [property: Description("Regions in the memory info list (VirtualQuery view); 0 when not recorded.")] int Regions);

    public sealed record HandleTypeCount(string Type, int Count);

    public sealed record StreamSummary(int Index, string Type, uint Size, string Rva);

    public sealed record DumpSummary(
        [property: Description("Id for dump_stack and read_dump_memory (the path works too).")] string Id,
        string Path, long FileSize, string TimeUtc,
        [property: Description("MINIDUMP_TYPE flags the dump was written with.")] IReadOnlyList<string> DumpType,
        SystemSummary? System, ProcessSummary Process, ExceptionSummary? Exception,
        [property: Description(".NET runtime state through its DAC (exception with inner chain, threads, heap); null when no managed runtime is loaded.")] ManagedSummary? Managed,
        int ModuleCount, int ModulesOffset, bool ModulesTruncated, IReadOnlyList<ModuleSummary> Modules,
        int ThreadCount, int ThreadsOffset, bool ThreadsTruncated, IReadOnlyList<ThreadSummary> Threads,
        int UnloadedModuleCount, IReadOnlyList<UnloadedModuleSummary> UnloadedModules,
        MemorySummary Memory, int HandleCount, IReadOnlyList<HandleTypeCount> HandleTypes,
        IReadOnlyList<StreamSummary> Streams, IReadOnlyList<string> Comments,
        [property: Description("What the parser could not read (truncation, bad counts, overlapping streams).")] IReadOnlyList<string> Issues,
        IReadOnlyList<string> Notes);

    public sealed record StackFrame(
        int Index, string Address, string StackPointer, string? Module, string? ModuleOffset,
        [property: Description("module!function+0xoffset, or module+0xoffset when the function has no name.")] string? Symbol,
        string? Function,
        [property: Description("user, pdb, il2cpp, discovered, export, nearest_export (a guess) or none.")] string? SymbolSource,
        string? FunctionAddress,
        [property: Description("native, managed (JIT or ReadyToRun code), unloaded_module or unknown.")] string Kind,
        [property: Description("How the frame was found: context, unwind_info, epilog, leaf, machine_frame, frame_pointer, call_target (x86: the return address whose call targets this function), scan (heuristic), or clr (the runtime's own stack walk).")] string Method,
        [property: Description("Found by scanning the stack for a return address: may be a stale value.")] bool Heuristic,
        string? Note,
        [property: Description("Managed frames: the method token, for decompile_member with assembly.")] string? Token = null,
        [property: Description("Managed frames: IL offset of the instruction, when the dump holds the JIT's IL map.")] int? IlOffset = null,
        [property: Description("Managed frames: id of the loaded assembly that is this build (file name and MVID).")] string? Assembly = null,
        [property: Description("Managed frames: match, mismatch (the loaded assembly of that name is another build), or unknown.")] string? BuildCheck = null,
        [property: Description("Managed frames: the C# statement at the IL offset (decompiled with sequence points), for a matching build.")] string? Statement = null);

    public sealed record StackReport(
        string Dump, uint ThreadId, string? ThreadName,
        [property: Description("exception (the context at the exception, like .ecxr) or thread (the context when the dump was written).")] string Context,
        string Architecture, string? Registers,
        int Total, int Offset, bool Truncated, IReadOnlyList<StackFrame> Frames,
        [property: Description("Why the walk ended: end_of_stack, max_frames, stack_not_captured, no_unwind_data, left_the_stack, ...")] string Stop,
        int HeuristicFrames,
        [property: Description("Managed frames: decoded (through the runtime's DAC), off, or the DAC status that kept them identified only (not_found, bitness_mismatch, ...); null without a managed runtime.")] string? Managed,
        [property: Description("Where the names and unwind data of each module came from, and what was not covered.")] IReadOnlyList<string> Notes);

    public sealed record MemoryRead(
        string Dump, string Address, int Requested, int Length,
        [property: Description("dump_memory, module_image (disk) or module_image (dump_memory); none when nothing is readable.")] string Source,
        string? Location, string? Region, string? Protection,
        [property: Description("Hex dump: address, 16 bytes, ASCII.")] string Hex,
        string Bytes, string? Note);

    public Task<DumpSummary> Summarize(string path, string? imageDirectories, int modulesOffset, int modulesLimit, int threadsOffset, int threadsLimit, CancellationToken ct) =>
        Summarize(path, imageDirectories, modulesOffset, modulesLimit, threadsOffset, threadsLimit, new DacRequest(), ct);

    public async Task<DumpSummary> Summarize(string path, string? imageDirectories, int modulesOffset, int modulesLimit, int threadsOffset, int threadsLimit, DacRequest dac,
        CancellationToken ct)
    {
        using var s = Open(path, imageDirectories);
        var d = s.Dump;
        modulesOffset = Math.Max(0, modulesOffset);
        threadsOffset = Math.Max(0, threadsOffset);
        modulesLimit = Math.Clamp(modulesLimit, 1, MaxListLimit);
        threadsLimit = Math.Clamp(threadsLimit, 1, MaxListLimit);
        var notes = new List<string>();

        SystemSummary? system = d.SystemInfo is { } si
            ? new SystemSummary(ArchName(d.Arch, si.ProcessorArchitecture), $"Windows {si.MajorVersion}.{si.MinorVersion}.{si.BuildNumber}" + (si.PlatformId != 2 ? $" (platform {si.PlatformId})" : ""),
                si.MajorVersion, si.MinorVersion, si.BuildNumber, si.ProductType switch { 1 => "workstation", 2 => "domain_controller", 3 => "server", _ => $"type {si.ProductType}" },
                si.Processors, si.ProcessorLevel, si.VendorId, string.IsNullOrEmpty(si.CsdVersion) ? null : si.CsdVersion, d.MiscInfo?.BuildString)
            : null;
        bool wow64 = d.Arch == NativeArch.X64 && d.Modules.Any(m => m.FileName.Equals("wow64cpu.dll", StringComparison.OrdinalIgnoreCase) || m.FileName.Equals("wow64.dll", StringComparison.OrdinalIgnoreCase));
        if (wow64) notes.Add("WoW64 process dumped by a 64-bit tool: threads and stacks are the 64-bit side (wow64cpu); the 32-bit stacks are not walked. A 32-bit tool (procdump -x86 ...) writes a dump with the x86 view.");
        HostsClr(d, out var runtime);
        if (runtime == null && d.Modules.Any(m => m.FileName.Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase))) runtime = "Il2Cpp (Unity)";
        var misc = d.MiscInfo;
        var process = new ProcessSummary(misc?.ProcessId, d.MainModule?.Path, misc?.ProcessCreateTime?.ToString("u"), misc?.ProcessUserSeconds, misc?.ProcessKernelSeconds,
            misc?.ProcessIntegrityLevel is { } il ? IntegrityName(il) : null, wow64, runtime);

        ExceptionSummary? exception = d.Exception != null ? await DescribeException(s, ct) : null;
        var managed = await ManagedSection(s, dac, ct);
        if (exception != null && d.Exception!.Code == ExceptionCodes.ClrException && managed?.Exception is { } thrown)
            exception = exception with { Description = $"CLR exception {thrown.Type}: {Format.Clip(thrown.Message ?? "", 200)} (managed.exception)" };

        var modules = d.Modules.Skip(modulesOffset).Take(modulesLimit).Select(m => ModuleRow(m, s.Directories, d.Arch, s.LoadedImages)).ToList();
        var exceptionThread = d.Exception?.ThreadId;
        var threads = new List<ThreadSummary>();
        foreach (var t in d.Threads.Skip(threadsOffset).Take(threadsLimit))
        {
            ct.ThrowIfCancellationRequested();
            var ctx = d.ReadContext(t.Context);
            string? where = null;
            if (ctx != null) where = (await Locate(s, ctx.Ip, false, ct)).Symbol;
            threads.Add(new ThreadSummary(t.Id, t.Name, t.Id == exceptionThread, t.SuspendCount, t.Priority, Hex(d, t.Teb), Hex(d, t.StackStart), Hex(d, t.StackStart + t.StackSize),
                t.StackSize, ctx != null ? Hex(d, ctx.Ip) : null, ctx != null ? Hex(d, ctx.Sp) : null, where, t.StartAddress is { } sa ? Hex(d, sa) : null));
        }
        if (d.Exception == null) notes.Add("No exception stream: the dump was written without an exception (a hang or on-demand dump). dump_stack walks any thread.");
        if (!d.HasMemory64 && d.Modules.Count > 0) notes.Add("Not a full-memory dump: module code is read from the image files on disk when a matching build is found.");
        var handleTypes = d.Handles.GroupBy(h => h.TypeName ?? "(unknown)").Select(g => new HandleTypeCount(g.Key, g.Count()))
            .OrderByDescending(h => h.Count).ThenBy(h => h.Type, StringComparer.Ordinal).Take(30).ToList();
        return new DumpSummary(s.Id, d.Path, d.FileSize, d.Time.ToString("u"), d.FlagNames, system, process, exception, managed,
            d.Modules.Count, modulesOffset, modulesOffset + modules.Count < d.Modules.Count, modules,
            d.Threads.Count, threadsOffset, threadsOffset + threads.Count < d.Threads.Count, threads,
            d.UnloadedModules.Count, d.UnloadedModules.Take(50).Select(u => new UnloadedModuleSummary(Path.GetFileName(u.Path), Hex(d, u.Base), $"0x{u.Size:X}", $"0x{u.TimeDateStamp:X8}")).ToList(),
            new MemorySummary(d.MemoryRanges.Count, d.CapturedBytes, d.HasMemory64, d.MemoryRegions.Count), d.Handles.Count, handleTypes,
            d.Streams.Where(st => st.Type != 0).Take(64).Select(st => new StreamSummary(st.Index, st.TypeName, st.Size, $"0x{st.Rva:X}")).ToList(),
            d.Comments.Select(c => Format.Clip(c, 2000)).ToList(),
            d.Issues.Select(i => $"{i.Area}: {i.Message}").ToList(), notes);
    }

    internal static ModuleSummary ModuleRow(DumpModule m, IReadOnlyList<string> directories, NativeArch arch, IReadOnlyList<string>? loaded = null)
    {
        var local = DumpImages.Find(m, directories, arch, loaded);
        string state = local.Matches ? "matches" : local.Exists ? "mismatch" : "missing";
        string? built = m.TimeDateStamp is > 0x30000000 and < 0x80000000 ? DateTimeOffset.FromUnixTimeSeconds(m.TimeDateStamp).UtcDateTime.ToString("u") : null;
        var cv = m.CodeView;
        return new ModuleSummary(m.FileName, m.Path, $"0x{m.Base:X}", $"0x{m.End:X}", $"0x{m.Size:X}", $"0x{m.TimeDateStamp:X8}", built, $"0x{m.CheckSum:X8}", m.FileVersion,
            cv?.PdbPath is { Length: > 0 } p ? p : null, cv is { Format: "RSDS" } ? cv.Guid.ToString("D") : null, cv?.Age,
            state, local.Path, local.Detail, local.Matches ? local.IsDotNet : null);
    }

    private async Task<ExceptionSummary> DescribeException(Session s, CancellationToken ct)
    {
        var d = s.Dump;
        var e = d.Exception!;
        var thread = d.ThreadById(e.ThreadId);
        var location = await Locate(s, e.Address, false, ct);
        var (insn, bytes, source) = Instruction(s, e.Address);
        var ctx = d.ReadContext(e.Context);
        return new ExceptionSummary($"0x{e.Code:X8}", ExceptionCodes.Name(e.Code), ExceptionCodes.Describe(e.Code, e.Parameters, d.Is64Bit), Hex(d, e.Address),
            e.ThreadId, thread?.Name, location.Module?.FileName, location.Rva is { } r ? $"0x{r:X}" : null, location.Symbol, location.Source,
            insn, bytes, source, e.Parameters.Select(p => $"0x{p:X}").ToList(), ctx?.Format(),
            e.Code == ExceptionCodes.CxxException ? ThrownTypes(s, e.Parameters) : [], (e.Flags & 1) == 0, e.NestedRecord != 0 ? Hex(d, e.NestedRecord) : null);
    }

    /// <summary>The instruction at <paramref name="address"/>: bytes from dump memory, else from the module image.</summary>
    private (string? Text, string? Bytes, string? Source) Instruction(Session s, ulong address)
    {
        var d = s.Dump;
        if (d.Arch is not (NativeArch.X64 or NativeArch.X86)) return (null, null, null);
        var buffer = new byte[16];
        int n = d.ReadMemory(address, buffer);
        string? source = n > 0 ? "dump_memory" : null;
        if (n < buffer.Length && d.ModuleAt(address) is { } m && s.Code(m) is { Image: { } image } mc)
        {
            var fromImage = new byte[16];
            int k = image.Read((uint)(address - m.Base), fromImage);
            if (k > n)
            {
                fromImage.AsSpan(0, k).CopyTo(buffer);
                n = k;
                source = $"module_image ({mc.Source})";
            }
        }
        if (n == 0) return (null, null, null);
        var decoder = Iced.Intel.Decoder.Create(d.Arch == NativeArch.X64 ? 64 : 32, new ByteArrayCodeReader(buffer, 0, n), address);
        decoder.Decode(out var insn);
        if (insn.IsInvalid) return ("(bad)", Convert.ToHexString(buffer, 0, Math.Min(n, 8)), source);
        var formatter = new MasmFormatter();
        formatter.Options.UppercaseHex = true;
        formatter.Options.SpaceAfterOperandSeparator = true;
        formatter.Options.FirstOperandCharIndex = 7;
        formatter.Options.MemorySizeOptions = MemorySizeOptions.Always;
        var output = new StringOutput();
        formatter.Format(insn, output);
        return (output.ToStringAndReset(), Convert.ToHexString(buffer, 0, insn.Length), source);
    }

    /// <summary>
    /// The thrown C++ type and its catchable bases from the MSVC ThrowInfo (x64: RVAs relative to the throwing image,
    /// parameter 3; x86: pointers), read from dump memory or the module image.
    /// </summary>
    private static List<string> ThrownTypes(Session s, IReadOnlyList<ulong> p)
    {
        var types = new List<string>();
        if (p.Count < 3 || p[0] is not (ExceptionCodes.CxxMagic1 or ExceptionCodes.CxxMagic2 or ExceptionCodes.CxxMagic3 or ExceptionCodes.CxxPure)) return types;
        var d = s.Dump;
        bool x64 = d.Is64Bit;
        ulong imageBase = x64 && p.Count >= 4 ? p[3] : 0;
        ulong throwInfo = p[2];
        if (throwInfo == 0) return types;
        ulong Ptr(ulong value) => x64 ? imageBase + (uint)value : (uint)value;
        if (!TryRead32(s, throwInfo + 12, out uint arrayRef)) return types;
        ulong array = Ptr(arrayRef);
        if (!TryRead32(s, array, out uint count)) return types;
        for (uint i = 0; i < Math.Min(count, 32u); i++)
        {
            if (!TryRead32(s, array + 4 + i * 4, out uint ctRef) || !TryRead32(s, Ptr(ctRef) + 4, out uint tdRef)) break;
            ulong descriptor = Ptr(tdRef);
            var name = new byte[256];
            int n = ReadAny(s, descriptor + (x64 ? 16UL : 8UL), name);
            int end = Array.IndexOf(name, (byte)0, 0, n);
            if (end <= 0) continue;
            var decorated = Encoding.ASCII.GetString(name, 0, end);
            types.Add(MsvcDemangler.DemangleTypeDescriptorName(decorated)?.Name ?? decorated);
        }
        return types;
    }

    private static bool TryRead32(Session s, ulong address, out uint value)
    {
        Span<byte> b = stackalloc byte[4];
        value = 0;
        if (ReadAny(s, address, b) < 4) return false;
        value = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(b);
        return true;
    }

    /// <summary>Dump memory, else the module image (read-only data and code are the same in both).</summary>
    private static int ReadAny(Session s, ulong address, Span<byte> destination)
    {
        int n = s.Dump.ReadMemory(address, destination);
        if (n == destination.Length) return n;
        if (s.Dump.ModuleAt(address) is { } m && s.Code(m).Image is { } image)
        {
            var tmp = new byte[destination.Length];
            int k = image.Read((uint)(address - m.Base), tmp);
            if (k > n)
            {
                tmp.AsSpan(0, k).CopyTo(destination);
                return k;
            }
        }
        return n;
    }

    public Task<StackReport> Stack(string path, string? thread, bool exceptionContext, int maxFrames, int offset, int limit, string? imageDirectories, CancellationToken ct) =>
        Stack(path, thread, exceptionContext, maxFrames, offset, limit, imageDirectories, true, ct);

    public async Task<StackReport> Stack(string path, string? thread, bool exceptionContext, int maxFrames, int offset, int limit, string? imageDirectories, bool managed,
        CancellationToken ct)
    {
        using var s = Open(path, imageDirectories);
        var d = s.Dump;
        var t = PickThread(d, thread);
        DumpContext? ctx = null;
        string contextKind = "thread";
        if (exceptionContext && d.Exception is { } e && e.ThreadId == t.Id && d.ReadContext(e.Context) is { } ec)
        {
            ctx = ec;
            contextKind = "exception";
        }
        ctx ??= d.ReadContext(t.Context) ?? throw new ToolError(ErrorCode.MalformedInput, $"thread {t.Id} has no readable register context in the dump.");
        maxFrames = Math.Clamp(maxFrames, 1, StackWalker.MaxFramesLimit);
        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, StackWalker.MaxFramesLimit);

        var walker = s.Walker();
        var walk = await Task.Run(() => walker.Walk(ctx, t.StackStart, t.StackStart + t.StackSize, maxFrames, ct), ct);
        var notes = new List<string>(walk.Notes);
        var (clrFrames, managedState) = await ManagedFrames(s, t.Id, managed, maxFrames, notes, ct);
        var merged = Merge(walk.Frames, clrFrames);
        if (merged.Count > maxFrames) merged.RemoveRange(maxFrames, merged.Count - maxFrames);
        var frames = await Frames(s, merged, offset, limit, ct);
        if (d.Arch == NativeArch.X64 && d.Modules.Any(m => m.FileName.Equals("wow64cpu.dll", StringComparison.OrdinalIgnoreCase)))
            notes.Add("WoW64 process: this is the 64-bit side of the thread; its 32-bit frames are not walked.");
        notes.AddRange(ModuleNotes(s));
        return new StackReport(s.Id, t.Id, t.Name, contextKind, ArchName(d.Arch, d.SystemInfo?.ProcessorArchitecture ?? 0xFFFF), ctx.Format(),
            merged.Count, offset, offset + frames.Count < merged.Count, frames, walk.Stop, merged.Count(f => f.Managed == null && f.Native!.Heuristic), managedState, notes);
    }

    /// <summary>Frames <paramref name="offset"/>.. of a walk, each named through <see cref="Locate"/>.</summary>
    internal Task<List<StackFrame>> Frames(Session s, WalkResult walk, int offset, int limit, CancellationToken ct) =>
        Frames(s, walk.Frames.Select(f => ((WalkFrame?)f, (ManagedFrame?)null)).ToList(), offset, limit, ct);

    /// <summary>Frames <paramref name="offset"/>.. of a merged walk: managed frames carry the runtime's names, the others are named through <see cref="Locate"/>.</summary>
    private async Task<List<StackFrame>> Frames(Session s, List<(WalkFrame? Native, ManagedFrame? Managed)> walk, int offset, int limit, CancellationToken ct)
    {
        var d = s.Memory;
        var frames = new List<StackFrame>();
        foreach (var ((native, clr), i) in walk.Select((f, i) => (f, i)).Skip(offset).Take(limit))
        {
            if (clr != null)
            {
                frames.Add(ManagedStackFrame(s, i, native, clr, ct));
                continue;
            }
            var f = native!;
            var where = await Locate(s, f.Ip, f.IsReturnAddress, ct);
            if (where.Kind == "managed" && where.Module == null && await MonoFrame(s, i, f, ct) is { } mono)
            {
                frames.Add(mono);
                continue;
            }
            string? note = string.Join("; ", new[] { f.Note, where.Note }.Where(x => !string.IsNullOrEmpty(x)));
            frames.Add(new StackFrame(i, Hex(d, f.Ip), Hex(d, f.Sp), where.Module?.FileName, where.Rva is { } r ? $"0x{r:X}" : null, where.Symbol, where.Function,
                where.Source, where.FunctionAddress is { } fa ? Hex(d, fa) : null, where.Kind, f.Method, f.Heuristic, note.Length > 0 ? note : null));
        }
        return frames;
    }

    /// <summary>Where each module's image and names came from, for the modules a session resolved.</summary>
    internal static IEnumerable<string> ModuleNotes(Session s)
    {
        foreach (var (m, c) in s.Loaded.OrderBy(x => x.Module.Base))
        {
            string names = c.Names is { } n ? n.PdbPath != null ? $"names from {n.PdbPath}" : "names from exports (no matching local PDB)" : "no names";
            if (c.NamesError != null) names += $" ({c.NamesError})";
            yield return $"{m.FileName}: image {c.Source}{(c.LocalPath != null && c.Source == "disk" ? $" ({c.LocalPath})" : "")}; {names}" + (c.Source == "disk" ? "" : $"; {c.Detail}");
        }
    }

    private static DumpThread PickThread(MinidumpFile d, string? thread)
    {
        if (d.Threads.Count == 0) throw new ToolError(ErrorCode.NotFound, "the dump has no thread list.");
        var text = thread?.Trim();
        if (string.IsNullOrEmpty(text) || text.Equals("exception", StringComparison.OrdinalIgnoreCase))
        {
            if (d.Exception is { } e && d.ThreadById(e.ThreadId) is { } faulting) return faulting;
            if (!string.IsNullOrEmpty(text)) throw new ToolError(ErrorCode.NotFound, "the dump has no exception (or its thread is not in the thread list).", "pass a thread id from open_minidump");
            return d.Threads[0];
        }
        if (text.StartsWith('#') && int.TryParse(text[1..], out int index))
            return index >= 0 && index < d.Threads.Count ? d.Threads[index]
                : throw new ToolError(ErrorCode.NotFound, $"thread index {index} is out of range (0-{d.Threads.Count - 1}).");
        ulong? id = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? NativeAddress.Number(text)
            : ulong.TryParse(text, out var dec) ? dec : null;
        if (id is { } v && v <= uint.MaxValue && d.ThreadById((uint)v) is { } t) return t;
        var named = d.Threads.Where(x => x.Name != null && x.Name.Equals(text, StringComparison.OrdinalIgnoreCase)).ToList();
        if (named.Count == 1) return named[0];
        if (named.Count > 1) throw new ToolError(ErrorCode.Ambiguous, $"{named.Count} threads are named '{text}': {string.Join(", ", named.Select(x => x.Id))}.", "pass the thread id");
        throw new ToolError(ErrorCode.NotFound, $"no thread '{text}' in the dump. Threads: {string.Join(", ", d.Threads.Take(40).Select(x => x.Id))}{(d.Threads.Count > 40 ? ", ..." : "")}.",
            "pass a thread id (decimal or 0x hex), '#index', a thread name, or 'exception'");
    }

    public async Task<MemoryRead> ReadMemory(string path, string address, int length, bool imageFallback, CancellationToken ct)
    {
        using var s = Open(path, null);
        var d = s.Dump;
        ulong va = ParseAddress(d, address);
        length = Math.Clamp(length, 1, MaxReadLength);
        var buffer = new byte[length];
        int n = d.ReadMemory(va, buffer);
        string source = n > 0 ? "dump_memory" : "none";
        string? note = null;
        if (n < length && imageFallback && d.ModuleAt(va + (ulong)n) is { } m && s.Code(m) is { Image: { } image } mc && va >= m.Base)
        {
            var tmp = new byte[length];
            int k = image.Read((uint)(va - m.Base), tmp);
            if (k > n)
            {
                note = n == 0 ? $"not captured in the dump; bytes from the module image ({mc.Source}): code and read-only data match the process, writable data shows initial values"
                    : $"the dump holds {n} bytes here; the rest is from the module image ({mc.Source})";
                tmp.AsSpan(n, k - n).CopyTo(buffer.AsSpan(n));
                n = k;
                source = n > 0 && source == "dump_memory" ? $"dump_memory + module_image ({mc.Source})" : $"module_image ({mc.Source})";
            }
        }
        if (n < length && note == null) note = n == 0 ? "the dump holds no memory at this address" : $"the dump holds {n} of the {length} bytes; the rest is not captured";
        var location = await Locate(s, va, false, ct);
        var range = d.RangeAt(va);
        var region = d.RegionAt(va);
        return new MemoryRead(s.Id, Hex(d, va), length, n, source, location.Symbol ?? location.Note,
            range is { } r ? $"{Hex(d, r.Start)}-{Hex(d, r.End)}" : null, region != null ? ProtectName(region.Protect) : null,
            HexDump(va, buffer.AsSpan(0, n), d.Is64Bit), Convert.ToHexString(buffer, 0, n), note);
    }

    private static ulong ParseAddress(MinidumpFile d, string text)
    {
        var t = (text ?? "").Trim();
        if (t.Length == 0) throw new ToolError(ErrorCode.InvalidArgument, "address is empty.", "pass a hex address (0x7FF6...) or module+0xoffset");
        int plus = t.IndexOf('+');
        if (plus > 0)
        {
            string name = t[..plus].Trim();
            var module = d.Modules.Where(m => m.FileName.Equals(name, StringComparison.OrdinalIgnoreCase) || ModuleLabel(m).Equals(name, StringComparison.OrdinalIgnoreCase)).ToList();
            if (module.Count == 0) throw new ToolError(ErrorCode.NotFound, $"no module '{name}' in the dump.", "open_minidump lists the modules");
            if (module.Count > 1) throw new ToolError(ErrorCode.Ambiguous, $"{module.Count} modules are named '{name}'.", "pass the absolute address");
            var off = NativeAddress.Number(t[(plus + 1)..].Trim()) ?? throw new ToolError(ErrorCode.InvalidArgument, $"'{t[(plus + 1)..]}' is not a hex offset.");
            return module[0].Base + off;
        }
        if (d.Modules.FirstOrDefault(m => m.FileName.Equals(t, StringComparison.OrdinalIgnoreCase) || ModuleLabel(m).Equals(t, StringComparison.OrdinalIgnoreCase)) is { } whole)
            return whole.Base;
        return NativeAddress.Number(t) ?? throw new ToolError(ErrorCode.InvalidArgument, $"'{text}' is not an address.", "pass a hex address (0x7FF6...) or module+0xoffset");
    }

    internal static string Hex(IProcessMemory d, ulong v) => d.Is64Bit ? $"0x{v:X}" : $"0x{v & 0xFFFFFFFF:X}";

    internal static string ArchName(NativeArch arch, ushort raw) => arch switch
    {
        NativeArch.X64 => "x64",
        NativeArch.X86 => "x86",
        NativeArch.Arm64 => "ARM64",
        NativeArch.Arm => "ARM",
        _ => $"unknown (processor architecture {raw})",
    };

    private static string IntegrityName(uint rid) => rid switch
    {
        0 => "untrusted",
        0x1000 => "low",
        0x2000 => "medium",
        0x2100 => "medium_plus",
        0x3000 => "high",
        0x4000 => "system",
        0x5000 => "protected_process",
        _ => $"0x{rid:X}",
    };

    internal static string ProtectName(uint protect)
    {
        string basic = (protect & 0xFF) switch
        {
            0x01 => "PAGE_NOACCESS",
            0x02 => "PAGE_READONLY",
            0x04 => "PAGE_READWRITE",
            0x08 => "PAGE_WRITECOPY",
            0x10 => "PAGE_EXECUTE",
            0x20 => "PAGE_EXECUTE_READ",
            0x40 => "PAGE_EXECUTE_READWRITE",
            0x80 => "PAGE_EXECUTE_WRITECOPY",
            0 => "none",
            var x => $"0x{x:X}",
        };
        if ((protect & 0x100) != 0) basic += "|PAGE_GUARD";
        if ((protect & 0x200) != 0) basic += "|PAGE_NOCACHE";
        return basic;
    }

    internal static string HexDump(ulong address, ReadOnlySpan<byte> bytes, bool is64)
    {
        var sb = new StringBuilder();
        for (int line = 0; line < bytes.Length; line += 16)
        {
            ulong at = address + (ulong)line;
            sb.Append(is64 ? $"{at >> 32:X8}`{at & 0xFFFFFFFF:X8}  " : $"{at & 0xFFFFFFFF:X8}  ");
            int n = Math.Min(16, bytes.Length - line);
            for (int i = 0; i < 16; i++)
            {
                sb.Append(i < n ? $"{bytes[line + i]:X2}" : "  ");
                sb.Append(i == 7 ? "-" : " ");
            }
            sb.Append(' ');
            for (int i = 0; i < n; i++)
            {
                byte b = bytes[line + i];
                sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
            }
            sb.Append('\n');
        }
        return sb.ToString();
    }
}
