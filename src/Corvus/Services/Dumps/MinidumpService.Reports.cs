using System.ComponentModel;
using System.Text;
using Iced.Intel;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Managed;
using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Msvc;

namespace Corvus.Services;

public sealed partial class MinidumpService
{
    public const int DefaultListLimit = 50;
    public const int MaxListLimit = 1000;
    public const int MaxReadLength = 64 * 1024;

    /// <summary>open_minidump views: the summary report, then the paged lists.</summary>
    public static readonly string[] Views = ["summary", "modules", "threads", "memory", "unloaded", "changes"];

    public sealed record SystemSummary(
        [property: Description("x64, x86, ARM64...")] string Architecture,
        [property: Description("Windows major.minor.build and product type (workstation, server, domain_controller).")] string Os,
        int Processors, string? BuildString);

    public sealed record ProcessSummary(
        uint? ProcessId, string? MainModule, string? CreateTimeUtc,
        [property: Description("Integrity level name (low, medium, high, system...) when recorded.")] string? Integrity,
        [property: Description("A 32-bit process dumped by a 64-bit tool: the 32-bit stacks are not walked.")] bool Wow64,
        [property: Description("Managed runtime loaded in the process (CoreCLR, CLR, Mono) or AOT; null for none.")] string? Runtime);

    public sealed record ExceptionSummary(
        string Code,
        [property: Description("Symbolic name, e.g. EXCEPTION_ACCESS_VIOLATION; null when unknown.")] string? Name,
        [property: Description("What happened, from the parameters: e.g. 'access violation writing 0x0000000000000000 (a null or near-null pointer)'.")] string Description,
        string Address, uint ThreadId,
        string? Module,
        [property: Description("module!function+0xoffset of the exception address.")] string? Symbol,
        [property: Description("Where the name came from: user, pdb, metadata, discovered, export, nearest_export, none.")] string? SymbolSource,
        [property: Description("The instruction at the exception address, disassembled, then its bytes in parentheses.")] string? Instruction,
        [property: Description("dump_memory, module_image (disk) or module_image (dump_memory); null when the bytes are not available.")] string? InstructionSource,
        IReadOnlyList<string> Parameters,
        [property: Description("Registers of the exception context.")] string? Registers,
        [property: Description("C++ exceptions: the thrown type and its catchable base types, from the ThrowInfo.")] IReadOnlyList<string>? ThrownTypes,
        bool Continuable);

    public record ModuleSummary(
        string Name, string Path, string Base, string Size,
        string TimeDateStamp, string? Built, string? FileVersion,
        string? PdbName, string? PdbGuid, uint? PdbAge,
        [property: Description("matches (a file with this timestamp and size was found), mismatch (a different build) or missing.")] string LocalImage,
        string? LocalPath, string LocalDetail,
        [property: Description("A .NET assembly (from the local file's header); null when unknown.")] bool? Managed)
    {
        [Description("ELF cores: the module's GNU build id, from its header in the core.")] public string? BuildId { get; init; }
    }

    /// <summary>A module row of a list view: the summary with the load path class, the local file's signer and the code comparison.</summary>
    public sealed record CheckedModule(
        string Name, string Path, string Base, string Size,
        string TimeDateStamp, string? Built, string? FileVersion,
        string? PdbName, string? PdbGuid, uint? PdbAge, string LocalImage, string? LocalPath, string LocalDetail, bool? Managed)
        : ModuleSummary(Name, Path, Base, Size, TimeDateStamp, Built, FileVersion, PdbName, PdbGuid, PdbAge, LocalImage, LocalPath, LocalDetail, Managed)
    {
        [Description("network, temp, user_writable, system, program_files or other.")] public string? LoadPath { get; init; }
        [Description("Common name of the local file's signer; null when unsigned or unknown.")] public string? Signer { get; init; }
        [Description("signed, catalog, unsigned, digest_mismatch, invalid, unreadable or unknown.")] public string? SignatureState { get; init; }
        [Description(".text in memory against the matching local file: same, differs, partial or unknown.")] public string? CodeState { get; init; }
        public string? CodeDetail { get; init; }
        [Description("Why the signature state is unknown: no local file, a file over the size limit or an unreadable file.")] public string? SignatureDetail { get; init; }
        [Description("Rebuilt .NET image: readable, partial, unreadable or unknown.")] public string? Metadata { get; init; }
        [Description("Why the metadata is not readable.")] public string? MetadataReason { get; init; }
        [Description("code for a saved code region; null for a module.")] public string? Format { get; init; }
        [Description("Protection of a saved code region.")] public string? Protection { get; init; }
        [Description("Function table entries inside a saved code region; null when unknown.")] public int? EntryCount { get; init; }
        [Description("Entries of a saved code region: N entries or unknown.")] public string? Entries { get; init; }
        [Description("File under outputPath listing the function starts and ends of a saved code region.")] public string? EntriesFile { get; init; }
        [Description("File written under outputPath.")] public string? ImageFile { get; init; }
        [Description("Why no file was written under outputPath.")] public string? ImageReason { get; init; }
        [Description("SHA-256 of the file written under outputPath.")] public string? ImageSha256 { get; init; }
        [Description("Percent of the image's pages the dump held.")] public int? ImageCaptured { get; init; }
        [Description("Rebuild checks of the written image: name, state (ok, partial, failed, skipped, unknown) and detail.")] public IReadOnlyList<Corvus.Native.Dump.Rebuild.RebuildCheck>? ImageChecks { get; init; }
        [Description("Modules the image delay-loads, named from the exports its resolved slots point at; null when none was resolved.")] public IReadOnlyList<string>? DelayImportModules { get; init; }
        [Description("PDB file copied next to the image under outputPath.")] public string? Pdb { get; init; }

        /// <summary>The checked row of <paramref name="m"/>, its checks unset.</summary>
        public static CheckedModule Of(ModuleSummary m) => new(m.Name, m.Path, m.Base, m.Size, m.TimeDateStamp, m.Built, m.FileVersion, m.PdbName, m.PdbGuid, m.PdbAge,
            m.LocalImage, m.LocalPath, m.LocalDetail, m.Managed) { BuildId = m.BuildId };
    }

    public sealed record ThreadSummary(
        uint Id, string? Name, bool Faulting, uint SuspendCount, uint Priority, string Teb,
        [property: Description("Lowest captured stack address.")] string StackStart,
        [property: Description("End of the captured stack.")] string StackEnd,
        string? InstructionPointer, string? StackPointer,
        [property: Description("module!function+0xoffset of the instruction pointer.")] string? Location,
        string? StartAddress);

    public sealed record UnloadedModuleSummary(string Name, string Base, string Size, string TimeDateStamp);

    /// <summary>A region of the address space (VirtualQuery view), or a captured range when the dump has no region list.</summary>
    public record MemoryRow(string Base, string End, string Size,
        [property: Description("commit, reserve or free; null for a captured range without region information.")] string? State,
        string? Protection,
        [property: Description("image, mapped or private.")] string? Type,
        [property: Description("The module whose image holds it.")] string? Module,
        [property: Description("Bytes of it the dump holds; null for a live process or a missing region file.")] ulong? Captured);

    /// <summary>A region row of regionFilter=unbacked: an executable region with no image, and what was found in it.</summary>
    public sealed record UnbackedRegion(string Base, string End, string Size, string? State, string? Protection, string? Type, string? Module, ulong? Captured)
        : MemoryRow(Base, End, Size, State, Protection, Type, Module, Captured)
    {
        [Description("jit (inside runtime code heaps) or unbacked.")] public string? Backing { get; init; }
        [Description("pe (PE header at the start), none, or unknown (bytes not held).")] public string? Header { get; init; }
        [Description("YARA rules that matched.")] public IReadOnlyList<string>? Yara { get; init; }
        [Description("Unbacked with a PE header or a YARA hit.")] public bool? Noteworthy { get; init; }
        [Description("Runtime code heap kinds the region lies in, wholly or partly.")] public string? Detail { get; init; }

        /// <summary>The unbacked row of <paramref name="r"/>, its findings unset.</summary>
        public static UnbackedRegion Of(MemoryRow r) => new(r.Base, r.End, r.Size, r.State, r.Protection, r.Type, r.Module, r.Captured);
    }

    public sealed record DumpTotals(int Modules, int Threads, int UnloadedModules,
        [property: Description("Captured memory ranges.")] int MemoryRanges,
        [property: Description("Regions in the memory info list (VirtualQuery view); 0 when not recorded.")] int MemoryRegions,
        ulong CapturedBytes,
        [property: Description("A full-memory dump (Memory64List).")] bool FullMemory,
        int Handles);

    /// <summary>open_minidump result: report fields in view=summary, paged items in list views.</summary>
    public sealed record DumpReport(
        [property: Description("Id for the other dump tools (the path works too).")] string Id,
        string View)
    {
        public string? Path { get; init; }
        public long? FileSize { get; init; }
        public string? TimeUtc { get; init; }
        [Description("MINIDUMP_TYPE flags the dump was written with.")] public IReadOnlyList<string>? DumpType { get; init; }
        public SystemSummary? System { get; init; }
        public ProcessSummary? Process { get; init; }
        public ExceptionSummary? Exception { get; init; }
        [Description(".NET runtime state through its DAC (exception with inner chain, threads, heap); absent without a managed runtime.")] public ManagedSummary? Managed { get; init; }
        [Description("Rows each list view holds.")] public DumpTotals? Counts { get; init; }
        [Description("The module holding the exception address.")] public ModuleSummary? FaultingModule { get; init; }
        public ThreadSummary? FaultingThread { get; init; }
        [Description("Handles per type, most first (up to 10).")] public IReadOnlyList<string>? HandleTypes { get; init; }
        [Description("What the parser could not read (truncation, bad counts, overlapping streams).")] public IReadOnlyList<string>? Issues { get; init; }
        public IReadOnlyList<string>? Notes { get; init; }
        [Description("List views: module, thread, memory, unloaded module or change rows.")] public IReadOnlyList<object>? Items { get; init; }
        public int? Offset { get; init; }
        public int? Total { get; init; }
    }

    public sealed record StackFrame(
        int Index, string Address, string StackPointer, string? Module, string? ModuleOffset,
        [property: Description("module!function+0xoffset, or module+0xoffset when the function has no name.")] string? Symbol,
        string? Function,
        [property: Description("user, pdb, metadata, discovered, export, nearest_export (a guess) or none.")] string? SymbolSource,
        string? FunctionAddress,
        [property: Description("native, managed (JIT or ReadyToRun code), unloaded_module or unknown.")] string Kind,
        [property: Description("How the frame was found: context, unwind_info, epilog, leaf, machine_frame, frame_data (PDB), frame_pointer, call_target (x86: the return address whose call targets this function), scan (heuristic), or clr (the runtime's own stack walk).")] string Method,
        [property: Description("derived (frame pointer chain, x86 call target) or inferred (a stack scan or a frame chained from one, may be stale; or a nearest-export name); absent when unwind data or the runtime observed it.")] string? Basis,
        string? Note,
        [property: Description("Managed frames: the method token, for decompile_member with assembly.")] string? Token = null,
        [property: Description("Managed frames: IL offset of the instruction, when the dump holds the JIT's IL map.")] int? IlOffset = null,
        [property: Description("Managed frames: id of the loaded assembly that is this build (file name and MVID).")] string? Assembly = null,
        [property: Description("Managed frames: match, mismatch (the loaded assembly of that name is another build), or unknown.")] string? BuildCheck = null,
        [property: Description("Managed frames: the C# statement at the IL offset (decompiled with sequence points), for a matching build.")] string? Statement = null);

    public sealed record StackReport(
        string Dump, uint ThreadId, string? ThreadName,
        [property: Description("exception (the context at the exception, like .ecxr), thread (the context when the dump was written), or unknown (the dump holds no register context for the thread).")] string Context,
        string Architecture, string? Registers,
        IReadOnlyList<StackFrame> Items, int Offset, int Total,
        [property: Description("Why the walk ended: end_of_stack, max_frames, stack_not_captured, no_unwind_data, left_the_stack, ...")] string Stop,
        [property: Description("Frames found by scanning the stack, or chained from a frame pointer a scan guessed (basis inferred).")] int ScannedFrames,
        [property: Description("Managed frames: decoded (through the runtime's DAC), off, or the DAC status that kept them identified only (not_found, bitness_mismatch, ...); null without a managed runtime.")] string? Managed,
        [property: Description("Where the names and unwind data of each module came from, and what was not covered.")] IReadOnlyList<string> Notes);

    /// <summary>read_dump_memory: a page of the bytes read, as hex (offset counts bytes from address).</summary>
    public sealed record MemoryRead(
        string Dump, string Address, int Requested,
        [property: Description("Bytes readable from address (fewer than requested where neither the dump nor the image holds them).")] int Length,
        [property: Description("dump_memory, module_image (disk) or module_image (dump_memory); none when nothing is readable.")] string Source,
        string? Location, string? Region, string? Protection,
        [property: Description("The page's bytes as hex.")] string Code,
        [property: Description("Bytes from address where the page starts.")] int Offset,
        string? Note)
    {
        [Description("Byte offset of the next page; absent on the last.")] public int? NextOffset { get; init; }
        [Description("Address of the next page: the same call with address=nextAddress continues too.")] public string? NextAddress { get; init; }
    }

    /// <summary>The bytes of a read and how to label them.</summary>
    internal sealed record MemoryBytes(MemoryRead Head, ulong Va, byte[] Data, bool Is64);

    public Task<DumpReport> Summarize(string path, string? imageDirectories, CancellationToken ct) => Summarize(path, imageDirectories, new DacRequest(), ct);

    /// <summary>The summary view: exception, faulting module and thread, .NET state, counts; the lists are the other views.</summary>
    public async Task<DumpReport> Summarize(string path, string? imageDirectories, DacRequest dac, CancellationToken ct)
    {
        using var s = Open(path, imageDirectories);
        if (s.Core is { } core) return await SummarizeCore(s, core, dac, ct);
        if (s.Regions is { } regions) return SummarizeRegions(s, regions);
        var d = s.Dump;
        var notes = new List<string>();

        SystemSummary? system = d.SystemInfo is { } si
            ? new SystemSummary(ArchName(d.Arch, si.ProcessorArchitecture), $"Windows {si.MajorVersion}.{si.MinorVersion}.{si.BuildNumber}" + (si.PlatformId != 2 ? $" (platform {si.PlatformId})" : "") + " " +
                (si.ProductType switch { 1 => "workstation", 2 => "domain_controller", 3 => "server", _ => $"type {si.ProductType}" }),
                si.Processors, d.MiscInfo?.BuildString)
            : null;
        bool wow64 = IsWow64Process(d);
        HostsClr(d, out var runtime);
        if (runtime == null && d.Modules.Any(m => m.FileName.Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase))) runtime = "AOT";
        var misc = d.MiscInfo;
        var process = new ProcessSummary(misc?.ProcessId, d.MainModule?.Path, misc?.ProcessCreateTime?.ToString("u"),
            misc?.ProcessIntegrityLevel is { } il ? IntegrityName(il) : null, wow64, runtime);

        ExceptionSummary? exception = d.Exception != null ? await DescribeException(s, ct) : null;
        var managed = await ManagedSection(s, dac, ct);
        if (exception != null && d.Exception!.Code == ExceptionCodes.ClrException && managed?.Exception is { } thrown)
            exception = exception with { Description = $"CLR exception {thrown.Type}: {Format.Clip(thrown.Message ?? "", 200)} (managed.exception)" };

        ModuleSummary? faultingModule = d.Exception is { } ex && d.ModuleAt(ex.Address) is { } fm ? ModuleRow(fm, s.Directories, d.Arch, s.LoadedImages) : null;
        ThreadSummary? faultingThread = null;
        int sides32 = 0;
        if (d.Exception is { } e2 && d.ThreadById(e2.ThreadId) is { } ft)
        {
            var (rows, sides) = await ThreadRows(s, [ft], wow64, ct);
            (faultingThread, sides32) = (rows[0], sides);
        }
        if (wow64)
            notes.Add(sides32 > 0 || d.Threads.Take(8).Any(t => Wow64.Thread(d, t.Teb) != null)
                ? "WoW64 process dumped by a 64-bit tool: thread locations are the 32-bit side, from the x86 context WoW64 saved; dump_stack walks both sides."
                : "WoW64 process dumped by a 64-bit tool: the 32-bit thread contexts are not in the dump, so threads show the 64-bit side; " +
                  "a full-memory dump or procdump -x86 holds them.");
        if (d.Exception == null) notes.Add("No exception stream (a hang or on-demand dump); dump_stack walks any thread.");
        notes.AddRange(d.Comments.Select(c => "comment: " + Format.Clip(c, 2000)));
        if (!d.HasMemory64 && d.Modules.Count > 0) notes.Add("Not a full-memory dump: module code is read from the image files on disk when a matching build is found.");
        var handleTypes = d.Handles.GroupBy(h => h.TypeName ?? "(unknown)").Select(g => (Type: g.Key, Count: g.Count()))
            .OrderByDescending(h => h.Count).ThenBy(h => h.Type, StringComparer.Ordinal).Take(10).Select(h => $"{h.Type} {h.Count}").ToList();
        return new DumpReport(s.Id, "summary")
        {
            Path = d.Path,
            FileSize = d.FileSize,
            TimeUtc = d.Time.ToString("u"),
            DumpType = d.FlagNames,
            System = system,
            Process = process,
            Exception = exception,
            Managed = managed,
            Counts = new DumpTotals(d.Modules.Count, d.Threads.Count, d.UnloadedModules.Count, d.MemoryRanges.Count, d.MemoryRegions.Count, d.CapturedBytes, d.HasMemory64, d.Handles.Count),
            FaultingModule = faultingModule,
            FaultingThread = faultingThread,
            HandleTypes = handleTypes,
            Issues = d.Issues.Select(i => $"{i.Area}: {i.Message}").ToList(),
            Notes = notes,
        };
    }

    private static bool IsWow64Process(MinidumpFile d) =>
        d.Arch == NativeArch.X64 && d.Modules.Any(m => m.FileName.Equals("wow64cpu.dll", StringComparison.OrdinalIgnoreCase) || m.FileName.Equals("wow64.dll", StringComparison.OrdinalIgnoreCase));

    /// <summary>Which modules view=modules or save_modules rebuild and how; <see cref="Parse"/> checks the option text.</summary>
    public sealed record ModuleOptions(string Module, OutputLayout Layout, ImportMode Imports, BaseMode Base, string Symbols = "none")
    {
        /// <summary>The defaults: every listed module, file layout, imports restored, loaded base.</summary>
        public static ModuleOptions Default { get; } = new("all", OutputLayout.File, ImportMode.Restore, BaseMode.Loaded);

        /// <summary>The options of the given texts, null or blank meaning the default; rejects a value outside the documented set (InvalidArgument).</summary>
        public static ModuleOptions Parse(string? module, string? layout, string? imports, string? @base, string? symbols = null)
        {
            var sym = string.IsNullOrWhiteSpace(symbols) ? "none" : symbols.Trim().ToLowerInvariant();
            if (sym is not ("none" or "local" or "download"))
                throw new ToolError(ErrorCode.InvalidArgument, $"symbols '{symbols}' is not none, local or download.", "pass symbols as none, local or download");
            var m = string.IsNullOrWhiteSpace(module) ? "all" : module.Trim();
            return new ModuleOptions(m,
                Choice("layout", layout, OutputLayout.File, OutputLayout.Mapped),
                Choice("imports", imports, ImportMode.Restore, ImportMode.Keep),
                Choice("base", @base, BaseMode.Loaded, BaseMode.Preferred), sym);
        }

        private static T Choice<T>(string name, string? value, T first, T second) where T : struct, Enum
        {
            var v = string.IsNullOrWhiteSpace(value) ? first.ToString().ToLowerInvariant() : value.Trim().ToLowerInvariant();
            var a = first.ToString().ToLowerInvariant();
            var b = second.ToString().ToLowerInvariant();
            if (v == a) return first;
            if (v == b) return second;
            throw new ToolError(ErrorCode.InvalidArgument, $"{name} '{value}' is not {a} or {b}.", $"pass {name} as {a} or {b}");
        }
    }

    /// <summary>Modules from <paramref name="offset"/>, with whether a matching image is here and the metadata state of each .NET image.</summary>
    /// <remarks>With <paramref name="outputPath"/>, the selected images go once to that new or empty folder, returned as Folder, rebuilt as <paramref name="rebuild"/> says (default: all listed modules); the rows are every listed module then every other written image, whatever <paramref name="offset"/> and <paramref name="limit"/> say, and Total counts them; a core file refuses it.</remarks>
    public (string Id, IReadOnlyList<CheckedModule> Rows, int Total, string? Folder) Modules(string path, string? imageDirectories, int offset, int limit, string? outputPath = null, CancellationToken ct = default, ModuleOptions? rebuild = null)
    {
        using var s = Open(path, imageDirectories);
        if (s.Core is { } core)
        {
            if (outputPath != null)
                throw new ToolError(ErrorCode.Unsupported, "A core file has no rebuilt module images.", "open_minidump view=modules without outputPath, or read_dump_memory at a module base");
            return (s.Id, core.CoreModules.Skip(Math.Max(0, offset)).Take(Math.Clamp(limit, 1, MaxListLimit))
                .Select(m => CheckedModule.Of(CoreModuleRow(s, m)) with { LoadPath = ModuleChecks.PathClass(m.Module.Path) }).ToList(), core.CoreModules.Count, null);
        }
        var d = s.Memory;
        if (outputPath != null && (rebuild ?? ModuleOptions.Default).Module.Equals("code", StringComparison.OrdinalIgnoreCase))
        {
            var codeRoot = SafeFile.Output(outputPath);
            if (File.Exists(codeRoot) || Directory.Exists(codeRoot) && Directory.EnumerateFileSystemEntries(codeRoot).Any())
                throw new ToolError(ErrorCode.Conflict, $"outputPath needs a new or empty folder: {codeRoot}.", "pass outputPath as a new folder, e.g. <dump>-modules");
            var codeRows = SaveCodeRegions(d, codeRoot, ct);
            return (s.Id, codeRows, codeRows.Count, codeRoot);
        }
        // A writing call reports every module in one order, so no page is cut here.
        var page = outputPath != null ? d.Modules.ToList() : d.Modules.Skip(Math.Max(0, offset)).Take(Math.Clamp(limit, 1, MaxListLimit)).ToList();
        List<(RebuiltModule Module, WrittenModule Written)>? saved = null;
        string? folder = null;
        var pdbs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (outputPath != null)
        {
            var save = rebuild ?? ModuleOptions.Default;
            var root = SafeFile.Output(outputPath);
            if (File.Exists(root) || Directory.Exists(root) && Directory.EnumerateFileSystemEntries(root).Any())
                throw new ToolError(ErrorCode.Conflict, $"outputPath needs a new or empty folder: {root}.", "pass outputPath as a new folder, e.g. <dump>-modules");
            var targets = ModuleRebuild.Select(d, save.Module, ct);
            if (targets.Count == 0)
                throw new ToolError(ErrorCode.NotFound, $"No module matches '{save.Module}'.", "pass modules as a listed file name, a 0x address, all or unlisted");
            var options = RebuildOptions.Default with { Layout = save.Layout, Imports = save.Imports, Base = save.Base };
            var rebuilt = targets.Select(t => ModuleRebuild.Rebuild(d, t, options, ct)).ToList();
            var written = ModuleWriter.WriteAll(rebuilt, root);
            var withSymbols = SaveSymbols(rebuilt, written, root, save.Symbols,
                s.Directories.Count == 0 ? null : string.Join(System.IO.Path.PathSeparator, s.Directories), ct);
            rebuilt = [.. withSymbols.Select(x => x.Module)];
            pdbs = withSymbols.Where(x => x.Pdb != null).ToDictionary(x => x.File!, x => x.Pdb!, StringComparer.OrdinalIgnoreCase);
            saved = [.. rebuilt.Zip(written)];
            folder = root;
        }
        var rows = page.Select(m =>
        {
            ct.ThrowIfCancellationRequested();
            var row = Checked(s, m);
            if (saved?.Where(x => x.Module.Target.Base == m.Base).Cast<(RebuiltModule Module, WrittenModule Written)?>().FirstOrDefault() is { } hit)
            {
                var (r, w) = hit;
                if (w.File == null)
                {
                    var skippedState = DumpManagedMetadata.Inspect(d, m, w.Reason);
                    return row with { Metadata = skippedState?.State, MetadataReason = skippedState?.Reason, ImageReason = w.Reason };
                }
                return row with
                {
                    Metadata = r.Metadata, MetadataReason = r.MetadataReason, ImageFile = w.File,
                    ImageSha256 = r.Sha256, ImageCaptured = r.CapturedPercent, ImageChecks = r.Checks, DelayImportModules = DelayModules(r),
                };
            }
            var state = DumpManagedMetadata.Inspect(d, m);
            return row with { Metadata = state?.State, MetadataReason = state?.Reason };
        }).ToList();
        if (saved != null)
            rows.AddRange(saved.Where(x => x.Module.Target.Origin != ModuleOrigin.Listed || !page.Any(m => m.Base == x.Module.Target.Base))
                .Select(x => SavedRow(s, x.Module, x.Written)));
        if (pdbs.Count > 0)
            for (int i = 0; i < rows.Count; i++)
                if (rows[i].ImageFile is { } f && pdbs.TryGetValue(f, out var pdb)) rows[i] = rows[i] with { Pdb = pdb };
        return (s.Id, rows, saved != null ? rows.Count : d.Modules.Count, folder);
    }

    // The distinct modules of the delay-load slots named from exports; null
    // when none.
    private static IReadOnlyList<string>? DelayModules(RebuiltModule r) =>
        r.DelayImportNames is { Count: > 0 } names
            ? [.. names.Select(n => n.Name.Contains('!') ? n.Name[..n.Name.IndexOf('!')] : n.Name).Distinct(StringComparer.OrdinalIgnoreCase)]
            : null;

    /// <summary>
    /// Adds a symbols check to each written module and, for local or download, copies the PDB its CodeView record names
    /// next to the module in <paramref name="root"/>. Returns the modules in order with the file and PDB written (null for none);
    /// a PDB that is not found, is of another build or does not fit is reported as unknown with the reason.
    /// </summary>
    public static IReadOnlyList<(RebuiltModule Module, string? File, string? Pdb)> SaveSymbols(IReadOnlyList<RebuiltModule> rebuilt,
        IReadOnlyList<WrittenModule> written, string root, string symbols, string? imageDirectories, CancellationToken ct)
    {
        var result = new List<(RebuiltModule, string?, string?)>();
        for (int i = 0; i < rebuilt.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var m = rebuilt[i];
            var file = written[i].File;
            if (file == null || m.Bytes == null) { result.Add((m, file, null)); continue; }
            string? pdb = null;
            RebuildCheck check;
            if (symbols == "none")
                check = RebuildCheck.Skipped("symbols", "symbols=none");
            else
            {
                var found = ModuleSymbols.Find(m.Bytes, imageDirectories, symbols == "download", ct);
                if (found.PdbPath == null)
                    check = RebuildCheck.Unknown("symbols", $"{found.Status}: {found.Reason}");
                else
                    check = CopyPdb(found.PdbPath, root, out pdb);
            }
            result.Add((m with { Checks = [.. m.Checks, check] }, file, pdb));
        }
        return result;
    }

    private static RebuildCheck CopyPdb(string source, string root, out string? name)
    {
        name = null;
        try
        {
            var length = new FileInfo(source).Length;
            if (length > ModuleRebuild.MaxImageBytes)
                return RebuildCheck.Unknown("symbols", $"the PDB is over the {ModuleRebuild.MaxImageBytes >> 20} MB limit");
            var target = System.IO.Path.GetFileName(source);
            if (File.Exists(System.IO.Path.Combine(root, target)))
                return RebuildCheck.Unknown("symbols", $"{target} is already in the folder");
            SafeFile.WriteUnderRoot(root, target, File.ReadAllBytes(source), overwrite: false);
            name = target;
            return RebuildCheck.Ok("symbols", target);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ToolError)
        {
            return RebuildCheck.Unknown("symbols", "the PDB could not be copied: " + e.Message);
        }
    }

    /// <summary>Writes each code region as code-&lt;base&gt;.bin with code-&lt;base&gt;.txt listing the function table entries inside it; one row per region.</summary>
    /// <remarks>A source without a function table stream lists the entries as unknown; limits and sources without a region list come back as a row naming them.</remarks>
    internal static List<CheckedModule> SaveCodeRegions(IProcessMemory memory, string root, CancellationToken ct)
    {
        var set = CodeRegions.Read(memory, ct);
        if (set.Regions.Count == 0 && set.Notes.Count == 0)
            throw new ToolError(ErrorCode.NotFound, "No executable region without an image is held.", "pass modules as a listed file name, a 0x address, all or unlisted");
        // No stream and an unreadable stream both leave the entries unknown.
        string unknown = "the source has no function table stream";
        List<RegisteredFunction>? entries = null;
        if (memory is MinidumpFile dump)
        {
            var stream = MinidumpFunctionTables.Read(dump, out var reason);
            if (stream != null)
                entries = stream.Tables.SelectMany(t => t.Functions).OrderBy(f => f.Begin).ToList();
            else if (reason != null)
                unknown = reason;
        }
        Directory.CreateDirectory(root);
        var rows = new List<CheckedModule>();
        foreach (var r in set.Regions)
        {
            ct.ThrowIfCancellationRequested();
            var inside = entries?.Where(f => f.Begin >= r.Base && f.Begin - r.Base < r.Size).ToList();
            var name = $"code-{r.Base:X}";
            SafeFile.WriteUnderRoot(root, name + ".bin", r.Bytes, overwrite: false);
            var text = new StringBuilder();
            if (inside == null)
                text.Append($"unknown: {unknown}\n");
            else
            {
                text.Append($"{inside.Count} entries\n");
                foreach (var f in inside)
                    text.Append($"0x{f.Begin:X} 0x{f.End:X}\n");
            }
            SafeFile.WriteUnderRoot(root, name + ".txt", Encoding.UTF8.GetBytes(text.ToString()), overwrite: false);
            var count = inside == null ? "unknown" : $"{inside.Count} entries";
            var protection = ProtectName(r.Protect);
            rows.Add(new CheckedModule(name + ".bin", "", $"0x{r.Base:X}", $"0x{r.Size:X}", "", null, null, null, null, null, "missing", null,
                $"code region, {protection}, {r.CapturedPercent}% captured, {count}", null)
            {
                Format = "code", Protection = protection, ImageFile = name + ".bin", ImageCaptured = r.CapturedPercent,
                EntryCount = inside?.Count, Entries = count, EntriesFile = name + ".txt",
            });
        }
        // Each row already carries its captured percent.
        var notes = set.Notes.Where(n => !n.Contains("captured-page map", StringComparison.Ordinal)).ToList();
        if (notes.Count > 0)
            rows.Add(new CheckedModule("code", "", "", "", "", null, null, null, null, null, "missing", null, "code regions", null) { Format = "code", ImageReason = string.Join(" ", notes) });
        return rows;
    }

    /// <summary>The row of a written module that is not on the listed page: its file, SHA-256, captured percent, checks and reason.</summary>
    private static CheckedModule SavedRow(Session s, RebuiltModule r, WrittenModule w)
    {
        var t = r.Target;
        var listed = t.Origin == ModuleOrigin.Listed ? s.Memory.Modules.FirstOrDefault(m => m.Base == t.Base) : null;
        var row = listed != null ? Checked(s, listed)
            : new CheckedModule(t.Name, t.Path ?? "", $"0x{t.Base:X}", $"0x{t.Size:X}", "", null, null, null, null, null, "missing", null,
                t.Origin == ModuleOrigin.Managed ? "in-memory assembly" : "found outside the module list", null);
        return row with
        {
            Metadata = r.Metadata, MetadataReason = r.MetadataReason, ImageFile = w.File, ImageReason = w.Reason,
            ImageSha256 = r.Sha256, ImageCaptured = w.File != null ? r.CapturedPercent : null, ImageChecks = w.File != null ? r.Checks : null,
            DelayImportModules = w.File != null ? DelayModules(r) : null,
        };
    }

    /// <summary>The module row with its load path class, the local file's signer and the code sections compared with that file.</summary>
    internal static CheckedModule Checked(Session s, DumpModule m)
    {
        var row = CheckedModule.Of(ModuleRow(m, s.Directories, s.Memory.Arch, s.LoadedImages));
        var signature = row.LocalImage != "missing" && row.LocalPath != null ? ModuleChecks.Signature(row.LocalPath) : new ModuleSignature(null, "unknown");
        CodeComparison code = row.LocalImage switch
        {
            "matches" when s.Code(m) is { Source: "disk", Image: { } image } => ModuleChecks.CompareCode(s.Memory, m, image),
            "matches" => new CodeComparison("unknown", "the local file could not be read"),
            "mismatch" => new CodeComparison("unknown", "the local file is another build"),
            _ => new CodeComparison("unknown", "no local file"),
        };
        return row with
        {
            LoadPath = ModuleChecks.PathClass(m.Path), Signer = signature.Signer, SignatureState = signature.State,
            SignatureDetail = signature.State == "unknown" ? UnknownSignatureReason(row) : null, CodeState = code.State, CodeDetail = code.Detail,
        };
    }

    /// <summary>Why the local file's signature could not be read, from the row's local file and its size.</summary>
    private static string UnknownSignatureReason(CheckedModule row)
    {
        if (row.LocalImage == "missing" || row.LocalPath == null) return "no local file";
        try
        {
            var info = new FileInfo(row.LocalPath);
            if (!info.Exists) return "the local file could not be read";
            if (info.Length > ModuleChecks.MaxSignedFile) return $"the local file is over the {ModuleChecks.MaxSignedFile >> 20} MB limit";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { }
        return "the local file could not be read as a PE image";
    }

    /// <summary>Threads from <paramref name="offset"/>, each instruction pointer named; for WoW64 the 32-bit side where the dump holds it.</summary>
    public async Task<(string Id, IReadOnlyList<ThreadSummary> Rows, int Total)> Threads(string path, string? imageDirectories, int offset, int limit, CancellationToken ct)
    {
        using var s = Open(path, imageDirectories);
        if (s.Core is { } core)
            return (s.Id, await CoreThreadRows(s, core, core.Threads.Skip(Math.Max(0, offset)).Take(Math.Clamp(limit, 1, MaxListLimit)).ToList(), ct), core.Threads.Count);
        var d = s.Dump;
        var (rows, _) = await ThreadRows(s, d.Threads.Skip(Math.Max(0, offset)).Take(Math.Clamp(limit, 1, MaxListLimit)).ToList(), IsWow64Process(d), ct);
        return (s.Id, rows, d.Threads.Count);
    }

    /// <summary>The ids of the threads whose register context the dump does not hold (their registers are unknown); empty when all are readable.</summary>
    public IReadOnlyList<uint> ThreadsWithoutContext(string path)
    {
        using var s = Open(path, null);
        if (s.Core != null) return [];
        var d = s.Dump;
        return d.Threads.Where(t => d.ReadContext(t.Context) == null && Wow64.Thread(d, t.Teb) == null).Select(t => t.Id).ToList();
    }

    private async Task<(List<ThreadSummary> Rows, int Sides32)> ThreadRows(Session s, IReadOnlyList<DumpThread> threads, bool wow64, CancellationToken ct)
    {
        var d = s.Dump;
        var rows = new List<ThreadSummary>();
        int sides32 = 0;
        foreach (var t in threads)
        {
            ct.ThrowIfCancellationRequested();
            var ctx = d.ReadContext(t.Context);
            if (wow64 && Wow64.Thread(d, t.Teb) is { } side)
            {
                ctx = side.Context;
                sides32++;
            }
            string? where = ctx != null ? (await Locate(s, ctx.Ip, false, ct)).Symbol : null;
            rows.Add(new ThreadSummary(t.Id, t.Name, t.Id == d.Exception?.ThreadId, t.SuspendCount, t.Priority, Hex(d, t.Teb), Hex(d, t.StackStart), Hex(d, t.StackStart + t.StackSize),
                ctx != null ? Hex(d, ctx.Ip) : null, ctx != null ? Hex(d, ctx.Sp) : null, where, t.StartAddress is { } sa ? Hex(d, sa) : null));
        }
        return (rows, sides32);
    }

    /// <summary>Memory regions (VirtualQuery view) with the bytes the dump holds of each; captured ranges when no region list was recorded.</summary>
    public (string Id, IReadOnlyList<MemoryRow> Rows, int Total) Memory(string path, int offset, int limit)
    {
        using var s = Open(path, null);
        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, MaxListLimit);
        if (s.Core is { } core) return (s.Id, core.Segments.Skip(offset).Take(limit).Select(g => CoreMemoryRow(core, g)).ToList(), core.Segments.Count);
        if (s.Regions is { } regions)
            return (s.Id, regions.Regions.Skip(offset).Take(limit).Select(r => new MemoryRow(Hex(regions, r.Base), Hex(regions, r.End), $"0x{r.Size:X}", null,
                r.Protect != 0 ? ProtectName(r.Protect) : null, null, regions.ModuleAt(r.Base)?.FileName, r.Missing ? null : r.Held)).ToList(), regions.Regions.Count);
        var d = s.Dump;
        if (d.MemoryRegions.Count > 0)
            return (s.Id, d.MemoryRegions.Skip(offset).Take(limit).Select(r => RegionRow(d, r, Captured(d.MemoryRanges, r.Base, r.Base + r.Size))).ToList(), d.MemoryRegions.Count);
        return (s.Id, d.MemoryRanges.Skip(offset).Take(limit).Select(r => new MemoryRow(Hex(d, r.Start), Hex(d, r.End), $"0x{r.Size:X}", null, null, null, d.ModuleAt(r.Start)?.FileName, r.Size)).ToList(),
            d.MemoryRanges.Count);
    }

    internal static MemoryRow RegionRow(IProcessMemory p, DumpMemoryRegion r, ulong? captured) =>
        new(Hex(p, r.Base), Hex(p, r.Base + r.Size), $"0x{r.Size:X}", StateName(r.State), r.State == 0x1000 ? ProtectName(r.Protect) : null, TypeName(r.Type),
            r.State == 0x10000 ? null : p.ModuleAt(r.Base)?.FileName, captured);

    /// <summary>Bytes of [start, end) inside the sorted, non-overlapping captured ranges.</summary>
    private static ulong Captured(IReadOnlyList<DumpMemoryRange> ranges, ulong start, ulong end)
    {
        int lo = 0, hi = ranges.Count;
        while (lo < hi)
        {
            int mid = (lo + hi) >>> 1;
            if (ranges[mid].End <= start) lo = mid + 1; else hi = mid;
        }
        ulong bytes = 0;
        for (int i = lo; i < ranges.Count && ranges[i].Start < end; i++)
            bytes += Math.Min(end, ranges[i].End) - Math.Max(start, ranges[i].Start);
        return bytes;
    }

    public (string Id, IReadOnlyList<UnloadedModuleSummary> Rows, int Total) Unloaded(string path, int offset, int limit)
    {
        using var s = Open(path, null);
        var d = s.Memory;
        return (s.Id, d.UnloadedModules.Skip(Math.Max(0, offset)).Take(Math.Clamp(limit, 1, MaxListLimit))
            .Select(u => new UnloadedModuleSummary(System.IO.Path.GetFileName(u.Path), Hex(d, u.Base), $"0x{u.Size:X}", $"0x{u.TimeDateStamp:X8}")).ToList(), d.UnloadedModules.Count);
    }

    internal static string StateName(uint state) => state switch
    {
        0x1000 => "commit",
        0x2000 => "reserve",
        0x10000 => "free",
        _ => $"0x{state:X}",
    };

    internal static string? TypeName(uint type) => type switch
    {
        0x1000000 => "image",
        0x40000 => "mapped",
        0x20000 => "private",
        0 => null,
        _ => $"0x{type:X}",
    };

    internal static ModuleSummary ModuleRow(DumpModule m, IReadOnlyList<string> directories, NativeArch arch, IReadOnlyList<string>? loaded = null)
    {
        var local = DumpImages.Find(m, directories, arch, loaded);
        string state = local.Matches ? "matches" : local.Exists ? "mismatch" : "missing";
        string? built = m.TimeDateStamp is > 0x30000000 and < 0x80000000 ? DateTimeOffset.FromUnixTimeSeconds(m.TimeDateStamp).UtcDateTime.ToString("u") : null;
        var cv = m.CodeView;
        return new ModuleSummary(m.FileName, m.Path, $"0x{m.Base:X}", $"0x{m.Size:X}", $"0x{m.TimeDateStamp:X8}", built, m.FileVersion,
            cv?.PdbPath is { Length: > 0 } p ? p : null, cv is { Format: "RSDS" } ? cv.Guid.ToString("D") : null, cv?.Age,
            state, local.Path, local.Detail, local.Matches ? local.IsDotNet : null);
    }

    private async Task<ExceptionSummary> DescribeException(Session s, CancellationToken ct)
    {
        var d = s.Dump;
        var e = d.Exception!;
        var location = await Locate(s, e.Address, false, ct);
        var (insn, bytes, source) = Instruction(s, e.Address);
        var ctx = Wow64.ExceptionContext(d, e.ThreadId) ?? d.ReadContext(e.Context);
        return new ExceptionSummary($"0x{e.Code:X8}", ExceptionCodes.Name(e.Code), ExceptionCodes.Describe(e.Code, e.Parameters, d.Is64Bit), Hex(d, e.Address),
            e.ThreadId, location.Module?.FileName, location.Symbol, location.Source,
            insn != null ? $"{insn} ({bytes})" : null, source, e.Parameters.Select(p => $"0x{p:X}").ToList(), ctx?.Format(),
            e.Code == ExceptionCodes.CxxException ? ThrownTypes(s, e.Parameters) : null, (e.Flags & 1) == 0);
    }

    /// <summary>The instruction at <paramref name="address"/>: bytes from dump memory, else from the module image.</summary>
    private (string? Text, string? Bytes, string? Source) Instruction(Session s, ulong address)
    {
        var d = s.Memory;
        if (d.Arch is not (NativeArch.X64 or NativeArch.X86)) return (null, null, null);
        var buffer = new byte[16];
        int n = d.ReadMemory(address, buffer);
        string? source = n > 0 ? "dump_memory" : null;
        if (n < buffer.Length && s.Core != null && d.ModuleAt(address) is { } em && s.Image(em).Image is { } elf)
        {
            var fromImage = new byte[16];
            int k = elf.Read(address, fromImage);
            if (k > n)
            {
                fromImage.AsSpan(0, k).CopyTo(buffer);
                n = k;
                source = $"module_image ({elf.Source})";
            }
        }
        else if (n < buffer.Length && s.Core == null && d.ModuleAt(address) is { } m && s.Code(m) is { Image: { } image } mc)
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

    /// <summary>The thrown C++ type and its catchable bases from the MSVC ThrowInfo; empty when unreadable.</summary>
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
        if (s.Core is { } core) return await CoreStack(s, core, thread, maxFrames, offset, limit, ct);
        var d = s.Dump;
        var t = PickThread(d, thread);
        DumpContext? ctx = null;
        byte[]? exceptionBytes = null;
        string contextKind = "thread";
        var exception32 = exceptionContext ? Wow64.ExceptionContext(d, t.Id) : null;
        if (exceptionContext && exception32 == null && d.Exception is { } e && e.ThreadId == t.Id && d.ReadContext(e.Context) is { } ec)
        {
            ctx = ec;
            exceptionBytes = d.ContextBytes(e.Context);
            contextKind = "exception";
        }
        ctx ??= d.ReadContext(t.Context);
        var wow64Side = Wow64.Thread(d, t.Teb);
        // A writer that captured no context for a thread leaves its registers unknown; a WoW64 thread still has its saved 32-bit side.
        if (ctx == null && wow64Side == null)
            return new StackReport(s.Id, t.Id, t.Name, "unknown", ArchName(d.Arch, d.SystemInfo?.ProcessorArchitecture ?? 0xFFFF), null, [], 0, 0, "context_unknown", 0, null,
                [$"thread {t.Id}: the dump holds no register context for it, so its registers and stack are unknown, not empty.",
                 "pass another thread id, or 'exception' for the faulting thread."]);
        maxFrames = Math.Clamp(maxFrames, 1, StackWalker.MaxFramesLimit);
        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, StackWalker.MaxFramesLimit);

        var walker = s.Walker();
        var walk = ctx == null
            ? new WalkResult([], "context_unknown", [$"thread {t.Id}: the dump holds no 64-bit register context for it; only its 32-bit side is walked."])
            : await Task.Run(() => walker.Walk(ctx!, t.StackStart, t.StackStart + t.StackSize, maxFrames, ct), ct);
        var notes = new List<string>(walk.Notes);
        // The runtime walks from the same context; a thread held by a session waits in code it cannot unwind.
        var (clrFrames, managedState) = ctx == null ? ([], null) : await ManagedFrames(s, t.Id, managed, maxFrames, notes, ct, exceptionBytes);
        var merged = Merge(walk.Frames, clrFrames);
        string arch = ArchName(d.Arch, d.SystemInfo?.ProcessorArchitecture ?? 0xFFFF), stop = walk.Stop;
        string? registers = ctx?.Format();
        if (wow64Side is { } wow)
        {
            // The 32-bit side, the program's own code, goes first; the 64-bit side follows.
            var context32 = exception32 ?? wow.Context;
            var walk32 = await Task.Run(() => s.Walker(Wow64.View(d)).Walk(context32, wow.StackLow, wow.StackHigh, maxFrames, ct), ct);
            merged.InsertRange(0, walk32.Frames.Select(f => ((WalkFrame?)f, (ManagedFrame?)null)));
            notes.Add($"WoW64 thread: frames 0-{walk32.Frames.Count - 1} are its 32-bit side ({(exception32 != null ? "from the exception's x86 context" : "the x86 context WoW64 saved for the thread")}); the 64-bit side follows.");
            (arch, registers, stop) = ("x86 (WoW64)", context32.Format(), walk32.Stop);
            if (exception32 != null) contextKind = "exception";
        }
        else if (Wow64.IsWow64(d))
            notes.Add($"WoW64 process: this is the thread's 64-bit side; its 32-bit context (WoW64 CPU area{(Wow64.CpuArea(d, t.Teb) is { } cpu ? $" at {Hex(d, cpu)}" : "")}) " +
                      "is not in the dump; a full-memory dump or procdump -x86 holds it.");
        if (merged.Count > maxFrames) merged.RemoveRange(maxFrames, merged.Count - maxFrames);
        var frames = await Frames(s, merged, offset, limit, ct);
        notes.AddRange(ModuleNotes(s));
        return new StackReport(s.Id, t.Id, t.Name, contextKind, arch, registers,
            frames, offset, merged.Count, stop, merged.Count(f => f.Managed == null && f.Native!.Heuristic), managedState, notes);
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
                where.Source, where.FunctionAddress is { } fa ? Hex(d, fa) : null, where.Kind, f.Method, FrameBasis(f.Method, f.Heuristic, where.Source), note.Length > 0 ? note : null));
        }
        return frames;
    }

    /// <summary>A frame's basis: null when observed (context, unwind data, the runtime's walk).</summary>
    internal static string? FrameBasis(string method, bool heuristic, string? symbolSource) =>
        heuristic || method == "scan" || symbolSource == "nearest_export" ? "inferred" : method is "frame_pointer" or "call_target" ? "derived" : null;

    /// <summary>Where each module's image and names came from, for the modules a session resolved.</summary>
    internal static IEnumerable<string> ModuleNotes(Session s)
    {
        foreach (var (m, c) in s.Loaded.OrderBy(x => x.Module.Base))
        {
            string names = c.Names is { } n ? n.PdbPath != null ? $"names from {n.PdbPath}" : n.HasSymbols ? "names from the image's symbol table (no matching local PDB)" : "names from exports (no matching local PDB)" : "no names";
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

    public async Task<MemoryRead> ReadMemory(string path, string address, int length, bool imageFallback, CancellationToken ct) =>
        (await ReadBytes(path, address, length, imageFallback, ct)).Head;

    internal async Task<MemoryBytes> ReadBytes(string path, string address, int length, bool imageFallback, CancellationToken ct)
    {
        using var s = Open(path, null);
        if (s.Core is { } core) return await CoreReadBytes(s, core, address, length, imageFallback, ct);
        if (s.Regions is { } regions) return await RegionReadBytes(s, regions, address, length, imageFallback, ct);
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
        var head = new MemoryRead(s.Id, Hex(d, va), length, n, source, location.Symbol ?? location.Note,
            range is { } r ? $"{Hex(d, r.Start)}-{Hex(d, r.End)}" : null, region != null ? ProtectName(region.Protect) : null,
            Convert.ToHexString(buffer, 0, n), 0, note);
        return new MemoryBytes(head, va, buffer[..n], d.Is64Bit);
    }

    private static ulong ParseAddress(IProcessMemory d, string text)
    {
        var t = (text ?? "").Trim();
        if (t.Length == 0) throw new ToolError(ErrorCode.InvalidArgument, "address is empty.", "pass a hex address (0x7FF6...) or module+0xoffset");
        int plus = t.IndexOf('+');
        if (plus > 0)
        {
            string name = t[..plus].Trim();
            var module = Named(d, name) ?? throw new ToolError(ErrorCode.NotFound, $"no module '{name}' in the dump.", "open_minidump lists the modules");
            var off = NativeAddress.Number(t[(plus + 1)..].Trim()) ?? throw new ToolError(ErrorCode.InvalidArgument, $"'{t[(plus + 1)..]}' is not a hex offset.");
            return module.Base + off;
        }
        if (Named(d, t) is { } whole) return whole.Base;
        return NativeAddress.Number(t) ?? throw new ToolError(ErrorCode.InvalidArgument, $"'{text}' is not an address.", "pass a hex address (0x7FF6...) or module+0xoffset");
    }

    /// <summary>The one module of that name (file name or debugger label), or null; two (a WoW64 process's ntdll.dll) are ambiguous.</summary>
    private static DumpModule? Named(IProcessMemory d, string name)
    {
        var modules = d.Modules.Where(m => m.FileName.Equals(name, StringComparison.OrdinalIgnoreCase) || ModuleLabel(m).Equals(name, StringComparison.OrdinalIgnoreCase)).ToList();
        if (modules.Count > 1)
            throw new ToolError(ErrorCode.Ambiguous, $"{modules.Count} modules are named '{name}': {string.Join(", ", modules.Select(m => $"{Hex(d, m.Base)} ({m.Path})"))}.",
                "pass the absolute address (a base above plus the offset)");
        return modules.FirstOrDefault();
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

    /// <summary>Bytes per hex dump line: grouped by four in memory order (as xxd -g4), then the line as ASCII.</summary>
    internal const int HexLine = 32;

    internal static string HexDump(ulong address, ReadOnlySpan<byte> bytes, bool is64)
    {
        var sb = new StringBuilder();
        for (int line = 0; line < bytes.Length; line += HexLine)
        {
            ulong at = address + (ulong)line;
            sb.Append(is64 ? $"{at:X16} " : $"{at & 0xFFFFFFFF:X8} ");
            int n = Math.Min(HexLine, bytes.Length - line);
            for (int i = 0; i < HexLine; i++)
            {
                if (i % 4 == 0) sb.Append(' ');
                sb.Append(i < n ? $"{bytes[line + i]:X2}" : "  ");
            }
            sb.Append("  ");
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
