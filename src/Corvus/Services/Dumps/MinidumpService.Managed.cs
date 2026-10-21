using System.ComponentModel;
using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Managed;

namespace Corvus.Services;

public sealed partial class MinidumpService
{
    /// <summary>Open CLR decoders (each holds a loaded DAC and its own dump handle); the least recently used is closed beyond this.</summary>
    private const int MaxDecoders = 4;

    private readonly List<(string Path, ClrDecoder Decoder)> _decoders = [];
    private readonly SemaphoreSlim _decoderGate = new(1, 1);
    private bool _disposed;

    public sealed record DacSummary(
        [property: Description("loaded, not_found, bitness_mismatch, host_unsupported, signature_invalid, download_refused_offline, download_failed, load_failed or unsupported_runtime.")] string Status,
        string? Path,
        [property: Description("Where the DAC came from, or why none was loaded and what to do.")] string Detail);

    public sealed record HeapSummary(
        bool Walkable, int Segments, ulong Bytes,
        [property: Description("heap_not_captured or heap_not_walkable with the reason; null when the heap can be walked (dump_heap, dump_object).")] string? Reason);

    public sealed record ManagedFrameSummary(
        [property: Description("Ns.Type.Method(signature), or a runtime frame in brackets.")] string Function,
        [property: Description("Method token for decompile_member (with assembly).")] string? Token,
        [property: Description("IL offset of the instruction (from the JIT's IL map); null when the dump does not hold it.")] int? IlOffset,
        string? Module,
        [property: Description("Id of the loaded assembly that is this build (file name and MVID).")] string? Assembly,
        [property: Description("match (same MVID), mismatch (a loaded assembly of that name is another build), unknown, or null when no such assembly is loaded.")] string? BuildCheck,
        string? Address,
        [property: Description("The C# statement at the IL offset (decompiled with sequence points), for a frame of a matching build.")] string? Statement = null);

    public sealed record ManagedExceptionSummary(
        string Type, string? Message, string HResult,
        [property: Description("Address of the exception object (dump_object).")] string Address,
        uint? ThreadId, IReadOnlyList<ManagedFrameSummary> Stack,
        [property: Description("Inner exceptions, outermost first (up to 5).")] IReadOnlyList<ManagedExceptionSummary> Inner);

    public sealed record ManagedSummary(
        [property: Description("e.g. .NET 10.0.11 (CoreCLR), .NET Framework 4.8.x (CLR), Mono.")] string Runtime,
        string? Version, DacSummary Dac, int? AppDomains, int? ManagedThreads, HeapSummary? Heap,
        [property: Description("The managed exception in flight: on the faulting thread for a CLR exception, else on the first thread that has one.")] ManagedExceptionSummary? Exception,
        IReadOnlyList<string> Notes);

    /// <summary>The dump's CLR decoder, created on first use (and again when a new DAC request may succeed where the cached one failed).</summary>
    internal async Task<ClrDecoder?> Decoder(Session s, DacRequest request, CancellationToken ct)
    {
        var path = s.Core?.Path ?? s.Dump.Path;
        await _decoderGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            int at = _decoders.FindIndex(d => d.Path.Equals(path, StringComparison.OrdinalIgnoreCase));
            if (at >= 0)
            {
                var cached = _decoders[at];
                bool retry = !cached.Decoder.Loaded && (request.Path != null || request.Download);
                _decoders.RemoveAt(at);
                if (!retry)
                {
                    _decoders.Add(cached);
                    return cached.Decoder;
                }
                cached.Decoder.Dispose();
            }
            ClrDecoder? decoder;
            if (s.Core is { } core)
            {
                if (core.CoreModules.FirstOrDefault(m => m.Module.FileName == "libcoreclr.so") is not { } runtime) return null;
                var (file, matches, _) = FindElf(core, runtime, s.Directories);
                decoder = await ClrDecoder.OpenCore(path, runtime.Module, matches ? file : null, CoreArchitecture(core), request, ct).ConfigureAwait(false);
            }
            else
            {
                if (ClrDecoder.RuntimeModule(s.Dump) == null) return null;
                var file = MinidumpFile.Open(path);
                var dirs = s.Directories;
                decoder = await ClrDecoder.Open(file, m => Load(file, m, dirs).Image, dirs, request, ct).ConfigureAwait(false);
            }
            if (decoder == null) return null;
            _decoders.Add((path, decoder));
            while (_decoders.Count > MaxDecoders)
            {
                _decoders[0].Decoder.Dispose();
                _decoders.RemoveAt(0);
            }
            return decoder;
        }
        finally { _decoderGate.Release(); }
    }

    /// <summary>Closes the CLR decoders: their dump handles and the 32-bit decoder processes.</summary>
    public void Dispose()
    {
        _decoderGate.Wait();
        try
        {
            _disposed = true;
            foreach (var (_, decoder) in _decoders) decoder.Dispose();
            _decoders.Clear();
        }
        finally { _decoderGate.Release(); }
    }

    private async Task<ManagedSummary?> ManagedSection(Session s, DacRequest request, CancellationToken ct)
    {
        uint? faulting = null;
        if (s.Core is { } core)
        {
            if (CoreRuntime(core) != ".NET (CoreCLR)") return null;
        }
        else
        {
            if (!HostsClr(s.Dump, out var runtime)) return null;
            if (runtime == "Mono") return await MonoSection(s, ct);
            faulting = s.Dump.Exception is { Code: ExceptionCodes.ClrException } e ? e.ThreadId : null;
        }
        var decoder = await Decoder(s, request, ct);
        if (decoder == null) return null;
        var dac = new DacSummary(decoder.Dac.Status, decoder.Dac.Path, decoder.Dac.Detail);
        if (!decoder.Loaded) return new ManagedSummary(decoder.RuntimeName, decoder.Version, dac, null, null, null, null, []);
        lock (decoder.Gate)
        {
            var notes = new List<string>();
            var (domains, threads, heap) = decoder.Facts();
            if (decoder.OutOfProcess) notes.Add("A 32-bit process: decoded by the 32-bit decoder process with the 32-bit DAC.");
            ManagedException? ex = null;
            try { ex = decoder.Exception(faulting) ?? (faulting != null ? decoder.Exception(null) : null); }
            catch (Exception err) when (err is not OperationCanceledException) { notes.Add($"the exception object could not be read: {err.Message}"); }
            return new ManagedSummary(decoder.RuntimeName, decoder.Version, dac, domains, threads,
                new HeapSummary(heap.Walkable, heap.Segments, heap.Bytes, heap.Reason), ex == null ? null : ExceptionRow(s, ex, ct), notes);
        }
    }

    private ManagedExceptionSummary ExceptionRow(Session s, ManagedException e, CancellationToken ct)
    {
        var inner = new List<ManagedExceptionSummary>();
        for (var i = e.Inner; i != null; i = i.Inner) inner.Add(Row(i, []));
        return Row(e, inner);

        ManagedExceptionSummary Row(ManagedException x, IReadOnlyList<ManagedExceptionSummary> chain) =>
            new(x.Type, x.Message, $"0x{x.HResult:X8}", Hex(s.Memory, x.Address), x.ThreadId, x.Stack.Select(f => FrameRow(s, f, ct)).ToList(), chain);
    }

    private ManagedFrameSummary FrameRow(Session s, ManagedFrame f, CancellationToken ct)
    {
        var (assembly, check) = AssemblyFor(f.ModulePath, f.Mvid);
        return new ManagedFrameSummary(f.Name, f.Token is { } t ? $"0x{t:X8}" : null, f.IlOffset, ModuleFile(f.ModulePath), assembly, check, Hex(s.Memory, f.Ip),
            Statement(s, assembly, check, f.Token, f.IlOffset, ct));
    }

    /// <summary>Managed frames per call whose IL offset is mapped to a C# statement (each decompiles its method once).</summary>
    public const int MaxStatements = 20;

    /// <summary>The C# statement at a frame's IL offset, when the loaded assembly is that build (MVID); within the session's budget.</summary>
    private string? Statement(Session s, string? assemblyId, string? check, int? token, int? ilOffset, CancellationToken ct)
    {
        if (decompiler == null || workspace == null || assemblyId == null || check != "match" || token is not { } t || ilOffset is not { } il || s.StatementBudget <= 0) return null;
        s.StatementBudget--;
        return workspace.Read(() =>
        {
            var asm = workspace.Get(assemblyId);
            if (asm.Module.ResolveToken((uint)t) is not dnlib.DotNet.MethodDef method) return null;
            try { return decompiler.StatementAt(asm, method, il, ct)?.Text; }
            catch (ToolError) { return null; }
        });
    }

    /// <summary>Crash reports Unity's Mono runtime writes beside its dump, most detailed first for managed exceptions.</summary>
    private static readonly string[] MonoLogs = ["Player.log", "output_log.txt", "error.log"];

    /// <summary>
    /// The Mono runtime's own reports beside the dump (Unity's crash folder): managed exception lines with module MVID and
    /// IL offset, and its crash backtrace naming JIT code addresses. Read once per session.
    /// </summary>
    private async Task<IReadOnlyList<(string Log, StackTextService.SymbolizedStack Stack)>> MonoReports(Session s, CancellationToken ct)
    {
        if (s.MonoReports != null) return s.MonoReports;
        var found = new List<(string, StackTextService.SymbolizedStack)>();
        if (stacks != null && s.Memory is MinidumpFile d && Path.GetDirectoryName(d.Path) is { Length: > 0 } dir)
            foreach (var name in MonoLogs)
            {
                var log = Path.Combine(dir, name);
                if (!File.Exists(log)) continue;
                try
                {
                    var r = await stacks.Symbolize(null, log, "auto", null, null, 0, 1000, ct).ConfigureAwait(false);
                    if (r.Items.Any(f => f.Kind == "managed")) found.Add((log, r));
                }
                catch (ToolError) { }
            }
        return s.MonoReports = found;
    }

    private async Task<ManagedSummary> MonoSection(Session s, CancellationToken ct)
    {
        var dac = new DacSummary("unsupported_runtime", null, "Mono has no DAC; JIT code is named from the Mono runtime's crash report beside the dump when there is one");
        var reports = await MonoReports(s, ct);
        var withIl = reports.FirstOrDefault(r => r.Stack.Items.Any(f => f.IlOffset != null));
        if (withIl.Log == null)
            return new ManagedSummary("Mono", null, dac, null, null, null, null,
                [reports.Count > 0 ? $"{Path.GetFileName(reports[0].Log)} beside the dump names the JIT code frames in dump_stack."
                    : "For Unity Mono titles, symbolize_stack_text on Player.log resolves the managed frames (with their module MVIDs); Unity's crash folder keeps it beside the dump."]);
        var x = withIl.Stack.Exception;
        var frames = withIl.Stack.Items.Where(f => f.Kind == "managed").Take(ClrDecoder.MaxExceptionFrames)
            .Select(f => new ManagedFrameSummary(f.Resolved ?? f.Raw.Trim(), f.Token, f.IlOffset, null, f.Assembly, f.BuildCheck, f.Address, f.Statement)).ToList();
        return new ManagedSummary("Mono", null, dac, null, null, null,
            new ManagedExceptionSummary(x?.Type ?? "(not named)", x?.Message, "", "", null, frames, []),
            [$"The managed exception and frames are from {Path.GetFileName(withIl.Log)} beside the dump (the Mono runtime's report), resolved by module MVID with the C# statement at each IL offset."]);
    }

    private static string? ModuleFile(string? path) => string.IsNullOrEmpty(path) ? null : Path.GetFileName(path.Replace('/', '\\').Split('\\')[^1]);

    /// <summary>The loaded assembly that is this module's build: same file name and MVID; a name match with another MVID is a mismatch.</summary>
    internal (string? Assembly, string? Check) AssemblyFor(string? modulePath, Guid? mvid)
    {
        if (workspace == null || ModuleFile(modulePath) is not { } file) return (null, null);
        var named = workspace.Read(() => workspace.Assemblies
            .Where(a => Path.GetFileName(a.FilePath).Equals(file, StringComparison.OrdinalIgnoreCase))
            .Select(a => (a.Id, a.Module.Mvid)).ToList());
        if (named.Count == 0) return (null, null);
        if (mvid == null) return (named[0].Id, "unknown");
        foreach (var (id, m) in named)
            if (m == mvid) return (id, "match");
        return (named[0].Id, "mismatch");
    }

    /// <summary>The runtime's managed frames of a thread, and the decoding state for the report (null without a CLR).</summary>
    private async Task<(IReadOnlyList<ManagedFrame> Frames, string? State)> ManagedFrames(Session s, uint threadId, bool enabled, int maxFrames, List<string> notes, CancellationToken ct,
        byte[]? context = null)
    {
        if (!HostsClr(s.Dump, out var runtime)) return ([], null);
        if (!enabled) return ([], "off");
        if (runtime == "Mono")
        {
            notes.Add("Mono runtime: managed frames are identified, not decoded; symbolize_stack_text on Player.log resolves them.");
            return ([], "unsupported_runtime");
        }
        var decoder = await Decoder(s, new DacRequest(), ct);
        if (decoder == null) return ([], null);
        if (!decoder.Loaded)
        {
            notes.Add($"Managed frames are identified, not decoded (DAC {decoder.Dac.Status}): {decoder.Dac.Detail}");
            return ([], decoder.Dac.Status);
        }
        lock (decoder.Gate)
        {
            try
            {
                var frames = decoder.Frames(threadId, maxFrames, context);
                notes.Add($"Managed frames from the runtime's own stack walk ({decoder.RuntimeName}, DAC {decoder.Dac.Path}).");
                return (frames, "decoded");
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                notes.Add($"The runtime's stack walk failed: {ex.Message}");
                return ([], "walk_failed");
            }
        }
    }

    private StackFrame ManagedStackFrame(Session s, int index, WalkFrame? native, ManagedFrame f, CancellationToken ct)
    {
        var d = s.Memory;
        var (assembly, check) = AssemblyFor(f.ModulePath, f.Mvid);
        var module = d.ModuleAt(f.Ip);
        string file = module?.FileName ?? ModuleFile(f.ModulePath) ?? "?";
        string label = Path.GetFileNameWithoutExtension(file);
        string? note = check == "mismatch" ? $"{assembly} is another build of {ModuleFile(f.ModulePath)} (MVID differs): its decompiled code may not match this frame" : null;
        return new StackFrame(index, Hex(d, f.Ip), Hex(d, f.Sp), module?.FileName ?? ModuleFile(f.ModulePath), module != null ? $"0x{f.Ip - module.Base:X}" : null,
            $"{label}!{f.Name}", f.Name, "clr", f.MethodStart is { } ms ? Hex(d, ms) : null, "managed", "clr", null, note,
            f.Token is { } t ? $"0x{t:X8}" : null, f.IlOffset, assembly, check, Statement(s, assembly, check, f.Token, f.IlOffset, ct));
    }

    /// <summary>A frame in Mono JIT code named by the Mono runtime's crash report beside the dump (same address); null when it has none.</summary>
    private async Task<StackFrame?> MonoFrame(Session s, int index, WalkFrame f, CancellationToken ct)
    {
        foreach (var (log, stack) in await MonoReports(s, ct))
            foreach (var m in stack.Items)
                if (m.Kind == "managed" && m.Address is { } a && Native.NativeAddress.Number(a) == f.Ip)
                    return new StackFrame(index, Hex(s.Memory, f.Ip), Hex(s.Memory, f.Sp), null, null, m.Resolved ?? m.Raw.Trim(), m.Resolved, "mono_log", null, "managed",
                        f.Method, FrameBasis(f.Method, f.Heuristic, null), $"Mono JIT code, named from {Path.GetFileName(log)}", m.Token, m.IlOffset, m.Assembly, m.BuildCheck, m.Statement);
        return null;
    }

    /// <summary>Native frames and the CLR's managed frames merged by stack pointer: a managed frame at a native frame's address or stack pointer names it.</summary>
    internal static List<(WalkFrame? Native, ManagedFrame? Managed)> Merge(IReadOnlyList<WalkFrame> native, IReadOnlyList<ManagedFrame> managed)
    {
        var merged = native.Select(f => ((WalkFrame?)f, (ManagedFrame?)null)).ToList();
        var used = new bool[managed.Count];
        for (int i = 0; i < merged.Count; i++)
        {
            var f = merged[i].Item1!;
            int k = -1;
            for (int j = 0; j < managed.Count && k < 0; j++)
                if (!used[j] && managed[j].IsMethod && (managed[j].Ip == f.Ip || managed[j].Sp == f.Sp)) k = j;
            if (k < 0) continue;
            used[k] = true;
            merged[i] = (f, managed[k]);
        }
        // a scan from JIT code finds return addresses the runtime keeps on the stack (an inlined P/Invoke's frame record):
        // a scanned frame at a return address of a managed frame named elsewhere is that copy, not another call
        var named = managed.Where((m, j) => used[j]).Select(m => m.Ip).ToHashSet();
        merged.RemoveAll(x => x.Item2 == null && x.Item1!.Heuristic && named.Contains(x.Item1.Ip));
        for (int j = 0; j < managed.Count; j++)
        {
            if (used[j] || !managed[j].IsMethod) continue;
            var m = managed[j];
            int at = merged.FindIndex(x => (x.Item1?.Sp ?? x.Item2!.Sp) > m.Sp);
            merged.Insert(at < 0 ? merged.Count : at, (null, m));
        }
        return merged;
    }
}
