using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Runtime;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.Dump.Managed;

/// <summary>DAC outcome: loaded, not_found, bitness_mismatch, host_unsupported, signature_invalid, download_refused_offline, download_failed, load_failed or unsupported_runtime.</summary>
public sealed record DacState(string Status, string? Path, string Detail);

/// <summary>A managed frame: a method (with token and IL offset when the runtime has them) or a runtime transition frame.</summary>
public sealed record ManagedFrame(ulong Ip, ulong Sp, bool IsMethod, string Name, int? Token, int? IlOffset, string? ModulePath, Guid? Mvid, ulong? MethodStart);

/// <summary>A managed exception object with its stack and inner chain.</summary>
public sealed record ManagedException(string Type, string? Message, int HResult, ulong Address, uint? ThreadId, IReadOnlyList<ManagedFrame> Stack, ManagedException? Inner);

/// <summary>Heap facts: whether objects can be walked, and why not.</summary>
public sealed record ManagedHeapState(bool Walkable, int Segments, ulong Bytes, string? Reason);

/// <summary>
/// .NET (CoreCLR and .NET Framework) state of a dumped process through ClrMD and the runtime's own DAC: threads,
/// stacks, exceptions and the GC heap. The dumped program is never run; the DAC is Microsoft's debugging library for
/// that runtime build, loaded into this process only after its signature is verified. Calls are serialized on
/// <see cref="Gate"/>; the decoder owns its dump file.
/// </summary>
public sealed class ClrDecoder : IDisposable
{
    public const int MaxInnerExceptions = 5;
    public const int MaxExceptionFrames = 50;

    private readonly DataTarget? _target;
    private readonly ClrRuntime? _runtime;
    private readonly Dictionary<ulong, Guid?> _mvids = [];

    public object Gate { get; } = new();
    /// <summary>Runtime name and version, e.g. ".NET 10.0.11 (CoreCLR)".</summary>
    public string RuntimeName { get; }
    public string? Version { get; }
    public DacState Dac { get; }
    public ClrRuntime? Runtime => _runtime;
    public bool Loaded => _runtime != null;

    private ClrDecoder(string runtimeName, string? version, DacState dac, DataTarget? target, ClrRuntime? runtime)
    {
        RuntimeName = runtimeName;
        Version = version;
        Dac = dac;
        _target = target;
        _runtime = runtime;
    }

    /// <summary>The CLR flavor a dump hosts (CoreCLR or .NET Framework), from its runtime module; null for none.</summary>
    public static DumpModule? RuntimeModule(IProcessMemory dump) =>
        dump.Modules.FirstOrDefault(m => m.FileName.Equals("coreclr.dll", StringComparison.OrdinalIgnoreCase) || m.FileName.Equals("clr.dll", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Opens the CLR of <paramref name="dump"/> (which the decoder then owns). Null when the process hosts no CLR. A DAC
    /// that cannot be found or loaded gives a decoder without a runtime and the reason in <see cref="Dac"/>.
    /// </summary>
    public static async Task<ClrDecoder?> Open(MinidumpFile dump, Func<DumpModule, PeFile?> image, IReadOnlyList<string> imageDirectories, DacRequest request, CancellationToken ct)
    {
        var module = RuntimeModule(dump);
        if (module == null)
        {
            dump.Dispose();
            return null;
        }
        string flavor = module.FileName.Equals("coreclr.dll", StringComparison.OrdinalIgnoreCase) ? "CoreCLR" : ".NET Framework CLR";
        ClrDecoder Fail(string status, string detail)
        {
            dump.Dispose();
            return new ClrDecoder($"{flavor} {module.FileVersion}".TrimEnd(), module.FileVersion, new DacState(status, null, detail), null, null);
        }
        if (!OperatingSystem.IsWindows())
            return Fail("host_unsupported", "the DAC of a Windows dump is a Windows DLL: decode .NET frames with this server on Windows");
        var hostArch = RuntimeInformation.ProcessArchitecture;
        var dumpArch = dump.Arch switch { NativeArch.X86 => Architecture.X86, NativeArch.Arm64 => Architecture.Arm64, NativeArch.Arm => Architecture.Arm, _ => Architecture.X64 };
        if (hostArch != dumpArch)
            return Fail("bitness_mismatch", $"a {dumpArch} process needs a {dumpArch} DAC, which this {hostArch} server cannot load; frames stay identified as managed");

        var target = new DataTarget(new CustomDataTarget(new DumpDataReader(dump, image)) { FileLocator = new LocalImageLocator(imageDirectories) });
        try { return await Decode(target, module, flavor, request, ct).ConfigureAwait(false); }
        catch
        {
            target.Dispose();
            throw;
        }
    }

    /// <summary>Finds, verifies and loads the DAC; a failure disposes <paramref name="target"/> and gives a decoder without a runtime.</summary>
    private static async Task<ClrDecoder> Decode(DataTarget target, DumpModule module, string flavor, DacRequest request, CancellationToken ct)
    {
        string name = $"{flavor} {module.FileVersion}".TrimEnd();
        ClrDecoder Fail(string status, string detail)
        {
            target.Dispose();
            return new ClrDecoder(name, module.FileVersion, new DacState(status, null, detail), null, null);
        }
        ClrInfo? clr;
        try { clr = target.ClrVersions.FirstOrDefault(); }
        catch (Exception ex) when (ex is not OperationCanceledException) { return Fail("load_failed", $"the runtime module could not be read: {ex.Message}"); }
        if (clr == null) return Fail("load_failed", $"{module.FileName} is loaded but its runtime could not be identified");
        name = $"{(clr.Flavor == ClrFlavor.Core ? ".NET" : ".NET Framework")} {clr.Version} ({flavor})";

        var problems = new List<string>();
        bool signatureFailed = false;
        ClrRuntime? Try(DacCandidate c)
        {
            try
            {
                // held open without write sharing from the signature check until the library is loaded
                using var file = new FileStream(c.Path, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (file.Length > DacLocator.MaxDownloadBytes) { problems.Add($"{c.Path}: larger than {DacLocator.MaxDownloadBytes >> 20} MB"); return null; }
                var bytes = new byte[file.Length];
                file.ReadExactly(bytes);
                if (DacLocator.Verify(bytes, c.Path) is { } bad)
                {
                    signatureFailed = true;
                    problems.Add($"{c.Path} ({c.Source}): signature not accepted: {bad}");
                    return null;
                }
                return clr.CreateRuntime(c.Path);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                problems.Add($"{c.Path} ({c.Source}): {ex.Message}");
                return null;
            }
        }
        foreach (var c in DacLocator.Local(clr, module, request))
        {
            ct.ThrowIfCancellationRequested();
            if (Try(c) is { } rt) return new ClrDecoder(name, clr.Version.ToString(), new DacState("loaded", c.Path, c.Source), target, rt);
        }
        if (request.Download)
        {
            if (ReferencePacks.Offline)
                return Fail("download_refused_offline", Joined("NDM_OFFLINE=1: the DAC is not downloaded", problems));
            var (candidate, error) = await DacLocator.Download(clr, request, ct).ConfigureAwait(false);
            if (candidate != null && Try(candidate) is { } rt) return new ClrDecoder(name, clr.Version.ToString(), new DacState("loaded", candidate.Path, candidate.Source), target, rt);
            if (candidate == null) return Fail("download_failed", Joined($"download failed: {error}", problems));
        }
        if (signatureFailed) return Fail("signature_invalid", Joined("no DAC with a valid Microsoft signature", problems));
        if (problems.Count > 0) return Fail("load_failed", Joined("no DAC could be loaded", problems));
        return Fail("not_found", $"no DAC for {name} on this machine: pass dacPath (the dumped runtime's mscordaccore.dll / mscordacwks.dll or its folder), " +
                                 "install that runtime version, or open_minidump downloadDac=true");
    }

    private static string Joined(string head, List<string> problems) => problems.Count == 0 ? head : $"{head}; tried: {string.Join("; ", problems.Take(4))}";

    /// <summary>App domains, managed threads and heap facts; requires <see cref="Loaded"/>.</summary>
    public (int AppDomains, int Threads, ManagedHeapState Heap) Facts()
    {
        var rt = Require();
        var heap = rt.Heap;
        var segments = heap.Segments;
        ulong bytes = 0;
        foreach (var s in segments) bytes += s.ObjectRange.Length;
        string? reason = !heap.CanWalkHeap ? "heap_not_walkable: the runtime reports the heap in an inconsistent state (a GC was running)"
            : segments.Length == 0 || bytes == 0 ? "heap_not_captured: the dump holds no GC heap memory (a stacks-only dump; write one with full or private read/write memory)"
            : null;
        return (rt.AppDomains.Length, rt.Threads.Length, new ManagedHeapState(reason == null, segments.Length, bytes, reason));
    }

    /// <summary>
    /// The exception in flight: on <paramref name="threadId"/> when given (the faulting thread of a CLR exception), else
    /// on the first thread that has one. Inner exceptions to <see cref="MaxInnerExceptions"/>, frames to <see cref="MaxExceptionFrames"/>.
    /// </summary>
    public ManagedException? Exception(uint? threadId)
    {
        var rt = Require();
        var threads = rt.Threads.Where(t => threadId == null || t.OSThreadId == threadId);
        foreach (var t in threads)
            if (t.CurrentException is { } e) return Describe(e, t.OSThreadId, 0);
        return null;
    }

    private ManagedException Describe(ClrException e, uint? thread, int depth)
    {
        var frames = e.StackTrace.Take(MaxExceptionFrames).Select(Frame).ToList();
        var inner = depth < MaxInnerExceptions && e.Inner is { } i ? Describe(i, null, depth + 1) : null;
        return new ManagedException(e.Type?.Name ?? "(unknown type)", e.Message, e.HResult, e.Address, thread, frames, inner);
    }

    /// <summary>The managed stack of an OS thread, innermost first; empty when the runtime does not know the thread.</summary>
    public IReadOnlyList<ManagedFrame> Frames(uint threadId, int maxFrames)
    {
        var rt = Require();
        var thread = rt.Threads.FirstOrDefault(t => t.OSThreadId == threadId);
        if (thread == null) return [];
        return thread.EnumerateStackTrace(false, maxFrames).Select(Frame).ToList();
    }

    private ManagedFrame Frame(ClrStackFrame f)
    {
        var m = f.Method;
        if (f.Kind != ClrStackFrameKind.ManagedMethod || m == null)
            return new ManagedFrame(f.InstructionPointer, f.StackPointer, false, $"[{f.FrameName ?? f.Kind.ToString()}]", null, null, null, null, null);
        int? il = null;
        if (f.InstructionPointer != 0)
        {
            int at = m.GetILOffset(f.InstructionPointer > 0 ? f.InstructionPointer - 1 : 0);
            if (at < 0) at = m.GetILOffset(f.InstructionPointer);
            if (at >= 0) il = at;
        }
        var module = m.Type?.Module;
        return new ManagedFrame(f.InstructionPointer, f.StackPointer, true, m.Signature ?? m.Name ?? "(unknown method)", m.MetadataToken != 0 ? m.MetadataToken : null, il,
            module?.Name, module != null ? Mvid(module) : null, m.NativeCode != 0 && m.NativeCode != ulong.MaxValue ? m.NativeCode : null);
    }

    /// <summary>The module's MVID, read from its metadata in dump memory (or the read-only image).</summary>
    public Guid? Mvid(ClrModule module)
    {
        if (_mvids.TryGetValue(module.Address, out var known)) return known;
        Guid? mvid = null;
        if (module.MetadataAddress != 0 && module.MetadataLength is > 0 and <= 256u << 20)
        {
            var bytes = new byte[module.MetadataLength];
            if (_target!.DataReader.Read(module.MetadataAddress, bytes) == bytes.Length)
                mvid = ReadMvid(bytes);
        }
        return _mvids[module.Address] = mvid;
    }

    internal static Guid? ReadMvid(byte[] metadata)
    {
        try
        {
            using var provider = MetadataReaderProvider.FromMetadataImage(System.Collections.Immutable.ImmutableArray.Create(metadata));
            var md = provider.GetMetadataReader();
            return md.GetGuid(md.GetModuleDefinition().Mvid);
        }
        catch (BadImageFormatException) { return null; }
    }

    private ClrRuntime Require() => _runtime ?? throw new InvalidOperationException("no runtime");

    public void Dispose()
    {
        lock (Gate)
        {
            _runtime?.Dispose();
            _target?.Dispose();
        }
    }

    /// <summary>Module images ClrMD asks for, from local folders only (matched by timestamp and size); never the network.</summary>
    private sealed class LocalImageLocator(IReadOnlyList<string> directories) : IFileLocator
    {
        public string? FindPEImage(string fileName, int buildTimeStamp, int imageSize, bool checkProperties)
        {
            var name = System.IO.Path.GetFileName(fileName);
            var candidates = new List<string>();
            if (System.IO.Path.IsPathFullyQualified(fileName)) candidates.Add(fileName);
            if (name.Length > 0 && name.IndexOfAny(System.IO.Path.GetInvalidFileNameChars()) < 0)
                candidates.AddRange(directories.Select(d => System.IO.Path.Combine(d, name)));
            foreach (var c in candidates)
                if (File.Exists(c) && Pdb.PdbLocator.CheckImage(c, (uint)buildTimeStamp, (uint)imageSize) == null) return c;
            return null;
        }

        public string? FindPEImage(string fileName, SymbolProperties archivedUnder, System.Collections.Immutable.ImmutableArray<byte> buildIdOrUUID, OSPlatform originalPlatform, bool checkProperties) => null;
        public string? FindElfImage(string fileName, SymbolProperties archivedUnder, System.Collections.Immutable.ImmutableArray<byte> buildId, bool checkProperties) => null;
        public string? FindMachOImage(string fileName, SymbolProperties archivedUnder, System.Collections.Immutable.ImmutableArray<byte> uuid, bool checkProperties) => null;
    }
}
