using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Diagnostics.Runtime;
using Corvus.Core;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Managed;

/// <summary>DAC outcome: loaded, not_found, bitness_mismatch, host_unsupported, signature_invalid, download_refused_offline, download_failed, load_failed or unsupported_runtime.</summary>
public sealed record DacState(string Status, string? Path, string Detail);

/// <summary>A decoded CLR: in this process, or in the 32-bit decoder process for a 32-bit dump.</summary>
internal interface IClrBackend : IDisposable
{
    ManagedFacts Facts();
    ManagedException? Exception(uint? threadId);
    IReadOnlyList<ManagedFrame> Frames(uint threadId, int maxFrames);
    HeapWalk Walk(string? type, ulong minSize, long maxObjects, int objectsFrom, int objectsTake, CancellationToken ct);
    ObjectView? Object(ulong address, int depth, int maxFields, int maxArrayItems);
}

/// <summary>
/// .NET (CoreCLR and .NET Framework) state of a dumped process through ClrMD and the runtime's own DAC: threads,
/// stacks, exceptions and the GC heap. The dumped program is never run; the DAC is Microsoft's debugging library for
/// that runtime build, loaded only after its signature is verified: into this process when the dump has this
/// process's architecture, else (a 32-bit dump on a 64-bit server) into the 32-bit decoder process, which checks the
/// file's hash before loading it. Calls are serialized on <see cref="Gate"/>; the decoder owns its dump file.
/// </summary>
public sealed class ClrDecoder : IDisposable
{
    public const int MaxInnerExceptions = ClrReads.MaxInnerExceptions;
    public const int MaxExceptionFrames = ClrReads.MaxExceptionFrames;

    private readonly IClrBackend? _backend;
    private bool _disposed;

    public object Gate { get; } = new();
    /// <summary>Runtime name and version, e.g. ".NET 10.0.11 (CoreCLR)".</summary>
    public string RuntimeName { get; }
    public string? Version { get; }
    public DacState Dac { get; }
    public bool Loaded => _backend != null;
    /// <summary>Decoded in the 32-bit decoder process.</summary>
    public bool OutOfProcess => _backend is ClrHelperClient;

    private ClrDecoder(string runtimeName, string? version, DacState dac, IClrBackend? backend)
    {
        RuntimeName = runtimeName;
        Version = version;
        Dac = dac;
        _backend = backend;
    }

    /// <summary>
    /// The module that hosts the CLR: coreclr.dll or clr.dll, else a single-file app's executable, which links the runtime
    /// in and exports DotNetRuntimeInfo; null for none.
    /// </summary>
    public static DumpModule? RuntimeModule(IProcessMemory dump) =>
        dump.Modules.FirstOrDefault(m => m.FileName.Equals("coreclr.dll", StringComparison.OrdinalIgnoreCase) || m.FileName.Equals("clr.dll", StringComparison.OrdinalIgnoreCase))
        ?? dump.Modules.FirstOrDefault(m => m.FileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && Exports(dump, m.Base, SingleFileRuntimeExport));

    private const string SingleFileRuntimeExport = "DotNetRuntimeInfo";

    /// <summary>Whether the image mapped at <paramref name="imageBase"/> exports <paramref name="name"/>, read from the process's memory.</summary>
    private static bool Exports(IProcessMemory memory, ulong imageBase, string name)
    {
        uint U32(ulong at)
        {
            Span<byte> b = stackalloc byte[4];
            return memory.ReadMemory(at, b) == 4 ? System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(b) : 0;
        }
        var nt = imageBase + U32(imageBase + 0x3C);
        if (U32(nt) != 0x4550) return false; // "PE\0\0"
        Span<byte> magic = stackalloc byte[2];
        if (memory.ReadMemory(nt + 0x18, magic) != 2) return false;
        var exportDir = nt + 0x18 + (magic[0] == 0x0B && magic[1] == 0x02 ? 0x70u : 0x60u); // PE32+ or PE32
        var dir = U32(exportDir);
        if (dir == 0) return false;
        uint count = Math.Min(U32(imageBase + dir + 0x18), 100_000), names = U32(imageBase + dir + 0x20);
        var want = System.Text.Encoding.ASCII.GetBytes(name + "\0");
        Span<byte> got = stackalloc byte[want.Length];
        for (uint i = 0; i < count; i++)
            if (memory.ReadMemory(imageBase + U32(imageBase + names + 4 * i), got) == got.Length && got.SequenceEqual(want)) return true;
        return false;
    }

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
        string flavor = module.FileName.Equals("clr.dll", StringComparison.OrdinalIgnoreCase) ? ".NET Framework CLR" : "CoreCLR";
        ClrDecoder Fail(string status, string detail)
        {
            dump.Dispose();
            return new ClrDecoder($"{flavor} {module.FileVersion}".TrimEnd(), module.FileVersion, new DacState(status, null, detail), null);
        }
        if (!OperatingSystem.IsWindows())
            return Fail("host_unsupported", "the DAC of a Windows dump is a Windows DLL: decode .NET frames with this server on Windows");
        // ClrMD reads a 32-bit runtime only from a 32-bit dump; a WoW64 process holds no other runtime.
        if (Wow64.IsWow64(dump))
            return Fail("bitness_mismatch", "a 64-bit dump of a 32-bit (WoW64) process: its 32-bit runtime is decoded only from a dump written by a 32-bit tool " +
                                            "(procdump without -64, or a 32-bit MiniDumpWriteDump); frames stay identified as managed");
        var hostArch = RuntimeInformation.ProcessArchitecture;
        var dumpArch = dump.Arch switch { NativeArch.X86 => Architecture.X86, NativeArch.Arm64 => Architecture.Arm64, NativeArch.Arm => Architecture.Arm, _ => Architecture.X64 };
        string? helper = null;
        if (hostArch != dumpArch)
        {
            if (dumpArch != Architecture.X86 || hostArch != Architecture.X64)
                return Fail("bitness_mismatch", $"a {dumpArch} process needs a {dumpArch} DAC, which this {hostArch} server cannot load; frames stay identified as managed");
            helper = ClrHelperClient.Locate();
            if (helper == null)
                return Fail("bitness_mismatch", $"a 32-bit process needs the 32-bit DAC, loaded by the 32-bit decoder ({ClrHelperClient.Folder}/{ClrHelperClient.FileName}), " +
                                                "which is not installed beside this server; frames stay identified as managed");
        }

        var target = new DataTarget(new CustomDataTarget(new DumpDataReader(dump, image)) { FileLocator = new LocalImageLocator(imageDirectories) });
        try
        {
            if (helper == null)
                return await Decode(target, module, flavor, request, dumpArch, (clr, c, _) => new InProcessClr(target, clr.CreateRuntime(c.Path)), ownsTarget: true, ct).ConfigureAwait(false);
            // the DAC is found and checked here; the 32-bit process loads it and reads the dump file itself
            var path = dump.Path;
            var decoder = await Decode(target, module, flavor, request, dumpArch,
                (_, c, bytes) => ClrHelperClient.Start(helper, path, c.Path, Convert.ToHexStringLower(SHA256.HashData(bytes)), imageDirectories), ownsTarget: false, ct).ConfigureAwait(false);
            target.Dispose();
            return decoder;
        }
        catch
        {
            target.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Opens the CLR of a running process read through <paramref name="reader"/> (which the decoder then owns); the process
    /// is never suspended. Null when it hosts no CLR. A process of another architecture than this server's gives a decoder
    /// without a runtime: the 32-bit decoder process reads dump files only.
    /// </summary>
    public static async Task<ClrDecoder?> OpenLive(LiveDataReader reader, DacRequest request, CancellationToken ct)
    {
        var target = new DataTarget(new CustomDataTarget(reader) { FileLocator = new LocalImageLocator([]) });
        try
        {
            var module = RuntimeModule(reader.Process);
            if (module == null)
            {
                target.Dispose();
                return null;
            }
            string flavor = module.FileName.Equals("clr.dll", StringComparison.OrdinalIgnoreCase) ? ".NET Framework CLR" : "CoreCLR";
            if (reader.Architecture != RuntimeInformation.ProcessArchitecture)
            {
                target.Dispose();
                return new ClrDecoder($"{flavor} {module.FileVersion}".TrimEnd(), module.FileVersion,
                    new DacState("bitness_mismatch", null, $"a {reader.Architecture} process needs a {reader.Architecture} DAC, which this {RuntimeInformation.ProcessArchitecture} server reads from dump files only"), null);
            }
            return await Decode(target, module, flavor, request, reader.Architecture, (clr, c, _) => new InProcessClr(target, clr.CreateRuntime(c.Path)), ownsTarget: true, ct).ConfigureAwait(false);
        }
        catch
        {
            target.Dispose();
            throw;
        }
    }

    /// <summary>The runtime as ClrMD reads it, when it is decoded in this process; calls go under <see cref="Gate"/>.</summary>
    internal ClrRuntime? Runtime => _disposed ? null : (_backend as InProcessClr)?.Runtime;

    /// <summary>
    /// Finds and verifies the DAC, and loads it through <paramref name="load"/>; a failure gives a decoder without a
    /// runtime (and disposes <paramref name="target"/> when <paramref name="ownsTarget"/>).
    /// </summary>
    private static async Task<ClrDecoder> Decode(DataTarget target, DumpModule module, string flavor, DacRequest request, Architecture arch,
        Func<ClrInfo, DacCandidate, byte[], IClrBackend> load, bool ownsTarget, CancellationToken ct)
    {
        string name = $"{flavor} {module.FileVersion}".TrimEnd();
        ClrDecoder Fail(string status, string detail)
        {
            if (ownsTarget) target.Dispose();
            return new ClrDecoder(name, module.FileVersion, new DacState(status, null, detail), null);
        }
        ClrInfo? clr;
        try { clr = target.ClrVersions.FirstOrDefault(); }
        catch (Exception ex) when (ex is not OperationCanceledException) { return Fail("load_failed", $"the runtime module could not be read: {ex.Message}"); }
        if (clr == null) return Fail("load_failed", $"{module.FileName} is loaded but its runtime could not be identified");
        name = $"{(clr.Flavor == ClrFlavor.Core ? ".NET" : ".NET Framework")} {clr.Version} ({flavor})";

        var problems = new List<string>();
        bool signatureFailed = false;
        IClrBackend? Try(DacCandidate c)
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
                return load(clr, c, bytes);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                problems.Add($"{c.Path} ({c.Source}): {ex.Message}");
                return null;
            }
        }
        string Where(DacCandidate c) => arch != RuntimeInformation.ProcessArchitecture ? $"{c.Source}; decoded by the 32-bit decoder process" : c.Source;
        foreach (var c in request.DownloadOnly ? [] : DacLocator.Local(clr, module, request, arch))
        {
            ct.ThrowIfCancellationRequested();
            if (Try(c) is { } backend) return new ClrDecoder(name, clr.Version.ToString(), new DacState("loaded", c.Path, Where(c)), backend);
        }
        if (request.Download)
        {
            if (ReferencePacks.Offline)
                return Fail("download_refused_offline", Joined("CORVUS_OFFLINE=1: the DAC is not downloaded", problems));
            var (candidate, error) = await DacLocator.Download(clr, request, arch, ct).ConfigureAwait(false);
            if (candidate != null && Try(candidate) is { } backend) return new ClrDecoder(name, clr.Version.ToString(), new DacState("loaded", candidate.Path, Where(candidate)), backend);
            if (candidate == null) return Fail("download_failed", Joined($"download failed: {error}", problems));
        }
        if (signatureFailed) return Fail("signature_invalid", Joined("no DAC with a valid Microsoft signature", problems));
        if (problems.Count > 0) return Fail("load_failed", Joined("no DAC could be loaded", problems));
        return Fail("not_found", $"no DAC for {name} on this machine: pass dacPath (the dumped runtime's mscordaccore.dll / mscordacwks.dll or its folder), " +
                                 "install that runtime version, or downloadDac=true (open_minidump, live_session)");
    }

    private static string Joined(string head, List<string> problems) => problems.Count == 0 ? head : $"{head}; tried: {string.Join("; ", problems.Take(4))}";

    /// <summary>App domains, managed threads and heap facts; requires <see cref="Loaded"/>.</summary>
    public ManagedFacts Facts() => Require().Facts();

    /// <summary>
    /// The exception in flight: on <paramref name="threadId"/> when given (the faulting thread of a CLR exception), else
    /// on the first thread that has one. Inner exceptions to <see cref="MaxInnerExceptions"/>, frames to <see cref="MaxExceptionFrames"/>.
    /// </summary>
    public ManagedException? Exception(uint? threadId) => Require().Exception(threadId);

    /// <summary>
    /// The managed stack of an OS thread, innermost first; empty when the runtime does not know the thread. A dump's
    /// <paramref name="context"/> (the exception's) replaces the thread's own where this process decodes the runtime.
    /// </summary>
    public IReadOnlyList<ManagedFrame> Frames(uint threadId, int maxFrames, byte[]? context = null) =>
        context != null && Require() is InProcessClr clr ? clr.Frames(threadId, maxFrames, context) : Require().Frames(threadId, maxFrames);

    /// <summary>A bounded heap walk (see <see cref="ClrHeapView.Walk"/>).</summary>
    public HeapWalk Walk(string? type, ulong minSize, long maxObjects, int objectsFrom, int objectsTake, CancellationToken ct) =>
        Require().Walk(type, minSize, maxObjects, objectsFrom, objectsTake, ct);

    /// <summary>One object's contents (see <see cref="ClrHeapView.Object"/>); null when no valid object is there.</summary>
    public ObjectView? Object(ulong address, int depth, int maxFields, int maxArrayItems) => Require().Object(address, depth, maxFields, maxArrayItems);

    internal static Guid? ReadMvid(byte[] metadata) => ClrReads.ReadMvid(metadata);

    private IClrBackend Require() => _disposed ? throw Closed() : _backend ?? throw new InvalidOperationException("no runtime");

    private static ToolError Closed() =>
        new(ErrorCode.Conflict, "the dump's .NET decoder was closed while in use (more than four .NET dumps are open at once).", "call again");

    public void Dispose()
    {
        lock (Gate)
        {
            if (_disposed) return;
            _disposed = true;
            _backend?.Dispose();
        }
    }

    /// <summary>The CLR in this process: ClrMD over our dump reader.</summary>
    private sealed class InProcessClr(DataTarget target, ClrRuntime runtime) : IClrBackend
    {
        private readonly ClrReads _reads = new(runtime);

        public ClrRuntime Runtime => runtime;
        public ManagedFacts Facts() => _reads.Facts();
        public ManagedException? Exception(uint? threadId) => _reads.Exception(threadId);
        public IReadOnlyList<ManagedFrame> Frames(uint threadId, int maxFrames) => _reads.Frames(threadId, maxFrames);

        public IReadOnlyList<ManagedFrame> Frames(uint threadId, int maxFrames, byte[] context)
        {
            if (target.DataReader is not DumpDataReader reader) return Frames(threadId, maxFrames);
            reader.Override = (threadId, context);
            try { return Frames(threadId, maxFrames); }
            finally { reader.Override = null; }
        }
        public HeapWalk Walk(string? type, ulong minSize, long maxObjects, int objectsFrom, int objectsTake, CancellationToken ct) =>
            _reads.Walk(type, minSize, maxObjects, objectsFrom, objectsTake, ct);
        public ObjectView? Object(ulong address, int depth, int maxFields, int maxArrayItems) => _reads.Object(address, depth, maxFields, maxArrayItems);

        public void Dispose()
        {
            runtime.Dispose();
            target.Dispose();
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
            return DumpImages.ByIdentity(name, (uint)buildTimeStamp, (uint)imageSize, directories)?.Path;
        }

        public string? FindPEImage(string fileName, SymbolProperties archivedUnder, System.Collections.Immutable.ImmutableArray<byte> buildIdOrUUID, OSPlatform originalPlatform, bool checkProperties) => null;
        public string? FindElfImage(string fileName, SymbolProperties archivedUnder, System.Collections.Immutable.ImmutableArray<byte> buildId, bool checkProperties) => null;
        public string? FindMachOImage(string fileName, SymbolProperties archivedUnder, System.Collections.Immutable.ImmutableArray<byte> uuid, bool checkProperties) => null;
    }
}
