using Microsoft.Diagnostics.Runtime;
using Corvus.Core;
using Corvus.Native.Dump.Managed;
using Corvus.Native.Live;

namespace Corvus.Services;

/// <summary>
/// The .NET runtime of a session's program, read through ClrMD and the runtime's own DAC from the process's memory with
/// the inspector's read-only handle; the program is never suspended. Names JIT-compiled and ReadyToRun code, walks a
/// held thread's managed frames from the registers its stop captured, and finds a managed method's code. Windows, and
/// a program of this server's architecture, only.
/// </summary>
public sealed class LiveClr : IDisposable
{
    private readonly ClrDecoder _decoder;
    private readonly LiveDataReader _reader;

    private LiveClr(ClrDecoder decoder, LiveDataReader reader)
    {
        _decoder = decoder;
        _reader = reader;
    }

    /// <summary>Runtime name and version, e.g. ".NET 10.0.11 (CoreCLR)".</summary>
    public string RuntimeName => _decoder.RuntimeName;

    /// <summary>Why the runtime's code cannot be named (no DAC, another architecture); null when it can.</summary>
    public string? Unavailable => _decoder.Runtime == null ? $"{_decoder.Dac.Status}: {_decoder.Dac.Detail}" : null;

    /// <summary>The runtime of process <paramref name="pid"/>; null when it hosts none (yet).</summary>
    public static async Task<LiveClr?> OpenAsync(int pid, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var reader = new LiveDataReader(LiveProcess.Attach(pid, ct));
        try
        {
            var decoder = await ClrDecoder.OpenLive(reader, new DacRequest(), ct).ConfigureAwait(false);
            if (decoder != null) return new LiveClr(decoder, reader);
            reader.Dispose();
            return null;
        }
        catch
        {
            reader.Dispose();
            throw;
        }
    }

    /// <summary>Drops what was read before: the program has run since (new modules, code compiled, code moved to a later tier).</summary>
    public void Refresh()
    {
        lock (_decoder.Gate)
        {
            if (_decoder.Runtime is not { } runtime) return;
            _reader.FlushCachedData();
            runtime.FlushCachedData();
        }
    }

    /// <summary>The method whose code holds <paramref name="ip"/>: its assembly file, signature and code start; null for other code.</summary>
    public (string Assembly, string Signature, ulong Start)? MethodAt(ulong ip)
    {
        lock (_decoder.Gate)
        {
            if (_decoder.Runtime?.GetMethodByInstructionPointer(ip) is not { } m) return null;
            var hc = m.HotColdInfo;
            ulong start = hc.ColdSize > 0 && ip >= hc.ColdStart && ip - hc.ColdStart < hc.ColdSize ? hc.ColdStart : hc.HotStart;
            return (FileName(m.Type?.Module), m.Signature ?? m.Name ?? "?", start == 0 || start > ip ? ip : start);
        }
    }

    /// <summary>
    /// The managed frames of a held thread, innermost first, walked by the runtime from the registers its stop captured
    /// (instruction pointers of methods only); empty when the runtime does not know the thread or the walk finds nothing.
    /// </summary>
    public IReadOnlyList<ulong> Frames(long thread, IReadOnlyDictionary<string, string> registers, int max)
    {
        lock (_decoder.Gate)
        {
            if (_decoder.Runtime is not { } runtime || thread is <= 0 or > uint.MaxValue || !_reader.SetContext((uint)thread, registers)) return [];
            try
            {
                var t = runtime.Threads.FirstOrDefault(x => x.OSThreadId == (uint)thread);
                if (t == null) return [];
                return [.. t.EnumerateStackTrace(false, max).Where(f => f.Kind == ClrStackFrameKind.ManagedMethod && f.InstructionPointer != 0).Select(f => f.InstructionPointer)];
            }
            catch (Exception e) when (e is InvalidOperationException or ClrDiagnosticsException) { return []; }
            finally { _reader.ClearContext((uint)thread); }
        }
    }

    /// <summary>
    /// Where the method <paramref name="methodToken"/> of type <paramref name="typeToken"/> in the module loaded from
    /// <paramref name="path"/> has code now: what the runtime prepared (JIT-compiled or ReadyToRun), else its ReadyToRun
    /// body, which runs from the first call, in the module mapped at <paramref name="imageBase"/> (the runtime's own record
    /// of the module when it has one). Null when it has none yet: a JIT-compiled method gets code at its first call.
    /// </summary>
    public (ulong Code, string Kind)? CodeOf(string path, int typeToken, int methodToken, ulong imageBase)
    {
        lock (_decoder.Gate)
        {
            if (_decoder.Runtime is not { } runtime) return null;
            var module = runtime.EnumerateModules().FirstOrDefault(m => m.Name is { } n && SamePath(n, path));
            var type = module?.EnumerateTypeDefToMethodTableMap().FirstOrDefault(x => x.Token == typeToken) is { MethodTable: > 0 } map ? runtime.GetTypeByMethodTable(map.MethodTable) : null;
            if (type?.Methods.FirstOrDefault(m => m.MetadataToken == methodToken) is { NativeCode: var c } method && c != 0 && c != ulong.MaxValue)
                return (c, method.CompilationType == MethodCompilationType.Jit ? "JIT" : "ReadyToRun");
            if (module is { Layout: ModuleLayout.Flat }) return null;
            ulong at = module?.ImageBase is > 0 and var b ? b : imageBase;
            return at != 0 && ReadyToRunEntry(path, methodToken) is { } rva ? (at + rva, "ReadyToRun") : null;
        }
    }

    /// <summary>Where the runtime mapped the module loaded from <paramref name="path"/>, and whether as the file (flat) rather than as an image; null before it loads.</summary>
    public (ulong Base, bool Flat)? ModuleImage(string path)
    {
        lock (_decoder.Gate)
            return _decoder.Runtime?.EnumerateModules().FirstOrDefault(m => m.Name is { } n && SamePath(n, path)) is { ImageBase: > 0 } m
                ? (m.ImageBase, m.Layout == ModuleLayout.Flat) : null;
    }

    /// <summary>True when the runtime's module <paramref name="name"/> is the file at <paramref name="path"/>; a bundled assembly is named by its bundle-relative path.</summary>
    private static bool SamePath(string name, string path) => Path.IsPathRooted(name)
        ? string.Equals(Path.GetFullPath(name), Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase)
        : path.Replace('\\', '/').EndsWith('/' + name.Replace('\\', '/'), StringComparison.OrdinalIgnoreCase);

    private readonly Dictionary<string, Native.ReadyToRun.R2RImage?> _r2r = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The metadata tokens of the methods of an assembly the runtime has prepared code for: JIT-compiled at a first call,
    /// or ReadyToRun code bound at a first call.
    /// </summary>
    public IReadOnlyList<uint> Prepared(string path)
    {
        lock (_decoder.Gate)
        {
            if (_decoder.Runtime is not { } runtime) return [];
            var found = new List<uint>();
            foreach (var module in runtime.EnumerateModules().Where(m => m.Name is { } n && SamePath(n, path)))
                foreach (var type in module.EnumerateTypeDefToMethodTableMap().Select(x => runtime.GetTypeByMethodTable(x.MethodTable)).OfType<ClrType>())
                    foreach (var m in type.Methods)
                        if (m.Type == type && m.MetadataToken != 0 && m.NativeCode != 0 && m.NativeCode != ulong.MaxValue) found.Add((uint)m.MetadataToken);
            return found;
        }
    }

    /// <summary>
    /// The RVA of a method's precompiled body in the image at <paramref name="path"/> (its own ReadyToRun code, not a
    /// composite's); null without one.
    /// </summary>
    private uint? ReadyToRunEntry(string path, int token)
    {
        if (!File.Exists(path)) return null;
        if (!_r2r.TryGetValue(path, out var image))
        {
            try { image = Native.ReadyToRun.R2RImage.Open(Native.Pe.PeFile.Open(path)); }
            catch (Exception e) when (e is Native.ReadyToRun.R2RFormatException or ToolError or IOException or UnauthorizedAccessException) { image = null; }
            _r2r[path] = image;
        }
        if (image == null || image.IsComponent) return null;
        uint rid = (uint)token & 0x00FFFFFF;
        var entry = image.Entries.FirstOrDefault(e => !e.IsInstance && e.MethodDefRid == rid);
        return entry != null && entry.RuntimeFunction >= 0 && entry.RuntimeFunction < image.RuntimeFunctions.Count
            ? image.RuntimeFunctions[entry.RuntimeFunction].Begin : null;
    }

    private static string FileName(ClrModule? module) =>
        module?.Name is { Length: > 0 } path ? Path.GetFileName(path) : module?.AssemblyName ?? "?";

    public void Dispose() => _decoder.Dispose();
}
