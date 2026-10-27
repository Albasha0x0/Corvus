using Corvus.Core;
using Corvus.Native.Dump.Managed;
using Corvus.Native.Live;

namespace Corvus.Services;

// A 32-bit program under the 64-bit server is read by the 32-bit decoder process.
/// <summary>The .NET runtime of a session's program, read through ClrMD and its DAC with the inspector's read-only handle,
/// without suspending it; Windows only.</summary>
public sealed class LiveClr : IDisposable
{
    private readonly ClrDecoder _decoder;

    internal LiveClr(ClrDecoder decoder) => _decoder = decoder;

    /// <summary>Runtime name and version, e.g. ".NET 10.0.11 (CoreCLR)".</summary>
    public string RuntimeName => _decoder.RuntimeName;

    /// <summary>Why the runtime's code cannot be named (no DAC, no 32-bit decoder, the decoder stopped); null when it can.</summary>
    public string? Unavailable => Lost is { } lost ? $"decoder_stopped: {lost}" : _decoder.Live == null ? $"{_decoder.Dac.Status}: {_decoder.Dac.Detail}" : null;

    /// <summary>Why the 32-bit decoder process stopped (it failed, or a read took longer than its budget); null while it runs.</summary>
    public string? Lost { get; private set; }

    /// <summary>Called once, outside every read, when the decoder stops.</summary>
    public Action<string>? Stopped { get; set; }

    /// <summary>Called once, outside every read, when the running decoder answers a read with an error; that read gives nothing.</summary>
    public Action<string>? Failed { get; set; }

    private bool _failed;

    /// <summary>The runtime of process <paramref name="pid"/>; null when it hosts none (yet).</summary>
    public static async Task<LiveClr?> OpenAsync(int pid, DacRequest request, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var reader = new LiveDataReader(LiveProcess.Attach(pid, ct));
        try
        {
            // The decoder owns the reader from here.
            var decoder = await ClrDecoder.OpenLive(reader, request, ct).ConfigureAwait(false);
            return decoder != null ? new LiveClr(decoder) : null;
        }
        catch
        {
            reader.Dispose();
            throw;
        }
    }

    private T? Read<T>(Func<ILiveClrReads, T> read)
    {
        string? stopped = null, failed = null;
        lock (_decoder.Gate)
        {
            if (Lost != null || _decoder.Live is not { } live) return default;
            try { return read(live); }
            // The 32-bit decoder failed or ran past its budget, and was ended.
            catch (ToolError e) when (_decoder.Ended) { Lost = stopped = e.Message; }
            // A running decoder's error answer fails this read only; the first is noted.
            catch (ToolError e) when (!_failed) { _failed = true; failed = e.Message; }
            catch (ToolError) { }
        }
        if (stopped != null) Stopped?.Invoke(stopped);
        else if (failed != null) Failed?.Invoke(failed);
        return default;
    }

    /// <summary>Reads the runtime's heap or objects through its decoder; read errors reach the caller, a stopped decoder is recorded.</summary>
    internal T Decode<T>(Func<ClrDecoder, T> read)
    {
        string? stopped = null;
        lock (_decoder.Gate)
        {
            if (Unavailable is { } why) throw new ToolError(ErrorCode.Unsupported, $"the program's runtime cannot be read: {why}.");
            try { return read(_decoder); }
            catch (ToolError e) when (_decoder.Ended) { Lost = stopped = e.Message; }
        }
        Stopped?.Invoke(stopped);
        throw new ToolError(ErrorCode.ProviderUnavailable, $"the program's runtime cannot be read: decoder_stopped: {stopped}.");
    }

    /// <summary>Drops what was read before: the program has run since (new modules, code compiled, code moved to a later tier).</summary>
    public void Refresh() => Read(live => { live.Refresh(); return 0; });

    /// <summary>The method whose code holds <paramref name="ip"/>: its assembly file, signature and code start (0: unknown); null for other code.</summary>
    public (string Assembly, string Signature, ulong Start)? MethodAt(ulong ip) =>
        Read(live => live.MethodAt(ip)) is { } m ? (m.Assembly, m.Signature, m.Start) : null;

    /// <summary>Managed frame instruction pointers of a held thread, innermost first; empty when the runtime finds none.</summary>
    public IReadOnlyList<ulong> Frames(long thread, IReadOnlyDictionary<string, string> registers, int max) =>
        thread is <= 0 or > uint.MaxValue ? [] : Read(live => live.Frames((uint)thread, registers, max)) ?? [];

    /// <summary>A method's current code: what the runtime prepared, else its ReadyToRun body; null before a JIT method's first call.</summary>
    public (ulong Code, string Kind)? CodeOf(string path, int typeToken, int methodToken, ulong imageBase)
    {
        lock (_decoder.Gate)
        {
            if (Read(live => live.CodeOf(path, typeToken, methodToken)) is not { } code) return null;
            if (code.Code != 0) return (code.Code, code.Kind ?? "JIT");
            if (code.Flat) return null;
            ulong at = code.ModuleBase > 0 ? code.ModuleBase : imageBase;
            return at != 0 && ReadyToRunEntry(path, methodToken) is { } rva ? (at + rva, "ReadyToRun") : null;
        }
    }

    /// <summary>Where the runtime mapped the module loaded from <paramref name="path"/>, and whether as the file (flat) rather than as an image; null before it loads.</summary>
    public (ulong Base, bool Flat)? ModuleImage(string path) => Read(live => live.ModuleImage(path)) is { } m ? (m.Base, m.Flat) : null;

    /// <summary>Tokens of an assembly's methods the runtime has prepared code for (JIT or bound ReadyToRun); null when the read failed.</summary>
    public IReadOnlyList<uint>? Prepared(string path) => Read(live => live.Prepared(path));

    private readonly Dictionary<string, Native.ReadyToRun.R2RImage?> _r2r = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The RVA of a method's own ReadyToRun body (not a composite's); null without one.</summary>
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

    public void Dispose() => _decoder.Dispose();
}
