using System.Reflection.Metadata;
using Microsoft.Diagnostics.Runtime;

namespace Corvus.Native.Dump.Managed;

/// <summary>
/// Reads of a CLR opened through its DAC, as plain data: facts, the exception in flight, thread stacks and heap views.
/// Shared with the 32-bit decoder process; calls are not thread-safe.
/// </summary>
public sealed class ClrReads(ClrRuntime runtime)
{
    public const int MaxInnerExceptions = 5;
    public const int MaxExceptionFrames = 50;

    private readonly Dictionary<ulong, Guid?> _mvids = [];

    public ClrRuntime Runtime { get; } = runtime;

    public ManagedFacts Facts()
    {
        var heap = Runtime.Heap;
        var segments = heap.Segments;
        // The DAC lists segments from runtime globals even when the dump holds none of their memory: count captured ones only.
        ulong bytes = 0;
        var probe = new byte[8];
        foreach (var s in segments)
            if (s.ObjectRange.Length > 0 && Runtime.DataTarget.DataReader.Read(s.ObjectRange.Start, probe) == probe.Length) bytes += s.ObjectRange.Length;
        string? reason = !heap.CanWalkHeap ? "heap_not_walkable: the runtime reports the heap in an inconsistent state (a GC was running)"
            : segments.Length == 0 || bytes == 0 ? "heap_not_captured: the dump holds no GC heap memory (a stacks-only dump; write one with full or private read/write memory)"
            : null;
        return new ManagedFacts(Runtime.AppDomains.Length, Runtime.Threads.Length, new ManagedHeapState(reason == null, segments.Length, bytes, reason));
    }

    /// <summary>
    /// The exception in flight: on <paramref name="threadId"/> when given (the faulting thread of a CLR exception), else
    /// on the first thread that has one. Inner exceptions to <see cref="MaxInnerExceptions"/>, frames to <see cref="MaxExceptionFrames"/>.
    /// </summary>
    public ManagedException? Exception(uint? threadId)
    {
        foreach (var t in Runtime.Threads.Where(t => threadId == null || t.OSThreadId == threadId))
            if (t.CurrentException is { } e) return Describe(e, t.OSThreadId, 0);
        return null;
    }

    private ManagedException Describe(ClrException e, uint? thread, int depth)
    {
        var trace = e.StackTrace;
        var raw = trace.Length > 0 && trace.All(f => f.Method != null)
            ? trace.Select(f => (f.InstructionPointer, f.StackPointer, f.Method)).ToList()
            : TraceArray(e.Address) ?? trace.Select(f => (f.InstructionPointer, f.StackPointer, f.Method)).ToList();
        // frames past the first are calls: an IP the runtime did not step back is the return address
        var frames = raw.Take(MaxExceptionFrames).Select((f, i) => Frame(f.Item1, f.Item2, f.Item3, null, ClrStackFrameKind.ManagedMethod, returnAddress: i > 0)).ToList();
        var inner = depth < MaxInnerExceptions && e.Inner is { } i ? Describe(i, null, depth + 1) : null;
        return new ManagedException(e.Type?.Name ?? "(unknown type)", e.Message, e.HResult, e.Address, thread, frames, inner);
    }

    /// <summary>The managed stack of an OS thread, innermost first; empty when the runtime does not know the thread.</summary>
    public IReadOnlyList<ManagedFrame> Frames(uint threadId, int maxFrames)
    {
        var thread = Runtime.Threads.FirstOrDefault(t => t.OSThreadId == threadId);
        if (thread == null) return [];
        return thread.EnumerateStackTrace(false, maxFrames).Select(f => Frame(f.InstructionPointer, f.StackPointer, f.Method, f.FrameName, f.Kind, returnAddress: true)).ToList();
    }

    /// <summary>
    /// The exception's _stackTrace array read here: ClrMD takes its header as two pointers, but .NET 9+ adds a 32-bit
    /// keep-alive count after the 32-bit size, which shifts every element by 4 bytes on x86. The header length whose
    /// elements all name methods wins; null when none does.
    /// </summary>
    private List<(ulong Ip, ulong Sp, ClrMethod? Method)>? TraceArray(ulong exception)
    {
        var obj = Runtime.Heap.GetObject(exception);
        if (!obj.IsValid || obj.Type?.GetFieldByName("_stackTrace") == null) return null;
        var trace = obj.ReadObjectField("_stackTrace");
        if (trace.IsNull || !trace.IsArray) return null;
        // .NET 9+: an object[] whose first element is the byte[] when the trace keeps objects alive
        if (trace.Type?.ComponentType is { IsObjectReference: true } && trace.AsArray().Length > 0) trace = trace.AsArray().GetObjectValue(0);
        if (trace.IsNull || !trace.IsArray) return null;
        var reader = Runtime.DataTarget.DataReader;
        uint ptr = (uint)reader.PointerSize;
        ulong data = trace.Address + 2 * ptr, end = data + (ulong)trace.AsArray().Length;
        if (!reader.Read(data, out uint count) || count == 0 || count > 4096) return null;
        foreach (uint header in new[] { 2 * ptr, 3 * ptr })
        {
            if (data + header + count * 4 * ptr > end) continue;
            var frames = new List<(ulong, ulong, ClrMethod?)>();
            for (uint i = 0; i < count; i++)
            {
                ulong at = data + header + i * 4 * ptr;
                if (!reader.ReadPointer(at, out ulong ip) || !reader.ReadPointer(at + ptr, out ulong sp) || !reader.ReadPointer(at + 2 * ptr, out ulong md)
                    || Runtime.GetMethodByHandle(md) is not { } method) { frames = null; break; }
                frames.Add((ip, sp, method));
            }
            if (frames != null) return frames;
        }
        return null;
    }

    /// <summary>
    /// A frame; <paramref name="returnAddress"/> when its IP may be a return address (a thread walk, a caller in an
    /// exception trace) and the call is the byte before it. Stepping back is harmless for an IP already inside the call.
    /// </summary>
    private ManagedFrame Frame(ulong ip, ulong sp, ClrMethod? m, string? frameName, ClrStackFrameKind kind, bool returnAddress)
    {
        if (kind != ClrStackFrameKind.ManagedMethod || m == null)
            return new ManagedFrame(ip, sp, false, $"[{frameName ?? kind.ToString()}]", null, null, null, null, null);
        int? il = null;
        if (ip != 0)
        {
            var map = m.ILOffsetMap;
            il = (returnAddress ? IlOffset(map, ip - 1) : null) ?? IlOffset(map, ip);
        }
        var module = m.Type?.Module;
        return new ManagedFrame(ip, sp, true, m.Signature ?? m.Name ?? "(unknown method)", m.MetadataToken != 0 ? m.MetadataToken : null, il,
            module?.Name, module != null ? Mvid(module) : null, m.NativeCode != 0 && m.NativeCode != ulong.MaxValue ? m.NativeCode : null);
    }

    /// <summary>
    /// The IL offset of the map entry holding <paramref name="ip"/>; null outside mapped code (prolog, epilog, no mapping)
    /// and without a map: a dump without the runtime's memory has none, which ClrMD's GetILOffset reads as offset 0.
    /// </summary>
    private static int? IlOffset(System.Collections.Immutable.ImmutableArray<ILToNativeMap> map, ulong ip)
    {
        if (map.IsDefaultOrEmpty) return null;
        foreach (var e in map)
            if (ip >= e.StartAddress && ip < e.EndAddress) return e.ILOffset >= 0 ? e.ILOffset : null;
        return null;
    }

    /// <summary>A type with its module's path and MVID.</summary>
    public ManagedType Type(ClrType type) =>
        new(type.Name ?? "?", type.Module?.Name, type.Module is { } m ? Mvid(m) : null, type.MetadataToken);

    /// <summary>The module's MVID, read from its metadata in dump memory (or the read-only image).</summary>
    public Guid? Mvid(ClrModule module)
    {
        if (_mvids.TryGetValue(module.Address, out var known)) return known;
        Guid? mvid = null;
        if (module.MetadataAddress != 0 && module.MetadataLength is > 0 and <= 256u << 20)
        {
            var bytes = new byte[module.MetadataLength];
            if (Runtime.DataTarget.DataReader.Read(module.MetadataAddress, bytes) == bytes.Length)
                mvid = ReadMvid(bytes);
        }
        return _mvids[module.Address] = mvid;
    }

    public static Guid? ReadMvid(byte[] metadata)
    {
        try
        {
            using var provider = MetadataReaderProvider.FromMetadataImage(System.Collections.Immutable.ImmutableArray.Create(metadata));
            var md = provider.GetMetadataReader();
            return md.GetGuid(md.GetModuleDefinition().Mvid);
        }
        catch (BadImageFormatException) { return null; }
    }

    public HeapWalk Walk(string? type, ulong minSize, long maxObjects, int objectsFrom, int objectsTake, CancellationToken ct) =>
        ClrHeapView.Walk(this, type, minSize, maxObjects, objectsFrom, objectsTake, ct);

    public ObjectView? Object(ulong address, int depth, int maxFields, int maxArrayItems) =>
        ClrHeapView.Object(this, address, depth, maxFields, maxArrayItems);
}
