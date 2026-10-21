using System.ComponentModel;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Dump.Managed;

namespace Corvus.Services;

public sealed partial class MinidumpService
{
    public const long DefaultMaxHeapObjects = 5_000_000;

    /// <summary>How to write a dump that holds the GC heap: a Linux core is written by the runtime's own dump tools.</summary>
    internal static string HeapHint(bool core) => core
        ? "write the core with the heap (createdump --withheap, dotnet-dump collect --type Heap, DOTNET_DbgMiniDumpType=2) to inspect the heap"
        : "write the dump with full memory (procdump -ma, DOTNET_DbgMiniDumpType=4, MiniDumpWithFullMemory) to inspect the heap";

    /// <summary>mode=stats: a type with its object count and total size; mode=objects: one object.</summary>
    /// <summary>A TypeDef token, or null when there is none: arrays and generic instances carry 0 or a nil row (0x02000000).</summary>
    internal static string? TypeDefToken(long token) => (token & 0xFFFFFF) == 0 ? null : $"0x{token:X8}";

    public sealed record HeapRow(string Type,
        [property: Description("stats: bytes of all its objects; objects: the object's size.")] ulong Size)
    {
        [Description("stats: objects of the type.")] public long? Count { get; init; }
        [Description("objects: the object's address (dump_object).")] public string? Address { get; init; }
        [Description("objects: a string's value (up to 200 characters).")] public string? Value { get; init; }
        [Description("stats: id of the loaded assembly that is the type's module build, for get_type_info / decompile_member.")] public string? Assembly { get; init; }
        [Description("stats: TypeDef token of the type in that assembly.")] public string? Token { get; init; }
    }

    public sealed record HeapReport(
        string Dump, string Mode, string? Type, ulong MinSize,
        [property: Description("Objects walked.")] long Walked,
        [property: Description("Size of every matching object walked.")] ulong MatchedBytes,
        IReadOnlyList<HeapRow> Items, int Offset,
        [property: Description("stats: matching types; objects: matching objects.")] int Total,
        [property: Description("False when the walk stopped at maxObjects: counts cover only the walked part of the heap.")] bool TotalExact,
        IReadOnlyList<string> Notes);

    public sealed record ObjectFieldRow(
        [property: Description("Field name, dotted for fields of expanded references and structs; [i] for array elements.")] string Path,
        int Depth, string? Type, int? Offset,
        [property: Description("Primitive value, quoted string, null, or the array length; absent for objects and structs (see Address).")] string? Value,
        [property: Description("Address of the referenced object (dump_object) or of an inline struct.")] string? Address);

    public sealed record ObjectReport(
        string Dump, string Address, string Type, ulong Size,
        [property: Description("Id of the loaded assembly that is the type's module build.")] string? Assembly,
        [property: Description("TypeDef token, for get_type_info / decompile_member with assembly.")] string? Token,
        [property: Description("match, mismatch (the loaded assembly of that name is another build) or unknown.")] string? BuildCheck,
        [property: Description("A string's value, or a boxed primitive's.")] string? Value,
        [property: Description("Array length.")] int? Length,
        IReadOnlyList<ObjectFieldRow> Fields,
        [property: Description("More fields or elements exist than maxFields / maxArrayItems allowed.")] bool Truncated,
        IReadOnlyList<string> Notes);

    /// <summary>The dump's loaded runtime, or an error naming why it is not available.</summary>
    private async Task<ClrDecoder> RequireRuntime(Session s, bool heap, CancellationToken ct)
    {
        if (s.Core is { IsMachO: true })
            throw new ToolError(ErrorCode.Unsupported, $"{s.Id} is a Mach-O core: its .NET heap is not decoded here.", "dump_stack and read_dump_memory read the core");
        string? runtime = null;
        if (s.Core is { } core ? (runtime = CoreRuntime(core)) is not (".NET (CoreCLR)" or "Mono") : !HostsClr(s.Dump, out runtime))
            throw new ToolError(ErrorCode.Unsupported, "the dumped process has no .NET runtime (CoreCLR or .NET Framework) loaded.", "use dump_stack and read_dump_memory");
        if (runtime == "Mono")
            throw new ToolError(ErrorCode.Unsupported, "Mono has no DAC: its heap cannot be decoded.", "symbolize_stack_text resolves Mono frames from Player.log");
        var decoder = await Decoder(s, new DacRequest(), ct) ?? throw new ToolError(ErrorCode.Unsupported, "the dumped process hosts no CLR this tool decodes.");
        if (!decoder.Loaded)
            throw new ToolError(ErrorCode.Unsupported, $"the runtime's DAC is not loaded ({decoder.Dac.Status}): {decoder.Dac.Detail}",
                "open_minidump with dacPath (the dumped runtime's DAC or its folder) or downloadDac=true, then call again");
        if (heap)
        {
            ManagedHeapState state;
            using (AssemblyWorkspace.Lock(decoder.Gate)) state = decoder.Facts().Heap;
            if (!state.Walkable)
                throw new ToolError(ErrorCode.Unsupported, $"{state.Reason}.", HeapHint(s.Core != null));
        }
        return decoder;
    }


    /// <summary>A running program's heap changes during a read: said in every live heap and object report.</summary>
    internal const string LiveHeapNote = "The program runs during the read: objects allocated, moved or freed meanwhile can be missing or counted twice; " +
                                         "a snapshot (live_session action=snapshot, then open_minidump) holds one state.";

    private static bool HeapStats(string? mode) => (mode?.Trim().ToLowerInvariant() ?? "stats") switch
    {
        "" or "stats" => true,
        "objects" => false,
        _ => throw new ToolError(ErrorCode.InvalidArgument, $"mode '{mode}' is not stats or objects."),
    };

    public async Task<HeapReport> Heap(string path, string? mode, string? type, ulong minSize, int offset, int limit, long maxObjects, CancellationToken ct)
    {
        bool stats = HeapStats(mode);
        using var s = Open(path, null);
        var decoder = await RequireRuntime(s, heap: true, ct);
        using (AssemblyWorkspace.Lock(decoder.Gate))
            return HeapOf(s.Id, decoder, a => Hex(s.Memory, a), HeapHint(s.Core != null), stats, type, minSize, offset, limit, maxObjects, [], ct);
    }

    /// <summary>The heap of a session's running program, read through its runtime without stopping it.</summary>
    public HeapReport Heap(LiveSession session, LiveClr? clr, string? mode, string? type, ulong minSize, int offset, int limit, long maxObjects, CancellationToken ct)
    {
        bool stats = HeapStats(mode);
        var runtime = LiveRuntime(session, clr);
        return runtime.Decode(decoder =>
        {
            if (decoder.Facts().Heap is { Walkable: false } state)
                throw new ToolError(ErrorCode.Conflict, $"{state.Reason}: a garbage collection is in progress.", "call again");
            // cancelling ends the 32-bit decoder process, which the session keeps for its stops: that walk runs to its end
            return HeapOf(session.Id, decoder, a => LiveHex(session, a), "call again", stats, type, minSize, offset, limit, maxObjects, [LiveHeapNote],
                decoder.OutOfProcess ? CancellationToken.None : ct);
        });
    }

    private HeapReport HeapOf(string id, ClrDecoder decoder, Func<ulong, string> hex, string hint, bool stats, string? type, ulong minSize, int offset, int limit,
        long maxObjects, List<string> notes, CancellationToken ct)
    {
        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, MaxListLimit);
        maxObjects = Math.Clamp(maxObjects, 1, 100_000_000);
        string? pattern = string.IsNullOrWhiteSpace(type) ? null : type.Trim();
        var (rows, objects, matched, walked, stopped) = decoder.Walk(pattern, minSize, maxObjects, stats ? 0 : offset, stats ? 0 : limit, ct);
        if (walked == 0)
            throw new ToolError(ErrorCode.Unsupported, "heap_not_captured: no object of the GC heap is readable in this dump.", hint);
        if (stopped) notes.Add($"The walk stopped after {walked} objects (maxObjects): counts cover only that part of the heap.");
        ulong bytes = 0;
        foreach (var r in rows) bytes += r.TotalSize;
        if (stats)
        {
            var page = rows.Skip(offset).Take(limit).Select(r =>
            {
                var (assembly, _) = AssemblyFor(r.Type.ModulePath, r.Type.Mvid);
                return new HeapRow(r.Type.Name, r.TotalSize) { Count = r.Count, Assembly = assembly, Token = TypeDefToken(r.Type.Token) };
            }).ToList();
            return new HeapReport(id, "stats", pattern, minSize, walked, bytes, page, offset, rows.Count, !stopped, notes);
        }
        var list = objects.Select(o => new HeapRow(o.Type, o.Size) { Address = hex(o.Address), Value = o.Value }).ToList();
        return new HeapReport(id, "objects", pattern, minSize, walked, bytes, list, offset, (int)Math.Min(matched, int.MaxValue), !stopped, notes);
    }

    private static ulong ObjectAddress(string address) =>
        NativeAddress.Number((address ?? "").Trim())
        ?? throw new ToolError(ErrorCode.InvalidArgument, $"'{address}' is not an address.", "pass the hex address of a managed object (dump_heap objects, the exception address of open_minidump)");

    public async Task<ObjectReport> Object(string path, string address, int depth, int maxFields, int maxArrayItems, CancellationToken ct)
    {
        using var s = Open(path, null);
        ulong at = ObjectAddress(address);
        var decoder = await RequireRuntime(s, heap: false, ct);
        using (AssemblyWorkspace.Lock(decoder.Gate))
            return ObjectOf(s.Id, decoder, a => Hex(s.Memory, a), "(or the dump does not hold it)", at, depth, maxFields, maxArrayItems, []);
    }

    /// <summary>One object of a session's running program, read through its runtime without stopping it.</summary>
    public ObjectReport Object(LiveSession session, LiveClr? clr, string address, int depth, int maxFields, int maxArrayItems)
    {
        ulong at = ObjectAddress(address);
        return LiveRuntime(session, clr).Decode(decoder =>
            ObjectOf(session.Id, decoder, a => LiveHex(session, a), "(a garbage collection can move or free an object after its address was listed)", at, depth, maxFields, maxArrayItems, [LiveHeapNote]));
    }

    private ObjectReport ObjectOf(string id, ClrDecoder decoder, Func<ulong, string> hex, string missing, ulong at, int depth, int maxFields, int maxArrayItems, List<string> notes)
    {
        depth = Math.Clamp(depth, 1, 3);
        maxFields = Math.Clamp(maxFields, 1, 1000);
        maxArrayItems = Math.Clamp(maxArrayItems, 0, 1000);
        var view = decoder.Object(at, depth, maxFields, maxArrayItems)
                   ?? throw new ToolError(ErrorCode.NotFound, $"no managed object at {hex(at)} {missing}.",
                       "pass an object address from dump_heap mode=objects or open_minidump's managed exception");
        var (assembly, check) = AssemblyFor(view.Type.ModulePath, view.Type.Mvid);
        if (check == "mismatch") notes.Add($"{assembly} is another build of the type's module (MVID differs).");
        var fields = view.Fields.Select(f => new ObjectFieldRow(f.Path, f.Depth, f.Type, f.Offset, f.Value, f.Address is { } a ? hex(a) : null)).ToList();
        return new ObjectReport(id, hex(view.Address), view.Type.Name, view.Size, assembly,
            TypeDefToken(view.Type.Token), check, view.Value, view.Length, fields, view.Truncated, notes);
    }

    /// <summary>The session's runtime, or an error naming why its program has none to read.</summary>
    private static LiveClr LiveRuntime(LiveSession session, LiveClr? clr)
    {
        if (clr == null)
            throw new ToolError(ErrorCode.Unsupported, $"the program of session {session.Id} has loaded no .NET runtime (CoreCLR or .NET Framework) this tool reads.",
                "a program spawned suspended loads its runtime once it runs (live_break action=continue)");
        if (clr.Unavailable is { } why)
            throw new ToolError(ErrorCode.Unsupported, $"the program's runtime ({clr.RuntimeName}) cannot be read: {why}.",
                "open the session with downloadDac=true for a DAC this machine lacks");
        return clr;
    }

    private static string LiveHex(LiveSession session, ulong v) => session.Arch is "ia32" or "arm" ? $"0x{v & 0xFFFFFFFF:X}" : $"0x{v:X}";
}
