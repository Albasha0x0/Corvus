using System.ComponentModel;
using Microsoft.Diagnostics.Runtime;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Dump.Managed;

namespace NetDecompilerMcp.Services;

public sealed partial class MinidumpService
{
    public const long DefaultMaxHeapObjects = 5_000_000;

    public sealed record HeapTypeRow(
        string Type, long Count, ulong TotalSize,
        [property: Description("Id of the loaded assembly that is the type's module build, for get_type_info / decompile_type.")] string? Assembly,
        [property: Description("TypeDef token of the type in that assembly.")] string? Token);

    public sealed record HeapObjectRow(string Address, string Type, ulong Size,
        [property: Description("A string's value (up to 200 characters).")] string? Value);

    public sealed record HeapReport(
        string Dump, string Mode, string? Type, ulong MinSize,
        [property: Description("Objects walked.")] long Walked,
        [property: Description("The walk stopped at maxObjects: counts cover only the walked part of the heap.")] bool WalkStopped,
        [property: Description("stats: matching types; objects: matching objects.")] long Total,
        int Offset, bool Truncated,
        [property: Description("Size of every matching object walked.")] ulong MatchedBytes,
        IReadOnlyList<HeapTypeRow> Types, IReadOnlyList<HeapObjectRow> Objects, IReadOnlyList<string> Notes);

    public sealed record ObjectFieldRow(
        [property: Description("Field name, dotted for fields of expanded references and structs; [i] for array elements.")] string Path,
        int Depth, string? Type, int? Offset,
        [property: Description("Primitive value, quoted string, null, or the array length; absent for objects and structs (see Address).")] string? Value,
        [property: Description("Address of the referenced object (dump_object) or of an inline struct.")] string? Address);

    public sealed record ObjectReport(
        string Dump, string Address, string Type, ulong Size,
        [property: Description("Id of the loaded assembly that is the type's module build.")] string? Assembly,
        [property: Description("TypeDef token, for get_type_info / decompile_type with assembly.")] string? Token,
        [property: Description("match, mismatch (the loaded assembly of that name is another build) or unknown.")] string? BuildCheck,
        [property: Description("A string's value, or a boxed primitive's.")] string? Value,
        [property: Description("Array length.")] int? Length,
        IReadOnlyList<ObjectFieldRow> Fields,
        [property: Description("More fields or elements exist than maxFields / maxArrayItems allowed.")] bool Truncated,
        IReadOnlyList<string> Notes);

    /// <summary>The dump's loaded runtime, or an error naming why it is not available.</summary>
    private async Task<ClrDecoder> RequireRuntime(Session s, bool heap, CancellationToken ct)
    {
        if (!HostsClr(s.Dump, out var runtime))
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
            lock (decoder.Gate) state = decoder.Facts().Heap;
            if (!state.Walkable)
                throw new ToolError(ErrorCode.Unsupported, $"{state.Reason}.", "write the dump with full memory (procdump -ma, DOTNET_DbgMiniDumpType=4) to inspect the heap");
        }
        return decoder;
    }

    public async Task<HeapReport> Heap(string path, string? mode, string? type, ulong minSize, int offset, int limit, long maxObjects, CancellationToken ct)
    {
        bool stats = (mode?.Trim().ToLowerInvariant() ?? "stats") switch
        {
            "" or "stats" => true,
            "objects" => false,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"mode '{mode}' is not stats or objects."),
        };
        using var s = Open(path, null);
        var decoder = await RequireRuntime(s, heap: true, ct);
        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, MaxListLimit);
        maxObjects = Math.Clamp(maxObjects, 1, 100_000_000);
        string? pattern = string.IsNullOrWhiteSpace(type) ? null : type.Trim();
        var notes = new List<string>();
        lock (decoder.Gate)
        {
            var heap = decoder.Runtime!.Heap;
            var (rows, objects, matched, walked, stopped) = ClrHeapView.Walk(heap, pattern, minSize, maxObjects, stats ? 0 : offset, stats ? 0 : limit, ct);
            if (stopped) notes.Add($"The walk stopped after {walked} objects (maxObjects): counts cover only that part of the heap.");
            ulong bytes = 0;
            foreach (var r in rows) bytes += r.TotalSize;
            if (stats)
            {
                var page = rows.Skip(offset).Take(limit).Select(r =>
                {
                    var (assembly, _) = r.ClrType?.Module is { } m ? AssemblyFor(m.Name, decoder.Mvid(m)) : (null, null);
                    return new HeapTypeRow(r.Type, r.Count, r.TotalSize, assembly, r.ClrType is { MetadataToken: not 0 } t ? $"0x{t.MetadataToken:X8}" : null);
                }).ToList();
                return new HeapReport(s.Id, "stats", pattern, minSize, walked, stopped, rows.Count, offset, offset + page.Count < rows.Count, bytes, page, [], notes);
            }
            var list = objects.Select(o => new HeapObjectRow(Hex(s.Dump, o.Address), o.Type, o.Size, o.Value)).ToList();
            return new HeapReport(s.Id, "objects", pattern, minSize, walked, stopped, matched, offset, offset + list.Count < matched, bytes, [], list, notes);
        }
    }

    public async Task<ObjectReport> Object(string path, string address, int depth, int maxFields, int maxArrayItems, CancellationToken ct)
    {
        using var s = Open(path, null);
        ulong at = NativeAddress.Number((address ?? "").Trim())
                   ?? throw new ToolError(ErrorCode.InvalidArgument, $"'{address}' is not an address.", "pass the hex address of a managed object (dump_heap objects, the exception address of open_minidump)");
        var decoder = await RequireRuntime(s, heap: false, ct);
        depth = Math.Clamp(depth, 1, 3);
        maxFields = Math.Clamp(maxFields, 1, 1000);
        maxArrayItems = Math.Clamp(maxArrayItems, 0, 1000);
        lock (decoder.Gate)
        {
            var view = ClrHeapView.Object(decoder.Runtime!.Heap, at, depth, maxFields, maxArrayItems)
                       ?? throw new ToolError(ErrorCode.NotFound, $"no managed object at {Hex(s.Dump, at)} (or the dump does not hold it).",
                           "pass an object address from dump_heap mode=objects or open_minidump's managed exception");
            var notes = new List<string>();
            var (assembly, check) = view.Type.Module is { } m ? AssemblyFor(m.Name, decoder.Mvid(m)) : (null, null);
            if (check == "mismatch") notes.Add($"{assembly} is another build of the type's module (MVID differs).");
            var fields = view.Fields.Select(f => new ObjectFieldRow(f.Path, f.Depth, f.Type, f.Offset, f.Value, f.Address is { } a ? Hex(s.Dump, a) : null)).ToList();
            return new ObjectReport(s.Id, Hex(s.Dump, view.Address), view.Type.Name ?? "?", view.Size, assembly,
                view.Type.MetadataToken != 0 ? $"0x{view.Type.MetadataToken:X8}" : null, check, view.Value, view.Length, fields, view.Truncated, notes);
        }
    }
}
