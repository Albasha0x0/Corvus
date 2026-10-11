using System.Buffers.Binary;

namespace NetDecompilerMcp.Native.NativeAot;

/// <summary>An interface dispatch cell: the call site's interface MethodTable and slot, and the method's name when known.</summary>
public sealed record NativeAotDispatchCell(uint Rva, uint Interface, string InterfaceName, int Slot, string? Method)
{
    public string Target => $"{InterfaceName}::{Method ?? $"slot{Slot}"}";
}

/// <summary>A type's code for an interface slot, from its dispatch map.</summary>
public sealed record NativeAotImplementation(uint Type, string TypeName, uint Code);

/// <summary>
/// Interface dispatch in a NativeAOT module. Cells (InterfaceDispatchCellNode.cs, InterfaceDispatchCellSectionNode.cs,
/// .NET 7–10): two pointers each, the initial dispatch stub and a 32-bit relative pointer to the interface MethodTable
/// with flags in its low bits (3: direct, 2: through an indirection cell); runs of cells of one slot end with a null
/// pointer and the slot number. Interface method names come from the named implementations in the dispatch maps.
/// </summary>
public sealed class NativeAotDispatch
{
    private const int MaxRun = 64;
    private const uint FlagsMask = 3, InterfaceRelative = 3, IndirectedInterfaceRelative = 2;

    private NativeAotDispatch() { }

    public IReadOnlyList<NativeAotDispatchCell> Cells { get; private set; } = [];
    public NativeAotStage Stage { get; private set; } = new("dispatch cells", NativeAotStage.Absent);
    private Dictionary<uint, NativeAotDispatchCell> byRva = [];
    private Dictionary<(string, int), string> methods = [];
    private Dictionary<(uint, int), List<NativeAotImplementation>> implementations = [];

    public NativeAotDispatchCell? CellAt(uint rva) => byRva.GetValueOrDefault(rva);

    /// <summary>The method of slot <paramref name="slot"/> of an interface (by name, generic arguments ignored), or null.</summary>
    public string? InterfaceMethod(string interfaceName, int slot) => methods.GetValueOrDefault((Definition(interfaceName), slot));

    /// <summary>The types whose dispatch maps implement slot <paramref name="slot"/> of <paramref name="iface"/>, with the code.</summary>
    public IReadOnlyList<NativeAotImplementation> Implementers(uint iface, int slot) => implementations.GetValueOrDefault((iface, slot)) ?? [];

    private static string Definition(string type) => type.Split('<')[0];

    public static NativeAotDispatch Read(NativeAotImage aot, CancellationToken ct = default)
    {
        var dispatch = new NativeAotDispatch();
        var types = aot.Types;
        string Name(uint rva) => types.At(rva)?.Name ?? $"MT_{rva:X}";

        // Implementations and the interface method names they vote for ("IEnumerator slot 0" -> MoveNext).
        var votes = new Dictionary<(string, int), Dictionary<string, int>>();
        foreach (var t in types.ByRva.Values.Where(t => t.DispatchMap != 0).OrderBy(t => t.Rva))
        {
            ct.ThrowIfCancellationRequested();
            foreach (var impl in types.Implementations(t))
            {
                if (impl.Interface == 0 || impl.Code == 0) continue;
                var key = (impl.Interface, impl.InterfaceSlot);
                if (!dispatch.implementations.TryGetValue(key, out var list)) dispatch.implementations[key] = list = [];
                list.Add(new NativeAotImplementation(t.Rva, t.Name, impl.Code));
                if (!aot.Names.MethodAt.TryGetValue(impl.Code, out var named)) continue;
                var vote = (Definition(Name(impl.Interface)), impl.InterfaceSlot);
                var method = named.Name.Name[(named.Name.Name.LastIndexOf('.') + 1)..]; // explicit implementations: "Ns.IFoo.Bar" -> "Bar"
                if (!votes.TryGetValue(vote, out var counts)) votes[vote] = counts = new(StringComparer.Ordinal);
                counts[method] = counts.GetValueOrDefault(method) + 1;
            }
        }
        dispatch.methods = votes.ToDictionary(v => v.Key, v => v.Value.OrderByDescending(c => c.Value).ThenBy(c => c.Key, StringComparer.Ordinal).First().Key);

        // Cells: a pointer to code, then the tagged relative pointer to an interface MethodTable (zero padded to a pointer).
        var image = aot.Hydrated;
        uint ptr = (uint)image.PointerSize;
        var cells = new List<NativeAotDispatchCell>();
        var seen = new HashSet<uint>();
        int unnamed = 0;
        foreach (uint slot in Candidates(aot, ct))
        {
            if (seen.Contains(slot) || Interface(aot, slot) is not { } iface) continue;
            // The run's terminator: a null pointer and the slot number.
            int? number = null;
            var run = new List<(uint Cell, uint Iface)> { (slot, iface) };
            for (uint at = slot + 2 * ptr; run.Count <= MaxRun; at += 2 * ptr)
            {
                if (Interface(aot, at) is { } next) { run.Add((at, next)); continue; }
                if (image.PointerAt(at) == null && Natural(image, at + ptr) is { } n && n is >= 0 and < 4096) number = (int)n;
                break;
            }
            foreach (var (cell, i) in run) seen.Add(cell);
            if (number is not { } k) continue;
            foreach (var (cell, i) in run)
            {
                string name = Name(i);
                var method = dispatch.InterfaceMethod(name, k);
                if (method == null) unnamed++;
                cells.Add(new NativeAotDispatchCell(cell, i, name, k, method));
            }
        }
        dispatch.Cells = [.. cells.OrderBy(c => c.Rva)];
        dispatch.byRva = dispatch.Cells.ToDictionary(c => c.Rva);
        dispatch.Stage = cells.Count == 0 ? new("dispatch cells", NativeAotStage.Absent, "no interface dispatch cells found")
            : new("dispatch cells", NativeAotStage.Complete, $"{cells.Count} cells, {cells.Count - unnamed} with the method name; {dispatch.implementations.Count} interface slots with implementations");
        return dispatch;
    }

    /// <summary>
    /// Pointer-aligned data addresses followed by a tagged relative pointer (low bits 2 or 3); the stub pointer is not
    /// required, ELF images bind it by symbol.
    /// </summary>
    private static IEnumerable<uint> Candidates(NativeAotImage aot, CancellationToken ct)
    {
        var image = aot.Hydrated;
        int ptr = image.PointerSize;
        foreach (var section in aot.Image.Sections)
        {
            if (section.IsExecutable || section.MappedSize < 2 * ptr) continue;
            ct.ThrowIfCancellationRequested();
            var bytes = new byte[Math.Min(section.MappedSize, (uint)Array.MaxLength)];
            int n = image.Read(section.Rva, bytes);
            for (int at = (int)((ptr - section.Rva % ptr) % ptr); at + 2 * ptr <= n; at += ptr)
            {
                uint value = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(at + ptr));
                if ((value & FlagsMask) is InterfaceRelative or IndirectedInterfaceRelative && (ptr == 4 || BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(at + ptr + 4)) == 0))
                    yield return section.Rva + (uint)at;
            }
        }
    }

    /// <summary>The interface MethodTable of the cell at <paramref name="cell"/>, or null when it is not a cell.</summary>
    private static uint? Interface(NativeAotImage aot, uint cell)
    {
        var image = aot.Hydrated;
        uint ptr = (uint)image.PointerSize;
        if (image.PointerAt(cell) is { } stub && aot.Image.SectionAt(stub) is not { IsExecutable: true }) return null;
        Span<byte> b = stackalloc byte[8];
        if (image.Read(cell + ptr, b[..(int)ptr]) != ptr) return null;
        uint value = BinaryPrimitives.ReadUInt32LittleEndian(b);
        if (ptr == 8 && BinaryPrimitives.ReadUInt32LittleEndian(b[4..]) != 0) return null;
        uint flags = value & FlagsMask;
        if (flags is not (InterfaceRelative or IndirectedInterfaceRelative)) return null;
        long target = cell + ptr + (long)(int)(value & ~FlagsMask);
        if (target <= 0 || target >= aot.Image.SizeOfImage) return null;
        uint mt = flags == IndirectedInterfaceRelative ? image.PointerAt((uint)target) ?? 0 : (uint)target;
        if (aot.Types.ByRva.TryGetValue(mt, out var type)) return type.ElementType == NativeAotElementType.Interface ? mt : null;
        // An interface the crawl missed (canonical generic interfaces): read on demand when the stub pointer confirms the cell.
        return image.IsPointerSlot(cell) && image.PointerAt(cell) is { } code && aot.Image.SectionAt(code) is { IsExecutable: true }
               && aot.Types.At(mt) is { ElementType: NativeAotElementType.Interface } ? mt : null;
    }

    private static long? Natural(HydratedImage image, uint rva)
    {
        Span<byte> b = stackalloc byte[8];
        var slot = b[..image.PointerSize];
        if (image.Read(rva, slot) != slot.Length) return null;
        return slot.Length == 8 ? BinaryPrimitives.ReadInt64LittleEndian(slot) : BinaryPrimitives.ReadInt32LittleEndian(slot);
    }
}
