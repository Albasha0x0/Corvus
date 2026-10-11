using System.Buffers.Binary;
using System.Text;

namespace NetDecompilerMcp.Native.NativeAot;

/// <summary>
/// An object preinitialized by the compiler. <see cref="Rva"/> is the object reference (its MethodTable pointer, as code
/// loads it); the pointer-sized object header precedes it. <see cref="Text"/> is set for strings.
/// </summary>
public sealed record NativeAotFrozenObject(uint Rva, uint MethodTable, string TypeName, uint Size, string? Text = null);

/// <summary>
/// Linear walk of the frozen object region (section 206): contiguous objects [header][MethodTable*][payload] of
/// BaseSize + ComponentSize × length bytes, pointer aligned; zero padding between them is skipped.
/// </summary>
public sealed class NativeAotFrozen
{
    private const int MaxObjects = 4_000_000, MaxStringChars = 1 << 20;

    private NativeAotFrozen() { }

    public IReadOnlyList<NativeAotFrozenObject> Objects { get; private set; } = [];
    public NativeAotStage Stage { get; private set; } = new("frozen objects", NativeAotStage.Absent);
    public int StringCount => Objects.Count(o => o.Text != null);

    public static NativeAotFrozen Read(NativeAotImage aot, CancellationToken ct = default)
    {
        var frozen = new NativeAotFrozen();
        const string name = "frozen objects";
        var region = aot.Header.Section(SectionId.FrozenObjectRegion);
        if (region is not { Length: > 0 }) return frozen;
        var image = aot.Hydrated;
        var types = aot.Types;
        var objects = new List<NativeAotFrozenObject>();
        uint p = (uint)image.PointerSize, at = region.StartRva;
        string? stop = null;
        Span<byte> head = stackalloc byte[24];
        while (at + 2 * p <= region.EndRva)
        {
            if ((objects.Count & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            if (objects.Count >= MaxObjects) { stop = "the object limit"; break; }
            int n = image.Read(at, head[..(int)(2 * p + 4)]);
            if (n < 2 * p) { stop = $"unmapped bytes at RVA 0x{at:X}"; break; }
            if (!head[..(int)(2 * p)].ContainsAnyExcept((byte)0))
            {
                at += p;
                continue;
            }
            uint obj = at + p;
            var mt = image.PointerAt(obj) is { } rva ? types.At(rva) : null;
            if (mt == null) { stop = $"no MethodTable for the object at RVA 0x{obj:X}"; break; }
            uint length = mt.ComponentSize != 0 && n >= 2 * p + 4 ? BinaryPrimitives.ReadUInt32LittleEndian(head[(int)(2 * p)..]) : 0;
            ulong size = mt.BaseSize + (ulong)mt.ComponentSize * length;
            size = (size + p - 1) & ~(p - 1ul);
            if (size < 2 * p || at + size > region.EndRva) { stop = $"the object at RVA 0x{obj:X} runs past the region"; break; }
            string? text = mt.Name == "System.String" && mt.ComponentSize == 2 && length <= MaxStringChars ? String(image, obj + p + 4, length) : null;
            objects.Add(new NativeAotFrozenObject(obj, mt.Rva, mt.Name, (uint)size, text));
            at += (uint)size;
        }
        frozen.Objects = objects;
        int strings = objects.Count(o => o.Text != null);
        frozen.Stage = stop == null
            ? new(name, NativeAotStage.Complete, $"{objects.Count} objects, {strings} strings, {region.Length} bytes")
            : new(name, NativeAotStage.Partial, $"{objects.Count} objects, {strings} strings; stopped at {stop}");
        return frozen;
    }

    private static string String(HydratedImage image, uint rva, uint length)
    {
        // The length comes from the object; a string cannot hold more characters than the file has bytes.
        var bytes = new byte[(int)Math.Min(length * 2L, image.Image.FileSize > 0 ? image.Image.FileSize : Array.MaxLength)];
        int n = image.Read(rva, bytes);
        return Encoding.Unicode.GetString(bytes, 0, n & ~1);
    }
}
