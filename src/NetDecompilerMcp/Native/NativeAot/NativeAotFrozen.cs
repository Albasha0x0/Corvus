using System.Buffers.Binary;
using System.Text;

namespace NetDecompilerMcp.Native.NativeAot;

/// <summary>
/// An object preinitialized by the compiler. <see cref="Rva"/> is the object reference (its MethodTable pointer, as code
/// loads it); the 8-byte object header precedes it. <see cref="Text"/> is set for strings.
/// </summary>
public sealed record NativeAotFrozenObject(uint Rva, uint MethodTable, string TypeName, uint Size, string? Text = null);

/// <summary>
/// Linear walk of the frozen object region (section 206): contiguous objects [header][MethodTable*][payload] of
/// BaseSize + ComponentSize × length bytes, 8-byte aligned; zero padding between them is skipped.
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
        if (!aot.Image.Is64Bit)
        {
            frozen.Stage = new(name, NativeAotStage.Unsupported, "32-bit images are not read yet");
            return frozen;
        }
        var image = aot.Hydrated;
        var types = aot.Types;
        var objects = new List<NativeAotFrozenObject>();
        uint at = region.StartRva;
        string? stop = null;
        Span<byte> head = stackalloc byte[24];
        while (at + 16 <= region.EndRva)
        {
            if ((objects.Count & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            if (objects.Count >= MaxObjects) { stop = "the object limit"; break; }
            int n = image.Read(at, head);
            if (n < 16) { stop = $"unmapped bytes at RVA 0x{at:X}"; break; }
            if (BinaryPrimitives.ReadUInt64LittleEndian(head) == 0 && BinaryPrimitives.ReadUInt64LittleEndian(head[8..]) == 0)
            {
                at += 8;
                continue;
            }
            var mt = image.PointerAt(at + 8) is { } rva ? types.At(rva) : null;
            if (mt == null) { stop = $"no MethodTable for the object at RVA 0x{at + 8:X}"; break; }
            uint length = mt.ComponentSize != 0 && n >= 20 ? BinaryPrimitives.ReadUInt32LittleEndian(head[16..]) : 0;
            ulong size = mt.BaseSize + (ulong)mt.ComponentSize * length;
            size = (size + 7) & ~7ul;
            if (size < 16 || at + size > region.EndRva) { stop = $"the object at RVA 0x{at + 8:X} runs past the region"; break; }
            string? text = mt.Name == "System.String" && mt.ComponentSize == 2 && length <= MaxStringChars ? String(image, at + 20, length) : null;
            objects.Add(new NativeAotFrozenObject(at + 8, mt.Rva, mt.Name, (uint)size, text));
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
        var bytes = new byte[length * 2];
        int n = image.Read(rva, bytes);
        return Encoding.Unicode.GetString(bytes, 0, n & ~1);
    }
}
