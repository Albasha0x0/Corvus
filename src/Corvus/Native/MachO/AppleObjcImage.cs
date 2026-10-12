using System.Buffers.Binary;
using System.Text;

namespace Corvus.Native.MachO;

/// <summary>
/// Reads Objective-C and Swift metadata of a Mach-O image by virtual address. Pointer slots go through the fixup table:
/// a bind names its symbol (a raw read would give 0), a rebase gives its target; slots no fixup covers read as stored.
/// </summary>
internal sealed class AppleObjcImage(MachOFile image)
{
    /// <summary>Longest C string read (selectors, type encodings, mangled names).</summary>
    public const int MaxString = 4096;

    public MachOFile Image { get; } = image;
    public int PointerSize { get; } = image.Is64Bit ? 8 : 4;

    /// <summary>What a pointer slot holds: a target address, or the symbol a bind names (leading '_' removed).</summary>
    public readonly record struct Pointer(ulong Target, string? Symbol, long Addend = 0)
    {
        public bool IsNull => Target == 0 && Symbol == null;
    }

    public bool Has(ulong va, int size) => Image.TryVaToRva(va, out uint rva) && (ulong)rva + (ulong)size <= Image.SizeOfImage;

    private bool ReadBytes(ulong va, Span<byte> into) => Image.TryVaToRva(va, out uint rva) && Image.Read(rva, into) == into.Length;

    public uint U32(ulong va)
    {
        Span<byte> b = stackalloc byte[4];
        if (!ReadBytes(va, b)) return 0;
        return Image.BigEndian ? BinaryPrimitives.ReadUInt32BigEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);
    }

    public int I32(ulong va) => unchecked((int)U32(va));

    public ushort U16(ulong va)
    {
        Span<byte> b = stackalloc byte[2];
        if (!ReadBytes(va, b)) return 0;
        return Image.BigEndian ? BinaryPrimitives.ReadUInt16BigEndian(b) : BinaryPrimitives.ReadUInt16LittleEndian(b);
    }

    /// <summary>A pointer-sized value as mapped (rebases applied, binds 0).</summary>
    public ulong Word(ulong va)
    {
        Span<byte> b = stackalloc byte[8];
        var slot = b[..PointerSize];
        if (!ReadBytes(va, slot)) return 0;
        if (PointerSize == 4) return Image.BigEndian ? BinaryPrimitives.ReadUInt32BigEndian(slot) : BinaryPrimitives.ReadUInt32LittleEndian(slot);
        return Image.BigEndian ? BinaryPrimitives.ReadUInt64BigEndian(slot) : BinaryPrimitives.ReadUInt64LittleEndian(slot);
    }

    /// <summary>The pointer stored at <paramref name="va"/>, through the fixups (top byte cleared).</summary>
    public Pointer Ptr(ulong va)
    {
        switch (Image.Fixups.Resolve(va))
        {
            case MachOFixup.Bind b: return new Pointer(0, Unprefixed(b.Symbol), b.Addend);
            case MachOFixup.Rebase r: return new Pointer(r.TargetVm & 0x00FF_FFFF_FFFF_FFFFUL, null);
            default:
                ulong raw = Word(va);
                return new Pointer(PointerSize == 8 ? raw & 0x00FF_FFFF_FFFF_FFFFUL : raw, null);
        }
    }

    /// <summary>The target of a 32-bit self-relative offset at <paramref name="va"/>, or 0 for a null offset.</summary>
    public ulong Relative(ulong va)
    {
        int offset = I32(va);
        return offset == 0 ? 0 : unchecked(va + (ulong)(long)offset);
    }

    /// <summary>
    /// A relative pointer whose low bit marks indirection (Swift's RelativeIndirectablePointer): direct to its target,
    /// or through a pointer slot (often a bind to another image's symbol).
    /// </summary>
    public Pointer RelativeIndirectable(ulong va)
    {
        int offset = I32(va);
        if (offset == 0) return default;
        ulong target = unchecked(va + (ulong)(long)(offset & ~1));
        return (offset & 1) != 0 ? Ptr(target) : new Pointer(target, null);
    }

    /// <summary>The NUL-terminated UTF-8 string at <paramref name="va"/>, or null when unmapped or not terminated in <see cref="MaxString"/> bytes.</summary>
    public string? CString(ulong va)
    {
        if (va == 0 || !Image.TryVaToRva(va, out uint rva)) return null;
        Span<byte> buffer = stackalloc byte[256];
        var bytes = new List<byte>();
        while (bytes.Count < MaxString)
        {
            int n = Image.Read(rva + (uint)bytes.Count, buffer);
            if (n <= 0) return null;
            int nul = buffer[..n].IndexOf((byte)0);
            if (nul >= 0)
            {
                foreach (byte b in buffer[..nul]) bytes.Add(b);
                return Encoding.UTF8.GetString([.. bytes]);
            }
            foreach (byte b in buffer[..n]) bytes.Add(b);
        }
        return null;
    }

    /// <summary>
    /// A Swift mangled name at <paramref name="va"/> as one char per byte (symbolic references keep their 4- or 8-byte
    /// payloads), with the address of every char so references resolve; null when unreadable.
    /// </summary>
    public string? MangledName(ulong va)
    {
        if (va == 0 || !Image.TryVaToRva(va, out uint rva)) return null;
        var sb = new StringBuilder();
        Span<byte> one = stackalloc byte[1];
        while (sb.Length < MaxString)
        {
            if (Image.Read(rva + (uint)sb.Length, one) != 1) return null;
            byte c = one[0];
            if (c == 0) return sb.ToString();
            sb.Append((char)c);
            int payload = c is >= 0x01 and <= 0x17 ? 4 : c is >= 0x18 and <= 0x1F ? PointerSize : 0;
            for (int i = 0; i < payload; i++)
            {
                if (Image.Read(rva + (uint)sb.Length, one) != 1) return null;
                sb.Append((char)one[0]);
            }
        }
        return null;
    }

    /// <summary>Sections of that name in any segment (__DATA, __DATA_CONST, __DATA_DIRTY, __TEXT).</summary>
    public IEnumerable<MachOSection> Sections(string name) => Image.AllSections.Where(s => s.Name == name && s.Size > 0);

    public static string Unprefixed(string symbol) => symbol.StartsWith('_') ? symbol[1..] : symbol;
}
