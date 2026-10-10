using System.Buffers.Binary;
using System.Text;

namespace NetDecompilerMcp.Native.Msvc;

/// <summary>Bounds-checked reads of mapped image bytes for exception metadata decoding.</summary>
internal sealed class EhReader(INativeImage image)
{
    private readonly byte[] _scratch = new byte[8];
    private readonly IReadOnlyList<uint> _relocations = image.RelocationRvas;

    public INativeImage Image => image;

    public bool U32(uint rva, out uint value)
    {
        value = 0;
        if (image.Read(rva, _scratch.AsSpan(0, 4)) < 4) return false;
        value = BinaryPrimitives.ReadUInt32LittleEndian(_scratch);
        return true;
    }

    public bool I32(uint rva, out int value)
    {
        bool ok = U32(rva, out uint v);
        value = (int)v;
        return ok;
    }

    /// <summary>Reads exactly <paramref name="destination"/>.Length bytes.</summary>
    public bool Bytes(uint rva, Span<byte> destination) => image.Read(rva, destination) == destination.Length;

    /// <summary>Mapped bytes from <paramref name="rva"/>, at most <paramref name="max"/> (fewer at the end of the image).</summary>
    public byte[] Window(uint rva, int max)
    {
        var buffer = new byte[max];
        int n = image.Read(rva, buffer);
        return n == max ? buffer : buffer.AsSpan(0, Math.Max(n, 0)).ToArray();
    }

    public bool IsCode(uint rva) => rva != 0 && image.SectionAt(rva) is { IsExecutable: true };

    /// <summary>Inside a section (not the headers, not past the image).</summary>
    public bool IsMapped(uint rva) => rva != 0 && image.SectionAt(rva) != null;

    /// <summary>Inside a section that is not executable.</summary>
    public bool IsData(uint rva) => rva != 0 && image.SectionAt(rva) is { IsExecutable: false };

    /// <summary>x86: a virtual address in the image as an RVA.</summary>
    public bool VaToRva(uint va, out uint rva)
    {
        rva = 0;
        if (va < image.ImageBase || va - image.ImageBase >= image.SizeOfImage) return false;
        rva = (uint)(va - image.ImageBase);
        return true;
    }

    public bool HasRelocations => _relocations.Count > 0;

    /// <summary>A base relocation patches the pointer at <paramref name="rva"/>; true for images without relocations.</summary>
    public bool IsRelocatedOrUnknown(uint rva) => _relocations.Count == 0 || IsRelocated(rva);

    public bool IsRelocated(uint rva)
    {
        int lo = 0, hi = _relocations.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            uint v = _relocations[mid];
            if (v == rva) return true;
            if (v < rva) lo = mid + 1; else hi = mid - 1;
        }
        return false;
    }

    /// <summary>x86: the pointer at <paramref name="at"/> as an RVA; 0 stays 0. False when it is outside the image or not relocated.</summary>
    public bool Pointer32(uint at, out uint rva)
    {
        rva = 0;
        if (!U32(at, out uint va)) return false;
        if (va == 0) return true;
        return VaToRva(va, out rva) && IsRelocatedOrUnknown(at);
    }

    /// <summary>A NUL-terminated printable ASCII string of at most <paramref name="max"/> characters, or null.</summary>
    public string? CString(uint rva, int max)
    {
        var buffer = Window(rva, max + 1);
        int n = Array.IndexOf(buffer, (byte)0);
        if (n <= 0) return null;
        for (int i = 0; i < n; i++)
            if (buffer[i] is < 0x20 or > 0x7E) return null;
        return Encoding.ASCII.GetString(buffer, 0, n);
    }
}

/// <summary>
/// Reads the FH4 compressed encoding: unsigned values of 1-5 bytes whose length is given by the low bits of the first
/// byte, and plain little-endian 32-bit values. Any read past the window sets <see cref="Failed"/>.
/// </summary>
internal struct Fh4Cursor(byte[] buffer, int position = 0)
{
    private static ReadOnlySpan<byte> Lengths => [1, 2, 1, 3, 1, 2, 1, 4, 1, 2, 1, 3, 1, 2, 1, 5];

    public int Position { get; private set; } = position;
    public bool Failed { get; private set; }

    public uint ReadUnsigned()
    {
        if (Failed || Position >= buffer.Length) { Failed = true; return 0; }
        int length = Lengths[buffer[Position] & 0xF];
        if (Position + length > buffer.Length) { Failed = true; return 0; }
        var b = buffer.AsSpan(Position, length);
        uint value = length switch
        {
            1 => (uint)b[0] >> 1,
            2 => (uint)(b[0] | b[1] << 8) >> 2,
            3 => (uint)(b[0] | b[1] << 8 | b[2] << 16) >> 3,
            4 => BinaryPrimitives.ReadUInt32LittleEndian(b) >> 4,
            _ => BinaryPrimitives.ReadUInt32LittleEndian(b[1..]),
        };
        Position += length;
        return value;
    }

    public int ReadInt()
    {
        if (Failed || Position + 4 > buffer.Length) { Failed = true; return 0; }
        int value = BinaryPrimitives.ReadInt32LittleEndian(buffer.AsSpan(Position));
        Position += 4;
        return value;
    }

    public byte ReadByte()
    {
        if (Failed || Position >= buffer.Length) { Failed = true; return 0; }
        return buffer[Position++];
    }
}
