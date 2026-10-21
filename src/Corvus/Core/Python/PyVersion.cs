using System.Buffers.Binary;

namespace Corvus.Core.Python;

/// <summary>Python versions from a .pyc magic number, and the .pyc header each version writes.</summary>
public static class PyVersion
{
    /// <summary>The last magic number of each release (importlib's MAGIC_NUMBER), used to rebuild a header.</summary>
    private static readonly (int Major, int Minor, int Magic)[] Finals =
    [
        (2, 7, 62211), (3, 0, 3131), (3, 1, 3151), (3, 2, 3180), (3, 3, 3230), (3, 4, 3310), (3, 5, 3351), (3, 6, 3379), (3, 7, 3394),
        (3, 8, 3413), (3, 9, 3425), (3, 10, 3439), (3, 11, 3495), (3, 12, 3531), (3, 13, 3571), (3, 14, 3627),
    ];

    /// <summary>The highest magic each 3.x release range may use: CPython allots each version a block of numbers.</summary>
    private static readonly (int Minor, int Last)[] Blocks =
    [
        (0, 3139), (1, 3159), (2, 3189), (3, 3249), (4, 3319), (5, 3359), (6, 3389), (7, 3399), (8, 3419), (9, 3429), (10, 3449),
        (11, 3499), (12, 3549), (13, 3599), (14, 3649), (15, 3699), (16, 3749),
    ];

    /// <summary>The version a .pyc magic (its first two bytes, then "\r\n") belongs to; null for an unknown magic.</summary>
    public static (int Major, int Minor)? FromMagic(ReadOnlySpan<byte> header)
    {
        if (header.Length < 4 || header[2] != '\r' || header[3] != '\n') return null;
        int magic = BinaryPrimitives.ReadUInt16LittleEndian(header);
        if (magic is >= 62171 and <= 62211) return (2, 7);
        if (magic < 3000) return null;
        foreach (var (minor, last) in Blocks)
            if (magic <= last) return (3, minor);
        return null;
    }

    /// <summary>A .pyc file: a known magic, the flags of PEP 552 (3.7+), then a code object.</summary>
    public static bool LooksLikePyc(ReadOnlySpan<byte> b)
    {
        if (FromMagic(b) is not { } v || b.Length <= HeaderLength(v)) return false;
        if (AtLeast(v, 3, 7) && BinaryPrimitives.ReadUInt32LittleEndian(b[4..]) > 3) return false;
        return (b[HeaderLength(v)] & 0x7F) == 'c';
    }

    public static int Magic(ReadOnlySpan<byte> header) => BinaryPrimitives.ReadUInt16LittleEndian(header);

    /// <summary>The magic bytes of a version's final release; null for a version outside 2.7 to 3.14.</summary>
    public static byte[]? MagicOf((int Major, int Minor) version)
    {
        foreach (var f in Finals)
            if ((f.Major, f.Minor) == version) return [(byte)f.Magic, (byte)(f.Magic >> 8), (byte)'\r', (byte)'\n'];
        return null;
    }

    /// <summary>The .pyc header length: 16 bytes from 3.7 (PEP 552), 12 from 3.3, 8 before.</summary>
    public static int HeaderLength((int Major, int Minor) version) => AtLeast(version, 3, 7) ? 16 : AtLeast(version, 3, 3) ? 12 : 8;

    public static bool AtLeast((int Major, int Minor) v, int major, int minor) => v.Major > major || (v.Major == major && v.Minor >= minor);

    /// <summary>A .pyc: <paramref name="magic"/> and a zeroed rest of the header, then the marshalled code.</summary>
    public static byte[] WithHeader(ReadOnlySpan<byte> magic, (int Major, int Minor) version, ReadOnlySpan<byte> code)
    {
        var pyc = new byte[HeaderLength(version) + code.Length];
        magic[..4].CopyTo(pyc);
        code.CopyTo(pyc.AsSpan(HeaderLength(version)));
        return pyc;
    }

    /// <summary>A version from a library name: python310.dll, libpython3.14.dll, libpython3.11.so.1.0, Python (framework).</summary>
    public static (int Major, int Minor)? FromLibraryName(string name)
    {
        var m = System.Text.RegularExpressions.Regex.Match(Path.GetFileName(name), @"^(?:lib)?python(?<major>[23])\.?(?<minor>\d{1,2})(?:[dmu]*)?\.(?:dll|so|dylib)",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);
        return m.Success ? (int.Parse(m.Groups["major"].Value), int.Parse(m.Groups["minor"].Value)) : null;
    }

    public static string Label((int Major, int Minor) v) => $"{v.Major}.{v.Minor}";
}
