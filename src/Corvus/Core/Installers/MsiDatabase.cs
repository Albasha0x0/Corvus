using System.Buffers.Binary;
using Corvus.Core.Documents;

namespace Corvus.Core.Installers;

/// <summary>A Windows Installer database (.msi), patch (.msp) or transform (.mst): a compound file named by its root class id.</summary>
internal static class MsiDatabase
{
    private static readonly Guid Package = new("000C1084-0000-0000-C000-000000000046");
    private static readonly Guid Patch = new("000C1086-0000-0000-C000-000000000046");
    private static readonly Guid Transform = new("000C1082-0000-0000-C000-000000000046");

    /// <summary>The kind ("msi", "msp", "mst") from the root entry's class id, read without parsing the file; null for other compound files.</summary>
    public static string? KindOf(ReadOnlySpan<byte> b)
    {
        if (!CompoundFile.Looks(b)) return null;
        int shift = BinaryPrimitives.ReadUInt16LittleEndian(b[30..]);
        if (shift is not (9 or 12)) return null;
        long at = 512L + (long)BinaryPrimitives.ReadUInt32LittleEndian(b[48..]) * (1 << shift) + 80;
        if (at + 16 > b.Length) return null;
        var clsid = new Guid(b.Slice((int)at, 16));
        return clsid == Package ? "msi" : clsid == Patch ? "msp" : clsid == Transform ? "mst" : null;
    }

    public static bool Looks(ReadOnlySpan<byte> b) => KindOf(b) != null;
}
