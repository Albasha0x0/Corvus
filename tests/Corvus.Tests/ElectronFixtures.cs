using System.Buffers.Binary;
using System.Text;

namespace Corvus.Tests;

/// <summary>Electron-shaped files: an x64 PE with the INTEGRITY/ELECTRONASAR resource, fuses and version strings, and app folders around an ASAR.</summary>
public static class ElectronFixtures
{
    public const string Sentinel = "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX";

    /// <summary>
    /// A minimal PE32+ whose .rsrc holds <paramref name="integrityJson"/> as INTEGRITY/ELECTRONASAR (when given), followed by
    /// an overlay with the fuse wire (when given) and the user agent and Node header strings.
    /// </summary>
    public static byte[] Executable(string? integrityJson, string? fuses = "010011011", string electron = "44.2.0", string chromium = "152.0.7977.76", string node = "24.20.0")
    {
        var rsrc = integrityJson == null ? new byte[16] : ResourceTree(Encoding.UTF8.GetBytes(integrityJson));
        int rawSize = (rsrc.Length + 0x1FF) & ~0x1FF;
        var pe = new byte[0x200 + rawSize];
        pe[0] = (byte)'M'; pe[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(pe.AsSpan(0x3C), 0x40);
        "PE\0\0"u8.CopyTo(pe.AsSpan(0x40));
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x44), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x46), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x54), 0xF0);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x56), 0x22);
        const int opt = 0x58;
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(opt), 0x20B);
        BinaryPrimitives.WriteUInt64LittleEndian(pe.AsSpan(opt + 24), 0x140000000);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(opt + 32), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(opt + 36), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(opt + 56), (uint)(0x1000 + ((rawSize + 0xFFF) & ~0xFFF)));
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(opt + 60), 0x200);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(opt + 68), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(opt + 108), 16);
        if (integrityJson != null)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(opt + 112 + 16), 0x1000);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(opt + 112 + 20), (uint)rsrc.Length);
        }
        const int section = opt + 0xF0;
        ".rsrc"u8.CopyTo(pe.AsSpan(section));
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(section + 8), (uint)rsrc.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(section + 12), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(section + 16), (uint)rawSize);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(section + 20), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(section + 36), 0x40000040);
        rsrc.CopyTo(pe, 0x200);

        var overlay = new StringBuilder("\0padding\0");
        if (fuses != null) overlay.Append(Sentinel).Append('\x01').Append((char)fuses.Length).Append(fuses).Append('\0');
        overlay.Append($"isPrintingEnabled\0Chrome/{chromium} Electron/{electron}\0{chromium}\0");
        overlay.Append($"https://artifacts.electronjs.org/headers/dist/v{electron}/node-v{node}-headers.tar.gz\0");
        return [.. pe, .. Encoding.Latin1.GetBytes(overlay.ToString())];
    }

    /// <summary>type "INTEGRITY" -> name "ELECTRONASAR" -> language 1033 -> data, offsets relative to the section start (VA 0x1000).</summary>
    private static byte[] ResourceTree(byte[] data)
    {
        const int typeDir = 24, nameDir = 48, dataEntry = 72, typeName = 88, itemName = 108, payload = 136;
        var b = new byte[payload + data.Length];
        void Dir(int at, ushort named, ushort ids) { BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(at + 12), named); BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(at + 14), ids); }
        void Entry(int at, uint id, uint target) { BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(at), id); BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(at + 4), target); }
        void Name(int at, string s) { BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(at), (ushort)s.Length); Encoding.Unicode.GetBytes(s).CopyTo(b, at + 2); }
        Dir(0, 1, 0); Entry(16, 0x80000000 | typeName, 0x80000000 | typeDir);
        Dir(typeDir, 1, 0); Entry(typeDir + 16, 0x80000000 | itemName, 0x80000000 | nameDir);
        Dir(nameDir, 0, 1); Entry(nameDir + 16, 1033, dataEntry);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(dataEntry), 0x1000 + payload);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(dataEntry + 4), (uint)data.Length);
        Name(typeName, "INTEGRITY");
        Name(itemName, "ELECTRONASAR");
        data.CopyTo(b, payload);
        return b;
    }

    /// <summary>The integrity resource JSON naming resources\app.asar.</summary>
    public static string IntegrityJson(string headerSha256) => $$"""[{"file":"resources\\app.asar","alg":"SHA256","value":"{{headerSha256}}"}]""";

    /// <summary>
    /// A Windows-layout app under <paramref name="root"/>: App.exe (declaring <paramref name="declaredHash"/> when given) and
    /// resources/app.asar; returns the archive path.
    /// </summary>
    public static string App(string root, byte[] archive, string? declaredHash, string? fuses = "010011011")
    {
        Directory.CreateDirectory(Path.Combine(root, "resources"));
        File.WriteAllBytes(Path.Combine(root, "App.exe"), Executable(declaredHash == null ? null : IntegrityJson(declaredHash), fuses));
        var asar = Path.Combine(root, "resources", "app.asar");
        File.WriteAllBytes(asar, archive);
        return asar;
    }
}
