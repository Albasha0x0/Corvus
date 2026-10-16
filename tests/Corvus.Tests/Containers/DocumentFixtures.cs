using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Corvus.Tests;

/// <summary>In-test writers for Office fixtures: compound files (MS-CFB v3), MS-OVBA compression, VBA projects, BIFF8 workbooks, OLE Package streams.</summary>
internal static class DocumentFixtures
{
    private const uint EndOfChain = 0xFFFFFFFE, Free = 0xFFFFFFFF, FatSect = 0xFFFFFFFD;

    /// <summary>A version 3 compound file of these streams ("Storage/Name" paths), small streams in the mini stream.</summary>
    public static byte[] Compound(IEnumerable<(string Path, byte[] Data)> streams, Guid? rootClsid = null)
    {
        // directory: root, then every storage and stream; children chained through the right sibling
        var entries = new List<(string Name, int Type, byte[]? Data, int Parent)> { ("Root Entry", 5, null, -1) };
        int StorageOf(string path)
        {
            int parent = 0;
            var parts = path.Split('/');
            for (int i = 0; i < parts.Length - 1; i++)
            {
                int found = entries.FindIndex(e => e.Type == 1 && e.Parent == parent && e.Name == parts[i]);
                if (found < 0) { entries.Add((parts[i], 1, null, parent)); found = entries.Count - 1; }
                parent = found;
            }
            return parent;
        }
        foreach (var (path, data) in streams) entries.Add((path.Split('/')[^1], 2, data, StorageOf(path)));

        var mini = new MemoryStream();
        var miniFat = new List<uint>();
        var regular = new List<(int Entry, byte[] Data)>();
        var start = new uint[entries.Count];
        for (int i = 0; i < entries.Count; i++)
        {
            if (entries[i].Data is not { } d) continue;
            if (d.Length >= 4096) { regular.Add((i, d)); continue; }
            if (d.Length == 0) { start[i] = EndOfChain; continue; }
            int first = miniFat.Count, count = (d.Length + 63) / 64;
            start[i] = (uint)first;
            for (int k = 0; k < count; k++) miniFat.Add(k == count - 1 ? EndOfChain : (uint)(first + k + 1));
            mini.Write(d);
            mini.Write(new byte[count * 64 - d.Length]);
        }

        int dirSectors = (entries.Count * 128 + 511) / 512;
        int miniFatSectors = (miniFat.Count * 4 + 511) / 512;
        int miniSectors = (int)((mini.Length + 511) / 512);
        int dataSectors = regular.Sum(r => (r.Data.Length + 511) / 512);
        int content = dirSectors + miniFatSectors + miniSectors + dataSectors;
        int fatSectors = 1;
        while (fatSectors * 128 < fatSectors + content) fatSectors++;

        var fat = new List<uint>();
        for (int i = 0; i < fatSectors; i++) fat.Add(FatSect);
        uint Chain(int n)
        {
            if (n == 0) return EndOfChain;
            uint first = (uint)fat.Count;
            for (int k = 0; k < n; k++) fat.Add(k == n - 1 ? EndOfChain : (uint)(fat.Count + 1));
            return first;
        }
        uint dirStart = Chain(dirSectors), miniFatStart = Chain(miniFatSectors), miniStart = Chain(miniSectors);
        foreach (var (entry, data) in regular) start[entry] = Chain((data.Length + 511) / 512);
        start[0] = miniSectors > 0 ? miniStart : EndOfChain;

        var output = new MemoryStream();
        var header = new byte[512];
        new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(header, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(24), 0x3E);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(26), 3);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(28), 0xFFFE);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(30), 9);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(32), 6);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(44), (uint)fatSectors);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(48), dirStart);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(56), 4096);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(60), miniFatSectors > 0 ? miniFatStart : EndOfChain);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(64), (uint)miniFatSectors);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(68), EndOfChain);
        for (int i = 0; i < 109; i++) BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(76 + i * 4), i < fatSectors ? (uint)i : Free);
        output.Write(header);

        var fatBytes = new byte[fatSectors * 512];
        for (int i = 0; i < fatSectors * 128; i++) BinaryPrimitives.WriteUInt32LittleEndian(fatBytes.AsSpan(i * 4), i < fat.Count ? fat[i] : Free);
        output.Write(fatBytes);

        var dir = new byte[dirSectors * 512];
        for (int i = 0; i < dirSectors * 4; i++)
        {
            var e = dir.AsSpan(i * 128, 128);
            BinaryPrimitives.WriteUInt32LittleEndian(e[68..], Free);
            BinaryPrimitives.WriteUInt32LittleEndian(e[72..], Free);
            BinaryPrimitives.WriteUInt32LittleEndian(e[76..], Free);
            if (i >= entries.Count) continue;
            var (name, type, data, parent) = entries[i];
            var n = Encoding.Unicode.GetBytes(name);
            n.CopyTo(e);
            BinaryPrimitives.WriteUInt16LittleEndian(e[64..], (ushort)(n.Length + 2));
            e[66] = (byte)type;
            e[67] = 1;
            int next = entries.FindIndex(i + 1, x => x.Parent == parent && parent >= 0);
            if (parent >= 0 && next > 0) BinaryPrimitives.WriteUInt32LittleEndian(e[72..], (uint)next);
            int child = entries.FindIndex(x => x.Parent == i);
            if (type != 2 && child > 0) BinaryPrimitives.WriteUInt32LittleEndian(e[76..], (uint)child);
            if (i == 0 && rootClsid is { } clsid) clsid.TryWriteBytes(e.Slice(80, 16));
            BinaryPrimitives.WriteUInt32LittleEndian(e[116..], type == 1 ? 0 : start[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(e[120..], (uint)(i == 0 ? mini.Length : data?.Length ?? 0));
        }
        output.Write(dir);
        var mf = new byte[miniFatSectors * 512];
        for (int i = 0; i < miniFatSectors * 128; i++) BinaryPrimitives.WriteUInt32LittleEndian(mf.AsSpan(i * 4), i < miniFat.Count ? miniFat[i] : Free);
        output.Write(mf);
        output.Write(mini.ToArray());
        output.Write(new byte[miniSectors * 512 - mini.Length]);
        foreach (var (_, data) in regular)
        {
            output.Write(data);
            output.Write(new byte[(data.Length + 511) / 512 * 512 - data.Length]);
        }
        return output.ToArray();
    }

    /// <summary>MS-OVBA compression (2.4.1.3): greedy matches within each 4096-byte chunk.</summary>
    public static byte[] Compress(byte[] data)
    {
        var o = new MemoryStream();
        o.WriteByte(1);
        for (int chunkStart = 0; chunkStart < data.Length; chunkStart += 4096)
        {
            int chunkEnd = Math.Min(chunkStart + 4096, data.Length);
            var body = new MemoryStream();
            int pos = chunkStart;
            while (pos < chunkEnd)
            {
                long flagAt = body.Position;
                body.WriteByte(0);
                byte flags = 0;
                for (int bit = 0; bit < 8 && pos < chunkEnd; bit++)
                {
                    int difference = pos - chunkStart;
                    int bitCount = 4;
                    while ((1 << bitCount) < difference) bitCount++;
                    int maxLength = (0xFFFF >> bitCount) + 3;
                    int bestLength = 0, bestOffset = 0;
                    for (int c = pos - 1; c >= chunkStart && pos - c <= (1 << bitCount); c--)
                    {
                        int len = 0;
                        while (len < maxLength && pos + len < chunkEnd && data[c + len] == data[pos + len]) len++;
                        if (len > bestLength) { bestLength = len; bestOffset = pos - c; }
                    }
                    if (bestLength >= 3)
                    {
                        int token = ((bestOffset - 1) << (16 - bitCount)) | (bestLength - 3);
                        body.WriteByte((byte)token);
                        body.WriteByte((byte)(token >> 8));
                        flags |= (byte)(1 << bit);
                        pos += bestLength;
                    }
                    else body.WriteByte(data[pos++]);
                }
                var b = body.GetBuffer();
                b[flagAt] = flags;
            }
            var chunk = body.ToArray();
            if (chunk.Length > 4096) // incompressible: a raw 4096-byte chunk, padded
            {
                var raw = new byte[4096];
                data.AsSpan(chunkStart, chunkEnd - chunkStart).CopyTo(raw);
                o.WriteByte(0xFF); o.WriteByte(0x3F);
                o.Write(raw);
                continue;
            }
            int header = 0xB000 | (chunk.Length + 2 - 3);
            o.WriteByte((byte)header);
            o.WriteByte((byte)(header >> 8));
            o.Write(chunk);
        }
        return o.ToArray();
    }

    /// <summary>The streams of a VBA project under <paramref name="prefix"/> ("" for vbaProject.bin, "Macros/" in Word).</summary>
    public static List<(string, byte[])> VbaStreams(string prefix, params (string Name, string Type, string Source)[] modules)
    {
        var dir = new MemoryStream();
        void Record(int id, byte[] data, int? size = null)
        {
            Span<byte> h = stackalloc byte[6];
            BinaryPrimitives.WriteUInt16LittleEndian(h, (ushort)id);
            BinaryPrimitives.WriteInt32LittleEndian(h[2..], size ?? data.Length);
            dir.Write(h);
            dir.Write(data);
        }
        byte[] U32(uint v) { var b = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, v); return b; }
        byte[] U16(ushort v) { var b = new byte[2]; BinaryPrimitives.WriteUInt16LittleEndian(b, v); return b; }
        var latin = Encoding.Latin1;
        Record(0x0001, U32(1)); Record(0x0002, U32(0x409)); Record(0x0014, U32(0x409)); Record(0x0003, U16(1252));
        Record(0x0004, latin.GetBytes("Project"));
        Record(0x0005, []); Record(0x0040, []); Record(0x0006, []); Record(0x003D, []);
        Record(0x0007, U32(0)); Record(0x0008, U32(0)); Record(0x0009, [1, 0, 0, 0, 0, 0], 4);
        Record(0x000F, U16((ushort)modules.Length)); Record(0x0013, U16(0xFFFF));
        var streams = new List<(string, byte[])>();
        var project = new StringBuilder("ID=\"{00000000-0000-0000-0000-000000000000}\"\r\n");
        foreach (var (name, type, source) in modules)
        {
            Record(0x0019, latin.GetBytes(name)); Record(0x0047, Encoding.Unicode.GetBytes(name));
            Record(0x001A, latin.GetBytes(name)); Record(0x0032, Encoding.Unicode.GetBytes(name));
            Record(0x001C, []); Record(0x0048, []);
            Record(0x0031, U32(0)); Record(0x001E, U32(0)); Record(0x002C, U16(0xFFFF));
            Record(type == "standard" ? 0x0021 : 0x0022, []);
            Record(0x002B, []);
            streams.Add((prefix + "VBA/" + name, Compress(latin.GetBytes($"Attribute VB_Name = \"{name}\"\r\n" + source))));
            project.Append(type switch { "document" => $"Document={name}/&H00000000", "class" => $"Class={name}", _ => $"Module={name}" }).Append("\r\n");
        }
        Record(0x0010, []);
        project.Append("Name=\"Project\"\r\n");
        streams.Add((prefix + "VBA/dir", Compress(dir.ToArray())));
        streams.Add((prefix + "VBA/_VBA_PROJECT", [0xCC, 0x61, 0xFF, 0xFF, 0x00, 0x00, 0x00]));
        streams.Add((prefix + "PROJECT", latin.GetBytes(project.ToString())));
        return streams;
    }

    /// <summary>An OLE Package (\x01Ole10Native) stream carrying a file.</summary>
    public static byte[] Ole10Native(string label, string source, byte[] data)
    {
        var body = new MemoryStream();
        body.Write([2, 0]);
        body.Write(Encoding.Latin1.GetBytes(label + "\0"));
        body.Write(Encoding.Latin1.GetBytes(source + "\0"));
        body.Write([0, 0, 3, 0]);
        var temp = Encoding.Latin1.GetBytes(@"C:\Temp\" + label + "\0");
        body.Write(BitConverter.GetBytes(temp.Length));
        body.Write(temp);
        body.Write(BitConverter.GetBytes(data.Length));
        body.Write(data);
        var b = body.ToArray();
        return [.. BitConverter.GetBytes(b.Length), .. b];
    }

    /// <summary>A BIFF8 Workbook stream: a worksheet and a macro sheet in the given state, Auto_Open naming its A1, and one formula per cell.</summary>
    public static byte[] Biff8Workbook(string macroSheet, byte state, params byte[][] formulas)
    {
        var globals = new MemoryStream();
        void Rec(MemoryStream s, int id, byte[] data)
        {
            s.Write(BitConverter.GetBytes((ushort)id));
            s.Write(BitConverter.GetBytes((ushort)data.Length));
            s.Write(data);
        }
        byte[] Bof(ushort type) => [0x00, 0x06, (byte)type, (byte)(type >> 8), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        byte[] Sheet(uint at, byte hidden, byte kind, string name) => [.. BitConverter.GetBytes(at), hidden, kind, (byte)name.Length, 0, .. Encoding.Latin1.GetBytes(name)];
        // the sheet offsets are fixed up once the globals' size is known
        var sheetsAt = new List<long>();
        Rec(globals, 0x0809, Bof(0x0005));
        sheetsAt.Add(globals.Position + 4);
        Rec(globals, 0x0085, Sheet(0, 0, 0, "Sheet1"));
        sheetsAt.Add(globals.Position + 4);
        Rec(globals, 0x0085, Sheet(0, state, 1, macroSheet));
        // NAME: built-in Auto_Open (0x01) = macroSheet!A1 as ptgRef3d
        byte[] rgce = [0x3A, 0, 0, 0, 0, 0, 0];
        Rec(globals, 0x0018, [0x20, 0x00, 0, 1, (byte)rgce.Length, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, .. rgce]);
        Rec(globals, 0x000A, []);
        var sheet1 = new MemoryStream();
        Rec(sheet1, 0x0809, Bof(0x0010)); Rec(sheet1, 0x000A, []);
        var macro = new MemoryStream();
        Rec(macro, 0x0809, Bof(0x0040));
        for (int r = 0; r < formulas.Length; r++)
            Rec(macro, 0x0006, [.. BitConverter.GetBytes((ushort)r), 0, 0, 0x0F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, .. BitConverter.GetBytes((ushort)formulas[r].Length), .. formulas[r]]);
        Rec(macro, 0x000A, []);
        var all = globals.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(all.AsSpan((int)sheetsAt[0]), (uint)all.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(all.AsSpan((int)sheetsAt[1]), (uint)(all.Length + sheet1.Length));
        return [.. all, .. sheet1.ToArray(), .. macro.ToArray()];
    }

    /// <summary>A formula calling <paramref name="function"/> (Ftab number) with string arguments, as ptgStr + ptgFuncVar.</summary>
    public static byte[] Call(int function, params string[] args)
    {
        var f = new MemoryStream();
        foreach (var a in args) f.Write([0x17, (byte)a.Length, 0, .. Encoding.Latin1.GetBytes(a)]);
        f.Write([0x42, (byte)args.Length, (byte)function, (byte)(function >> 8)]);
        return f.ToArray();
    }

    /// <summary>An OOXML package encrypted with standard encryption (AES-128, SHA-1, MS-OFFCRYPTO 2.3.4.5) under <paramref name="password"/>.</summary>
    public static byte[] StandardEncrypted(byte[] package, string password)
    {
        var salt = Enumerable.Range(1, 16).Select(i => (byte)(i * 7)).ToArray();
        var h = System.Security.Cryptography.SHA1.HashData([.. salt, .. Encoding.Unicode.GetBytes(password)]);
        for (int i = 0; i < 50000; i++) h = System.Security.Cryptography.SHA1.HashData([.. BitConverter.GetBytes(i), .. h]);
        h = System.Security.Cryptography.SHA1.HashData([.. h, 0, 0, 0, 0]);
        var x1 = new byte[64]; var x2 = new byte[64];
        for (int i = 0; i < 64; i++) { x1[i] = (byte)(0x36 ^ (i < 20 ? h[i] : 0)); x2[i] = (byte)(0x5C ^ (i < 20 ? h[i] : 0)); }
        var key = System.Security.Cryptography.SHA1.HashData(x1).Concat(System.Security.Cryptography.SHA1.HashData(x2)).Take(16).ToArray();
        using var aes = System.Security.Cryptography.Aes.Create();
        aes.Key = key;
        var verifier = Enumerable.Range(0, 16).Select(i => (byte)(200 - i)).ToArray();
        var verifierHash = new byte[32];
        System.Security.Cryptography.SHA1.HashData(verifier).CopyTo(verifierHash, 0);
        var csp = Encoding.Unicode.GetBytes("Microsoft Enhanced RSA and AES Cryptographic Provider\0");
        var header = new MemoryStream();
        foreach (var v in new uint[] { 0x24, 0, 0x660E, 0x8004, 128, 0x18, 0, 0 }) header.Write(BitConverter.GetBytes(v));
        header.Write(csp);
        var info = new MemoryStream();
        info.Write(BitConverter.GetBytes((ushort)4)); info.Write(BitConverter.GetBytes((ushort)2)); info.Write(BitConverter.GetBytes(0x24u));
        info.Write(BitConverter.GetBytes((uint)header.Length)); info.Write(header.ToArray());
        info.Write(BitConverter.GetBytes(16u)); info.Write(salt);
        info.Write(aes.EncryptEcb(verifier, System.Security.Cryptography.PaddingMode.None));
        info.Write(BitConverter.GetBytes(20u)); info.Write(aes.EncryptEcb(verifierHash, System.Security.Cryptography.PaddingMode.None));
        var padded = new byte[(package.Length + 15) / 16 * 16];
        package.CopyTo(padded, 0);
        var encrypted = new byte[8 + padded.Length];
        BitConverter.GetBytes((long)package.Length).CopyTo(encrypted, 0);
        aes.EncryptEcb(padded, System.Security.Cryptography.PaddingMode.None).CopyTo(encrypted, 8);
        return Compound([("EncryptionInfo", info.ToArray()), ("EncryptedPackage", encrypted)]);
    }

    /// <summary>An OOXML package of these parts.</summary>
    public static byte[] Ooxml(params (string Name, byte[] Data)[] parts)
    {
        var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, data) in parts.Prepend(("[Content_Types].xml", "<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>"u8.ToArray())))
            {
                using var s = zip.CreateEntry(name).Open();
                s.Write(data);
            }
        }
        return ms.ToArray();
    }
}
