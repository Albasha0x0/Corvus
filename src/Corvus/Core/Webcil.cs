using System.Buffers.Binary;

namespace Corvus.Core;

/// <summary>
/// Webcil: how Blazor WebAssembly (.NET 8+) ships assemblies in its _framework folder. The PE headers are replaced by a
/// small "WbIL" header and section table, and the result is wrapped as a data segment of a WebAssembly module (.wasm).
/// The sections are the original PE sections, so a PE is rebuilt around them for every reader of .NET images.
/// </summary>
public static class Webcil
{
    private const int HeaderSize = 28, SectionSize = 16, FileAlignment = 0x200, SectionAlignment = 0x2000;

    /// <summary>The Webcil payload of a .wasm module or a bare Webcil file, or null.</summary>
    public static ReadOnlyMemory<byte>? Payload(byte[] data)
    {
        if (data.AsSpan().StartsWith("WbIL"u8)) return data;
        if (!data.AsSpan().StartsWith("\0asm"u8) || data.Length < 8 || BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(4)) != 1) return null;
        int at = 8;
        while (at < data.Length)
        {
            byte id = data[at++];
            long size = Uleb(data, ref at);
            if (size < 0 || size > data.Length - at) return null;
            int end = at + (int)size;
            // Data section: a passive segment holding the payload size, then a passive segment holding the payload.
            if (id == 11)
            {
                int p = at;
                if (Uleb(data, ref p) != 2 || p >= end || data[p++] != 1) return null;
                long first = Uleb(data, ref p);
                if (first < 0 || first >= end - p) return null;
                p += (int)first;
                if (data[p++] != 1) return null;
                long length = Uleb(data, ref p);
                if (length < 0 || length > end - p || !data.AsSpan(p).StartsWith("WbIL"u8)) return null;
                return data.AsMemory(p, (int)length);
            }
            at = end;
        }
        return null;
    }

    public static bool IsWebcil(byte[] data) => Payload(data) != null;

    /// <summary>The assembly as a PE image, or null when <paramref name="data"/> is not readable Webcil.</summary>
    public static byte[]? ToPe(byte[] data)
    {
        if (Payload(data) is not { } payload) return null;
        var w = payload.Span;
        if (w.Length < HeaderSize) return null;
        int sections = BinaryPrimitives.ReadUInt16LittleEndian(w[8..]);
        uint cliRva = BinaryPrimitives.ReadUInt32LittleEndian(w[12..]), cliSize = BinaryPrimitives.ReadUInt32LittleEndian(w[16..]);
        if (sections is 0 or > 96 || w.Length < HeaderSize + sections * SectionSize) return null;

        var table = new (uint VirtualSize, uint Va, uint RawSize, uint RawPointer)[sections];
        for (int i = 0; i < sections; i++)
        {
            var s = w[(HeaderSize + i * SectionSize)..];
            table[i] = (BinaryPrimitives.ReadUInt32LittleEndian(s), BinaryPrimitives.ReadUInt32LittleEndian(s[4..]),
                BinaryPrimitives.ReadUInt32LittleEndian(s[8..]), BinaryPrimitives.ReadUInt32LittleEndian(s[12..]));
            if ((long)table[i].RawPointer + table[i].RawSize > w.Length) return null;
        }

        const int peOffset = 0x80, optionalSize = 0xE0;
        int headers = Align(peOffset + 4 + 20 + optionalSize + sections * 40, FileAlignment);
        var rawPointers = new int[sections];
        int fileSize = headers;
        for (int i = 0; i < sections; i++) { rawPointers[i] = fileSize; fileSize += Align((int)table[i].RawSize, FileAlignment); }
        uint imageSize = (uint)Align((int)table.Max(t => t.Va + Math.Max(t.VirtualSize, t.RawSize)), SectionAlignment);

        var pe = new byte[fileSize];
        var o = pe.AsSpan();
        o[0] = (byte)'M'; o[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(o[0x3C..], peOffset);
        "PE\0\0"u8.CopyTo(o[peOffset..]);
        var coff = o[(peOffset + 4)..];
        BinaryPrimitives.WriteUInt16LittleEndian(coff, 0x14C);
        BinaryPrimitives.WriteUInt16LittleEndian(coff[2..], (ushort)sections);
        BinaryPrimitives.WriteUInt16LittleEndian(coff[16..], optionalSize);
        // Executable image, 32-bit, and DLL unless the CLI header names an entry point (a Blazor app is an exe: OutputType Exe on export).
        BinaryPrimitives.WriteUInt16LittleEndian(coff[18..], (ushort)(HasEntryPoint(w, table, cliRva) ? 0x0102 : 0x2102));
        var opt = coff[20..];
        BinaryPrimitives.WriteUInt16LittleEndian(opt, 0x10B);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[28..], 0x10000000); // image base
        BinaryPrimitives.WriteUInt32LittleEndian(opt[32..], SectionAlignment);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[36..], FileAlignment);
        BinaryPrimitives.WriteUInt16LittleEndian(opt[40..], 4); // OS and subsystem version 4.0
        BinaryPrimitives.WriteUInt16LittleEndian(opt[48..], 4);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[56..], imageSize);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[60..], (uint)headers);
        BinaryPrimitives.WriteUInt16LittleEndian(opt[68..], 3); // console subsystem
        BinaryPrimitives.WriteUInt16LittleEndian(opt[70..], 0x8540); // dynamic base, NX, no SEH, terminal server aware
        BinaryPrimitives.WriteUInt32LittleEndian(opt[72..], 0x100000);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[76..], 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[80..], 0x100000);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[84..], 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[92..], 16);
        // Only the CLI header directory: the debug directory's file offsets point into the Webcil payload.
        BinaryPrimitives.WriteUInt32LittleEndian(opt[(96 + 14 * 8)..], cliRva);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[(96 + 14 * 8 + 4)..], cliSize);
        var headersAt = o[(peOffset + 4 + 20 + optionalSize)..];
        for (int i = 0; i < sections; i++)
        {
            var h = headersAt[(i * 40)..];
            System.Text.Encoding.ASCII.GetBytes(i == 0 ? ".text" : $".sect{i}").CopyTo(h);
            BinaryPrimitives.WriteUInt32LittleEndian(h[8..], table[i].VirtualSize);
            BinaryPrimitives.WriteUInt32LittleEndian(h[12..], table[i].Va);
            BinaryPrimitives.WriteUInt32LittleEndian(h[16..], (uint)Align((int)table[i].RawSize, FileAlignment));
            BinaryPrimitives.WriteUInt32LittleEndian(h[20..], (uint)rawPointers[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(h[36..], i == 0 ? 0x60000020u : 0x40000040u);
            w.Slice((int)table[i].RawPointer, (int)table[i].RawSize).CopyTo(o[rawPointers[i]..]);
        }
        return pe;
    }

    /// <summary>
    /// The module the Blazor SDK wraps every Webcil payload in, up to its data section: it imports the loader's memory and
    /// exports webcilVersion, webcilSize, getWebcilSize and getWebcilPayload, which copy the two data segments out.
    /// </summary>
    private static ReadOnlySpan<byte> WasmPrefix =>
    [
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x02, 0x60, 0x01, 0x7f, 0x00, 0x60, 0x02, 0x7f, 0x7f, 0x00,
        0x02, 0x12, 0x01, 0x06, 0x77, 0x65, 0x62, 0x63, 0x69, 0x6c, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x01,
        0x03, 0x03, 0x02, 0x00, 0x01, 0x06, 0x0b, 0x02, 0x7f, 0x00, 0x41, 0x00, 0x0b, 0x7f, 0x00, 0x41, 0x00, 0x0b, 0x07, 0x41,
        0x04, 0x0d, 0x77, 0x65, 0x62, 0x63, 0x69, 0x6c, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x03, 0x00, 0x0a, 0x77, 0x65,
        0x62, 0x63, 0x69, 0x6c, 0x53, 0x69, 0x7a, 0x65, 0x03, 0x01, 0x0d, 0x67, 0x65, 0x74, 0x57, 0x65, 0x62, 0x63, 0x69, 0x6c,
        0x53, 0x69, 0x7a, 0x65, 0x00, 0x00, 0x10, 0x67, 0x65, 0x74, 0x57, 0x65, 0x62, 0x63, 0x69, 0x6c, 0x50, 0x61, 0x79, 0x6c,
        0x6f, 0x61, 0x64, 0x00, 0x01, 0x0c, 0x01, 0x02, 0x0a, 0x1b, 0x02, 0x0c, 0x00, 0x20, 0x00, 0x41, 0x00, 0x41, 0x04, 0xfc,
        0x08, 0x00, 0x00, 0x0b, 0x0c, 0x00, 0x20, 0x00, 0x41, 0x00, 0x20, 0x01, 0xfc, 0x08, 0x01, 0x00, 0x0b,
    ];

    /// <summary>A PE image as Blazor ships it: a Webcil payload (header, section table, the PE's sections) in a .wasm module.</summary>
    public static byte[] FromPe(byte[] pe)
    {
        using var reader = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(pe, writable: false));
        var headers = reader.PEHeaders;
        if (headers.CorHeader == null || headers.PEHeader is not { } optional)
            throw new ToolError(ErrorCode.Unsupported, "Only a .NET assembly can be written as Webcil.");
        var sections = headers.SectionHeaders;
        int tableEnd = HeaderSize + sections.Length * SectionSize;
        var payload = new byte[tableEnd + sections.Sum(s => s.SizeOfRawData)];
        var w = payload.AsSpan();
        "WbIL"u8.CopyTo(w); // version 0.0
        BinaryPrimitives.WriteUInt16LittleEndian(w[8..], (ushort)sections.Length);
        BinaryPrimitives.WriteInt32LittleEndian(w[12..], optional.CorHeaderTableDirectory.RelativeVirtualAddress);
        BinaryPrimitives.WriteInt32LittleEndian(w[16..], optional.CorHeaderTableDirectory.Size);
        BinaryPrimitives.WriteInt32LittleEndian(w[20..], optional.DebugTableDirectory.RelativeVirtualAddress);
        BinaryPrimitives.WriteInt32LittleEndian(w[24..], optional.DebugTableDirectory.Size);
        int raw = tableEnd;
        for (int i = 0; i < sections.Length; i++)
        {
            var s = sections[i];
            var h = w[(HeaderSize + i * SectionSize)..];
            BinaryPrimitives.WriteInt32LittleEndian(h, s.VirtualSize);
            BinaryPrimitives.WriteInt32LittleEndian(h[4..], s.VirtualAddress);
            BinaryPrimitives.WriteInt32LittleEndian(h[8..], s.SizeOfRawData);
            BinaryPrimitives.WriteInt32LittleEndian(h[12..], raw);
            pe.AsSpan(s.PointerToRawData, Math.Min(s.SizeOfRawData, pe.Length - s.PointerToRawData)).CopyTo(w[raw..]);
            raw += s.SizeOfRawData;
        }

        // Data section: two passive segments, the payload size and the payload, padded so the payload starts 4-byte aligned;
        // the padding depends on the length of the section size's encoding, which depends on the padding.
        var size = Leb(payload.Length);
        for (int sectionLeb = 1; ; sectionLeb++)
        {
            int padding = (4 - (WasmPrefix.Length + 1 + sectionLeb + 3 + 4 + 1 + size.Length) % 4) % 4;
            var segments = new List<byte> { 2, 1, (byte)(4 + padding) };
            segments.AddRange(BitConverter.GetBytes(payload.Length));
            segments.AddRange(new byte[padding]);
            segments.Add(1);
            segments.AddRange(size);
            var sectionSize = Leb(segments.Count + payload.Length);
            if (sectionSize.Length != sectionLeb) continue;
            var wasm = new List<byte>(WasmPrefix.Length + 1 + sectionLeb + segments.Count + payload.Length);
            wasm.AddRange(WasmPrefix);
            wasm.Add(11);
            wasm.AddRange(sectionSize);
            wasm.AddRange(segments);
            wasm.AddRange(payload);
            return [.. wasm];
        }
    }
    private static byte[] Leb(int value)
    {
        var bytes = new List<byte>();
        do
        {
            byte b = (byte)(value & 0x7F);
            value >>= 7;
            bytes.Add(value != 0 ? (byte)(b | 0x80) : b);
        } while (value != 0);
        return [.. bytes];
    }

    /// <summary>The CLI header at <paramref name="cliRva"/> has a managed entry point (a MethodDef token).</summary>
    private static bool HasEntryPoint(ReadOnlySpan<byte> w, (uint VirtualSize, uint Va, uint RawSize, uint RawPointer)[] table, uint cliRva)
    {
        foreach (var s in table)
            if (cliRva >= s.Va && cliRva - s.Va + 24 <= s.RawSize)
            {
                uint token = BinaryPrimitives.ReadUInt32LittleEndian(w[(int)(s.RawPointer + (cliRva - s.Va) + 20)..]);
                return token >> 24 == 0x06 && (token & 0xFFFFFF) != 0;
            }
        return false;
    }

    /// <summary>The error for a Webcil file given to load_assembly: it is read only as a container for now.</summary>
    public static void ThrowIfWebcil(string file)
    {
        Span<byte> magic = stackalloc byte[4];
        try
        {
            using (var stream = File.OpenRead(file))
                if (stream.ReadAtLeast(magic, 4, throwOnEndOfStream: false) < 4 || !(magic.SequenceEqual("\0asm"u8) || magic.SequenceEqual("WbIL"u8))) return;
            if (!IsWebcil(File.ReadAllBytes(file))) return;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return; }
        throw new ToolError(ErrorCode.Unsupported,
            $"{file} is a Webcil assembly (Blazor WebAssembly wraps each .NET assembly in a .wasm module); load_assembly does not read Webcil directly yet (planned).",
            $"unpack_container path=\"{Path.GetDirectoryName(Path.GetFullPath(file))}\" converts the folder's Webcil assemblies to PEs that load (path=\"{file}\" only this one); summarize_file and list_assemblies with path read it as it is");
    }

    /// <summary>
    /// The note a folder load adds when the folder (or its _framework subfolder) holds Webcil assemblies, which are not
    /// loaded directly.
    /// </summary>
    public static string? FolderHint(string folder)
    {
        var found = FolderFiles(folder);
        if (found.Count == 0) return null;
        var where = Path.GetDirectoryName(found[0])!;
        return $"{found.Count} .NET assemblies here are Webcil (Blazor WebAssembly: each wrapped in a .wasm module, e.g. {Path.GetFileName(found[0])}), " +
               $"which load_assembly does not read directly yet (planned). unpack_container path=\"{where}\" converts them all to PEs that load " +
               $"and resolve each other; summarize_file and list_assemblies with path read them as they are. Folder: {where}";
    }

    /// <summary>The Webcil .wasm files of a folder, else of its _framework or wwwroot/_framework subfolder (the first that has any).</summary>
    public static List<string> FolderFiles(string folder)
    {
        folder = Path.GetFullPath(folder);
        foreach (var dir in new[] { folder, Path.Combine(folder, "_framework"), Path.Combine(folder, "wwwroot", "_framework") })
        {
            if (!Directory.Exists(dir)) continue;
            var found = new List<string>();
            foreach (var file in Directory.EnumerateFiles(dir, "*.wasm").Order(StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    if (new FileInfo(file).Length <= 64L << 20 && IsWebcil(File.ReadAllBytes(file))) found.Add(file);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
            if (found.Count > 0) return found;
        }
        return [];
    }

    /// <summary>
    /// The .wasm file names and "sha256-..." integrity values the boot manifests of a _framework folder list: blazor.boot.json
    /// (.NET 8, 9), dotnet.boot.js or the config embedded in dotnet.js (.NET 10). Null when the folder has none.
    /// </summary>
    public static HashSet<string>? BootManifestEntries(string folder)
    {
        HashSet<string>? entries = null;
        IEnumerable<string> candidates;
        try { candidates = Directory.EnumerateFiles(folder, "blazor.boot.json").Concat(Directory.EnumerateFiles(folder, "dotnet*.js")).ToList(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
        foreach (var file in candidates)
        {
            string text;
            try
            {
                if (new FileInfo(file).Length > 16L << 20) continue;
                text = File.ReadAllText(file);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
            if (file.EndsWith(".js", StringComparison.OrdinalIgnoreCase))
            {
                // The JSON sits between these markers; otherwise the file is not a boot config (dotnet.native.js, ...).
                int start = text.IndexOf("/*json-start*/", StringComparison.Ordinal), end = text.IndexOf("/*json-end*/", StringComparison.Ordinal);
                if (start < 0 || end < start) continue;
                text = text[(start + "/*json-start*/".Length)..end];
            }
            try
            {
                using var json = System.Text.Json.JsonDocument.Parse(text, new System.Text.Json.JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = System.Text.Json.JsonCommentHandling.Skip });
                if (json.RootElement.ValueKind != System.Text.Json.JsonValueKind.Object || !json.RootElement.TryGetProperty("resources", out var resources)) continue;
                Collect(resources, entries ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            }
            catch (System.Text.Json.JsonException) { }
        }
        return entries;

        // Names are keys (assembly, fingerprinting) or "name" values; integrity values are values ("sha256-...").
        static void Collect(System.Text.Json.JsonElement e, HashSet<string> into)
        {
            switch (e.ValueKind)
            {
                case System.Text.Json.JsonValueKind.Object:
                    foreach (var p in e.EnumerateObject())
                    {
                        if (p.Name.EndsWith(".wasm", StringComparison.OrdinalIgnoreCase)) into.Add(p.Name);
                        Collect(p.Value, into);
                    }
                    break;
                case System.Text.Json.JsonValueKind.Array:
                    foreach (var item in e.EnumerateArray()) Collect(item, into);
                    break;
                case System.Text.Json.JsonValueKind.String when e.GetString() is { } s && (s.EndsWith(".wasm", StringComparison.OrdinalIgnoreCase) || s.StartsWith("sha256-", StringComparison.Ordinal)):
                    into.Add(s);
                    break;
            }
        }
    }

    /// <summary>A file's integrity value as boot manifests write it.</summary>
    public static string Integrity(byte[] file) => "sha256-" + Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(file));

    /// <summary>An unsigned LEB128 value, or -1 when it runs past the data or past 32 bits.</summary>
    private static long Uleb(byte[] data, ref int at)
    {
        long value = 0;
        for (int shift = 0; shift < 35 && at < data.Length; shift += 7)
        {
            byte b = data[at++];
            value |= (long)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return value;
        }
        return -1;
    }

    private static int Align(int value, int alignment) => (value + alignment - 1) & ~(alignment - 1);
}
