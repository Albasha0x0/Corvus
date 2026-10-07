using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services.Analysis;

/// <summary>One file taken out of a container. <see cref="Origin"/> says where it came from and how it was decoded.</summary>
public sealed record ExtractedItem(string Name, byte[] Bytes, string Origin);

/// <summary>What a container held: its kind, the items (one level deep), and notes on skipped or unusual entries.</summary>
public sealed record ContainerContents(string Kind, List<ExtractedItem> Items, List<string> Notes);

/// <summary>
/// Opens one container level (callers recurse): .NET single-file bundles (PE, ELF or Mach-O apphost; compressed or
/// not), Costura.Fody embedded assemblies, ZIP-based packages (.nupkg, Xamarin / MAUI .apk / .aab, plain .zip) including
/// Xamarin XALZ (LZ4) assemblies and assembly stores, and, for anything else, carving of embedded .NET images and XALZ
/// chunks.
/// Pure byte-level code: nothing is loaded or executed, every length and offset is bounds-checked, and every
/// decompression is bounded by <see cref="AnalysisLimits"/>.
/// </summary>
public static class Containers
{
    /// <summary>SHA-256 of ".net core bundle": marks the bundle header offset slot in an apphost.</summary>
    private static readonly byte[] BundleSignature =
    [
        0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
        0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
    ];

    private static readonly Regex CosturaName = new(@"^costura(?:32|64)?\.(?<name>.+?)(?<compressed>\.compressed)?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>Opens <paramref name="data"/>; Kind "none" (with notes) when it is not a container this knows.</summary>
    public static ContainerContents Open(byte[] data, string name, AnalysisLimits limits, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var kind = Blob.Identify(data);
        if (kind == "zip") return OpenZip(data, name, limits, ct);
        if (kind.StartsWith("xalz", StringComparison.Ordinal))
        {
            var decoded = Blob.TryXalz(data, limits.MaxItemBytes) ?? throw new ToolError($"{name}: corrupt XALZ (LZ4) data.");
            return new ContainerContents("Xamarin XALZ", [new ExtractedItem(Path.GetFileName(name), decoded, "XALZ (LZ4) decompressed")], []);
        }

        var pe = PeImage.TryParse(data);
        if (pe != null && !pe.IsDotNet(data))
        {
            var bundle = OpenBundle(data, limits, ct);
            if (bundle != null) return bundle;
            if (pe.IsNativeAot(data))
                return new ContainerContents("NativeAOT executable", [], ["NativeAOT: the managed code was compiled to native code; there is no IL or metadata to decompile. Analyze it with a native disassembler (IDA / Ghidra)."]);
        }
        if (pe != null && pe.IsDotNet(data))
        {
            var costura = OpenCostura(data, limits, ct);
            if (costura != null) return costura;
            return new ContainerContents("none", [], ["A plain .NET assembly: nothing bundled. Load it and use list_resources / get_resource for data hidden in its resources."]);
        }
        if (pe == null && kind is "elf" or "mach-o") // Linux / macOS apphosts carry bundles the same way
        {
            var bundle = OpenBundle(data, limits, ct);
            if (bundle != null) return bundle;
        }
        return Carve(data, name, pe != null ? "native PE" : kind, limits, ct);
    }

    // ------------------------------------------------------------------ single-file bundles

    private static ContainerContents? OpenBundle(byte[] data, AnalysisLimits limits, CancellationToken ct)
    {
        int sig = data.AsSpan().IndexOf(BundleSignature);
        if (sig < 8) return null;
        long headerOffset = BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(sig - 8));
        if (headerOffset == 0)
            return new ContainerContents(".NET apphost (not bundled)", [],
                ["An apphost launcher without a bundle: the application is the .dll of the same name next to it."]);
        if (headerOffset < 0 || headerOffset >= data.Length) throw new ToolError($"Corrupt single-file bundle: header offset 0x{headerOffset:X} is outside the file.");

        var r = new SpanReader(data, (int)headerOffset);
        uint major = r.UInt32(), minor = r.UInt32();
        int count = r.Int32();
        string bundleId = r.String();
        if (major is 0 or > 64 || count < 0 || count > limits.MaxItems) throw new ToolError($"Corrupt single-file bundle header (version {major}.{minor}, {count} files).");
        if (major >= 2) r.Skip(8 * 4 + 8); // deps.json and runtimeconfig.json locations (they are also manifest entries), flags

        var items = new List<ExtractedItem>();
        var notes = new List<string> { $"Single-file bundle v{major}.{minor}, id {bundleId}, {count} files." };
        long total = 0;
        for (int i = 0; i < count; i++)
        {
            ct.ThrowIfCancellationRequested();
            long offset = r.Int64(), size = r.Int64();
            long compressed = major >= 6 ? r.Int64() : 0;
            byte type = r.Byte();
            string path = r.String();
            long stored = compressed > 0 ? compressed : size;
            if (offset < 0 || size < 0 || stored < 0 || offset > data.Length - stored) // not offset + stored: it can overflow
            {
                notes.Add($"Skipped {path}: its data lies outside the file (corrupt manifest).");
                continue;
            }
            if (size > limits.MaxItemBytes || (total += size) > limits.MaxTotalBytes)
            {
                notes.Add($"Skipped {path}: larger than the extraction limit.");
                continue;
            }
            byte[]? bytes = compressed > 0
                ? Blob.TryDecompress(data.AsSpan((int)offset, (int)compressed), "deflate", limits.MaxItemBytes)
                : data.AsSpan((int)offset, (int)size).ToArray();
            if (bytes == null || bytes.Length != size)
            {
                notes.Add($"Skipped {path}: decompression failed or produced the wrong size.");
                continue;
            }
            items.Add(new ExtractedItem(path, bytes, $"bundle entry ({BundleType(type)}{(compressed > 0 ? ", deflate" : "")})"));
        }
        return new ContainerContents(".NET single-file bundle", items, notes);
    }

    private static string BundleType(byte t) => t switch
    {
        1 => "assembly",
        2 => "native binary",
        3 => "deps.json",
        4 => "runtimeconfig.json",
        5 => "symbols",
        _ => "other",
    };

    // ------------------------------------------------------------------ Costura.Fody

    private static ContainerContents? OpenCostura(byte[] data, AnalysisLimits limits, CancellationToken ct)
    {
        ModuleDefMD module;
        try { module = ModuleDefMD.Load(data); }
        catch (Exception) { return null; } // malformed metadata: not our problem here
        using (module)
        {
            var items = new List<ExtractedItem>();
            var notes = new List<string>();
            List<EmbeddedResource> resources;
            try { resources = module.Resources.OfType<EmbeddedResource>().ToList(); } // rows are read lazily
            catch (Exception) { return null; }
            foreach (var res in resources)
            {
                ct.ThrowIfCancellationRequested();
                var m = CosturaName.Match(res.Name);
                if (!m.Success) continue;
                byte[] raw;
                try { raw = res.CreateReader().ToArray(); }
                catch (Exception) { notes.Add($"Skipped {res.Name}: unreadable resource."); continue; }
                var bytes = m.Groups["compressed"].Success ? Blob.TryDecompress(raw, "deflate", limits.MaxItemBytes) : raw;
                if (bytes == null) { notes.Add($"Skipped {res.Name}: not valid deflate data."); continue; }
                items.Add(new ExtractedItem(m.Groups["name"].Value, bytes, $"Costura resource {res.Name}{(m.Groups["compressed"].Success ? " (deflate)" : "")}"));
            }
            return items.Count == 0 && notes.Count == 0 ? null : new ContainerContents("Costura.Fody (embedded assemblies)", items, notes);
        }
    }

    // ------------------------------------------------------------------ ZIP-based packages

    /// <summary>An APK entry that only a .NET (Xamarin / MAUI) app has: its assemblies, assembly store or Mono runtime.</summary>
    private static bool IsAndroidDotNet(string entry) =>
        entry.StartsWith("assemblies/", StringComparison.Ordinal) || entry.Contains("libmonodroid", StringComparison.Ordinal)
        || entry.Contains("libmonosgen", StringComparison.Ordinal) || entry.Contains("libassemblies.", StringComparison.Ordinal)
        || entry.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || entry.EndsWith(".blob", StringComparison.OrdinalIgnoreCase);

    private static ContainerContents OpenZip(byte[] data, string name, AnalysisLimits limits, CancellationToken ct)
    {
        ZipArchive zip;
        IReadOnlyCollection<ZipArchiveEntry> entries;
        try
        {
            zip = new ZipArchive(new MemoryStream(data, writable: false), ZipArchiveMode.Read);
            entries = zip.Entries; // the central directory is read here, not in the constructor
        }
        catch (InvalidDataException ex)
        {
            // a cut-off download or a carved file has no central directory: read what the local headers still hold
            var recovered = RecoverLocalEntries(data, limits, ct);
            if (recovered.Count == 0) throw new ToolError($"{name}: corrupt zip ({ex.Message}).");
            var contents = ReadZipEntries(recovered.Select(e => (e.Name, (Func<byte[]?>)(() => e.Bytes))).ToList(), limits, ct);
            contents.Notes.Insert(0, $"Damaged zip ({ex.Message}): {recovered.Count} entr(ies) recovered from local headers; entries past the damage are lost.");
            return contents;
        }
        using (zip)
            return ReadZipEntries(entries.Select(e => (e.FullName, (Func<byte[]?>)(() =>
            {
                using var s = e.Open();
                return Blob.ReadBounded(s, limits.MaxItemBytes);
            }))).ToList(), limits, ct);
    }

    private static ContainerContents ReadZipEntries(List<(string FullName, Func<byte[]?> Read)> entries, AnalysisLimits limits, CancellationToken ct)
    {
        string kind = entries.Any(e => e.FullName == "AndroidManifest.xml")
                ? entries.Any(e => IsAndroidDotNet(e.FullName)) ? "Android package (Xamarin / MAUI)" : "Android package (no .NET runtime or assemblies)"
            : entries.Any(e => e.FullName.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase)) ? "NuGet package"
            : "zip archive";
        var items = new List<ExtractedItem>();
        var notes = new List<string>();
        long total = 0;
        foreach (var e in entries)
        {
            ct.ThrowIfCancellationRequested();
            if (!IsInteresting(e.FullName)) continue;
            if (items.Count >= limits.MaxItems) { notes.Add("Stopped: too many entries."); break; }
            byte[]? bytes;
            try { bytes = e.Read(); }
            catch (Exception ex) when (ex is InvalidDataException or IOException or NotSupportedException)
            {
                notes.Add($"Skipped {e.FullName}: {ex.Message}");
                continue;
            }
            if (bytes == null || (total += bytes.Length) > limits.MaxTotalBytes)
            {
                notes.Add($"Skipped {e.FullName}: larger than the extraction limit.");
                continue;
            }
            if (Blob.StartsWith(bytes, "XALZ"u8))
            {
                var decoded = Blob.TryXalz(bytes, limits.MaxItemBytes);
                if (decoded == null) { notes.Add($"Skipped {e.FullName}: corrupt XALZ data."); continue; }
                items.Add(new ExtractedItem(e.FullName, decoded, $"{kind} entry {e.FullName} (XALZ LZ4)"));
            }
            else if (IsAssemblyStore(e.FullName, bytes))
            {
                var store = Carve(bytes, e.FullName, "Xamarin assembly store", limits, ct);
                items.AddRange(store.Items.Select(i => i with { Origin = $"{e.FullName}: {i.Origin}" }));
                notes.AddRange(store.Notes.Select(n => $"{e.FullName}: {n}"));
            }
            else
            {
                items.Add(new ExtractedItem(e.FullName, bytes, $"{kind} entry"));
            }
        }
        if (items.Count == 0) notes.Add("No assemblies or nested packages found in the archive.");
        return new ContainerContents(kind, items, notes);
    }

    /// <summary>
    /// Entries read from the local file headers in order (stored or deflated, sizes in the header), stopping at the
    /// first one that is cut off or unreadable. Used when the central directory is missing.
    /// </summary>
    private static List<(string Name, byte[] Bytes)> RecoverLocalEntries(byte[] data, AnalysisLimits limits, CancellationToken ct)
    {
        var result = new List<(string, byte[])>();
        int at = 0;
        while (at + 30 <= data.Length && result.Count < limits.MaxItems)
        {
            ct.ThrowIfCancellationRequested();
            if (BitConverter.ToUInt32(data, at) != 0x04034B50) break; // "PK\x03\x04"
            ushort flags = BitConverter.ToUInt16(data, at + 6), method = BitConverter.ToUInt16(data, at + 8);
            uint compressed = BitConverter.ToUInt32(data, at + 18);
            int nameLength = BitConverter.ToUInt16(data, at + 26), extraLength = BitConverter.ToUInt16(data, at + 28);
            int body = at + 30 + nameLength + extraLength;
            if ((flags & 0x08) != 0 || (flags & 0x01) != 0) break; // sizes in a trailing descriptor / encrypted: cannot continue
            if (body > data.Length || compressed > data.Length - body) break; // cut off here
            var name = Encoding.UTF8.GetString(data, at + 30, nameLength);
            var raw = data.AsSpan(body, (int)compressed).ToArray();
            byte[]? bytes = method switch
            {
                0 => raw,
                8 => Blob.TryDecompress(raw, "deflate", limits.MaxItemBytes),
                _ => null,
            };
            if (bytes == null) break;
            if (!name.EndsWith('/')) result.Add((name, bytes));
            at = body + (int)compressed;
        }
        return result;
    }

    /// <summary>Archive entries extracted: .dll / .exe / .winmd, assembly stores, nested packages, and .deps.json / .runtimeconfig.json / assemblies.manifest.</summary>
    private static bool IsInteresting(string path)
    {
        var file = Path.GetFileName(path).ToLowerInvariant();
        if (file.StartsWith("libassemblies.", StringComparison.Ordinal) && file.EndsWith(".blob.so", StringComparison.Ordinal)) return true;
        if (file is "assemblies.manifest" || file.EndsWith(".deps.json", StringComparison.Ordinal) || file.EndsWith(".runtimeconfig.json", StringComparison.Ordinal)) return true;
        return Path.GetExtension(file) is ".dll" or ".exe" or ".winmd" or ".blob" or ".nupkg" or ".zip" or ".apk" or ".aab" or ".xap" or ".vsix";
    }

    private static bool IsAssemblyStore(string path, byte[] bytes) =>
        Blob.StartsWith(bytes, "XABA"u8) || path.EndsWith(".blob", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".blob.so", StringComparison.OrdinalIgnoreCase);

    // ------------------------------------------------------------------ carving fallback

    /// <summary>Finds .NET images (validated PE headers) and XALZ chunks anywhere in the data; native images are counted, not extracted.</summary>
    public static ContainerContents Carve(byte[] data, string name, string kind, AnalysisLimits limits, CancellationToken ct)
    {
        var items = new List<ExtractedItem>();
        var notes = new List<string>();
        int native = 0;
        foreach (var c in Blob.CarvePe(data, limits.MaxItems))
        {
            ct.ThrowIfCancellationRequested();
            if (c.Offset == 0 && c.Length == data.Length) continue; // the input itself
            if (!c.IsDotNet) { native++; continue; }
            items.Add(new ExtractedItem($"carved_0x{c.Offset:X}.dll", data.AsSpan(c.Offset, c.Length).ToArray(), $"carved .NET image at 0x{c.Offset:X}"));
        }
        foreach (int at in Blob.FindAll(data, "XALZ"u8, limits.MaxItems))
        {
            ct.ThrowIfCancellationRequested();
            var decoded = Blob.TryXalz(data.AsSpan(at), limits.MaxItemBytes);
            if (decoded != null) items.Add(new ExtractedItem($"xalz_0x{at:X}.dll", decoded, $"XALZ (LZ4) chunk at 0x{at:X}"));
        }
        if (native > 0) notes.Add($"{native} embedded native PE image(s) found (not extracted).");
        if (items.Count == 0)
            notes.Add(kind == "native PE"
                ? "A native executable with no .NET bundle or embedded .NET images (it may be packed, compressed, or not .NET at all)."
                : $"Not a known container ({kind}) and no embedded .NET images were found.");
        return new ContainerContents(items.Count > 0 ? $"{kind} with embedded .NET images" : "none", items, notes);
    }

    /// <summary>Bounds-checked little-endian reader; throws ToolError on truncated data.</summary>
    private ref struct SpanReader(byte[] data, int position)
    {
        private int _pos = position;

        private ReadOnlySpan<byte> Take(int n)
        {
            if (_pos < 0 || n < 0 || _pos > data.Length - n) throw new ToolError("Corrupt single-file bundle: the manifest is truncated.");
            var s = data.AsSpan(_pos, n);
            _pos += n;
            return s;
        }

        public void Skip(int n) => Take(n);
        public byte Byte() => Take(1)[0];
        public int Int32() => BinaryPrimitives.ReadInt32LittleEndian(Take(4));
        public uint UInt32() => BinaryPrimitives.ReadUInt32LittleEndian(Take(4));
        public long Int64() => BinaryPrimitives.ReadInt64LittleEndian(Take(8));

        /// <summary>BinaryWriter string: 7-bit encoded length + UTF-8.</summary>
        public string String()
        {
            int len = 0, shift = 0;
            byte b;
            do
            {
                b = Byte();
                len |= (b & 0x7F) << shift;
                shift += 7;
                if (shift > 28) throw new ToolError("Corrupt single-file bundle: bad string length.");
            } while ((b & 0x80) != 0);
            if (len > 4096) throw new ToolError("Corrupt single-file bundle: path too long.");
            return Encoding.UTF8.GetString(Take(len));
        }
    }
}
