using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using dnlib.DotNet;

namespace Corvus.Core;

/// <summary>A file extracted from a container; Origin describes its location and decoding.</summary>
public sealed record ExtractedItem(string Name, byte[] Bytes, string Origin);

/// <summary>An entry of an archive container (ASAR, UnityWebData, HAR, flows), listed without extracting it.</summary>
public sealed record ContainerEntry(string Path, long Size, string? Detail = null);

/// <summary>Container kind, its items (one level deep), and notes on skipped or unusual entries.</summary>
public sealed record ContainerContents(string Kind, List<ExtractedItem> Items, List<string> Notes)
{
    /// <summary>Every entry of an archive container; null for the others, whose items are what they hold.</summary>
    public List<ContainerEntry>? Entries { get; init; }
}

/// <summary>
/// Opens one container level (callers recurse): .NET single-file bundles, Costura.Fody resources, ZIP-based packages
/// (.nupkg, .apk / .aab, .zip) with XALZ / XAZS assemblies and .NET for Android assembly stores, otherwise carves embedded .NET images.
/// All offsets are bounds-checked and decompression is bounded by <see cref="AnalysisLimits"/>.
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

    /// <summary>The simple name of the assembly in a PE image, or null.</summary>
    private static string? AssemblyNameOf(byte[] pe)
    {
        try
        {
            using var reader = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(pe, writable: false));
            var md = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(reader);
            var name = md.IsAssembly ? md.GetString(md.GetAssemblyDefinition().Name) : null;
            return string.IsNullOrWhiteSpace(name) || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ? null : name;
        }
        catch (Exception ex) when (ex is BadImageFormatException or InvalidOperationException) { return null; }
    }

    /// <summary>
    /// Returns Kind "none" with notes when the data is not a known container. <paramref name="location"/> is the file on disk
    /// (for data kept beside it, like an ASAR's .unpacked folder); <paramref name="allFiles"/> extracts every file of an
    /// archive container rather than only assemblies and nested packages.
    /// </summary>
    public static ContainerContents Open(byte[] data, string name, AnalysisLimits limits, CancellationToken ct, string? location = null, bool allFiles = false)
    {
        ct.ThrowIfCancellationRequested();
        var kind = Blob.Identify(data);
        if (kind == "asar") return AsarContainer.Open(data, location, allFiles, limits, ct);
        if (kind == "zip") return OpenZip(data, name, limits, ct);
        if (kind is "wasm" or "webcil")
        {
            // Named by the assembly, not the fingerprinted file (App.3tcu7b1rf6.wasm), so references to it resolve in the output folder.
            if (Webcil.ToPe(data) is { } pe32)
                return new ContainerContents("Webcil", [new ExtractedItem((AssemblyNameOf(pe32) ?? Path.GetFileNameWithoutExtension(name)) + ".dll", pe32,
                    "Webcil (Blazor WebAssembly) converted to PE")], []);
            return new ContainerContents("none", [], [kind == "wasm" ? "A WebAssembly module without a .NET assembly (Webcil) in it." : "Unreadable Webcil data."]);
        }
        if (kind.StartsWith("xalz", StringComparison.Ordinal))
        {
            var decoded = Blob.TryXalz(data, limits.MaxItemBytes) ?? throw new ToolError(ErrorCode.MalformedInput, $"{name}: corrupt XALZ (LZ4) data.");
            return new ContainerContents("Xamarin XALZ", [new ExtractedItem(Path.GetFileName(name), decoded, "XALZ (LZ4) decompressed")], []);
        }
        if (kind.StartsWith("xazs", StringComparison.Ordinal))
        {
            var decoded = Blob.TryXazs(data, limits.MaxItemBytes) ?? throw new ToolError(ErrorCode.MalformedInput, $"{name}: corrupt XAZS (Zstandard) data.");
            return new ContainerContents(".NET for Android XAZS", [new ExtractedItem(Path.GetFileName(name), decoded, "XAZS (Zstandard) decompressed")], []);
        }

        var pe = PeImage.TryParse(data);
        if (pe != null && !pe.IsDotNet(data))
        {
            var bundle = OpenBundle(data, limits, ct);
            if (bundle != null) return bundle;
            if (pe.IsNativeAot(data))
                return new ContainerContents("NativeAOT executable", [], [NativeAotNote(() => Native.NativeAot.NativeAotImage.Open(Native.Pe.PeFile.FromBytes(data))?.Describe())]);
        }
        if (pe != null && pe.IsDotNet(data))
        {
            var costura = OpenCostura(data, limits, ct);
            if (costura != null) return costura;
            return new ContainerContents("none", [], ["A plain .NET assembly: nothing bundled. Load it and use list_resources / get_resource for data hidden in its resources."]);
        }
        if (pe == null && kind is "elf" or "mach-o") // Linux / macOS apphosts use the same bundle layout
        {
            var bundle = OpenBundle(data, limits, ct);
            if (bundle != null) return bundle;
            if (NativeAotImageOf(data) is { } aot) return new ContainerContents("NativeAOT executable", [], [NativeAotNote(aot.Describe)]);
        }
        return Carve(data, name, pe != null ? "native PE" : kind, limits, ct);
    }

    /// <summary>The NativeAOT view of an ELF or Mach-O image that carries NativeAOT markers, or null.</summary>
    private static Native.NativeAot.NativeAotImage? NativeAotImageOf(byte[] data)
    {
        try
        {
            var image = Native.NativeImageLoader.FromBytes(data);
            return Native.NativeAot.NativeAotLocator.HasMarkers(image) ? Native.NativeAot.NativeAotImage.Open(image) : null;
        }
        catch (ToolError) { return null; }
    }

    private static string NativeAotNote(Func<string?> describe)
    {
        string? found = null;
        try { found = describe(); }
        catch (ToolError) { } // an unreadable header only loses the version detail
        return $"NativeAOT{(found != null ? $" ({found})" : "")}: the managed code was compiled to native code, so there is no IL to decompile. " +
               "load_assembly opens it as a native image whose method, MethodTable and string names, recovered from its own metadata, apply " +
               "automatically (list_functions, disassemble, decompile_native); get_nativeaot_info lists the recovered types, methods and strings.";
    }

    private static ContainerContents? OpenBundle(byte[] data, AnalysisLimits limits, CancellationToken ct)
    {
        int sig = data.AsSpan().IndexOf(BundleSignature);
        if (sig < 8) return null;
        long headerOffset = BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(sig - 8));
        if (headerOffset == 0)
            return new ContainerContents(".NET apphost (not bundled)", [],
                ["An apphost launcher without a bundle: the application is the .dll of the same name next to it."]);
        if (headerOffset < 0 || headerOffset >= data.Length) throw new ToolError(ErrorCode.MalformedInput, $"Corrupt single-file bundle: header offset 0x{headerOffset:X} is outside the file.");

        var r = new SpanReader(data, (int)headerOffset);
        uint major = r.UInt32(), minor = r.UInt32();
        int count = r.Int32();
        string bundleId = r.String();
        if (major is 0 or > 64 || count < 0 || count > limits.MaxItems) throw new ToolError(ErrorCode.MalformedInput, $"Corrupt single-file bundle header (version {major}.{minor}, {count} files).");
        if (major >= 2) r.Skip(8 * 4 + 8); // deps.json / runtimeconfig.json locations and flags

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
            if (offset < 0 || size < 0 || stored < 0 || offset > data.Length - stored) // avoids overflow of offset + stored
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

    private static ContainerContents? OpenCostura(byte[] data, AnalysisLimits limits, CancellationToken ct)
    {
        ModuleDefMD module;
        try { module = ModuleDefMD.Load(data); }
        catch (Exception) { return null; }
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

    /// <summary>An APK entry specific to .NET (Xamarin / MAUI) apps: assemblies, assembly store or Mono runtime.</summary>
    private static bool IsAndroidDotNet(string entry) =>
        entry.StartsWith("assemblies/", StringComparison.Ordinal) || entry.Contains("libmonodroid", StringComparison.Ordinal)
        || entry.Contains("libmonosgen", StringComparison.Ordinal) || entry.Contains("libassemblies.", StringComparison.Ordinal)
        || entry.EndsWith("libassembly-store.so", StringComparison.Ordinal)
        || entry.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || entry.EndsWith(".blob", StringComparison.OrdinalIgnoreCase);

    private static ContainerContents OpenZip(byte[] data, string name, AnalysisLimits limits, CancellationToken ct)
    {
        ZipArchive zip;
        IReadOnlyCollection<ZipArchiveEntry> entries;
        try
        {
            zip = new ZipArchive(new MemoryStream(data, writable: false), ZipArchiveMode.Read);
            entries = zip.Entries; // central directory is read here, not in the constructor
        }
        catch (InvalidDataException ex)
        {
            // Truncated or carved zips lack a central directory; recover from local headers.
            var (recovered, skipped, complete) = RecoverLocalEntries(data, limits, ct);
            if (recovered.Count == 0) throw new ToolError(ErrorCode.MalformedInput, $"{name}: corrupt zip ({ex.Message}).");
            var contents = ReadZipEntries(recovered.Select(e => (e.Name, (Func<byte[]?>)(() => e.Bytes))).ToList(), limits, ct);
            contents.Notes.Insert(0, $"Damaged zip ({ex.Message}): {recovered.Count} entr(ies) recovered from local headers"
                                     + (complete ? "." : "; the entries past the damage are lost."));
            contents.Notes.InsertRange(1, skipped);
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
        string? android = entries.Any(e => e.FullName == "AndroidManifest.xml") ? "Android package"
            : entries.Any(e => e.FullName is "BundleConfig.pb" or "base/manifest/AndroidManifest.xml") ? "Android App Bundle"
            : null;
        // Unity Mono ships its Managed folder as plain .dll entries, which would otherwise read as Xamarin / MAUI.
        string kind = android != null
                ? entries.Any(e => e.FullName.Contains("assets/bin/Data/Managed/", StringComparison.Ordinal)) ? android + " (Unity Mono)"
                : entries.Any(e => IsAndroidDotNet(e.FullName)) ? android + " (Xamarin / MAUI)"
                : android + " (no .NET runtime or assemblies)"
            : entries.Any(e => e.FullName.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase)) ? "NuGet package"
            : "zip archive";
        var items = new List<ExtractedItem>();
        var notes = new List<string>();
        var stores = new List<(string Path, byte[] Bytes)>();
        Dictionary<(uint, int), string>? v1Names = null;
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
            if (Blob.TryDecompressAssembly(bytes, limits.MaxItemBytes) is (var decoded, { } compression))
            {
                var label = compression == "lz4" ? "XALZ LZ4" : "XAZS Zstandard";
                if (decoded == null) { notes.Add($"Skipped {e.FullName}: corrupt {label} data."); continue; }
                items.Add(new ExtractedItem(e.FullName, decoded, $"{kind} entry {e.FullName} ({label})"));
            }
            else if (IsAssemblyStore(e.FullName, bytes)) stores.Add((e.FullName, bytes));
            else
            {
                if (Path.GetFileName(e.FullName) == "assemblies.manifest") v1Names = Mobile.AssemblyStore.ReadV1Manifest(Encoding.UTF8.GetString(bytes));
                items.Add(new ExtractedItem(e.FullName, bytes, $"{kind} entry"));
            }
        }
        foreach (var (path, bytes) in stores) // after the loop: assemblies.manifest may come after the stores
        {
            ct.ThrowIfCancellationRequested();
            var store = Mobile.AssemblyStore.TryRead(bytes, path, limits, v1Names);
            notes.AddRange((store?.Issues ?? []).Select(i => $"{path}: {i.Message}."));
            if (store is { Entries.Count: > 0 })
            {
                foreach (var a in store.Entries)
                {
                    var at = a.Abi == null ? $"assemblies/{a.Name}" : $"assemblies/{a.Abi}/{a.Name}";
                    var origin = $"{path}: assembly store v{store.Version} ({store.Location}) entry {a.Index}" +
                                 (a.Compression == "none" ? "" : a.Compression == "lz4" ? " (XALZ LZ4)" : " (XAZS Zstandard)") + (a.Ignored ? ", marked ignored" : "");
                    items.Add(new ExtractedItem(at, a.Image, origin));
                    if (a.Debug != null) items.Add(new ExtractedItem(Path.ChangeExtension(at, ".pdb"), a.Debug, origin + " debug data"));
                    if (a.Config != null) items.Add(new ExtractedItem(at + ".config", a.Config, origin + " config data"));
                }
                continue;
            }
            var carved = Carve(bytes, path, "Xamarin assembly store", limits, ct);
            notes.Add($"{path}: not a readable assembly store; .NET images carved from its bytes (names lost).");
            items.AddRange(carved.Items.Select(i => i with { Origin = $"{path}: {i.Origin}" }));
            notes.AddRange(carved.Notes.Select(n => $"{path}: {n}"));
        }
        if (items.Count == 0) notes.Add("No assemblies or nested packages found in the archive.");
        return new ContainerContents(kind, items, notes);
    }

    /// <summary>
    /// Walks local file headers when the central directory is missing. Sizes come from the header, its zip64 extra
    /// field, or the trailing data descriptor; data is CRC-checked. Complete is true when the walk reached the central
    /// directory or end of file.
    /// </summary>
    private static (List<(string Name, byte[] Bytes)> Entries, List<string> Skipped, bool Complete) RecoverLocalEntries(byte[] data, AnalysisLimits limits, CancellationToken ct)
    {
        var result = new List<(string, byte[])>();
        var skipped = new List<string>();
        int at = 0;
        while (at + 30 <= data.Length && result.Count < limits.MaxItems)
        {
            ct.ThrowIfCancellationRequested();
            uint signature = BitConverter.ToUInt32(data, at);
            if (signature is 0x02014B50 or 0x06054B50 or 0x06064B50) return (result, skipped, true); // central directory / end record
            if (signature != 0x04034B50) break;
            ushort flags = BitConverter.ToUInt16(data, at + 6), method = BitConverter.ToUInt16(data, at + 8);
            uint crc = BitConverter.ToUInt32(data, at + 14);
            long compressed = BitConverter.ToUInt32(data, at + 18);
            int nameLength = BitConverter.ToUInt16(data, at + 26), extraLength = BitConverter.ToUInt16(data, at + 28);
            int body = at + 30 + nameLength + extraLength;
            if (body > data.Length) break;
            var name = Encoding.UTF8.GetString(data, at + 30, nameLength);
            if (compressed == uint.MaxValue && Zip64CompressedSize(data, at + 30 + nameLength, extraLength) is { } large) compressed = large;

            int next;
            if ((flags & 0x08) != 0)
            {
                // Sizes and CRC follow the data in a data descriptor.
                if (FindDescriptor(data, body, out compressed, out crc, out next) == false) break;
            }
            else
            {
                if (compressed > data.Length - body) break;
                next = body + (int)compressed;
            }

            if ((flags & 0x01) != 0)
                skipped.Add($"Skipped {name}: encrypted.");
            else if (!name.EndsWith('/'))
            {
                var raw = data.AsSpan(body, (int)compressed);
                byte[]? bytes = method switch
                {
                    0 => raw.ToArray(),
                    8 => Blob.TryDecompress(raw, "deflate", limits.MaxItemBytes),
                    _ => null,
                };
                if (bytes == null) skipped.Add($"Skipped {name}: {(method is 0 or 8 ? "unreadable data" : $"compression method {method} not supported")}.");
                else if (Crc32(bytes) != crc) skipped.Add($"Skipped {name}: damaged data (CRC mismatch).");
                else result.Add((name, bytes));
            }
            at = next;
        }
        return (result, skipped, at >= data.Length);
    }

    /// <summary>
    /// Finds the first data descriptor (optional PK\x07\x08 signature, 32- or 64-bit sizes) whose compressed size equals
    /// its distance from the data start.
    /// </summary>
    private static bool FindDescriptor(byte[] data, int body, out long compressed, out uint crc, out int next)
    {
        for (int p = body; p + 12 <= data.Length; p++)
        {
            // Signed: PK 07 08, crc, compressed, uncompressed (sizes 4 or 8 bytes).
            if (data[p] == 0x50 && data[p + 1] == 0x4B && data[p + 2] == 0x07 && data[p + 3] == 0x08 && p + 16 <= data.Length)
            {
                if (BitConverter.ToUInt32(data, p + 8) == p - body) { crc = BitConverter.ToUInt32(data, p + 4); compressed = p - body; next = p + 16; return true; }
                if (p + 24 <= data.Length && BitConverter.ToInt64(data, p + 8) == p - body) { crc = BitConverter.ToUInt32(data, p + 4); compressed = p - body; next = p + 24; return true; }
            }
            // Unsigned: crc, compressed, uncompressed, immediately before the next header.
            if (p + 16 <= data.Length && data[p + 12] == 0x50 && data[p + 13] == 0x4B && BitConverter.ToUInt32(data, p + 4) == p - body)
            {
                crc = BitConverter.ToUInt32(data, p); compressed = p - body; next = p + 12; return true;
            }
        }
        compressed = 0; crc = 0; next = data.Length;
        return false;
    }

    /// <summary>Compressed size from a zip64 extra field (id 1: uncompressed, then compressed size).</summary>
    private static long? Zip64CompressedSize(byte[] data, int extra, int length)
    {
        for (int p = extra; p + 4 <= extra + length && p + 4 <= data.Length;)
        {
            ushort id = BitConverter.ToUInt16(data, p), size = BitConverter.ToUInt16(data, p + 2);
            if (id == 1 && size >= 16 && p + 20 <= data.Length) return BitConverter.ToInt64(data, p + 12);
            p += 4 + size;
        }
        return null;
    }

    private static readonly uint[] CrcTable = Enumerable.Range(0, 256).Select(n =>
    {
        uint c = (uint)n;
        for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
        return c;
    }).ToArray();

    private static uint Crc32(byte[] bytes)
    {
        uint c = 0xFFFFFFFF;
        foreach (var b in bytes) c = CrcTable[(c ^ b) & 0xFF] ^ (c >> 8);
        return c ^ 0xFFFFFFFF;
    }

    /// <summary>Entries worth extracting: assemblies, assembly stores, nested packages and .NET manifests.</summary>
    internal static bool IsInteresting(string path)
    {
        var file = Path.GetFileName(path).ToLowerInvariant();
        if (file.StartsWith("libassemblies.", StringComparison.Ordinal) && file.EndsWith(".blob.so", StringComparison.Ordinal) || file == "libassembly-store.so") return true;
        if (file is "assemblies.manifest" || file.EndsWith(".deps.json", StringComparison.Ordinal) || file.EndsWith(".runtimeconfig.json", StringComparison.Ordinal)) return true;
        return Path.GetExtension(file) is ".dll" or ".exe" or ".winmd" or ".blob" or ".nupkg" or ".zip" or ".apk" or ".aab" or ".xap" or ".vsix";
    }

    private static bool IsAssemblyStore(string path, byte[] bytes) =>
        Blob.StartsWith(bytes, "XABA"u8) || path.EndsWith(".blob", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".blob.so", StringComparison.OrdinalIgnoreCase)
        || path.EndsWith("libassembly-store.so", StringComparison.Ordinal);

    /// <summary>Carves .NET images and XALZ chunks from arbitrary data; native images are counted, not extracted.</summary>
    public static ContainerContents Carve(byte[] data, string name, string kind, AnalysisLimits limits, CancellationToken ct)
    {
        var items = new List<ExtractedItem>();
        var notes = new List<string>();
        int native = 0;
        foreach (var c in Blob.CarvePe(data, limits.MaxItems))
        {
            ct.ThrowIfCancellationRequested();
            if (c.Offset == 0 && c.Length == data.Length) continue;
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
                ? "A native executable with no .NET bundle or embedded .NET images (it may be wrapped, compressed, or not .NET at all)."
                : $"Not a known container ({kind}) and no embedded .NET images were found.");
        return new ContainerContents(items.Count > 0 ? $"{kind} with embedded .NET images" : "none", items, notes);
    }

    /// <summary>Bounds-checked little-endian reader; throws ToolError on truncated data.</summary>
    private ref struct SpanReader(byte[] data, int position)
    {
        private int _pos = position;

        private ReadOnlySpan<byte> Take(int n)
        {
            if (_pos < 0 || n < 0 || _pos > data.Length - n) throw new ToolError(ErrorCode.MalformedInput, "Corrupt single-file bundle: the manifest is truncated.");
            var s = data.AsSpan(_pos, n);
            _pos += n;
            return s;
        }

        public void Skip(int n) => Take(n);
        public byte Byte() => Take(1)[0];
        public int Int32() => BinaryPrimitives.ReadInt32LittleEndian(Take(4));
        public uint UInt32() => BinaryPrimitives.ReadUInt32LittleEndian(Take(4));
        public long Int64() => BinaryPrimitives.ReadInt64LittleEndian(Take(8));

        /// <summary>BinaryWriter string: 7-bit encoded length, then UTF-8.</summary>
        public string String()
        {
            int len = 0, shift = 0;
            byte b;
            do
            {
                b = Byte();
                len |= (b & 0x7F) << shift;
                shift += 7;
                if (shift > 28) throw new ToolError(ErrorCode.MalformedInput, "Corrupt single-file bundle: bad string length.");
            } while ((b & 0x80) != 0);
            if (len > 4096) throw new ToolError(ErrorCode.MalformedInput, "Corrupt single-file bundle: path too long.");
            return Encoding.UTF8.GetString(Take(len));
        }
    }
}
