using System.Buffers.Binary;
using System.Xml.Linq;

namespace Corvus.Core.Installers;

/// <summary>WiX Burn bundles: files listed under their manifest paths; downloaded payloads are listed, not extracted.</summary>
internal sealed class BurnBundleReader : IContainerReader
{
    private const uint Magic = 0x00F14300;
    private const int HeaderBytes = 48;
    private const int MaxContainers = 1024;
    private const int HeadBytes = 1 << 20;

    public string Kind => "burn";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Section(data[..Math.Min(data.Length, HeadBytes)]) != null;

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Open(new MemoryStream(data, writable: false), name, allFiles, limits, ct)!;

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var read = InstallerPe.Of(stream);
        var head = read(0, (int)Math.Min(stream.Length, HeadBytes))!;
        var h = Section(head) ?? throw new ToolError(ErrorCode.MalformedInput, $"{name}: no .wixburn section.");
        var cabinets = new List<(long Offset, long Size)>();
        long at = h.StubSize;
        for (int i = 0; i < h.Sizes.Count; i++)
        {
            cabinets.Add((at, h.Sizes[i]));
            // Attached cabinets start after the stub's original signature.
            at = i == 0 && h.SignatureOffset > 0 ? (long)h.SignatureOffset + h.SignatureSize : at + h.Sizes[i];
        }
        var notes = new List<string>();
        var ux = Cabinet(read, cabinets[0], "user interface cabinet", limits, name);
        var manifestFile = ux.Files.FirstOrDefault(f => f.Name == "0") ?? throw new ToolError(ErrorCode.MalformedInput, $"{name}: the user interface cabinet has no manifest.");
        var manifest = Manifest.Parse(ux.Extract(manifestFile, limits.MaxItemBytes) ?? throw new ToolError(ErrorCode.MalformedInput, $"{name}: unreadable manifest."));
        notes.Add($"WiX Burn bundle{(manifest.Name != null ? $" {manifest.Name}" : "")}{(manifest.Version != null ? $" {manifest.Version}" : "")}" +
                  $"{(manifest.Publisher != null ? $" by {manifest.Publisher}" : "")}: bundle id {h.BundleId:B}, {h.Sizes.Count} cabinet(s), " +
                  $"{manifest.Packages.Count} package(s) ({string.Join(", ", manifest.Packages.GroupBy(p => p.Kind).Select(g => $"{g.Count()} {g.Key}"))}).");

        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        string Path(string sourcePath, string fallback) => manifest.Paths.TryGetValue(sourcePath, out var p) ? p : fallback;
        Add(CabinetReader.Contents(ux, allFiles, limits, ct, "", f => "ux/" + (f.Name == "0" ? "manifest.xml" : Path(f.Name, f.Name))));
        for (int i = 1; i < cabinets.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            try { Add(CabinetReader.Contents(Cabinet(read, cabinets[i], $"attached cabinet {i}", limits, name), allFiles, limits, ct, "", f => Path(f.Name, f.Name))); }
            catch (ToolError ex) when (ex.Code is ErrorCode.MalformedInput or ErrorCode.LimitExceeded) { notes.Add(ex.Message); }
        }
        foreach (var p in manifest.External)
            entries.Add(new ContainerEntry(p.Path, p.Size, p.Url != null ? $"downloaded at install from {p.Url}" : "downloaded at install"));
        if (manifest.External.Count > 0) notes.Add($"{manifest.External.Count} payload(s) are downloaded at install time: listed, not in the bundle.");
        return new ContainerContents("WiX Burn bundle", items, notes) { Entries = entries };

        void Add(ContainerContents c)
        {
            items.AddRange(c.Items);
            entries.AddRange(c.Entries ?? []);
            notes.AddRange(c.Notes);
        }
    }

    private sealed record Header(Guid BundleId, uint StubSize, uint SignatureOffset, uint SignatureSize, IReadOnlyList<uint> Sizes);

    /// <summary>The .wixburn section's header, read from the bytes that hold the section table and the section.</summary>
    private static Header? Section(ReadOnlySpan<byte> head)
    {
        if (PeImage.TryParse(head) is not { } pe || pe.Sections.FirstOrDefault(s => s.Name == ".wixburn") is not { } s) return null;
        // The raw data, not the virtual size: a virtual size can end before the cabinet sizes.
        if (s.RawPointer + (long)s.RawSize > head.Length || s.RawSize < HeaderBytes) return null;
        // Magic, version, bundle id, stub size, checksum, signature offset and size, format, count, sizes.
        var b = head.Slice((int)s.RawPointer, (int)s.RawSize);
        // Format 1: cabinets.
        if (U32(b, 0) != Magic || U32(b, 40) != 1) return null;
        uint count = U32(b, 44);
        if (count is 0 or > MaxContainers || HeaderBytes + 4L * count > b.Length) return null;
        var sizes = new uint[count];
        for (int i = 0; i < count; i++) sizes[i] = U32(b, HeaderBytes + 4 * i);
        return new Header(new Guid(b.Slice(8, 16)), U32(b, 24), U32(b, 32), U32(b, 36), sizes);
    }

    private static uint U32(ReadOnlySpan<byte> b, int at) => BinaryPrimitives.ReadUInt32LittleEndian(b[at..]);

    private static Cabinet Cabinet(InstallerPe.Read read, (long Offset, long Size) c, string what, AnalysisLimits limits, string name)
    {
        if (c.Size > limits.MaxItemBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{name}: the {what} is {c.Size:N0} bytes, over the {limits.MaxItemBytes:N0}-byte item limit.");
        var bytes = read(c.Offset, (int)c.Size);
        if (bytes == null || !Installers.Cabinet.Looks(bytes)) throw new ToolError(ErrorCode.MalformedInput, $"{name}: the {what} at {c.Offset:N0} is not a cabinet.");
        return Installers.Cabinet.Read(bytes, what);
    }

    private sealed record ExternalPayload(string Path, long Size, string? Url);

    private sealed record Package(string Id, string Kind);

    /// <summary>The manifest's names: payload source paths to file paths, packages, the downloaded payloads, the product.</summary>
    private sealed record Manifest(Dictionary<string, string> Paths, List<Package> Packages, List<ExternalPayload> External, string? Name, string? Version, string? Publisher)
    {
        public static Manifest Parse(byte[] xml)
        {
            XElement root;
            try { root = XElement.Load(new MemoryStream(xml, writable: false), LoadOptions.None); }
            catch (System.Xml.XmlException ex) { throw new ToolError(ErrorCode.MalformedInput, $"manifest: {ex.Message}"); }
            var paths = new Dictionary<string, string>(StringComparer.Ordinal);
            var external = new List<ExternalPayload>();
            foreach (var p in root.Descendants().Where(e => e.Name.LocalName == "Payload"))
            {
                var file = (string?)p.Attribute("FilePath");
                if (file == null) continue;
                if ((string?)p.Attribute("Packaging") == "external")
                    external.Add(new ExternalPayload(file.Replace('\\', '/'), long.TryParse((string?)p.Attribute("FileSize"), out var size) ? size : 0, (string?)p.Attribute("DownloadUrl")));
                else if ((string?)p.Attribute("SourcePath") is { } source)
                    paths.TryAdd(source, file.Replace('\\', '/'));
            }
            var packages = root.Descendants().Where(e => e.Name.LocalName.EndsWith("Package", StringComparison.Ordinal) && e.Parent?.Name.LocalName == "Chain")
                .Select(e => new Package((string?)e.Attribute("Id") ?? "", e.Name.LocalName)).ToList();
            var arp = root.Descendants().FirstOrDefault(e => e.Name.LocalName == "Arp");
            return new Manifest(paths, packages, external, (string?)arp?.Attribute("DisplayName"), (string?)arp?.Attribute("DisplayVersion"), (string?)arp?.Attribute("Publisher"));
        }
    }
}
