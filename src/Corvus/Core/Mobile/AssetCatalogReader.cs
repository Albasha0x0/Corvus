using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace Corvus.Core.Mobile;

/// <summary>A rendition's link into a packed image: the rectangle (lower-left origin) and the packed rendition's key.</summary>
internal sealed record CatalogLink(int X, int Y, int Width, int Height, IReadOnlyList<(int Type, int Value)> Key);

/// <summary>
/// One rendition of a compiled asset catalog: its asset (facet) name, null when no facet names it; its CSI name, layout,
/// pixel format, size in pixels, scale in hundredths, key attributes, payload tag (CELM, RAWD, COLR, ARGG; empty for
/// none) and the payload bytes after the tag's header.
/// </summary>
internal sealed record CatalogRendition(int Index, string? Asset, string Name, int Layout, string PixelFormat, int Width, int Height, int Scale,
    IReadOnlyList<(int Type, int Value)> Key, string Tag, uint Compression, byte[] Payload)
{
    public CatalogLink? Link { get; init; }

    public int Attribute(int type) => Key.FirstOrDefault(k => k.Type == type).Value;
}

/// <summary>
/// A compiled asset catalog (Assets.car): a BOM store whose CARHEADER, KEYFORMAT, FACETKEYS, APPEARANCEKEYS and
/// RENDITIONS hold the renditions. CAR data is little-endian ('RATC') or big-endian ('CTAR'). Damaged structure throws
/// <see cref="InvalidDataException"/>.
/// </summary>
internal sealed class AssetCatalog
{
    // Rendition key attributes (CoreUI's rendition attribute types) used in names.
    public const int Appearance = 7, Scale = 12, Idiom = 15, Identifier = 17, Gamut = 24;

    private static readonly HashSet<string> NumericCodes =
        ["CTAR", "CTSI", "kfmt", "CELM", "RAWD", "COLR", "INLK", "ARGB", "GA8 ", "GA16", "RGB5", "RGBW", "DATA", "JPEG", "HEIF", "PDF ", "SVG "];

    public bool LittleEndian { get; }
    public int DeclaredCount { get; }
    public string StorageVersion { get; }
    public string? Platform { get; }
    public IReadOnlyDictionary<int, string> Appearances { get; }
    public IReadOnlyList<CatalogRendition> Renditions { get; }

    public static bool Looks(ReadOnlySpan<byte> data) => BomStore.Names(data, "CARHEADER"u8);

    public AssetCatalog(byte[] data)
    {
        var bom = new BomStore(data);
        var header = bom.Variable("CARHEADER") ?? throw new InvalidDataException("no CARHEADER");
        if (header.Length < 436) throw new InvalidDataException($"a CARHEADER of {header.Length} bytes");
        bool little = LittleEndian = header.AsSpan().StartsWith("RATC"u8);
        if (!little && !header.AsSpan().StartsWith("CTAR"u8)) throw new InvalidDataException("a CARHEADER without its 'CTAR' tag");
        uint U32(ReadOnlySpan<byte> b) => little ? BinaryPrimitives.ReadUInt32LittleEndian(b) : BinaryPrimitives.ReadUInt32BigEndian(b);
        ushort U16(ReadOnlySpan<byte> b) => little ? BinaryPrimitives.ReadUInt16LittleEndian(b) : BinaryPrimitives.ReadUInt16BigEndian(b);
        // Most four-character codes are stored as numbers, reversed in little-endian data; others ('ARGG', 'SISM') as text.
        string Code(ReadOnlySpan<byte> b)
        {
            if (b[..4].IndexOfAnyExcept((byte)0) < 0) return "";
            string text = Encoding.ASCII.GetString(b[..4]), reversed = new([.. text.Reverse()]);
            return little && NumericCodes.Contains(reversed) ? reversed : text;
        }

        DeclaredCount = (int)Math.Min(U32(header.AsSpan(16)), int.MaxValue);
        StorageVersion = Text(header.AsSpan(148, 256));
        if (bom.Variable("EXTENDED_METADATA") is { Length: >= 1028 } meta)
            Platform = $"{Text(meta.AsSpan(516, 256))} {Text(meta.AsSpan(260, 256))}".Trim() is { Length: > 0 } p ? p : null;

        var format = bom.Variable("KEYFORMAT") ?? throw new InvalidDataException("no KEYFORMAT");
        if (format.Length < 12 || Code(format) != "kfmt") throw new InvalidDataException("a KEYFORMAT without its 'kfmt' tag");
        long types = U32(format.AsSpan(8));
        if (types > (format.Length - 12) / 4) throw new InvalidDataException($"a KEYFORMAT of {types:N0} attributes in {format.Length} bytes");
        var keyTypes = Enumerable.Range(0, (int)types).Select(i => (int)U32(format.AsSpan(12 + 4 * i))).ToArray();

        var appearances = new Dictionary<int, string>();
        foreach (var (key, value) in bom.Tree("APPEARANCEKEYS") ?? [])
            if (value.Length >= 2) appearances[U16(value)] = Text(key);
        Appearances = appearances;

        var names = new Dictionary<int, string>();
        foreach (var (key, value) in bom.Tree("FACETKEYS") ?? throw new InvalidDataException("no FACETKEYS"))
        {
            if (value.Length < 6) throw new InvalidDataException("a facet value is cut short");
            int count = U16(value.AsSpan(4));
            for (int i = 0; i < count && 10 + 4 * i <= value.Length; i++)
                if (U16(value.AsSpan(6 + 4 * i)) == Identifier) names.TryAdd(U16(value.AsSpan(8 + 4 * i)), Text(key));
        }

        var renditions = new List<CatalogRendition>();
        foreach (var (key, csi) in bom.Tree("RENDITIONS") ?? throw new InvalidDataException("no RENDITIONS"))
        {
            int index = renditions.Count;
            if (key.Length < 2 * keyTypes.Length) throw new InvalidDataException($"rendition {index}: a key of {key.Length} bytes for {keyTypes.Length} attributes");
            var attributes = keyTypes.Select((t, i) => (t, (int)U16(key.AsSpan(2 * i)))).ToArray();
            if (csi.Length < 180 || Code(csi) != "CTSI") throw new InvalidDataException($"rendition {index}: no CSI header");
            long tlvLength = U32(csi.AsSpan(168)), bitmaps = U32(csi.AsSpan(172));
            long tlvAt = 180 + 4 * bitmaps;
            if (tlvAt > csi.Length || tlvLength > csi.Length - tlvAt) throw new InvalidDataException($"rendition {index}: its TLVs run past the CSI block");
            int payloadAt = (int)(tlvAt + tlvLength);
            var payload = csi.AsSpan(payloadAt);
            string tag = payload.Length >= 4 ? Code(payload) : "";
            int headerSize = tag switch { "CELM" => 16, "RAWD" => 12, _ => 0 };
            uint compression = tag == "CELM" && payload.Length >= 16 ? U32(payload[8..]) : 0;
            var body = payload.Length >= headerSize ? payload[headerSize..] : [];
            if (tag == "RAWD" && payload.Length >= 12 && U32(payload[8..]) < body.Length) body = body[..(int)U32(payload[8..])];
            int identifier = attributes.FirstOrDefault(a => a.t == Identifier).Item2;
            renditions.Add(new CatalogRendition(index, names.GetValueOrDefault(identifier), Text(csi.AsSpan(40, 128)), U16(csi.AsSpan(36)), Code(csi.AsSpan(24)),
                (int)Math.Min(U32(csi.AsSpan(12)), int.MaxValue), (int)Math.Min(U32(csi.AsSpan(16)), int.MaxValue), (int)Math.Min(U32(csi.AsSpan(20)), int.MaxValue),
                attributes, tag, compression, body.ToArray())
            { Link = Link(csi.AsSpan((int)tlvAt, (int)tlvLength), U32, U16) });
        }
        Renditions = renditions;
    }

    /// <summary>The internal link TLV (1010) of a CSI record, or null; record lengths that count their header or are stored shifted left 11 bits are accepted.</summary>
    private static CatalogLink? Link(ReadOnlySpan<byte> tlvs, Func<ReadOnlySpan<byte>, uint> u32, Func<ReadOnlySpan<byte>, ushort> u16)
    {
        for (int p = 0; p + 8 <= tlvs.Length;)
        {
            uint type = u32(tlvs[p..]);
            long length = u32(tlvs[(p + 4)..]), left = tlvs.Length - p - 8;
            if (length > left && length >= 8 && length - 8 == left) length -= 8;
            if (length > left && (length & 0x7FF) == 0 && length >> 11 == left) length >>= 11;
            if (length > left) return null;
            var value = tlvs.Slice(p + 8, (int)length);
            if (type == 1010 && value.Length >= 30)
            {
                long keyLength = u32(value[26..]);
                var key = new List<(int, int)>();
                for (int i = 30; keyLength <= value.Length - 30 && i + 4 <= 30 + keyLength; i += 4)
                {
                    int t = u16(value[i..]), v = u16(value[(i + 2)..]);
                    if (t == 0 && v == 0) break;
                    key.Add((t, v));
                }
                return new CatalogLink((int)u32(value[8..]), (int)u32(value[12..]), (int)u32(value[16..]), (int)u32(value[20..]), key);
            }
            p += 8 + (int)length;
        }
        return null;
    }

    /// <summary>The rendition a link names: the one whose key equals the link's tokens, attributes the link omits being 0; null when none or several do.</summary>
    public CatalogRendition? Target(CatalogLink link)
    {
        var want = link.Key.GroupBy(k => k.Type).ToDictionary(g => g.Key, g => g.First().Value);
        var found = Renditions.Where(r => r.Key.All(k => k.Value == want.GetValueOrDefault(k.Type)) && want.Keys.All(t => r.Key.Any(k => k.Type == t))).Take(2).ToList();
        return found.Count == 1 ? found[0] : null;
    }

    public uint U32(ReadOnlySpan<byte> b) => LittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(b) : BinaryPrimitives.ReadUInt32BigEndian(b);

    private static string Text(ReadOnlySpan<byte> b)
    {
        int end = b.IndexOf((byte)0);
        return Encoding.UTF8.GetString(end < 0 ? b : b[..end]).Trim();
    }
}

/// <summary>
/// Compiled asset catalogs (Assets.car) as a container: each rendition listed under its asset with its size, scale,
/// idiom and appearance; bitmaps extracted as PNG, images cropped from packed images, original data (PNG, JPEG, PDF,
/// SVG) as stored, and colors and gradients described. Compressions not read are named per rendition and counted.
/// </summary>
internal sealed class AssetCatalogReader : IContainerReader
{
    private static readonly Dictionary<int, string> Layouts = new()
    {
        [7] = "text effect", [9] = "vector", [10] = "image", [11] = "tiled image", [12] = "image", [50] = "animation filmstrip",
        [1000] = "data", [1001] = "external link", [1002] = "layer stack", [1003] = "internal reference", [1004] = "packed image",
        [1005] = "named content", [1006] = "thinning placeholder", [1007] = "texture", [1008] = "texture image", [1009] = "color",
        [1010] = "multisize image set", [1011] = "layer reference", [1012] = "content rendition", [1013] = "recognition object",
        [1019] = "icon image stack", [1020] = "icon group", [1021] = "gradient",
    };

    private static readonly string[] Idioms = ["universal", "iphone", "ipad", "tv", "car", "watch", "marketing", "mac", "vision"];

    private static readonly string[] ColorSpaces = ["", "sRGB", "gray gamma 2.2", "Display P3", "extended sRGB", "", "extended gray"];

    public string Kind => "asset catalog";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => AssetCatalog.Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        AssetCatalog catalog;
        try { catalog = new AssetCatalog(data); }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{name}: not a readable asset catalog: {ex.Message}."); }
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var notes = new List<string>();
        var paths = new HashSet<string>(StringComparer.Ordinal);
        var packed = new Dictionary<int, byte[]?>();
        var notDecoded = new Dictionary<string, int>();
        int unreadable = 0, skipped = 0;
        long total = 0;
        foreach (var r in catalog.Renditions)
        {
            ct.ThrowIfCancellationRequested();
            byte[]? bytes = null;
            string detail;
            string ext = "";
            if (r.Tag == "CELM" || r.Layout == 1003)
            {
                ext = ".png";
                detail = $"{Layout(r)} {r.Width}x{r.Height}{ScaleText(r)}, " + (r.Tag == "CELM" ? AssetCatalogBitmap.CompressionName(r.Compression) : "cropped from a packed image");
                if (allFiles)
                {
                    try
                    {
                        var rgba = Pixels(catalog, r, packed, limits.MaxItemBytes);
                        PngWriter.Unpremultiply(rgba);
                        bytes = PngWriter.Rgba(r.Width, r.Height, rgba);
                    }
                    catch (NotSupportedException ex)
                    {
                        detail += "; not decoded";
                        notDecoded[ex.Message] = notDecoded.GetValueOrDefault(ex.Message) + 1;
                    }
                    catch (InvalidDataException ex)
                    {
                        detail += $"; unreadable: {ex.Message}";
                        unreadable++;
                    }
                }
            }
            else if (r.Tag == "RAWD")
            {
                ext = r.PixelFormat.Trim() switch { "JPEG" => ".jpg", "HEIF" => ".heic", "PDF" => ".pdf", "SVG" => ".svg", _ => "" };
                string kind = r.PixelFormat.Trim() is { Length: > 0 } f && f != "DATA" ? f : "original";
                detail = r.Payload.Length == 0 ? Layout(r) : $"{Layout(r)}, {kind} data";
                bytes = r.Payload.Length == 0 ? null : r.Payload;
                if (bytes != null && Firmware.Lzfse.Looks(bytes))
                    try { bytes = AssetCatalogBitmap.Lzfse(bytes, limits.MaxItemBytes); }
                    catch (InvalidDataException ex) { bytes = null; unreadable++; detail += $"; unreadable: {ex.Message}"; }
            }
            else if (r.Tag == "COLR") detail = Color(catalog, r.Payload, r.Layout == 1009 ? "color" : Layout(r));
            else if (r.Tag == "ARGG") detail = $"gradient, {(r.Payload.Length >= 8 ? catalog.U32(r.Payload.AsSpan(4)) : 0)} stops";
            else detail = Layout(r);

            string path = UniquePath(catalog, r, ext, paths);
            entries.Add(new ContainerEntry(path, bytes?.Length ?? r.Payload.Length, detail));
            if (bytes == null) continue;
            if (items.Count >= limits.MaxItems || total + bytes.Length > limits.MaxTotalBytes) { skipped++; continue; }
            total += bytes.Length;
            items.Add(new ExtractedItem(path, bytes, "asset catalog rendition"));
        }
        int assets = catalog.Renditions.Select(r => r.Asset).Where(a => a != null).Distinct().Count();
        notes.Add($"asset catalog: {catalog.Renditions.Count:N0} renditions of {assets:N0} assets" + (catalog.Platform is { } p ? $" for {p}" : "") + (catalog.StorageVersion.Length > 0 ? $"; {catalog.StorageVersion}" : ""));
        if (catalog.DeclaredCount != 0 && catalog.DeclaredCount != catalog.Renditions.Count) notes.Add($"the header declares {catalog.DeclaredCount:N0} renditions; the tree holds {catalog.Renditions.Count:N0}");
        if (notDecoded.Count > 0) notes.Add($"renditions not decoded: {string.Join(", ", notDecoded.OrderBy(k => k.Key, StringComparer.Ordinal).Select(k => $"{k.Key} ({k.Value})"))}");
        if (unreadable > 0) notes.Add($"{unreadable} renditions unreadable (see their entries)");
        if (skipped > 0) notes.Add($"{skipped} renditions not extracted (the item limit)");
        return new ContainerContents(Kind, items, notes) { Entries = entries };
    }

    /// <summary>A rendition's premultiplied RGBA pixels: its own bitmap, or the rectangle its link names in a packed image.</summary>
    internal static byte[] Pixels(AssetCatalog catalog, CatalogRendition r, Dictionary<int, byte[]?> packed, long maxBytes)
    {
        if (r.Tag == "CELM")
        {
            if (r.Payload.Length == 0) throw new InvalidDataException("a CELM payload without its header");
            return AssetCatalogBitmap.Decode(r.Compression, r.PixelFormat, r.Payload, r.Width, r.Height, maxBytes);
        }
        if (r.Link is not { } link) throw new InvalidDataException("an internal reference without its link");
        if (catalog.Target(link) is not { Tag: "CELM" } target) throw new InvalidDataException("the packed image a link names is not in the catalog");
        if (!packed.TryGetValue(target.Index, out var source))
            packed[target.Index] = source = AssetCatalogBitmap.Decode(target.Compression, target.PixelFormat, target.Payload, target.Width, target.Height, maxBytes);
        // Link rectangles have a lower-left origin.
        int x0 = link.X, y0 = target.Height - link.Y - link.Height;
        if (link.Width != r.Width || link.Height != r.Height || x0 < 0 || y0 < 0 || link.X + link.Width > target.Width || y0 + link.Height > target.Height)
            throw new InvalidDataException($"a {link.Width}x{link.Height} rectangle at ({link.X}, {link.Y}) of a {target.Width}x{target.Height} packed image for a {r.Width}x{r.Height} rendition");
        var rgba = new byte[4 * r.Width * r.Height];
        for (int y = 0; y < r.Height; y++) source!.AsSpan(4 * ((y0 + y) * target.Width + x0), 4 * r.Width).CopyTo(rgba.AsSpan(4 * y * r.Width));
        return rgba;
    }

    private static string Layout(CatalogRendition r) => Layouts.GetValueOrDefault(r.Layout) ?? (r.Layout is > 10 and < 50 ? "image" : $"layout {r.Layout}");

    private static string ScaleText(CatalogRendition r) => r.Scale <= 0 ? "" : $" @{(r.Scale / 100.0).ToString(CultureInfo.InvariantCulture)}x";

    private static string Color(AssetCatalog catalog, byte[] p, string what)
    {
        // Tag, version, color space, component count, then 64-bit floats.
        if (p.Length < 16) return what;
        uint space = catalog.U32(p.AsSpan(8)), count = catalog.U32(p.AsSpan(12));
        if (count > (p.Length - 16) / 8) return what;
        var parts = Enumerable.Range(0, (int)count).Select(i => p.AsSpan(16 + 8 * i, 8).ToArray())
            .Select(b => BitConverter.Int64BitsToDouble(catalog.LittleEndian ? BinaryPrimitives.ReadInt64LittleEndian(b) : BinaryPrimitives.ReadInt64BigEndian(b)))
            .Select(v => v.ToString("0.####", CultureInfo.InvariantCulture)).ToList();
        string name = space < ColorSpaces.Length && ColorSpaces[space].Length > 0 ? ColorSpaces[space] : $"color space {space}";
        return $"{what} {name} {string.Join(' ', parts)}";
    }

    // Asset/stem~idiom~appearance~gamut@scale.ext: a bitmap ends in .png, original data keeps its name's extension or
    // takes one from its format; a name already taken gets -2, -3 and so on.
    private static string UniquePath(AssetCatalog catalog, CatalogRendition r, string ext, HashSet<string> taken)
    {
        static string Clean(string s) => s.Replace('/', '_').Replace('\\', '_');
        string name = r.Name.Length > 0 ? r.Name : r.Asset ?? $"rendition-{r.Index}";
        // An extension is one to five letters and digits after the last dot, so version numbers stay in the stem.
        string own = Path.GetExtension(name);
        if (own.Length is < 2 or > 6 || !own[1..].All(char.IsAsciiLetterOrDigit) || !own.Any(char.IsAsciiLetter)) own = "";
        string bare = own.Length > 0 && name.Length > own.Length ? name[..^own.Length] : name;
        var (stem, extension) = ext == ".png" ? (bare, ext) : r.Tag == "RAWD" && own.Length > 0 ? (bare, own) : (name, ext);
        var suffix = new StringBuilder();
        if (r.Attribute(AssetCatalog.Idiom) is var idiom and > 0) suffix.Append('~').Append(idiom < Idioms.Length ? Idioms[idiom] : $"idiom{idiom}");
        if (r.Attribute(AssetCatalog.Appearance) is var look and > 0)
        {
            string a = catalog.Appearances.GetValueOrDefault(look) ?? $"appearance{look}";
            foreach (var prefix in new[] { "NSAppearanceName", "UIAppearance", "ISAppearance" })
                if (a.StartsWith(prefix, StringComparison.Ordinal) && a.Length > prefix.Length) a = a[prefix.Length..];
            suffix.Append('~').Append(a);
        }
        if (r.Attribute(AssetCatalog.Gamut) is var gamut and > 0) suffix.Append(gamut == 1 ? "~P3" : $"~gamut{gamut}");
        if (ext == ".png" && r.Scale > 0) suffix.Append(ScaleText(r).TrimStart());
        else if (r.Attribute(AssetCatalog.Scale) > 1) suffix.Append('@').Append(r.Attribute(AssetCatalog.Scale)).Append('x');
        string folder = Clean(r.Asset ?? bare), file = Clean(stem) + suffix;
        string path = $"{folder}/{file}{extension}";
        for (int n = 2; !taken.Add(path); n++) path = $"{folder}/{file}-{n}{extension}";
        return path;
    }
}
