using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Corvus.Core.Flash;

/// <summary>
/// SWF files as a container: the ActionScript 3 blocks (DoABC) with a class outline each, ActionScript 1 and 2 actions,
/// images, sounds, binary data and the metadata, named by the SymbolClass and ExportAssets tags where they name a
/// character.
/// </summary>
internal sealed class SwfReader : IContainerReader
{
    public const string KindName = "Flash SWF";

    public string Kind => KindName;

    public bool Accepts(ReadOnlySpan<byte> data, string name) =>
        SwfFile.Looks(data) && (data[0] != 'F' || data.Length >= 21 && BinaryPrimitives.ReadUInt32LittleEndian(data[4..]) == data.Length);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var swf = SwfFile.Read(data, name, limits.MaxItemBytes);
        var b = swf.Body;
        var notes = new List<string>(swf.Notes);
        var symbols = Symbols(swf);
        var resources = new List<(string Path, byte[] Content, string? Detail)>();
        var paths = new HashSet<string>(StringComparer.Ordinal);
        void Add(string path, byte[] content, string? detail)
        {
            string unique = path;
            for (int n = 2; !paths.Add(unique); n++) unique = Path.ChangeExtension(path, null) + $"_{n}" + Path.GetExtension(path);
            resources.Add((unique, content, detail));
        }
        string Named(int id, string folder, string ext) =>
            $"{folder}/{(symbols.TryGetValue(id, out var s) ? Safe(s) : $"character_{id}")}{ext}";
        byte[]? tables = null;
        int abcBlocks = 0, actions = 0, failed = 0;
        // Frames count per timeline: the file's (0) and each sprite's.
        var frames = new Dictionary<int, int>();
        foreach (var t in swf.Tags)
        {
            ct.ThrowIfCancellationRequested();
            var body = b.AsSpan(t.At, t.Length);
            try
            {
                switch (t.Code)
                {
                    case 1:
                        frames[t.Sprite] = frames.GetValueOrDefault(t.Sprite) + 1;
                        break;
                    case 72 or 82:
                        int abcAt = 0;
                        string blockName = "";
                        if (t.Code == 82)
                        {
                            blockName = SwfFile.String(b, t.At + 4, t.At + t.Length, out int next);
                            abcAt = next - t.At;
                        }
                        var abc = body[abcAt..].ToArray();
                        string stem = $"scripts/{(blockName.Length > 0 ? Safe(blockName) : $"block_{abcBlocks}")}";
                        abcBlocks++;
                        try
                        {
                            var file = AbcFile.Read(abc);
                            Add(stem + ".abc", abc, $"ABC {file.Major}.{file.Minor}, {file.Classes.Count:N0} classes, {file.Methods.Length:N0} methods, {file.Bodies.Count:N0} method bodies");
                            Add(stem + ".classes.txt", Encoding.UTF8.GetBytes(Outline(file)), null);
                        }
                        catch (InvalidDataException ex)
                        {
                            Add(stem + ".abc", abc, "does not parse");
                            notes.Add($"{stem}.abc: {ex.Message}");
                        }
                        break;
                    case 12:
                        string timeline = t.Sprite == 0 ? "actions" : $"actions/{(symbols.TryGetValue(t.Sprite, out var clip) ? Safe(clip) : $"sprite_{t.Sprite}")}";
                        Add($"{timeline}/frame_{frames.GetValueOrDefault(t.Sprite) + 1}.bin", body.ToArray(), "DoAction: ActionScript 1/2 bytecode");
                        actions++;
                        break;
                    case 59 when t.Length >= 2:
                        Add(Named(BinaryPrimitives.ReadUInt16LittleEndian(body), "actions", ".init.bin"), body[2..].ToArray(), "DoInitAction: ActionScript 1/2 bytecode");
                        actions++;
                        break;
                    case 8:
                        tables = body.ToArray();
                        break;
                    case 6 when t.Length >= 2:
                        Add(Named(Id(body), "images", ".jpg"), Jpeg(tables, body[2..]), tables == null ? "DefineBits without JPEGTables" : "DefineBits, joined with JPEGTables");
                        break;
                    case 21 when t.Length >= 2:
                        Image(Id(body), body[2..], null, "DefineBitsJPEG2");
                        break;
                    case 35 or 90 when t.Length >= 6:
                        int alphaAt = (int)Math.Min(int.MaxValue, BinaryPrimitives.ReadUInt32LittleEndian(body[2..]));
                        int from = t.Code == 90 ? 8 : 6;
                        if (from > t.Length || alphaAt > t.Length - from) throw new InvalidDataException("the alpha offset runs past the tag");
                        Image(Id(body), body.Slice(from, alphaAt), alphaAt < t.Length - from ? "alpha channel stored apart (zlib), not applied" : null, t.Name);
                        break;
                    case 20 or 36 when t.Length >= 7:
                        Add(Named(Id(body), "images", ".png"), Lossless(body, t.Code == 36, limits.MaxItemBytes), t.Name);
                        break;
                    case 14 when t.Length >= 7:
                        var (ext, sound, detail) = Sound(body);
                        Add(Named(Id(body), "sounds", ext), sound, detail);
                        break;
                    case 87 when t.Length >= 6:
                        Add(Named(Id(body), "binary", ".bin"), body[6..].ToArray(), "DefineBinaryData");
                        break;
                    case 77:
                        Add("metadata.xml", body.TrimEnd((byte)0).ToArray(), "Metadata (XMP)");
                        break;
                }
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException or ArgumentException)
            {
                if (failed++ < 3) notes.Add($"{t.Name} at 0x{t.At:X}: {ex.Message}");
            }
        }
        if (failed > 3) notes.Add($"{failed - 3} more tags do not read.");

        void Image(int id, ReadOnlySpan<byte> image, string? extra, string tag)
        {
            // Files written before Flash Player 8 may start with an extra EOI and SOI pair.
            if (image.StartsWith((ReadOnlySpan<byte>)[0xFF, 0xD9, 0xFF, 0xD8])) image = image[4..];
            string ext = image.StartsWith((ReadOnlySpan<byte>)[0x89, 0x50, 0x4E, 0x47]) ? ".png" : image.StartsWith("GIF8"u8) ? ".gif" : ".jpg";
            Add(Named(id, "images", ext), image.ToArray(), extra == null ? tag : $"{tag}, {extra}");
        }

        var counts = swf.Tags.GroupBy(x => x.Name).OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.Ordinal).Take(8).Select(g => $"{g.Count():N0} {g.Key}");
        notes.Insert(0, $"Flash SWF version {swf.Version}, {(swf.Compression == "none" ? "uncompressed" : $"{swf.Compression}-compressed")}, " +
            $"{(swf.Frame.XMax - swf.Frame.XMin) / 20.0:0.##}x{(swf.Frame.YMax - swf.Frame.YMin) / 20.0:0.##} px, {swf.FrameRate:0.##} fps, {swf.FrameCount:N0} frame(s); " +
            $"{swf.Tags.Count:N0} tags ({string.Join(", ", counts)}); {abcBlocks} ActionScript 3 block(s), {actions} ActionScript 1/2 action list(s).");
        var entries = new List<ContainerEntry>();
        var items = new List<ExtractedItem>();
        long total = 0;
        bool stopped = false;
        foreach (var (path, content, detail) in resources)
        {
            entries.Add(new ContainerEntry(path, content.Length, detail));
            if (stopped || !(allFiles || Containers.IsInteresting(path))) continue;
            if (items.Count >= limits.MaxItems || (total += content.Length) > limits.MaxTotalBytes) { notes.Add("Stopped: the extraction limit was reached."); stopped = true; continue; }
            items.Add(new ExtractedItem(path, content, "SWF resource"));
        }
        if (!allFiles && !stopped && entries.Count > items.Count) notes.Add($"{entries.Count - items.Count} of {entries.Count} files not extracted (not binaries or packages; allFiles extracts every file).");
        return new ContainerContents(Kind, items, notes) { Entries = entries };
    }

    /// <summary>One line per class, as the ABC declares it: kind, name, base class, interfaces, then its traits.</summary>
    public static string Outline(AbcFile abc)
    {
        var s = new StringBuilder();
        foreach (var c in abc.Classes)
        {
            s.Append(c.IsInterface ? "interface " : c.IsFinal ? "final class " : "class ").Append(c.Name);
            if (c.Super != null) s.Append(" extends ").Append(c.Super);
            if (c.Interfaces.Count > 0) s.Append(" implements ").AppendJoin(", ", c.Interfaces);
            s.Append('\n');
            foreach (var t in c.StaticTraits) s.Append("  static ").Append(t.Kind).Append(' ').Append(t.Name).Append('\n');
            foreach (var t in c.Traits) s.Append("  ").Append(t.Kind).Append(' ').Append(t.Name).Append('\n');
        }
        return s.ToString();
    }

    /// <summary>Character names: SymbolClass gives the ActionScript class, ExportAssets the export name; the class wins.</summary>
    private static Dictionary<int, string> Symbols(SwfFile swf)
    {
        var names = new Dictionary<int, string>();
        foreach (var t in swf.Tags.Where(x => x.Code is 56 or 76).OrderBy(x => x.Code))
        {
            if (t.Length < 2) continue;
            int count = BinaryPrimitives.ReadUInt16LittleEndian(swf.Body.AsSpan(t.At)), p = t.At + 2, end = t.At + t.Length;
            for (int i = 0; i < count && p + 2 <= end; i++)
            {
                int id = BinaryPrimitives.ReadUInt16LittleEndian(swf.Body.AsSpan(p));
                string name = SwfFile.String(swf.Body, p + 2, end, out p);
                if (id != 0 && name.Length > 0) names[id] = name;
            }
        }
        return names;
    }

    private static int Id(ReadOnlySpan<byte> body) => BinaryPrimitives.ReadUInt16LittleEndian(body);

    /// <summary>A path segment: a class name keeps its dots, and characters a file name cannot hold become '_'.</summary>
    private static string Safe(string name)
    {
        var s = new StringBuilder(Math.Min(name.Length, 120));
        foreach (char c in name.AsSpan(0, Math.Min(name.Length, 120))) s.Append(c < 0x20 || "<>:\"/\\|?*".Contains(c) ? '_' : c);
        return s.ToString().Trim('.', ' ') is { Length: > 0 } x ? x : "_";
    }

    /// <summary>DefineBits data completed by the JPEGTables tables: the tables without their EOI, then the data without its SOI.</summary>
    private static byte[] Jpeg(byte[]? tables, ReadOnlySpan<byte> data)
    {
        if (data.StartsWith((ReadOnlySpan<byte>)[0xFF, 0xD9, 0xFF, 0xD8])) data = data[4..];
        if (tables is not { Length: > 4 }) return data.ToArray();
        ReadOnlySpan<byte> t = tables;
        if (t.StartsWith((ReadOnlySpan<byte>)[0xFF, 0xD9, 0xFF, 0xD8])) t = t[4..];
        if (t.EndsWith((ReadOnlySpan<byte>)[0xFF, 0xD9])) t = t[..^2];
        if (data.StartsWith((ReadOnlySpan<byte>)[0xFF, 0xD8])) data = data[2..];
        return [.. t, .. data];
    }

    /// <summary>
    /// A DefineBitsLossless bitmap as PNG: format 3 (colormapped, rows padded to 4 bytes), 4 (PIX15) or 5 (XRGB; premultiplied
    /// ARGB in DefineBitsLossless2), expanded from zlib.
    /// </summary>
    private static byte[] Lossless(ReadOnlySpan<byte> body, bool alpha, long maxBytes)
    {
        int format = body[2], width = BinaryPrimitives.ReadUInt16LittleEndian(body[3..]), height = BinaryPrimitives.ReadUInt16LittleEndian(body[5..]);
        if (width == 0 || height == 0) throw new InvalidDataException("an empty bitmap");
        int colors = format == 3 ? body.Length > 7 ? body[7] + 1 : throw new InvalidDataException("the color table size is cut short") : 0;
        int entry = alpha ? 4 : 3;
        int stride = format switch { 3 => (width + 3) & ~3, 4 => (width * 2 + 3) & ~3, 5 => width * 4, _ => throw new InvalidDataException($"bitmap format {format} is not defined") };
        long size = (long)colors * entry + (long)stride * height;
        if (size > maxBytes || 4L * width * height > maxBytes) throw new InvalidDataException($"a {width}x{height} bitmap is past the item limit");
        var raw = new byte[size];
        using (var z = new ZLibStream(new MemoryStream(body[(format == 3 ? 8 : 7)..].ToArray(), writable: false), CompressionMode.Decompress))
        {
            int got = 0;
            for (int n; got < raw.Length && (n = z.Read(raw, got, raw.Length - got)) > 0;) got += n;
            if (got < raw.Length) throw new InvalidDataException($"the bitmap expands to {got:N0} of {raw.Length:N0} bytes");
        }
        var rgba = new byte[4L * width * height];
        int pixels = colors * entry;
        for (int y = 0; y < height; y++)
            for (int x = 0; x < width; x++)
            {
                int o = (y * width + x) * 4;
                switch (format)
                {
                    case 3:
                        int index = raw[pixels + y * stride + x];
                        if (index < colors)
                        {
                            raw.AsSpan(index * entry, 3).CopyTo(rgba.AsSpan(o));
                            rgba[o + 3] = alpha ? raw[index * entry + 3] : (byte)255;
                        }
                        break;
                    case 4:
                        int v = BinaryPrimitives.ReadUInt16BigEndian(raw.AsSpan(y * stride + x * 2));
                        rgba[o] = (byte)((v >> 10 & 31) * 255 / 31);
                        rgba[o + 1] = (byte)((v >> 5 & 31) * 255 / 31);
                        rgba[o + 2] = (byte)((v & 31) * 255 / 31);
                        rgba[o + 3] = 255;
                        break;
                    default:
                        int p = y * stride + x * 4;
                        rgba[o] = raw[p + 1];
                        rgba[o + 1] = raw[p + 2];
                        rgba[o + 2] = raw[p + 3];
                        rgba[o + 3] = alpha ? raw[p] : (byte)255;
                        break;
                }
            }
        // Colormapped DefineBitsLossless2 entries are premultiplied too.
        if (alpha) PngWriter.Unpremultiply(rgba);
        return PngWriter.Rgba(width, height, rgba);
    }

    /// <summary>A DefineSound as a file: MP3 frames, uncompressed PCM as WAV, the other formats as their raw stream.</summary>
    private static (string Ext, byte[] Content, string Detail) Sound(ReadOnlySpan<byte> body)
    {
        byte flags = body[2];
        int format = flags >> 4, rate = ((int[])[5512, 11025, 22050, 44100])[flags >> 2 & 3], bits = (flags & 2) != 0 ? 16 : 8, channels = (flags & 1) + 1;
        uint samples = BinaryPrimitives.ReadUInt32LittleEndian(body[3..]);
        var data = body[7..];
        string detail = $"{samples:N0} samples, {rate:N0} Hz, {channels} channel(s)";
        switch (format)
        {
            case 2:
                // MP3 sound data starts with a 16-bit seek sample count.
                return (".mp3", data.Length >= 2 ? data[2..].ToArray() : [], "MP3, " + detail);
            case 0 or 3:
                var wav = new byte[44 + data.Length];
                "RIFF"u8.CopyTo(wav);
                BinaryPrimitives.WriteInt32LittleEndian(wav.AsSpan(4), 36 + data.Length);
                "WAVEfmt "u8.CopyTo(wav.AsSpan(8));
                BinaryPrimitives.WriteInt32LittleEndian(wav.AsSpan(16), 16);
                BinaryPrimitives.WriteInt16LittleEndian(wav.AsSpan(20), 1);
                BinaryPrimitives.WriteInt16LittleEndian(wav.AsSpan(22), (short)channels);
                BinaryPrimitives.WriteInt32LittleEndian(wav.AsSpan(24), rate);
                BinaryPrimitives.WriteInt32LittleEndian(wav.AsSpan(28), rate * channels * bits / 8);
                BinaryPrimitives.WriteInt16LittleEndian(wav.AsSpan(32), (short)(channels * bits / 8));
                BinaryPrimitives.WriteInt16LittleEndian(wav.AsSpan(34), (short)bits);
                "data"u8.CopyTo(wav.AsSpan(36));
                BinaryPrimitives.WriteInt32LittleEndian(wav.AsSpan(40), data.Length);
                data.CopyTo(wav.AsSpan(44));
                return (".wav", wav, $"PCM {bits}-bit, " + detail);
            default:
                string name = format switch { 1 => "ADPCM", 4 => "Nellymoser 16 kHz", 5 => "Nellymoser 8 kHz", 6 => "Nellymoser", 11 => "Speex", _ => $"format {format}" };
                return (".raw", data.ToArray(), $"{name}, not converted, " + detail);
        }
    }
}
