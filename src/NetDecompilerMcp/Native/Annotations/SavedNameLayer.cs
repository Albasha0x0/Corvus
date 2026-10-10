using System.IO.Compression;
using System.Text;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Native.Annotations;

/// <summary>
/// The file format of one saved imported name layer (&lt;sha256&gt;.&lt;source&gt;.names beside the annotation sidecar):
/// gzip over a binary stream: magic, version, image hash and path, source, origin, provenance (source path, identity,
/// import time), the function starts, then names and comments sorted by RVA with the RVA as a delta from the previous
/// one (7-bit encoded) and the text as length-prefixed UTF-8. About 15 bytes per Il2Cpp name with its comment.
/// </summary>
public static class SavedNameLayer
{
    private const string Magic = "ndm-names";
    private const int Version = 1;
    /// <summary>Written last: a file cut short reads as no layer.</summary>
    private const string End = "end";
    /// <summary>Most entries read from one list; a larger count is a corrupt file.</summary>
    private const int MaxEntries = 20_000_000;

    public static void Write(Stream output, string sha256, string imagePath, NativeNameLayers.Layer layer)
    {
        var info = layer.Info ?? new ImportInfo(null, null, DateTime.UtcNow);
        using var gz = new GZipStream(output, CompressionLevel.Fastest, leaveOpen: true);
        using var w = new BinaryWriter(gz, Encoding.UTF8, leaveOpen: true);
        w.Write(Magic);
        w.Write(Version);
        w.Write(sha256);
        w.Write(imagePath);
        w.Write((int)layer.Source);
        w.Write(layer.Origin);
        w.Write(info.SourcePath ?? "");
        w.Write(info.SourceIdentity ?? "");
        w.Write(info.ImportedUtc.ToUniversalTime().Ticks);
        WriteRvas(w, info.FunctionStarts ?? []);
        WriteMap(w, layer.Names);
        WriteMap(w, layer.Comments);
        w.Write(End);
    }

    /// <summary>The layer in <paramref name="input"/> (marked restored), or null when it is not a layer of <paramref name="sha256"/> or is unreadable.</summary>
    public static NativeNameLayers.Layer? Read(Stream input, string sha256, CancellationToken ct = default)
    {
        try
        {
            using var gz = new GZipStream(input, CompressionMode.Decompress, leaveOpen: true);
            using var r = new BinaryReader(gz, Encoding.UTF8, leaveOpen: true);
            if (r.ReadString() != Magic || r.ReadInt32() != Version) return null;
            if (!string.Equals(r.ReadString(), sha256, StringComparison.OrdinalIgnoreCase)) return null;
            r.ReadString(); // image path
            int source = r.ReadInt32();
            if (source is not ((int)NativeNameSource.Pdb or (int)NativeNameSource.Il2Cpp or (int)NativeNameSource.Ida)) return null;
            var origin = r.ReadString();
            var path = r.ReadString();
            var identity = r.ReadString();
            long ticks = r.ReadInt64();
            if (ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks) return null;
            var starts = ReadRvas(r, ct);
            var names = ReadMap(r, ct);
            var comments = ReadMap(r, ct);
            if (starts == null || names == null || comments == null || r.ReadString() != End) return null;
            var info = new ImportInfo(path.Length > 0 ? path : null, identity.Length > 0 ? identity : null, new DateTime(ticks, DateTimeKind.Utc),
                starts.Length > 0 ? starts : null, Restored: true);
            return new NativeNameLayers.Layer((NativeNameSource)source, names, comments, origin, info);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or EndOfStreamException or FormatException or OverflowException
                                       or ArgumentException or DecoderFallbackException)
        {
            return null;
        }
    }

    private static void WriteRvas(BinaryWriter w, IReadOnlyList<uint> rvas)
    {
        w.Write7BitEncodedInt(rvas.Count);
        long previous = 0;
        foreach (var rva in rvas.Order())
        {
            w.Write7BitEncodedInt64(rva - previous);
            previous = rva;
        }
    }

    private static uint[]? ReadRvas(BinaryReader r, CancellationToken ct)
    {
        int count = r.Read7BitEncodedInt();
        if (count is < 0 or > MaxEntries) return null;
        var rvas = new uint[count];
        long rva = 0;
        for (int i = 0; i < count; i++)
        {
            if ((i & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            rva += r.Read7BitEncodedInt64();
            if (rva is < 0 or > uint.MaxValue) return null;
            rvas[i] = (uint)rva;
        }
        return rvas;
    }

    private static void WriteMap(BinaryWriter w, IReadOnlyDictionary<uint, string> map)
    {
        w.Write7BitEncodedInt(map.Count);
        long previous = 0;
        foreach (var (rva, text) in map.OrderBy(kv => kv.Key))
        {
            w.Write7BitEncodedInt64(rva - previous);
            w.Write(text);
            previous = rva;
        }
    }

    private static Dictionary<uint, string>? ReadMap(BinaryReader r, CancellationToken ct)
    {
        int count = r.Read7BitEncodedInt();
        if (count is < 0 or > MaxEntries) return null;
        var map = new Dictionary<uint, string>(count);
        long rva = 0;
        for (int i = 0; i < count; i++)
        {
            if ((i & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            rva += r.Read7BitEncodedInt64();
            if (rva is < 0 or > uint.MaxValue) return null;
            var text = r.ReadString();
            if (text.Length > 0) map[(uint)rva] = text;
        }
        return map;
    }
}
