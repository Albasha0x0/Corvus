using System.IO.Compression;

namespace Corvus.Core.Models;

/// <summary>A torch.save file, zip or legacy format; the pickle is scanned, never unpickled, and storage sizes checked.</summary>
public sealed class TorchCheckpoint
{
    // torch.serialization.MAGIC_NUMBER, 0x1950a86a20f9469cfc6c, as LONG1 writes it.
    private static readonly byte[] LegacyMagic = [0x6c, 0xfc, 0x9c, 0x46, 0xf9, 0x20, 0x6a, 0xa8, 0x50, 0x19];

    public string Format { get; private init; } = "";
    /// <summary>The zip's record folder ("archive" for torch.save's default).</summary>
    public string? Prefix { get; private init; }
    public string? Version { get; private init; }
    public string? ByteOrder { get; private init; }
    public PickleScan Pickle { get; private init; } = null!;
    public List<string> Issues { get; } = [];

    /// <summary>The zip's central directory names a data.pkl beside data/ records.</summary>
    public static bool IsZip(Func<Func<string, bool>, bool> hasEntry) => hasEntry(n => n == "data.pkl" || n.EndsWith("/data.pkl", StringComparison.Ordinal));

    /// <summary>The bytes start with the legacy format's magic-number pickle.</summary>
    public static bool IsLegacy(ReadOnlySpan<byte> head) =>
        head.Length >= 14 && head[0] == 0x80 && head[1] == 0x02 && head[2] == 0x8a && head[3] == 0x0a && head.Slice(4, 10).SequenceEqual(LegacyMagic);

    /// <summary>Reads a zip checkpoint from <paramref name="s"/>; throws <see cref="InvalidDataException"/> when it has no data.pkl or one over <paramref name="maxPickle"/> bytes.</summary>
    public static TorchCheckpoint ReadZip(Stream s, CancellationToken ct = default, long maxPickle = int.MaxValue)
    {
        using var zip = new ZipArchive(s, ZipArchiveMode.Read, leaveOpen: true);
        var pkl = zip.Entries.Where(e => e.FullName == "data.pkl" || e.FullName.EndsWith("/data.pkl", StringComparison.Ordinal))
            .OrderBy(e => e.FullName.Length).FirstOrDefault() ?? throw new InvalidDataException("no data.pkl");
        var prefix = pkl.FullName.Length > "data.pkl".Length ? pkl.FullName[..^"/data.pkl".Length] : null;
        string Entry(string name) => prefix == null ? name : $"{prefix}/{name}";
        string? Small(string name)
        {
            var e = zip.GetEntry(Entry(name));
            if (e == null || e.Length > 4096) return null;
            using var r = new StreamReader(e.Open());
            return r.ReadToEnd().Trim();
        }
        if (pkl.Length > Math.Min(maxPickle, int.MaxValue)) throw new InvalidDataException($"data.pkl is {pkl.Length:N0} bytes, over the {Math.Min(maxPickle, int.MaxValue):N0} byte limit");
        var bytes = new byte[pkl.Length];
        using (var p = pkl.Open()) p.ReadExactly(bytes);
        var scan = PickleScan.Read(new MemoryStream(bytes, writable: false), bytes.Length, ct);
        var c = new TorchCheckpoint
        {
            Format = "zip", Prefix = prefix, Version = Small("version") ?? Small(".data/version"), ByteOrder = Small("byteorder"), Pickle = scan,
        };
        var stored = zip.Entries.Where(e => e.FullName.StartsWith(Entry("data/"), StringComparison.Ordinal))
            .ToDictionary(e => e.FullName[Entry("data/").Length..], e => e.Length, StringComparer.Ordinal);
        c.CheckStorages(stored);
        return c;
    }

    /// <summary>Reads a legacy checkpoint from <paramref name="s"/> (at its start); storages are not checked.</summary>
    public static TorchCheckpoint ReadLegacy(Stream s, long length, CancellationToken ct = default)
    {
        // The magic number, protocol version and system info pickles come before the object pickle.
        for (int i = 0; i < 3; i++)
        {
            var header = PickleScan.Read(s, length, ct);
            if (!header.Complete) throw new InvalidDataException($"header pickle {i + 1} does not end: {string.Join("; ", header.Issues)}");
        }
        var scan = PickleScan.Read(s, length, ct);
        return new TorchCheckpoint { Format = "legacy", Pickle = scan };
    }

    private static readonly Dictionary<string, int> ElementSizes = new(StringComparer.Ordinal)
    {
        ["float64"] = 8, ["float32"] = 4, ["float16"] = 2, ["bfloat16"] = 2, ["int64"] = 8, ["int32"] = 4, ["int16"] = 2, ["int8"] = 1, ["uint8"] = 1,
        ["bool"] = 1, ["complex128"] = 16, ["complex64"] = 8, ["qint8"] = 1, ["qint32"] = 4, ["quint8"] = 1, ["quint4x2"] = 1, ["quint2x4"] = 1,
    };

    private void CheckStorages(Dictionary<string, long> stored)
    {
        foreach (var t in Pickle.TorchTensors(int.MaxValue).DistinctBy(t => t.StorageKey))
        {
            if (!stored.TryGetValue(t.StorageKey, out var size)) Issues.Add($"{t.Name}: storage data/{t.StorageKey} is not in the archive");
            else if (ElementSizes.TryGetValue(t.Dtype, out var e) && t.StorageElements >= 0 && size != t.StorageElements * e)
                Issues.Add($"{t.Name}: storage data/{t.StorageKey} holds {size:N0} bytes for {t.StorageElements:N0} {t.Dtype} elements");
        }
    }
}
