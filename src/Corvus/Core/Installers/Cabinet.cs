using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Corvus.Core.Archives;

namespace Corvus.Core.Installers;

/// <summary>A file of a cabinet: its name, size, folder and offset in the folder's data, and DOS attributes.</summary>
internal sealed record CabinetFile(string Name, long Size, int Folder, long Offset, int Attributes, DateTime? Modified);

/// <summary>Cabinet files (MS-CAB): stored, MSZIP and LZX folders; Quantum folders and spanned files are listed, not extracted.</summary>
internal sealed class Cabinet
{
    public List<CabinetFile> Files { get; } = [];
    public List<string> Notes { get; } = [];
    private readonly byte[] _data;
    private readonly List<(long DataAt, int Blocks, int Compression)> _folders = [];
    private readonly int _dataReserve;
    private readonly Dictionary<int, byte[]> _decoded = [];
    public string Name { get; }

    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= 36 && b.StartsWith("MSCF"u8) && b[25] == 1 && b[24] == 3;

    private Cabinet(byte[] data, string name)
    {
        _data = data;
        Name = name;
        var h = data.AsSpan();
        uint filesAt = BinaryPrimitives.ReadUInt32LittleEndian(h[16..]);
        int folders = BinaryPrimitives.ReadUInt16LittleEndian(h[26..]), files = BinaryPrimitives.ReadUInt16LittleEndian(h[28..]);
        int flags = BinaryPrimitives.ReadUInt16LittleEndian(h[30..]);
        int pos = 36, folderReserve = 0;
        if ((flags & 4) != 0)
        {
            int headerReserve = BinaryPrimitives.ReadUInt16LittleEndian(h[36..]);
            folderReserve = h[38];
            _dataReserve = h[39];
            pos = 40 + headerReserve;
        }
        if ((flags & 1) != 0) { pos = SkipString(pos); pos = SkipString(pos); Notes.Add("continues an earlier cabinet; files begun there are not extracted"); }
        if ((flags & 2) != 0) { pos = SkipString(pos); pos = SkipString(pos); Notes.Add("continues in a later cabinet; files that run into it are not extracted"); }
        for (int i = 0; i < folders; i++)
        {
            if (pos + 8 > data.Length) throw Malformed("the folder table runs past the file");
            _folders.Add((BinaryPrimitives.ReadUInt32LittleEndian(h[pos..]), BinaryPrimitives.ReadUInt16LittleEndian(h[(pos + 4)..]), BinaryPrimitives.ReadUInt16LittleEndian(h[(pos + 6)..])));
            pos += 8 + folderReserve;
        }
        pos = (int)Math.Min(filesAt, (uint)data.Length);
        for (int i = 0; i < files; i++)
        {
            if (pos + 16 > data.Length) throw Malformed("the file table runs past the file");
            long size = BinaryPrimitives.ReadUInt32LittleEndian(h[pos..]);
            long offset = BinaryPrimitives.ReadUInt32LittleEndian(h[(pos + 4)..]);
            int folder = BinaryPrimitives.ReadUInt16LittleEndian(h[(pos + 8)..]);
            int date = BinaryPrimitives.ReadUInt16LittleEndian(h[(pos + 10)..]), time = BinaryPrimitives.ReadUInt16LittleEndian(h[(pos + 12)..]);
            int attributes = BinaryPrimitives.ReadUInt16LittleEndian(h[(pos + 14)..]);
            int nameAt = pos + 16;
            int end = data.AsSpan(nameAt).IndexOf((byte)0);
            if (end < 0) throw Malformed("a file name runs past the file");
            var raw = data.AsSpan(nameAt, end);
            var fileName = (attributes & 0x80) != 0 ? Encoding.UTF8.GetString(raw) : Encoding.Latin1.GetString(raw);
            Files.Add(new CabinetFile(fileName.Replace('\\', '/'), size, folder, offset, attributes, DosTime(date, time)));
            pos = nameAt + end + 1;
        }
    }

    private static DateTime? DosTime(int date, int time)
    {
        try { return new DateTime(1980 + (date >> 9), Math.Max(1, (date >> 5) & 15), Math.Max(1, date & 31), time >> 11, (time >> 5) & 63, (time & 31) * 2, DateTimeKind.Unspecified); }
        catch (ArgumentOutOfRangeException) { return null; }
    }

    private int SkipString(int pos)
    {
        int end = _data.AsSpan(Math.Min(pos, _data.Length)).IndexOf((byte)0);
        return end < 0 ? _data.Length : pos + end + 1;
    }

    private ToolError Malformed(string what) => new(ErrorCode.MalformedInput, $"{Name}: {what}.");

    public static Cabinet Read(byte[] data, string name)
    {
        if (!Looks(data)) throw new ToolError(ErrorCode.MalformedInput, $"{name} is not a cabinet (no MSCF 1.3 header).");
        return new Cabinet(data, name);
    }

    public string Compression(int folder) => folder < _folders.Count ? (_folders[folder].Compression & 0x0F) switch
    {
        0 => "stored", 1 => "MSZIP", 2 => "Quantum", 3 => $"LZX:{(_folders[folder].Compression >> 8) & 0x1F}", var t => $"type {t}",
    } : "?";

    /// <summary>A file's bytes, its folder decoded once; null for a file continued from or into another cabinet.</summary>
    public byte[]? Extract(CabinetFile f, long max)
    {
        if (f.Folder >= 0xFFFD || f.Folder >= _folders.Count) return null;
        var data = Folder(f.Folder, max);
        if (f.Offset + f.Size > data.Length) throw Malformed($"{f.Name} runs past its folder's data ({data.Length:N0} bytes)");
        return data.AsSpan((int)f.Offset, (int)f.Size).ToArray();
    }

    private byte[] Folder(int index, long max)
    {
        if (_decoded.TryGetValue(index, out var cached)) return cached;
        var (at, blocks, compression) = _folders[index];
        var raw = new List<byte[]>();
        var sizes = new List<int>();
        long pos = at, total = 0;
        for (int i = 0; i < blocks; i++)
        {
            if (pos + 8 + _dataReserve > _data.Length) throw Malformed($"data block {i} of folder {index} runs past the file");
            int compressed = BinaryPrimitives.ReadUInt16LittleEndian(_data.AsSpan((int)pos + 4)), uncompressed = BinaryPrimitives.ReadUInt16LittleEndian(_data.AsSpan((int)pos + 6));
            long body = pos + 8 + _dataReserve;
            if (body + compressed > _data.Length) throw Malformed($"data block {i} of folder {index} runs past the file");
            raw.Add(_data.AsSpan((int)body, compressed).ToArray());
            sizes.Add(uncompressed);
            total += uncompressed;
            pos = body + compressed;
        }
        if (total > max) throw new ToolError(ErrorCode.LimitExceeded, $"{Name}: folder {index} holds {total:N0} bytes, over the {max:N0}-byte item limit.");
        byte[] result = (compression & 0x0F) switch
        {
            0 => [.. raw.SelectMany(b => b)],
            1 => MsZip(raw, sizes),
            3 => Lzx.DecodeFolder([.. raw.SelectMany(b => b)], sizes, (compression >> 8) & 0x1F, max),
            _ => throw new ToolError(ErrorCode.Unsupported, $"{Name}: folder {index} is {Compression(index)}-compressed, which is not decoded."),
        };
        _decoded[index] = result;
        return result;
    }

    /// <summary>MSZIP: each block is "CK" and deflate data whose matches may reach into the previous 32 KiB, given here as a stored block before it.</summary>
    private byte[] MsZip(List<byte[]> blocks, List<int> sizes)
    {
        var output = new MemoryStream();
        var buffer = new byte[65536];
        for (int i = 0; i < blocks.Count; i++)
        {
            var b = blocks[i];
            if (b.Length < 2 || b[0] != 'C' || b[1] != 'K') throw Malformed($"MSZIP block {i} lacks its CK signature");
            int history = (int)Math.Min(output.Length, 32768);
            var input = new MemoryStream();
            if (history > 0)
            {
                input.Write([0, (byte)history, (byte)(history >> 8), (byte)~history, (byte)(~history >> 8)]);
                input.Write(output.GetBuffer(), (int)output.Length - history, history);
            }
            input.Write(b, 2, b.Length - 2);
            input.Position = 0;
            int want = history + sizes[i], got = 0;
            var block = new byte[want];
            using (var inflate = new DeflateStream(input, CompressionMode.Decompress))
            {
                try
                {
                    int n;
                    while (got < want && (n = inflate.Read(block, got, want - got)) > 0) got += n;
                }
                catch (InvalidDataException) when (got >= want) { }
            }
            if (got < want) throw Malformed($"MSZIP block {i} decodes to {got - history:N0} of {sizes[i]:N0} bytes");
            output.Write(block, history, sizes[i]);
        }
        return output.ToArray();
    }
}

/// <summary>Cabinet files as containers: every file listed with its compression, binaries and packages (all files with allFiles) extracted.</summary>
internal sealed class CabinetReader : IContainerReader
{
    public string Kind => "cab";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Cabinet.Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) => Contents(Cabinet.Read(data, name), allFiles, limits, ct, "");

    /// <summary>A cabinet's files as items and entries under <paramref name="prefix"/>.</summary>
    public static ContainerContents Contents(Cabinet cab, bool allFiles, AnalysisLimits limits, CancellationToken ct, string prefix, Func<CabinetFile, string>? rename = null)
    {
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var notes = new List<string>(cab.Notes);
        long total = 0;
        int unreadable = 0;
        foreach (var f in cab.Files)
        {
            ct.ThrowIfCancellationRequested();
            var path = prefix + (rename?.Invoke(f) ?? f.Name);
            byte[]? bytes;
            try { bytes = cab.Extract(f, limits.MaxItemBytes); }
            catch (Exception ex) when (ex is InvalidDataException || ex is ToolError { Code: ErrorCode.MalformedInput or ErrorCode.Unsupported or ErrorCode.LimitExceeded })
            {
                entries.Add(new ContainerEntry(path, f.Size, cab.Compression(f.Folder)));
                if (++unreadable <= 10) notes.Add($"{path}: {ex.Message}");
                continue;
            }
            if (bytes == null) { entries.Add(new ContainerEntry(path, f.Size, "continued across cabinets")); continue; }
            ArchiveItems.Take(items, entries, $"cabinet file ({cab.Compression(f.Folder)})", path, bytes, allFiles, limits, ref total);
        }
        if (unreadable > 10) notes.Add($"{unreadable - 10} more files unreadable");
        if (!allFiles && entries.Count > items.Count) notes.Add($"{entries.Count - items.Count} of {entries.Count} files not extracted (not binaries or packages; allFiles extracts every file).");
        return new ContainerContents("cabinet", items, notes) { Entries = entries };
    }
}
