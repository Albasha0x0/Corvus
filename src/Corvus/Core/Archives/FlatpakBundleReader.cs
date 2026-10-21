using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Archives;

/// <summary>
/// Flatpak single-file bundles (.flatpak, as flatpak build-bundle writes them): an OSTree static delta superblock in GVariant
/// format with its parts inline. The ref, commit and the app's metadata keys are listed; a delta from no earlier commit is
/// applied to rebuild the commit's tree, every file under its path (metadata, files/, export/).
/// </summary>
internal sealed class FlatpakBundleReader : IContainerReader
{
    public string Kind => "flatpak bundle";

    // OSTREE_STATIC_DELTA_SUPERBLOCK_FORMAT, OSTREE_COMMIT_GVARIANT_FORMAT, OSTREE_TREE_GVARIANT_FORMAT, OSTREE_STATIC_DELTA_PART_PAYLOAD_FORMAT_V0
    private const string Superblock = "(a{sv}tayay(a{sv}aya(say)sstayay)aya(uayttay)a(yaytt))";
    private const string CommitFormat = "(a{sv}aya(say)sstayay)";
    private const string TreeFormat = "(a(say)a(sayay))";
    private const string PartFormat = "(a(uuu)aa(ayay)ayay)";

    /// <summary>The metadata dictionary's first entry: key "flatpak", the bundle magic 0xE5890001 as a u32.</summary>
    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= 16 && b.StartsWith("flatpak\0"u8) && BinaryPrimitives.ReadUInt32LittleEndian(b[8..]) == 0xE5890001;

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Looks(data);

    /// <summary>Directories walked at most: trees are shared by content, so one may be reached many times.</summary>
    private const int MaxDirectories = 200_000;

    /// <summary>An object a delta wrote; a file's <see cref="Stat"/> is its uid, gid and mode as stored (big endian).</summary>
    private sealed record OstreeObject(byte Type, byte[] Stat, ReadOnlyMemory<byte> Data)
    {
        public uint Mode => Stat.Length == 12 ? BinaryPrimitives.ReadUInt32BigEndian(Stat.AsSpan(8)) : 0;
    }

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        try { return Read(data, allFiles, limits, ct); }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{name}: damaged flatpak bundle ({ex.Message})."); }
    }

    /// <summary>The superblock frames its members from the end and holds the parts inline: a streamed bundle is read whole, within the item limit.</summary>
    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        if (stream.Length > limits.MaxItemBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{name}: a {stream.Length:N0}-byte flatpak bundle is over the item limit.");
        var data = new byte[stream.Length];
        stream.Position = 0;
        stream.ReadExactly(data);
        return Open(data, name, allFiles, limits, ct);
    }

    private static ContainerContents Read(byte[] data, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var sb = GVariant.Tuple(Superblock, data);
        var meta = GVariant.Dictionary(sb[0]);
        string? Text(string key) => meta.TryGetValue(key, out var v) && v.Type == "s" ? GVariant.String(v.Value) : null;
        var commit = GVariant.Tuple(CommitFormat, sb[4]);
        var parts = GVariant.Array("(uayttay)", sb[6]);
        ulong unpacked = 0;
        foreach (var p in parts) unpacked += GVariant.U64(GVariant.Tuple("(uayttay)", p)[3]);
        // OSTree writes timestamps big endian
        var built = DateTimeOffset.FromUnixTimeSeconds((long)Math.Min(BinaryPrimitives.ReadUInt64BigEndian(Pad8(commit[5])), 253402300799UL));
        var tree = new Firmware.FsTree("flatpak bundle", allFiles, limits, ct);
        tree.Notes.Add($"flatpak bundle {Text("ref") ?? "(no ref)"}: commit {Convert.ToHexStringLower(sb[3].Span)}, built {built:yyyy-MM-dd HH:mm} UTC" +
                       (GVariant.String(commit[3]) is { Length: > 0 } subject ? $" ('{subject}')" : "") + $", OSTree static delta of {parts.Count} parts, {unpacked:N0} bytes unpacked");
        if (Text("metadata") is { } keyfile) tree.Notes.Add("metadata: " + Keys(keyfile));
        if (Text("runtime-repo") is { Length: > 0 } repo) tree.Notes.Add($"runtime repository: {repo}");
        if (sb[2].Length > 0)
        {
            tree.Notes.Add($"a delta from commit {Convert.ToHexStringLower(sb[2].Span)}: its files are rebuilt from that commit's objects, which the bundle does not hold; nothing extracted");
            return tree.Done();
        }
        var objects = Apply(parts, meta, limits, tree.Notes, ct);
        if (objects.TryGetValue(Convert.ToHexStringLower(commit[6].Span), out var root) && root.Type == 2) Walk(root, "", objects, tree, 0, new int[1]);
        else tree.Notes.Add("the commit's root directory is not among the bundle's objects");
        return tree.Done();
    }

    private static byte[] Pad8(ReadOnlyMemory<byte> b) => b.Length >= 8 ? b[..8].ToArray() : new byte[8];

    /// <summary>The keyfile's groups and keys in one line: "[Application] name=..., runtime=...; [Context] shared=...".</summary>
    private static string Keys(string keyfile)
    {
        var groups = new List<string>();
        var current = new List<string>();
        string? group = null;
        void Flush() { if (group != null) groups.Add($"[{group}] {string.Join(", ", current)}"); current.Clear(); }
        foreach (var raw in keyfile.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;
            if (line[0] == '[' && line[^1] == ']') { Flush(); group = line[1..^1]; }
            else if (line.Contains('=')) current.Add(line);
        }
        Flush();
        var text = string.Join("; ", groups);
        return text.Length > 1000 ? text[..1000] + "..." : text;
    }

    /// <summary>Each part decoded and its operations run: the objects it writes, by checksum.</summary>
    private static Dictionary<string, OstreeObject> Apply(List<ReadOnlyMemory<byte>> parts, Dictionary<string, (string Type, ReadOnlyMemory<byte> Value)> meta,
        AnalysisLimits limits, List<string> notes, CancellationToken ct)
    {
        var objects = new Dictionary<string, OstreeObject>(StringComparer.Ordinal);
        long total = 0;
        for (int i = 0; i < parts.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var header = GVariant.Tuple("(uayttay)", parts[i]);
            var key = meta.Keys.FirstOrDefault(k => k.StartsWith("deltas/", StringComparison.Ordinal) && k.EndsWith($"/{i}", StringComparison.Ordinal));
            if (key == null || meta[key].Type != "(yay)") { notes.Add($"delta part {i} is not inline: its objects are missing"); continue; }
            var inline = GVariant.Tuple("(yay)", meta[key].Value);
            byte compression = inline[0].Length > 0 ? inline[0].Span[0] : (byte)0;
            long size = (long)Math.Min(GVariant.U64(header[3]), long.MaxValue);
            if (size > limits.MaxItemBytes || (total += size) > limits.MaxTotalBytes) { notes.Add($"delta part {i}: {size:N0} bytes unpacked, over the extraction limit; not read"); continue; }
            ReadOnlyMemory<byte> payload = compression switch
            {
                0 => inline[1],
                // the header's unpacked size leaves out the payload's own framing: the item limit bounds the decode
                (byte)'x' => Firmware.FsCodec.DecodeStream("xz", inline[1].Span, limits.MaxItemBytes),
                _ => throw new InvalidDataException($"delta part {i} has compression '{(char)compression}'"),
            };
            var body = GVariant.Tuple(PartFormat, payload);
            var modes = GVariant.Array("(uuu)", body[0]).Select(m => m.ToArray()).ToList();
            var list = header[4];
            var raw = body[2];
            var ops = body[3];
            int op = 0, index = 0;
            (string Id, byte[] Stat, MemoryStream Data)? open = null;
            (byte Type, string Id) Next()
            {
                if ((index + 1) * 33 > list.Length) throw new InvalidDataException($"delta part {i} runs past its object list");
                return (list.Span[index * 33], Convert.ToHexStringLower(list.Span.Slice(index * 33 + 1, 32)));
            }
            ulong Var()
            {
                ulong v = 0;
                for (int shift = 0; shift < 64; shift += 7)
                {
                    if (op >= ops.Length) throw new InvalidDataException("an operation runs past the end");
                    byte b = ops.Span[op++];
                    v |= (ulong)(b & 0x7F) << shift;
                    if (b < 0x80) return v;
                }
                throw new InvalidDataException("an operand is too long");
            }
            ReadOnlyMemory<byte> Slice(ulong offset, ulong length) =>
                offset <= (ulong)raw.Length && length <= (ulong)raw.Length - offset ? raw.Slice((int)offset, (int)length) : throw new InvalidDataException("an operation reads past the part's data");
            byte[] Stat()
            {
                ulong m = Var();
                Var(); // extended attributes
                return m < (ulong)modes.Count ? modes[(int)m] : throw new InvalidDataException("an operation names a mode the part does not hold");
            }
            while (op < ops.Length)
            {
                ct.ThrowIfCancellationRequested();
                switch ((char)ops.Span[op++])
                {
                    case 'S':
                        var (type, id) = Next();
                        if (type == 1)
                        {
                            var stat = Stat();
                            ulong length = Var();
                            objects[id] = new OstreeObject(type, stat, Slice(Var(), length));
                        }
                        else
                        {
                            ulong length = Var();
                            objects[id] = new OstreeObject(type, [], Slice(Var(), length));
                        }
                        index++;
                        break;
                    case 'o':
                        var (_, openId) = Next();
                        var openStat = Stat();
                        Var(); // content size
                        open = (openId, openStat, new MemoryStream());
                        break;
                    case 'w':
                        if (open is not { } o) throw new InvalidDataException("a write with no object open");
                        ulong writeLength = Var();
                        var chunk = Slice(Var(), writeLength);
                        if (o.Data.Length + chunk.Length > limits.MaxItemBytes) throw new InvalidDataException("an object grows past the item limit");
                        o.Data.Write(chunk.Span);
                        break;
                    case 'c':
                        if (open is not { } c) throw new InvalidDataException("a close with no object open");
                        objects[c.Id] = new OstreeObject(1, c.Stat, c.Data.ToArray());
                        open = null;
                        index++;
                        break;
                    case 'r' or 'R' or 'B':
                        notes.Add($"delta part {i} copies from objects of an earlier commit: the rest of the part is not read");
                        op = ops.Length;
                        break;
                    case var unknown:
                        throw new InvalidDataException($"unknown delta operation 0x{(byte)unknown:X2}");
                }
            }
        }
        int mismatched = objects.Count(o => Checksum(o.Value) != o.Key);
        notes.Add(mismatched == 0 ? $"{objects.Count:N0} objects, each matching its SHA-256 checksum" : $"{mismatched:N0} of {objects.Count:N0} objects do not match their SHA-256 checksum");
        return objects;
    }

    /// <summary>
    /// An object's OSTree checksum: a metadata object's SHA-256; a file's over its header (uid, gid, mode, rdev, link target,
    /// no extended attributes, as a GVariant (uuuusa(ayay)) after its big-endian length and 4 zero bytes) and its content.
    /// </summary>
    private static string Checksum(OstreeObject o)
    {
        if (o.Type != 1) return Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(o.Data.Span));
        bool link = (o.Mode & 0xF000) == 0xA000;
        var target = link ? o.Data.Span : [];
        int body = 16 + target.Length + 1, size = body + 1 <= 0xFF ? 1 : 2;
        var header = new byte[8 + body + size];
        BinaryPrimitives.WriteUInt32BigEndian(header, (uint)(body + size));
        o.Stat.CopyTo(header, 8);
        target.CopyTo(header.AsSpan(8 + 16));
        if (size == 1) header[^1] = (byte)body;
        else BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(header.Length - 2), (ushort)body);
        using var sha = System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
        sha.AppendData(header);
        if (!link) sha.AppendData(o.Data.Span);
        return Convert.ToHexStringLower(sha.GetHashAndReset());
    }

    private static void Walk(OstreeObject dir, string path, Dictionary<string, OstreeObject> objects, Firmware.FsTree tree, int depth, int[] walked)
    {
        if (depth > Firmware.FsTree.MaxDepth) { tree.Notes.Add($"{path}: nested deeper than {Firmware.FsTree.MaxDepth} directories; not read"); return; }
        if (++walked[0] > MaxDirectories) throw new InvalidDataException($"more than {MaxDirectories:N0} directories");
        var t = GVariant.Tuple(TreeFormat, dir.Data);
        foreach (var file in GVariant.Array("(say)", t[0]))
        {
            tree.Token.ThrowIfCancellationRequested();
            var f = GVariant.Tuple("(say)", file);
            var name = GVariant.String(f[0]);
            if (!Firmware.FsTree.UsableName(name)) continue;
            var child = path + name;
            if (!objects.TryGetValue(Convert.ToHexStringLower(f[1].Span), out var o) || o.Type != 1) { tree.Notes.Add($"{child}: its object is not in the bundle"); continue; }
            var bytes = o.Data;
            if ((o.Mode & 0xF000) == 0xA000) tree.Link(child, Encoding.UTF8.GetString(bytes.Span));
            else if ((o.Mode & 0xF000) == 0x8000) tree.File(child, bytes.Length, n => bytes[..(int)n].ToArray());
        }
        foreach (var sub in GVariant.Array("(sayay)", t[1]))
        {
            var d = GVariant.Tuple("(sayay)", sub);
            var name = GVariant.String(d[0]);
            var id = Convert.ToHexStringLower(d[1].Span);
            if (!Firmware.FsTree.UsableName(name)) continue;
            if (!objects.TryGetValue(id, out var o) || o.Type != 2) { tree.Notes.Add($"{path}{name}/: its directory object is not in the bundle"); continue; }
            Walk(o, path + name + "/", objects, tree, depth + 1, walked);
        }
    }
}
