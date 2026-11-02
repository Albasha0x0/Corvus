using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Corvus.Core.Disks;
using SharpCompress.Common;
using SharpCompress.Readers;

namespace Corvus.Core.Archives;

/// <summary>
/// An image saved as a tar (docker save, or an OCI image layout): its
/// configuration, history, and the files and whiteouts of each layer.
/// </summary>
internal static class ContainerImage
{
    private const int MaxJsonBytes = 4 << 20;

    private const int MaxIndexDepth = 4;

    private const string WhiteoutPrefix = ".wh.";

    private const string OpaqueMarker = ".wh..wh..opq";

    private sealed record TarRecord(string Name, long Offset, long Size);

    private sealed record Layer(string Path, string? MediaType, string? Digest);

    private sealed record Image(string Name, string? Config, List<Layer> Layers);

    /// <summary>The kind, listing and notes of the image; null when the tar holds no readable image manifest.</summary>
    internal sealed record Listing(string Kind, List<ContainerEntry> Entries, List<string> Notes);

    /// <summary>Whether the entries name a docker save manifest or an OCI layout at the top level.</summary>
    public static bool Looks(IEnumerable<ContainerEntry> entries)
    {
        var names = entries.Select(e => Normal(e.Path)).ToHashSet(StringComparer.Ordinal);
        return names.Contains("manifest.json") || (names.Contains("oci-layout") && names.Contains("index.json"));
    }

    /// <summary>Reads the image in a seekable plain tar; null when no manifest lists an image, with the layers it cannot read named in the notes.</summary>
    public static Listing? Read(Stream tar, AnalysisLimits limits, CancellationToken ct)
    {
        var notes = new List<string>();
        var records = Index(tar, limits, notes, ct);
        var byName = new Dictionary<string, TarRecord>(StringComparer.Ordinal);
        foreach (var r in records) byName[r.Name] = r;

        JsonDocument? Json(string path)
        {
            if (!byName.TryGetValue(path, out var r)) return null;
            if (r.Size > MaxJsonBytes)
            {
                notes.Add($"{path}: {r.Size:N0} bytes, over the {MaxJsonBytes:N0}-byte limit for a manifest or configuration; not read.");
                return null;
            }
            var bytes = new byte[r.Size];
            tar.Position = r.Offset;
            tar.ReadExactly(bytes);
            try { return InputJson.ParseDocument(bytes); }
            catch (JsonException ex)
            {
                notes.Add($"{path}: not valid JSON ({ex.Message.TrimEnd('.')}).");
                return null;
            }
        }

        string kind = "";
        bool listsImages = false;
        var images = new List<Image>();
        using (var docker = Json("manifest.json"))
        {
            if (docker is { RootElement.ValueKind: JsonValueKind.Array })
            {
                kind = "docker image archive";
                listsImages = true;
                foreach (var m in docker.RootElement.EnumerateArray()) images.Add(DockerImage(m));
            }
            else
            {
                using var index = Json("index.json");
                if (index != null)
                {
                    kind = "OCI image layout";
                    listsImages = true;
                    OciImages(index.RootElement, null, Json, images, new HashSet<string>(), 0, notes);
                }
            }
        }
        if (images.Count == 0) return listsImages && notes.Count > 0 ? new Listing(kind, [], notes) : null;

        var entries = new List<ContainerEntry>();
        int listed = 0, cut = 0;
        long budget = limits.MaxTotalBytes;
        notes.Insert(0, $"{kind}: {images.Count} image(s), {records.Count:N0} entries.");
        for (int i = 0; i < images.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var image = images[i];
            string prefix = images.Count > 1 ? $"image {i + 1}/" : "";
            notes.Add($"{prefix}image: {image.Name}");
            var history = new List<JsonElement>();
            using var config = image.Config == null ? null : Json(image.Config);
            if (config == null) notes.Add($"{prefix}configuration {image.Config ?? "(not named)"}: unknown; entrypoint, environment and history are not read.");
            else Describe(config.RootElement, prefix, notes, history);

            for (int h = 0; h < history.Count; h++)
                entries.Add(new ContainerEntry($"{prefix}history/{h + 1}", 0, HistoryDetail(history[h])));

            for (int n = 0; n < image.Layers.Count; n++)
            {
                var layer = image.Layers[n];
                string label = $"{prefix}layer {n + 1}";
                if (!byName.TryGetValue(layer.Path, out var rec))
                {
                    entries.Add(new ContainerEntry(label, 0, $"{layer.Digest ?? layer.Path}; blob not in the archive; files unknown"));
                    continue;
                }
                if (layer.MediaType is { } type && !type.Contains("tar", StringComparison.Ordinal))
                {
                    entries.Add(new ContainerEntry(label, rec.Size, $"{layer.Digest ?? layer.Path}; {type}; not a file system layer"));
                    continue;
                }
                int summary = entries.Count;
                entries.Add(new ContainerEntry(label, rec.Size, layer.Digest ?? layer.Path));
                var stats = ReadLayer(tar, rec, label, entries, limits, ref budget, ref listed, ref cut, ct);
                entries[summary] = entries[summary] with { Detail = stats.Detail(layer.Digest ?? layer.Path) };
                if (stats.Note != null) notes.Add($"{label}: {stats.Note}");
            }
        }
        if (cut > 0) notes.Add(AnalysisLimits.Reached("item count", $"{limits.MaxItems:N0}-file", cut));
        return new Listing(kind, entries, notes);
    }

    private static long RecordLimit(AnalysisLimits limits) => 10L * limits.MaxItems;

    private static string Normal(string path) => path.StartsWith("./", StringComparison.Ordinal) ? path[2..] : path;

    private static List<TarRecord> Index(Stream s, AnalysisLimits limits, List<string> notes, CancellationToken ct)
    {
        var records = new List<TarRecord>();
        var block = new byte[512];
        long p = 0, length = s.Length;
        string? longName = null, paxPath = null;
        while (p + 512 <= length)
        {
            ct.ThrowIfCancellationRequested();
            s.Position = p;
            s.ReadExactly(block);
            if (Array.TrueForAll(block, b => b == 0)) break;
            long? size;
            try { size = ArchiveReader.Size(block); }
            catch (OverflowException) { size = null; }
            if (!ArchiveReader.ChecksumHolds(block) || size is not { } n || n > length - p - 512)
            {
                notes.Add($"tar header at 0x{p:X} is damaged; the entries after it are unknown.");
                break;
            }
            if (records.Count >= RecordLimit(limits))
            {
                notes.Add($"scanned {records.Count:N0} entries, then stopped at the {RecordLimit(limits):N0}-entry limit (10 times limits.MaxItems); later entries are unknown.");
                break;
            }
            byte type = block[156];
            long data = p + 512;
            if (type is (byte)'L' or (byte)'x' && n <= 65_536)
            {
                var body = new byte[n];
                s.Position = data;
                s.ReadExactly(body);
                if (type == (byte)'L') longName = Encoding.UTF8.GetString(body).TrimEnd('\0');
                else paxPath = PaxPath(body);
            }
            else if (type is 0 or (byte)'0')
            {
                records.Add(new TarRecord(Normal(longName ?? paxPath ?? ArchiveReader.Name(block, p)), data, n));
                longName = paxPath = null;
            }
            else if (type != (byte)'g') longName = paxPath = null;
            p = data + (n + 511) / 512 * 512;
        }
        return records;
    }

    private static string? PaxPath(byte[] body)
    {
        foreach (var line in Encoding.UTF8.GetString(body).Split('\n'))
        {
            int space = line.IndexOf(' ');
            if (space > 0 && line.AsSpan(space + 1).StartsWith("path=")) return line[(space + 6)..];
        }
        return null;
    }

    private static Image DockerImage(JsonElement m)
    {
        string? config = m.TryGetProperty("Config", out var c) && c.ValueKind == JsonValueKind.String ? Normal(c.GetString()!) : null;
        var tags = m.TryGetProperty("RepoTags", out var t) && t.ValueKind == JsonValueKind.Array
            ? t.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList() : [];
        var layers = m.TryGetProperty("Layers", out var l) && l.ValueKind == JsonValueKind.Array
            ? l.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => new Layer(Normal(x.GetString()!), null, null)).ToList() : [];
        return new Image(tags.Count > 0 ? string.Join(", ", tags) : config ?? "(untagged)", config, layers);
    }

    private static string BlobPath(string digest) => "blobs/" + digest.Replace(':', '/');

    private static void OciImages(JsonElement index, string? name, Func<string, JsonDocument?> json, List<Image> images, HashSet<string> seen, int depth, List<string> notes)
    {
        if (index.ValueKind != JsonValueKind.Object || !index.TryGetProperty("manifests", out var list) || list.ValueKind != JsonValueKind.Array) return;
        foreach (var d in list.EnumerateArray())
        {
            if (!d.TryGetProperty("digest", out var dg) || dg.GetString() is not { } digest) continue;
            string label = name ?? "(untagged)";
            if (d.TryGetProperty("annotations", out var a) && a.TryGetProperty("org.opencontainers.image.ref.name", out var rn) && rn.GetString() is { } refName) label = refName;
            if (d.TryGetProperty("platform", out var pl) && pl.TryGetProperty("os", out var os) && pl.TryGetProperty("architecture", out var arch))
                label += $" ({os.GetString()}/{arch.GetString()}{(pl.TryGetProperty("variant", out var v) ? "/" + v.GetString() : "")})";
            if (!seen.Add(digest)) continue;
            using var doc = json(BlobPath(digest));
            if (doc == null)
            {
                notes.Add($"{label}: manifest {digest} is not in the archive; its layers are unknown.");
                continue;
            }
            var root = doc.RootElement;
            if (root.TryGetProperty("manifests", out _))
            {
                if (depth + 1 >= MaxIndexDepth) notes.Add($"{label}: index nested more than {MaxIndexDepth} levels; not followed.");
                else OciImages(root, label, json, images, seen, depth + 1, notes);
                continue;
            }
            string? config = root.TryGetProperty("config", out var c) && c.TryGetProperty("digest", out var cd) && cd.GetString() is { } cdg ? BlobPath(cdg) : null;
            var layers = new List<Layer>();
            if (root.TryGetProperty("layers", out var ls) && ls.ValueKind == JsonValueKind.Array)
                foreach (var layer in ls.EnumerateArray())
                    if (layer.TryGetProperty("digest", out var ld) && ld.GetString() is { } ldg)
                        layers.Add(new Layer(BlobPath(ldg), layer.TryGetProperty("mediaType", out var mt) ? mt.GetString() : null, ldg));
            images.Add(new Image(label, config, layers));
        }
    }

    private static string Strings(JsonElement e) =>
        e.ValueKind == JsonValueKind.Array ? "[" + string.Join(", ", e.EnumerateArray().Select(x => x.GetRawText())) + "]" : e.GetRawText();

    private static void Describe(JsonElement root, string prefix, List<string> notes, List<JsonElement> history)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            notes.Add($"{prefix}configuration is not a JSON object: unknown; entrypoint, environment and history are not read.");
            return;
        }
        string Text(JsonElement e, string key) => e.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : "";
        string platform = $"{Text(root, "os")}/{Text(root, "architecture")}".Trim('/');
        string created = Text(root, "created");
        if (platform.Length > 0 || created.Length > 0) notes.Add($"{prefix}platform: {(platform.Length > 0 ? platform : "unknown")}; created {(created.Length > 0 ? created : "unknown")}");
        if (root.TryGetProperty("config", out var cfg) && cfg.ValueKind == JsonValueKind.Object)
        {
            foreach (var (key, label) in new[] { ("Entrypoint", "entrypoint"), ("Cmd", "cmd") })
                if (cfg.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.Array) notes.Add($"{prefix}{label}: {Strings(v)}");
            if (Text(cfg, "User") is { Length: > 0 } user) notes.Add($"{prefix}user: {user}");
            if (Text(cfg, "WorkingDir") is { Length: > 0 } dir) notes.Add($"{prefix}working directory: {dir}");
            if (cfg.TryGetProperty("Env", out var env) && env.ValueKind == JsonValueKind.Array)
                notes.Add($"{prefix}env ({env.GetArrayLength()}): " + string.Join("; ", env.EnumerateArray().Select(x => x.GetString())));
            if (cfg.TryGetProperty("ExposedPorts", out var ports) && ports.ValueKind == JsonValueKind.Object)
                notes.Add($"{prefix}exposed ports: " + string.Join(", ", ports.EnumerateObject().Select(x => x.Name)));
            if (cfg.TryGetProperty("Labels", out var labels) && labels.ValueKind == JsonValueKind.Object && labels.EnumerateObject().Any())
                notes.Add($"{prefix}labels: " + string.Join("; ", labels.EnumerateObject().Select(x => $"{x.Name}={x.Value}")));
        }
        if (root.TryGetProperty("history", out var h) && h.ValueKind == JsonValueKind.Array) history.AddRange(h.EnumerateArray().Select(x => x.Clone()));
    }

    private static string HistoryDetail(JsonElement h)
    {
        string by = h.TryGetProperty("created_by", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString()! : "(no command recorded)";
        bool empty = h.TryGetProperty("empty_layer", out var e) && e.ValueKind == JsonValueKind.True;
        return empty ? by + "; no layer" : by;
    }

    private sealed class LayerStats
    {
        public int Files, Whiteouts, Opaque, Directories;
        public string? Compression, Note;

        public string Detail(string id) =>
            $"{id}; {Compression ?? "unknown compression"}; {Files:N0} file(s), {Directories:N0} directories, {Whiteouts:N0} whiteout(s), {Opaque:N0} opaque directory marker(s)"
            + (Note != null ? "; partial" : "");
    }

    private sealed class LimitReached : IOException;

    /// <summary>Counts the bytes a layer yields once decompressed, so one layer cannot read past the call's total limit.</summary>
    private sealed class BudgetStream(Stream inner, long budget) : Stream
    {
        public long Used { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = inner.Read(buffer, offset, count);
            Used += n;
            if (Used > budget) throw new LimitReached();
            return n;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static LayerStats ReadLayer(Stream tar, TarRecord rec, string label, List<ContainerEntry> entries, AnalysisLimits limits,
        ref long budget, ref int listed, ref int cut, CancellationToken ct)
    {
        var stats = new LayerStats();
        var raw = new SubStream(tar, rec.Offset, rec.Size);
        Span<byte> magic = stackalloc byte[4];
        int got = raw.Read(magic);
        raw.Position = 0;
        Stream body;
        if (got >= 2 && magic[0] == 0x1F && magic[1] == 0x8B) { stats.Compression = "gzip"; body = new GZipStream(raw, CompressionMode.Decompress); }
        else if (got == 4 && magic.SequenceEqual((ReadOnlySpan<byte>)[0x28, 0xB5, 0x2F, 0xFD])) { stats.Compression = "zstd"; body = new ZstdSharp.DecompressionStream(raw); }
        else { stats.Compression = "none"; body = raw; }
        using var owned = body;
        var counted = new BudgetStream(body, budget);
        int seen = 0;
        try
        {
            using var reader = ReaderFactory.OpenReader(counted);
            while (reader.MoveToNextEntry())
            {
                ct.ThrowIfCancellationRequested();
                seen++;
                var e = reader.Entry;
                string key = Normal((e.Key ?? "").Replace('\\', '/')).TrimEnd('/');
                if (e.IsDirectory) { stats.Directories++; continue; }
                int slash = key.LastIndexOf('/');
                string leaf = key[(slash + 1)..], dir = slash < 0 ? "" : key[..slash];
                string? detail = null;
                long size = e.Size;
                if (leaf == OpaqueMarker)
                {
                    stats.Opaque++;
                    size = 0;
                    detail = $"opaque directory: hides /{dir} of the lower layers";
                }
                else if (leaf.StartsWith(WhiteoutPrefix, StringComparison.Ordinal))
                {
                    stats.Whiteouts++;
                    size = 0;
                    detail = $"whiteout: removes /{(dir.Length > 0 ? dir + "/" : "")}{leaf[WhiteoutPrefix.Length..]} of the lower layers";
                }
                else
                {
                    stats.Files++;
                    if (e.LinkTarget is { Length: > 0 } link) detail = $"link to {link}";
                }
                if (listed >= limits.MaxItems) { cut++; continue; }
                listed++;
                entries.Add(new ContainerEntry($"{label}/{key}", size, detail));
            }
            // Drain the stream, then check the gzip trailer's length: a truncated
            // layer ends without an error otherwise.
            counted.CopyTo(Stream.Null);
            if (stats.Compression == "gzip" && rec.Size >= 4)
            {
                Span<byte> trailer = stackalloc byte[4];
                raw.Position = rec.Size - 4;
                raw.ReadExactly(trailer);
                if (System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(trailer) != (uint)counted.Used)
                    throw new InvalidDataException("the compressed layer ends early");
            }
        }
        catch (LimitReached)
        {
            stats.Note = AnalysisLimits.Reached("total", $"{limits.MaxTotalBytes:N0}-byte", null, label) + $" Read {seen:N0} entries; later entries are unknown.";
        }
        catch (Exception ex) when (ex is SharpCompressException or InvalidDataException or IOException or NotSupportedException or OverflowException or ZstdSharp.ZstdException)
        {
            stats.Note = $"stopped reading after {seen:N0} entries ({ex.Message.TrimEnd('.')}); later entries are unknown.";
        }
        budget -= counted.Used;
        return stats;
    }
}
