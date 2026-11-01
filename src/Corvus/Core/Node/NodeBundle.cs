using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.Json;

namespace Corvus.Core.Node;

/// <summary>Lists the payload of a SEA, pkg, nexe, Bun or Deno executable.</summary>
public static class NodeBundle
{
    private static readonly byte[] SeaFuse = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2"u8.ToArray();
    private static readonly byte[] SeaMagic = [0x20, 0xDA, 0x43, 0x01];
    private static readonly byte[] NexeSentinel = "<nexe~~sentinel>"u8.ToArray();
    private static readonly byte[] BunMarker = "\n---- Bun! ----\n"u8.ToArray();
    private static readonly byte[] DenoMagic = "d3n0l4nd"u8.ToArray();
    private static readonly byte[] PkgMarker = "PAYLOAD_POSITION = '"u8.ToArray();

    /// <summary>Whether a native image carries a marker of one of the five formats.</summary>
    public static bool Accepts(ReadOnlySpan<byte> data)
    {
        if (Blob.Identify(data) is not ("native PE" or "elf" or "mach-o")) return false;
        return BunTrailer(data) >= 0 || NexeTrailer(data) >= 0 || DenoTrailer(data) >= 0
            || data.IndexOf(SeaFuse) >= 0 || data.IndexOf(PkgMarker) >= 0;
    }

    /// <summary>The payload as a container; kind is "none" when none is found, with a note.</summary>
    public static ContainerContents Open(byte[] data, AnalysisLimits limits, CancellationToken ct)
    {
        var sink = new Sink(limits, ct);
        string kind;
        if (BunBundle(data, sink)) kind = "Bun executable";
        else if (DenoBundle(data, sink)) kind = "Deno executable";
        else if (NexeBundle(data, sink)) kind = "nexe executable";
        else if (PkgBundle(data, sink)) kind = "pkg executable";
        else if (SeaBundle(data, sink)) kind = "Node SEA executable";
        else
        {
            sink.Notes.Add($"No bundled application found: scanned {data.Length:N0} bytes for a SEA blob, pkg prelude, nexe, Bun and Deno trailer; a payload kept in a separate file is unknown.");
            kind = "none";
        }
        return new ContainerContents(kind, sink.Items, sink.Notes) { Entries = sink.Entries };
    }

    private sealed class Sink(AnalysisLimits limits, CancellationToken ct)
    {
        public readonly List<ExtractedItem> Items = [];
        public readonly List<ContainerEntry> Entries = [];
        public readonly List<string> Notes = [];
        private readonly HashSet<string> _paths = new(StringComparer.Ordinal);
        private long _total;
        private bool _full;

        public long Remaining => limits.MaxTotalBytes - _total;

        public void Add(string path, byte[] bytes, string role)
        {
            ct.ThrowIfCancellationRequested();
            var safe = Safe(path);
            path = safe;
            for (int n = 2; !_paths.Add(path); n++) path = $"{safe}-{n}";
            if (path != safe) Notes.Add($"Two entries map to {safe}; the later one is named {path}.");
            Entries.Add(new ContainerEntry(path, bytes.Length, role));
            if (_full) return;
            if (Items.Count >= limits.MaxItems || _total + bytes.Length > limits.MaxTotalBytes)
            {
                _full = true;
                Notes.Add("Stopped: the extraction limit was reached; later files are listed but not extracted.");
                return;
            }
            _total += bytes.Length;
            Items.Add(new ExtractedItem(path, bytes, role));
        }
    }

    /// <summary>A relative path without drive, root or parent segments.</summary>
    private static string Safe(string path)
    {
        var parts = path.Replace('\\', '/').Replace(":", "").Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Where(p => p is not ("." or ".."))
            .Select(p => p.TrimStart('$', '~'))
            .Where(p => p.Length > 0);
        var joined = string.Join('/', parts);
        return joined.Length > 0 ? joined : "unnamed";
    }

    private static bool Range(long offset, long length, long limit) => offset >= 0 && length >= 0 && offset <= limit && length <= limit - offset;

    private static byte[] Unpacked(byte[] bytes, long bound, Sink sink, string name)
    {
        if (bytes.Length < 2 || bytes[0] != 0x1F || bytes[1] != 0x8B) return bytes;
        try
        {
            using var gz = new GZipStream(new MemoryStream(bytes), CompressionMode.Decompress);
            using var ms = new MemoryStream();
            var buffer = new byte[81920];
            int n;
            while ((n = gz.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (ms.Length + n > bound)
                {
                    sink.Notes.Add($"pkg: expansion of {name} stopped at {bound:N0} bytes; the compressed bytes are kept.");
                    return bytes;
                }
                ms.Write(buffer, 0, n);
            }
            return ms.ToArray();
        }
        catch (InvalidDataException) { return bytes; }
    }

    private static bool SeaBundle(byte[] data, Sink sink)
    {
        int fuse = data.AsSpan().IndexOf(SeaFuse);
        if (fuse < 0) return false;
        var state = fuse + SeaFuse.Length + 1 < data.Length ? (char)data[fuse + SeaFuse.Length + 1] : '?';
        int from = 0, hits = 0;
        while (from < data.Length)
        {
            int at = data.AsSpan(from).IndexOf(SeaMagic);
            if (at < 0) break;
            at += from;
            from = at + 1;
            hits++;
            if (ReadSea(data, at, sink)) return true;
        }
        if (state == '1')
            sink.Notes.Add($"Node SEA: the fuse is set but no valid blob was found ({hits} magic hits checked in {data.Length:N0} bytes); the blob may use a layout this reader does not decode.");
        else
            sink.Notes.Add("Node runtime with no injected application: the SEA fuse is not set.");
        return true;
    }

    private static bool ReadSea(byte[] data, int at, Sink sink)
    {
        var r = new Cursor(data, at + 4);
        if (!r.U32(out var flags) || flags > 0xFF) return false;
        var probe = r;
        if (probe.U64(out var pathLength) && pathLength is > 0 and <= 4096 && pathLength > (ulong)(data.Length - probe.Position))
            return Truncated(sink, probe, "main code path");
        if (!r.Str(out var codePath) || codePath.Length is 0 or > 4096 || codePath.Any(b => b < 0x20)) return false;
        bool snapshot = (flags & 2) != 0;
        sink.Notes.Add($"Node SEA: main script {Encoding.UTF8.GetString(codePath)}, flags 0x{flags:X}{(snapshot ? ", startup snapshot" : "")}.");
        if (!r.Str(out var main)) return Truncated(sink, r, "main script");
        sink.Add(snapshot ? "sea-snapshot.bin" : "sea-main.js", main, snapshot ? "SEA startup snapshot" : "SEA main script");
        if ((flags & 4) != 0)
        {
            if (!r.Str(out var cache)) return Truncated(sink, r, "code cache");
            sink.Add("sea-code-cache.bin", cache, "SEA V8 code cache");
        }
        if ((flags & 8) != 0)
        {
            if (!r.U64(out var count) || count > 100_000) return Truncated(sink, r, "asset table");
            for (ulong i = 0; i < count; i++)
            {
                if (!r.Str(out var key) || !r.Str(out var value)) return Truncated(sink, r, $"asset {i + 1} of {count}");
                sink.Add("assets/" + Encoding.UTF8.GetString(key), value, "SEA asset");
            }
        }
        if ((flags & 16) != 0)
        {
            if (!r.U64(out var count) || count > 10_000) return Truncated(sink, r, "execution arguments");
            var args = new List<string>();
            for (ulong i = 0; i < count; i++)
            {
                if (!r.Str(out var arg)) return Truncated(sink, r, "execution arguments");
                args.Add(Encoding.UTF8.GetString(arg));
            }
            sink.Notes.Add("Node SEA execution arguments: " + string.Join(' ', args));
        }
        if ((flags & ~0x1Fu) != 0) sink.Notes.Add($"Node SEA: flag bits 0x{flags & ~0x1Fu:X} are not decoded; the blob may hold more than listed.");
        return true;
    }

    private static bool Truncated(Sink sink, Cursor r, string what)
    {
        sink.Notes.Add($"Node SEA: the blob ends inside the {what} at offset 0x{r.Position:X}; the entries before it are kept.");
        return true;
    }

    private struct Cursor(byte[] data, long position)
    {
        public long Position { get; private set; } = position;

        public bool U32(out uint value)
        {
            value = 0;
            if (!Range(Position, 4, data.Length)) return false;
            value = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan((int)Position));
            Position += 4;
            return true;
        }

        public bool U64(out ulong value)
        {
            value = 0;
            if (!Range(Position, 8, data.Length)) return false;
            value = BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan((int)Position));
            Position += 8;
            return true;
        }

        public bool Str(out byte[] value)
        {
            value = [];
            if (!U64(out var length)) return false;
            if (length > (ulong)(data.Length - Position)) { Position -= 8; return false; }
            value = data.AsSpan((int)Position, (int)length).ToArray();
            Position += (long)length;
            return true;
        }
    }

    private static long? Placeholder(byte[] data, string name)
    {
        var key = Encoding.ASCII.GetBytes(name + " = '");
        int at = data.AsSpan().IndexOf(key);
        if (at < 0) return null;
        int start = at + key.Length, end = start;
        while (end < data.Length && end - start < 20 && data[end] is >= (byte)'0' and <= (byte)'9') end++;
        return end > start && long.TryParse(Encoding.ASCII.GetString(data, start, end - start), out var v) ? v : null;
    }

    private static bool PkgBundle(byte[] data, Sink sink)
    {
        if (Placeholder(data, "PAYLOAD_POSITION") is not { } payloadAt || Placeholder(data, "PAYLOAD_SIZE") is not { } payloadSize
            || Placeholder(data, "PRELUDE_POSITION") is not { } preludeAt || Placeholder(data, "PRELUDE_SIZE") is not { } preludeSize) return false;
        if (!Range(payloadAt, payloadSize, data.Length) || !Range(preludeAt, preludeSize, data.Length))
        {
            sink.Notes.Add($"pkg: the payload (0x{payloadAt:X}, {payloadSize:N0} bytes) or prelude (0x{preludeAt:X}, {preludeSize:N0} bytes) lies outside the {data.Length:N0}-byte image; nothing extracted.");
            return true;
        }
        var prelude = data.AsSpan((int)preludeAt, (int)preludeSize);
        int tail = prelude.LastIndexOf("\n})("u8);
        var rest = tail >= 0 ? prelude[(tail + 4)..] : default;
        int brace = rest.IndexOf((byte)'{');
        if (brace < 0 || !ReadJsonValue(rest[brace..], out var table, out var used))
        {
            sink.Notes.Add("pkg: the file table could not be parsed; the prelude text is kept as an item.");
            sink.Add("pkg-prelude.js", prelude.ToArray(), "pkg prelude");
            return true;
        }
        using (table)
        {
            string? entry = null;
            var after = rest[(brace + used)..];
            int q = after.IndexOf((byte)'"');
            if (q >= 0 && ReadJsonValue(after[q..], out var e, out _)) { using (e) entry = e.RootElement.GetString(); }
            int files = 0, bad = 0;
            foreach (var file in table.RootElement.EnumerateObject())
            {
                if (file.Value.ValueKind != JsonValueKind.Object) continue;
                foreach (var part in file.Value.EnumerateObject())
                {
                    var role = part.Name switch { "1" => "pkg file content", "0" => "pkg V8 code cache", _ => null };
                    if (role == null || part.Value.ValueKind != JsonValueKind.Array || part.Value.GetArrayLength() != 2
                        || !part.Value[0].TryGetInt64(out var off) || !part.Value[1].TryGetInt64(out var len)) continue;
                    if (!Range(off, len, payloadSize)) { bad++; continue; }
                    var name = file.Name + (part.Name == "0" ? ".v8cache" : "");
                    sink.Add(name, Unpacked(data.AsSpan((int)(payloadAt + off), (int)len).ToArray(), sink.Remaining, sink, name), role);
                    files++;
                }
            }
            sink.Notes.Insert(0, $"pkg: {files:N0} snapshot files{(entry != null ? $", entry {entry}" : "")}{(bad > 0 ? $"; {bad:N0} entries lie outside the payload and are not extracted" : "")}.");
        }
        return true;
    }

    private static bool ReadJsonValue(ReadOnlySpan<byte> bytes, out JsonDocument document, out int used)
    {
        document = null!;
        used = 0;
        try
        {
            var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { AllowTrailingCommas = true });
            document = JsonDocument.ParseValue(ref reader);
            used = (int)reader.BytesConsumed;
            return true;
        }
        catch (JsonException) { return false; }
    }

    private static int NexeTrailer(ReadOnlySpan<byte> data) =>
        data.Length >= 32 && data.Slice(data.Length - 32, 16).SequenceEqual(NexeSentinel) ? data.Length - 32 : -1;

    private static bool NexeBundle(byte[] data, Sink sink)
    {
        int trailer = NexeTrailer(data);
        if (trailer < 0) return false;
        var code = BinaryPrimitives.ReadDoubleLittleEndian(data.AsSpan(trailer + 16));
        var resources = BinaryPrimitives.ReadDoubleLittleEndian(data.AsSpan(trailer + 24));
        if (!(code >= 0 && resources >= 0 && code + resources <= trailer) || code != Math.Floor(code) || resources != Math.Floor(resources))
        {
            sink.Notes.Add($"nexe: the trailer lengths ({code}, {resources}) do not fit the {data.Length:N0}-byte image; nothing extracted.");
            return true;
        }
        long codeAt = trailer - (long)resources - (long)code, resAt = trailer - (long)resources;
        var script = data.AsSpan((int)codeAt, (int)code).ToArray();
        sink.Notes.Add($"nexe: bundle {script.Length:N0} bytes, resources {(long)resources:N0} bytes.");
        sink.Add("nexe-bundle.js", script, "nexe bundle");
        int at = Encoding.UTF8.GetString(script, 0, Math.Min(script.Length, 4096)).IndexOf("process.__nexe", StringComparison.Ordinal);
        if (at < 0)
        {
            sink.Notes.Add("nexe: the settings object was not found in the first 4,096 bytes of the bundle; the resources are unknown.");
            return true;
        }
        var open = Array.IndexOf(script, (byte)'{', at);
        if (open < 0 || !ReadJsonValue(script.AsSpan(open), out var meta, out _))
        {
            sink.Notes.Add("nexe: the settings object could not be parsed; resources are not listed.");
            return true;
        }
        using (meta)
        {
            if (!meta.RootElement.TryGetProperty("resources", out var table) || table.ValueKind != JsonValueKind.Object) return true;
            foreach (var res in table.EnumerateObject())
            {
                if (res.Value.ValueKind != JsonValueKind.Array || res.Value.GetArrayLength() != 2
                    || !res.Value[0].TryGetInt64(out var off) || !res.Value[1].TryGetInt64(out var len) || !Range(off, len, (long)resources))
                {
                    sink.Notes.Add($"nexe: resource {res.Name} lies outside the resource blob; not extracted.");
                    continue;
                }
                sink.Add("resources/" + res.Name, data.AsSpan((int)(resAt + off), (int)len).ToArray(), "nexe resource");
            }
        }
        return true;
    }

    private static int BunTrailer(ReadOnlySpan<byte> data) =>
        data.EndsWith(BunMarker) ? data.Length - BunMarker.Length : -1;

    private static bool BunBundle(byte[] data, Sink sink)
    {
        int trailer = BunTrailer(data);
        if (trailer < 0) return false;
        foreach (var offsetsSize in new[] { 32, 28, 24, 20 })
        {
            long offsets = trailer - offsetsSize;
            if (offsets < 0) continue;
            var o = data.AsSpan((int)offsets, offsetsSize);
            var byteCount = BinaryPrimitives.ReadUInt64LittleEndian(o);
            var modAt = BinaryPrimitives.ReadUInt32LittleEndian(o[8..]);
            var modLen = BinaryPrimitives.ReadUInt32LittleEndian(o[12..]);
            var entryId = BinaryPrimitives.ReadUInt32LittleEndian(o[16..]);
            if (byteCount > (ulong)offsets || modLen == 0 || !Range(modAt, modLen, (long)byteCount)) continue;
            long start = offsets - (long)byteCount;
            foreach (var recordSize in new[] { 36, 32, 28 })
                if (modLen % recordSize == 0 && ReadBun(data, start, (long)byteCount, modAt, (int)modLen / recordSize, recordSize, entryId, sink)) return true;
        }
        sink.Notes.Add($"Bun: the trailer is at 0x{trailer:X} but the module table matches no known layout; the module list is unknown.");
        return true;
    }

    private static bool ReadBun(byte[] data, long start, long size, long tableAt, int count, int recordSize, uint entryId, Sink sink)
    {
        static bool Pointer(ReadOnlySpan<byte> record, int at, long size, out int off, out int len)
        {
            off = (int)BinaryPrimitives.ReadUInt32LittleEndian(record[at..]);
            len = (int)BinaryPrimitives.ReadUInt32LittleEndian(record[(at + 4)..]);
            return Range(off, len, size);
        }
        ReadOnlySpan<byte> Record(int i) => data.AsSpan((int)(start + tableAt + (long)i * recordSize), recordSize);
        var names = new List<string>();
        for (int i = 0; i < count; i++)
        {
            if (!Pointer(Record(i), 0, size, out var no, out var nl) || nl == 0 || nl > 4096) return false;
            var name = Encoding.UTF8.GetString(data, (int)(start + no), nl);
            if (name.Any(c => c < 0x20)) return false;
            names.Add(name);
        }
        sink.Notes.Add($"Bun: {count:N0} modules, entry {(entryId < count ? names[(int)entryId] : "(index out of range)")}.");
        string[] suffix = ["", "", ".map", ".jsc"];
        string[] role = ["", "Bun module source", "Bun source map", "Bun bytecode"];
        for (int i = 0; i < count; i++)
        {
            for (int p = 1; p < Math.Min(4, recordSize / 8); p++)
            {
                if (!Pointer(Record(i), p * 8, size, out var off, out var len) || len == 0) continue;
                sink.Add(names[i] + suffix[p], data.AsSpan((int)(start + off), len).ToArray(), role[p]);
            }
        }
        return true;
    }

    private static int DenoTrailer(ReadOnlySpan<byte> data)
    {
        if (data.Length < 32) return -1;
        var tail = data[^Math.Min(data.Length, 128)..];
        int at = tail.LastIndexOf(DenoMagic);
        return at < 0 ? -1 : data.Length - tail.Length + at;
    }

    private static bool DenoBundle(byte[] data, Sink sink)
    {
        int trailer = DenoTrailer(data);
        if (trailer < 0) return false;
        int fields = (data.Length - trailer - DenoMagic.Length) / 8;
        var offsets = new long[fields];
        for (int i = 0; i < fields; i++)
        {
            var v = BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(trailer + DenoMagic.Length + i * 8));
            offsets[i] = v > (ulong)trailer ? -1 : (long)v;
        }
        if (fields != 2 || offsets.Any(v => v < 0) || offsets[0] > offsets[1])
        {
            sink.Notes.Add($"Deno: the trailer holds {fields} offsets ({string.Join(", ", offsets.Select(v => v < 0 ? "invalid" : $"0x{v:X}"))}); this layout is not decoded, so the embedded modules are unknown.");
            return true;
        }
        sink.Notes.Add($"Deno: module archive at 0x{offsets[0]:X}, metadata at 0x{offsets[1]:X}; the archive is kept whole and its modules are not decoded.");
        sink.Add("deno-modules.eszip", data.AsSpan((int)offsets[0], (int)(offsets[1] - offsets[0])).ToArray(), "Deno module archive");
        sink.Add("deno-metadata.json", data.AsSpan((int)offsets[1], trailer - (int)offsets[1]).ToArray(), "Deno metadata");
        return true;
    }
}
