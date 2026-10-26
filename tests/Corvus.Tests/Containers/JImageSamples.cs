using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Corvus.Tests;

/// <summary>
/// Writes Java runtime images as jlink lays them out (ImageHeader, PerfectHashBuilder, ImageLocation and
/// CompressedResourceHeader in OpenJDK): header, redirect and offset tables, locations, strings, then the resources.
/// </summary>
internal sealed class JImageSamples
{
    public const uint Magic = 0xCAFEDADA;

    /// <summary>A resource or directory entry; Stored holds its bytes as written (compressed layers included), Content what they decode to.</summary>
    public sealed record Entry(string Module, string? Parent, string Base, string? Extension, byte[] Content)
    {
        public byte[]? Stored { get; init; }
        public long Preview { get; init; }
        public string Path => (Parent != null ? Parent + "/" : "") + Base + (Extension != null ? "." + Extension : "");
    }

    private readonly List<byte> _strings = [0];
    private readonly Dictionary<string, int> _offsets = new(StringComparer.Ordinal) { [""] = 0 };

    public bool BigEndian { get; init; }
    public int Minor { get; init; }

    /// <summary>The offset of <paramref name="s"/> in the strings table, adding it.</summary>
    public int String(string s)
    {
        if (_offsets.TryGetValue(s, out var at)) return at;
        at = _strings.Count;
        _strings.AddRange(ModifiedUtf8(s));
        _strings.Add(0);
        return _offsets[s] = at;
    }

    public static byte[] ModifiedUtf8(string s)
    {
        var b = new List<byte>();
        foreach (var c in s)
        {
            if (c is > '\0' and < '\u0080') b.Add((byte)c);
            else if (c < 'ࠀ') { b.Add((byte)(0xC0 | (c >> 6))); b.Add((byte)(0x80 | (c & 0x3F))); }
            else { b.Add((byte)(0xE0 | (c >> 12))); b.Add((byte)(0x80 | ((c >> 6) & 0x3F))); b.Add((byte)(0x80 | (c & 0x3F))); }
        }
        return [.. b];
    }

    /// <summary>A layer header and its payload: the decompressor by name, the size the payload decodes to.</summary>
    public byte[] Layer(string decompressor, byte[] payload, long size)
    {
        var b = new byte[29 + payload.Length];
        Put32(b, 0, 0xCAFEFAFA);
        Put64(b, 4, payload.Length);
        Put64(b, 12, size);
        Put32(b, 20, (uint)String(decompressor));
        Put32(b, 24, uint.MaxValue);
        b[28] = 1;
        payload.CopyTo(b, 29);
        return b;
    }

    public byte[] Zip(byte[] content)
    {
        var ms = new MemoryStream();
        using (var z = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true)) z.Write(content);
        return Layer("zip", ms.ToArray(), content.Length);
    }

    /// <summary>
    /// A class file and its compact-cp form: a Utf8 kept inline, a Long (two pool slots), a Class, a name moved to the
    /// strings table and a descriptor whose class names are moved there by package and class.
    /// </summary>
    public (byte[] Original, byte[] Shared) SharedClass()
    {
        var head = new byte[] { 0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 55 };
        var tail = new byte[] { 0x00, 0x21, 0x00, 0x03, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0 };
        var o = new List<byte>(head);
        var t = new List<byte>(head);
        void Both(params byte[] b) { o.AddRange(b); t.AddRange(b); }
        void Utf8(List<byte> to, string s) { var e = ModifiedUtf8(s); to.Add(1); to.Add((byte)(e.Length >> 8)); to.Add((byte)e.Length); to.AddRange(e); }
        Both(0, 7); // count: 6 entries, the Long taking two slots
        Utf8(o, "Sample");
        Utf8(t, "Sample");
        Both(5, 1, 2, 3, 4, 5, 6, 7, 8);
        Both(7, 0, 1);
        Utf8(o, "java/lang/Object");
        t.Add(23);
        t.AddRange(Index(String("java/lang/Object")));
        Utf8(o, "(Ljava/lang/String;ILjava/util/List;)V");
        t.Add(25);
        t.AddRange(Index(String("(L;IL;)V")));
        var flow = new List<byte>();
        foreach (var s in new[] { "java/lang", "String", "java/util", "List" }) flow.AddRange(Index(String(s)));
        t.AddRange(Index(flow.Count));
        t.AddRange(flow);
        Both(tail);
        return ([.. o], Layer("compact-cp", [.. t], o.Count));
    }

    /// <summary>CompressIndexes.compress: 1 to 3 bytes with a flagged length, else 4 plain bytes.</summary>
    public static byte[] Index(int value)
    {
        int width = 32 - System.Numerics.BitOperations.LeadingZeroCount((uint)value);
        int size = Math.Min(((width + 2) >> 3) + 1, 4);
        var b = new byte[size];
        for (int i = 0; i < size; i++) b[i] = (byte)(value >> ((size - i - 1) * 8));
        if (size < 4) b[0] |= (byte)(0x80 | (size << 5));
        return b;
    }

    public byte[] Build(IReadOnlyList<Entry> entries)
    {
        int n = entries.Count;
        var names = entries.Select(FullName).ToList();
        var data = new List<byte>();
        var locations = new List<byte> { 0 }; // offset 0 marks an empty table slot
        var at = new int[n];
        for (int i = 0; i < n; i++)
        {
            var e = entries[i];
            var stored = e.Stored ?? e.Content;
            at[i] = locations.Count;
            Attribute(locations, 1, String(e.Module));
            if (e.Parent != null) Attribute(locations, 2, String(e.Parent));
            Attribute(locations, 3, String(e.Base));
            if (e.Extension != null) Attribute(locations, 4, String(e.Extension));
            Attribute(locations, 5, data.Count);
            if (e.Stored != null) Attribute(locations, 6, stored.Length);
            Attribute(locations, 7, e.Content.Length);
            if (e.Preview != 0) Attribute(locations, 8, e.Preview);
            locations.Add(0);
            data.AddRange(stored);
        }
        var (redirect, slots) = PerfectHash(names);
        var strings = _strings.ToArray();
        var index = new byte[28 + 8 * n + locations.Count + strings.Length];
        Put32(index, 0, Magic);
        Put32(index, 4, (uint)(1 << 16 | Minor));
        Put32(index, 12, (uint)n);
        Put32(index, 16, (uint)n);
        Put32(index, 20, (uint)locations.Count);
        Put32(index, 24, (uint)strings.Length);
        for (int i = 0; i < n; i++)
        {
            Put32(index, 28 + 4 * i, (uint)redirect[i]);
            Put32(index, 28 + 4 * n + 4 * slots[i], (uint)at[i]);
        }
        locations.CopyTo(index, 28 + 8 * n);
        strings.CopyTo(index, 28 + 8 * n + locations.Count);
        return [.. index, .. data];
    }

    /// <summary>The full name a lookup hashes: /module/parent/base.extension.</summary>
    public static byte[] FullName(Entry e) => ModifiedUtf8("/" + e.Module + "/" + e.Path);

    private static (int[] Redirect, int[] Slot) PerfectHash(List<byte[]> names)
    {
        int n = names.Count;
        var redirect = new int[n];
        var slot = new int[n];
        var used = new bool[n];
        var buckets = Enumerable.Range(0, n).GroupBy(i => (int)(Hash(names[i], 0x01000193) % (uint)n)).OrderByDescending(g => g.Count()).ToList();
        foreach (var bucket in buckets.Where(b => b.Count() > 1))
        {
            // A power-of-two table length takes the low bits of the hash, which no seed changes: the search is bounded.
            for (int seed = 1; ; seed++)
            {
                if (seed > 100_000) throw new InvalidOperationException($"no seed places a bucket of {bucket.Count()} names in a table of {n}");
                var places = bucket.Select(i => (int)(Hash(names[i], (uint)seed) % (uint)n)).ToList();
                if (places.Distinct().Count() != places.Count || places.Any(p => used[p])) continue;
                foreach (var (i, p) in bucket.Zip(places)) { slot[i] = p; used[p] = true; }
                redirect[bucket.Key] = seed;
                break;
            }
        }
        int free = 0;
        foreach (var bucket in buckets.Where(b => b.Count() == 1))
        {
            while (used[free]) free++;
            used[free] = true;
            slot[bucket.First()] = free;
            redirect[bucket.Key] = -1 - free;
        }
        return (redirect, slot);
    }

    public static uint Hash(byte[] name, uint seed)
    {
        foreach (var b in name) seed = (seed * 0x01000193) ^ b;
        return seed & 0x7FFFFFFF;
    }

    private static void Attribute(List<byte> to, int kind, long value)
    {
        int length = 1;
        while (length < 8 && value >> (8 * length) != 0) length++;
        to.Add((byte)(kind << 3 | (length - 1)));
        for (int i = length - 1; i >= 0; i--) to.Add((byte)(value >> (8 * i)));
    }

    private void Put32(byte[] b, int at, uint v)
    {
        if (BigEndian) BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(at), v);
        else BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(at), v);
    }

    private void Put64(byte[] b, int at, long v)
    {
        if (BigEndian) BinaryPrimitives.WriteInt64BigEndian(b.AsSpan(at), v);
        else BinaryPrimitives.WriteInt64LittleEndian(b.AsSpan(at), v);
    }

    /// <summary>A small image: two modules, a module-info class, a stored file with a non-ASCII name, zip, compact-cp and stacked resources, and /packages entries.</summary>
    public static (byte[] Image, List<Entry> Resources) Sample(bool bigEndian = false, int minor = 0)
    {
        var w = new JImageSamples { BigEndian = bigEndian, Minor = minor };
        var (cls, shared) = w.SharedClass();
        var text = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("resource text, repeated so zip has something to fold\n", 40)));
        var resources = new List<Entry>
        {
            new("app.core", null, "module-info", "class", [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 55, 0, 1]),
            new("app.core", "com/example", "Sample", "class", cls) { Stored = shared },
            new("app.core", "com/example/data", "notes", "txt", text) { Stored = w.Zip(text) },
            new("app.core", "com/example", "Shared", "class", cls) { Stored = w.Zip(shared) },
            new("app.tools", "META-INF/services", "Ünïcode", null, Encoding.UTF8.GetBytes("com.example.Tool\n")),
            new("app.tools", "com/example/tool", "Tool", "class", [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 55, 0, 2]) { Preview = minor > 0 ? 1 : 0 },
        };
        var all = new List<Entry>(resources)
        {
            new("packages", "com.example", "app.core", null, [0, 0, 0, 0, 0, 0, 0, 1]),
            new("packages", "com.example.tool", "app.tools", null, [0, 0, 0, 0, 0, 0, 0, 2]),
            new("packages", "com.example.data", "app.core", null, [0, 0, 0, 0, 0, 0, 0, 1]),
        };
        return (w.Build(all), resources);
    }
}
