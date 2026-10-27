using System.Text;

namespace Corvus.Core.Pcap;

/// <summary>A QPACK decoder (RFC 9204) for one HTTP/3 endpoint; malformed input returns null, never an exception.</summary>
internal sealed class Qpack
{
    private const int MaxHeaders = 200, MaxString = 64 * 1024, MaxInstructionBuffer = 1 << 20;

    // RFC 9204 Appendix A.
    private static readonly (string Name, string Value)[] Static =
    [
        (":authority", ""),
        (":path", "/"),
        ("age", "0"),
        ("content-disposition", ""),
        ("content-length", "0"),
        ("cookie", ""),
        ("date", ""),
        ("etag", ""),
        ("if-modified-since", ""),
        ("if-none-match", ""),
        ("last-modified", ""),
        ("link", ""),
        ("location", ""),
        ("referer", ""),
        ("set-cookie", ""),
        (":method", "CONNECT"),
        (":method", "DELETE"),
        (":method", "GET"),
        (":method", "HEAD"),
        (":method", "OPTIONS"),
        (":method", "POST"),
        (":method", "PUT"),
        (":scheme", "http"),
        (":scheme", "https"),
        (":status", "103"),
        (":status", "200"),
        (":status", "304"),
        (":status", "404"),
        (":status", "503"),
        ("accept", "*/*"),
        ("accept", "application/dns-message"),
        ("accept-encoding", "gzip, deflate, br"),
        ("accept-ranges", "bytes"),
        ("access-control-allow-headers", "cache-control"),
        ("access-control-allow-headers", "content-type"),
        ("access-control-allow-origin", "*"),
        ("cache-control", "max-age=0"),
        ("cache-control", "max-age=2592000"),
        ("cache-control", "max-age=604800"),
        ("cache-control", "no-cache"),
        ("cache-control", "no-store"),
        ("cache-control", "public, max-age=31536000"),
        ("content-encoding", "br"),
        ("content-encoding", "gzip"),
        ("content-type", "application/dns-message"),
        ("content-type", "application/javascript"),
        ("content-type", "application/json"),
        ("content-type", "application/x-www-form-urlencoded"),
        ("content-type", "image/gif"),
        ("content-type", "image/jpeg"),
        ("content-type", "image/png"),
        ("content-type", "text/css"),
        ("content-type", "text/html; charset=utf-8"),
        ("content-type", "text/plain"),
        ("content-type", "text/plain;charset=utf-8"),
        ("range", "bytes=0-"),
        ("strict-transport-security", "max-age=31536000"),
        ("strict-transport-security", "max-age=31536000; includesubdomains"),
        ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
        ("vary", "accept-encoding"),
        ("vary", "origin"),
        ("x-content-type-options", "nosniff"),
        ("x-xss-protection", "1; mode=block"),
        (":status", "100"),
        (":status", "204"),
        (":status", "206"),
        (":status", "302"),
        (":status", "400"),
        (":status", "403"),
        (":status", "421"),
        (":status", "425"),
        (":status", "500"),
        ("accept-language", ""),
        ("access-control-allow-credentials", "FALSE"),
        ("access-control-allow-credentials", "TRUE"),
        ("access-control-allow-headers", "*"),
        ("access-control-allow-methods", "get"),
        ("access-control-allow-methods", "get, post, options"),
        ("access-control-allow-methods", "options"),
        ("access-control-expose-headers", "content-length"),
        ("access-control-request-headers", "content-type"),
        ("access-control-request-method", "get"),
        ("access-control-request-method", "post"),
        ("alt-svc", "clear"),
        ("authorization", ""),
        ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
        ("early-data", "1"),
        ("expect-ct", ""),
        ("forwarded", ""),
        ("if-range", ""),
        ("origin", ""),
        ("purpose", "prefetch"),
        ("server", ""),
        ("timing-allow-origin", "*"),
        ("upgrade-insecure-requests", "1"),
        ("user-agent", ""),
        ("x-forwarded-for", ""),
        ("x-frame-options", "deny"),
        ("x-frame-options", "sameorigin"),
    ];

    private readonly List<(string Name, string Value)> _entries = [];
    private readonly MemoryStream _instructions = new();
    private long _dropped, _size, _capacity;

    /// <summary>Entries ever inserted into the dynamic table.</summary>
    public long Inserts => _dropped + _entries.Count;

    /// <summary>The decoder's SETTINGS_QPACK_MAX_TABLE_CAPACITY, which bounds the table and decodes Required Insert Count.</summary>
    public long MaxCapacity { get; set; }

    /// <summary>False once an encoder instruction was malformed; the table state is then unknown.</summary>
    public bool Healthy { get; private set; } = true;

    /// <summary>Applies the encoder stream bytes that complete instructions; a cut instruction waits for the next bytes.</summary>
    public void Encoder(ReadOnlySpan<byte> data)
    {
        if (!Healthy) return;
        if (_instructions.Length + data.Length > MaxInstructionBuffer) { Healthy = false; return; }
        _instructions.Write(data);
        var b = _instructions.GetBuffer().AsSpan(0, (int)_instructions.Length);
        int at = 0;
        while (at < b.Length)
        {
            int start = at;
            int done = Instruction(b, ref at);
            if (done == 0) { at = start; break; }
            if (done < 0) { Healthy = false; return; }
        }
        var rest = b[at..].ToArray();
        _instructions.SetLength(0);
        _instructions.Write(rest);
    }

    // One encoder instruction: 1 applied, 0 cut by the end of the bytes, -1 malformed.
    private int Instruction(ReadOnlySpan<byte> b, ref int at)
    {
        byte first = b[at];
        if ((first & 0x80) != 0)
        {
            // Insert with name reference: static (T set) or relative to the latest insert.
            bool isStatic = (first & 0x40) != 0;
            if (!Hpack.Integer(b, ref at, 6, out var index)) return 0;
            int r = String(b, ref at, 7, out var value);
            if (r <= 0) return r;
            string? name = isStatic ? StaticEntry(index)?.Name : Relative(index)?.Name;
            return name == null ? -1 : Insert(name, value!);
        }
        if ((first & 0x40) != 0)
        {
            int r = String(b, ref at, 5, out var name);
            if (r <= 0) return r;
            r = String(b, ref at, 7, out var value);
            return r <= 0 ? r : Insert(name!, value!);
        }
        if ((first & 0x20) != 0)
        {
            if (!Hpack.Integer(b, ref at, 5, out var capacity)) return 0;
            if (MaxCapacity > 0 && (long)capacity > MaxCapacity || capacity > 1 << 30) return -1;
            _capacity = (long)capacity;
            Evict(0);
            return 1;
        }
        if (!Hpack.Integer(b, ref at, 5, out var duplicate)) return 0;
        return Relative(duplicate) is { } e ? Insert(e.Name, e.Value) : -1;
    }

    private (string Name, string Value)? Relative(ulong index) => index >= (ulong)Inserts ? null : Absolute(Inserts - 1 - (long)index);

    private (string Name, string Value)? Absolute(long index) =>
        index >= _dropped && index < Inserts ? _entries[(int)(index - _dropped)] : null;

    private int Insert(string name, string value)
    {
        long size = name.Length + value.Length + 32;
        if (size > _capacity) return -1;
        Evict(size);
        _entries.Add((name, value));
        _size += size;
        return 1;
    }

    private void Evict(long room)
    {
        int n = 0;
        while (n < _entries.Count && _size + room > _capacity)
        {
            _size -= _entries[n].Name.Length + _entries[n].Value.Length + 32;
            n++;
        }
        _entries.RemoveRange(0, n);
        _dropped += n;
    }

    /// <summary>A field section's Required Insert Count; null when its prefix is malformed; a count past <see cref="Inserts"/> waits for encoder stream bytes.</summary>
    public long? Required(ReadOnlySpan<byte> section)
    {
        int at = 0;
        if (!Hpack.Integer(section, ref at, 8, out var encoded)) return null;
        if (encoded == 0) return 0;
        long maxEntries = MaxCapacity / 32, fullRange = 2 * maxEntries;
        if (fullRange == 0 || encoded > (ulong)fullRange) return null;
        long maxValue = Inserts + maxEntries, maxWrapped = maxValue / fullRange * fullRange;
        long required = maxWrapped + (long)encoded - 1;
        if (required > maxValue)
        {
            if (required <= fullRange) return null;
            required -= fullRange;
        }
        return required == 0 ? null : required;
    }

    /// <summary>The field lines of a whole field section, or null when it is malformed or refers to entries the table does not hold.</summary>
    public List<(string Name, string Value)>? Decode(ReadOnlySpan<byte> b)
    {
        if (Required(b) is not long required) return null;
        int at = 0;
        Hpack.Integer(b, ref at, 8, out _);
        if (at >= b.Length) return null;
        bool sign = (b[at] & 0x80) != 0;
        if (!Hpack.Integer(b, ref at, 7, out var delta) || delta > int.MaxValue) return null;
        long baseIndex = sign ? required - (long)delta - 1 : required + (long)delta;
        var headers = new List<(string, string)>();
        while (at < b.Length)
        {
            if (headers.Count >= MaxHeaders) return null;
            byte first = b[at];
            (string Name, string Value)? line;
            if ((first & 0x80) != 0)
            {
                // Indexed field line: static (T set) or relative to the base.
                bool isStatic = (first & 0x40) != 0;
                if (!Hpack.Integer(b, ref at, 6, out var index)) return null;
                line = isStatic ? StaticEntry(index) : Before(baseIndex, index);
            }
            else if ((first & 0x40) != 0)
            {
                // Literal with name reference.
                bool isStatic = (first & 0x10) != 0;
                if (!Hpack.Integer(b, ref at, 4, out var index)) return null;
                var name = isStatic ? StaticEntry(index)?.Name : Before(baseIndex, index)?.Name;
                if (name == null || String(b, ref at, 7, out var value) <= 0) return null;
                line = (name, value!);
            }
            else if ((first & 0x20) != 0)
            {
                // Literal with literal name.
                if (String(b, ref at, 3, out var name) <= 0 || String(b, ref at, 7, out var value) <= 0) return null;
                line = (name!, value!);
            }
            else if ((first & 0x10) != 0)
            {
                // Indexed with post-base index.
                if (!Hpack.Integer(b, ref at, 4, out var index)) return null;
                line = After(baseIndex, index);
            }
            else
            {
                // Literal with post-base name reference.
                if (!Hpack.Integer(b, ref at, 3, out var index)) return null;
                var name = After(baseIndex, index)?.Name;
                if (name == null || String(b, ref at, 7, out var value) <= 0) return null;
                line = (name, value!);
            }
            if (line == null) return null;
            headers.Add(line.Value);
        }
        return headers;
    }

    private (string Name, string Value)? Before(long baseIndex, ulong index) => index >= int.MaxValue ? null : Absolute(baseIndex - 1 - (long)index);

    private (string Name, string Value)? After(long baseIndex, ulong index) => index >= int.MaxValue ? null : Absolute(baseIndex + (long)index);

    private static (string Name, string Value)? StaticEntry(ulong index) => index < (ulong)Static.Length ? Static[index] : null;

    /// <summary>A string literal whose length has a <paramref name="prefix"/>-bit prefix with the Huffman flag above it: 1 read, 0 cut, -1 malformed.</summary>
    private static int String(ReadOnlySpan<byte> b, ref int at, int prefix, out string? s)
    {
        s = null;
        if (at >= b.Length) return 0;
        bool huffman = (b[at] & (1 << prefix)) != 0;
        if (!Hpack.Integer(b, ref at, prefix, out var length)) return 0;
        if (length > MaxString) return -1;
        if (length > (ulong)(b.Length - at)) return 0;
        var raw = b.Slice(at, (int)length);
        at += (int)length;
        s = huffman ? Hpack.Huffman(raw) : Encoding.Latin1.GetString(raw);
        return s == null ? -1 : 1;
    }
}
