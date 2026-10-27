namespace Corvus.Core.Protobuf;

/// <summary>A descriptor found in a file: where (byte offset, or the code site that builds it) and how it was stored.</summary>
public sealed record FoundDescriptor(ProtoFile File, string Source, string Encoding, long Offset, string? Site = null);

/// <summary>Finds serialized FileDescriptorProto blobs, raw (C++, Go), Latin-1 strings (Java) or base64 strings (C#).</summary>
public static class ProtoScan
{
    private static readonly byte[] Suffix = ".proto"u8.ToArray();

    /// <summary>Most descriptors read from one blob.</summary>
    public const int MaxPerBlob = 4096;

    /// <summary>Raw descriptors in <paramref name="data"/>, in offset order; a descriptor's bytes are not searched again.</summary>
    public static List<(long Offset, ProtoFile File)> Raw(ReadOnlySpan<byte> data, CancellationToken ct = default)
    {
        var found = new List<(long, ProtoFile)>();
        int from = 0, covered = 0;
        while (found.Count < MaxPerBlob)
        {
            int hit = data[from..].IndexOf(Suffix);
            if (hit < 0) break;
            int end = from + hit + Suffix.Length;
            from = end;
            if ((found.Count & 63) == 0) ct.ThrowIfCancellationRequested();
            // 0x0A, a one- or two-byte length, then the name that ends here.
            for (int length = 7; length <= 1024 && length <= end - 2; length++)
            {
                int name = end - length;
                int start = length < 0x80 ? name - 2 : name - 3;
                if (start < covered) break;
                if (data[start] != 0x0A) continue;
                bool lengthMatches = length < 0x80 ? data[name - 1] == length : data[name - 2] == (byte)(length | 0x80) && data[name - 1] == length >> 7;
                if (!lengthMatches) continue;
                if (ProtoFile.Read(data[start..]) is { } file)
                {
                    found.Add((start, file));
                    covered = start + file.Length;
                    from = Math.Max(from, covered);
                    break;
                }
            }
        }
        return found;
    }

    /// <summary>True when a string may begin a descriptor: '\n', its name length, a name ending in ".proto" (chars as bytes).</summary>
    public static bool StartsDescriptor(string s)
    {
        if (s.Length < 9 || s[0] != '\n' || s[1] > 0x7F || s[1] < 7 || s.Length < 2 + s[1]) return false;
        return s.AsSpan(2, s[1]).EndsWith(".proto", StringComparison.Ordinal);
    }

    /// <summary>Strings whose chars are bytes (Java's descriptorData), concatenated; null when a char is above 0xFF.</summary>
    public static byte[]? Latin1(IEnumerable<string> parts)
    {
        var bytes = new List<byte>();
        foreach (var p in parts)
            foreach (var c in p)
            {
                if (c > 0xFF) return null;
                bytes.Add((byte)c);
            }
        return [.. bytes];
    }

    /// <summary>A base64 string (C#'s descriptorData) when it decodes to a descriptor.</summary>
    public static ProtoFile? Base64(string text)
    {
        if (text.Length < 12 || text[0] != 'C') return null;
        var buffer = new byte[text.Length * 3 / 4 + 3];
        if (!Convert.TryFromBase64String(text, buffer, out int written)) return null;
        return ProtoFile.Read(buffer.AsSpan(0, written));
    }
}
