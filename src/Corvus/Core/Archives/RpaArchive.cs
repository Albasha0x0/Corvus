using System.Buffers.Binary;
using System.IO.Compression;
using System.Numerics;
using System.Text;

namespace Corvus.Core.Archives;

/// <summary>
/// An RPA archive: a text line "RPA-3.0 &lt;index offset&gt; &lt;key&gt;" or "RPA-2.0 &lt;index offset&gt;",
/// file data, and at the offset a zlib stream holding a pickle of name to
/// (offset, length, prefix) lists.
/// </summary>
public static class RpaArchive
{
    /// <summary>The container kind reported for an RPA archive.</summary>
    public const string Kind = "rpa archive";
    private const int MaxLine = 96, MaxOps = 4_000_000, MaxStack = 1_000_000;

    /// <summary>True when the data starts with the "RPA-2.0 " or "RPA-3.0 " signature.</summary>
    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= 8 && b[..4].SequenceEqual("RPA-"u8) && (b[4] == '2' || b[4] == '3')
        && b[5] == '.' && b[6] == '0' && b[7] == ' ';

    /// <summary>Lists the index entries and extracts the files within <paramref name="limits"/>; a bad index is named as malformed and lists nothing.</summary>
    public static ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var notes = new List<string>();
        var items = new List<ExtractedItem>();
        ContainerContents Malformed(string why)
        {
            notes.Add($"RPA archive malformed: {why}; entries unknown.");
            return new ContainerContents(Kind, items, notes) { Entries = [] };
        }

        int eol = Array.IndexOf(data, (byte)'\n', 0, Math.Min(data.Length, MaxLine));
        if (eol < 0) return Malformed("no header line");
        var line = Encoding.ASCII.GetString(data, 0, eol).Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        bool v3 = line[0] == "RPA-3.0";
        long key = 0;
        long indexAt;
        try
        {
            if (line.Length < (v3 ? 3 : 2)) return Malformed("header line is short");
            indexAt = Convert.ToInt64(line[1], 16);
            if (v3) foreach (var k in line.Skip(2)) key ^= Convert.ToInt64(k, 16);
        }
        catch (Exception ex) when (ex is FormatException or OverflowException or ArgumentException)
        {
            return Malformed("header numbers are not hexadecimal");
        }
        if (indexAt < 0 || indexAt >= data.Length) return Malformed($"index offset 0x{indexAt:X} lies outside the file");

        object? root;
        try
        {
            var pickle = Inflate(data.AsSpan((int)indexAt), Math.Min(limits.MaxItemBytes, int.MaxValue / 2));
            root = new PickleReader(pickle, ct).Read();
        }
        catch (Exception ex) when (ex is InvalidDataException or InvalidOperationException or NotSupportedException)
        {
            return Malformed(ex.Message);
        }
        if (root is not List<KeyValuePair<object, object>> map) return Malformed("the index is not a dictionary");

        var entries = new List<ContainerEntry>();
        var names = new List<string>();
        long total = 0;
        int outside = 0, odd = 0;
        bool stopped = false;
        foreach (var (k, v) in map)
        {
            ct.ThrowIfCancellationRequested();
            string path = k is string s ? s : k is byte[] kb ? Encoding.UTF8.GetString(kb) : "";
            var tuple = v is List<object> { Count: > 0 } list ? list[0] : v;
            if (path.Length == 0 || tuple is not object[] t || t.Length < 2 || t[0] is not BigInteger o || t[1] is not BigInteger l)
            {
                odd++;
                continue;
            }
            byte[] prefix = t.Length > 2 ? t[2] switch { byte[] b => b, string ps => Encoding.Latin1.GetBytes(ps), _ => [] } : [];
            BigInteger offset = o ^ key, length = l ^ key;
            names.Add(path);
            if (offset < 0 || length < 0 || offset + length > data.Length)
            {
                outside++;
                entries.Add(new ContainerEntry(path, 0, "outside the file"));
                continue;
            }
            long size = (long)length + prefix.Length;
            entries.Add(new ContainerEntry(path, size, $"offset 0x{(long)offset:X}" + (prefix.Length > 0 ? $", {prefix.Length:N0} prefix bytes" : "")));
            if (stopped) continue;
            if (items.Count >= limits.MaxItems || total + size > limits.MaxTotalBytes) { stopped = true; continue; }
            if (size > limits.MaxItemBytes) { notes.Add($"{path}: over the per-item limit of {limits.MaxItemBytes:N0} bytes; not extracted."); continue; }
            var content = new byte[size];
            prefix.CopyTo(content, 0);
            Buffer.BlockCopy(data, (int)offset, content, prefix.Length, (int)length);
            if (!allFiles && Blob.Identify(content) == "data") continue;
            total += size;
            items.Add(new ExtractedItem(Blob.SafeRelativePath(path, "file"), content, "RPA entry") { Member = true });
        }
        notes.Insert(0, $"RPA archive {(v3 ? "3.0" : "2.0")}, {entries.Count:N0} entr(ies), index at 0x{indexAt:X}" + (v3 ? $", key 0x{key:X}." : "."));
        notes.AddRange(MemberNames.Notes(names));
        if (outside > 0) notes.Add($"{outside:N0} entr(ies) lie outside the file.");
        if (odd > 0) notes.Add($"{odd:N0} index record(s) have an unexpected shape; not listed.");
        if (stopped) notes.Add("Stopped: the extraction limit was reached.");
        return new ContainerContents(Kind, items, notes) { Entries = entries };
    }

    // Bound the inflated index, which is the one stream the archive does not size.
    private static byte[] Inflate(ReadOnlySpan<byte> packed, long limit)
    {
        using var input = new MemoryStream(packed.ToArray(), writable: false);
        using var z = new ZLibStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        var buffer = new byte[81920];
        try
        {
            int n;
            while ((n = z.Read(buffer)) > 0)
            {
                if (output.Length + n > limit) throw new IndexTooLarge(limit);
                output.Write(buffer, 0, n);
            }
        }
        catch (IndexTooLarge ex) { throw new InvalidDataException($"index inflates past {ex.Limit:N0} bytes"); }
        catch (InvalidDataException) { throw new InvalidDataException("index is not a zlib stream"); }
        return output.ToArray();
    }

    private sealed class IndexTooLarge(long limit) : Exception
    {
        public long Limit { get; } = limit;
    }

    // Reads only the opcodes the index uses; any other opcode is refused and nothing is run.
    private sealed class PickleReader(byte[] p, CancellationToken ct)
    {
        private static readonly object Mark = new();
        private readonly List<object> stack = [];
        private readonly Dictionary<int, object> memo = [];
        private int at;

        public object Read()
        {
            int ops = 0;
            while (true)
            {
                if (++ops > MaxOps) throw new InvalidDataException("index has too many opcodes");
                if ((ops & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
                byte op = Byte();
                switch ((char)op)
                {
                    case '.': return stack.Count == 1 ? stack[0] : throw new InvalidDataException("index leaves no single result");
                    case (char)0x80: Skip(1); break;
                    case (char)0x95: Skip(8); break;
                    case '}': Push(new List<KeyValuePair<object, object>>()); break;
                    case ']': Push(new List<object>()); break;
                    case ')': Push(Array.Empty<object>()); break;
                    case '(': Push(Mark); break;
                    case 'K': Push(new BigInteger(Byte())); break;
                    case 'M': Push(new BigInteger(BinaryPrimitives.ReadUInt16LittleEndian(Take(2)))); break;
                    case 'J': Push(new BigInteger(BinaryPrimitives.ReadInt32LittleEndian(Take(4)))); break;
                    case (char)0x8a: Push(new BigInteger(Take(Byte()), isUnsigned: false)); break;
                    case (char)0x8b: Push(new BigInteger(Take(Count(BinaryPrimitives.ReadUInt32LittleEndian(Take(4)))), isUnsigned: false)); break;
                    case 'I' or 'L': Push(Number(Line(), op == 'L')); break;
                    case 'U' or 'C': Push(Take(Byte()).ToArray()); break;
                    case 'T' or 'B': Push(Take(Count(BinaryPrimitives.ReadUInt32LittleEndian(Take(4)))).ToArray()); break;
                    case 'X': Push(Encoding.UTF8.GetString(Take(Count(BinaryPrimitives.ReadUInt32LittleEndian(Take(4)))))); break;
                    case (char)0x8c: Push(Encoding.UTF8.GetString(Take(Byte()))); break;
                    case 'q': memo[Byte()] = Top(); break;
                    case 'r': memo[(int)BinaryPrimitives.ReadUInt32LittleEndian(Take(4))] = Top(); break;
                    case (char)0x94: memo[memo.Count] = Top(); break;
                    case 'h': Push(Recall(Byte())); break;
                    case 'j': Push(Recall((int)BinaryPrimitives.ReadUInt32LittleEndian(Take(4)))); break;
                    case (char)0x85: Tuple(1); break;
                    case (char)0x86: Tuple(2); break;
                    case (char)0x87: Tuple(3); break;
                    case 't': Push(PopToMark().ToArray()); break;
                    case 'a': { var item = Pop(); ListOf(Top()).Add(item); break; }
                    case 'e': { var items = PopToMark(); ListOf(Top()).AddRange(items); break; }
                    case 's': { var value = Pop(); var key = Pop(); MapOf(Top()).Add(new(key, value)); break; }
                    case 'u':
                    {
                        var kv = PopToMark();
                        if (kv.Count % 2 != 0) throw new InvalidDataException("odd key and value count");
                        var map = MapOf(Top());
                        for (int i = 0; i < kv.Count; i += 2) map.Add(new(kv[i], kv[i + 1]));
                        break;
                    }
                    default: throw new InvalidDataException($"index uses opcode 0x{op:X2} at 0x{at - 1:X}, which is refused");
                }
            }
        }

        private void Push(object o)
        {
            if (stack.Count >= MaxStack) throw new InvalidDataException("index stack too deep");
            stack.Add(o);
        }

        private object Top() => stack.Count > 0 && stack[^1] != Mark ? stack[^1] : throw new InvalidDataException("empty stack");

        private object Pop()
        {
            var o = Top();
            stack.RemoveAt(stack.Count - 1);
            return o;
        }

        private List<object> PopToMark()
        {
            int m = stack.LastIndexOf(Mark);
            if (m < 0) throw new InvalidDataException("no mark");
            var items = stack.GetRange(m + 1, stack.Count - m - 1);
            stack.RemoveRange(m, stack.Count - m);
            return items;
        }

        private void Tuple(int n)
        {
            if (stack.Count < n) throw new InvalidDataException("stack too short for a tuple");
            var items = stack.GetRange(stack.Count - n, n);
            if (items.Contains(Mark)) throw new InvalidDataException("mark inside a tuple");
            stack.RemoveRange(stack.Count - n, n);
            Push(items.ToArray());
        }

        private static List<object> ListOf(object o) => o as List<object> ?? throw new InvalidDataException("append to a non-list");

        private static List<KeyValuePair<object, object>> MapOf(object o) =>
            o as List<KeyValuePair<object, object>> ?? throw new InvalidDataException("set item on a non-dictionary");

        private object Recall(int i) => memo.TryGetValue(i, out var o) ? o : throw new InvalidDataException("memo slot not set");

        private static BigInteger Number(string text, bool isLong)
        {
            if (isLong && text.EndsWith('L')) text = text[..^1];
            return BigInteger.TryParse(text, out var n) ? n : throw new InvalidDataException("bad integer text");
        }

        private byte Byte() => at < p.Length ? p[at++] : throw new InvalidDataException("index ends inside an opcode");

        private int Count(uint n) => n <= (uint)(p.Length - at) ? (int)n : throw new InvalidDataException("index ends inside a value");

        private ReadOnlySpan<byte> Take(int n)
        {
            if (n < 0 || n > p.Length - at) throw new InvalidDataException("index ends inside a value");
            var s = p.AsSpan(at, n);
            at += n;
            return s;
        }

        private void Skip(int n) => Take(n);

        private string Line()
        {
            int e = Array.IndexOf(p, (byte)'\n', at);
            if (e < 0) throw new InvalidDataException("index ends inside a value");
            var s = Encoding.ASCII.GetString(p, at, e - at);
            at = e + 1;
            return s;
        }
    }
}
