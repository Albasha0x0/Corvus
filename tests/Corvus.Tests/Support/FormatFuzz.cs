using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Text;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>
/// Seeded mutation of a small seed file for readers that must never throw: bytes overwritten, flipped, truncated or
/// duplicated, and structural edits (an offset aimed at a sibling's target or at its own block, a count at its maximum, an
/// element of the seed's text nested many levels deep). Each read runs as one call, bounded in CPU time and in bytes
/// allocated. A failure names the iteration that reproduces it.
/// </summary>
internal static class FormatFuzz
{
    private static readonly bool Full = Environment.GetEnvironmentVariable("CORVUS_ALL_TESTS") == "1";

    /// <summary>The least iterations of an entry in the full set.</summary>
    public const int FullFloor = 200;

    /// <summary>The least iterations of an entry in the quick set.</summary>
    public const int QuickFloor = 25;

    /// <summary>
    /// The iterations an entry runs: in the full set (full.runsettings) all it
    /// asks for and at least <see cref="FullFloor"/>; in the quick set a tenth,
    /// at least <see cref="QuickFloor"/> and never more than it asks for.
    /// </summary>
    public static int Iterations(int asked, bool full) => full ? Math.Max(asked, FullFloor) : Math.Min(asked, Math.Max(QuickFloor, asked / 10));

    public static List<string> Run(byte[] seed, Action<byte[]> read, int iterations, int baseSeed = 20261011)
    {
        iterations = Iterations(iterations, Full);
        var failures = new List<string>();
        // The seed is read once first, so caches a reader fills on its first
        // call are not counted against an iteration.
        try { read(seed); }
        catch (Exception) { }
        for (int i = 0; i < iterations; i++)
        {
            var rng = new Random(unchecked(baseSeed * 1_000_003 + i));
            var bytes = Mutate(seed, rng);
            var cpu = ThreadCpuClock.Now();
            long allocated = GC.GetAllocatedBytesForCurrentThread();
            try
            {
                using var call = Spent.Enter(new Spent());
                read(bytes);
            }
            catch (Exception ex) { failures.Add($"iteration {i}: {ex.GetType().Name}: {ex.Message} (in {Where(ex)})"); }
            // A few ms each; the bound is CPU time, so a starved machine does not trip it.
            if (ThreadCpuClock.Now() - cpu is var took && took > TimeSpan.FromSeconds(2)) failures.Add($"iteration {i}: took {took.TotalSeconds:0.0} s of CPU");
            // The expansion limit's own bound: a mutated header may not buy a
            // large allocation.
            if (GC.GetAllocatedBytesForCurrentThread() - allocated is var bytesTaken && bytesTaken > AllocationBound(bytes.Length))
                failures.Add($"iteration {i}: allocated {bytesTaken:N0} bytes for a {bytes.Length:N0}-byte input");
        }
        return failures;
    }

    /// <summary>The most bytes one read of <paramref name="input"/> bytes may allocate.</summary>
    public static long AllocationBound(long input) => Spent.Floor + Spent.DefaultRatio * input;

    /// <summary>Where an exception was thrown: the pattern for a regex timeout, whose throwing method is the regex runner.</summary>
    private static string Where(Exception ex) => ex is System.Text.RegularExpressions.RegexMatchTimeoutException t
        ? $"the regex '{t.Pattern}' ({t.MatchTimeout.TotalMilliseconds:0} ms limit) on {t.Input.Length:N0} chars"
        : $"{ex.TargetSite?.DeclaringType?.FullName}.{ex.TargetSite?.Name}";

    private static byte[] Mutate(byte[] seed, Random rng)
    {
        var b = (byte[])seed.Clone();
        // Byte edits three times in four, structural edits the rest.
        int kind = rng.Next(16);
        switch (kind < 12 ? kind / 3 : kind - 8)
        {
            case 0: // a few random bytes
                for (int n = rng.Next(1, 6); n > 0 && b.Length > 0; n--) b[rng.Next(b.Length)] = (byte)rng.Next(256);
                break;
            case 1: // an extreme 32-bit value at a 4-aligned position (sizes, counts, offsets)
                if (b.Length >= 4)
                {
                    int at = rng.Next(b.Length / 4) * 4;
                    uint[] extremes = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0xFFFF, (uint)rng.Next()];
                    BitConverter.GetBytes(extremes[rng.Next(extremes.Length)]).CopyTo(b, at);
                }
                break;
            case 2: // truncation
                Array.Resize(ref b, rng.Next(b.Length + 1));
                break;
            case 3: // a block copied over another place
                if (b.Length > 8)
                {
                    int len = rng.Next(1, Math.Min(64, b.Length / 2));
                    Array.Copy(seed, rng.Next(seed.Length - len), b, rng.Next(b.Length - len), len);
                }
                break;
            case 4: // two entries naming one target
                Sibling(b, rng);
                break;
            case 5: // an entry naming the block or structure it sits in
                Parent(b, rng);
                break;
            case 6: // a count at the maximum of its field
                MaxCount(b, rng);
                break;
            default: // an element of the text nested inside itself
                return Nested(seed, rng) ?? b;
        }
        return b;
    }

    private readonly record struct Field(int At, int Width, bool Big)
    {
        public ulong Read(byte[] b)
        {
            ulong v = 0;
            for (int k = 0; k < Width; k++) v |= (ulong)b[At + (Big ? Width - 1 - k : k)] << (8 * k);
            return v;
        }

        public void Write(byte[] b, ulong v)
        {
            for (int k = 0; k < Width; k++) b[At + (Big ? Width - 1 - k : k)] = (byte)(v >> (8 * k));
        }
    }

    private static readonly int[] Widths = [2, 4, 4, 8];

    /// <summary>A field at a random position whose value passes <paramref name="keep"/>, from at most 4,096 tries; null when none does.</summary>
    private static Field? Pick(byte[] b, Random rng, int width, bool big, Func<Field, ulong, bool> keep)
    {
        if (b.Length < width) return null;
        // Mostly aligned to the field's width, sometimes anywhere (marshal
        // and bit streams).
        int step = rng.Next(4) == 0 ? 1 : width;
        for (int t = 0; t < 4096; t++)
        {
            var f = new Field(rng.Next((b.Length - width) / step + 1) * step, width, big);
            if (keep(f, f.Read(b))) return f;
        }
        return null;
    }

    private static void Sibling(byte[] b, Random rng)
    {
        int width = Widths[rng.Next(Widths.Length)];
        bool big = rng.Next(2) == 0;
        bool Offset(Field _, ulong v) => v > 0 && v < (ulong)b.Length;
        if (Pick(b, rng, width, big, Offset) is not { } to) return;
        ulong mine = to.Read(b);
        if (Pick(b, rng, width, big, (f, v) => f.At != to.At && Offset(f, v) && v != mine) is { } from) to.Write(b, from.Read(b));
    }

    private static void Parent(byte[] b, Random rng)
    {
        int width = Widths[rng.Next(Widths.Length)];
        bool big = rng.Next(2) == 0;
        if (Pick(b, rng, width, big, (_, v) => v > 0 && v < (ulong)b.Length) is not { } f) return;
        ulong target = rng.Next(3) switch
        {
            // Its own block, as a block number.
            0 => (ulong)f.At / (ulong)(512 << rng.Next(4)),
            // The start of the structure around it, as a byte offset.
            1 => (ulong)(f.At & ~((16 << rng.Next(6)) - 1)),
            // The first entry of an index (a root or the first reference).
            _ => 0,
        };
        f.Write(b, target);
    }

    private static void MaxCount(byte[] b, Random rng)
    {
        int width = rng.Next(3) switch { 0 => 1, 1 => 2, _ => 4 };
        bool big = rng.Next(2) == 0;
        if (Pick(b, rng, width, big, (_, v) => v is > 0 and <= 64) is not { } f) return;
        ulong max = width == 8 ? ulong.MaxValue : (1UL << (8 * width)) - 1;
        f.Write(b, rng.Next(2) == 0 ? max : max >> 1);
    }

    // 256 KB overflowed an unchecked folder walk (4,500 levels); more only
    // slows every reader.
    private const int MaxNesting = 50_000;
    private const int MaxNestedBytes = 1 << 18;

    /// <summary>The seed's text, and the zlib stream it sits in when a header field names that stream's length.</summary>
    private sealed record TextSite(string Text, int Start, int Length, Field? LengthField, Field? SizeField);

    private static readonly ConditionalWeakTable<byte[], TextSite[]> Sites = [];

    /// <summary>The seed with one element of its text nested inside itself many times; null when the seed holds no such text.</summary>
    private static byte[]? Nested(byte[] seed, Random rng)
    {
        var sites = Sites.GetValue(seed, FindText);
        if (sites.Length == 0) return null;
        var site = sites[rng.Next(sites.Length)];
        if (Deepen(site.Text, rng) is not { } text) return null;
        if (site.LengthField == null) return Encoding.Latin1.GetBytes(text);
        var body = new MemoryStream();
        using (var z = new ZLibStream(body, CompressionLevel.Fastest, leaveOpen: true)) z.Write(Encoding.Latin1.GetBytes(text));
        var packed = body.ToArray();
        var result = new byte[seed.Length - site.Length + packed.Length];
        seed.AsSpan(0, site.Start).CopyTo(result);
        packed.CopyTo(result, site.Start);
        seed.AsSpan(site.Start + site.Length).CopyTo(result.AsSpan(site.Start + packed.Length));
        site.LengthField.Value.Write(result, (ulong)packed.Length);
        site.SizeField?.Write(result, (ulong)text.Length);
        return result;
    }

    private static TextSite[] FindText(byte[] seed)
    {
        if (IsText(seed)) return [new TextSite(Encoding.Latin1.GetString(seed), 0, seed.Length, null, null)];
        var sites = new List<TextSite>();
        // A zlib stream in the first 4 KB whose compressed length a field in
        // the first 64 bytes names. Aligned fields come first: the low bytes
        // of a big-endian 8-byte length also read as an unaligned 4-byte one.
        for (int z = 0; z + 2 <= Math.Min(seed.Length, 4096) && sites.Count == 0; z++)
        {
            if (seed[z] != 0x78 || ((seed[z] << 8) | seed[z + 1]) % 31 != 0) continue;
            var fields = (from aligned in new[] { true, false }
                          from width in new[] { 8, 4 }
                          from big in new[] { false, true }
                          from at in Enumerable.Range(0, Math.Max(0, Math.Min(z, 64) - width + 1))
                          where (at % width == 0) == aligned
                          select new Field(at, width, big)).ToList();
            foreach (var length in fields)
            {
                ulong n = length.Read(seed);
                if (n < 8 || n > (ulong)(seed.Length - z) || Inflate(seed, z, (int)n) is not { } text || !IsText(text)) continue;
                var size = fields.FirstOrDefault(f => f.Width == length.Width && f.Big == length.Big && f.At != length.At && f.Read(seed) == (ulong)text.Length);
                sites.Add(new TextSite(Encoding.Latin1.GetString(text), z, (int)n, length, size == default ? null : size));
                break;
            }
        }
        return [.. sites];
    }

    private static byte[]? Inflate(byte[] b, int at, int length)
    {
        try
        {
            using var z = new ZLibStream(new MemoryStream(b, at, length), CompressionMode.Decompress);
            var output = new MemoryStream();
            z.CopyTo(output);
            return output.Length is > 0 and < 16 << 20 ? output.ToArray() : null;
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException) { return null; }
    }

    private static bool IsText(byte[] b)
    {
        if (b.Length < 8) return false;
        int printable = 0, n = Math.Min(b.Length, 4096);
        for (int i = 0; i < n; i++) if (b[i] is >= 0x20 and < 0x7F or (byte)'\n' or (byte)'\r' or (byte)'\t') printable++;
        return printable * 10 >= n * 9;
    }

    /// <summary>
    /// The text with one XML element holding child elements, or one bracketed span, opened many times around its content and
    /// closed as often; null when the text has neither. An element may repeat with the children before its first child
    /// element that holds children (a folder's name and type before the file inside it).
    /// </summary>
    private static string? Deepen(string text, Random rng)
    {
        var spans = new List<(int Open, int Head, int Close, int CloseEnd)>();
        var stack = new List<(string Name, int Open, int OpenEnd, bool Parent, int Head)>();
        for (int i = text.IndexOf('<'); i >= 0 && i < text.Length - 1; i = text.IndexOf('<', i + 1))
        {
            int end = text.IndexOf('>', i);
            if (end < 0) break;
            if (text[i + 1] is '?' or '!') continue;
            if (text[i + 1] == '/')
            {
                var name = text[(i + 2)..end].Trim();
                if (stack.Count == 0) continue;
                var top = stack[^1];
                stack.RemoveAt(stack.Count - 1);
                if (top.Name != name || !top.Parent) continue;
                spans.Add((top.Open, rng.Next(2) == 0 || top.Head < 0 ? top.OpenEnd : top.Head, i, end + 1));
                if (stack.Count > 0 && stack[^1].Head < 0) stack[^1] = stack[^1] with { Head = top.Open };
                continue;
            }
            if (stack.Count > 0) stack[^1] = stack[^1] with { Parent = true };
            if (text[end - 1] != '/') stack.Add((text[(i + 1)..end].Split([' ', '\t', '\r', '\n', '/'], 2)[0], i, end + 1, false, -1));
        }
        if (spans.Count == 0)
        {
            var brackets = new Stack<int>();
            for (int i = 0; i < text.Length; i++)
            {
                if (text[i] is '[' or '{' or '(') brackets.Push(i);
                else if (text[i] is ']' or '}' or ')' && brackets.TryPop(out var o)) spans.Add((o, o + 1, i, i + 1));
            }
        }
        if (spans.Count == 0) return null;
        var (open, head, close, closeEnd) = spans[rng.Next(spans.Count)];
        int unit = head - open + closeEnd - close;
        int times = Math.Max(2, Math.Min(MaxNesting, (MaxNestedBytes - text.Length) / unit));
        var sb = new StringBuilder(text.Length + times * unit);
        sb.Append(text, 0, open);
        for (int k = 0; k < times; k++) sb.Append(text, open, head - open);
        sb.Append(text, head, close - head);
        for (int k = 0; k < times; k++) sb.Append(text, close, closeEnd - close);
        sb.Append(text, closeEnd, text.Length - closeEnd);
        return sb.ToString();
    }
}
