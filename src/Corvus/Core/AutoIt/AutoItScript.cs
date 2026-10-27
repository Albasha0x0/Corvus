using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace Corvus.Core.AutoIt;

/// <summary>One record of a compiled AutoIt script: its type string, the path stored with it, sizes and file times.</summary>
public sealed record AutoItRecord(string Type, string Path, bool Compressed, long StoredSize, long Size, DateTime? Created, DateTime? Written, byte[]? Data);

/// <summary>Compiled AutoIt scripts (.a3x or embedded; EA05 and EA06): the script text and its FileInstall files.</summary>
/// <remarks>EA05 is AutoIt 3.2.4 and earlier, EA06 3.2.6 and later; EA06 text is rebuilt from tokens, so comments and layout are lost.</remarks>
public static class AutoItScript
{
    public const string Kind = "AutoIt compiled script";
    private static readonly byte[] Magic = [0xA3, 0x48, 0x4B, 0xBE, 0x98, 0x6C, 0x4A, 0xA9, 0x99, 0x4C, 0x53, 0x0A, 0x86, 0xD6, 0x48, 0x7D];
    private const string ScriptTokens = ">>>AUTOIT SCRIPT<<<", ScriptUnicode = ">AUTOIT UNICODE SCRIPT<", ScriptAnsi = ">AUTOIT SCRIPT<", NoExecute = ">>>AUTOIT NO CMDEXECUTE<<<";

    // Per-layout constants: the record tag key, the string length and key pairs, the size, checksum and data keys.
    private sealed record Layout(bool Unicode, uint Tag, (uint Length, uint Key) TypeKey, (uint Length, uint Key) PathKey, uint SizeKey, uint CrcKey, uint DataKey);

    private static readonly Layout Ea05 = new(false, 0x16FA, (0x29BC, 0xA25E), (0x29AC, 0xF25E), 0x45AA, 0xC3D2, 0x22AF);
    private static readonly Layout Ea06 = new(true, 0x18EE, (0xADBC, 0xB33F), (0xF820, 0xF479), 0x87BC, 0xA685, 0x2477);

    /// <summary>The offset of the script data (the 16-byte marker, then AU3!EA05 or AU3!EA06), or -1.</summary>
    public static int Find(ReadOnlySpan<byte> data)
    {
        for (int at = 0; at <= data.Length - 24;)
        {
            int i = data[at..].IndexOf(Magic);
            if (i < 0) return -1;
            at += i;
            if (data.Slice(at + 16, 7).SequenceEqual("AU3!EA0"u8) && data[at + 23] is (byte)'5' or (byte)'6') return at;
            at++;
        }
        return -1;
    }

    public static bool Looks(ReadOnlySpan<byte> data) => data.Length >= 24 && Find(data[..24]) == 0;

    /// <summary>The records in file order and the layout name ("EA05" or "EA06"). Throws InvalidDataException on damage.</summary>
    public static (string Layout, List<AutoItRecord> Records) Read(byte[] data, int at, long maxItemBytes, CancellationToken ct = default)
    {
        bool ea05 = data[at + 23] == (byte)'5';
        var layout = ea05 ? Ea05 : Ea06;
        int p = at + 24;
        var head = Take(data, ref p, 16);
        // EA05 keys the data with the sum of the 16 bytes after the marker; EA06 does not.
        uint seed = 0;
        if (ea05) foreach (byte b in head) seed += b;
        var records = new List<AutoItRecord>();
        while (p + 4 <= data.Length)
        {
            ct.ThrowIfCancellationRequested();
            var tag = Decrypt(ea05, data.AsSpan(p, 4), layout.Tag);
            if (!tag.AsSpan().SequenceEqual("FILE"u8)) break;
            p += 4;
            string type = String(data, ref p, layout, layout.TypeKey, ea05);
            string path = String(data, ref p, layout, layout.PathKey, ea05);
            int compressed = Take(data, ref p, 1)[0];
            uint stored = U32(data, ref p) ^ layout.SizeKey;
            if (type == NoExecute)
            {
                // A marker record: its size, checksum and times are skipped with its data, unread.
                Take(data, ref p, (long)stored + 0x18);
                records.Add(new AutoItRecord(type, path, compressed == 1, stored, 0, null, null, null));
                continue;
            }
            uint size = U32(data, ref p) ^ layout.SizeKey;
            uint crc = U32(data, ref p) ^ layout.CrcKey;
            var created = FileTime(data, ref p);
            var written = FileTime(data, ref p);
            var content = Decrypt(ea05, Take(data, ref p, stored), unchecked(seed + layout.DataKey));
            if (Ark.ArkFile.Adler32(content) != crc) throw new InvalidDataException($"record {records.Count} ({type}) fails its Adler-32 check");
            if (compressed == 1) content = Decompress(content, maxItemBytes);
            records.Add(new AutoItRecord(type, path, compressed == 1, stored, compressed == 1 ? content.Length : size, created, written, content));
        }
        if (records.Count == 0) throw new InvalidDataException("no record follows the script marker");
        return (ea05 ? "EA05" : "EA06", records);
    }

    public static ContainerContents Open(byte[] data, int at, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        string layoutName;
        List<AutoItRecord> records;
        try { (layoutName, records) = Read(data, at, limits.MaxItemBytes, ct); }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{name}: not a readable compiled AutoIt script: {ex.Message}"); }
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var notes = new List<string>();
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long total = 0;
        foreach (var r in records)
        {
            string detail = $"{r.Type}; stored as {r.Path}" + (r.Compressed ? $"; {r.StoredSize:N0} bytes compressed" : "") + (r.Written is { } w ? $"; written {w:yyyy-MM-dd HH:mm:ss} UTC" : "");
            if (r.Data == null) { entries.Add(new ContainerEntry(r.Type, r.StoredSize, detail)); continue; }
            string itemName;
            byte[] bytes;
            string origin;
            switch (r.Type)
            {
                case ScriptTokens:
                    var script = Detokenize(r.Data);
                    if (script.Problem != null) notes.Add($"The script is listed up to line {script.Lines.Count + 1}: {script.Problem}.");
                    bytes = Encoding.UTF8.GetBytes(Render(script.Lines));
                    itemName = "script.au3";
                    origin = "script rebuilt from its tokens";
                    break;
                case ScriptUnicode or ScriptAnsi:
                    bytes = Encoding.UTF8.GetBytes(r.Type == ScriptUnicode ? Encoding.Unicode.GetString(r.Data).TrimStart('﻿') : Encoding.Latin1.GetString(r.Data));
                    itemName = "script.au3";
                    origin = "script source";
                    break;
                default:
                    itemName = "files/" + RelativeName(r.Type);
                    bytes = r.Data;
                    origin = "FileInstall file";
                    break;
            }
            for (int n = 2; !used.Add(itemName); n++) itemName = $"{Path.ChangeExtension(itemName, null)}~{n}{Path.GetExtension(itemName)}";
            entries.Add(new ContainerEntry(itemName, bytes.Length, detail));
            if (origin == "FileInstall file" && !(allFiles || Containers.IsInteresting(itemName))) continue;
            if (items.Count >= limits.MaxItems || (total += bytes.Length) > limits.MaxTotalBytes) { notes.Add("Stopped: the extraction limit was reached."); break; }
            items.Add(new ExtractedItem(itemName, bytes, origin));
        }
        int files = records.Count(r => r.Data != null && r.Type is not (ScriptTokens or ScriptUnicode or ScriptAnsi));
        notes.Insert(0, $"{Kind} ({layoutName}, AutoIt {(layoutName == "EA05" ? "3.2.4 or earlier" : "3.2.6 or later")}) at 0x{at:X}: {records.Count} record(s), " +
            $"{files} FileInstall file(s)" + (records.Any(r => r.Type == ScriptTokens) ? "; the script is rebuilt from tokens, without its comments and layout." : "."));
        return new ContainerContents(Kind, items, notes) { Entries = entries };
    }

    // A FileInstall source path, kept relative: drive and leading separators dropped, separators as '/'.
    private static string RelativeName(string path)
    {
        var parts = path.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries).Where(s => s is not ("." or "..") && !s.EndsWith(':')).ToArray();
        return parts.Length > 0 ? string.Join('/', parts) : "file";
    }

    private static string String(byte[] d, ref int p, Layout layout, (uint Length, uint Key) key, bool ea05)
    {
        uint length = U32(d, ref p) ^ key.Length;
        long bytes = layout.Unicode ? 2L * length : length;
        var plain = Decrypt(ea05, Take(d, ref p, bytes), unchecked(length + key.Key));
        return layout.Unicode ? Encoding.Unicode.GetString(plain) : Encoding.Latin1.GetString(plain);
    }

    private static DateTime? FileTime(byte[] d, ref int p)
    {
        // The high half is written first.
        long t = (long)((ulong)U32(d, ref p) << 32 | U32(d, ref p));
        return t > 0 && t < DateTime.MaxValue.ToFileTimeUtc() ? DateTime.FromFileTimeUtc(t) : null;
    }

    private static uint U32(byte[] d, ref int p) => BinaryPrimitives.ReadUInt32LittleEndian(Take(d, ref p, 4));

    private static ReadOnlySpan<byte> Take(byte[] d, ref int p, long n)
    {
        if (n < 0 || p > d.Length - n) throw new InvalidDataException($"{n:N0} bytes at 0x{p:X} run past the data");
        var s = d.AsSpan(p, (int)n);
        p += (int)n;
        return s;
    }

    private static byte[] Decrypt(bool ea05, ReadOnlySpan<byte> data, uint seed)
    {
        var o = data.ToArray();
        if (ea05) Twister(o, seed);
        else Lame(o, seed);
        return o;
    }

    // EA06 key stream: a lagged generator of 17 words; each byte is the top byte of every second output.
    private static void Lame(byte[] data, uint seed)
    {
        Span<uint> state = stackalloc uint[17];
        for (int i = 0; i < 17; i++) state[i] = seed = unchecked(1 - seed * 0x53A9B4FB);
        int c0 = 0, c1 = 10;
        uint Next(Span<uint> s)
        {
            uint v = unchecked(uint.RotateLeft(s[c0], 9) + uint.RotateLeft(s[c1], 13));
            s[c0] = v;
            c0 = c0 == 0 ? 16 : c0 - 1;
            c1 = c1 == 0 ? 16 : c1 - 1;
            return v;
        }
        for (int i = 0; i < 9; i++) Next(state);
        for (int i = 0; i < data.Length; i++)
        {
            Next(state);
            data[i] ^= (byte)(Next(state) >> 24);
        }
    }

    // EA05 key stream: a Mersenne Twister with the format's own output tempering.
    private static void Twister(byte[] data, uint seed)
    {
        var mt = new uint[624];
        mt[0] = seed;
        for (uint i = 1; i < 624; i++) mt[i] = unchecked(i + 0x6C078965 * (mt[i - 1] ^ (mt[i - 1] >> 30)));
        for (int i = 0; i < data.Length; i++)
        {
            int k = i % 624;
            if (k == 0) Twist(mt);
            uint r = mt[k];
            r = ((((r >> 11) ^ r) & 0xFF3A58AD) << 7) ^ (r >> 11) ^ r;
            uint t = ((r & 0xFFFFDF8C) << 15) ^ r;
            r = (t ^ (t >> 18)) >> 1;
            data[i] ^= (byte)r;
        }
    }

    private static void Twist(uint[] s)
    {
        static uint Mix(uint a, uint b, uint into) => into ^ ((a ^ ((b ^ a) & 0x7FFFFFFE)) >> 1) ^ ((b & 1) != 0 ? 0x9908B0DFu : 0);
        for (int i = 0; i < 227; i++) s[i] = Mix(s[i], s[i + 1], s[i + 397]);
        for (int i = 0; i < 396; i++) s[227 + i] = Mix(s[i + 227], s[i + 228], s[i]);
        s[623] = Mix(s[623], s[0], s[396]);
    }

    /// <summary>Expands an EA05 or EA06 compressed block; throws InvalidDataException past <paramref name="maxBytes"/> or on damage.</summary>
    public static byte[] Decompress(ReadOnlySpan<byte> data, long maxBytes)
    {
        if (data.Length < 8) throw new InvalidDataException("a compressed record shorter than its header");
        bool ea06 = data[..4].SequenceEqual("EA06"u8);
        if (!ea06 && !data[..4].SequenceEqual("EA05"u8)) throw new InvalidDataException($"compression tag '{Encoding.Latin1.GetString(data[..4])}' is not read");
        uint size = BinaryPrimitives.ReadUInt32BigEndian(data[4..]);
        if (size > maxBytes) throw new InvalidDataException($"a record expands to {size:N0} bytes, past the {maxBytes:N0}-byte limit");
        var output = new byte[size];
        var bits = new BitReader(data[8..]);
        int literal = ea06 ? 1 : 0, o = 0;
        while (o < output.Length)
        {
            if (bits.Read(1) == literal) { output[o++] = (byte)bits.Read(8); continue; }
            int distance = bits.Read(15);
            int length = MatchLength(ref bits);
            if (distance == 0 || distance > o) throw new InvalidDataException($"a match {distance} bytes back at output {o:N0}");
            for (int i = 0; i < length && o < output.Length; i++, o++) output[o] = output[o - distance];
        }
        return output;
    }

    // Lengths grow in steps: 2 bits (3 more), 3 bits, 5 bits, then bytes; all ones moves to the next step.
    private static int MatchLength(ref BitReader bits)
    {
        ReadOnlySpan<(int Base, int Bits)> steps = [(3, 2), (6, 3), (13, 5), (44, 8), (299, 8)];
        foreach (var (b, n) in steps)
        {
            int v = bits.Read(n), all = (1 << n) - 1;
            if (v != all) return b + v;
        }
        int length = 299;
        while (true)
        {
            length += 255;
            int v = bits.Read(8);
            if (v != 255) return length + v;
            if (length > 1 << 30) throw new InvalidDataException("a match length past the data");
        }
    }

    private ref struct BitReader(ReadOnlySpan<byte> data)
    {
        private readonly ReadOnlySpan<byte> data = data;
        private long position;

        public int Read(int count)
        {
            if (position + count > 8L * data.Length) throw new InvalidDataException("the compressed bit stream ends early");
            int v = 0;
            for (int i = 0; i < count; i++, position++) v = (v << 1) | ((data[(int)(position >> 3)] >> (7 - (int)(position & 7))) & 1);
            return v;
        }
    }

    /// <summary>The script lines as token lists, and why reading stopped early (null when every line was read).</summary>
    public sealed record Tokens(List<List<string>> Lines, string? Problem);

    private static readonly Dictionary<string, string> KeywordNames = AutoItNames.Keywords.ToDictionary(k => k.ToUpperInvariant());
    private static readonly Dictionary<string, string> FunctionNames = AutoItNames.Functions.ToDictionary(k => k.ToUpperInvariant());
    private static readonly Dictionary<string, string> MacroNames = AutoItNames.Macros.ToDictionary(k => k[1..].ToUpperInvariant(), k => k);
    private static readonly string[] Operators = [",", "=", ">", "<", "<>", ">=", "<=", "(", ")", "+", "-", "/", "*", "&", "[", "]", "==", "^", "+=", "-=", "/=", "*=", "&=", "?", ":"];

    /// <summary>Reads an EA06 token stream; built-in names take the vendor's spelling, user names stay upper case.</summary>
    public static Tokens Detokenize(ReadOnlySpan<byte> s)
    {
        var lines = new List<List<string>>();
        if (s.Length < 4) return new Tokens(lines, "the token stream has no line count");
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(s);
        int p = 4;
        var line = new List<string>();
        try
        {
            while (lines.Count < count)
            {
                if (p >= s.Length) return new Tokens(lines, "the token stream ends early");
                byte t = s[p++];
                switch (t)
                {
                    case 0x00: line.Add($"{{keyword {I32(s, ref p)}}}"); break;
                    case 0x01: line.Add($"{{function {I32(s, ref p)}}}"); break;
                    case 0x05: line.Add(I32(s, ref p).ToString(CultureInfo.InvariantCulture)); break;
                    case 0x10: line.Add(BinaryPrimitives.ReadInt64LittleEndian(Bytes(s, ref p, 8)).ToString(CultureInfo.InvariantCulture)); break;
                    case 0x20: line.Add(Number(BinaryPrimitives.ReadDoubleLittleEndian(Bytes(s, ref p, 8)))); break;
                    case 0x30: { var k = Name(s, ref p); line.Add(KeywordNames.GetValueOrDefault(k, k)); break; }
                    case 0x31: { var f = Name(s, ref p); line.Add(FunctionNames.GetValueOrDefault(f, f)); break; }
                    case 0x32: { var m = Name(s, ref p); line.Add(MacroNames.GetValueOrDefault(m, "@" + m)); break; }
                    case 0x33: line.Add("$" + Name(s, ref p)); break;
                    case 0x34 or 0x37: line.Add(Name(s, ref p)); break;
                    case 0x35: line.Add("." + Name(s, ref p)); break;
                    case 0x36: line.Add("\"" + Name(s, ref p).Replace("\"", "\"\"") + "\""); break;
                    case >= 0x40 and <= 0x58: line.Add(Operators[t - 0x40]); break;
                    case 0x7F: lines.Add(line); line = []; break;
                    default: return new Tokens(lines, $"token 0x{t:X2} at 0x{p - 1:X} is not known");
                }
            }
        }
        catch (InvalidDataException ex) { return new Tokens(lines, ex.Message); }
        return new Tokens(lines, null);
    }

    private static ReadOnlySpan<byte> Bytes(ReadOnlySpan<byte> s, ref int p, int n)
    {
        if (p > s.Length - n) throw new InvalidDataException($"a token at 0x{p:X} runs past the stream");
        var b = s.Slice(p, n);
        p += n;
        return b;
    }

    private static int I32(ReadOnlySpan<byte> s, ref int p) => BinaryPrimitives.ReadInt32LittleEndian(Bytes(s, ref p, 4));

    // A name: a UTF-16 length, then the characters XORed with that length.
    private static string Name(ReadOnlySpan<byte> s, ref int p)
    {
        uint length = (uint)I32(s, ref p);
        if (length > (s.Length - p) / 2) throw new InvalidDataException($"a name of {length:N0} characters at 0x{p:X} runs past the stream");
        var chars = new char[length];
        var b = Bytes(s, ref p, 2 * (int)length);
        for (int i = 0; i < chars.Length; i++) chars[i] = (char)(BinaryPrimitives.ReadUInt16LittleEndian(b[(2 * i)..]) ^ (ushort)length);
        return new string(chars);
    }

    /// <summary>A float token as a decimal that reads back as the same value, with ".0" when it would read as an integer.</summary>
    public static string Number(double d)
    {
        string s = d.ToString("R", CultureInfo.InvariantCulture).Replace("E", "e");
        return s.Any(c => c is '.' or 'e' or 'N' or 'I') ? s : s + ".0";
    }

    private static readonly HashSet<string> Opens = new(StringComparer.Ordinal) { "While", "Do", "For", "Func", "With", "Switch", "Select" };
    private static readonly HashSet<string> Closes = new(StringComparer.Ordinal) { "WEnd", "Until", "Next", "EndFunc", "EndIf", "EndWith" };

    /// <summary>Token lines as source: block bodies indented by a tab, no spaces inside brackets or before a call's parenthesis.</summary>
    public static string Render(List<List<string>> lines)
    {
        var sb = new StringBuilder();
        var blocks = new Stack<string>();
        foreach (var line in lines)
        {
            string first = line.Count > 0 ? line[0] : "";
            if (Closes.Contains(first) && blocks.Count > 0) blocks.Pop();
            else if (first is "EndSwitch" or "EndSelect")
            {
                if (blocks.TryPeek(out var top) && top == "Case") blocks.Pop();
                if (blocks.Count > 0) blocks.Pop();
            }
            else if (first is "Else" or "ElseIf" && blocks.Count > 0) blocks.Pop();
            else if (first == "Case" && blocks.TryPeek(out var top) && top == "Case") blocks.Pop();
            sb.Append('\t', blocks.Count);
            for (int i = 0; i < line.Count; i++)
            {
                string t = line[i];
                if (i > 0 && Spaced(line[i - 1], t)) sb.Append(' ');
                sb.Append(t);
            }
            sb.Append("\r\n");
            if (Opens.Contains(first)) blocks.Push(first);
            else if (first is "If" or "ElseIf" or "Else" && (first == "Else" || line[^1] == "Then")) blocks.Push("If");
            else if (first == "Case") blocks.Push("Case");
        }
        return sb.ToString();
    }

    private static bool Spaced(string before, string token)
    {
        if (token is ")" or "]" or "," || before is "(" or "[") return false;
        if (token.StartsWith('.') && token.Length > 1) return false;
        if (token == "(" && (char.IsLetterOrDigit(before[^1]) || before[^1] == '_') && !KeywordNames.ContainsKey(before.ToUpperInvariant())) return false;
        if (token == "[" && (before.StartsWith('$') || before == "]" || before.StartsWith('.'))) return false;
        return true;
    }
}
