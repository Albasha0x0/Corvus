using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core;

/// <summary>
/// A GameMaker data file (data.win, game.unx, game.ios, game.droid): a FORM of chunks. Reads the chunk inventory, the
/// GEN8 header (bytecode version, names, declared version), code entries with their argument and local counts, the
/// string table, and the embedded textures and audio, which are extracted. Code compiled to native code (YYC) leaves
/// the CODE chunk empty; that is reported.
/// </summary>
public static class GameMakerData
{
    public const string Kind = "GameMaker data file";
    private const int MaxChunks = 256, MaxListCount = 4_000_000;

    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= 16 && b.StartsWith("FORM"u8) && b.Slice(8, 4).SequenceEqual("GEN8"u8);

    public static ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        if (!Looks(data)) throw new ToolError(ErrorCode.MalformedInput, $"{name}: no GameMaker FORM header.");
        try { return Read(data, allFiles, limits, ct); }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{name}: the GameMaker data file is unreadable: {ex.Message}"); }
    }

    private static ContainerContents Read(byte[] b, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        long formEnd = 8L + U32(b, 4);
        if (formEnd > b.Length) throw new InvalidDataException($"the FORM declares {formEnd - 8:N0} bytes; the file holds {b.Length - 8:N0}");
        var chunks = new List<(string Name, int Start, int Size)>();
        for (long p = 8; p + 8 <= formEnd;)
        {
            if (chunks.Count >= MaxChunks) throw new InvalidDataException($"over {MaxChunks} chunks");
            var tag = b.AsSpan((int)p, 4);
            foreach (var c in tag) if (c is < (byte)'0' or > (byte)'Z') throw new InvalidDataException($"chunk name bytes {Convert.ToHexString(tag)} at 0x{p:X}");
            long size = U32(b, (int)p + 4);
            if (p + 8 + size > formEnd) throw new InvalidDataException($"chunk {Encoding.ASCII.GetString(tag)} at 0x{p:X} runs past the FORM");
            chunks.Add((Encoding.ASCII.GetString(tag), (int)p + 8, (int)size));
            p += 8 + size;
        }
        (int Start, int Size)? Chunk(string n) => chunks.FirstOrDefault(c => c.Name == n) is { Name: not null } c ? (c.Start, c.Size) : null;

        var gen8 = Chunk("GEN8") ?? throw new InvalidDataException("no GEN8 chunk");
        if (gen8.Size < 60) throw new InvalidDataException($"GEN8 is {gen8.Size} bytes");
        int g = gen8.Start, bytecode = b[g + 1];
        string String(int at) => ReadString(b, at);
        string gameName = String((int)U32(b, g + 40)), config = String((int)U32(b, g + 8));
        string version = $"{U32(b, g + 44)}.{U32(b, g + 48)}.{U32(b, g + 52)}.{U32(b, g + 56)}";
        string display = gen8.Size >= 104 ? String((int)U32(b, g + 100)) : "";

        var notes = new List<string>();
        var listed = new List<ContainerEntry>();
        var items = new List<ExtractedItem>();
        long total = 0;
        bool Add(string path, byte[] bytes, string origin)
        {
            if (!(allFiles || Containers.IsInteresting(path))) return true;
            if (items.Count >= limits.MaxItems || (total += bytes.Length) > limits.MaxTotalBytes) { notes.Add("Stopped: the extraction limit was reached."); return false; }
            if (bytes.Length > limits.MaxItemBytes) { notes.Add($"{path}: {bytes.Length:N0} bytes, over the per-item limit; not extracted."); return true; }
            items.Add(new ExtractedItem(path, bytes, origin));
            return true;
        }
        int Count(string n) => Chunk(n) is { Size: >= 4 } c ? List(b, c).Length : 0;

        // Strings: each pointer is to a length, then the bytes and a terminator.
        var strings = Chunk("STRG") is { Size: >= 4 } strg ? List(b, strg).Select(p => ReadString(b, p + 4)).ToArray() : [];
        listed.Add(new ContainerEntry("strings.txt", strings.Sum(s => Encoding.UTF8.GetByteCount(s) + 1), $"{strings.Length:N0} strings"));
        bool going = Add("strings.txt", Encoding.UTF8.GetBytes(string.Join('\n', strings)), "GameMaker string table");

        // Code: from bytecode 15 on, an entry names its locals and arguments and points at its bytecode; child entries
        // (functions of a script, GameMaker 2.3 on) point into their parent's bytecode.
        int codeCount = 0, yyc = 0;
        if (Chunk("CODE") is { } code)
        {
            if (code.Size == 0) yyc = 1;
            else
            {
                var roots = new Dictionary<long, string>();
                foreach (int p in List(b, code))
                {
                    ct.ThrowIfCancellationRequested();
                    Need(b, p, 8);
                    string entry = String((int)U32(b, p));
                    uint length = U32(b, p + 4);
                    string detail;
                    if (bytecode <= 14) detail = "bytecode";
                    else
                    {
                        Need(b, p, 20);
                        int locals = BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(p + 8)), args = BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(p + 10)) & 0x7FFF;
                        long address = p + 12 + BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(p + 12));
                        detail = $"bytecode, {args} argument(s), {locals} local(s)";
                        if (length > 0 && !roots.TryAdd(address, entry)) detail = $"function in {roots[address]}, offset {U32(b, p + 16)}";
                    }
                    listed.Add(new ContainerEntry($"code/{entry}", length, detail));
                    codeCount++;
                }
            }
        }

        int textures = 0;
        if (going && Chunk("TXTR") is { Size: >= 4 } txtr)
        {
            var entries = List(b, txtr);
            for (int i = 0; i < entries.Length && going; i++)
            {
                // The entry's fields grow with the version (mips, block size, dimensions); the data pointer is the field
                // that points at an image.
                int blob = -1;
                for (int f = 4; f <= 24 && entries[i] + f + 4 <= b.Length; f += 4)
                    if (U32(b, entries[i] + f) is var t and > 0 && t < b.Length - 8 && ImageFormat(b.AsSpan((int)t)) != null) { blob = (int)t; break; }
                if (blob < 0) { listed.Add(new ContainerEntry($"textures/{i}", 0, "external or unreadable texture data")); continue; }
                string format = ImageFormat(b.AsSpan(blob))!;
                int end = format == "png" ? PngEnd(b, blob) : NextStart(entries, b, blob, txtr);
                var bytes = b.AsSpan(blob, end - blob).ToArray();
                string path = $"textures/{i}.{format}";
                listed.Add(new ContainerEntry(path, bytes.Length, format == "png" ? "PNG texture page" : "GameMaker QOI texture page, not converted"));
                going = Add(path, bytes, "GameMaker embedded texture");
                textures++;
            }
        }

        int audio = 0;
        if (going && Chunk("AUDO") is { Size: >= 4 } audo)
        {
            foreach (int p in List(b, audo))
            {
                Need(b, p, 4);
                int length = (int)U32(b, p);
                Need(b, p + 4, length);
                var bytes = b.AsSpan(p + 4, length).ToArray();
                string ext = bytes.AsSpan().StartsWith("RIFF"u8) ? "wav" : bytes.AsSpan().StartsWith("OggS"u8) ? "ogg" : "bin";
                string path = $"audio/{audio++}.{ext}";
                listed.Add(new ContainerEntry(path, length, "embedded audio"));
                if (!(going = Add(path, bytes, "GameMaker embedded audio"))) break;
            }
        }

        notes.Insert(0, $"GameMaker data file, bytecode version {bytecode}, declared version {version}: {Quote(gameName)}" +
                        (display.Length > 0 && display != gameName ? $" ({Quote(display)})" : "") + $", configuration {Quote(config)}; " +
                        (yyc > 0 ? "code compiled to native code (YYC), no bytecode" : $"{codeCount:N0} code entries") +
                        $", {Count("SCPT"):N0} scripts, {Count("OBJT"):N0} objects, {Count("ROOM"):N0} rooms, {Count("SPRT"):N0} sprites, {Count("SOND"):N0} sounds, " +
                        $"{strings.Length:N0} strings, {textures:N0} textures, {audio:N0} audio.");
        notes.Insert(1, "Chunks: " + string.Join(", ", chunks.Select(c => $"{c.Name} ({c.Size:N0})")) + ".");
        return new ContainerContents(Kind, items, notes) { Entries = listed };
    }

    private static string Quote(string s) => $"\"{s}\"";

    /// <summary>The entry offsets of a pointer list (count, then offsets from the file start).</summary>
    private static int[] List(byte[] b, (int Start, int Size) chunk)
    {
        uint n = U32(b, chunk.Start);
        if (n > MaxListCount || 4L + 4L * n > chunk.Size) throw new InvalidDataException($"a list of {n:N0} entries at 0x{chunk.Start:X} runs past its chunk");
        var r = new int[n];
        for (int i = 0; i < n; i++)
        {
            uint p = U32(b, chunk.Start + 4 + 4 * i);
            if (p >= b.Length) throw new InvalidDataException($"entry {i} of the list at 0x{chunk.Start:X} points past the file");
            r[i] = (int)p;
        }
        return r;
    }

    // A string reference points at the bytes; the length sits in the four bytes before them.
    private static string ReadString(byte[] b, int at)
    {
        if (at == 0) return "";
        if (at < 4 || at > b.Length) throw new InvalidDataException($"string at 0x{at:X} lies outside the file");
        uint n = U32(b, at - 4);
        if (n > b.Length - at) throw new InvalidDataException($"string at 0x{at:X} of {n:N0} bytes runs past the file");
        return Encoding.UTF8.GetString(b, at, (int)n);
    }

    // A u8 literal would encode \x89 as two UTF-8 bytes.
    private static ReadOnlySpan<byte> PngSignature => [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    private static string? ImageFormat(ReadOnlySpan<byte> s) =>
        s.StartsWith(PngSignature) ? "png" : s.StartsWith("fioq"u8) ? "qoi" : s.StartsWith("2zoq"u8) ? "bz2qoi" : null;

    private static int PngEnd(byte[] b, int start)
    {
        for (long p = start + 8; p + 12 <= b.Length;)
        {
            long length = BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan((int)p));
            bool end = b.AsSpan((int)p + 4, 4).SequenceEqual("IEND"u8);
            p += 12 + length;
            if (p > b.Length) break;
            if (end) return (int)p;
        }
        throw new InvalidDataException($"the PNG at 0x{start:X} has no IEND chunk");
    }

    // QOI pages carry no total length here: they run to the next texture's data or the end of the chunk.
    private static int NextStart(int[] entries, byte[] b, int blob, (int Start, int Size) chunk)
    {
        int end = chunk.Start + chunk.Size;
        foreach (int e in entries)
            for (int f = 4; f <= 24 && e + f + 4 <= b.Length; f += 4)
                if (U32(b, e + f) is var t && t > blob && t < end && ImageFormat(b.AsSpan((int)t)) != null) { end = (int)t; break; }
        return end;
    }

    private static void Need(byte[] b, int at, int n)
    {
        if (at < 0 || n < 0 || at > b.Length - n) throw new InvalidDataException($"{n:N0} bytes at 0x{at:X} run past the file");
    }

    private static uint U32(byte[] b, int at)
    {
        Need(b, at, 4);
        return BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at));
    }
}
