using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Corvus.Core.Flash;

/// <summary>
/// A SWF file as the SWF File Format Specification (version 19) lays it out: "FWS" (uncompressed), "CWS" (zlib from
/// byte 8) or "ZWS" (LZMA from byte 12), the version, the uncompressed length, the frame rectangle in twips, the frame
/// rate (8.8 fixed) and count, then tag records (code and length, long form past 62 bytes) to the End tag. DefineSprite
/// tags hold their own tag lists, read in place.
/// </summary>
internal sealed class SwfFile
{
    /// <summary>One tag: code, name, where its body starts in <see cref="Body"/>, its length, and the sprite it belongs to (0 for the file).</summary>
    public sealed record Tag(int Code, string Name, int At, int Length, int Sprite);

    public required string Compression { get; init; }
    public required int Version { get; init; }
    public required long DeclaredLength { get; init; }
    /// <summary>The file with its body expanded: the 8-byte header, then the frame fields and tags.</summary>
    public required byte[] Body { get; init; }
    public required (int XMin, int XMax, int YMin, int YMax) Frame { get; init; }
    public required double FrameRate { get; init; }
    public required int FrameCount { get; init; }
    public required List<Tag> Tags { get; init; }
    public required List<string> Notes { get; init; }

    private const int MaxTags = 2_000_000;

    /// <summary>"FWS", "CWS" or "ZWS" and a version byte of at most 64.</summary>
    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= 8 && b[1] == 'W' && b[2] == 'S' && b[0] is (byte)'F' or (byte)'C' or (byte)'Z' && b[3] is > 0 and <= 64;

    /// <summary>Reads the header and every tag; throws <see cref="ToolError"/> on a header or body that does not read, notes a damaged tag list.</summary>
    public static SwfFile Read(byte[] data, string name, long maxBytes)
    {
        if (!Looks(data)) throw Malformed(name, "no SWF header");
        int version = data[3];
        long declared = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(4));
        if (declared < 8 || declared > maxBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{name}: the SWF declares {declared:N0} bytes, past the {maxBytes:N0}-byte item limit.", "raise the limits");
        var notes = new List<string>();
        byte[] body;
        string compression;
        switch ((char)data[0])
        {
            case 'F':
                compression = "none";
                body = data;
                break;
            case 'C':
                compression = "zlib";
                body = Expand(new ZLibStream(new MemoryStream(data, 8, data.Length - 8, writable: false), CompressionMode.Decompress), data, declared, notes, name);
                break;
            default:
                compression = "lzma";
                if (data.Length < 17) throw Malformed(name, "the LZMA header is cut short");
                var props = data.AsSpan(12, 5).ToArray();
                var lzma = SharpCompress.Compressors.LZMA.LzmaStream.Create(props, new MemoryStream(data, 17, data.Length - 17, writable: false), data.Length - 17, declared - 8, false);
                body = Expand(lzma, data, declared, notes, name);
                break;
        }
        if (body.Length < 8 + 2 + 4) throw Malformed(name, "the body is cut short");
        // RECT: a 5-bit field size, then four signed fields of that size.
        int bits = body[8] >> 3;
        int rectBytes = (5 + 4 * bits + 7) / 8;
        if (8 + rectBytes + 4 > body.Length) throw Malformed(name, "the frame fields are cut short");
        var reader = new BitReader(body, 8);
        reader.Bits(5);
        var frame = (reader.Signed(bits), reader.Signed(bits), reader.Signed(bits), reader.Signed(bits));
        int p = 8 + rectBytes;
        double rate = BinaryPrimitives.ReadUInt16LittleEndian(body.AsSpan(p)) / 256.0;
        int frames = BinaryPrimitives.ReadUInt16LittleEndian(body.AsSpan(p + 2));
        var tags = new List<Tag>();
        ReadTags(body, p + 4, body.Length, 0, tags, notes, 0);
        return new SwfFile
        {
            Compression = compression, Version = version, DeclaredLength = declared, Body = body, Frame = frame, FrameRate = rate, FrameCount = frames,
            Tags = tags, Notes = notes,
        };
    }

    /// <summary>The expanded body behind the 8-byte header; a stream that ends early keeps what it gave and is a note.</summary>
    private static byte[] Expand(Stream z, byte[] data, long declared, List<string> notes, string name)
    {
        var body = new byte[declared];
        data.AsSpan(0, 8).CopyTo(body);
        int got = 8;
        try
        {
            using (z)
                for (int n; got < body.Length && (n = z.Read(body, got, body.Length - got)) > 0;) got += n;
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or SharpCompress.Common.SharpCompressException or IndexOutOfRangeException or ArgumentException)
        {
            if (got <= 8) throw Malformed(name, $"the body does not expand ({ex.Message})");
            notes.Add($"the body stops expanding after {got:N0} of {declared:N0} bytes ({ex.Message})");
        }
        if (got < body.Length && !notes.Exists(n => n.StartsWith("the body stops", StringComparison.Ordinal)))
            notes.Add($"the body expands to {got:N0} of the {declared:N0} bytes the header declares");
        return got < body.Length ? body[..got] : body;
    }

    private static void ReadTags(byte[] b, int p, int end, int sprite, List<Tag> tags, List<string> notes, int depth)
    {
        while (p + 2 <= end)
        {
            int header = BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(p));
            int code = header >> 6;
            long length = header & 0x3F;
            p += 2;
            if (length == 0x3F)
            {
                if (p + 4 > end) { notes.Add($"tag {Name(code)} at 0x{p - 2:X}: its long length is cut short"); return; }
                length = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(p));
                p += 4;
            }
            if (length > end - p) { notes.Add($"tag {Name(code)} at 0x{p - 2:X} runs past the end ({length:N0} bytes); the tag list stops there"); return; }
            if (tags.Count >= MaxTags) { notes.Add($"more than {MaxTags:N0} tags; the rest are not read"); return; }
            tags.Add(new Tag(code, Name(code), p, (int)length, sprite));
            if (code == 0) return;
            // DefineSprite: id, frame count, then the sprite's own tags; sprites do not nest in the format.
            if (code == 39 && length >= 4 && depth == 0) ReadTags(b, p + 4, p + (int)length, BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(p)), tags, notes, depth + 1);
            p += (int)length;
        }
    }

    /// <summary>The tag names of the specification, by code; an unknown code is "Tag{code}".</summary>
    public static string Name(int code) => code < Names.Length && Names[code] is { } n ? n : $"Tag{code}";

    private static readonly string?[] Names = Build();

    private static string?[] Build()
    {
        var n = new string?[100];
        foreach (var (code, name) in new (int, string)[]
        {
            (0, "End"), (1, "ShowFrame"), (2, "DefineShape"), (4, "PlaceObject"), (5, "RemoveObject"), (6, "DefineBits"), (7, "DefineButton"),
            (8, "JPEGTables"), (9, "SetBackgroundColor"), (10, "DefineFont"), (11, "DefineText"), (12, "DoAction"), (13, "DefineFontInfo"),
            (14, "DefineSound"), (15, "StartSound"), (17, "DefineButtonSound"), (18, "SoundStreamHead"), (19, "SoundStreamBlock"),
            (20, "DefineBitsLossless"), (21, "DefineBitsJPEG2"), (22, "DefineShape2"), (23, "DefineButtonCxform"), (24, "Protect"),
            (26, "PlaceObject2"), (28, "RemoveObject2"), (32, "DefineShape3"), (33, "DefineText2"), (34, "DefineButton2"), (35, "DefineBitsJPEG3"),
            (36, "DefineBitsLossless2"), (37, "DefineEditText"), (39, "DefineSprite"), (41, "ProductInfo"), (43, "FrameLabel"),
            (45, "SoundStreamHead2"), (46, "DefineMorphShape"), (48, "DefineFont2"), (56, "ExportAssets"), (57, "ImportAssets"),
            (58, "EnableDebugger"), (59, "DoInitAction"), (60, "DefineVideoStream"), (61, "VideoFrame"), (62, "DefineFontInfo2"), (63, "DebugID"),
            (64, "EnableDebugger2"), (65, "ScriptLimits"), (66, "SetTabIndex"), (69, "FileAttributes"), (70, "PlaceObject3"), (71, "ImportAssets2"),
            (72, "DoABC"), (73, "DefineFontAlignZones"), (74, "CSMTextSettings"), (75, "DefineFont3"), (76, "SymbolClass"), (77, "Metadata"),
            (78, "DefineScalingGrid"), (82, "DoABC2"), (83, "DefineShape4"), (84, "DefineMorphShape2"), (86, "DefineSceneAndFrameLabelData"),
            (87, "DefineBinaryData"), (88, "DefineFontName"), (89, "StartSound2"), (90, "DefineBitsJPEG4"), (91, "DefineFont4"), (93, "EnableTelemetry"),
        }) n[code] = name;
        return n;
    }

    /// <summary>A NUL-terminated UTF-8 string at <paramref name="at"/> within <paramref name="end"/>; <paramref name="next"/> is the byte after the NUL (or the end).</summary>
    public static string String(byte[] b, int at, int end, out int next)
    {
        int nul = b.AsSpan(at, Math.Max(0, end - at)).IndexOf((byte)0);
        int stop = nul < 0 ? end : at + nul;
        next = nul < 0 ? end : stop + 1;
        return Encoding.UTF8.GetString(b, at, Math.Max(0, stop - at));
    }

    private static ToolError Malformed(string name, string what) => new(ErrorCode.MalformedInput, $"{name}: not a readable SWF file: {what}.");

    /// <summary>Reads big-endian bit fields, most significant bit first, as SWF packs RECT and MATRIX.</summary>
    private struct BitReader(byte[] b, int at)
    {
        private long _bit = (long)at * 8;

        public uint Bits(int n)
        {
            uint v = 0;
            for (int i = 0; i < n; i++, _bit++)
            {
                int index = (int)(_bit >> 3);
                int bit = index < b.Length ? (b[index] >> (7 - (int)(_bit & 7))) & 1 : 0;
                v = v << 1 | (uint)bit;
            }
            return v;
        }

        public int Signed(int n) => n == 0 ? 0 : (int)(Bits(n) << (32 - n)) >> (32 - n);
    }
}
