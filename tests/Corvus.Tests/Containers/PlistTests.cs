using System.Buffers.Binary;
using System.Numerics;
using System.Text;
using System.Text.Json;
using Corvus.Core.Mobile;

namespace Corvus.Tests;

/// <summary>Property lists in all three forms and keyed-archive projection; integers stay exact at every width.</summary>
public class PlistTests
{
    private static PlistDict Dict(params (string Key, PlistNode Value)[] entries) => new(entries.Select(e => new KeyValuePair<string, PlistNode>(e.Key, e.Value)).ToList());
    private static PlistArray Array(params PlistNode[] items) => new(items);
    private static PlistString S(string s) => new(s);
    private static PlistInteger I(BigInteger i) => new(i);

    private static JsonElement Json(PlistNode node) => JsonDocument.Parse(Plist.ToJson(node)).RootElement;

    [Fact]
    public void Binary_reads_every_type_with_exact_integers()
    {
        var big = BigInteger.Pow(2, 100);
        var tree = Dict(
            ("small", I(255)), ("short", I(65535)), ("negative", I(-1)), ("max", I(long.MaxValue)), ("umax", I(ulong.MaxValue)), ("huge", I(big)),
            ("pi", new PlistReal(3.25)), ("when", new PlistDate(new DateTimeOffset(2024, 2, 29, 12, 0, 0, TimeSpan.Zero))),
            ("blob", new PlistData([1, 2, 3])), ("ascii", S("plain")), ("unicode", S("Grüße 漢字")),
            ("list", new PlistArray(Enumerable.Range(0, 40).Select(i => (PlistNode)I(i)).ToList())), ("set", new PlistArray([S("a")], IsSet: true)),
            ("yes", new PlistBool(true)), ("uid", new PlistUid(7)));
        var bytes = BplistWriter.Write(tree);
        var doc = Plist.Read(bytes);
        Assert.Empty(doc.Issues);
        Assert.Equal("binary", doc.Format);
        var root = (PlistDict)doc.Root!;
        Assert.Equal(ulong.MaxValue, (ulong)((PlistInteger)root["umax"]!).Value);
        Assert.Equal(big, ((PlistInteger)root["huge"]!).Value);
        Assert.Equal(-1, (int)((PlistInteger)root["negative"]!).Value);
        Assert.True(((PlistArray)root["set"]!).IsSet);
        Assert.Equal(40, ((PlistArray)root["list"]!).Items.Count);

        var json = Plist.ToJson(root);
        Assert.Contains("\"umax\": 18446744073709551615", json);
        Assert.Contains("\"huge\": 1267650600228229401496703205376", json);
        var parsed = JsonDocument.Parse(json).RootElement;
        Assert.Equal("2024-02-29T12:00:00Z", parsed.GetProperty("when").GetProperty("$date").GetString());
        Assert.Equal("AQID", parsed.GetProperty("blob").GetProperty("$data").GetString());
        Assert.Equal("Grüße 漢字", parsed.GetProperty("unicode").GetString());
        Assert.Equal(7, parsed.GetProperty("uid").GetProperty("$uid").GetInt32());
    }

    [Fact]
    public void Binary_cycle_and_bad_references_are_issues_not_hangs()
    {
        // Object 0: an array holding itself and an out-of-range reference.
        byte[] objects = [0xA2, 0x00, 0x05];
        var bytes = BplistWriter.Raw(objects, [0], top: 0);
        var doc = Plist.Read(bytes);
        Assert.Contains(doc.Issues, i => i.Message.Contains("contains itself"));
        Assert.Contains(doc.Issues, i => i.Message.Contains("not one of"));
        Assert.Equal(2, ((PlistArray)doc.Root!).Items.Count);
        Assert.NotEmpty(Plist.Read("bplist00"u8).Issues);
    }

    [Fact]
    public void XML_reads_types_exact_integers_and_never_expands_entities()
    {
        const string text = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
              <key>CFBundleIdentifier</key><string>com.example.app</string>
              <key>big</key><integer>18446744073709551615</integer>
              <key>negative</key><integer>-5</integer>
              <key>hex</key><integer>0x10</integer>
              <key>ratio</key><real>0.5</real>
              <key>built</key><date>2023-06-01T08:30:00Z</date>
              <key>icon</key><data>
                AAEC
                Aw==
              </data>
              <key>flags</key><array><true/><false/><dict/></array>
            </dict>
            </plist>
            """;
        var doc = Plist.Read(Encoding.UTF8.GetBytes(text));
        Assert.Empty(doc.Issues);
        Assert.Equal("xml", doc.Format);
        var root = (PlistDict)doc.Root!;
        Assert.Equal(ulong.MaxValue, (ulong)((PlistInteger)root["big"]!).Value);
        Assert.Equal(16, (int)((PlistInteger)root["hex"]!).Value);
        Assert.Equal(new byte[] { 0, 1, 2, 3 }, ((PlistData)root["icon"]!).Value);
        Assert.Equal(new DateTimeOffset(2023, 6, 1, 8, 30, 0, TimeSpan.Zero), ((PlistDate)root["built"]!).Value);
        Assert.Equal(3, ((PlistArray)root["flags"]!).Items.Count);
        Assert.Contains("\"big\": 18446744073709551615", Plist.ToJson(root));

        var secret = Path.GetTempFileName();
        try
        {
            File.WriteAllText(secret, "SECRET-CONTENT");
            var hostile = $"<?xml version=\"1.0\"?><!DOCTYPE plist [<!ENTITY x SYSTEM \"{new Uri(secret)}\">]><plist><dict><key>a</key><string>&x;</string></dict></plist>";
            var read = Plist.Read(Encoding.UTF8.GetBytes(hostile));
            Assert.DoesNotContain("SECRET", Plist.ToJson(read.Root ?? PlistNull.Value));
            Assert.NotEmpty(read.Issues);
        }
        finally { File.Delete(secret); }
    }

    [Fact]
    public void XML_truncated_keeps_what_was_read()
    {
        var doc = Plist.Read("<plist><dict><key>a</key><string>1</string><key>b</key><array><integer>2</integer>"u8);
        Assert.NotEmpty(doc.Issues);
        var root = (PlistDict)doc.Root!;
        Assert.Equal("1", ((PlistString)root["a"]!).Value);
        Assert.Equal(2, (int)((PlistInteger)((PlistArray)root["b"]!).Items[0]).Value);
    }

    [Fact]
    public void ASCII_OpenStep_GNUstep_and_strings_files_read()
    {
        const string text = """
            // a comment
            {
                name = "Quoted \"text\"\n\U00e9";
                bare = some.value-1;
                list = (one, "two", <0a0B ff>, );  /* trailing comma */
                typed = { i = <*I-12345678901234567890>; r = <*R2.5>; b = <*BY>; d = <*D2001-01-01 00:00:00 +0000>; };
                octal = "\101";
            }
            """;
        var doc = Plist.Read(Encoding.UTF8.GetBytes(text));
        Assert.Empty(doc.Issues);
        Assert.Equal("ascii", doc.Format);
        var root = (PlistDict)doc.Root!;
        Assert.Equal("Quoted \"text\"\né", ((PlistString)root["name"]!).Value);
        Assert.Equal("some.value-1", ((PlistString)root["bare"]!).Value);
        var list = (PlistArray)root["list"]!;
        Assert.Equal(new byte[] { 0x0a, 0x0b, 0xff }, ((PlistData)list.Items[2]).Value);
        var typed = (PlistDict)root["typed"]!;
        Assert.Equal(BigInteger.Parse("-12345678901234567890", System.Globalization.CultureInfo.InvariantCulture), ((PlistInteger)typed["i"]!).Value);
        Assert.True(((PlistBool)typed["b"]!).Value);
        Assert.Equal(new DateTimeOffset(2001, 1, 1, 0, 0, 0, TimeSpan.Zero), ((PlistDate)typed["d"]!).Value);
        Assert.Equal("A", ((PlistString)root["octal"]!).Value);

        var strings = Plist.Read(Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("/* Title */\n\"title\" = \"Bonjour\";\n\"bye\" = \"Au revoir\";\n")).ToArray());
        Assert.Empty(strings.Issues);
        Assert.Equal("Au revoir", ((PlistString)((PlistDict)strings.Root!)["bye"]!).Value);

        var broken = Plist.Read("{ a = (1, 2"u8);
        Assert.NotEmpty(broken.Issues);
        Assert.Equal(2, ((PlistArray)((PlistDict)broken.Root!)["a"]!).Items.Count);
    }

    /// <summary>A keyed archive as NSKeyedArchiver writes it: a person whose friends array points back at the person.</summary>
    private static PlistDict Archive() => Dict(
        ("$version", I(100000)), ("$archiver", S("NSKeyedArchiver")), ("$top", Dict(("root", new PlistUid(1)))),
        ("$objects", Array(
            S("$null"),
            Dict(("$class", new PlistUid(2)), ("name", new PlistUid(3)), ("friends", new PlistUid(4)), ("age", I(41)), ("meta", new PlistUid(6)), ("born", new PlistUid(9))),
            Dict(("$classname", S("Person")), ("$classes", Array(S("Person"), S("NSObject")))),
            S("Ada"),
            Dict(("$class", new PlistUid(5)), ("NS.objects", Array(new PlistUid(1), new PlistUid(3)))),
            Dict(("$classname", S("NSMutableArray")), ("$classes", Array(S("NSMutableArray"), S("NSArray"), S("NSObject")))),
            Dict(("$class", new PlistUid(7)), ("NS.keys", Array(new PlistUid(8))), ("NS.objects", Array(new PlistUid(3)))),
            Dict(("$classname", S("NSDictionary")), ("$classes", Array(S("NSDictionary"), S("NSObject")))),
            S("nickname"),
            Dict(("$class", new PlistUid(10)), ("NS.time", new PlistReal(86400))),
            Dict(("$classname", S("NSDate")), ("$classes", Array(S("NSDate"), S("NSObject")))))));

    [Fact]
    public void Keyed_archive_projects_the_object_graph_with_classes_and_references()
    {
        var doc = Plist.Read(BplistWriter.Write(Archive()));
        Assert.Empty(doc.Issues);
        Assert.True(KeyedArchive.IsKeyedArchive(doc.Root));
        var (root, issues) = KeyedArchive.Project(doc.Root!);
        Assert.Empty(issues);
        var json = Json(root);
        Assert.Equal("Person", json.GetProperty("$class").GetString());
        Assert.Equal(1, json.GetProperty("$uid").GetInt32());
        Assert.Equal("NSObject", json.GetProperty("$classes")[1].GetString());
        Assert.Equal("Ada", json.GetProperty("name").GetString());
        Assert.Equal(41, json.GetProperty("age").GetInt32());
        var friends = json.GetProperty("friends");
        // The cycle back to the person.
        Assert.Equal(1, friends[0].GetProperty("$ref").GetInt32());
        Assert.Equal("Ada", friends[1].GetString());
        Assert.Equal("Ada", json.GetProperty("meta").GetProperty("nickname").GetString());
        Assert.Equal("2001-01-02T00:00:00Z", json.GetProperty("born").GetProperty("$date").GetString());

        Assert.NotEmpty(KeyedArchive.Project(S("x")).Issues);
    }

    [Fact]
    public void A_plist_read_from_a_stream_equals_its_bytes_and_keeps_the_start_of_long_values()
    {
        var root = Dict(("name", S("Ada")), ("list", Array(I(1), I(-70000), new PlistReal(2.5))), ("blob", new PlistData([.. Enumerable.Range(0, 300).Select(i => (byte)i)])),
            ("text", S(new string('x', 5000))), ("archive", Archive()));
        var binary = BplistWriter.Write(root);
        var xml = Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><plist><dict><key>a</key><array><integer>1</integer><data>AAECAwQFBgcICQ==</data><string>"
                                         + new string('y', 5000) + "</string></array></dict></plist>");
        foreach (var bytes in new[] { binary, xml })
        {
            var whole = Plist.Read(bytes);
            var streamed = Plist.Read(new MemoryStream(bytes), int.MaxValue);
            Assert.Equal(Plist.ToJson(whole.Root!), Plist.ToJson(streamed.Root!));
            Assert.Empty(streamed.Issues);
            var clipped = Plist.Read(new MemoryStream(bytes), 64);
            Assert.Contains(clipped.Issues, i => i.Message.Contains("the first 64 read", StringComparison.Ordinal));
        }
        var text = (PlistString)((PlistDict)Plist.Read(new MemoryStream(binary), 64).Root!)["text"]!;
        Assert.Equal(new string('x', 64), text.Value);
    }

    [Fact]
    [FuzzEntry(typeof(Plist))]
    public void Mutated_input_never_throws()
    {
        var binary = BplistWriter.Write(Archive());
        var xml = Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><plist><dict><key>a</key><array><integer>1</integer><real>2.5</real><data>AAEC</data><date>2020-01-01T00:00:00Z</date></array></dict></plist>");
        var ascii = Encoding.UTF8.GetBytes("{ a = (1, \"two\", <00ff>, <*I5>); b = { c = d; }; }");
        void Read(byte[] b)
        {
            Plist.Read(new MemoryStream(b), 16);
            var doc = Plist.Read(b);
            if (doc.Root is { } root)
            {
                Plist.ToJson(root, maxValues: 10_000);
                if (KeyedArchive.IsKeyedArchive(root)) Plist.ToJson(KeyedArchive.Project(root, 10_000).Root, maxValues: 10_000);
            }
        }
        var failures = FormatFuzz.Run(binary, Read, 1500);
        failures.AddRange(FormatFuzz.Run(xml, Read, 500));
        failures.AddRange(FormatFuzz.Run(ascii, Read, 500));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}

/// <summary>Writes bplist00 the way CoreFoundation does (big-endian, minimal integer widths, 16-byte integers above 2^63 - 1).</summary>
internal static class BplistWriter
{
    public static byte[] Write(PlistNode root)
    {
        var objects = new List<byte[]>();
        var refs = new List<List<int>>();
        Flatten(root, objects, refs);
        int refSize = objects.Count < 256 ? 1 : 2;
        var bodies = objects.Select((o, i) => refs[i].Count == 0 ? o : [.. o, .. refs[i].SelectMany(r => Be((ulong)r, refSize))]).ToList();
        var data = new MemoryStream();
        data.Write("bplist00"u8);
        var offsets = new List<long>();
        foreach (var b in bodies) { offsets.Add(data.Length); data.Write(b); }
        return Finish(data, offsets, refSize, 0);
    }

    /// <summary>A file from raw object bytes (already holding 1-byte references) and their offsets after the header.</summary>
    public static byte[] Raw(byte[] objects, int[] offsets, int top)
    {
        var data = new MemoryStream();
        data.Write("bplist00"u8);
        data.Write(objects);
        return Finish(data, offsets.Select(o => (long)o + 8).ToList(), 1, top);
    }

    private static byte[] Finish(MemoryStream data, List<long> offsets, int refSize, int top)
    {
        long table = data.Length;
        int offsetSize = table < 256 ? 1 : table < 65536 ? 2 : 4;
        foreach (var o in offsets) data.Write(Be((ulong)o, offsetSize));
        var trailer = new byte[32];
        trailer[6] = (byte)offsetSize;
        trailer[7] = (byte)refSize;
        BinaryPrimitives.WriteUInt64BigEndian(trailer.AsSpan(8), (ulong)offsets.Count);
        BinaryPrimitives.WriteUInt64BigEndian(trailer.AsSpan(16), (ulong)top);
        BinaryPrimitives.WriteUInt64BigEndian(trailer.AsSpan(24), (ulong)table);
        data.Write(trailer);
        return data.ToArray();
    }

    private static byte[] Be(ulong v, int size)
    {
        var b = new byte[size];
        for (int i = size - 1; i >= 0; i--) { b[i] = (byte)v; v >>= 8; }
        return b;
    }

    private static byte[] Marker(int kind, int count) =>
        count < 15 ? [(byte)(kind << 4 | count)] : [(byte)(kind << 4 | 0xF), .. Integer(count)];

    private static byte[] Integer(BigInteger v)
    {
        if (v >= 0 && v <= byte.MaxValue) return [0x10, (byte)v];
        if (v >= 0 && v <= ushort.MaxValue) return [0x11, .. Be((ulong)v, 2)];
        if (v >= 0 && v <= uint.MaxValue) return [0x12, .. Be((ulong)v, 4)];
        if (v >= long.MinValue && v <= long.MaxValue) return [0x13, .. Be((ulong)(long)v, 8)];
        var bytes = v.ToByteArray(isUnsigned: false, isBigEndian: true);
        var padded = new byte[16];
        if (v.Sign < 0) System.Array.Fill(padded, (byte)0xFF);
        bytes.CopyTo(padded, 16 - bytes.Length);
        return [0x14, .. padded];
    }

    private static int Flatten(PlistNode node, List<byte[]> objects, List<List<int>> refs)
    {
        int index = objects.Count;
        objects.Add([]);
        refs.Add([]);
        byte[] body;
        switch (node)
        {
            case PlistBool b: body = [b.Value ? (byte)0x09 : (byte)0x08]; break;
            case PlistInteger i: body = Integer(i.Value); break;
            case PlistReal r: body = [0x23, .. Be((ulong)BitConverter.DoubleToInt64Bits(r.Value), 8)]; break;
            case PlistDate d: body = [0x33, .. Be((ulong)BitConverter.DoubleToInt64Bits((d.Value - new DateTimeOffset(2001, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds), 8)]; break;
            case PlistData data: body = [.. Marker(4, data.Value.Length), .. data.Value]; break;
            case PlistString s when s.Value.All(char.IsAscii): body = [.. Marker(5, s.Value.Length), .. Encoding.ASCII.GetBytes(s.Value)]; break;
            case PlistString s: body = [.. Marker(6, s.Value.Length), .. Encoding.BigEndianUnicode.GetBytes(s.Value)]; break;
            case PlistUid u: body = [0x80, (byte)u.Value]; break;
            case PlistArray a:
                body = Marker(a.IsSet ? 0xC : 0xA, a.Items.Count);
                foreach (var item in a.Items) refs[index].Add(Flatten(item, objects, refs));
                break;
            case PlistDict dict:
                body = Marker(0xD, dict.Entries.Count);
                var keys = dict.Entries.Select(e => Flatten(new PlistString(e.Key), objects, refs)).ToList();
                var values = dict.Entries.Select(e => Flatten(e.Value, objects, refs)).ToList();
                refs[index].AddRange([.. keys, .. values]);
                break;
            default: body = [0x00]; break;
        }
        objects[index] = body;
        return index;
    }
}
