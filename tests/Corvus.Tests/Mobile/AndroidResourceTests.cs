using Corvus.Core.Mobile;
using static Corvus.Tests.AxmlWriter;

namespace Corvus.Tests;

/// <summary>Android binary XML and resource tables: written by the test writers in the layouts aapt2 emits, then read back.</summary>
public class AndroidResourceTests
{
    private const uint AppName = 0x7f010000;

    private static (byte[] Manifest, byte[] Table) Sample(bool utf8 = false, ArscWriter.Layout layout = ArscWriter.Layout.Dense)
    {
        var res = new ArscWriter(0x7f, "com.example.app");
        Assert.Equal(AppName, res.String("string", "app_name", "Example"));
        res.String("string", "app_name", "Exemplo", ArscWriter.Config("pt", "BR"));
        res.String("string", "app_name", "示例", ArscWriter.Config("zh", script: "Hans"));
        var flag = res.Value("bool", "is_tablet", ResValue.IntBoolean, 0);
        res.Value("bool", "is_tablet", ResValue.IntBoolean, 1, ArscWriter.Config(density: 480, sdk: 31, night: true));
        res.Value("color", "accent", ResValue.ColorArgb8, 0xFF3366CC);
        res.Value("dimen", "margin", ResValue.Dimension, (16u << 8) | 1); // 16dp
        var alias = res.Value("string", "title", ResValue.Reference, AppName);
        res.Bag("style", "AppTheme", 0x01030224, (0x01010000, ResValue.Reference, flag));
        Assert.NotEqual(0u, alias);

        var manifest = new Node("manifest", String("package", "com.example.app", ns: null), Int("versionCode", 42, 0x0101021b), String("versionName", "1.2", 0x0101021c))
            .Add(
                new Node("uses-sdk", Int("minSdkVersion", 24, 0x0101020c), Int("targetSdkVersion", 34, 0x01010270)),
                new Node("uses-permission", String("name", "android.permission.INTERNET", 0x01010003)),
                new Node("application", Ref("label", AppName, 0x01010001), Bool("debuggable", true, 0x0101000f))
                    .Add(new Node("activity", String("name", ".Main", 0x01010003), Bool("exported", true, 0x01010010))
                        .Add(new Node("intent-filter").Add(new Node("action", String("name", "android.intent.action.MAIN", 0x01010003))))),
                new Node("meta") { Text = "a < b & c" });
        return (AxmlWriter.Write(manifest, utf8), res.Build(layout, utf8));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Manifest_ReadsTree_Attributes_AndResolvesReferencesThroughTheTable(bool utf8)
    {
        var (manifestBytes, tableBytes) = Sample(utf8);
        Assert.True(AxmlDocument.IsAxml(manifestBytes));
        var doc = AxmlDocument.Read(manifestBytes);
        Assert.Empty(doc.Issues);
        Assert.Equal(utf8, doc.Strings.IsUtf8);
        var root = doc.Root!;
        Assert.Equal("manifest", root.Name);
        Assert.Equal("com.example.app", root.Attribute("package", android: false)!.RawValue);
        Assert.Equal(42, (int)root.Attribute("versionCode")!.Value.Data);
        Assert.Equal(0x0101021bu, root.Attribute("versionCode")!.ResourceId);
        var app = root.Elements("application").Single();
        Assert.True(app.Attribute("label")!.Value.IsReference);
        Assert.Equal("android.intent.action.MAIN", app.Children[0].Children[0].Children[0].Attribute("name")!.RawValue);

        var table = ArscTable.Read(tableBytes);
        Assert.Empty(table.Issues);
        var xml = doc.ToXml(table.Resolver);
        Assert.Contains("xmlns:android=\"http://schemas.android.com/apk/res/android\"", xml);
        Assert.Contains("android:label=\"@string/app_name\"", xml);
        Assert.Contains("android:debuggable=\"true\"", xml);
        Assert.Contains("android:versionCode=\"42\"", xml);
        Assert.Contains("<meta>a &lt; b &amp; c</meta>", xml);
        Assert.Equal("Example", table.DefaultText(app.Attribute("label")!.Value.Data));
        // Parsable XML, with the same structure.
        var parsed = System.Xml.Linq.XDocument.Parse(xml);
        Assert.Equal(4, parsed.Root!.Elements().Count());
    }

    [Fact]
    public void StrippedAttributeNames_AreNamedFromTheirResourceIds()
    {
        var bytes = AxmlWriter.Write(new Node("manifest", new Attr(Android, "", 0x0101021b, ResValue.IntDec, 7), new Attr(Android, "", 0x01017777, ResValue.IntDec, 1)));
        var root = AxmlDocument.Read(bytes).Root!;
        Assert.Equal(7u, root.Attribute("versionCode")!.Value.Data);
        Assert.NotNull(root.Attribute("attr_0x01017777"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Table_ReadsEveryEntryLayout_ConfigsAndTypedValues(int layoutNumber)
    {
        var layout = (ArscWriter.Layout)layoutNumber;
        var table = ArscTable.Read(Sample(layout: layout).Table);
        Assert.Empty(table.Issues);
        var package = Assert.Single(table.Packages);
        Assert.Equal(0x7fu, package.Id);
        Assert.Equal("com.example.app", package.Name);
        Assert.Equal("@string/app_name", table.Name(AppName));
        var names = table.Values(AppName).ToDictionary(v => v.Config.Qualifiers, v => table.Format(v.Value!.Value));
        Assert.Equal("Example", names[""]);
        Assert.Equal("Exemplo", names["pt-rBR"]);
        Assert.Equal("示例", names["b+zh+Hans"]);
        var tablet = table.Values(0x7f020000);
        Assert.Equal(["", "night-xxhdpi-v31"], tablet.Select(v => v.Config.Qualifiers));
        Assert.Equal("true", table.Format(tablet[1].Value!.Value));
        Assert.Equal("#ff3366cc", table.DefaultText(0x7f030000));
        Assert.Equal("16dp", table.DefaultText(0x7f040000));
        Assert.Equal("Example", table.DefaultText(0x7f010001)); // a reference is followed
        if (layout != ArscWriter.Layout.Compact)
        {
            var style = Assert.Single(table.Values(0x7f050000));
            Assert.Null(style.Value);
            Assert.Equal(0x01030224u, style.Parent);
            Assert.Equal("@bool/is_tablet", table.Format(Assert.Single(style.Map!).Value));
            Assert.Equal("@android:style/Theme", ArscTable.Read(FrameworkTable()).Name(0x01030224));
        }
    }

    private static byte[] FrameworkTable()
    {
        // 0x01030224: the style type is the third type, Theme its entry 0x224.
        var b = new ArscWriter(0x01, "android");
        b.Value("attr", "theme", ResValue.IntDec, 0);
        b.Value("id", "a", ResValue.IntDec, 0);
        for (int i = 0; i < 0x224; i++) b.Bag("style", $"S{i}", 0);
        b.Bag("style", "Theme", 0);
        return b.Build();
    }

    [Theory]
    [InlineData("pt", "BR", 0, 0, false, null, "pt-rBR")]
    [InlineData("en", null, 160, 21, false, null, "en-mdpi-v21")]
    [InlineData(null, null, 0xFFFE, 0, true, null, "night-anydpi")]
    [InlineData("sr", "RS", 0, 0, false, "Latn", "b+sr+Latn+RS")]
    public void ConfigQualifiers_MatchAaptDirectoryNames(string? lang, string? region, int density, int sdk, bool night, string? script, string expected) =>
        Assert.Equal(expected, new ArscConfig(ArscWriter.Config(lang, region, (ushort)density, (ushort)sdk, night, script)).Qualifiers);

    [Fact]
    public void PackedThreeLetterLanguage_IsUnpacked()
    {
        var c = ArscWriter.Config();
        // "fil" packed: 0x80 | third << 2 | second >> 3, second << 5 | first (letters from 'a').
        int f = 'f' - 'a', i = 'i' - 'a', l = 'l' - 'a';
        c[8] = (byte)(0x80 | l << 2 | i >> 3);
        c[9] = (byte)((i & 7) << 5 | f);
        Assert.Equal("b+fil", new ArscConfig(c).Qualifiers);
    }

    [Fact]
    public void Truncated_AndCorruptInput_GivesPartialResultsWithIssues()
    {
        var (manifest, table) = Sample();
        var half = AxmlDocument.Read(manifest.AsSpan(0, manifest.Length * 2 / 3));
        Assert.NotEmpty(half.Issues);
        Assert.Equal("manifest", half.Root?.Name);
        Assert.NotEmpty(ArscTable.Read(table.AsSpan(0, table.Length - 10)).Issues);
        Assert.NotEmpty(AxmlDocument.Read([1, 2, 3]).Issues);
        Assert.NotEmpty(ArscTable.Read(manifest).Issues);
        Assert.False(AxmlDocument.IsAxml(table));
        Assert.True(ArscTable.IsArsc(table));
    }

    [Fact]
    [FuzzEntry(typeof(AxmlDocument), typeof(ArscTable), typeof(ResStringPool), typeof(ResValue))]
    public void MutatedInput_NeverThrows()
    {
        var (manifest, table) = Sample();
        var failures = FormatFuzz.Run(manifest, b => AxmlDocument.Read(b).ToXml(), 1500);
        failures.AddRange(FormatFuzz.Run(table, b =>
        {
            var t = ArscTable.Read(b);
            foreach (var p in t.Packages) foreach (var e in p.Entries) { _ = e.Config.Qualifiers; if (e.Value is { } v) t.Format(v); t.Name(e.Id); }
        }, 1500));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
