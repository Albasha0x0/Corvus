using System.Text;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Core.Mobile;
using NetDecompilerMcp.Services.Mobile;

namespace NetDecompilerMcp.Tests;

/// <summary>Protobuf messages in the field layout of aapt2's Resources.proto and Configuration.proto.</summary>
internal sealed class Proto
{
    private readonly MemoryStream _s = new();

    private void Varint(ulong v) { do { byte b = (byte)(v & 0x7F); v >>= 7; _s.WriteByte((byte)(b | (v != 0 ? 0x80 : 0))); } while (v != 0); }
    public Proto V(int field, ulong value) { Varint((ulong)field << 3); Varint(value); return this; }
    public Proto S(int field, string value) => B(field, Encoding.UTF8.GetBytes(value));
    public Proto M(int field, Proto message) => B(field, message.Bytes);
    public Proto F32(int field, uint value) { Varint((ulong)field << 3 | 5); _s.Write(BitConverter.GetBytes(value)); return this; }
    public Proto B(int field, byte[] bytes) { Varint((ulong)field << 3 | 2); Varint((ulong)bytes.Length); _s.Write(bytes); return this; }
    public byte[] Bytes => _s.ToArray();

    public const string Android = "http://schemas.android.com/apk/res/android";

    // XmlNode{element=1}; XmlElement{namespace_declaration=1, namespace_uri=2, name=3, attribute=4, child=5}; XmlAttribute{namespace_uri=1, name=2, value=3, resource_id=5, compiled_item=6}
    public static Proto Element(string name, Proto[] attributes, params Proto[] children)
    {
        var e = new Proto().S(3, name);
        foreach (var a in attributes) e.M(4, a);
        foreach (var c in children) e.M(5, new Proto().M(1, c));
        return e;
    }

    public static Proto Attr(string name, string value, uint id = 0, Proto? item = null, string? ns = Android)
    {
        var a = new Proto();
        if (ns != null) a.S(1, ns);
        a.S(2, name).S(3, value);
        if (id != 0) a.V(5, id);
        if (item != null) a.M(6, item);
        return a;
    }

    // Item{ref=1, str=2, file=5, prim=7}; Reference{id=2, name=3}; Primitive{int_decimal=6, boolean=8}
    public static Proto Ref(uint id, string name) => new Proto().M(1, new Proto().V(2, id).S(3, name));
    public static Proto Str(string s) => new Proto().M(2, new Proto().S(1, s));
    public static Proto Int(int v) => new Proto().M(7, new Proto().V(6, (uint)v));
    public static Proto Bool(bool v) => new Proto().M(7, new Proto().V(8, v ? 1u : 0));
    public static Proto File(string path) => new Proto().M(5, new Proto().S(1, path));
}

public sealed class AabTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static byte[] Manifest() => new Proto().M(1, Proto.Element("manifest",
        [Proto.Attr("package", "com.example.bundle", ns: null), Proto.Attr("versionCode", "7", 0x0101021b, Proto.Int(7))],
        Proto.Element("uses-sdk", [Proto.Attr("minSdkVersion", "26", 0x0101020c, Proto.Int(26)), Proto.Attr("targetSdkVersion", "34", 0x01010270, Proto.Int(34))]),
        Proto.Element("uses-permission", [Proto.Attr("name", "android.permission.CAMERA", 0x01010003)]),
        Proto.Element("application", [Proto.Attr("label", "@string/app_name", 0x01010001, Proto.Ref(0x7f010000, "string/app_name")),
                Proto.Attr("debuggable", "true", 0x0101000f, Proto.Bool(true))],
            Proto.Element("activity", [Proto.Attr("name", ".Main", 0x01010003), Proto.Attr("exported", "true", 0x01010010, Proto.Bool(true))],
                Proto.Element("intent-filter", [],
                    Proto.Element("action", [Proto.Attr("name", "android.intent.action.MAIN", 0x01010003)]),
                    Proto.Element("category", [Proto.Attr("name", "android.intent.category.LAUNCHER", 0x01010003)])))))).Bytes;

    // ResourceTable{package=2}; Package{package_id=1, package_name=2, type=3}; Type{type_id=1, name=2, entry=3}; Entry{entry_id=1, name=2, config_value=6};
    // ConfigValue{config=1, value=2}; Value{item=4, compound_value=5}; CompoundValue{array=4}; Array{element=1}; Element{item=3}; Configuration{locale=3, density=18, ui_mode_night=17, sdk_version=24}
    private static byte[] Resources()
    {
        Proto Value(Proto item) => new Proto().M(4, item);
        Proto Config(string? locale = null, uint density = 0, uint night = 0, uint sdk = 0)
        {
            var c = new Proto();
            if (locale != null) c.S(3, locale);
            if (night != 0) c.V(17, night);
            if (density != 0) c.V(18, density);
            if (sdk != 0) c.V(24, sdk);
            return c;
        }
        Proto Entry(uint id, string name, params (Proto Config, Proto Value)[] values)
        {
            var e = new Proto().M(1, new Proto().V(1, id)).S(2, name);
            foreach (var (c, v) in values) e.M(6, new Proto().M(1, c).M(2, v));
            return e;
        }
        var strings = new Proto().M(1, new Proto().V(1, 1)).S(2, "string")
            .M(3, Entry(0, "app_name", (Config(), Value(Proto.Str("Bundle"))), (Config("pt-BR"), Value(Proto.Str("Pacote"))), (Config("sr-Latn-RS"), Value(Proto.Str("Paket")))))
            .M(3, Entry(1, "alias", (Config(), Value(Proto.Ref(0x7f010000, "string/app_name")))));
        var xml = new Proto().M(1, new Proto().V(1, 2)).S(2, "xml")
            .M(3, Entry(0, "config", (Config(density: 480, night: 1, sdk: 31), Value(Proto.File("res/xml/config.xml")))));
        var array = new Proto().M(4, new Proto().M(1, new Proto().M(3, Proto.Int(1))).M(1, new Proto().M(3, Proto.Str("two"))));
        var arrays = new Proto().M(1, new Proto().V(1, 3)).S(2, "array").M(3, new Proto().M(1, new Proto().V(1, 0)).S(2, "items").M(6, new Proto().M(1, Config()).M(2, new Proto().M(5, array))));
        var package = new Proto().M(1, new Proto().V(1, 0x7f)).S(2, "com.example.bundle").M(3, strings).M(3, xml).M(3, arrays);
        return new Proto().M(2, package).Bytes;
    }

    private string Bundle() => AndroidSamples.Save(_dir, "app.aab", ContainerFixtures.Zip(
        ("BundleConfig.pb", [0]),
        ("base/manifest/AndroidManifest.xml", Manifest()),
        ("base/resources.pb", Resources()),
        ("base/res/xml/config.xml", new Proto().M(1, Proto.Element("network-security-config", [], Proto.Element("base-config", [Proto.Attr("cleartextTrafficPermitted", "false", ns: null)]))).Bytes),
        ("base/dex/classes.dex", AndroidSamples.Dex()),
        ("base/lib/arm64-v8a/libnative.so", [0x7F])));

    [Fact]
    public void ManifestAndResources_FromProtobuf()
    {
        var service = new AndroidPackageService(new OutputPager(new ServerOptions()));
        var aab = Bundle();
        var m = service.Manifest(aab);
        Assert.Equal(("com.example.bundle", "7", 26, 34), (m.Package, m.VersionCode, m.MinSdk, m.TargetSdk));
        Assert.Equal(("Bundle", true), (m.Application.Label, m.Application.Debuggable));
        Assert.True(m.Components.Single().Launcher);
        Assert.Equal("android.permission.CAMERA", m.Permissions.Single().Name);

        var rows = service.Resources(aab, null, null, null, 0, 100);
        Assert.Equal(6, rows.Total);
        Assert.Equal(["", "b+sr+Latn+RS", "pt-rBR"], rows.Items.Where(r => r.Name == "app_name").Select(r => r.Config));
        Assert.Equal(("reference", "@string/app_name"), rows.Items.Where(r => r.Name == "alias").Select(r => (r.ValueType, r.Value)).Single());
        Assert.Equal(("night-xxhdpi-v31", "file", "res/xml/config.xml"), rows.Items.Where(r => r.Type == "xml").Select(r => (r.Config, r.ValueType, r.Value)).Single());
        Assert.Equal("[0]=1; [1]=two", rows.Items.Single(r => r.Type == "array").Value);

        Assert.Contains("<base-config cleartextTrafficPermitted=\"false\" />", service.Resource(aab, "@xml/config", null, false, 0, null));
        Assert.Contains("android:label=\"@string/app_name\"", service.Resource(aab, "AndroidManifest.xml", null, false, 0, null));
        Assert.Equal(4, new DexService().ListClasses(aab, null, null, 0, 10, default).Total);
        using var p = AndroidPackage.Open(aab);
        Assert.Equal("aab", p.Kind);
        Assert.Equal(["arm64-v8a"], p.Abis);
    }

    [Fact]
    public void DamagedProtobuf_NeverThrows()
    {
        var manifest = Manifest();
        var resources = Resources();
        var random = new Random(5);
        for (int n = 0; n < 300; n++)
        {
            var m = (byte[])manifest.Clone();
            var r = (byte[])resources.Clone();
            for (int k = 0; k < 4; k++) { m[random.Next(m.Length)] = (byte)random.Next(256); r[random.Next(r.Length)] = (byte)random.Next(256); }
            var doc = AabProto.ReadManifest(m[..random.Next(m.Length)]);
            _ = doc.ToXml();
            _ = AabProto.ReadResources(r[..random.Next(r.Length)]).Rows.ToList();
        }
    }
}
