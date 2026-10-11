using NetDecompilerMcp.Core.Mobile;
using static NetDecompilerMcp.Tests.AxmlWriter;

namespace NetDecompilerMcp.Tests;

/// <summary>Synthetic Android packages for the Android tool tests: a manifest exercising the exported rules, resources and extra entries.</summary>
internal static class AndroidSamples
{
    public const uint AppName = 0x7f010000;

    /// <summary>Resource ids of the sample table.</summary>
    public static uint NetworkConfig, Layout, IsTablet;

    public static byte[] Resources()
    {
        var res = new ArscWriter(0x7f, "com.example.app");
        res.String("string", "app_name", "Example");
        res.String("string", "app_name", "Exemplo", ArscWriter.Config("pt", "BR"));
        res.String("string", "host", "api.example.com");
        IsTablet = res.Value("bool", "is_tablet", ResValue.IntBoolean, 0);
        res.Value("bool", "is_tablet", ResValue.IntBoolean, 1, ArscWriter.Config(density: 480, sdk: 31, night: true));
        NetworkConfig = res.String("xml", "network_security_config", "res/xml/network_security_config.xml");
        Layout = res.String("layout", "main", "res/layout/main.xml");
        res.Bag("array", "planets", 0, (0x02000000, ResValue.Reference, AppName), (0x02000001, ResValue.IntDec, 7));
        return res.Build();
    }

    public static byte[] Manifest(int targetSdk = 30, string package = "com.example.app")
    {
        var filter = (string scheme, string host) => new Node("intent-filter", Bool("autoVerify", true, 0x010104ee)).Add(
            new Node("action", String("name", "android.intent.action.VIEW", 0x01010003)),
            new Node("category", String("name", "android.intent.category.BROWSABLE", 0x01010003)),
            new Node("data", String("scheme", scheme, 0x01010027), String("host", host, 0x01010028), String("pathPrefix", "/open", 0x0101002b)));
        var root = new Node("manifest", String("package", package, ns: null), Int("versionCode", 42, 0x0101021b), String("versionName", "1.2", 0x0101021c),
                Int("compileSdkVersion", 34, 0x01010572))
            .Add(
                new Node("uses-sdk", Int("minSdkVersion", 24, 0x0101020c), Int("targetSdkVersion", targetSdk, 0x01010270)),
                new Node("uses-permission", String("name", "android.permission.INTERNET", 0x01010003)),
                new Node("uses-permission-sdk-23", String("name", "android.permission.CAMERA", 0x01010003)),
                new Node("uses-permission", String("name", "android.permission.READ_EXTERNAL_STORAGE", 0x01010003), Int("maxSdkVersion", 28, 0x01010271)),
                new Node("permission", String("name", "com.example.app.PRIVATE", 0x01010003), new Attr(Android, "protectionLevel", 0x01010009, 0x11, 0x12)),
                new Node("queries").Add(new Node("package", String("name", "com.other.app", 0x01010003))),
                new Node("application", Ref("label", AppName, 0x01010001), Bool("debuggable", true, 0x0101000f), String("name", ".App", 0x01010003),
                        Ref("networkSecurityConfig", NetworkConfig, 0x01010527), Bool("usesCleartextTraffic", true, 0x010104ec))
                    .Add(
                        new Node("activity", String("name", ".Main", 0x01010003), Bool("exported", true, 0x01010010))
                            .Add(new Node("intent-filter").Add(
                                new Node("action", String("name", "android.intent.action.MAIN", 0x01010003)),
                                new Node("category", String("name", "android.intent.category.LAUNCHER", 0x01010003)))),
                        new Node("activity", String("name", "crc64a1b2c3d4e5f60718.LinkActivity", 0x01010003)).Add(filter("https", "example.com")),
                        new Node("activity-alias", String("name", ".Alias", 0x01010003), String("targetActivity", ".Main", 0x01010202), Bool("exported", false, 0x01010010)),
                        new Node("service", String("name", "com.example.app.Sync", 0x01010003), String("permission", "com.example.app.PRIVATE", 0x01010006),
                            Bool("exported", true, 0x01010010)),
                        new Node("receiver", String("name", "Boot", 0x01010003)).Add(new Node("intent-filter").Add(
                            new Node("action", String("name", "android.intent.action.BOOT_COMPLETED", 0x01010003)))),
                        new Node("provider", String("name", ".Files", 0x01010003), String("authorities", "com.example.app.files", 0x01010018),
                            Bool("grantUriPermissions", true, 0x0101001b)),
                        new Node("meta-data", String("name", "com.example.KEY", 0x01010003), String("value", "abc", 0x01010024))));
        return AxmlWriter.Write(root);
    }

    public static byte[] NetworkSecurityConfig() => AxmlWriter.Write(new Node("network-security-config").Add(
        new Node("domain-config", new Attr(null, "cleartextTrafficPermitted", 0, 0x12, uint.MaxValue)).Add(
            new Node("domain", new Attr(null, "includeSubdomains", 0, 0x12, uint.MaxValue)) { Text = "example.com" })));

    /// <summary>An APK with the sample manifest and resources plus <paramref name="extra"/> entries.</summary>
    public static byte[] Apk(int targetSdk = 30, params (string Name, byte[] Data)[] extra)
    {
        var resources = Resources(); // assigns the ids the manifest references
        return ContainerFixtures.Zip([
            ("AndroidManifest.xml", Manifest(targetSdk)),
            ("resources.arsc", resources),
            ("res/xml/network_security_config.xml", NetworkSecurityConfig()),
            ("res/layout/main.xml", AxmlWriter.Write(new Node("LinearLayout", Ref("text", AppName, 0x0101014f)))),
            ("assets/config.json", "{\"endpoint\":\"https://api.example.com\"}"u8.ToArray()),
            .. extra]);
    }

    public static string Save(TempDir dir, string name, byte[] bytes)
    {
        var path = dir.File(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }
}
