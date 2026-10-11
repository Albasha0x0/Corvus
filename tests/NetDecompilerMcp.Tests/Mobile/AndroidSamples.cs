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
                        new Node("activity", String("name", LinkPackage + ".LinkActivity", 0x01010003)).Add(filter("https", "example.com")),
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

    public const string Main = "Lcom/example/app/Main;", Helper = "Lcom/example/app/Helper;";

    /// <summary>The Java callable wrapper of MyApp.LinkActivity in assembly MyApp, named as the .NET for Android build names it.</summary>
    public static readonly string LinkPackage = "crc64" + NetDecompilerMcp.Services.Mobile.JavaDotNetMap.Crc64("MyApp:MyApp");
    public static readonly string Link = $"L{LinkPackage}/LinkActivity;";
    public const string NameField = Main + "->name:Ljava/lang/String;", CountField = Main + "->COUNT:I";
    public const string Log = Helper + "->log(Ljava/lang/String;)V", ComputeInt = Main + "->compute(I)I", ComputeString = Main + "->compute(Ljava/lang/String;)I";

    /// <summary>
    /// A DEX with an activity (overloads, a field written and read, a string, a switch, array data, a try block, line numbers), a helper
    /// with Kotlin metadata, an inner class, and a Java callable wrapper with a native method, as Xamarin generates them.
    /// </summary>
    public static byte[] Dex()
    {
        var b = new DexBuilder();
        var main = b.Class(Main, 1, "Landroid/app/Activity;", "Main.java").Field("name", "Ljava/lang/String;", 2).Field("COUNT", "I", 0x19, 7);
        main.Annotations.Add(("Ldalvik/annotation/MemberClasses;", 2, [("value", new[] { "Lcom/example/app/Main$Inner;" })]));
        main.Method("<init>", "V", [], 1, Asm.Invoke(0x70, "Landroid/app/Activity;-><init>()V", 0), Asm.ReturnVoid()).Registers = 1;
        var onCreate = main.Method("onCreate", "V", ["Landroid/os/Bundle;"], 4,
            Asm.Invoke(0x6f, "Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V", 1, 2),
            Asm.ConstString(0, "https://api.example.com/v1"),
            Asm.Instance(0x5b, 0, 1, NameField),
            Asm.Invoke(0x71, Log, 0),
            Asm.ReturnVoid());
        onCreate.Registers = 3;
        onCreate.Lines.AddRange([(0, 10), (3, 11), (5, 12), (7, 13)]);
        onCreate.ParameterNames = ["savedInstanceState"];
        main.Method("compute", "I", ["I"], 1,
            Asm.Static(0x60, 0, CountField),
            Asm.AddIntLit8(0, 2, 42),
            Asm.IfEqz(0, 4),
            Asm.Instance(0x54, 0, 1, NameField),
            Asm.Return(0x0f, 2)).Registers = 3;
        main.Method("compute", "I", ["Ljava/lang/String;"], 1,
            Asm.Invoke(0x6e, "Ljava/lang/String;->length()I", 2),
            Asm.Op11x(0x0a, 0),
            Asm.Return(0x0f, 0)).Registers = 3;
        main.Method("pick", "I", ["I"], 9,
            Asm.PackedSwitch(1, 8),            // 0: switch on p0 (v1); the payload at 8 (payloads start 4-byte aligned)
            Asm.Const4(0, -1),                 // 3
            Asm.Return(0x0f, 0),               // 4
            Asm.ConstHigh16(0, 0x3f800000),    // 5: 1.0f
            Asm.Return(0x0f, 0),               // 7
            Asm.PackedSwitchPayload(10, 5, 3)).Registers = 2;
        var guarded = main.Method("guarded", "V", [], 9,
            Asm.Invoke(0x71, Log, 0),
            Asm.ReturnVoid(),
            Asm.Op11x(0x0d, 0),
            Asm.ReturnVoid());
        guarded.Registers = 1;
        guarded.Tries.Add(new(0, 3, [("Ljava/lang/Exception;", 4), (null, 4)]));
        var data = main.Method("data", "V", [], 9,
            Asm.FillArrayData(0, 4), Asm.ReturnVoid(), Asm.ArrayPayload(4, 1, -2, 0x7fffffff));
        data.Registers = 1;
        main.Method("abstractLike", "V", [], 0x101); // native: no code

        var helper = b.Class(Helper, 0x11, source: "Helper.kt").Field("level", "I", 9);
        helper.Annotations.Add(("Lkotlin/Metadata;", 1, [("k", 1), ("d2", new[] { "Lcom/example/app/Helper;", "log", "", "msg", "" })]));
        helper.Method("log", "V", ["Ljava/lang/String;"], 9,
            Asm.ConstString(0, "Example"),
            Asm.Invoke(0x71, "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I", 0, 1),
            Asm.Static(0x67, 0, Helper + "->level:I"),
            Asm.ReturnVoid()).Registers = 2;

        b.Class("Lcom/example/app/Main$Inner;", 0x10, source: "Main.java");
        var link = b.Class(Link, 1, "Landroid/app/Activity;", "LinkActivity.java");
        link.Interfaces.Add("Lmono/android/IGCUserPeer;");
        link.Method("onCreate", "V", ["Landroid/os/Bundle;"], 1,
            Asm.Invoke(0x70, Link + "->n_onCreate(Landroid/os/Bundle;)V", 1, 2), Asm.ReturnVoid()).Registers = 3;
        link.Method("n_onCreate", "V", ["Landroid/os/Bundle;"], 0x102);
        return b.Build();
    }

    /// <summary>A .NET for Android shaped package: the sample DEX, a Mono.Android with bindings and an app assembly (XALZ compressed).</summary>
    public static string SaveXamarin(TempDir dir)
    {
        var (mono, app) = XamarinSample.Build();
        return Save(dir, "xamarin.apk", Apk(30, ("classes.dex", Dex()), ("assemblies/Mono.Android.dll", mono), ("assemblies/MyApp.dll", ContainerFixtures.Xalz(app)),
            ("lib/arm64-v8a/libmonodroid.so", [0x7F, (byte)'E', (byte)'L', (byte)'F'])));
    }

    public static string Save(TempDir dir, string name, byte[] bytes)
    {
        var path = dir.File(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }
}
