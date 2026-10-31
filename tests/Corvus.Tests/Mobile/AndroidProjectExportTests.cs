using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Services.Mobile;
using static Corvus.Tests.AxmlWriter;

namespace Corvus.Tests;

/// <summary>export_project on an Android package: a Gradle project with decoded manifest and resources, assets, jniLibs, and Java or smali code.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class AndroidProjectExportTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly FakeTool _fake = new();

    public void Dispose()
    {
        _fake.Dispose();
        _dir.Dispose();
    }

    private string Apk() => AndroidSamples.Save(_dir, "app.apk", AndroidSamples.Apk(30, ("classes.dex", AndroidSamples.Dex()),
        ("lib/arm64-v8a/libapp.so", [0x7F, (byte)'E', (byte)'L', (byte)'F']), ("META-INF/CERT.SF", "Signature-Version: 1.0\r\n"u8.ToArray()),
        ("okhttp3/publicsuffixes.gz", [1, 2, 3])));

    private string Read(string root, string relative) => File.ReadAllText(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));

    // Regression for 93a5e739: the files worker passes no progress callback, and the class count moved only inside it.
    [Fact]
    public async Task Without_JADX_and_without_a_progress_callback_export_writes_smali()
    {
        using var env = new EnvironmentScope().Set("CORVUS_JAVA_DECOMPILER", Path.Combine(_dir.Path, "missing.jar"));
        using var java = new JavaDecompilerService(new DexService());
        var r = await new AndroidProjectExport(new DexService(), java).Export(Apk(), _dir.File("out"), null, default);
        Assert.Equal("smali", r.Sources);
        Assert.Equal(0, r.SourceFailures);
    }

    [Fact]
    public async Task Without_JADX_export_decodes_resources_and_writes_smali_per_class()
    {
        using var env = new EnvironmentScope().Set("CORVUS_JAVA_DECOMPILER", Path.Combine(_dir.Path, "missing.jar"));
        using var java = new JavaDecompilerService(new DexService());
        var export = new AndroidProjectExport(new DexService(), java);
        var apk = Apk();
        var progress = new List<string>();
        var r = await export.Export(apk, _dir.File("out"), (_, _, s) => progress.Add(s), default);
        var root = r.Directory;
        Assert.Equal("smali", r.Sources);
        Assert.Contains(r.Notes, n => n.StartsWith("Sources are smali", StringComparison.Ordinal));

        Assert.Contains("rootProject.name = \"com.example.app\"", Read(root, "settings.gradle"));
        var build = Read(root, "app/build.gradle");
        Assert.Contains("applicationId 'com.example.app'", build);
        Assert.Contains("minSdk 24", build);
        Assert.Contains("targetSdk 30", build);
        Assert.Contains("package=\"com.example.app\"", Read(root, "app/src/main/AndroidManifest.xml"));
        Assert.Contains("cleartextTrafficPermitted", Read(root, "app/src/main/res/xml/network_security_config.xml"));
        Assert.Contains("@string/app_name", Read(root, "app/src/main/res/layout/main.xml"));
        Assert.Contains("<string name=\"app_name\">Example</string>", Read(root, "app/src/main/res/values/strings.xml"));
        Assert.Contains("<string name=\"app_name\">Exemplo</string>", Read(root, "app/src/main/res/values-pt-rBR/strings.xml"));
        Assert.Contains("<bool name=\"is_tablet\">false</bool>", Read(root, "app/src/main/res/values/bools.xml"));
        var arrays = Read(root, "app/src/main/res/values/arrays.xml");
        Assert.Contains("<item>@string/app_name</item>", arrays);
        Assert.Contains("<item>7</item>", arrays);
        Assert.Contains("api.example.com", Read(root, "app/src/main/assets/config.json"));
        Assert.True(File.Exists(Path.Combine(root, "app", "src", "main", "jniLibs", "arm64-v8a", "libapp.so")));
        Assert.True(File.Exists(Path.Combine(root, "app", "src", "main", "resources", "okhttp3", "publicsuffixes.gz")));
        Assert.False(Directory.Exists(Path.Combine(root, "app", "src", "main", "resources", "META-INF")));

        Assert.Contains(".class public Lcom/example/app/Main;", Read(root, "app/src/main/smali/com/example/app/Main.smali"));
        Assert.True(File.Exists(Path.Combine(root, "app", "src", "main", "smali", "com", "example", "app", "Main$Inner.smali")));
        Assert.Equal(r.Classes, Directory.GetFiles(Path.Combine(root, "app", "src", "main", "smali"), "*.smali", SearchOption.AllDirectories).Length);
        Assert.Contains(AndroidSamples.Main, progress);

        Assert.Equal(ErrorCode.Conflict, (await Assert.ThrowsAsync<ToolError>(() => export.Export(apk, root, null, default))).Code);
    }

    /// <summary>R8 names classes a and A in one package: on a case-insensitive file system the second gets its own file, not a conflict.</summary>
    [Fact]
    public async Task Classes_differing_only_in_case_get_their_own_files()
    {
        using var env = new EnvironmentScope().Set("CORVUS_JAVA_DECOMPILER", Path.Combine(_dir.Path, "missing.jar"));
        using var java = new JavaDecompilerService(new DexService());
        var dex = new DexBuilder();
        dex.Class("Lp/a;");
        dex.Class("Lp/A;");
        var apk = AndroidSamples.Save(_dir, "case.apk", AndroidSamples.Apk(30, ("classes.dex", dex.Build())));
        var r = await new AndroidProjectExport(new DexService(), java).Export(apk, _dir.File("out"), null, default);
        var ext = r.Sources == "java" ? ".java" : ".smali";
        var files = Directory.GetFiles(Path.Combine(r.Directory, "app", "src", "main", r.Sources, "p")).Select(Path.GetFileName).Order(StringComparer.Ordinal).ToList();
        Assert.Equal(["A" + ext, "a_2" + ext], files);
        Assert.Contains(r.Notes, n => n.StartsWith("1 class(es) differ from another only in letter case", StringComparison.Ordinal));
    }

    [Fact]
    public async Task With_JADX_export_writes_one_Java_file_per_top_level_class()
    {
        var jar = Path.Combine(_fake.Directory, "jadx-headless-mcp-0.7.1-all.jar");
        File.WriteAllBytes(jar, [0x50, 0x4B, 3, 4]);
        _fake.Set("mcp", new JsonObject());
        using var env = new EnvironmentScope().Set("CORVUS_JAVA", _fake.CopyAs("java")).Set("CORVUS_JAVA_DECOMPILER", jar);
        using var java = new JavaDecompilerService(new DexService()) { Environment = _fake.Environment };
        var r = await new AndroidProjectExport(new DexService(), java).Export(Apk(), _dir.File("out"), null, default);
        Assert.Equal("java", r.Sources);
        var javaRoot = Path.Combine(r.Directory, "app", "src", "main", "java");
        Assert.Equal("// source of com.example.app.Main", Read(javaRoot, "com/example/app/Main.java"));
        // In its outer class's file.
        Assert.False(File.Exists(Path.Combine(javaRoot, "com", "example", "app", "Main$Inner.java")));
        Assert.Equal(r.Classes, Directory.GetFiles(javaRoot, "*.java", SearchOption.AllDirectories).Length);
        Assert.False(Directory.Exists(Path.Combine(r.Directory, "app", "src", "main", "smali")));
    }

    /// <summary>aapt2 rejects numbers for enum and flag attributes: the exported manifest names them; values without a name stay numbers.</summary>
    [Fact]
    public async Task Manifest_enum_and_flag_values_are_written_by_name()
    {
        const byte Hex = 0x11;
        var manifest = Write(new Node("manifest", String("package", "com.example.app", ns: null), Int("installLocation", 1, 0x010102b7))
            .Add(new Node("permission", String("name", "com.example.app.P", 0x01010003), new Attr(Android, "protectionLevel", 0x01010009, Hex, 0x12)),
                new Node("application").Add(new Node("activity", String("name", ".Main", 0x01010003), Int("launchMode", 2, 0x0101001d),
                    Int("screenOrientation", -1, 0x0101001e), new Attr(Android, "configChanges", 0x0101001f, Hex, 0x4a0),
                    new Attr(Android, "windowSoftInputMode", 0x0101022b, Hex, 0x12), Int("uiOptions", 7, 0x01010398)))));
        var apk = AndroidSamples.Save(_dir, "enums.apk", ContainerFixtures.Zip([("AndroidManifest.xml", manifest)]));
        using var env = new EnvironmentScope().Set("CORVUS_JAVA_DECOMPILER", Path.Combine(_dir.Path, "missing.jar"));
        using var java = new JavaDecompilerService(new DexService());
        var r = await new AndroidProjectExport(new DexService(), java).Export(apk, _dir.File("out"), null, default);
        var xml = Read(r.Directory, "app/src/main/AndroidManifest.xml");
        Assert.Contains("android:installLocation=\"internalOnly\"", xml);
        Assert.Contains("android:protectionLevel=\"signature|privileged\"", xml);
        Assert.Contains("android:launchMode=\"singleTask\"", xml);
        Assert.Contains("android:screenOrientation=\"unspecified\"", xml);
        Assert.Contains("android:configChanges=\"keyboardHidden|orientation|screenSize\"", xml);
        Assert.Contains("android:windowSoftInputMode=\"stateHidden|adjustResize\"", xml);
        Assert.Contains("android:uiOptions=\"7\"", xml);
    }

    /// <summary>
    /// Every enum and flag value of the framework's manifest attributes (AOSP core/res/res/values/attrs_manifest.xml) is named
    /// as the framework names it; several attributes and flags were missing, so their values stayed numbers aapt2 rejects.
    /// </summary>
    [Fact]
    public void Manifest_enum_and_flag_names_match_the_framework_attributes()
    {
        // name=value pairs per attribute, as attrs_manifest.xml declares them (aliases such as protectionLevel "system" left out).
        const string Framework = """
            protectionLevel normal=0 dangerous=1 signature=2 signatureOrSystem=3 internal=4 privileged=0x10 development=0x20 appop=0x40 pre23=0x80 installer=0x100 verifier=0x200 preinstalled=0x400 setup=0x800 instant=0x1000 runtime=0x2000 oem=0x4000 vendorPrivileged=0x8000 textClassifier=0x10000 configurator=0x80000 incidentReportApprover=0x100000 appPredictor=0x200000 module=0x400000 companion=0x800000 retailDemo=0x1000000 recents=0x2000000 role=0x4000000 knownSigner=0x8000000
            permissionGroupFlags personalInfo=0x1
            permissionFlags costsMoney=0x1 removed=0x2 hardRestricted=0x4 softRestricted=0x8 immutablyRestricted=0x10 installerExemptIgnored=0x20
            rotationAnimation rotate=0 crossfade=1 jumpcut=2 seamless=3
            launchMode standard=0 singleTop=1 singleTask=2 singleInstance=3 singleInstancePerTask=4
            screenOrientation unspecified=-1 landscape=0 portrait=1 user=2 behind=3 sensor=4 nosensor=5 sensorLandscape=6 sensorPortrait=7 reverseLandscape=8 reversePortrait=9 fullSensor=10 userLandscape=11 userPortrait=12 fullUser=13 locked=14
            recreateOnConfigChanges mcc=0x1 mnc=0x2
            configChanges mcc=0x1 mnc=0x2 locale=0x4 touchscreen=0x8 keyboard=0x10 keyboardHidden=0x20 navigation=0x40 orientation=0x80 screenLayout=0x100 uiMode=0x200 screenSize=0x400 smallestScreenSize=0x800 density=0x1000 layoutDirection=0x2000 colorMode=0x4000 grammaticalGender=0x8000 fontScale=0x40000000 fontWeightAdjustment=0x10000000 assetsPaths=0x80000000 resourcesUnused=0x8000000
            reqTouchScreen undefined=0 notouch=1 stylus=2 finger=3
            reqKeyboardType undefined=0 nokeys=1 qwerty=2 twelvekey=3
            reqNavigation undefined=0 nonav=1 dpad=2 trackball=3 wheel=4
            installLocation auto=0 internalOnly=1 preferExternal=2
            uiOptions none=0 splitActionBarWhenNarrow=1
            persistableMode persistRootOnly=0 persistNever=1 persistAcrossReboots=2
            documentLaunchMode none=0 intoExisting=1 always=2 never=3
            lockTaskMode normal=0 never=1 always=2 if_whitelisted=3
            foregroundServiceType dataSync=0x1 mediaPlayback=0x2 phoneCall=0x4 location=0x8 connectedDevice=0x10 mediaProjection=0x20 camera=0x40 microphone=0x80 health=0x100 remoteMessaging=0x200 systemExempted=0x400 shortService=0x800 mediaProcessing=0x2000 specialUse=0x40000000
            gwpAsanMode default=-1 never=0 always=1
            memtagMode default=-1 off=0 async=1 sync=2
            pageSizeCompat enabled=32 disabled=64
            intentMatchingFlags none=0x1 enforceIntentFilter=0x2 allowNullAction=0x4
            appCategory game=0 audio=1 video=2 image=3 social=4 news=5 maps=6 productivity=7 accessibility=8
            autoRevokePermissions allowed=0 discouraged=1 disallowed=2
            rollbackDataPolicy restore=0 wipe=1 retain=2
            usesPermissionFlags neverForLocation=0x10000
            colorMode default=0 wideColorGamut=1 hdr=2
            requireContentUriPermissionFromCaller none=0 read=1 write=2 readOrWrite=3 readAndWrite=4
            screenSize small=200 normal=300 large=400 xlarge=500
            screenDensity ldpi=120 mdpi=160 hdpi=240 xhdpi=320 xxhdpi=480 xxxhdpi=640
            windowSoftInputMode stateUnspecified=0 stateUnchanged=1 stateHidden=2 stateAlwaysHidden=3 stateVisible=4 stateAlwaysVisible=5 adjustResize=0x10 adjustPan=0x20 adjustNothing=0x30
            """;
        var wrong = new List<string>();
        foreach (var line in Framework.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = line.Split(' ');
            foreach (var pair in parts.Skip(1))
            {
                var (name, text) = (pair[..pair.IndexOf('=')], pair[(pair.IndexOf('=') + 1)..]);
                uint value = text.StartsWith("0x", StringComparison.Ordinal) ? Convert.ToUInt32(text[2..], 16) : unchecked((uint)int.Parse(text, System.Globalization.CultureInfo.InvariantCulture));
                // A protection level always names its base: a flag is checked with "signature".
                if (parts[0] == "protectionLevel" && value >= 0x10) (value, name) = (value | 2, "signature|" + name);
                if (AndroidAttributes.Symbolic(parts[0], value) is var got && got != name)
                    wrong.Add($"{parts[0]} {text}: {got ?? "(none)"}, framework {name}");
            }
        }
        Assert.True(wrong.Count == 0, string.Join("\n", wrong));
    }

    /// <summary>A shrunk build renames resource files; they are written where their table entry says they belong.</summary>
    [Fact]
    public async Task Renamed_resource_files_go_to_their_canonical_path()
    {
        var res = new ArscWriter(0x7f, "com.example.app");
        res.String("string", "app_name", "Example");
        res.String("xml", "rules", "res/a1.xml");
        var apk = AndroidSamples.Save(_dir, "shrunk.apk", ContainerFixtures.Zip([
            ("AndroidManifest.xml", AndroidSamples.Manifest()),
            ("resources.arsc", res.Build()),
            ("res/a1.xml", Write(new Node("full-backup-content")))]));
        using var env = new EnvironmentScope().Set("CORVUS_JAVA_DECOMPILER", Path.Combine(_dir.Path, "missing.jar"));
        using var java = new JavaDecompilerService(new DexService());
        var r = await new AndroidProjectExport(new DexService(), java).Export(apk, _dir.File("out"), null, default);
        Assert.Contains("<full-backup-content", Read(r.Directory, "app/src/main/res/xml/rules.xml"));
        Assert.False(File.Exists(Path.Combine(r.Directory, "app", "src", "main", "res", "a1.xml")));
        // No DEX code.
        Assert.Equal("none", r.Sources);
    }
}
