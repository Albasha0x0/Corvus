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
        ("lib/arm64-v8a/libgame.so", [0x7F, (byte)'E', (byte)'L', (byte)'F']), ("META-INF/CERT.SF", "Signature-Version: 1.0\r\n"u8.ToArray()),
        ("okhttp3/publicsuffixes.gz", [1, 2, 3])));

    private string Read(string root, string relative) => File.ReadAllText(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));

    [Fact]
    public async Task WithoutJadx_ResourcesDecodedAndSmaliPerClass()
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
        Assert.True(File.Exists(Path.Combine(root, "app", "src", "main", "jniLibs", "arm64-v8a", "libgame.so")));
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
    public async Task ClassesDifferingOnlyInCaseGetTheirOwnFiles()
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
    public async Task WithJadx_OneJavaFilePerTopLevelClass()
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
        Assert.False(File.Exists(Path.Combine(javaRoot, "com", "example", "app", "Main$Inner.java"))); // in its outer class's file
        Assert.Equal(r.Classes, Directory.GetFiles(javaRoot, "*.java", SearchOption.AllDirectories).Length);
        Assert.False(Directory.Exists(Path.Combine(r.Directory, "app", "src", "main", "smali")));
    }

    /// <summary>aapt2 rejects numbers for enum and flag attributes: the exported manifest names them; values without a name stay numbers.</summary>
    [Fact]
    public async Task ManifestEnumAndFlagValuesAreWrittenByName()
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

    /// <summary>A shrunk build renames resource files; they are written where their table entry says they belong.</summary>
    [Fact]
    public async Task RenamedResourceFilesGoToTheirCanonicalPath()
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
        Assert.Equal("none", r.Sources); // no DEX code
    }
}
