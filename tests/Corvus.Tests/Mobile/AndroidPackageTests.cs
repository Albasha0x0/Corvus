using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Services.Analysis;
using Corvus.Services.Mobile;

namespace Corvus.Tests;

/// <summary>get_android_manifest, list_android_resources, get_android_resource and the Android facts of summarize_file on synthetic packages.</summary>
public sealed class AndroidPackageTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AndroidPackageService _service = new();

    public void Dispose() => _dir.Dispose();

    private string Apk(int targetSdk = 30, params (string, byte[])[] extra) => AndroidSamples.Save(_dir, $"app{targetSdk}-{extra.Length}.apk", AndroidSamples.Apk(targetSdk, extra));

    [Fact]
    public void Manifest_summary_resolves_references_and_applies_the_exported_rules()
    {
        var m = _service.Manifest(Apk());
        Assert.Equal(("com.example.app", "42", "1.2", 24, 30, 34), (m.Package, m.VersionCode, m.VersionName, m.MinSdk, m.TargetSdk, m.CompileSdk));
        Assert.Equal(["android.permission.INTERNET", "android.permission.CAMERA", "android.permission.READ_EXTERNAL_STORAGE"], m.Permissions.Select(p => p.Name));
        Assert.True(m.Permissions[1].Sdk23Only);
        Assert.Equal(28, m.Permissions[2].MaxSdkVersion);
        Assert.Equal("signature|privileged", m.DeclaredPermissions.Single().ProtectionLevel);
        Assert.Equal(("com.example.app.App", "Example", true, true), (m.Application.Name, m.Application.Label, m.Application.Debuggable, m.Application.UsesCleartextTraffic));
        Assert.Equal("@xml/network_security_config = res/xml/network_security_config.xml", m.Application.NetworkSecurityConfig);
        Assert.Equal(["com.other.app"], m.Queries.Packages);

        AndroidComponent C(string name) => m.Components.Single(c => c.Name == name);
        var main = C("com.example.app.Main");
        Assert.True(main.Launcher);
        Assert.Equal((true, "explicit"), (main.EffectiveExported, main.ExportedReason));
        var link = C(AndroidSamples.LinkPackage + ".LinkActivity");
        Assert.Null(link.Exported);
        Assert.True(link.EffectiveExported);
        Assert.Contains("implied by an intent filter", link.ExportedReason);
        Assert.Equal(["https://example.com/open"], link.DeepLinks);
        Assert.True(link.IntentFilters.Single().AutoVerify);
        Assert.Equal("com.example.app.Main", C("com.example.app.Alias").TargetActivity);
        Assert.False(C("com.example.app.Alias").EffectiveExported);
        Assert.Equal("com.example.app.PRIVATE", C("com.example.app.Sync").Permission);
        Assert.True(C("com.example.app.Boot").EffectiveExported);
        var provider = C("com.example.app.Files");
        Assert.Equal(("com.example.app.files", false, true), (provider.Authorities, provider.EffectiveExported, provider.GrantUriPermissions));
        Assert.Equal("abc", m.MetaData.Single().Value);

        Assert.Contains(m.Highlights, h => h.StartsWith("android:debuggable=true", StringComparison.Ordinal));
        Assert.Contains(m.Highlights, h => h.StartsWith("Cleartext", StringComparison.Ordinal));
        Assert.Contains(m.Highlights, h => h.Contains("exported component(s) without a permission", StringComparison.Ordinal) && h.Contains("LinkActivity", StringComparison.Ordinal) && h.Contains("Boot", StringComparison.Ordinal));
        Assert.Contains(m.Highlights, h => h.StartsWith("Deep links: https://example.com/open", StringComparison.Ordinal));
        Assert.Empty(m.Issues);
    }

    [Fact]
    public void Manifest_for_API_31_flags_a_filter_without_exported()
    {
        var m = _service.Manifest(Apk(targetSdk: 33));
        var link = m.Components.Single(c => c.Name.EndsWith("LinkActivity", StringComparison.Ordinal));
        Assert.Contains("Android 12+ refuses to install", link.ExportedReason);
        Assert.Contains(m.Highlights, h => h.Contains("has an intent filter but no android:exported", StringComparison.Ordinal));
    }

    [Fact]
    public void Resources_filter_by_type_name_and_config_with_bags_and_files()
    {
        var path = Apk();
        var all = _service.Resources(path, null, null, null, 0, 500);
        Assert.Equal(8, all.Total);
        Assert.Equal(new Dictionary<string, int> { ["array"] = 1, ["bool"] = 2, ["layout"] = 1, ["string"] = 3, ["xml"] = 1 }, all.Types);
        var names = _service.Resources(path, "string", "app_*", null, 0, 500);
        Assert.Equal(["", "pt-rBR"], names.Items.Select(r => r.Config));
        Assert.Equal("Exemplo", names.Items[1].Value);
        var night = Assert.Single(_service.Resources(path, null, null, "night-xxhdpi-v31", 0, 500).Items);
        Assert.Equal(("bool", "true"), (night.ValueType, night.Value));
        Assert.Equal(("file", "res/xml/network_security_config.xml"), (_service.Resources(path, "xml", null, "default", 0, 500).Items.Single().ValueType,
            _service.Resources(path, "xml", null, null, 0, 500).Items.Single().Value));
        Assert.Equal("[0]=@string/app_name; [1]=7", _service.Resources(path, "array", null, null, 0, 500).Items.Single().Value);
        var page = _service.Resources(path, null, null, null, 2, 3);
        Assert.Equal((3, 2, 8), (page.Items.Count, page.Offset, page.Total));
    }

    [Fact]
    public void Resource_by_path_or_name_decodes_binary_XML_and_saves()
    {
        var path = Apk();
        var manifest = _service.Resource(path, "AndroidManifest.xml", null, false).Text;
        Assert.Contains("android:label=\"@string/app_name\"", manifest);
        Assert.Contains("android:debuggable=\"true\"", manifest);
        var nsc = _service.Resource(path, "@xml/network_security_config", null, false).Text;
        Assert.Contains("<domain includeSubdomains=\"true\">example.com</domain>", nsc);
        Assert.Contains("Example", _service.Resource(path, "@string/app_name", null, false).Text);
        Assert.Contains("[pt-rBR] string: Exemplo", _service.Resource(path, $"0x{AndroidSamples.AppName:x8}", null, false).Text);
        Assert.Contains("api.example.com", _service.Resource(path, "assets/config.json", null, false).Text);

        var saved = _dir.File("layout.bin");
        Assert.StartsWith("Wrote res/layout/main.xml", _service.Resource(path, "@layout/main", saved, false).Text);
        Assert.True(AxmlDocument.IsAxml(File.ReadAllBytes(saved)));
        Assert.Equal(ErrorCode.Conflict, Assert.Throws<ToolError>(() => _service.Resource(path, "@layout/main", saved, false)).Code);

        var missing = Assert.Throws<ToolError>(() => _service.Resource(path, "res/xml/network_security.xml", null, false));
        Assert.Equal(ErrorCode.NotFound, missing.Code);
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => _service.Resource(path, "@string/nope", null, false)).Code);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => _service.Resource(path, "@nope", null, false)).Code);
    }

    [Fact]
    public void Split_sets_are_read_through_their_base_APK_and_other_zips_are_refused()
    {
        var set = AndroidSamples.Save(_dir, "app.apks", ContainerFixtures.Zip(("splits/config.arm64_v8a.apk", ContainerFixtures.Zip(("lib/arm64-v8a/libx.so", [1]))),
            ("splits/base-master.apk", AndroidSamples.Apk()), ("toc.pb", [0])));
        Assert.Equal("com.example.app", _service.Manifest(set).Package);
        using (var p = AndroidPackage.Open(set))
        {
            Assert.Equal("split set", p.Kind);
            Assert.Equal(["splits/base-master.apk", "splits/config.arm64_v8a.apk"], p.SplitApks);
        }
        var zip = AndroidSamples.Save(_dir, "plain.zip", ContainerFixtures.Zip(("a.txt", [1])));
        Assert.Equal(ErrorCode.Unsupported, Assert.Throws<ToolError>(() => _service.Manifest(zip)).Code);
        Assert.Equal(ErrorCode.MalformedInput, Assert.Throws<ToolError>(() => _service.Manifest(Env.FixturePath)).Code);
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => _service.Manifest(_dir.File("none.apk"))).Code);
    }

    [Fact]
    public void Summarize_reports_runtimes_with_evidence_ABIs_DEX_and_signature()
    {
        byte[] metadata = [0xAF, 0x1B, 0xB1, 0xFA, 31, 0, 0, 0];
        var path = Apk(30,
            ("classes.dex", "dex\n035\0"u8.ToArray()), ("classes2.dex", "dex\n035\0"u8.ToArray()), ("kotlin/kotlin.kotlin_builtins", [1]),
            ("lib/arm64-v8a/libil2cpp.so", [0x7F]), ("lib/armeabi-v7a/libil2cpp.so", [0x7F]), ("assets/bin/Data/Managed/Metadata/global-metadata.dat", metadata),
            ("lib/arm64-v8a/libflutter.so", [0x7F]), ("lib/arm64-v8a/libapp.so", [0x7F]),
            ("lib/arm64-v8a/libassembly-store.so", [0x7F]), ("assets/index.android.bundle", [0xC6, 0x1F, 0xBC, 0x03, 0xC1, 0x03, 0x19, 0x1F]));
        using var workspace = new AssemblyWorkspace(new ServerOptions());
        var summary = new InspectionService(workspace).Summarize(null, path, default);
        var a = summary.Android!;
        Assert.Equal(("apk", "com.example.app", "1.2", 24, 30), (a.Kind, a.Package, a.VersionName, a.MinSdk, a.TargetSdk));
        Assert.Equal(["dotnet-android", "aot", "flutter", "react-native", "kotlin"], a.Runtimes.Select(r => r.Family));
        Assert.Equal("AOT: metadata header readable", a.Runtimes[1].Note);
        Assert.Contains("assets/bin/Data/Managed/Metadata/global-metadata.dat", a.Runtimes[1].Evidence);
        Assert.StartsWith("React Native: Hermes bytecode bundle;", a.Runtimes[3].Note);
        Assert.Equal(["arm64-v8a", "armeabi-v7a"], a.Abis);
        Assert.Equal((2, 16L), (a.DexFiles, a.DexBytes));
        Assert.Equal((6, 4), (a.Components, a.ExportedComponents));
        Assert.StartsWith("unsigned", a.Signature);
        Assert.Contains(summary.Highlights, h => h.StartsWith("android:debuggable=true", StringComparison.Ordinal));
        Assert.Contains(summary.Highlights, h => h.StartsWith("APK signature: unsigned", StringComparison.Ordinal));

        var tampered = Apk(31, ("lib/arm64-v8a/libil2cpp.so", [0x7F]), ("assets/bin/Data/Managed/Metadata/global-metadata.dat", [1, 2, 3, 4]));
        var aot = new InspectionService(workspace).Summarize(null, tampered, default).Android!.Runtimes.Single();
        Assert.Contains("encrypted or tampered", aot.Note);
    }
}
