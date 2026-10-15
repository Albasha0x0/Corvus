using System.Diagnostics;
using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Services.Analysis;
using Corvus.Tests.NativeFormats;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>survey_features on apps: MASVS rules over DEX code, the manifest and network security config, and Mach-O images.</summary>
public sealed class MobileRulesTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    private const string App = "Lcom/example/app/Web;", WebView = "Landroid/webkit/WebView;", Settings = "Landroid/webkit/WebSettings;";

    /// <summary>
    /// App code: a WebView bridge, JavaScript on and off, a TLS-error proceed, a trust-all manager, a hostname verifier that
    /// delegates to a lambda returning true, an ECB cipher, a key built from a string literal, a DexClassLoader and a su path;
    /// library code (com.google): an MD5 digest only there.
    /// </summary>
    private static byte[] AppDex()
    {
        var b = new DexBuilder();
        var web = b.Class(App);
        web.Method("setup", "V", [WebView], 1,
            Asm.Invoke(0x6e, $"{WebView}->getSettings(){Settings}", 2),
            Asm.Op11x(0x0c, 0),
            Asm.Const4(1, 1),
            Asm.Invoke(0x6e, $"{Settings}->setJavaScriptEnabled(Z)V", 0, 1),
            Asm.Const4(1, 0),
            Asm.Invoke(0x6e, $"{Settings}->setAllowFileAccessFromFileURLs(Z)V", 0, 1),
            Asm.ConstString(1, "Android"),
            Asm.Invoke(0x6e, $"{WebView}->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V", 2, 2, 1),
            Asm.ReturnVoid()).Registers = 3;
        web.Method("onReceivedSslError", "V", [WebView, "Landroid/webkit/SslErrorHandler;", "Landroid/net/http/SslError;"], 1,
            Asm.Invoke(0x6e, "Landroid/webkit/SslErrorHandler;->proceed()V", 2), Asm.ReturnVoid()).Registers = 4;

        var trust = b.Class("Lcom/example/app/Trust;");
        trust.Interfaces.Add("Ljavax/net/ssl/X509TrustManager;");
        trust.Method("checkServerTrusted", "V", ["[Ljava/security/cert/X509Certificate;", "Ljava/lang/String;"], 1,
            Asm.ConstString(0, "chain"), Asm.Invoke(0x71, "Lkotlin/jvm/internal/Intrinsics;->checkNotNullParameter(Ljava/lang/Object;Ljava/lang/String;)V", 1, 0),
            Asm.ReturnVoid()).Registers = 3;
        trust.Method("checkClientTrusted", "V", ["[Ljava/security/cert/X509Certificate;", "Ljava/lang/String;"], 1,
            Asm.NewInstance(0, "Ljava/security/cert/CertificateException;"), Asm.Op11x(0x27, 0)).Registers = 3;

        var verifier = b.Class("Lcom/example/app/Hosts$$Lambda;");
        verifier.Interfaces.Add("Ljavax/net/ssl/HostnameVerifier;");
        verifier.Method("verify", "Z", ["Ljava/lang/String;", "Ljavax/net/ssl/SSLSession;"], 1,
            Asm.Invoke(0x71, "Lcom/example/app/Hosts;->lambda$0(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z", 1, 2),
            Asm.Op11x(0x0a, 0), Asm.Return(0x0f, 0)).Registers = 3;
        b.Class("Lcom/example/app/Hosts;").Method("lambda$0", "Z", ["Ljava/lang/String;", "Ljavax/net/ssl/SSLSession;"], 9,
            Asm.Const4(0, 1), Asm.Return(0x0f, 0)).Registers = 3;

        b.Class("Lcom/example/app/Crypto;").Method("box", "V", [], 9,
            Asm.ConstString(0, "AES/ECB/PKCS5Padding"),
            Asm.Invoke(0x71, "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;", 0),
            Asm.ConstString(1, "0123456789abcdef"),
            Asm.Invoke(0x6e, "Ljava/lang/String;->getBytes()[B", 1),
            Asm.Op11x(0x0c, 1),
            Asm.NewInstance(2, "Ljavax/crypto/spec/SecretKeySpec;"),
            Asm.ConstString(3, "AES"),
            Asm.Invoke(0x70, "Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V", 2, 1, 3),
            Asm.ConstString(0, "/system/xbin/su"),
            Asm.NewInstance(1, "Ldalvik/system/DexClassLoader;"),
            Asm.Invoke(0x70, "Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V", 1, 0, 0, 0, 0),
            Asm.ReturnVoid()).Registers = 4;

        b.Class("Lcom/google/lib/Digest;").Method("md5", "V", [], 9,
            Asm.ConstString(0, "MD5"),
            Asm.Invoke(0x71, "Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;", 0),
            Asm.ReturnVoid()).Registers = 1;
        return b.Build();
    }

    private InspectionService.FeatureReport Survey(string path, string? category = "all") => new InspectionService(_ws).SurveyFeatures(null, path, category, default);

    private static Feature Rule(InspectionService.FeatureReport r, string id) =>
        r.Features.FirstOrDefault(f => f.Rule?.Id == id) ?? throw new Xunit.Sdk.XunitException($"{id} not in {string.Join(", ", r.Features.Select(f => f.Rule?.Id ?? f.Name))}");

    private static List<string> Locations(Feature f) => [.. f.Evidence.SelectMany(e => e.Locations)];

    [Fact]
    public void Webview_bridge_javascript_and_ssl_proceed_are_found_at_method_and_offset()
    {
        var path = _dir.File("app.dex");
        File.WriteAllBytes(path, AppDex());
        var r = Survey(path);
        Assert.Equal(["Lcom/example/app/Web;->setup(Landroid/webkit/WebView;)V +0xe: Landroid/webkit/WebView;->addJavascriptInterface(\"Android\")"], Locations(Rule(r, "android-webview-bridge")));
        Assert.Equal("MASVS-PLATFORM-2", Rule(r, "android-webview-bridge").Rule!.Masvs);
        Assert.Equal(["Lcom/example/app/Web;->setup(Landroid/webkit/WebView;)V +0x5: Landroid/webkit/WebSettings;->setJavaScriptEnabled(1)"], Locations(Rule(r, "android-webview-javascript")));
        Assert.DoesNotContain(r.Features, f => f.Rule?.Id == "android-webview-file-access"); // set to false
        Assert.Equal("high", Rule(r, "android-webview-ssl-proceed").Rule!.Severity);
    }

    [Fact]
    public void Trust_all_manager_and_a_lambda_accepting_any_host_are_found()
    {
        var path = _dir.File("app.dex");
        File.WriteAllBytes(path, AppDex());
        var r = Survey(path);
        Assert.Equal(["Lcom/example/app/Trust;->checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V +0x0: returns without checking the chain"],
            Locations(Rule(r, "android-trust-all")));
        Assert.Equal(["Lcom/example/app/Hosts$$Lambda;->verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z +0x0: returns true for any host"],
            Locations(Rule(r, "android-any-hostname")));
    }

    [Fact]
    public void Key_built_from_a_string_literal_is_followed_through_get_bytes()
    {
        var path = _dir.File("app.dex");
        File.WriteAllBytes(path, AppDex());
        var r = Survey(path);
        Assert.Equal(["Lcom/example/app/Crypto;->box()V +0xf: Ljavax/crypto/spec/SecretKeySpec;-><init>: string literal \"0123456789abcdef\", 128 bits"],
            Locations(Rule(r, "android-hardcoded-key")));
        Assert.Contains("\"AES/ECB/PKCS5Padding\"", Assert.Single(Locations(Rule(r, "android-weak-cipher"))));
        Assert.Single(Locations(Rule(r, "android-dynamic-code")));
        Assert.Equal("derived", Assert.Single(Rule(r, "android-root-detection").Evidence).Basis);
    }

    [Fact]
    public void Weakness_seen_only_in_library_code_is_left_out_with_a_note()
    {
        var path = _dir.File("app.dex");
        File.WriteAllBytes(path, AppDex());
        var r = Survey(path);
        Assert.DoesNotContain(r.Features, f => f.Rule?.Id == "android-weak-hash");
        Assert.Contains(r.Notes, n => n.Contains("left out: android-weak-hash (1)", StringComparison.Ordinal));
        Assert.All(r.Features, f => Assert.Equal("android", f.Rule?.Platform)); // the .NET and native rules do not run on DEX
    }

    [Fact]
    public void Manifest_and_network_security_config_give_debuggable_cleartext_and_user_certificates()
    {
        var path = _dir.File("app.apk");
        File.WriteAllBytes(path, AndroidSamples.Apk(30, ("classes.dex", AppDex())));
        var r = Survey(path, "MASVS-NETWORK");
        Assert.Equal(["AndroidManifest.xml: android:usesCleartextTraffic=true", "res/xml/network_security_config.xml: domain-config example.com (and subdomains): cleartextTrafficPermitted=true"],
            Locations(Rule(r, "android-cleartext")));
        Assert.All(r.Features, f => Assert.StartsWith("MASVS-NETWORK", f.Rule!.Masvs));
        Assert.Single(Locations(Rule(Survey(path), "android-debuggable")));
    }

    [Fact]
    [FuzzEntry(typeof(AndroidNetworkSecurityConfig))]
    public void Network_security_config_mutated_never_throws()
    {
        var failures = FormatFuzz.Run(PinnedConfig(), b => AndroidNetworkSecurityConfig.Of(AxmlDocument.Read(b)), 1500);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    [Fact]
    public void Network_security_config_reads_scopes_pins_and_trust_anchors()
    {
        var config = AndroidNetworkSecurityConfig.Of(AxmlDocument.Read(PinnedConfig()));
        Assert.Equal(["system", "user"], config.Scopes[0].TrustAnchors);
        var pinned = config.Scopes[1];
        Assert.Equal(["api.example.com"], pinned.Domains);
        Assert.Equal("2030-01-01", pinned.PinExpiration);
        Assert.Equal(["SHA-256/7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y="], pinned.Pins);
    }

    private static byte[] PinnedConfig() =>
        AxmlWriter.Write(new AxmlWriter.Node("network-security-config").Add(
            new AxmlWriter.Node("base-config").Add(new AxmlWriter.Node("trust-anchors").Add(
                new AxmlWriter.Node("certificates", AxmlWriter.String("src", "system", ns: null)),
                new AxmlWriter.Node("certificates", AxmlWriter.String("src", "user", ns: null)))),
            new AxmlWriter.Node("domain-config").Add(
                new AxmlWriter.Node("domain") { Text = "api.example.com" },
                new AxmlWriter.Node("pin-set", AxmlWriter.String("expiration", "2030-01-01", ns: null)).Add(
                    new AxmlWriter.Node("pin", AxmlWriter.String("digest", "SHA-256", ns: null)) { Text = "7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=" }))));

    /// <summary>
    /// An iOS app folder: the executable loads the addScriptMessageHandler:name: selector reference (adrp + ldr), refers to
    /// UIWebView and imports kSecAttrAccessibleAlways; Info.plist allows arbitrary loads.
    /// </summary>
    [Fact]
    public void Macho_app_rules_read_selectors_classes_imports_and_info_plist()
    {
        var w = new MachOWriter
        {
            FileType = 2,
            // adrp x8, 0x100005000; ldr x1, [x8, #0x300]; ret
            Text = [0x28, 0x00, 0x00, 0x90, 0x01, 0x81, 0x41, 0xF9, 0xC0, 0x03, 0x5F, 0xD6],
            Symbols = [new("_setupWebView", MachOWriter.TextOffset)],
            FunctionStarts = [MachOWriter.TextOffset],
        };
        var b = new AppleMetadataBuilder(w);
        var selrefs = b.Section("__DATA_CONST", "__objc_selrefs", 0x5300, 0x10000005);
        var classrefs = b.Section("__DATA_CONST", "__objc_classrefs", 0x5400);
        var got = b.Section("__DATA_CONST", "__got", 0x5500);
        b.Ptr(selrefs, b.Str("addScriptMessageHandler:name:"));
        b.Bind(classrefs, "_OBJC_CLASS_$_UIWebView");
        b.Bind(got, "_kSecAttrAccessibleAlways");
        b.Build();
        var bundle = Directory.CreateDirectory(Path.Combine(_dir.Path, "Demo.app")).FullName;
        File.WriteAllBytes(Path.Combine(bundle, "Demo"), w.Build());
        File.WriteAllText(Path.Combine(bundle, "Info.plist"), """
            <?xml version="1.0" encoding="UTF-8"?>
            <plist version="1.0"><dict><key>CFBundleExecutable</key><string>Demo</string>
            <key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict></dict></plist>
            """);
        var r = Survey(Path.Combine(bundle, "Demo"));
        Assert.Equal(["_setupWebView+0x4 @0x100001004: addScriptMessageHandler:name:"], Locations(Rule(r, "apple-webview-bridge")));
        Assert.Single(Locations(Rule(r, "apple-uiwebview")));
        Assert.StartsWith("import ", Assert.Single(Locations(Rule(r, "apple-keychain-always"))));
        Assert.Equal(["Info.plist: NSAppTransportSecurity NSAllowsArbitraryLoads=true"], Locations(Rule(r, "apple-ats-exception")));
    }

    [RequiresRealDataFact(RealData.MobileApps)]
    [Trait("Speed", "Slow")]
    public void Real_apps_per_rule_counts_and_time()
    {
        var root = RealData.Path(RealData.MobileApps);
        var apps = Directory.EnumerateFiles(root, "*.*", new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 2 })
            .Where(f => f.EndsWith(".apk", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".ipa", StringComparison.OrdinalIgnoreCase))
            .Where(f => { using var s = File.OpenRead(f); return s.ReadByte() == 'P' && s.ReadByte() == 'K'; }) // not Alpine packages
            .Concat(Directory.EnumerateDirectories(root, "*.app", new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 4 })
                .Select(AppleFileView.MainExecutable).OfType<string>())
            .OrderBy(f => new FileInfo(f).Length).ToList();
        Assert.NotEmpty(apps);
        var inspection = new InspectionService(_ws);
        foreach (var app in apps)
        {
            var clock = Stopwatch.StartNew();
            var r = inspection.SurveyFeatures(null, app, "all", default);
            clock.Stop();
            if (app.EndsWith(".apk", StringComparison.OrdinalIgnoreCase) && new FileInfo(app).Length <= 32 << 20)
                Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), $"{app}: {clock.ElapsedMilliseconds} ms (target 2 s; 5 s allowed on a loaded machine)");
            output.WriteLine($"{Path.GetFileName(app)} {new FileInfo(app).Length / 1048576.0:0.0} MB {clock.ElapsedMilliseconds} ms, {r.MethodsScanned} methods");
            foreach (var f in r.Features.Where(f => f.Rule != null))
            {
                output.WriteLine($"  {f.Rule!.Id} {f.Evidence.Sum(e => e.Count)} (+{f.Evidence.Sum(e => e.Library ?? 0)} lib)");
                foreach (var l in f.Evidence.SelectMany(e => e.Locations).Take(5)) output.WriteLine("      " + l);
            }
            foreach (var n in r.Notes.Where(n => n.StartsWith("In library", StringComparison.Ordinal))) output.WriteLine("  " + n);
        }
    }
}
