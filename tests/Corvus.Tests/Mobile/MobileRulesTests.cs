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
        // Set to false.
        Assert.DoesNotContain(r.Features, f => f.Rule?.Id == "android-webview-file-access");
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
        // The .NET and native rules do not run on DEX.
        Assert.All(r.Features, f => Assert.Equal("android", f.Rule?.Platform));
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

    /// <summary>
    /// A string decoder (StringBuilder reverse) and two calls of it: one returns a su path, the other an MD5 digest name
    /// passed straight to MessageDigest.getInstance. Neither string is in the DEX as a literal.
    /// </summary>
    private static byte[] DecoderDex()
    {
        const string Sb = "Ljava/lang/StringBuilder;", S = "Ljava/lang/String;", Rev = "Lcom/example/app/Text;->r(Ljava/lang/String;)Ljava/lang/String;";
        var b = new DexBuilder();
        b.Class("Lcom/example/app/Text;").Method("r", S, [S], 9,
            Asm.NewInstance(0, Sb), Asm.Invoke(0x70, Sb + "-><init>(Ljava/lang/String;)V", 0, 1), Asm.Invoke(0x6e, Sb + "->reverse()Ljava/lang/StringBuilder;", 0),
            Asm.Op11x(0x0c, 0), Asm.Invoke(0x6e, Sb + "->toString()Ljava/lang/String;", 0), Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0)).Registers = 2;
        b.Class("Lcom/example/app/Check;").Method("run", "V", [], 9,
            Asm.ConstString(0, "us/nibx/metsys/"), Asm.Invoke(0x71, Rev, 0), Asm.Op11x(0x0c, 0),
            Asm.ConstString(1, "5DM"), Asm.Invoke(0x71, Rev, 1), Asm.Op11x(0x0c, 1),
            Asm.Invoke(0x71, "Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;", 1),
            Asm.ReturnVoid()).Registers = 2;
        return b.Build();
    }

    /// <summary>Check.run passes getInstance a new String(char[]) over Text.c("5DM"), which returns the reversed characters.</summary>
    private static byte[] ArrayDecoderDex()
    {
        const string Sb = "Ljava/lang/StringBuilder;", S = "Ljava/lang/String;";
        var b = new DexBuilder();
        b.Class("Lcom/example/app/Text;").Method("c", "[C", [S], 9,
            Asm.NewInstance(0, Sb), Asm.Invoke(0x70, Sb + "-><init>(Ljava/lang/String;)V", 0, 1), Asm.Invoke(0x6e, Sb + "->reverse()Ljava/lang/StringBuilder;", 0),
            Asm.Op11x(0x0c, 0), Asm.Invoke(0x6e, Sb + "->toString()Ljava/lang/String;", 0), Asm.Op11x(0x0c, 0), Asm.Invoke(0x6e, S + "->toCharArray()[C", 0),
            Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0)).Registers = 2;
        b.Class("Lcom/example/app/Check;").Method("run", "V", [], 9,
            Asm.ConstString(0, "5DM"), Asm.Invoke(0x71, "Lcom/example/app/Text;->c(Ljava/lang/String;)[C", 0), Asm.Op11x(0x0c, 0),
            Asm.NewInstance(1, S), Asm.Invoke(0x70, S + "-><init>([C)V", 1, 0),
            Asm.Invoke(0x71, "Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;", 1),
            Asm.ReturnVoid()).Registers = 2;
        return b.Build();
    }

    /// <summary>Holder's static initializer stores Text.r("5DM") in K[0]; Check.run passes K[0] to getInstance.</summary>
    private static byte[] TableDex()
    {
        const string Sb = "Ljava/lang/StringBuilder;", S = "Ljava/lang/String;", K = "Lcom/example/app/Holder;->K:[Ljava/lang/String;";
        var b = new DexBuilder();
        b.Class("Lcom/example/app/Text;").Method("r", S, [S], 9,
            Asm.NewInstance(0, Sb), Asm.Invoke(0x70, Sb + "-><init>(Ljava/lang/String;)V", 0, 1), Asm.Invoke(0x6e, Sb + "->reverse()Ljava/lang/StringBuilder;", 0),
            Asm.Op11x(0x0c, 0), Asm.Invoke(0x6e, Sb + "->toString()Ljava/lang/String;", 0), Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0)).Registers = 2;
        b.Class("Lcom/example/app/Holder;").Field("K", "[" + S, 0x18).Method("<clinit>", "V", [], 8,
            Asm.Const4(0, 1), new DexInsn(p => [0x23, (ushort)p.Type("[" + S)], [], ["[" + S], [], []), Asm.ConstString(1, "5DM"),
            Asm.Invoke(0x71, "Lcom/example/app/Text;->r(Ljava/lang/String;)Ljava/lang/String;", 1), Asm.Op11x(0x0c, 1), Asm.Const4(2, 0), Asm.Op23x(0x4d, 1, 0, 2),
            Asm.Static(0x69, 0, K), Asm.ReturnVoid()).Registers = 3;
        b.Class("Lcom/example/app/Check;").Method("run", "V", [], 9,
            Asm.Static(0x62, 0, K), Asm.Const4(1, 0), Asm.Op23x(0x46, 0, 0, 1),
            Asm.Invoke(0x71, "Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;", 0),
            Asm.ReturnVoid()).Registers = 2;
        return b.Build();
    }

    /// <summary>Check.run passes getInstance the string Text.INSTANCE.r("5DM") returns, Text being a final class without instance fields.</summary>
    private static byte[] ObjectDecoderDex()
    {
        const string Sb = "Ljava/lang/StringBuilder;", S = "Ljava/lang/String;", T = "Lcom/example/app/Text;";
        var b = new DexBuilder();
        var text = b.Class(T, access: 0x11).Field("INSTANCE", T, 0x19);
        text.Method("<clinit>", "V", [], 8,
            Asm.NewInstance(0, T), Asm.Invoke(0x70, T + "-><init>()V", 0), Asm.Static(0x69, 0, T + "->INSTANCE:" + T), Asm.ReturnVoid()).Registers = 1;
        text.Method("<init>", "V", [], 2, Asm.Invoke(0x70, "Ljava/lang/Object;-><init>()V", 0), Asm.ReturnVoid()).Registers = 1;
        text.Method("r", S, [S], 0x11,
            Asm.NewInstance(0, Sb), Asm.Invoke(0x70, Sb + "-><init>(Ljava/lang/String;)V", 0, 2), Asm.Invoke(0x6e, Sb + "->reverse()Ljava/lang/StringBuilder;", 0),
            Asm.Op11x(0x0c, 0), Asm.Invoke(0x6e, Sb + "->toString()Ljava/lang/String;", 0), Asm.Op11x(0x0c, 0), Asm.Return(0x11, 0)).Registers = 3;
        b.Class("Lcom/example/app/Check;").Method("run", "V", [], 9,
            Asm.Static(0x62, 0, T + "->INSTANCE:" + T), Asm.ConstString(1, "5DM"), Asm.Invoke(0x6e, T + "->r(Ljava/lang/String;)Ljava/lang/String;", 0, 1),
            Asm.Op11x(0x0c, 1), Asm.Invoke(0x71, "Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;", 1),
            Asm.ReturnVoid()).Registers = 2;
        return b.Build();
    }

    [Fact]
    public void A_call_argument_rule_reads_a_string_an_object_decoder_returns()
    {
        var path = _dir.File("app.dex");
        File.WriteAllBytes(path, ObjectDecoderDex());
        Assert.Equal(["Lcom/example/app/Check;->run()V +0x8: Ljava/security/MessageDigest;->getInstance(\"MD5\")"],
            Locations(Rule(Survey(path), "android-weak-hash")));
    }

    [Fact]
    public void A_call_argument_rule_reads_a_string_from_a_table_the_static_initializer_fills()
    {
        var path = _dir.File("app.dex");
        File.WriteAllBytes(path, TableDex());
        Assert.Equal(["Lcom/example/app/Check;->run()V +0x5: Ljava/security/MessageDigest;->getInstance(\"MD5\")"],
            Locations(Rule(Survey(path), "android-weak-hash")));
    }

    [Fact]
    public void A_call_argument_rule_reads_a_string_built_from_an_array_decoder_result()
    {
        var path = _dir.File("app.dex");
        File.WriteAllBytes(path, ArrayDecoderDex());
        Assert.Equal(["Lcom/example/app/Check;->run()V +0xb: Ljava/security/MessageDigest;->getInstance(\"MD5\")"],
            Locations(Rule(Survey(path), "android-weak-hash")));
    }

    [Fact]
    public void A_dex_string_rule_matches_a_string_a_decoder_call_returns()
    {
        var path = _dir.File("app.dex");
        File.WriteAllBytes(path, DecoderDex());
        Assert.Equal(["Lcom/example/app/Check;->run()V +0x2: \"/system/xbin/su\" from Lcom/example/app/Text;->r(Ljava/lang/String;)Ljava/lang/String;"],
            Locations(Rule(Survey(path), "android-root-detection")));
    }

    [Fact]
    public void A_call_argument_rule_reads_a_string_a_decoder_call_returns()
    {
        var path = _dir.File("app.dex");
        File.WriteAllBytes(path, DecoderDex());
        Assert.Equal(["Lcom/example/app/Check;->run()V +0xc: Ljava/security/MessageDigest;->getInstance(\"MD5\")"],
            Locations(Rule(Survey(path), "android-weak-hash")));
    }

    [Fact]
    public void Pins_name_the_certificate_files_the_package_carries()
    {
        using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        using var ca = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=Example Pinned CA", key,
            System.Security.Cryptography.HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UnixEpoch, new DateTimeOffset(2120, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var pin = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(ca.PublicKey.ExportSubjectPublicKeyInfo()));
        var config = AxmlWriter.Write(new AxmlWriter.Node("network-security-config").Add(
            new AxmlWriter.Node("domain-config").Add(
                new AxmlWriter.Node("domain") { Text = "api.example.com" },
                new AxmlWriter.Node("pin-set").Add(new AxmlWriter.Node("pin", AxmlWriter.String("digest", "SHA-256", ns: null)) { Text = pin }))));
        var b = new DexBuilder();
        b.Class("Lcom/example/app/Pins;").Method("pin", "Ljava/lang/String;", [], 9, Asm.ConstString(0, "sha256/" + pin), Asm.Return(0x11, 0)).Registers = 1;
        var path = _dir.File("app.apk");
        File.WriteAllBytes(path, AndroidSamples.Apk(config, 30, ("classes.dex", b.Build()),
            ("res/raw/pinned_ca.pem", System.Text.Encoding.ASCII.GetBytes(ca.ExportCertificatePem()))));
        var joined = " (pins res/raw/pinned_ca.pem #0 CN=Example Pinned CA)";
        var found = Locations(Rule(Survey(path, "MASVS-NETWORK"), "android-pinning"));
        Assert.Contains($"res/xml/network_security_config.xml: domain-config api.example.com: 1 pin(s) SHA-256/{pin}{joined}", found);
        Assert.Contains(found, l => l.StartsWith("Lcom/example/app/Pins;->pin()", StringComparison.Ordinal) && l.EndsWith(joined, StringComparison.Ordinal));
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
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void Real_apps_report_counts_and_time_per_rule()
    {
        var root = RealData.Path(RealData.MobileApps);
        var apps = Directory.EnumerateFiles(root, "*.*", new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 2 })
            .Where(f => f.EndsWith(".apk", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".ipa", StringComparison.OrdinalIgnoreCase))
            // Not Alpine packages.
            .Where(f => { using var s = File.OpenRead(f); return s.ReadByte() == 'P' && s.ReadByte() == 'K'; })
            .Concat(Directory.EnumerateDirectories(root, "*.app", new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 4 })
                .Select(AppleFileView.MainExecutable).OfType<string>())
            .OrderBy(f => new FileInfo(f).Length).ToList();
        Assert.NotEmpty(apps);
        var inspection = new InspectionService(_ws);
        foreach (var app in apps)
        {
            (DexRuleScan.Scans, DexRuleScan.MethodsDecoded) = (0, 0);
            var clock = Stopwatch.StartNew();
            var r = inspection.SurveyFeatures(null, app, "all", default);
            clock.Stop();
            // One scan per app for every dex rule, and a raw-code prefilter: well under 1 % of methods are decoded.
            Assert.InRange(DexRuleScan.Scans, 0, 1);
            Assert.InRange(DexRuleScan.MethodsDecoded, 0, Math.Max(1, r.MethodsScanned / 20));
            if (app.EndsWith(".apk", StringComparison.OrdinalIgnoreCase) && new FileInfo(app).Length <= 32 << 20)
                PerfBudget.Time("mobile/apk-survey", clock.Elapsed, TimeSpan.FromSeconds(5), output);
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
