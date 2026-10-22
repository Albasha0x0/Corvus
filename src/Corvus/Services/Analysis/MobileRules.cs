using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.MachO;
using Corvus.Services.Mobile;

namespace Corvus.Services.Analysis;

/// <summary>
/// What the mobile rules read: an Android app's DEX code, manifest and network security config, or an Apple app's
/// Info.plist beside the Mach-O image the survey indexes. Scans run once, on first use.
/// </summary>
public sealed class MobileSubject
{
    /// <summary>"android" or "apple".</summary>
    public required string Platform { get; init; }
    public DexIndex? Dex { get; init; }
    public AndroidManifestSummary? Manifest { get; init; }
    public AndroidNetworkSecurityConfig? NetworkConfig { get; init; }
    /// <summary>The config's file in the package (res/xml/....xml).</summary>
    public string? NetworkConfigFile { get; init; }
    public PlistDict? InfoPlist { get; init; }

    private DexRuleScan? _dex;
    private AppleObjcMetadata? _objc;
    private readonly object _lock = new();

    internal DexRuleScan DexScan(CancellationToken ct)
    {
        lock (_lock) return _dex ??= new DexRuleScan(Dex!, MobileRules.DexFeatures, IsLibrary, ct);
    }

    internal AppleObjcMetadata? Objc(INativeImage image, CancellationToken ct)
    {
        if (image is not MachOFile macho) return null;
        lock (_lock) return _objc ??= AppleObjcMetadata.Read(macho, ct);
    }

    /// <summary>
    /// Packages of widely shipped libraries; code in them is reported apart from the app's. The app's own package always
    /// counts as the app.
    /// </summary>
    private static readonly string[] LibraryPackages =
    [
        "Landroidx/", "Landroid/support/", "Lcom/google/", "Lkotlin/", "Lkotlinx/", "Lokhttp3/", "Lokio/", "Lcom/squareup/", "Lretrofit2/",
        "Lio/grpc/", "Lio/reactivex/", "Lrx/", "Lorg/apache/", "Lorg/bouncycastle/", "Lorg/spongycastle/", "Lorg/conscrypt/", "Lorg/chromium/",
        "Lorg/webrtc/", "Lorg/jetbrains/", "Lorg/intellij/", "Lorg/json/", "Lorg/slf4j/", "Lch/qos/", "Lcom/fasterxml/", "Lcom/facebook/",
        "Lcom/bumptech/", "Lio/sentry/", "Lcom/microsoft/", "Ldagger/", "Ljavax/", "Lj$/", "Lcom/airbnb/", "Lio/flutter/", "Lcom/amazon/",
        "Lcom/amazonaws/", "Lcom/crashlytics/", "Lio/fabric/", "Lcom/firebase/", "Lnet/zetetic/", "Lnet/sqlcipher/", "Lio/realm/", "Lcom/onesignal/",
        "Lcom/journeyapps/", "Lorg/greenrobot/", "Lcom/swmansion/", "Lcom/reactnativecommunity/", "Lcom/th3rdwave/", "Lexpo/", "Lio/ktor/",
        "Lorg/mozilla/", "Lnet/sourceforge/zbar/", "Lcom/android/volley/", "Lcom/jakewharton/", "Lorg/joda/", "Lorg/threeten/", "Lcoil/",
        "Lcom/github/bumptech/", "Lcom/scottyab/rootbeer/", "Lcom/datatheorem/android/trustkit/", "Lorg/osmdroid/", "Lorg/acra/", "Lcom/tencent/",
        "Lcom/unity3d/", "Lcom/applovin/", "Lcom/ironsource/", "Lcom/adjust/", "Lcom/appsflyer/", "Lio/branch/", "Lcom/mixpanel/", "Lcom/segment/",
        "Lcom/stripe/", "Lcom/paypal/", "Lcom/braintreepayments/", "Lmono/", "Lcrc64", "Lxamarin/", "Lmicrosoft/",
        "Lcom/jcraft/", "Lnet/freehaven/tor/control/", "Lcom/learnium/RNDeviceInfo/", "Lcom/pcloud/sdk/", "Lcom/dropbox/core/",
    ];

    private string? _appPackage;

    internal bool IsLibrary(string descriptor)
    {
        _appPackage ??= Manifest is { Package.Length: > 0 } m ? "L" + m.Package.Replace('.', '/') + "/" : "";
        if (_appPackage.Length > 0 && descriptor.StartsWith(_appPackage, StringComparison.Ordinal)) return false;
        foreach (var p in LibraryPackages)
            if (descriptor.StartsWith(p, StringComparison.Ordinal)) return true;
        return false;
    }
}

/// <summary>
/// survey_features rules for Android and Apple apps, each with its MASVS control, severity and a review note: findings are
/// places worth reviewing, never verdicts. Kinds: "dex:" (<see cref="DexRuleScan"/>), "apk:" (manifest and network security
/// config: debuggable, cleartext, user-certificates, pins), "objc:sel:NAME" / "objc:class:NAME" (Objective-C selector and
/// class references with the functions that use them), "objc:check:trust-unchecked" (a function that builds a credential
/// from a server trust without calling SecTrustEvaluate*), "sym:REGEX" (imports and symbols, Swift names mangled) and
/// "plist:ats-insecure" / "plist:pinned-domains" (Info.plist App Transport Security). Apple rules also use "str:".
/// </summary>
internal sealed class MobileRules : ISurveyRuleProvider
{
    private const int MaxLocations = 5;

    private static Features.Rule Android(string id, string masvs, string severity, string name, string review, params string[] features) =>
        Rule("android", id, masvs, severity, name, review, features);

    private static Features.Rule Apple(string id, string masvs, string severity, string name, string review, params string[] features) =>
        Rule("apple", id, masvs, severity, name, review, features);

    private static Features.Rule Rule(string platform, string id, string masvs, string severity, string name, string review, string[] features) =>
        new(name, masvs.Split('-')[1].ToLowerInvariant(), [features])
        {
            Id = id, Masvs = masvs, Severity = severity, Review = review, Platform = platform,
        };

    private const string Secrets = @"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\s*[A-Za-z0-9+/=\s]{64}|\bAKIA[0-9A-Z]{16}\b|\bsk_live_[0-9A-Za-z]{20,}|\bxox[abposr]-[0-9A-Za-z-]{10,}|\bgh[pousr]_[0-9A-Za-z]{36}\b";

    private const string FridaNames = @"(?i)^(?:frida(?:-server|-agent|-gadget)?|re\.frida\.server|gum-js-loop|gmain|linjector|frida_agent_main|libfrida-gadget\.(?:so|dylib)|FridaGadget(?:\.dylib)?|/data/local/tmp/(?:re\.frida\.server|frida-server)|/usr/sbin/frida-server)$";

    public static readonly IReadOnlyList<Features.Rule> All =
    [
        Android("android-webview-bridge", "MASVS-PLATFORM-2", "medium", "expose Java objects to WebView JavaScript",
            "Every @JavascriptInterface method is callable by any page the WebView loads, iframes included; check which origins load and what the methods reach.",
            "dex:call:*->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V"),
        Android("android-webview-javascript", "MASVS-PLATFORM-2", "low", "enable JavaScript in a WebView",
            "Scripts run for every page the WebView loads; check that it loads only the app's own HTTPS content.",
            "dex:call:*->setJavaScriptEnabled(Z)V#1=i:1"),
        Android("android-webview-file-access", "MASVS-PLATFORM-2", "medium", "let file:// pages in a WebView read other files or origins",
            "A file:// page can then read local files or any origin; check where loaded files come from.",
            "dex:call:*->setAllowUniversalAccessFromFileURLs(Z)V#1=i:1", "dex:call:*->setAllowFileAccessFromFileURLs(Z)V#1=i:1"),
        Android("android-webview-ssl-proceed", "MASVS-NETWORK-1", "high", "continue past WebView TLS errors",
            "SslErrorHandler.proceed() loads the page despite a bad certificate; check that it follows an explicit user choice or a debug-only path.",
            "dex:call:Landroid/webkit/SslErrorHandler;->proceed()V"),
        Android("android-trust-all", "MASVS-NETWORK-1", "high", "accept any server certificate",
            "A trust manager whose checkServerTrusted returns without checking; check whether a socket factory or client uses it outside debug builds.",
            "dex:check:trust-all"),
        Android("android-any-hostname", "MASVS-NETWORK-1", "high", "accept any host name for TLS",
            "A hostname verifier that accepts every host; check where it is installed (setHostnameVerifier, setDefaultHostnameVerifier).",
            "dex:check:any-hostname", "dex:field:Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER",
            "dex:call:Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;-><init>("),
        Android("android-cleartext", "MASVS-NETWORK-1", "medium", "allow cleartext HTTP",
            "Check which hosts are reached over http:// (search_container kind=endpoint lists them).",
            "apk:cleartext"),
        Android("android-user-certificates", "MASVS-NETWORK-1", "medium", "trust user-installed CA certificates",
            "Any CA the user (or a device policy) installs can intercept the app's TLS; check that this is meant outside debug-overrides.",
            "apk:user-certificates"),
        Android("android-pinning", "MASVS-NETWORK-2", "info", "pin server certificates",
            "Check the pinned hosts, backup pins and expiry; these are also the methods an interception layer wraps.",
            "dex:call:Lokhttp3/CertificatePinner$Builder;->add(", "dex:call:Lcom/squareup/okhttp/CertificatePinner$Builder;->add(", "apk:pins",
            "dex:class:Lcom/datatheorem/android/trustkit/TrustKit;", @"dex:str:^sha(?:256|1)/[A-Za-z0-9+/]{27,43}=*$"),
        Android("android-root-detection", "MASVS-RESILIENCE-1", "info", "look for root (su binaries, root managers)",
            "Root checks can be worked around on a rooted device; check what the app does when one fires (or whether the app uses root itself).",
            @"dex:str:^/(?:system/(?:xbin|bin|sbin|sd/xbin|bin/failsafe)/su|sbin/su|su/bin/su|data/local/(?:xbin|bin)/su|data/local/su|system/app/Superuser\.apk|cache/su|dev/su)$",
            @"dex:str:^(?:com\.topjohnwu\.magisk|eu\.chainfire\.supersu|com\.noshufou\.android\.su(?:\.elite)?|com\.koushikdutta\.superuser|com\.thirdparty\.superuser|com\.kingroot\.kinguser|com\.yellowes\.su|com\.devadvance\.rootcloak2?|de\.robv\.android\.xposed\.installer|com\.saurik\.substrate)$",
            "dex:class:Lcom/scottyab/rootbeer/RootBeer;"),
        Android("android-integrity-attestation", "MASVS-RESILIENCE-1", "info", "request device integrity attestation (Play Integrity, SafetyNet)",
            "Attestation only helps when a server verifies the token; check where the token goes.",
            "dex:call:Lcom/google/android/play/core/integrity/IntegrityManager;->requestIntegrityToken(",
            "dex:call:Lcom/google/android/play/core/integrity/StandardIntegrityManager;->prepareIntegrityToken(",
            "dex:call:Lcom/google/android/gms/safetynet/SafetyNetClient;->attest("),
        // Emulator files and properties only: Build.MODEL names (goldfish, Genymotion) are also device quirk lists (CameraX)
        Android("android-emulator-detection", "MASVS-RESILIENCE-1", "info", "look for emulator files or properties",
            "Check what the app does on an emulator; these checks are routine in anti-fraud SDKs too.",
            @"dex:str:^(?:/dev/qemu_pipe|/dev/socket/qemud|/dev/goldfish_pipe|/system/lib(?:64)?/libc_malloc_debug_qemu\.so|/sys/qemu_trace|/system/bin/qemu-props|/system/bin/qemud|ro\.kernel\.qemu(?:\.gles)?|init\.goldfish\.rc|ueventd\.ranchu\.rc|/system/lib/libdroid4x\.so|/system/bin/nox-prop|/system/bin/ttVM-prop|fstab\.vbox86|ueventd\.vbox86\.rc|/dev/vboxguest|/dev/vboxuser)$"),
        Android("android-instrumentation-detection", "MASVS-RESILIENCE-4", "info", "look for instrumentation frameworks",
            "Check what the app does when it finds them; the strings are also what an interception script renames.",
            "dex:str:" + FridaNames, @"dex:str:^(?:de\.robv\.android\.xposed\.XposedBridge|XposedBridge\.jar|/system/framework/XposedBridge\.jar|com\.saurik\.substrate\.MS\$2)$"),
        Android("android-debugger-detection", "MASVS-RESILIENCE-4", "info", "check for an attached debugger",
            "Check what the app does when a debugger is attached.",
            "dex:call:Landroid/os/Debug;->isDebuggerConnected()Z", "dex:call:Landroid/os/Debug;->waitingForDebugger()Z", @"dex:str:^TracerPid:?\s*$"),
        Android("android-debuggable", "MASVS-RESILIENCE-4", "high", "ship as debuggable",
            "android:debuggable=true lets any debugger attach and run-as read the app's data; release builds should not set it.",
            "apk:debuggable"),
        Android("android-dynamic-code", "MASVS-CODE-4", "medium", "load DEX code at run time",
            "Check where the code comes from (a download, external storage) and whether it is verified before it is loaded.",
            "dex:call:Ldalvik/system/DexClassLoader;-><init>(", "dex:call:Ldalvik/system/InMemoryDexClassLoader;-><init>(",
            "dex:call:Ldalvik/system/PathClassLoader;-><init>(", "dex:call:Ldalvik/system/DexFile;->loadDex(", "dex:call:Ldalvik/system/DexFile;-><init>("),
        Android("android-native-load-path", "MASVS-CODE-4", "medium", "load a native library from a file path",
            "System.load takes any path, unlike loadLibrary; check that the file cannot be replaced by another app or a download.",
            "dex:call:Ljava/lang/System;->load(Ljava/lang/String;)V", "dex:call:Ljava/lang/Runtime;->load(Ljava/lang/String;)V"),
        Android("android-weak-hash", "MASVS-CRYPTO-1", "low", "hash with MD5 or SHA-1",
            "Not collision-resistant, so unsuitable for signatures, passwords and integrity; fine for cache keys and checksums. Check what the digest protects.",
            @"dex:call:Ljava/security/MessageDigest;->getInstance(*#0=s:(?i)^(?:MD2|MD4|MD5|SHA-?1|SHA)$"),
        Android("android-weak-cipher", "MASVS-CRYPTO-1", "medium", "encrypt with a weak cipher or ECB mode",
            "DES, 3DES, RC4 and Blowfish are weak; ECB (also bare \"AES\") leaks patterns. Check what the cipher protects.",
            @"dex:call:Ljavax/crypto/Cipher;->getInstance(*#0=s:(?i)^(?:DES|DESede|TripleDES|RC4|ARCFOUR|RC2|Blowfish)(?:/.*)?$|^(?:R|RS|(?:[^R/]|R[^S/]|RS[^A/])[^/]*)/ECB/|^AES$"),
        Android("android-hardcoded-key", "MASVS-CRYPTO-2", "high", "build a key or IV from a literal",
            "A key in the app is readable by anyone with the APK; check whether it protects anything beyond local obfuscation.",
            "dex:call:Ljavax/crypto/spec/SecretKeySpec;-><init>([B*#1=literal", "dex:call:Ljavax/crypto/spec/IvParameterSpec;-><init>([B*#1=literal",
            "dex:call:Ljavax/crypto/spec/PBEKeySpec;-><init>([C*#1=literal", "dex:call:Ljavax/crypto/spec/GCMParameterSpec;-><init>(I[B*#2=literal"),
        Android("android-hardcoded-secret", "MASVS-CRYPTO-2", "high", "embed a private key or service token",
            "Check whether the secret is live and what it grants; rotate it if so.",
            "dex:str:" + Secrets),

        Apple("apple-webview-bridge", "MASVS-PLATFORM-2", "medium", "receive WKWebView script messages",
            "Any page the web view loads can post to the handler; check which origins load and what the handler does with the message.",
            "objc:sel:addScriptMessageHandler:name:", "objc:sel:addScriptMessageHandler:contentWorld:name:", "objc:sel:addScriptMessageHandlerWithReply:contentWorld:name:"),
        Apple("apple-uiwebview", "MASVS-PLATFORM-2", "low", "use UIWebView",
            "UIWebView always runs JavaScript and cannot limit file access; App Store review rejects new apps that use it.",
            "objc:class:UIWebView"),
        Apple("apple-ats-exception", "MASVS-NETWORK-1", "medium", "relax App Transport Security",
            "Check which hosts are reached over plain HTTP or weak TLS and why the exception is needed.",
            "plist:ats-insecure"),
        Apple("apple-trust-override", "MASVS-NETWORK-1", "medium", "override server trust evaluation",
            "Check that the challenge handler evaluates the trust (SecTrustEvaluateWithError) before it answers with a credential; evaluation may live in another function.",
            "objc:check:trust-unchecked", "objc:sel:setAllowInvalidCertificates:", @"sym:(?:DisabledTrustEvaluator|DisabledEvaluator)",
            "sym:^kCFStreamSSLValidatesCertificateChain$"),
        Apple("apple-pinning", "MASVS-NETWORK-2", "info", "pin server certificates",
            "Check the pinned hosts, backup pins and expiry; these are also the functions an interception layer wraps.",
            "plist:pinned-domains", @"sym:(?:PinnedCertificatesTrustEvaluator|PublicKeysTrustEvaluator)", "objc:class:TSKPinningValidator",
            "objc:class:TrustKit", "objc:sel:policyWithPinningMode:", "str:^TSKPublicKeyHashes$"),
        Apple("apple-jailbreak-detection", "MASVS-RESILIENCE-1", "info", "look for a jailbreak",
            "Jailbreak checks can be worked around on a jailbroken device; check what the app does when one fires. Swift strings under 16 bytes live in code and are not seen.",
            @"str:^(?:/Applications/(?:Cydia|Sileo|Zebra|blackra1n|FakeCarrier|Icy|IntelliScreen|MxTube|RockApp|SBSettings|WinterBoard)\.app/?|/Library/MobileSubstrate/(?:MobileSubstrate\.dylib|DynamicLibraries/?)|/private/var/lib/(?:apt|cydia)/?|/private/var/stash|/private/jailbreak\.txt|/var/jb/?|/usr/libexec/cydia/?|/var/checkra1n\.dmg|/\.bootstrapped_electra|/usr/lib/libjailbreak\.dylib|/etc/apt/?|/jb/lzma|/\.installed_unc0ver)$",
            @"str:^(?:cydia|sileo|zbra|undecimus|filza)://"),
        Apple("apple-instrumentation-detection", "MASVS-RESILIENCE-4", "info", "look for Frida, Cycript or Substrate",
            "Check what the app does when it finds them.",
            "str:" + FridaNames, @"str:^(?:cynject|libcycript(?:\.dylib)?|SubstrateLoader\.dylib|SSLKillSwitch2?\.dylib|MobileSubstrate\.dylib)$"),
        Apple("apple-debugger-detection", "MASVS-RESILIENCE-4", "info", "check for or deny a debugger (ptrace)",
            "Check what the app does when a debugger is attached.",
            "sym:^ptrace$", "str:^ptrace$"),
        Apple("apple-dynamic-code", "MASVS-CODE-4", "medium", "load code at run time (dlopen, NSBundle load)",
            "System frameworks are routine; check that no path comes from a download or the app's writable folders.",
            "sym:^dlopen$", "objc:sel:loadAndReturnError:"),
        Apple("apple-weak-hash", "MASVS-CRYPTO-1", "low", "hash with MD5 or SHA-1",
            "Not collision-resistant, so unsuitable for signatures, passwords and integrity; fine for cache keys and checksums. Check what the digest protects.",
            "sym:^CC_(?:MD2|MD4|MD5|SHA1)$", @"sym:CryptoKit8InsecureO(?:3MD5|4SHA1)V"),
        Apple("apple-keychain-always", "MASVS-STORAGE-1", "medium", "store keychain items readable while the device is locked",
            "kSecAttrAccessibleAlways* items are readable without the passcode; check which items use it.",
            "sym:^kSecAttrAccessibleAlways(?:ThisDeviceOnly)?$"),
        Apple("apple-hardcoded-secret", "MASVS-CRYPTO-2", "high", "embed a private key or service token",
            "Check whether the secret is live and what it grants; rotate it if so.",
            "str:" + Secrets),
    ];

    /// <summary>Every "dex:" feature of the rules, scanned in one pass.</summary>
    internal static IEnumerable<string> DexFeatures => All.SelectMany(r => r.Groups).SelectMany(g => g).Where(f => f.StartsWith("dex:", StringComparison.Ordinal));

    public IEnumerable<Features.Rule> Rules => All;

    public IReadOnlyCollection<string> Kinds => ["dex", "apk", "objc", "sym", "plist"];

    public Evidence? Evaluate(SurveySubject subject, string feature, CancellationToken ct)
    {
        if (subject.Mobile is not { } mobile) return null;
        int colon = feature.IndexOf(':');
        var (kind, pattern) = (feature[..colon], feature[(colon + 1)..]);
        return kind switch
        {
            "dex" when mobile.Dex != null => mobile.DexScan(ct).Evidence(feature),
            "apk" => Package(mobile, feature, pattern),
            "plist" when mobile.InfoPlist != null => Plist(mobile.InfoPlist, feature, pattern),
            "objc" when subject.Native != null => Objc(subject.Native, mobile, feature, pattern, ct),
            "sym" when subject.Native != null => Symbols(subject.Native, feature, pattern),
            _ => null,
        };
    }

    private static Evidence? Of(string feature, List<string> found, string? basis = null) =>
        found.Count == 0 ? null : new Evidence(feature, found.Count, [.. found.Take(MaxLocations)]) { Basis = basis };

    private static Evidence? Package(MobileSubject m, string feature, string check)
    {
        var found = new List<string>();
        var app = m.Manifest?.Application;
        var nsc = m.NetworkConfig?.Scopes.Where(s => s.Scope != "debug-overrides").ToList() ?? [];
        var file = m.NetworkConfigFile ?? "network security config";
        string Where(NetworkSecurityScope s) => $"{file}: {s.Scope}{(s.Domains.Count > 0 ? " " + string.Join(", ", s.Domains.Take(5)) : "")}";
        switch (check)
        {
            case "debuggable" when app?.Debuggable == true:
                found.Add("AndroidManifest.xml: android:debuggable=true");
                break;
            case "cleartext":
                if (app?.UsesCleartextTraffic == true) found.Add("AndroidManifest.xml: android:usesCleartextTraffic=true");
                found.AddRange(nsc.Where(s => s.CleartextPermitted == true).Select(s => $"{Where(s)}: cleartextTrafficPermitted=true"));
                if (found.Count == 0 && app != null && app.UsesCleartextTraffic == null && m.NetworkConfig == null && m.Manifest!.TargetSdk is < 28)
                    found.Add($"AndroidManifest.xml: targetSdkVersion {m.Manifest.TargetSdk} (below 28 cleartext is allowed unless denied)");
                break;
            case "user-certificates":
                found.AddRange(nsc.Where(s => s.TrustAnchors.Contains("user")).Select(s => $"{Where(s)}: <certificates src=\"user\">"));
                break;
            case "pins":
                found.AddRange(nsc.Where(s => s.Pins.Count > 0).Select(s => $"{Where(s)}: {s.Pins.Count} pin(s){(s.PinExpiration != null ? ", expire " + s.PinExpiration : "")}"));
                break;
        }
        return Of(feature, found);
    }

    private static Evidence? Plist(PlistDict info, string feature, string check)
    {
        var found = new List<string>();
        if (info["NSAppTransportSecurity"] is not PlistDict ats) return null;
        static bool True(PlistNode? n) => n is PlistBool { Value: true };
        switch (check)
        {
            case "ats-insecure":
                foreach (var key in new[] { "NSAllowsArbitraryLoads", "NSAllowsArbitraryLoadsInWebContent", "NSAllowsArbitraryLoadsForMedia", "NSAllowsLocalNetworking" })
                    if (True(ats[key]) && key != "NSAllowsLocalNetworking") found.Add($"Info.plist: NSAppTransportSecurity {key}=true");
                if (ats["NSExceptionDomains"] is PlistDict domains)
                    foreach (var (domain, node) in domains.Entries)
                        if (node is PlistDict d)
                            foreach (var key in new[] { "NSExceptionAllowsInsecureHTTPLoads", "NSTemporaryExceptionAllowsInsecureHTTPLoads", "NSThirdPartyExceptionAllowsInsecureHTTPLoads" })
                                if (True(d[key])) found.Add($"Info.plist: NSExceptionDomains {domain} {key}=true");
                break;
            case "pinned-domains":
                if (ats["NSPinnedDomains"] is PlistDict pinned)
                    found.AddRange(pinned.Entries.Select(e => $"Info.plist: NSPinnedDomains {e.Key}"));
                break;
        }
        return Of(feature, found);
    }

    private static Evidence? Objc(NativeCodeIndex index, MobileSubject m, string feature, string pattern, CancellationToken ct)
    {
        if (m.Objc(index.Image, ct) is not { } objc) return null;
        var image = index.Image;
        var found = new List<string>();
        int count = 0;
        string Where(uint rva) => index.FunctionAt(rva) is { } f ? $"{Format.Within(index.NameAt(f.Start) ?? f.Name, f.Start, rva)} @{NativeAddress.Va(image, rva)}" : $"@{NativeAddress.Va(image, rva)}";
        void Refs(ObjcReference r, string what)
        {
            var sites = index.RefsTo((uint)(r.Va - image.ImageBase), 1000);
            count += Math.Max(1, sites.Count);
            if (sites.Count == 0 && found.Count < MaxLocations) found.Add($"{what} (referenced @{r.Va:x}, no code reference read)");
            foreach (var s in sites.Take(MaxLocations - found.Count)) found.Add($"{Where(s.From)}: {what}");
        }
        if (pattern.StartsWith("sel:", StringComparison.Ordinal))
        {
            var name = pattern[4..];
            foreach (var r in objc.References.Where(r => r.Kind == "selector" && r.Name == name)) Refs(r, name);
        }
        else if (pattern.StartsWith("class:", StringComparison.Ordinal))
        {
            var name = pattern[6..];
            foreach (var r in objc.References.Where(r => r.Kind is "class" or "superclass" && r.Name == name)) Refs(r, $"{r.Kind} {name}");
            foreach (var c in objc.Classes.Where(c => c.Name == name || c.Superclass == name))
            {
                count++;
                if (found.Count < MaxLocations) found.Add(c.Name == name ? $"defines class {name}" : $"class {c.DisplayName} : {name}");
            }
        }
        else if (pattern == "check:trust-unchecked")
        {
            var evaluated = new HashSet<uint>();
            foreach (var imp in image.Imports)
                if (imp.Name?.TrimStart('_') is { } n && n.StartsWith("SecTrustEvaluate", StringComparison.Ordinal))
                    foreach (var c in index.Callers(imp))
                        if (index.FunctionAt(c.From) is { } f) evaluated.Add(f.Start);
            var reported = new HashSet<uint>();
            foreach (var r in objc.References.Where(r => r.Kind == "selector" && r.Name is "credentialForTrust:" or "initWithTrust:"))
                foreach (var s in index.RefsTo((uint)(r.Va - image.ImageBase), 1000))
                    if (index.FunctionAt(s.From) is { } f && !evaluated.Contains(f.Start) && reported.Add(f.Start))
                    {
                        count++;
                        if (found.Count < MaxLocations) found.Add($"{Where(s.From)}: {r.Name} without SecTrustEvaluate* in the function");
                    }
        }
        return count == 0 ? null : new Evidence(feature, count, found);
    }

    private static Evidence? Symbols(NativeCodeIndex index, string feature, string pattern)
    {
        var regex = Features.RulePattern(pattern);
        var found = new List<string>();
        int count = 0;
        bool Match(string name) => regex.IsMatch(name.StartsWith('_') ? name[1..] : name);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var imp in index.Image.Imports)
        {
            if (imp.Name == null || !Match(imp.Name) || !seen.Add(imp.Name)) continue;
            var callers = index.Callers(imp);
            var first = callers.Count > 0 && index.FunctionAt(callers[0].From) is { } f ? $", first in {index.NameAt(f.Start) ?? f.Name}" : "";
            count += Math.Max(1, callers.Count);
            if (found.Count < MaxLocations) found.Add($"import {imp.Module}!{imp.Name} ({callers.Count} call sites{first})");
        }
        if (index.Image is MachOFile macho)
            foreach (var s in macho.Symbols)
            {
                if (!Match(s.Name) || !seen.Add(s.Name)) continue;
                count++;
                if (found.Count < MaxLocations) found.Add($"symbol {s.Name} @{NativeAddress.Va(index.Image, s.Rva)}");
            }
        return count == 0 ? null : new Evidence(feature, count, found);
    }
}
