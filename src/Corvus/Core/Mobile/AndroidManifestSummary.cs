using System.ComponentModel;
using System.Globalization;

namespace Corvus.Core.Mobile;

public sealed record AndroidPermission(string Name, int? MaxSdkVersion, bool Sdk23Only);

public sealed record AndroidDeclaredPermission(string Name, string ProtectionLevel, string? Group);

public sealed record AndroidIntentData(string? Scheme, string? Host, string? Port, string? Path, string? MimeType);

public sealed record AndroidIntentFilter(IReadOnlyList<string> Actions, IReadOnlyList<string> Categories, IReadOnlyList<AndroidIntentData> Data, bool AutoVerify, int? Priority);

public sealed record AndroidMetaData(string Name, string? Value, string? Resource);

public sealed record AndroidComponent(
    [property: Description("activity, activity-alias, service, receiver or provider.")] string Kind,
    [property: Description("Fully qualified class name.")] string Name,
    [property: Description("android:exported as written; null when absent.")] bool? Exported,
    [property: Description("Whether other apps can reach it: the explicit value, or the platform default.")] bool EffectiveExported,
    [property: Description("Why EffectiveExported has its value.")] string ExportedReason,
    string? Permission, bool? Enabled, string? Process,
    [property: Description("activity-alias: the activity it opens.")] string? TargetActivity,
    [property: Description("provider: its authorities; readPermission / writePermission and grantUriPermissions follow.")] string? Authorities,
    string? ReadPermission, string? WritePermission, bool? GrantUriPermissions,
    [property: Description("MAIN + LAUNCHER intent filter.")] bool Launcher,
    [property: Description("scheme://host/path URIs its BROWSABLE / VIEW filters accept.")] IReadOnlyList<string> DeepLinks,
    IReadOnlyList<AndroidIntentFilter> IntentFilters, IReadOnlyList<AndroidMetaData> MetaData)
{
    /// <summary>The .NET type behind a Java callable wrapper (set by the Java / .NET map).</summary>
    [Description("The .NET type implementing this component (Xamarin / MAUI apps), with how it was matched.")]
    public string? DotNetType { get; init; }
}

public sealed record AndroidApplicationFlags(string? Name, string? Label, bool? Debuggable, bool? AllowBackup, bool? UsesCleartextTraffic,
    [property: Description("The android:networkSecurityConfig resource and its file.")] string? NetworkSecurityConfig,
    bool? ExtractNativeLibs, bool? TestOnly, bool? HasCode, string? AppComponentFactory, string? BackupAgent, string? DataExtractionRules, string? FullBackupContent);

public sealed record AndroidQueries(IReadOnlyList<string> Packages, IReadOnlyList<string> Intents, IReadOnlyList<string> Providers);

/// <summary>What AndroidManifest.xml declares, with resource references resolved and platform defaults applied.</summary>
public sealed record AndroidManifestSummary(string Package, string? VersionCode, string? VersionName, int? MinSdk, int? TargetSdk, int? MaxSdk, int? CompileSdk,
    [property: Description("Set on a split APK: its split name.")] string? Split,
    IReadOnlyList<AndroidPermission> Permissions, IReadOnlyList<AndroidDeclaredPermission> DeclaredPermissions,
    AndroidApplicationFlags Application, IReadOnlyList<AndroidComponent> Components, AndroidQueries Queries,
    IReadOnlyList<string> Features, IReadOnlyList<string> Libraries, IReadOnlyList<AndroidMetaData> MetaData,
    [property: Description("Notable facts: debuggable, cleartext traffic, backups, exported components without permission, deep links.")] IReadOnlyList<string> Highlights,
    IReadOnlyList<string> Issues)
{
    /// <summary>Reads the summary; <paramref name="resources"/> resolves references (labels, booleans, network security config).</summary>
    public static AndroidManifestSummary Of(AxmlDocument doc, IResourceTable? resources)
    {
        var root = doc.Root ?? throw new ToolError(ErrorCode.MalformedInput, "the manifest has no root element.");
        var r = new Reader(doc, resources);
        var package = r.Text(root.Attribute("package", android: false)) ?? "";
        var sdk = root.Elements("uses-sdk").FirstOrDefault();
        int? min = r.Int(sdk?.Attribute("minSdkVersion")), target = r.Int(sdk?.Attribute("targetSdkVersion")) ?? min, max = r.Int(sdk?.Attribute("maxSdkVersion"));
        int? compile = r.Int(root.Attribute("compileSdkVersion")) ?? r.Int(root.Attribute("platformBuildVersionCode", android: false));

        var permissions = root.Children.Where(c => c.Name is "uses-permission" or "uses-permission-sdk-23" or "uses-permission-sdk-m")
            .Select(c => new AndroidPermission(r.Text(c.Attribute("name")) ?? "", r.Int(c.Attribute("maxSdkVersion")), c.Name != "uses-permission")).ToList();
        var declared = root.Elements("permission").Select(c => new AndroidDeclaredPermission(r.Text(c.Attribute("name")) ?? "",
            ProtectionLevel(c.Attribute("protectionLevel") is { } p ? p.Value.Data : 0), r.Text(c.Attribute("permissionGroup")))).ToList();

        var app = root.Elements("application").FirstOrDefault();
        var flags = new AndroidApplicationFlags(r.ClassName(app?.Attribute("name"), package), r.Text(app?.Attribute("label")), r.Bool(app?.Attribute("debuggable")),
            r.Bool(app?.Attribute("allowBackup")), r.Bool(app?.Attribute("usesCleartextTraffic")), r.Reference(app?.Attribute("networkSecurityConfig")),
            r.Bool(app?.Attribute("extractNativeLibs")), r.Bool(app?.Attribute("testOnly")), r.Bool(app?.Attribute("hasCode")),
            r.ClassName(app?.Attribute("appComponentFactory"), package), r.ClassName(app?.Attribute("backupAgent"), package),
            r.Reference(app?.Attribute("dataExtractionRules")), r.Reference(app?.Attribute("fullBackupContent")));

        var components = new List<AndroidComponent>();
        foreach (var c in app?.Children ?? [])
            if (c.Name is "activity" or "activity-alias" or "service" or "receiver" or "provider")
                components.Add(Component(c, r, package, target));

        var queries = root.Elements("queries").ToList();
        var q = new AndroidQueries(
            queries.SelectMany(x => x.Elements("package")).Select(x => r.Text(x.Attribute("name")) ?? "").ToList(),
            queries.SelectMany(x => x.Elements("intent")).Select(x => string.Join(" ", x.Children.Select(i => $"{i.Name}:{string.Join(",", i.Attributes.Select(a => r.Text(a)))}"))).ToList(),
            queries.SelectMany(x => x.Elements("provider")).Select(x => r.Text(x.Attribute("authorities")) ?? "").ToList());

        var summary = new AndroidManifestSummary(package, r.Text(root.Attribute("versionCode")), r.Text(root.Attribute("versionName")), min, target, max, compile,
            r.Text(root.Attribute("split", android: false)), permissions, declared, flags, components, q,
            root.Elements("uses-feature").Select(f => r.Text(f.Attribute("name")) ?? (r.Int(f.Attribute("glEsVersion")) is { } gl ? $"OpenGL ES 0x{gl:x}" : "")).Where(s => s.Length > 0).ToList(),
            (app?.Elements("uses-library") ?? []).Concat(app?.Elements("uses-native-library") ?? []).Select(l => r.Text(l.Attribute("name")) ?? "").ToList(),
            ReadMetaData(app, r), [], [.. doc.Issues.Select(i => i.Message), .. resources?.Issues.Select(i => i.Message) ?? []]);
        return summary with { Highlights = FindHighlights(summary) };
    }

    private static List<AndroidMetaData> ReadMetaData(AxmlElement? parent, Reader r) =>
        [.. (parent?.Elements("meta-data") ?? []).Select(m => new AndroidMetaData(r.Text(m.Attribute("name")) ?? "", r.Text(m.Attribute("value")), r.Reference(m.Attribute("resource"))))];

    private static AndroidComponent Component(AxmlElement c, Reader r, string package, int? targetSdk)
    {
        var filters = c.Elements("intent-filter").Select(f => new AndroidIntentFilter(
            f.Elements("action").Select(a => r.Text(a.Attribute("name")) ?? "").ToList(),
            f.Elements("category").Select(a => r.Text(a.Attribute("name")) ?? "").ToList(),
            f.Elements("data").Select(d => new AndroidIntentData(r.Text(d.Attribute("scheme")), r.Text(d.Attribute("host")), r.Text(d.Attribute("port")),
                r.Text(d.Attribute("path")) ?? r.Text(d.Attribute("pathPrefix")) ?? r.Text(d.Attribute("pathPattern")) ?? r.Text(d.Attribute("pathAdvancedPattern")),
                r.Text(d.Attribute("mimeType")))).ToList(),
            r.Bool(f.Attribute("autoVerify")) == true, r.Int(f.Attribute("priority")))).ToList();
        bool? exported = r.Bool(c.Attribute("exported"));
        (bool effective, string reason) = exported is { } e ? (e, "explicit")
            : c.Name == "provider" ? (targetSdk is < 17, targetSdk is < 17 ? "providers default to exported below API 17" : "providers default to not exported from API 17")
            : filters.Count > 0
                ? targetSdk is >= 31 ? (true, "missing android:exported with an intent filter: Android 12+ refuses to install the app; older versions export it")
                : (true, "implied by an intent filter (targetSdk below 31)")
            : (false, "no intent filter");
        bool launcher = filters.Any(f => f.Actions.Contains("android.intent.action.MAIN") && f.Categories.Contains("android.intent.category.LAUNCHER"));
        var links = filters.Where(f => f.Categories.Contains("android.intent.category.BROWSABLE") || f.Actions.Contains("android.intent.action.VIEW"))
            .SelectMany(f =>
            {
                var schemes = f.Data.Select(d => d.Scheme).OfType<string>().Distinct().ToList();
                var hosts = f.Data.Select(d => d.Host).OfType<string>().Distinct().DefaultIfEmpty("").ToList();
                var paths = f.Data.Select(d => d.Path).OfType<string>().Distinct().DefaultIfEmpty("").ToList();
                return schemes.SelectMany(s => hosts.SelectMany(h => paths.Select(p => $"{s}://{h}{(p.Length > 0 && !p.StartsWith('/') ? "/" : "")}{p}")));
            }).Distinct().ToList();
        return new AndroidComponent(c.Name, r.ClassName(c.Attribute("name"), package) ?? "", exported, effective, reason, r.Text(c.Attribute("permission")),
            r.Bool(c.Attribute("enabled")), r.Text(c.Attribute("process")), r.ClassName(c.Attribute("targetActivity"), package), r.Text(c.Attribute("authorities")),
            r.Text(c.Attribute("readPermission")), r.Text(c.Attribute("writePermission")), r.Bool(c.Attribute("grantUriPermissions")), launcher, links, filters, ReadMetaData(c, r));
    }

    private static List<string> FindHighlights(AndroidManifestSummary s)
    {
        var h = new List<string>();
        if (s.Application.Debuggable == true) h.Add("android:debuggable=true: a debugger can attach and run-as works on any device.");
        if (s.Application.UsesCleartextTraffic == true) h.Add("Cleartext (HTTP) traffic allowed by android:usesCleartextTraffic.");
        else if (s.Application.UsesCleartextTraffic == null && s.TargetSdk is < 28 && s.Application.NetworkSecurityConfig == null)
            h.Add("Cleartext (HTTP) traffic allowed by default (targetSdk below 28, no network security config).");
        if (s.Application.AllowBackup != false && s.Application.DataExtractionRules == null && s.Application.FullBackupContent == null)
            h.Add("App data can be backed up (android:allowBackup not false, no backup rules).");
        if (s.Application.TestOnly == true) h.Add("android:testOnly=true: installs only with adb install -t.");
        var open = s.Components.Where(c => c.EffectiveExported && c.Permission == null && !c.Launcher && !(c.Kind == "provider" && c.ReadPermission != null)).ToList();
        if (open.Count > 0) h.Add($"{open.Count} exported component(s) without a permission: {string.Join(", ", open.Take(8).Select(c => $"{c.Kind} {c.Name}"))}{(open.Count > 8 ? ", ..." : "")}.");
        foreach (var c in s.Components.Where(c => c.Exported == null && c.IntentFilters.Count > 0 && s.TargetSdk is >= 31))
            h.Add($"{c.Kind} {c.Name} has an intent filter but no android:exported: Android 12+ refuses to install the app.");
        var links = s.Components.SelectMany(c => c.DeepLinks).Distinct().ToList();
        if (links.Count > 0) h.Add($"Deep links: {string.Join(", ", links.Take(10))}{(links.Count > 10 ? ", ..." : "")}.");
        if (s.Package.Length == 0) h.Add("The manifest has no package attribute.");
        return h;
    }

    /// <summary>The base level and its flags, as the platform names them.</summary>
    public static string ProtectionLevel(uint value)
    {
        var names = new List<string> { (value & 0xF) switch { 0 => "normal", 1 => "dangerous", 2 => "signature", 3 => "signatureOrSystem", 4 => "internal", var b => $"base{b}" } };
        (uint Bit, string Name)[] flags =
        [
            (0x10, "privileged"), (0x20, "development"), (0x40, "appop"), (0x80, "pre23"), (0x100, "installer"), (0x200, "verifier"), (0x400, "preinstalled"),
            (0x800, "setup"), (0x1000, "instant"), (0x2000, "runtime"), (0x4000, "oem"), (0x8000, "vendorPrivileged"), (0x10000, "textClassifier"),
            (0x40000, "documenter"), (0x80000, "configurator"), (0x100000, "incidentReportApprover"), (0x200000, "appPredictor"), (0x400000, "module"), (0x800000, "companion"),
            (0x1000000, "retailDemo"), (0x2000000, "recents"), (0x4000000, "role"), (0x8000000, "knownSigner"),
        ];
        names.AddRange(flags.Where(f => (value & f.Bit) != 0).Select(f => f.Name));
        return string.Join("|", names);
    }

    /// <summary>Attribute values as text, numbers and booleans, resource references followed through the table.</summary>
    private sealed class Reader(AxmlDocument doc, IResourceTable? resources)
    {
        public string? Text(AxmlAttribute? a)
        {
            if (a == null) return null;
            if (a.Value.IsReference && a.Value.Data != 0 && resources?.DefaultText(a.Value.Data) is { } resolved) return resolved;
            return doc.Text(a, resources == null ? null : resources.Name);
        }

        /// <summary>A reference shown as its name with the value it resolves to ("@xml/network_security_config = res/xml/....xml").</summary>
        public string? Reference(AxmlAttribute? a)
        {
            if (a == null) return null;
            if (!a.Value.IsReference) return Text(a);
            var name = resources?.Name(a.Value.Data) ?? $"@0x{a.Value.Data:x8}";
            return resources?.DefaultText(a.Value.Data) is { } value && value != name ? $"{name} = {value}" : name;
        }

        public int? Int(AxmlAttribute? a)
        {
            if (a == null) return null;
            if (a.Value.DataType is ResValue.IntDec or ResValue.IntHex) return (int)a.Value.Data;
            return int.TryParse(Text(a), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;
        }

        public bool? Bool(AxmlAttribute? a)
        {
            if (a == null) return null;
            if (a.Value.DataType == ResValue.IntBoolean) return a.Value.Data != 0;
            return Text(a) switch { "true" => true, "false" => false, _ => null };
        }

        /// <summary>".Main" and "Main" are relative to the package.</summary>
        public string? ClassName(AxmlAttribute? a, string package)
        {
            var name = Text(a);
            if (string.IsNullOrEmpty(name)) return name;
            if (name.StartsWith('.')) return package + name;
            return name.Contains('.', StringComparison.Ordinal) ? name : $"{package}.{name}";
        }
    }
}
