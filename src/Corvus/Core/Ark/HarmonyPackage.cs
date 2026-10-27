using System.IO.Compression;
using System.Text.Json;

namespace Corvus.Core.Ark;

/// <summary>An ability or extension ability a module declares, with its skills and required permissions.</summary>
public sealed record HarmonyAbility(string Name, string Type, string? SrcEntry, bool Exported, IReadOnlyList<string> Actions,
    IReadOnlyList<string> Entities, IReadOnlyList<string> Uris, IReadOnlyList<string> Permissions);

/// <summary>A permission a module requests: name, reason resource and when it is used (abilities, inuse or always); null for not stated.</summary>
public sealed record HarmonyPermission(string Name, string? Reason, string? UsedWhen);

/// <summary>One HarmonyOS module (.hap or .hsp); null fields were not stated.</summary>
public sealed record HarmonyModule(string Path, string Model, string? Bundle, string? VersionName, long? VersionCode, int? MinApi, int? TargetApi,
    string? Name, string? Type, IReadOnlyList<string> DeviceTypes, IReadOnlyList<HarmonyAbility> Abilities, IReadOnlyList<HarmonyPermission> Permissions,
    IReadOnlyList<string> Bytecode, IReadOnlyList<string> NativeLibraries);

/// <summary>A HarmonyOS module (.hap, .hsp) or application bundle (.app); unreadable profiles go to <see cref="Issues"/>.</summary>
public sealed class HarmonyPackage
{
    public IReadOnlyList<HarmonyModule> Modules { get; }
    public IReadOnlyList<string> Issues { get; }

    /// <summary>Whether a zip's entry names mark a module or a bundle of modules.</summary>
    public static bool IsPackage(IEnumerable<string> names)
    {
        var set = names.ToHashSet(StringComparer.Ordinal);
        return set.Contains("module.json") || (set.Contains("config.json") && set.Any(n => n.StartsWith("assets/js/", StringComparison.Ordinal) || n.EndsWith(".abc", StringComparison.Ordinal)))
            || (set.Contains("pack.info") && set.Any(n => n.EndsWith(".hap", StringComparison.Ordinal) || n.EndsWith(".hsp", StringComparison.Ordinal)));
    }

    /// <summary>Reads the package; <paramref name="bytecode"/> receives each .abc file found, with its path, up to <paramref name="maxBytes"/> each.</summary>
    public HarmonyPackage(Stream zip, long maxBytes, Action<string, byte[]>? bytecode = null)
    {
        var modules = new List<HarmonyModule>();
        var issues = new List<string>();
        Read(zip, "", modules, issues, maxBytes, bytecode, depth: 0);
        Modules = modules;
        Issues = issues;
    }

    private static void Read(Stream stream, string path, List<HarmonyModule> modules, List<string> issues, long maxBytes, Action<string, byte[]>? bytecode, int depth)
    {
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read);
        var names = zip.Entries.Select(e => e.FullName).ToList();
        string prefix = path.Length > 0 ? path + "!/" : "";
        foreach (var e in zip.Entries)
            if (depth == 0 && (e.FullName.EndsWith(".hap", StringComparison.Ordinal) || e.FullName.EndsWith(".hsp", StringComparison.Ordinal)))
            {
                if (e.Length > maxBytes) { issues.Add($"{e.FullName}: {e.Length:N0} bytes, past the item limit; not read"); continue; }
                using var inner = new MemoryStream(Bytes(e));
                try { Read(inner, e.FullName, modules, issues, maxBytes, bytecode, depth + 1); }
                catch (InvalidDataException ex) { issues.Add($"{e.FullName}: not a readable zip: {ex.Message}"); }
            }
        var profile = zip.GetEntry("module.json") ?? zip.GetEntry("config.json");
        if (profile == null) return;
        var abc = names.Where(n => n.EndsWith(".abc", StringComparison.Ordinal)).Order(StringComparer.Ordinal).ToList();
        var libs = names.Where(n => n.StartsWith("libs/", StringComparison.Ordinal) && n.EndsWith(".so", StringComparison.Ordinal)).Order(StringComparer.Ordinal).ToList();
        if (bytecode != null)
            foreach (var name in abc)
            {
                var e = zip.GetEntry(name)!;
                if (e.Length > maxBytes) issues.Add($"{prefix}{name}: {e.Length:N0} bytes, past the item limit; not read");
                else bytecode(prefix + name, Bytes(e));
            }
        try
        {
            using var doc = JsonDocument.Parse(Bytes(profile), new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            modules.Add(profile.FullName == "module.json" ? Stage(path, doc.RootElement, abc, libs) : Fa(path, doc.RootElement, abc, libs));
        }
        catch (JsonException ex) { issues.Add($"{prefix}{profile.FullName}: not readable JSON: {ex.Message}"); }
    }

    // Stage model (API 9 and later): app and module objects; abilities and extensionAbilities carry skills.
    private static HarmonyModule Stage(string path, JsonElement root, List<string> abc, List<string> libs)
    {
        var app = Obj(root, "app");
        var module = Obj(root, "module");
        var abilities = new List<HarmonyAbility>();
        foreach (var a in Arr(module, "abilities")) abilities.Add(Ability(a, "page"));
        foreach (var a in Arr(module, "extensionAbilities")) abilities.Add(Ability(a, Str(a, "type") ?? "extension"));
        var permissions = Arr(module, "requestPermissions").Select(p =>
        {
            string? when = Obj(p, "usedScene") is { ValueKind: JsonValueKind.Object } scene
                ? string.Join(", ", Arr(scene, "abilities").Select(x => x.ToString()).Append(Str(scene, "when") ?? "").Where(x => x.Length > 0)) : null;
            return new HarmonyPermission(Str(p, "name") ?? "", Str(p, "reason"), string.IsNullOrEmpty(when) ? null : when);
        }).ToList();
        return new HarmonyModule(path, "stage", Str(app, "bundleName"), Str(app, "versionName"), Long(app, "versionCode"), (int?)Long(app, "minAPIVersion"),
            (int?)Long(app, "targetAPIVersion"), Str(module, "name"), Str(module, "type"), Arr(module, "deviceTypes").Select(x => x.ToString()).ToList(),
            abilities, permissions, abc, libs);
    }

    // FA model (API 8 and earlier): app, deviceConfig and module objects; versions sit in app.version and app.apiVersion.
    private static HarmonyModule Fa(string path, JsonElement root, List<string> abc, List<string> libs)
    {
        var app = Obj(root, "app");
        var module = Obj(root, "module");
        var version = Obj(app, "version");
        var api = Obj(app, "apiVersion");
        var abilities = Arr(module, "abilities").Select(a => Ability(a, Str(a, "type") ?? "page")).ToList();
        var permissions = Arr(module, "reqPermissions").Select(p => new HarmonyPermission(Str(p, "name") ?? "", Str(p, "reason"),
            Obj(p, "usedScene") is { ValueKind: JsonValueKind.Object } s ? Str(s, "when") : null)).ToList();
        return new HarmonyModule(path, "FA", Str(app, "bundleName"), Str(version, "name"), Long(version, "code"), (int?)Long(api, "compatible"),
            (int?)Long(api, "target"), Str(Obj(module, "distro"), "moduleName") ?? Str(module, "package"), Str(Obj(module, "distro"), "moduleType"),
            Arr(module, "deviceType").Select(x => x.ToString()).ToList(), abilities, permissions, abc, libs);
    }

    // Profiles write the path without its leading separator ("path": "open").
    private static string UriPath(string? path) => string.IsNullOrEmpty(path) ? "" : path.StartsWith('/') ? path : "/" + path;

    // Stage abilities name their skills "skills" with "uris" objects; FA ones use the same key, FA ones also "visible" for exported.
    private static HarmonyAbility Ability(JsonElement a, string type)
    {
        var skills = Arr(a, "skills").ToList();
        var uris = skills.SelectMany(s => Arr(s, "uris")).Select(u => u.ValueKind == JsonValueKind.Object
            ? $"{Str(u, "scheme")}://{Str(u, "host")}{(Str(u, "port") is { } port ? ":" + port : "")}{UriPath(Str(u, "path") ?? Str(u, "pathStartWith") ?? Str(u, "pathRegex"))}"
            : u.ToString()).Distinct(StringComparer.Ordinal).ToList();
        bool exported = Bool(a, "exported") ?? Bool(a, "visible") ?? false;
        var permissions = Arr(a, "permissions").Select(x => x.ToString()).ToList();
        return new HarmonyAbility(Str(a, "name") ?? "", type, Str(a, "srcEntry") ?? Str(a, "srcEntrance") ?? Str(a, "srcPath"), exported,
            skills.SelectMany(s => Arr(s, "actions")).Select(x => x.ToString()).Distinct(StringComparer.Ordinal).ToList(),
            skills.SelectMany(s => Arr(s, "entities")).Select(x => x.ToString()).Distinct(StringComparer.Ordinal).ToList(), uris, permissions);
    }

    private static byte[] Bytes(ZipArchiveEntry e)
    {
        using var s = e.Open();
        using var m = new MemoryStream();
        s.CopyTo(m);
        return m.ToArray();
    }

    private static JsonElement Obj(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) ? v : default;

    private static IEnumerable<JsonElement> Arr(JsonElement e, string name) =>
        Obj(e, name) is { ValueKind: JsonValueKind.Array } a ? a.EnumerateArray() : [];

    private static string? Str(JsonElement e, string name) => Obj(e, name) switch
    {
        { ValueKind: JsonValueKind.String } s => s.GetString(),
        { ValueKind: JsonValueKind.Number } n => n.GetRawText(),
        _ => null,
    };

    private static long? Long(JsonElement e, string name) => Obj(e, name) switch
    {
        { ValueKind: JsonValueKind.Number } n when n.TryGetInt64(out var v) => v,
        { ValueKind: JsonValueKind.String } s when long.TryParse(s.GetString(), out var v) => v,
        _ => null,
    };

    private static bool? Bool(JsonElement e, string name) => Obj(e, name) switch
    {
        { ValueKind: JsonValueKind.True } => true,
        { ValueKind: JsonValueKind.False } => false,
        _ => null,
    };
}
