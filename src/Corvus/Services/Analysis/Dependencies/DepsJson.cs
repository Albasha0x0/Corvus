using System.Text.Json;

namespace Corvus.Services.Analysis.Dependencies;

/// <summary>A library of a deps.json: type is package, project, runtimepack or reference; Sha512 is the package hash in hex, or null.</summary>
public sealed record DepsLibrary(string Name, string Version, string Type, string? Sha512)
{
    /// <summary>The target's dependencies of this library, by name with the resolved version.</summary>
    public IReadOnlyDictionary<string, string> Dependencies { get; init; } = new Dictionary<string, string>();

    /// <summary>The runtime, native and resource asset paths the target lists for it.</summary>
    public IReadOnlyList<string> Assets { get; init; } = [];
}

/// <summary>A .deps.json dependency manifest: the runtime target and its libraries with dependencies and assets.</summary>
public sealed record DepsJson(string Path, string? RuntimeTarget, IReadOnlyList<DepsLibrary> Libraries)
{
    private const int MaxLibraries = 20_000;

    /// <summary>The manifest in <paramref name="json"/>, or null when it is no deps.json or does not parse.</summary>
    public static DepsJson? Parse(string path, byte[] json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("libraries", out var libraries) || libraries.ValueKind != JsonValueKind.Object)
                return null;
            string? runtimeTarget = root.TryGetProperty("runtimeTarget", out var rt) && rt.ValueKind == JsonValueKind.Object
                && rt.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString() : null;
            var target = Target(root, runtimeTarget);
            var list = new List<DepsLibrary>();
            foreach (var lib in libraries.EnumerateObject())
            {
                if (list.Count >= MaxLibraries) break;
                int slash = lib.Name.IndexOf('/');
                if (slash <= 0 || lib.Value.ValueKind != JsonValueKind.Object) continue;
                var type = lib.Value.TryGetProperty("type", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString()! : "unknown";
                var sha = lib.Value.TryGetProperty("sha512", out var s) && s.ValueKind == JsonValueKind.String ? Sha512Hex(s.GetString()!) : null;
                var entry = new DepsLibrary(lib.Name[..slash], lib.Name[(slash + 1)..], type, sha);
                if (target is { } tg && tg.TryGetProperty(lib.Name, out var detail) && detail.ValueKind == JsonValueKind.Object)
                    entry = entry with { Dependencies = Dependencies(detail), Assets = Assets(detail) };
                list.Add(entry);
            }
            return new DepsJson(path, runtimeTarget, list);
        }
        catch (JsonException) { return null; }
    }

    /// <summary>The target the runtime uses: the runtimeTarget name, else the first that lists libraries.</summary>
    private static JsonElement? Target(JsonElement root, string? name)
    {
        if (!root.TryGetProperty("targets", out var targets) || targets.ValueKind != JsonValueKind.Object) return null;
        if (name != null && targets.TryGetProperty(name, out var named) && named.ValueKind == JsonValueKind.Object) return named;
        foreach (var t in targets.EnumerateObject())
            if (t.Value.ValueKind == JsonValueKind.Object && t.Value.EnumerateObject().Any()) return t.Value;
        return null;
    }

    private static Dictionary<string, string> Dependencies(JsonElement detail)
    {
        var deps = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (detail.TryGetProperty("dependencies", out var d) && d.ValueKind == JsonValueKind.Object)
            foreach (var p in d.EnumerateObject())
                if (p.Value.ValueKind == JsonValueKind.String) deps[p.Name] = p.Value.GetString()!;
        return deps;
    }

    private static List<string> Assets(JsonElement detail)
    {
        var assets = new List<string>();
        foreach (var kind in new[] { "runtime", "native", "resources" })
            if (detail.TryGetProperty(kind, out var a) && a.ValueKind == JsonValueKind.Object)
                assets.AddRange(a.EnumerateObject().Select(p => p.Name));
        if (detail.TryGetProperty("runtimeTargets", out var rts) && rts.ValueKind == JsonValueKind.Object)
            assets.AddRange(rts.EnumerateObject().Select(p => p.Name));
        return assets;
    }

    /// <summary>"sha512-&lt;base64&gt;" as lowercase hex; null when empty or malformed.</summary>
    internal static string? Sha512Hex(string value)
    {
        const string prefix = "sha512-";
        if (!value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return null;
        var bytes = new byte[64];
        return Convert.TryFromBase64String(value[prefix.Length..], bytes, out int written) && written == 64 ? Convert.ToHexStringLower(bytes) : null;
    }
}
