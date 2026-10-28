using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using Corvus.Native.Providers;

namespace Corvus.Core;

/// <summary>
/// A public YARA rule set pinned to one release archive by URL and SHA-256;
/// LicenseEntry is null when it has none, AsOf (the release's publication date)
/// when it is not pinned.
/// </summary>
public sealed record RulePack(string Name, string Version, string Url, string Sha256, string RulesFolder, string? LicenseEntry, string License, string Description,
    DateOnly? AsOf = null);

/// <summary>
/// A rule pack installed under the data folder: its version, folder, number of
/// rule files, and the as-of date pinned for it (null when unknown).
/// </summary>
public sealed record InstalledRulePack(string Name, string Version, string Folder, int RuleFiles, DateOnly? AsOf = null)
{
    /// <summary>The version digest: the SHA-256 of the archive the pack was installed from, as its manifest records it; null when unreadable.</summary>
    public string? Digest { get; init; }

    /// <summary>
    /// "name version, rules as of yyyy-MM-dd"; "as of unknown" without the date.
    /// </summary>
    public string Label => $"{Name} {Version}, rules as of {AsOf?.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture) ?? "unknown"}";
}

/// <summary>
/// Opt-in YARA rule packs fetched by <c>corvus rules fetch</c> or imported by
/// <c>corvus rules import</c>, verified against a pinned SHA-256.
/// </summary>
/// <remarks>Installed with their license under &lt;data&gt;/rules/&lt;pack&gt;/&lt;version&gt;/; search_container kind=yara reads them as query=pack:&lt;name&gt;.</remarks>
public static class RulePacks
{
    public const string QueryPrefix = "pack:";
    private const string ManifestName = "pack.json";
    private const string LicenseName = "LICENSE";
    private static readonly JsonSerializerOptions ManifestJson = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>Archives above this size are refused before they are hashed; the largest pinned one is 52 MB.</summary>
    public const long MaxArchiveBytes = 256L << 20;

    /// <summary>
    /// The known packs. A new release is pinned by changing its row: URL,
    /// SHA-256, version, folder and as-of date together.
    /// </summary>
    public static readonly IReadOnlyList<RulePack> Known =
    [
        new("malcontent", "1.27.1", "https://github.com/chainguard-dev/malcontent/archive/refs/tags/v1.27.1.tar.gz",
            "cb331829862efdc0a7d2a10abdbc47fbcfd4af3b6c9978b213938b756c87a180", "malcontent-1.27.1/rules/", "malcontent-1.27.1/LICENSE", "Apache-2.0",
            "Chainguard malcontent's rules: capabilities and behaviours of programs and scripts.", new DateOnly(2026, 10, 7)),
        new("yara-forge-core", "20261018", "https://github.com/YARAHQ/yara-forge/releases/download/20261018/yara-forge-rules-core.zip",
            "d5b5f0006a0c58684459c3967b6aaae94f1e128597ed23ea5d4e8f16965a74ba", "packages/core/", null,
            "per rule: each rule's license meta and its source repository's header block in the .yar file",
            "YARA Forge's core package: curated rules from public repositories.", new DateOnly(2026, 10, 18)),
    ];

    /// <summary>The folder packs are installed in: &lt;data&gt;/rules.</summary>
    public static string Root => DataFolder.Combine("rules");

    /// <summary>The known pack named <paramref name="name"/> (any letter case), or null.</summary>
    public static RulePack? Find(string name) => Known.FirstOrDefault(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    /// <summary>Every installed pack under <paramref name="root"/>, by name then version; an empty list when none is.</summary>
    public static IReadOnlyList<InstalledRulePack> Installed(string root)
    {
        if (!Directory.Exists(root)) return [];
        var packs = new List<InstalledRulePack>();
        foreach (var pack in Directory.EnumerateDirectories(root).Order(StringComparer.Ordinal))
            foreach (var version in Directory.EnumerateDirectories(pack).Where(d => File.Exists(Path.Combine(d, ManifestName))).Order(StringComparer.Ordinal))
                packs.Add(At(version));
        return packs;
    }

    /// <summary>
    /// The installed pack in <paramref name="folder"/>; its as-of date is null
    /// when the manifest holds none.
    /// </summary>
    public static InstalledRulePack At(string folder)
    {
        DateOnly? asOf = null;
        string? digest = null;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(folder, ManifestName)));
            if (doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("asOf", out var t)
                && t.ValueKind == JsonValueKind.String
                && DateOnly.TryParseExact(t.GetString(), "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var date))
                asOf = date;
            if (doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("sha256", out var sha) && sha.ValueKind == JsonValueKind.String)
                digest = sha.GetString();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException) { }
        var version = Path.TrimEndingDirectorySeparator(folder);
        return new InstalledRulePack(Path.GetFileName(Path.GetDirectoryName(version))!, Path.GetFileName(version), folder, RuleFiles(folder).Count(), asOf) { Digest = digest };
    }

    /// <summary>The installed pack's folder, pinned version first, else the last installed; null when none is.</summary>
    public static string? Folder(string root, string name)
    {
        var installed = Installed(root).Where(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).ToList();
        if (installed.Count == 0) return null;
        var pinned = Find(name)?.Version;
        return (installed.FirstOrDefault(p => p.Version == pinned)
                ?? installed.OrderBy(p => File.GetLastWriteTimeUtc(Path.Combine(p.Folder, ManifestName))).Last()).Folder;
    }

    /// <summary>The rule folder a pack:&lt;name&gt; query names, null for other queries; a missing pack is a not_found error naming the install command.</summary>
    public static string? ResolveQuery(string query, string root)
    {
        var text = query.Trim();
        if (!text.StartsWith(QueryPrefix, StringComparison.OrdinalIgnoreCase) || text.Contains('\n')) return null;
        var name = text[QueryPrefix.Length..].Trim();
        if (Folder(root, name) is { } folder) return folder;
        var installed = Installed(root).Select(p => p.Name).Distinct().ToList();
        throw new ToolError(ErrorCode.NotFound, $"Rule pack '{name}' is not installed" + (installed.Count > 0 ? $" (installed: {string.Join(", ", installed)})." : "."),
            Find(name) is { } known ? $"run: corvus rules fetch {known.Name}" : $"corvus rules list names the known packs: {string.Join(", ", Known.Select(p => p.Name))}");
    }

    /// <summary>Installs <paramref name="pack"/> unless present; refuses offline, past <see cref="MaxArchiveBytes"/>, or on a hash mismatch.</summary>
    public static async Task<(InstalledRulePack Pack, bool Downloaded)> FetchAsync(RulePack pack, string root, HttpMessageHandler handler, bool offline, CancellationToken ct)
    {
        var target = Path.Combine(root, pack.Name, pack.Version);
        if (File.Exists(Path.Combine(target, ManifestName))) return (At(target), false);
        if (offline)
            throw new ToolError(ErrorCode.Unsupported, $"CORVUS_OFFLINE is set: rule pack {pack.Name} {pack.Version} is not downloaded.", "unset CORVUS_OFFLINE to fetch it");

        byte[] archive;
        using (var http = new HttpClient(handler, disposeHandler: false) { Timeout = TimeSpan.FromMinutes(10) })
        {
            http.DefaultRequestHeaders.UserAgent.ParseAdd("Corvus/" + (typeof(RulePacks).Assembly.GetName().Version?.ToString(3) ?? "0"));
            using var response = await http.GetAsync(pack.Url, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
                throw new ToolError(ErrorCode.Failed, $"{pack.Url} answered {(int)response.StatusCode} {response.ReasonPhrase}; nothing was installed.");
            if (response.Content.Headers.ContentLength > MaxArchiveBytes) throw TooLarge(pack);
            await using var body = await response.Content.ReadAsStreamAsync(ct);
            using var buffer = new MemoryStream();
            var chunk = new byte[1 << 16];
            for (int n; (n = await body.ReadAsync(chunk, ct)) > 0;)
            {
                if (buffer.Length + n > MaxArchiveBytes) throw TooLarge(pack);
                buffer.Write(chunk, 0, n);
            }
            archive = buffer.ToArray();
        }
        var actual = Convert.ToHexStringLower(SHA256.HashData(archive));
        if (!actual.Equals(pack.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new ToolError(ErrorCode.Failed, $"{pack.Url}: SHA-256 {actual} differs from the pinned {pack.Sha256}; nothing was installed.");
        return (Install(pack, archive, root, pack.Url), true);
    }

    /// <summary>
    /// Installs the pinned pack a local archive holds, unless present: the one
    /// named, else the one whose SHA-256 the archive has. Refuses past
    /// <see cref="MaxArchiveBytes"/> and an archive whose SHA-256 is not the pin,
    /// naming both hashes. Reads no network.
    /// </summary>
    public static (InstalledRulePack Pack, bool Installed) Import(string archivePath, string root, string? name = null, IReadOnlyList<RulePack>? pins = null)
    {
        pins ??= Known;
        var path = InputFiles.RequireRegularFile(archivePath, "archive");
        if (new FileInfo(path).Length > MaxArchiveBytes)
            throw new ToolError(ErrorCode.LimitExceeded, $"{path} is larger than {MaxArchiveBytes >> 20} MB; nothing was installed.");
        var archive = File.ReadAllBytes(path);
        var actual = Convert.ToHexStringLower(SHA256.HashData(archive));
        RulePack pack;
        if (name != null)
        {
            pack = pins.FirstOrDefault(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                   ?? throw new ToolError(ErrorCode.NotFound, $"Unknown rule pack '{name}'.", $"corvus rules list names the known packs: {string.Join(", ", pins.Select(p => p.Name))}");
            if (!actual.Equals(pack.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new ToolError(ErrorCode.Failed, $"{path}: SHA-256 {actual} differs from the pinned {pack.Sha256} of {pack.Name} {pack.Version}; nothing was installed.");
        }
        else
            pack = pins.FirstOrDefault(p => actual.Equals(p.Sha256, StringComparison.OrdinalIgnoreCase))
                   ?? throw new ToolError(ErrorCode.Failed,
                       $"{path}: SHA-256 {actual} is not pinned ({string.Join("; ", pins.Select(p => $"{p.Name} {p.Version}: {p.Sha256}"))}); nothing was installed.");
        var target = Path.Combine(root, pack.Name, pack.Version);
        if (File.Exists(Path.Combine(target, ManifestName))) return (At(target), false);
        return (Install(pack, archive, root, path), true);
    }

    /// <summary>
    /// Extracts a verified archive of <paramref name="pack"/>;
    /// <paramref name="source"/> names it in errors and the manifest.
    /// </summary>
    private static InstalledRulePack Install(RulePack pack, byte[] archive, string root, string source)
    {
        var target = Path.Combine(root, pack.Name, pack.Version);
        // Extract beside the target, then move it in, so a failed extraction leaves no partial pack.
        var staging = Path.Combine(root, pack.Name, ".new-" + Guid.NewGuid().ToString("N"));
        try
        {
            var license = Extract(pack, archive, staging);
            if (license == null)
            {
                if (pack.LicenseEntry != null)
                    throw new ToolError(ErrorCode.MalformedInput, $"{source} holds no {pack.LicenseEntry}; nothing was installed.");
                SafeFile.WritePrivateUnderRoot(staging, LicenseName,
                    System.Text.Encoding.UTF8.GetBytes($"{pack.Name} {pack.Version}: license {pack.License}.\nSource: {pack.Url}\n"), overwrite: false);
            }
            if (!RuleFiles(staging).Any()) throw new ToolError(ErrorCode.MalformedInput, $"{source} holds no .yar or .yara files under {pack.RulesFolder}; nothing was installed.");
            var manifest = JsonSerializer.SerializeToUtf8Bytes(
                new { pack.Name, pack.Version, pack.Url, Source = source, pack.Sha256, pack.License, AsOf = pack.AsOf?.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture), Installed = DateTimeOffset.UtcNow }, ManifestJson);
            SafeFile.WritePrivateUnderRoot(staging, ManifestName, manifest, overwrite: false);
            if (Directory.Exists(target)) Directory.Delete(target, recursive: true);
            Directory.Move(staging, target);
        }
        finally
        {
            if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true);
        }
        return At(target);
    }

    private static ToolError TooLarge(RulePack pack) =>
        new(ErrorCode.LimitExceeded, $"{pack.Url} is larger than {MaxArchiveBytes >> 20} MB; nothing was installed.");

    private static IEnumerable<string> RuleFiles(string folder) =>
        Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".yara", StringComparison.OrdinalIgnoreCase));

    /// <summary>Writes the pack's rule files and license under <paramref name="folder"/>; returns the license path, or null when the archive has none.</summary>
    private static string? Extract(RulePack pack, byte[] archive, string folder)
    {
        string? license = null;
        void Entry(string name, Func<byte[]> read)
        {
            name = name.Replace('\\', '/');
            if (name == pack.LicenseEntry) license = SafeFile.WritePrivateUnderRoot(folder, LicenseName, read(), overwrite: true, flush: false);
            else if (name.StartsWith(pack.RulesFolder, StringComparison.Ordinal) && name.Length > pack.RulesFolder.Length
                     && (name.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".yara", StringComparison.OrdinalIgnoreCase)))
                SafeFile.WritePrivateUnderRoot(folder, name[pack.RulesFolder.Length..], read(), overwrite: true, flush: false);
        }

        if (pack.Url.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
        {
            using var zip = new ZipArchive(new MemoryStream(archive), ZipArchiveMode.Read);
            foreach (var e in zip.Entries.Where(e => !e.FullName.EndsWith('/')))
                Entry(e.FullName, () =>
                {
                    using var s = e.Open();
                    using var m = new MemoryStream();
                    s.CopyTo(m);
                    return m.ToArray();
                });
        }
        else
        {
            using var tar = new TarReader(new GZipStream(new MemoryStream(archive), CompressionMode.Decompress));
            // Links and devices are skipped: only regular files are written.
            while (tar.GetNextEntry() is { } e)
                if (e.EntryType is TarEntryType.RegularFile or TarEntryType.V7RegularFile && e.DataStream != null)
                    Entry(e.Name, () =>
                    {
                        using var m = new MemoryStream();
                        e.DataStream.CopyTo(m);
                        return m.ToArray();
                    });
        }
        return license;
    }
}
