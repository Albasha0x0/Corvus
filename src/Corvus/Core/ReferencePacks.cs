using System.Collections.Concurrent;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

namespace Corvus.Core;

/// <summary>Downloads a missing framework reference pack from nuget.org into local app data; CORVUS_OFFLINE=1 disables it.</summary>
/// <remarks>Used when neither the runtime nor the pack is installed, so code resolves against that version's exact API.</remarks>
internal static class ReferencePacks
{
    private const string FeedBase = "https://api.nuget.org/v3-flatcontainer/";
    private const string RegistrationBase = "https://api.nuget.org/v3/registration5-semver1/";
    private const string CatalogBase = "https://api.nuget.org/v3/catalog0/";
    /// <summary>One download per pack; a waiting call stops when it is cancelled, the download goes on for the next.</summary>
    private static readonly ConcurrentDictionary<string, Lazy<Task<string?>>> Fetched = new(StringComparer.OrdinalIgnoreCase);

    public static string CacheRoot { get; } = Corvus.Native.Providers.DataFolder.Combine("packs");

    /// <summary>1 or true: nothing is downloaded.</summary>
    public const string OfflineVariable = "CORVUS_OFFLINE";

    /// <summary>True when <see cref="OfflineVariable"/> is 1 or true.</summary>
    public static bool Offline => Corvus.Native.Providers.ExternalTools.ReadVariable(OfflineVariable) is "1" or "true";

    /// <summary>Why the most recent failed download in this process gave no pack (network, or the hash check); null when none failed.</summary>
    public static string? LastProblem { get; private set; }

    /// <summary>The cached <c>ref/net{major}.0</c> directory of the pack, downloading it once per process if needed.</summary>
    public static string? Get(string packId, int major)
    {
        if (major < 5) return null;
        if (Cached(packId, major) is { } dir) return dir;
        if (Offline) return null;
        var download = Fetched.GetOrAdd($"{packId}/{major}", _ => new Lazy<Task<string?>>(() => Task.Run(() => Download(packId, major)))).Value;
        download.Wait(AssemblyWorkspace.CallToken);
        return download.Result;
    }

    /// <summary>The newest cached pack directory for the major, else null.</summary>
    public static string? Cached(string packId, int major)
    {
        var packs = Path.Combine(CacheRoot, packId.ToLowerInvariant());
        if (!Directory.Exists(packs)) return null;
        try
        {
            return Directory.EnumerateDirectories(packs)
                .Select(d => (Dir: d, Version: Version.TryParse(Path.GetFileName(d), out var v) ? v : null))
                .Where(x => x.Version?.Major == major).OrderByDescending(x => x.Version)
                .Select(x => Path.Combine(x.Dir, "ref", $"net{major}.0")).FirstOrDefault(Directory.Exists);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>Writes the pack's reference assemblies and data files under <paramref name="folder"/>; other entries are left out.</summary>
    internal static void Extract(ZipArchive zip, string folder)
    {
        foreach (var entry in zip.Entries)
        {
            var name = entry.FullName.Replace('\\', '/');
            if (!(name.StartsWith("ref/", StringComparison.OrdinalIgnoreCase) || name.StartsWith("data/", StringComparison.OrdinalIgnoreCase))
                || name.EndsWith('/') || name.Contains("..", StringComparison.Ordinal)) continue;
            // Documentation files are 82% of a pack (6.0.36: 23.6 of 28.6 MB), unread, and calls wait on extraction.
            if (name.StartsWith("ref/", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)) continue;
            var path = Path.Combine(folder, name);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            entry.ExtractToFile(path, overwrite: true);
        }
    }

    private static string? Download(string packId, int major)
    {
        // Calls wait on this download: a network that never answers costs seconds, not minutes.
        using var http = new HttpClient(new SocketsHttpHandler { ConnectTimeout = TimeSpan.FromSeconds(10) }) { Timeout = TimeSpan.FromSeconds(30) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("Corvus/" + (typeof(ReferencePacks).Assembly.GetName().Version?.ToString(3) ?? "0"));
        var (dir, problem) = Download(http, packId, major, CacheRoot);
        if (problem != null) LastProblem = problem;
        return dir;
    }

    /// <summary>Downloads and extracts the newest pack for <paramref name="major"/> once its SHA-512 matches; null Dir with the problem otherwise.</summary>
/// <remarks>Problem is null too when nuget.org lists no release of that major.</remarks>
    internal static (string? Dir, string? Problem) Download(HttpClient http, string packId, int major, string root)
    {
        var id = packId.ToLowerInvariant();
        string? version = null;
        // Four requests share one bound, as the two before the hash check did.
        using var bound = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var ct = bound.Token;
        try
        {
            using (var index = JsonDocument.Parse(http.GetStringAsync($"{FeedBase}{id}/index.json", ct).GetAwaiter().GetResult()))
                version = index.RootElement.GetProperty("versions").EnumerateArray()
                    .Select(v => v.GetString()!)
                    .Where(v => !v.Contains('-'))
                    .Select(v => (Text: v, Version: Version.TryParse(v, out var parsed) ? parsed : null))
                    .Where(x => x.Version?.Major == major)
                    .OrderByDescending(x => x.Version).Select(x => x.Text).FirstOrDefault();
            if (version == null) return (null, null);

            var expected = PackageHash(http, id, version, ct);
            if (expected == null) return (null, Refused(id, version, "nuget.org lists no SHA-512 package hash for it"));
            var bytes = http.GetByteArrayAsync($"{FeedBase}{id}/{version}/{id}.{version}.nupkg", ct).GetAwaiter().GetResult();
            if (!CryptographicOperations.FixedTimeEquals(SHA512.HashData(bytes), expected))
                return (null, Refused(id, version, "its SHA-512 does not match nuget.org's package hash"));

            var target = Path.Combine(root, id, version);
            var staging = target + ".tmp-" + Guid.NewGuid().ToString("N");
            using (var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read))
                Extract(zip, staging);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            try { SafeFile.WhenReleased(() => Directory.Move(staging, target), lost: () => Directory.Exists(target)); }
            // Another process finished first.
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException && Directory.Exists(target)) { Directory.Delete(staging, recursive: true); }
            var dir = Path.Combine(target, "ref", $"net{major}.0");
            return Directory.Exists(dir) ? (dir, null) : (null, null);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or IOException or UnauthorizedAccessException
                                       or JsonException or InvalidDataException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            return (null, $"reference pack {id} {version ?? $"{major}.x"} not downloaded: {ex.Message}");
        }
    }

    private static string Refused(string id, string version, string reason) => $"reference pack {id} {version} refused: {reason}";

    /// <summary>The package SHA-512 from nuget.org's catalog; null when it names none or lies outside nuget.org.</summary>
    private static byte[]? PackageHash(HttpClient http, string id, string version, CancellationToken ct)
    {
        using var leaf = JsonDocument.Parse(http.GetStringAsync($"{RegistrationBase}{id}/{version.ToLowerInvariant()}.json", ct).GetAwaiter().GetResult());
        if (leaf.RootElement.GetProperty("catalogEntry").GetString() is not { } entry
            || !entry.StartsWith(CatalogBase, StringComparison.OrdinalIgnoreCase)) return null;
        using var catalog = JsonDocument.Parse(http.GetStringAsync(entry, ct).GetAwaiter().GetResult());
        var root = catalog.RootElement;
        if (!root.TryGetProperty("packageHashAlgorithm", out var algorithm) || !string.Equals(algorithm.GetString(), "SHA512", StringComparison.OrdinalIgnoreCase)
            || !root.TryGetProperty("packageHash", out var hash) || hash.GetString() is not { Length: > 0 } text) return null;
        var bytes = Convert.FromBase64String(text);
        return bytes.Length == SHA512.HashSizeInBytes ? bytes : null;
    }
}
