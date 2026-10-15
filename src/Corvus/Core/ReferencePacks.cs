using System.Collections.Concurrent;
using System.IO.Compression;
using System.Text.Json;

namespace Corvus.Core;

/// <summary>
/// Downloads a shared framework's reference pack (e.g. Microsoft.NETCore.App.Ref 6.0.x) from nuget.org when neither the
/// runtime nor the pack is installed, so code targeting that version resolves against its exact API.
/// Cached under the local application data folder; disabled by CORVUS_OFFLINE=1.
/// </summary>
internal static class ReferencePacks
{
    private const string FeedBase = "https://api.nuget.org/v3-flatcontainer/";
    /// <summary>One download per pack; a waiting call stops when it is cancelled, the download goes on for the next.</summary>
    private static readonly ConcurrentDictionary<string, Lazy<Task<string?>>> Fetched = new(StringComparer.OrdinalIgnoreCase);

    public static string CacheRoot { get; } = Corvus.Native.Providers.DataFolder.Combine("packs");

    public static bool Offline => Environment.GetEnvironmentVariable("CORVUS_OFFLINE") is "1" or "true";

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

    private static string? Download(string packId, int major)
    {
        var id = packId.ToLowerInvariant();
        try
        {
            // Calls wait on this download: a network that never answers costs seconds, not minutes.
            using var http = new HttpClient(new SocketsHttpHandler { ConnectTimeout = TimeSpan.FromSeconds(10) }) { Timeout = TimeSpan.FromSeconds(30) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("Corvus/" + (typeof(ReferencePacks).Assembly.GetName().Version?.ToString(3) ?? "0"));
            using var index = JsonDocument.Parse(http.GetStringAsync($"{FeedBase}{id}/index.json").GetAwaiter().GetResult());
            var version = index.RootElement.GetProperty("versions").EnumerateArray()
                .Select(v => v.GetString()!)
                .Where(v => !v.Contains('-'))
                .Select(v => (Text: v, Version: Version.TryParse(v, out var parsed) ? parsed : null))
                .Where(x => x.Version?.Major == major)
                .OrderByDescending(x => x.Version).Select(x => x.Text).FirstOrDefault();
            if (version == null) return null;

            var bytes = http.GetByteArrayAsync($"{FeedBase}{id}/{version}/{id}.{version}.nupkg").GetAwaiter().GetResult();
            var target = Path.Combine(CacheRoot, id, version);
            var staging = target + ".tmp-" + Guid.NewGuid().ToString("N");
            using (var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read))
            {
                foreach (var entry in zip.Entries)
                {
                    var name = entry.FullName.Replace('\\', '/');
                    if (!(name.StartsWith("ref/", StringComparison.OrdinalIgnoreCase) || name.StartsWith("data/", StringComparison.OrdinalIgnoreCase))
                        || name.EndsWith('/') || name.Contains("..", StringComparison.Ordinal)) continue;
                    var path = Path.Combine(staging, name);
                    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                    entry.ExtractToFile(path, overwrite: true);
                }
            }
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            try { SafeFile.WhenReleased(() => Directory.Move(staging, target), lost: () => Directory.Exists(target)); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException && Directory.Exists(target)) { Directory.Delete(staging, recursive: true); } // another process finished first
            var dir = Path.Combine(target, "ref", $"net{major}.0");
            return Directory.Exists(dir) ? dir : null;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException or UnauthorizedAccessException
                                       or JsonException or InvalidDataException or KeyNotFoundException or InvalidOperationException)
        {
            return null;
        }
    }
}
