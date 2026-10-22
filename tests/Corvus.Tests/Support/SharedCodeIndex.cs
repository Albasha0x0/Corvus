using System.Security.Cryptography;
using Corvus.Core;
using Corvus.Native.Code;

namespace Corvus.Tests;

/// <summary>
/// A code index cache shared by tests and test runs of one server build: an image is indexed once, and later tests load
/// the saved index, as the server does by default. Tests about building an index keep the cache off.
/// </summary>
internal static class SharedCodeIndex
{
    private static readonly string Folder = Path.Combine(LeakGuard.SharedTemp, "corvus-test-data", "code-index");
    private static readonly Lazy<CodeIndexCacheOptions> Cache = new(Create);

    /// <summary>Server options with the shared cache; every index is saved, however fast it built.</summary>
    public static ServerOptions Options() => new() { CodeIndexCache = Cache.Value };

    // The key is the server build: the index is built by its code, so another build indexes again.
    private static CodeIndexCacheOptions Create()
    {
        var build = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(typeof(NativeCodeIndex).Assembly.Location)))[..12];
        RemoveOtherBuilds(build);
        return new(Path.Combine(Folder, build), 1L << 30, TimeSpan.FromDays(1), TimeSpan.Zero);
    }

    /// <summary>Caches of other builds unused for a day.</summary>
    private static void RemoveOtherBuilds(string build)
    {
        if (!Directory.Exists(Folder)) return;
        foreach (var dir in Directory.EnumerateDirectories(Folder))
        {
            if (Path.GetFileName(dir) == build || Directory.GetLastWriteTimeUtc(dir) > DateTime.UtcNow.AddDays(-1)) continue;
            try { Directory.Delete(dir, true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }
}
