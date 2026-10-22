using Corvus.Core;
using Corvus.Native.Code;

namespace Corvus.Tests;

/// <summary>
/// A code index cache shared by tests and test runs: an image is indexed once, and later tests load the saved index, as
/// the server does by default. Tests about building an index keep the cache off.
/// </summary>
internal static class SharedCodeIndex
{
    private static readonly string Folder = Path.Combine(LeakGuard.SharedTemp, "corvus-test-data", "code-index");
    private static readonly Lazy<CodeIndexCacheOptions> Cache = new(Create);

    /// <summary>Server options with the shared cache; every index is saved, however fast it built.</summary>
    public static ServerOptions Options() => new() { CodeIndexCache = Cache.Value };

    // Keyed as the server keys its own cache (input hash, build options, index format version), so it stays warm across
    // server builds.
    private static CodeIndexCacheOptions Create()
    {
        RemoveBuildFolders();
        return new(Folder, 1L << 30, TimeSpan.FromDays(1), TimeSpan.Zero);
    }

    /// <summary>Per-build folders an earlier layout kept, unused for a day.</summary>
    private static void RemoveBuildFolders()
    {
        if (!Directory.Exists(Folder)) return;
        foreach (var dir in Directory.EnumerateDirectories(Folder))
        {
            if (Directory.GetLastWriteTimeUtc(dir) > DateTime.UtcNow.AddDays(-1)) continue;
            try { Directory.Delete(dir, true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }
}
