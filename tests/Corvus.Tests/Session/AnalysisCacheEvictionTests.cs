using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary>Size and age bounds of the engine database cache; an entry open in a session is never evicted.</summary>
public class AnalysisCacheEvictionTests
{
    private static string Input(TempDir dir, string name, int size)
    {
        var path = Path.Combine(dir.Path, name);
        var bytes = new byte[size];
        new Random(name.GetHashCode()).NextBytes(bytes);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static void Age(CacheEntry entry, TimeSpan age)
    {
        var when = DateTime.UtcNow - age;
        File.SetLastWriteTimeUtc(Path.Combine(entry.Directory, AnalysisCache.OwnerFile), when);
        Directory.SetLastWriteTimeUtc(entry.Directory, when);
    }

    [Fact]
    public void Entries_unused_past_the_age_limit_go_unless_open()
    {
        using var dir = new TempDir();
        var cache = new AnalysisCache(Path.Combine(dir.Path, "cache"), maxBytes: long.MaxValue, maxAge: TimeSpan.FromDays(1)) { AutoEvict = false };
        var old = cache.Acquire("ida", Input(dir, "old.bin", 4096), null);
        old.Dispose();
        Age(old, TimeSpan.FromDays(10));
        using var open = cache.Acquire("ghidra", Input(dir, "open.bin", 4096), null);
        Age(open, TimeSpan.FromDays(10));
        var fresh = cache.Acquire("ida", Input(dir, "fresh.bin", 4096), null);
        fresh.Dispose();

        Assert.Equal(1, cache.Evict());
        Assert.False(Directory.Exists(old.Directory));
        Assert.True(File.Exists(open.InputCopy));
        Assert.True(File.Exists(fresh.InputCopy));
        var status = cache.Status();
        Assert.Equal(2, status.Entries);
        Assert.True(status.Evicted >= 1);
    }

    [Fact]
    public void The_least_recently_used_go_first_beyond_the_size_limit()
    {
        using var dir = new TempDir();
        var cache = new AnalysisCache(Path.Combine(dir.Path, "cache"), maxBytes: 150_000, maxAge: TimeSpan.FromDays(365)) { AutoEvict = false };
        var entries = new List<CacheEntry>();
        foreach (var (name, days) in new[] { ("a.bin", 3), ("b.bin", 1), ("c.bin", 2) })
        {
            var e = cache.Acquire("ida", Input(dir, name, 100_000), null);
            e.Dispose();
            Age(e, TimeSpan.FromDays(days));
            entries.Add(e);
        }
        Assert.Equal(2, cache.Evict());
        Assert.Equal(new[] { false, true, false }, entries.Select(e => Directory.Exists(e.Directory)));
    }

    [Fact]
    public void Short_keyed_entries_are_counted_and_evicted()
    {
        using var dir = new TempDir();
        var root = Path.Combine(dir.Path, "cache");
        var shortKeys = new AnalysisCache(root, maxBytes: long.MaxValue, maxAge: TimeSpan.FromDays(1)) { ShortKeys = true, AutoEvict = false };
        var old = shortKeys.Acquire("ida", Input(dir, "old.bin", 4096), null);
        old.Dispose();
        Age(old, TimeSpan.FromDays(10));
        Assert.Equal(16, Path.GetFileName(old.Directory).Length);
        var fresh = shortKeys.Acquire("ida", Input(dir, "fresh.bin", 4096), null);
        fresh.Dispose();
        var legacy = new AnalysisCache(root) { AutoEvict = false }.Acquire("ghidra", Input(dir, "legacy.bin", 4096), null);
        legacy.Dispose();
        Assert.Equal(64, Path.GetFileName(legacy.Directory).Length);

        Assert.Equal(3, shortKeys.Status().Entries);
        Assert.Equal(1, shortKeys.Evict());
        Assert.False(Directory.Exists(old.Directory));
        Assert.Null(shortKeys.Find("ida", old.Sha256));
        Assert.Equal(fresh.Directory, shortKeys.Find("ida", fresh.Sha256));
        Assert.Equal(2, shortKeys.Status().Entries);
    }

    [Fact]
    public void Abandoned_snapshots_go_and_snapshots_in_use_stay()
    {
        using var dir = new TempDir();
        var cache = new AnalysisCache(Path.Combine(dir.Path, "cache")) { AutoEvict = false };
        var abandoned = Directory.CreateDirectory(Path.Combine(cache.Root, "ghidra", "snapshots", "abandoned"));
        File.WriteAllText(Path.Combine(abandoned.FullName, "db"), "x");
        var used = Directory.CreateDirectory(Path.Combine(cache.Root, "ghidra", "snapshots", "used"));
        using var hold = new FileStream(Path.Combine(used.FullName, ".lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose);
        foreach (var d in new[] { abandoned, used }) Directory.SetLastWriteTimeUtc(d.FullName, DateTime.UtcNow.AddDays(-2));

        Assert.Equal(0, cache.Evict());
        Assert.False(Directory.Exists(abandoned.FullName));
        Assert.True(Directory.Exists(used.FullName));
    }
}
