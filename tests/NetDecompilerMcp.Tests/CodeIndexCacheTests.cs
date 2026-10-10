using System.Text.Json;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

/// <summary>Saved code indexes: a loaded index answers like a fresh build; changed, damaged or foreign entries are rebuilt; the cache stays bounded.</summary>
public sealed class CodeIndexCacheTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private CodeIndexCache NewCache(long maxBytes = 1L << 30, int maxDays = 30) =>
        new(new CodeIndexCacheOptions(_dir.File("cache"), maxBytes, TimeSpan.FromDays(maxDays), TimeSpan.Zero));

    private static string? VersionDll(bool wow = false)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var path = wow ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64", "version.dll") : Path.Combine(Environment.SystemDirectory, "version.dll");
        return File.Exists(path) ? path : null;
    }

    [Fact]
    public void Loaded_index_answers_like_a_fresh_build()
    {
        foreach (var path in new[] { VersionDll(), VersionDll(wow: true) })
        {
            if (path == null) continue;
            var cache = NewCache();
            var built = NativeCodeIndex.Build(PeFile.Open(path));
            Assert.True(cache.Save(built, null));
            var loaded = cache.TryLoad(PeFile.Open(path), null);
            Assert.NotNull(loaded);
            Assert.True(loaded.LoadedFromCache);
            AssertSameIndex(built, loaded, graphs: int.MaxValue);
            Assert.Equal(1, cache.Status().Hits);
        }
    }

    [Trait("Speed", "Slow")]
    [Theory]
    [InlineData("kernelbase.dll", false)]
    [InlineData("kernelbase.dll", true)]
    [InlineData("ntdll.dll", false)]
    [InlineData("msvcp_win.dll", false)]
    [InlineData("combase.dll", true)]
    public void Loaded_index_of_a_system_dll_answers_like_a_fresh_build(string name, bool wow)
    {
        if (!OperatingSystem.IsWindows()) return;
        var path = Path.Combine(wow ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64") : Environment.SystemDirectory, name);
        if (!File.Exists(path)) return;
        var cache = NewCache();
        var built = NativeCodeIndex.Build(PeFile.Open(path));
        Assert.True(cache.Save(built, null));
        var loaded = cache.TryLoad(PeFile.Open(path), null)!;
        AssertSameIndex(built, loaded, graphs: 3000);
    }

    [Fact]
    public void Changed_bytes_or_options_miss_and_damaged_entries_are_rebuilt()
    {
        if (VersionDll() is not { } path) return;
        var bytes = File.ReadAllBytes(path);
        var cache = NewCache();
        var image = PeFile.FromBytes(bytes, path);
        var built = NativeCodeIndex.Build(image);
        Assert.True(cache.Save(built, null));
        var file = Directory.GetFiles(_dir.File("cache"), "*.cidx").Single();

        // one byte of the image (the header time stamp), and other symbol starts: other keys
        var changed = (byte[])bytes.Clone();
        changed[BitConverter.ToInt32(bytes, 0x3C) + 8] ^= 1;
        Assert.Null(cache.TryLoad(PeFile.FromBytes(changed, path), null));
        Assert.Null(cache.TryLoad(image, new CodeIndexOptions { SymbolStarts = [built.Functions[0].Start] }));
        Assert.Equal(2, cache.Status().Misses);
        Assert.NotNull(cache.TryLoad(image, new CodeIndexOptions()));

        var good = File.ReadAllBytes(file);
        var damaged = new List<byte[]>
        {
            Array.Empty<byte>(), good[..50], good[..(good.Length / 2)], good[..^1], Flip(good, 8), Flip(good, 120), Flip(good, good.Length - 3),
            Enumerable.Repeat((byte)0xAB, good.Length).ToArray(),
        };
        // another format version
        var version = (byte[])good.Clone();
        BitConverter.GetBytes(NativeCodeIndex.PersistFormatVersion + 1).CopyTo(version, 8);
        damaged.Add(version);
        foreach (var bad in damaged)
        {
            File.WriteAllBytes(file, bad);
            Assert.Null(cache.TryLoad(image, null));
        }
        Assert.Equal(damaged.Count, cache.Status().Rejected);
        Assert.NotNull(cache.Status().LastError);

        // the next build overwrites the entry
        Assert.True(cache.Save(NativeCodeIndex.Build(image), null));
        Assert.NotNull(cache.TryLoad(image, null));
    }

    private static byte[] Flip(byte[] b, int at)
    {
        var c = (byte[])b.Clone();
        c[at] ^= 0x40;
        return c;
    }

    [Fact]
    public void Eviction_keeps_the_cache_within_its_size_and_age()
    {
        var root = _dir.File("cache");
        Directory.CreateDirectory(root);
        var now = DateTime.UtcNow;
        string Entry(string name, int kb, double daysAgo)
        {
            var f = Path.Combine(root, name);
            File.WriteAllBytes(f, new byte[kb * 1024]);
            File.SetLastWriteTimeUtc(f, now.AddDays(-daysAgo));
            File.SetLastAccessTimeUtc(f, now.AddDays(-daysAgo));
            return f;
        }
        var old = Entry("old.cidx", 10, 40);
        var lru = Entry("lru.cidx", 600, 3);
        var recent = Entry("recent.cidx", 600, 1);
        var newest = Entry("newest.cidx", 300, 0);
        var stale = Entry("x.cidx.1.tmp", 1, 2);
        var other = Entry("keep.txt", 1, 100);

        var cache = NewCache(maxBytes: 1024 * 1024, maxDays: 30);
        cache.Evict();
        Assert.False(File.Exists(old));     // unused past the age limit
        Assert.False(File.Exists(lru));     // least recently used beyond the size limit
        Assert.True(File.Exists(recent));
        Assert.True(File.Exists(newest));
        Assert.False(File.Exists(stale));   // abandoned temporary file
        Assert.True(File.Exists(other));    // not the cache's
        var status = cache.Status();
        Assert.Equal((2, 900L * 1024, 2), (status.Entries, status.Bytes, status.Evicted));
    }

    [Fact]
    public async Task Two_processes_saving_and_loading_one_entry_never_see_a_partial_file()
    {
        if (VersionDll(wow: true) is not { } path) return;
        var image = PeFile.Open(path);
        var built = NativeCodeIndex.Build(image);
        // two caches over one directory stand for two server processes
        var caches = new[] { NewCache(), NewCache() };
        var tasks = Enumerable.Range(0, 8).Select(i => Task.Run(() =>
        {
            var c = caches[i % 2];
            for (int k = 0; k < 4; k++)
            {
                c.Save(built, null);
                if (c.TryLoad(PeFile.Open(path), null) is { } loaded) Assert.Equal(built.Stats.Xrefs, loaded.Stats.Xrefs);
            }
        })).ToArray();
        await Task.WhenAll(tasks);
        Assert.Equal(0, caches.Sum(c => c.Status().Rejected));
        Assert.Single(Directory.GetFiles(_dir.File("cache")));
    }

    [Fact]
    public async Task Reopened_image_loads_its_saved_index_with_user_names()
    {
        if (VersionDll() is not { } source) return;
        var path = _dir.File("version.dll");
        File.Copy(source, path);
        var options = new ServerOptions { BackgroundIndexing = false, CodeIndexCache = new CodeIndexCacheOptions(_dir.File("cache"), 1L << 30, TimeSpan.FromDays(1), TimeSpan.Zero) };
        var annotations = new NetDecompilerMcp.Native.Annotations.AnnotationStore(_dir.File("ann"));
        uint rva;
        using (var ws = new AssemblyWorkspace())
        {
            var code = new NativeCodeService(ws, options, annotations: annotations);
            var native = ws.LoadAny(path).Native!;
            var index = await code.Index(native, null, default);
            Assert.False(index.LoadedFromCache);
            rva = index.Functions.Last(f => f.KnownName == null).Start;
            code.Annotations(native).SetName(rva, "my_function");
            index.SetUserName(rva, "my_function");
            Assert.Equal(1, code.IndexCache!.Status().Writes);
        }
        using (var ws = new AssemblyWorkspace())
        {
            var code = new NativeCodeService(ws, options, annotations: annotations);
            var native = ws.LoadAny(path).Native!;
            var index = await code.Index(native, null, default);
            Assert.True(index.LoadedFromCache);
            Assert.Equal("my_function", index.FunctionByStart(rva)!.Name);
            // the saved index holds the analysis' names only
            index.SetUserName(rva, null);
            Assert.Equal($"sub_{rva:X}", index.FunctionByStart(rva)!.Name);
        }
    }

    [Fact]
    public void Command_line_and_environment_choose_the_cache()
    {
        Assert.Null(new ServerOptions().CodeIndexCache);
        Assert.Null(ServerOptions.Parse(["--index-cache", "off"]).CodeIndexCache);
        var o = ServerOptions.Parse(["--index-cache", _dir.Path, "--index-cache-mb", "64", "--index-cache-days", "3"]).CodeIndexCache!;
        Assert.Equal((_dir.Path, 64L << 20, TimeSpan.FromDays(3)), (o.Root, o.MaxBytes, o.MaxAge));
        Assert.Throws<ArgumentException>(() => ServerOptions.Parse(["--index-cache-mb", "-1"]));
    }

    /// <summary>Every query a tool makes answers the same on both indexes; <paramref name="graphs"/> functions get their graphs and listings compared.</summary>
    internal static void AssertSameIndex(NativeCodeIndex a, NativeCodeIndex b, int graphs)
    {
        Assert.Equal(a.Support, b.Support);
        Assert.Equal(a.Stats, b.Stats);
        Assert.Equal(a.Truncations, b.Truncations);
        Assert.Equal(a.AbsoluteRefsUnconfirmed, b.AbsoluteRefsUnconfirmed);
        Assert.Equal(a.Strings, b.Strings);
        Assert.Equal(a.Functions.Count, b.Functions.Count);
        var json = new JsonSerializerOptions { IncludeFields = true };
        Assert.Equal(JsonSerializer.Serialize(a.ExceptionInfo, json), JsonSerializer.Serialize(b.ExceptionInfo, json));
        Assert.Equal(a.VirtualCalls.Sites, b.VirtualCalls.Sites);
        Assert.Equal(a.VirtualCalls.Stats, b.VirtualCalls.Stats);
        Assert.Equal(a.VirtualCalls.Notes, b.VirtualCalls.Notes);
        Assert.Equal(a.VirtualEdges, b.VirtualEdges);
        for (int i = 0; i < a.Functions.Count; i++)
        {
            var f = a.Functions[i];
            var g = b.Functions[i];
            Assert.Equal((f.Start, f.Name, f.Sources, f.Flags, f.End, f.Size, f.BlockCount, f.InstructionCount, f.Parent?.Start, f.ThunkImport),
                (g.Start, g.Name, g.Sources, g.Flags, g.End, g.Size, g.BlockCount, g.InstructionCount, g.Parent?.Start, g.ThunkImport));
            Assert.Equal(f.Chunks, g.Chunks);
            Assert.Equal(a.Ranges(f), b.Ranges(g));
            Assert.Equal(a.RefsFrom(f), b.RefsFrom(g));
            Assert.Equal(a.RefsTo(f.Start), b.RefsTo(g.Start));
            Assert.Equal(a.Callers(f).Select(c => (c.From, c.Kind, c.Caller?.Start)), b.Callers(g).Select(c => (c.From, c.Kind, c.Caller?.Start)));
            Assert.Equal(a.Callees(f).Select(c => (c.From, c.Target, c.Kind, c.Import)), b.Callees(g).Select(c => (c.From, c.Target, c.Kind, c.Import)));
            foreach (var c in f.Chunks) Assert.Equal(a.ChunkOwner(c.Start)?.Start, b.ChunkOwner(c.Start)?.Start);
            Assert.Equal(a.FunctionAt(f.End - 1)?.Start, b.FunctionAt(f.End - 1)?.Start);
            if (i >= graphs) continue;
            var ga = a.GetGraph(f);
            var gb = b.GetGraph(g);
            Assert.Equal(ga.Blocks.Select(x => (x.Start, x.End, x.EndKind, x.InstructionCount, string.Join(",", x.Successors))),
                gb.Blocks.Select(x => (x.Start, x.End, x.EndKind, x.InstructionCount, string.Join(",", x.Successors))));
            Assert.Equal(ga.Switches.Select(s => (s.JumpRva, s.TableRva, string.Join(",", s.Targets))), gb.Switches.Select(s => (s.JumpRva, s.TableRva, string.Join(",", s.Targets))));
            Assert.Equal(ga.UnresolvedJumps, gb.UnresolvedJumps);
            Assert.Equal(ga.TailCalls, gb.TailCalls);
            Assert.Equal(a.DisassembleFunction(f, 400, out _).Select(l => l.Label + l.Line?.ToString()),
                b.DisassembleFunction(g, 400, out _).Select(l => l.Label + l.Line?.ToString()));
        }
        foreach (var s in a.Strings.Take(500)) Assert.Equal(a.CommentFor(s.Rva), b.CommentFor(s.Rva));
    }
}
