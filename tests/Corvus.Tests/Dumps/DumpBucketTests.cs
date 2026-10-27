using Corvus.Core;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>bucket_minidumps over synthetic crashes of synth.dll (Big → Outer → Crash): rebases, offsets, codes, hangs, versions, corrupt files and the cache.</summary>
public sealed class DumpBucketTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly MinidumpService _service;

    public DumpBucketTests()
    {
        Directory.CreateDirectory(_dir.File("dumps"));
        _service = new MinidumpService { BucketCache = _dir.File("cache") };
    }

    public void Dispose()
    {
        _service.Dispose();
        _dir.Dispose();
    }

    private string Folder => _dir.File("dumps");

    private void Write(string name, MinidumpBuilder builder) => File.WriteAllBytes(Path.Combine(Folder, name), builder.Build());

    private Task<MinidumpService.DumpBuckets> Run(bool splitByVersion = false, int topFrames = 3, string? skip = null) =>
        _service.Bucket(Folder, false, null, topFrames, skip, splitByVersion, true, 1000, null, 0, 50, null, default);

    [Fact]
    public async Task Crashes_group_by_signature_across_rebases_and_offsets()
    {
        Write("a.dmp", SyntheticCrash.Builder());
        Write("b.dmp", SyntheticCrash.Builder(moduleBase: 0x7FF6_3000_0000)); // rebased: same bucket
        Write("c.dmp", SyntheticCrash.Builder(moduleBase: 0x7FF6_5000_0000, faultOffset: 7)); // same function, another offset
        Write("d.mdmp", SyntheticCrash.Builder(code: 0xC0000094)); // another exception
        Write("hang.dmp", SyntheticCrash.Builder(exception: false));
        File.WriteAllBytes(Path.Combine(Folder, "broken.dmp"), "not a dump"u8.ToArray());
        File.WriteAllText(Path.Combine(Folder, "notes.txt"), "ignored");

        var r = await Run();
        Assert.Equal(6, r.Dumps.Seen);
        Assert.Equal(6, r.Dumps.Parsed);
        Assert.Equal(1, r.Dumps.Failed);
        Assert.Equal("broken.dmp", Path.GetFileName(Assert.Single(r.Failed).Path));
        Assert.Contains("not a Windows minidump", r.Failed[0].Reason);
        Assert.Equal(3, r.Total);

        var av = r.Items[0];
        Assert.Equal("0xC0000005 | synth!Crash | synth!Outer > synth!Big", av.Signature);
        Assert.Equal("exception", av.Kind);
        Assert.Equal(3, av.Count);
        Assert.Equal(new Dictionary<string, int> { ["+0x5"] = 2, ["+0x7"] = 1 }, av.Offsets);
        Assert.Equal(new Dictionary<string, int> { ["1.2.3.4"] = 3 }, av.ModuleVersions);
        Assert.Equal(["a.dmp", "b.dmp", "c.dmp"], av.Sample.Order());
        Assert.Contains(av.Representative, av.Sample);
        Assert.Contains(r.Items, b => b.Signature.StartsWith("0xC0000094 | synth!Crash", StringComparison.Ordinal));
        var hang = Assert.Single(r.Items, b => b.Kind == "no_exception");
        Assert.StartsWith("hang | synth!Crash", hang.Signature);

        // The representatives open by id.
        var opened = await _service.Summarize(av.Representative, null, default);
        Assert.Equal(av.Representative, opened.Id);
    }

    [Fact]
    public async Task Versions_split_on_request_and_frames_can_be_skipped()
    {
        Write("v1.dmp", SyntheticCrash.Builder());
        Write("v2.dmp", SyntheticCrash.Builder(versionLs: 0x00030005));
        Assert.Equal(1, (await Run()).Total);
        var split = await Run(splitByVersion: true);
        Assert.Equal(2, split.Total);
        Assert.Contains(split.Items, b => b.Signature.EndsWith("| version 1.2.3.5", StringComparison.Ordinal));

        var skipped = await Run(skip: "synth!Crash");
        Assert.Equal("0xC0000005 | synth!Outer | synth!Big", skipped.Items[0].Signature);
        Assert.Equal("0xC0000005 | synth!Crash | ", (await Run(topFrames: 0)).Items[0].Signature);
    }

    [Fact]
    public async Task A_second_run_parses_only_new_or_changed_dumps()
    {
        Write("a.dmp", SyntheticCrash.Builder());
        Write("b.dmp", SyntheticCrash.Builder(code: 0xC0000094));
        var first = await Run();
        Assert.Equal((2, 0), (first.Dumps.Parsed, first.Dumps.Cached));

        var again = await Run();
        Assert.Equal((0, 2), (again.Dumps.Parsed, again.Dumps.Cached));
        Assert.Equal(first.Items.Select(b => b.Signature), again.Items.Select(b => b.Signature));

        File.SetLastWriteTimeUtc(Path.Combine(Folder, "a.dmp"), DateTime.UtcNow.AddMinutes(1));
        Write("c.dmp", SyntheticCrash.Builder(moduleBase: 0x7FF6_3000_0000));
        var third = await Run();
        Assert.Equal((2, 1), (third.Dumps.Parsed, third.Dumps.Cached));
        Assert.Equal(3, third.Items.Sum(b => b.Count));

        // Other options are another cache key.
        var split = await Run(splitByVersion: false, topFrames: 1);
        Assert.Equal(3, split.Dumps.Parsed);
    }

    [Fact]
    public async Task Limits_and_arguments_are_reported()
    {
        for (int i = 0; i < 3; i++) Write($"{i}.dmp", SyntheticCrash.Builder());
        var limited = await _service.Bucket(Folder, false, null, 3, null, false, true, 2, null, 0, 50, null, default);
        Assert.True(limited.Dumps.LimitReached);
        Assert.Equal(2, limited.Items.Single().Count);
        Assert.Contains(limited.Notes, n => n.Contains("maxDumps", StringComparison.Ordinal));

        var none = await _service.Bucket(Folder, false, "*.none", 3, null, false, true, 10, null, 0, 50, null, default);
        Assert.Equal(0, none.Total);
        Assert.Contains(none.Notes, n => n.StartsWith("No file", StringComparison.Ordinal));

        var missing = await Assert.ThrowsAsync<ToolError>(() => _service.Bucket(_dir.File("nowhere"), false, null, 3, null, false, true, 10, null, 0, 50, null, default));
        Assert.Equal(ErrorCode.NotFound, missing.Code);
    }

    /// <summary>dump_heap and dump_object rows of arrays and generic instances (no TypeDef, or the nil row 0x02000000) carry no token.</summary>
    [Theory]
    [InlineData(0L, null)]
    [InlineData(0x02000000L, null)]
    [InlineData(0x02000012L, "0x02000012")]
    public void Heap_rows_leave_out_a_nil_type_def_token(long token, string? expected) => Assert.Equal(expected, MinidumpService.TypeDefToken(token));
}
