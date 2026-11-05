using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Native.Pe;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>open_minidump view=modules with outputPath saves modules rebuilt as PE files.</summary>
public sealed class OpenMinidumpSaveTests : IDisposable
{
    private const ulong Base = 0x1_8000_0000;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public async Task open_minidump_saves_a_module_that_reloads_as_a_PE_file()
    {
        var file = RebuildFixtures.Pe(new PeSpec(true, [new SectionSpec(".text", 0x60000020, Enumerable.Range(1, 0x300).Select(i => (byte)i).ToArray())], ImageBase: Base));
        var mapped = RebuildFixtures.Mapped(file);
        var b = new MinidumpBuilder { ProcessorArchitecture = 9 };
        b.Modules.Add(new MinidumpBuilder.Module(Base, (uint)mapped.Length, 0, @"Z:\app\saved.dll"));
        b.Memory.Add((Base, mapped));
        var dump = _dir.File("saved.dmp");
        File.WriteAllBytes(dump, b.Build());
        var folder = _dir.File("modules");

        using var service = new MinidumpService();
        var text = await new MinidumpTools(service).OpenMinidump(dump, "modules", outputPath: folder);

        Assert.Contains("saved.dll", text);
        var saved = PeFile.FromBytes(File.ReadAllBytes(Path.Combine(folder, "saved.dll")));
        Assert.True(saved.Is64Bit);
        var row = Assert.Single(service.Modules(dump, null, 0, 10, _dir.File("again")).Rows);
        Assert.Equal(64, row.ImageSha256!.Length);
        Assert.Equal(100, row.ImageCaptured);
        Assert.Contains(row.ImageChecks!, c => c.Name == "parse");
    }

    [Fact]
    public async Task Limit_bounds_the_images_written_and_the_text_names_how_many_of_how_many()
    {
        var file = RebuildFixtures.Pe(new PeSpec(true, [new SectionSpec(".text", 0x60000020, [0x90, 0xC3])], ImageBase: Base));
        var mapped = RebuildFixtures.Mapped(file);
        var b = new MinidumpBuilder { ProcessorArchitecture = 9 };
        for (int i = 0; i < 4; i++)
        {
            var at = Base + (ulong)i * 0x100000;
            b.Modules.Add(new MinidumpBuilder.Module(at, (uint)mapped.Length, 0, $@"Z:\app\m{i}.dll"));
            b.Memory.Add((at, mapped));
        }
        var dump = _dir.File("many.dmp");
        File.WriteAllBytes(dump, b.Build());
        var folder = _dir.File("limited");

        using var service = new MinidumpService();
        var text = await new MinidumpTools(service).OpenMinidump(dump, "modules", limit: 2, outputPath: folder);

        Assert.Equal(2, Directory.GetFiles(folder, "*.dll").Length);
        Assert.Contains("2 written modules of 4", text);
    }

    [Fact]
    public async Task An_unlisted_image_gets_a_row_with_its_checks_and_a_text_line()
    {
        var file = RebuildFixtures.Pe(new PeSpec(true, [new SectionSpec(".text", 0x60000020, [0x90, 0xC3])], ImageBase: Base));
        var mapped = RebuildFixtures.Mapped(file);
        var b = new MinidumpBuilder { ProcessorArchitecture = 9 };
        b.Modules.Add(new MinidumpBuilder.Module(Base, (uint)mapped.Length, 0, @"Z:\app\listed.dll"));
        b.Memory.Add((Base, mapped));
        b.Memory.Add((Base + 0x100000, mapped));
        b.Memory.Sort((x, y) => x.Start.CompareTo(y.Start));
        var dump = _dir.File("hidden.dmp");
        File.WriteAllBytes(dump, b.Build());

        using var service = new MinidumpService();
        var rows = service.Modules(dump, null, 0, 10, _dir.File("out"), default, MinidumpService.ModuleOptions.Default with { Module = "unlisted" }).Rows;

        var row = Assert.Single(rows, r => r.ImageFile != null);
        Assert.StartsWith("image-", row.ImageFile);
        Assert.Equal(64, row.ImageSha256!.Length);
        Assert.NotNull(row.ImageCaptured);
        Assert.Contains(row.ImageChecks!, c => c.Name == "parse");
        Assert.Contains("image image-", Corvus.Tools.DumpText.Module(row));
    }

    private string TwoModuleDump() => ModuleDump(["one.dll", "two.dll"]);

    private string ModuleDump(IReadOnlyList<string> names)
    {
        var b = new MinidumpBuilder { ProcessorArchitecture = 9 };
        for (int i = 0; i < names.Count; i++)
        {
            ulong at = Base + (ulong)i * 0x100000;
            var mapped = RebuildFixtures.Mapped(RebuildFixtures.Pe(new PeSpec(true, [new SectionSpec(".text", 0x60000020, new byte[0x300])], ImageBase: at)));
            b.Modules.Add(new MinidumpBuilder.Module(at, (uint)mapped.Length, 0, @"Z:\app\" + names[i]));
            b.Memory.Add((at, mapped));
        }
        var dump = _dir.File($"{names.Count}.dmp");
        File.WriteAllBytes(dump, b.Build());
        return dump;
    }

    [Fact]
    public async Task A_writing_call_over_its_budget_keeps_every_row_for_read_result()
    {
        var names = Enumerable.Range(0, 40).Select(i => $"module{i:D2}.dll").ToList();
        var dump = ModuleDump(names);
        await using var server = await InProcessServer.StartAsync();

        var first = await server.Client.CallToolAsync("open_minidump",
            new Dictionary<string, object?> { ["path"] = dump, ["view"] = "modules", ["outputPath"] = _dir.File("budget"), ["maxTokens"] = 1_000 });
        var id = first.StructuredContent!.Value.GetProperty("resultId").GetString()!;
        var kept = await server.Client.CallToolAsync("read_result", new Dictionary<string, object?> { ["id"] = id, ["maxTokens"] = 100_000 });
        var text = string.Concat(kept.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(t => t.Text));

        Assert.True(first.IsError != true);
        Assert.All(names, n => Assert.Contains(n, text));
    }

    [Fact]
    public async Task A_writing_call_keeps_its_rows_behind_one_result_id()
    {
        var names = Enumerable.Range(0, 60).Select(i => $"module{i:D2}.dll").ToList();
        var dump = ModuleDump(names);
        await using var server = await InProcessServer.StartAsync();

        var first = await server.Client.CallToolAsync("open_minidump",
            new Dictionary<string, object?> { ["path"] = dump, ["view"] = "modules", ["limit"] = 100, ["outputPath"] = _dir.File("one-id") });
        var id = first.StructuredContent!.Value.GetProperty("resultId").GetString()!;
        var firstText = string.Concat(first.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(t => t.Text));
        var text = new System.Text.StringBuilder();
        int offset = 0;
        for (int page = 0; page < 200; page++)
        {
            var read = await server.Client.CallToolAsync("read_result", new Dictionary<string, object?> { ["id"] = id, ["offset"] = offset, ["maxTokens"] = 2_000 });
            text.Append(string.Concat(read.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(t => t.Text)));
            if (!read.StructuredContent!.Value.TryGetProperty("nextOffset", out var next)) break;
            offset = next.GetInt32();
        }

        Assert.All(names, n => Assert.Contains(n, text.ToString()));
        Assert.DoesNotContain("read_result id=", text.ToString().Replace($"id={id}", ""));
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(firstText, "r-[0-9a-f]{12}").Select(m => m.Value).Distinct());
    }

    [Fact]
    public async Task The_module_option_saves_only_the_named_module()
    {
        var dump = TwoModuleDump();
        var folder = _dir.File("named");

        using var service = new MinidumpService();
        await new MinidumpTools(service).OpenMinidump(dump, "modules", outputPath: folder, modules: "two.dll");

        Assert.Equal(["two.dll"], Directory.GetFiles(folder).Select(Path.GetFileName));
    }

    [Fact]
    public async Task A_save_that_writes_every_image_names_no_rest()
    {
        var dump = TwoModuleDump();
        var folder = _dir.File("every");

        using var service = new MinidumpService();
        var text = await new MinidumpTools(service).OpenMinidump(dump, "modules", outputPath: folder);

        Assert.Contains("images: 2 of 2 written to", text);
        Assert.DoesNotContain("not written", text);
    }

    [Fact]
    public async Task A_save_that_skips_a_module_counts_it_and_names_its_reason()
    {
        var b = new MinidumpBuilder { ProcessorArchitecture = 9 };
        var mapped = RebuildFixtures.Mapped(RebuildFixtures.Pe(new PeSpec(true, [new SectionSpec(".text", 0x60000020, new byte[0x300])], ImageBase: Base)));
        b.Modules.Add(new MinidumpBuilder.Module(Base, (uint)mapped.Length, 0, @"Z:\app\one.dll"));
        b.Memory.Add((Base, mapped));
        // The second module has no memory in the dump.
        b.Modules.Add(new MinidumpBuilder.Module(Base + 0x100000, (uint)mapped.Length, 0, @"Z:\app\gone.dll"));
        var dump = _dir.File("skip.dmp");
        File.WriteAllBytes(dump, b.Build());

        using var service = new MinidumpService();
        var text = await new MinidumpTools(service).OpenMinidump(dump, "modules", outputPath: _dir.File("skip"));

        Assert.Contains("images: 1 of 2 written to", text);
        Assert.Contains("; 1 not written, each row names why.", text);
        Assert.Contains("not written (", text);
    }

    [Fact]
    public void A_writing_call_returns_one_row_per_written_file_whatever_its_limit()
    {
        var dump = TwoModuleDump();
        var folder = _dir.File("all");

        using var service = new MinidumpService();
        var (_, rows, total, _) = service.Modules(dump, null, 0, 1, folder);

        Assert.Equal(2, total);
        Assert.Equal(Directory.GetFiles(folder).Select(Path.GetFileName).Order(), rows.Select(r => r.ImageFile).Order());
    }

    [Fact]
    public async Task A_writing_call_refuses_an_offset_and_names_read_result()
    {
        var dump = TwoModuleDump();

        using var service = new MinidumpService();
        var error = await Assert.ThrowsAsync<ToolError>(() => new MinidumpTools(service).OpenMinidump(dump, "modules", offset: 1, outputPath: _dir.File("paged")));

        Assert.Contains("read_result", error.Remediation);
        Assert.False(Directory.Exists(_dir.File("paged")));
    }

    [Fact]
    public async Task The_mapped_layout_option_keeps_section_offsets_at_their_RVAs()
    {
        var dump = TwoModuleDump();
        var folder = _dir.File("mapped");

        using var service = new MinidumpService();
        await new MinidumpTools(service).OpenMinidump(dump, "modules", outputPath: folder, modules: "one.dll", layout: "mapped");

        var text = PeFile.FromBytes(File.ReadAllBytes(Path.Combine(folder, "one.dll"))).Sections.Single(s => s.Name == ".text");
        Assert.Equal(text.Rva, text.RawOffset);
    }
}
