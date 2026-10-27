using System.Security.Cryptography;
using System.Text.Json;
using ModelContextProtocol.Protocol;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>The dotnet read tools over the protocol: row pages and their records, sections and views, basis, folded tools.</summary>
public sealed class DotnetToolTests : IAsyncLifetime
{
    private InProcessServer _server = null!;
    private readonly TempDir _dir = new();

    public async Task InitializeAsync()
    {
        var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false };
        options.Preload.Add(Env.FixturePath);
        options.Preload.Add(Env.ConsumerPath);
        _server = await InProcessServer.StartAsync(options: options);
    }

    public async Task DisposeAsync()
    {
        await _server.DisposeAsync();
        _dir.Dispose();
    }

    private async Task<(string Text, JsonElement Record)> Call(string tool, Dictionary<string, object?> args)
    {
        var r = await _server.Client.CallToolAsync(tool, args);
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        Assert.True(r.IsError != true, text);
        return (text, JsonDocument.Parse(r.StructuredContent!.Value.GetRawText()).RootElement.Clone());
    }

    private static List<string> Strings(JsonElement items, string property) => items.EnumerateArray().Select(i => i.GetProperty(property).ToString()).ToList();

    /// <summary>Pages of limit rows from offset 0 until nextOffset ends: the items, in order.</summary>
    private async Task<List<JsonElement>> Walk(string tool, Dictionary<string, object?> args, int limit)
    {
        var rows = new List<JsonElement>();
        int offset = 0;
        for (int page = 0; page < 1_000; page++)
        {
            var (text, record) = await Call(tool, new(args) { ["offset"] = offset, ["limit"] = limit });
            rows.AddRange(record.GetProperty("items").EnumerateArray());
            if (!record.TryGetProperty("nextOffset", out var next)) return rows;
            Assert.Contains($"offset={next.GetInt32()}", text);
            offset = next.GetInt32();
        }
        throw new InvalidOperationException("no last page");
    }

    /// <summary>diff_edits pages by characters: one totalChars on every page, the text it walks, and nothing past it.</summary>
    [Fact]
    public async Task Diff_edits_pages_keep_one_total()
    {
        // Unloading at the end drops the unsaved-edit journal, which would otherwise reach later servers of this process.
        try
        {
            foreach (var m in new[] { "Fixture.Model.Account::Score", "Fixture.Model.Shop::Describe", "Fixture.Model.Secret::Validate" })
                await Call("stub_method", new() { ["method"] = m, ["dryRun"] = false });
            var sb = new System.Text.StringBuilder();
            var totals = new HashSet<int>();
            int pages = 0;
            int? offset = 0;
            while (offset is { } at)
            {
                var (_, record) = await Call("diff_edits", new() { ["assembly"] = "TestFixture", ["offset"] = at, ["maxTokens"] = 500 });
                pages++;
                Assert.Equal(sb.Length, record.GetProperty("offset").GetInt32());
                sb.Append(record.GetProperty("code").GetString());
                totals.Add(record.GetProperty("totalChars").GetInt32());
                offset = record.TryGetProperty("nextOffset", out var n) ? n.GetInt32() : null;
            }
            Assert.Equal(sb.Length, Assert.Single(totals));
            Assert.True(pages > 1, $"{pages} page(s), {sb.Length} chars");
            var past = await _server.Client.CallToolAsync("diff_edits", new Dictionary<string, object?> { ["assembly"] = "TestFixture", ["offset"] = sb.Length });
            Assert.True(past.IsError);
        }
        finally
        {
            await _server.Client.CallToolAsync("unload_assembly", new Dictionary<string, object?> { ["assembly"] = "TestFixture" });
        }
    }

    [Fact]
    public async Task Type_info_sections_page_one_kind()
    {
        var (text, summary) = await Call("get_type_info", new() { ["type"] = "Fixture.Model.Account" });
        Assert.Equal("summary", summary.GetProperty("section").GetString());
        int methods = summary.GetProperty("counts").GetProperty("methods").GetInt32();
        Assert.True(methods > 2);
        Assert.Contains("members: ", text);
        var walked = await Walk("get_type_info", new() { ["type"] = "Fixture.Model.Account", ["section"] = "methods" }, 2);
        var (_, all) = await Call("get_type_info", new() { ["type"] = "Fixture.Model.Account", ["section"] = "methods", ["limit"] = 500 });
        Assert.Equal(Strings(all.GetProperty("items"), "token"), walked.Select(w => w.GetProperty("token").GetString()!).ToList());
        Assert.Equal(methods, walked.Count);
        Assert.All(walked, w => Assert.False(w.TryGetProperty("kind", out _))); // one kind: the section says it
    }

    [Fact]
    public async Task Attributes_are_rows_or_assembly_CSharp()
    {
        var (_, rows) = await Call("get_attributes", new() { ["symbol"] = "NativeThing::First" });
        var first = rows.GetProperty("items")[0];
        Assert.Equal("method", first.GetProperty("target").GetString());
        Assert.Contains("RVA = \"0x1000\"", first.GetProperty("attribute").GetString());
        Assert.StartsWith("Fixture.Native.NativeThing::First", first.GetProperty("owner").GetString());

        var (text, code) = await Call("get_attributes", new() { ["assembly"] = "TestFixture", ["format"] = "csharp" });
        Assert.Contains("TargetFramework", text);
        Assert.Contains("TargetFramework", code.GetProperty("code").GetString());
        Assert.Equal(0, code.GetProperty("offset").GetInt32());
    }

    /// <summary>maxTokens sizes a list page: a small budget holds fewer rows and continues where it stopped.</summary>
    [Fact]
    public async Task Max_tokens_sizes_a_list_page()
    {
        var (_, full) = await Call("list_types", new() { ["assembly"] = "TestFixture" });
        var (text, small) = await Call("list_types", new() { ["assembly"] = "TestFixture", ["maxTokens"] = 500 });
        int shown = small.GetProperty("items").GetArrayLength();
        Assert.True(shown < full.GetProperty("items").GetArrayLength(), $"{shown} rows at 500 tokens");
        Assert.Equal(shown, small.GetProperty("nextOffset").GetInt32());
        Assert.Contains($"[More: offset={shown}]", text);
    }

    [Fact]
    public async Task Resolve_symbol_pages_its_matches()
    {
        var (text, record) = await Call("resolve_symbol", new() { ["symbol"] = "Account::Charge", ["limit"] = 1 });
        Assert.Equal(2, record.GetProperty("total").GetInt32());
        Assert.Equal(1, record.GetProperty("nextOffset").GetInt32());
        Assert.Contains("[More: offset=1]", text);
        Assert.Contains("public void Charge(", record.GetProperty("items")[0].GetProperty("signature").GetString());
    }

    [Fact]
    public async Task References_through_a_base_method_are_derived_and_overrides_are_a_kind()
    {
        var (_, record) = await Call("find_references", new() { ["symbol"] = "Fixture.Model.Account::Score" });
        var viaBase = Assert.Single(record.GetProperty("items").EnumerateArray(), i => i.TryGetProperty("where", out var w) && w.GetString()!.StartsWith("Consumer.Branch::Total"));
        Assert.Equal("derived", viaBase.GetProperty("basis").GetString());
        Assert.All(record.GetProperty("items").EnumerateArray(), i => Assert.Contains(i.GetProperty("basis").GetString(), new[] { "observed", "derived" }));
        var (_, direct) = await Call("find_references", new() { ["symbol"] = "Fixture.Model.Account::Score", ["directOnly"] = true });
        Assert.DoesNotContain(direct.GetProperty("items").EnumerateArray(), i => i.GetProperty("basis").GetString() == "derived");

        var (text, overrides) = await Call("find_references", new() { ["symbol"] = "Fixture.Model.Entity::Score", ["kind"] = "overrides" });
        Assert.Contains("PremiumAccount::Score()", text);
        Assert.All(overrides.GetProperty("items").EnumerateArray(), i => Assert.Equal("override", i.GetProperty("kind").GetString()));
    }

    [Fact]
    public async Task Call_tree_rows_name_their_parents()
    {
        var walked = await Walk("get_call_tree", new() { ["method"] = "Fixture.Model.Account::Charge(int)", ["direction"] = "callers", ["depth"] = 3 }, 1);
        Assert.NotEmpty(walked);
        // A row is at most one level deeper than the row above; a row without depth is at the row above's depth.
        Assert.Equal(1, walked[0].GetProperty("depth").GetInt32());
        int last = 1;
        for (int i = 1; i < walked.Count; i++)
        {
            int depth = walked[i].TryGetProperty("depth", out var d) ? d.GetInt32() : last;
            Assert.InRange(depth, 1, last + 1);
            last = depth;
        }
    }

    [Fact]
    public async Task Call_paths_page_by_limit()
    {
        var (_, all) = await Call("find_call_paths", new() { ["to"] = "Fixture.Model.Account::Charge(int)", ["limit"] = 50 });
        int total = all.GetProperty("total").GetInt32();
        Assert.True(total >= 2, $"{total} paths");
        var (text, first) = await Call("find_call_paths", new() { ["to"] = "Fixture.Model.Account::Charge(int)", ["limit"] = 1 });
        Assert.True(first.GetProperty("hasMore").GetBoolean());
        Assert.False(first.GetProperty("totalExact").GetBoolean());
        Assert.Contains("[More: offset=1]", text);
        var step = first.GetProperty("items")[0].GetProperty("steps")[0];
        Assert.False(step.TryGetProperty("basis", out _)); // observed
        Assert.StartsWith("0x06", step.GetProperty("token").GetString());
    }

    [Fact]
    public async Task Resources_carry_their_hash_and_extract_to_output_path()
    {
        var (_, list) = await Call("list_resources", new() { ["assembly"] = "TestFixture" });
        var hello = Assert.Single(list.GetProperty("items").EnumerateArray(), i => i.GetProperty("name").GetString() == "Fixture.hello.txt");
        var target = _dir.File("hello.bin");
        var (text, saved) = await Call("get_resource", new() { ["assembly"] = "TestFixture", ["name"] = "Fixture.hello.txt", ["outputPath"] = target });
        Assert.Equal("saved", saved.GetProperty("kind").GetString());
        Assert.Equal(Path.GetFullPath(target), saved.GetProperty("savedTo").GetString());
        var bytes = File.ReadAllBytes(target);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(bytes)), hello.GetProperty("sha256").GetString());
        // The file offset points at the data in the file as loaded.
        long at = Convert.ToInt64(hello.GetProperty("fileOffset").GetString(), 16);
        Assert.Equal(bytes, File.ReadAllBytes(Env.FixturePath).AsSpan((int)at, bytes.Length).ToArray());
        var (_, read) = await Call("get_resource", new() { ["assembly"] = "TestFixture", ["name"] = "Fixture.hello.txt" });
        Assert.Equal("text", read.GetProperty("kind").GetString());
        Assert.Contains("Hello from", read.GetProperty("code").GetString());
    }

    [Fact]
    public void Icon_groups_name_their_icons()
    {
        // GRPICONDIR: reserved, type 1, two entries of 14 bytes ending in the RT_ICON id.
        var group = new byte[6 + 2 * 14];
        group[2] = 1;
        group[4] = 2;
        BitConverter.GetBytes((ushort)3).CopyTo(group, 6 + 12);
        BitConverter.GetBytes((ushort)7).CopyTo(group, 6 + 14 + 12);
        Assert.Equal([3, 7], Corvus.Tools.ResourceTools.IconIds(group));
    }

    [Fact]
    public async Task Search_IL_shows_context_instructions()
    {
        var (_, record) = await Call("search_il", new() { ["pattern"] = "ldstr *PREVIEW*", ["context"] = 1 });
        Assert.All(record.GetProperty("items").EnumerateArray(), i => Assert.Single(i.GetProperty("instructions").EnumerateArray()));
    }

    [Fact]
    public async Task Assembly_info_views_return_their_own_sections()
    {
        var (text, summary) = await Call("get_assembly_info", new() { ["assembly"] = "TestFixture" });
        Assert.False(summary.TryGetProperty("references", out _));
        Assert.Contains("(view=references lists them)", text);
        Assert.True(summary.GetProperty("referenceCount").GetInt32() > 0);
        var (_, references) = await Call("get_assembly_info", new() { ["assembly"] = "TestFixture", ["view"] = "references" });
        Assert.Equal(summary.GetProperty("referenceCount").GetInt32(), references.GetProperty("references").GetArrayLength());
        Assert.False(references.TryGetProperty("tables", out _));
        var (metaText, metadata) = await Call("get_assembly_info", new() { ["assembly"] = "TestFixture", ["view"] = "metadata" });
        Assert.Contains("Sections:", metaText);
        Assert.True(metadata.GetProperty("tables").GetArrayLength() > 0);
    }

    [Fact]
    public async Task Code_records_carry_the_page_and_its_symbols()
    {
        var (text, record) = await Call("decompile_member", new() { ["member"] = "Fixture.Model.Account" });
        Assert.Equal("csharp", record.GetProperty("language").GetString());
        Assert.Contains("class Account", record.GetProperty("code").GetString());
        Assert.Equal("type", record.GetProperty("symbols")[0].GetProperty("kind").GetString());
        var (ilText, il) = await Call("get_il", new() { ["symbol"] = "Account::CheckPreview" });
        var hash = il.GetProperty("methods")[0].GetProperty("ilHash").GetString()!;
        Assert.Contains(hash[..16], ilText);
    }
}
