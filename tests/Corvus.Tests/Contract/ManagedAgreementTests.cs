using System.Text.Json;
using ModelContextProtocol.Protocol;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>Tools that answer one managed or string question report the same facts.</summary>
public sealed class ManagedAgreementTests : IAsyncLifetime
{
    private const string Chain =
        "namespace Chain { public class Hub { public int Entry() { return Mid(1) + Mid(2); } " +
        "public int Other() { Leaf(); return Mid(3); } int Mid(int x) { Leaf(); return x; } void Leaf() { } } }";

    private const string Edited =
        "namespace Edited { public class Vault { public int Open(int x) { return x + 1; } public int Close(int x) { return x * 2; } } }";

    private const string Names =
        "namespace Zoo { public class Keeper { public int Feed(int n) { return n; } public string Name; public class Badge { public int Id; } } " +
        "public interface IGate { void Open(); } } namespace Zoo.Cage { public class Lock { public void Turn() { } } }";

    private const string Literals =
        "namespace Lit { public class Cfg { public string Url() { return \"https://cfg.example.com/api/v2/poll\"; } " +
        "public string Ip() { return \"203.0.113.7\"; } public string Plain() { return \"plain label\"; } } }";

    private readonly TempDir _dir = new();
    private InProcessServer _server = null!;

    public async Task InitializeAsync()
    {
        var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false };
        foreach (var (name, source) in new[] { ("Chain", Chain), ("Edited", Edited), ("Names", Names), ("Lit", Literals) })
        {
            File.WriteAllBytes(_dir.File(name + ".dll"), Roslyn.Release(name, source));
            options.Preload.Add(_dir.File(name + ".dll"));
        }
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

    private static List<JsonElement> Items(JsonElement record) => [.. record.GetProperty("items").EnumerateArray()];

    private static HashSet<string> Strings(JsonElement record, string property) =>
        Items(record).Where(i => i.TryGetProperty(property, out _)).Select(i => i.GetProperty(property).GetString()!).ToHashSet(StringComparer.Ordinal);

    private static List<string> DiffHeaders(JsonElement diff) =>
        [.. diff.GetProperty("code").GetString()!.Split('\n').Where(l => l.StartsWith("=== ", StringComparison.Ordinal)).Select(l => l[4..].TrimEnd('\r'))];

    [Theory]
    [InlineData("Hub::Leaf")]
    [InlineData("Hub::Mid")]
    public async Task Find_references_call_tree_and_call_paths_list_the_same_callers(string target)
    {
        var (_, refs) = await Call("find_references", new() { ["symbol"] = target });
        var (_, tree) = await Call("get_call_tree", new() { ["method"] = target, ["depth"] = 1 });
        var (_, paths) = await Call("find_call_paths", new() { ["to"] = target, ["limit"] = 50 });
        // A caller that uses the target twice is listed once,
        // in the first of its rows.
        var fromRefs = Strings(refs, "token");
        Assert.NotEmpty(fromRefs);
        Assert.Equal(fromRefs, Strings(tree, "token"));
        var lastCallers = Items(paths).Select(p => p.GetProperty("steps").EnumerateArray().ToList())
            .Select(steps => steps[^2].GetProperty("token").GetString()!).ToHashSet();
        Assert.Equal(fromRefs, lastCallers);
        var (_, resolved) = await Call("resolve_symbol", new() { ["symbol"] = target });
        var targetLabel = Items(resolved).Single().GetProperty("label").GetString()!;
        foreach (var caller in Items(refs).Where(r => r.TryGetProperty("where", out _)).Select(r => r.GetProperty("where").GetString()!))
        {
            var (_, callees) = await Call("find_callees", new() { ["method"] = caller });
            Assert.Contains(targetLabel, Strings(callees, "target"));
        }
    }

    [Fact]
    public async Task A_method_without_callers_is_empty_in_every_caller_tool()
    {
        var (_, refs) = await Call("find_references", new() { ["symbol"] = "Hub::Entry" });
        var (_, tree) = await Call("get_call_tree", new() { ["method"] = "Hub::Entry", ["depth"] = 1 });
        Assert.Empty(Items(refs));
        Assert.Empty(Items(tree));
        var (_, paths) = await Call("find_call_paths", new() { ["to"] = "Hub::Entry", ["limit"] = 50 });
        // A path of one step is the target alone, with no caller.
        Assert.All(Items(paths), x => Assert.Single(x.GetProperty("steps").EnumerateArray()));
    }

    [Fact]
    public async Task List_edits_and_diff_edits_describe_the_same_edits()
    {
        await Call("rename_symbol", new() { ["symbol"] = "Vault::Open", ["newName"] = "Unseal", ["dryRun"] = false });
        await Call("stub_method", new() { ["method"] = "Vault::Close", ["dryRun"] = false });
        var (_, listed) = await Call("list_edits", new() { ["assembly"] = "Edited" });
        var (_, diff) = await Call("diff_edits", new() { ["assembly"] = "Edited" });
        var fromList = Items(listed).Select(e => $"#{e.GetProperty("number").GetInt32()} {e.GetProperty("tool").GetString()}: {e.GetProperty("description").GetString()}").ToList();
        Assert.Equal(2, fromList.Count);
        Assert.Equal(fromList, DiffHeaders(diff));
        var (_, one) = await Call("diff_edits", new() { ["assembly"] = "Edited", ["number"] = 2 });
        Assert.Equal([fromList[1]], DiffHeaders(one));
        await Call("undo_edit", new() { ["assembly"] = "Edited" });
        var (_, afterUndo) = await Call("list_edits", new() { ["assembly"] = "Edited" });
        var (_, diffAfter) = await Call("diff_edits", new() { ["assembly"] = "Edited" });
        var remaining = Items(afterUndo).Select(e => $"#{e.GetProperty("number").GetInt32()} {e.GetProperty("tool").GetString()}: {e.GetProperty("description").GetString()}").ToList();
        Assert.Equal([fromList[0]], remaining);
        Assert.Equal(remaining, DiffHeaders(diffAfter));
    }

    [Fact]
    public async Task Type_listings_searches_and_outlines_name_the_same_types_and_members()
    {
        var (_, types) = await Call("list_types", new() { ["assembly"] = "Names", ["limit"] = 500 });
        var named = Items(types).ToDictionary(t => t.GetProperty("token").GetString()!, t => t.GetProperty("name").GetString()!);
        Assert.Equal(4, named.Count);
        var (_, spaces) = await Call("list_namespaces", new() { ["assembly"] = "Names" });
        var counted = named.Values.Select(n => n.Split('/')[0]).GroupBy(n => n[..n.LastIndexOf('.')]).ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(counted, Items(spaces).ToDictionary(i => i.GetProperty("namespace").GetString()!, i => i.GetProperty("types").GetInt32()));
        foreach (var (token, name) in named)
        {
            var simple = name[(name.LastIndexOfAny(['.', '/']) + 1)..];
            var (_, found) = await Call("search_symbols", new() { ["query"] = simple, ["kind"] = "type", ["assembly"] = "Names" });
            var (_, resolved) = await Call("resolve_symbol", new() { ["symbol"] = simple, ["kind"] = "type", ["assembly"] = "Names" });
            foreach (var record in new[] { found, resolved })
            {
                var row = Items(record).Single(r => r.GetProperty("token").GetString() == token);
                Assert.Equal(name, row.GetProperty("label").GetString()!.Replace('+', '/'));
            }
        }
        var (_, outline) = await Call("get_type_info", new() { ["type"] = "Keeper", ["section"] = "all" });
        var members = Items(outline).Where(m => m.GetProperty("kind").GetString() is "method" or "field").Select(m => m.GetProperty("token").GetString()!).ToHashSet();
        foreach (var member in new[] { "Keeper::Feed", "Keeper::Name" })
        {
            var (_, resolved) = await Call("resolve_symbol", new() { ["symbol"] = member });
            Assert.Contains(Items(resolved).Single().GetProperty("token").GetString()!, members);
        }
    }

    [Fact]
    public async Task Search_strings_and_extract_strings_report_the_same_literals()
    {
        var (_, all) = await Call("search_strings", new() { ["query"] = ".", ["regex"] = true, ["assembly"] = "Lit" });
        var literals = Items(all).ToDictionary(i => i.GetProperty("value").GetString()!,
            i => $"{i.GetProperty("owner").GetProperty("label").GetString()} @IL_{i.GetProperty("ilOffset").GetInt32():X4}");
        Assert.Equal(3, literals.Count);
        var (_, typed) = await Call("extract_strings", new() { ["assembly"] = "Lit" });
        foreach (var value in Items(typed))
        {
            var text = value.GetProperty("value").GetString()!;
            var owners = literals.Where(l => l.Key.Contains(text, StringComparison.Ordinal)).Select(l => l.Value).ToList();
            Assert.NotEmpty(owners);
            Assert.Contains(value.GetProperty("locations")[0].GetString(), owners);
        }
        Assert.Contains(Items(typed), v => v.GetProperty("type").GetString() == "url");
        Assert.Contains(Items(typed), v => v.GetProperty("type").GetString() == "ipv4");

        var expected = literals.Keys.Order(StringComparer.Ordinal).ToList();
        var pe = new PeBuilder { Is64 = true, Machine = 0x8664, ImageBase = 0x140000000UL };
        uint textRva = pe.NextRva, dataRva = textRva + 0x1000;
        // One lea per literal, so code references each string.
        var code = new List<byte>();
        uint at = dataRva;
        foreach (var l in expected)
        {
            code.AddRange([0x48, 0x8D, 0x05]);
            code.AddRange(BitConverter.GetBytes((int)(at - (textRva + (uint)code.Count + 4))));
            at += (uint)l.Length + 1;
        }
        code.Add(0xC3);
        pe.EntryPoint = pe.Add(".text", [.. code], 0x60000020).Rva;
        pe.Add(".rdata", rva =>
        {
            var blob = new PeBlob(rva);
            foreach (var l in expected) blob.Ascii(l);
            return blob.ToArray();
        });
        File.WriteAllBytes(_dir.File("literals.bin"), pe.Build());
        await Call("load_assembly", new() { ["path"] = _dir.File("literals.bin") });
        var (_, native) = await Call("search_native_strings", new() { ["image"] = "literals.bin" });
        Assert.Equal(expected, Items(native).Select(i => i.GetProperty("text").GetString()!).Order(StringComparer.Ordinal).ToList());
    }

    [Fact]
    public async Task Extract_strings_lists_the_strings_of_a_native_image()
    {
        var pe = new PeBuilder { Is64 = true, Machine = 0x8664, ImageBase = 0x140000000UL };
        pe.EntryPoint = pe.Add(".text", [0xC3], 0x60000020).Rva;
        pe.Add(".rdata", System.Text.Encoding.ASCII.GetBytes("\0https://updates.example.net/v1/check\0"));
        File.WriteAllBytes(_dir.File("plain.bin"), pe.Build());
        var listed = await _server.Client.CallToolAsync("extract_strings", new Dictionary<string, object?> { ["path"] = _dir.File("plain.bin") });
        Assert.NotEqual(true, listed.IsError);
        Assert.Contains("https://updates.example.net/v1/check", string.Concat(listed.Content.OfType<TextContentBlock>().Select(b => b.Text)));
    }
}
