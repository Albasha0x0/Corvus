using System.Text.Json;
using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Native tools that report one fact agree on it for a built image.</summary>
public class NativeAgreementTests
{
    private static IEnumerable<JsonElement> Items(JsonElement r, string field = "items") => r.GetProperty(field).EnumerateArray();

    [Fact]
    public async Task Import_and_export_tools_list_the_same_imports_and_exports_of_a_built_image()
    {
        using var dir = new TempDir();
        var (app, prov, _) = LinkedImages.Trio(dir);
        await using var server = await AgreementServer.Open(app, prov);

        var imports = await server.Call("list_imports", new() { ["image"] = "app.dll" });
        var listed = Items(imports).Select(i => $"{i.GetProperty("module").GetString()}!{i.GetProperty("name").GetString()}").Order().ToList();
        var verified = await server.Call("verify_native_imports", new() { ["assembly"] = "app.dll" });
        var checks = Items(verified).Select(c => $"{c.GetProperty("module").GetString()}!{c.GetProperty("entryPoint").GetString()}").Order().ToList();
        Assert.Equal(6, listed.Count);
        Assert.Equal(listed, checks);
        Assert.Equal(listed.Count, verified.GetProperty("declarations").GetInt32());

        var info = await server.Call("get_pe_info", new() { ["image"] = "app.dll" });
        Assert.Equal(listed.Count, info.GetProperty("importFunctions").GetInt32());
        Assert.Equal(listed.Select(n => n[..n.IndexOf('!')]).Distinct(StringComparer.OrdinalIgnoreCase).Count(), info.GetProperty("importModules").GetInt32());

        var exports = await server.Call("list_exports", new() { ["image"] = "provlib.dll" });
        Assert.Equal(Items(exports).Count(), (await server.Call("get_pe_info", new() { ["image"] = "provlib.dll" })).GetProperty("exports").GetInt32());
        Assert.Equal(["Fwd", "Plain", "Work"], Items(exports).Select(e => e.GetProperty("name").GetString()!).Order().ToList());
    }

    private const string AddressScript = """
        {
          "ScriptMethod": [
            { "Address": 4096, "Name": "Fixture.Native.NativeThing$$First" },
            { "Address": 4352, "Name": "Fixture.Native.NativeThing$$Second" },
            { "Address": 4608, "Name": "Fixture.Native.NativeThing$$Shared<int>" }
          ],
          "Addresses": [ 4096, 4352, 4608 ]
        }
        """;

    [Fact]
    public async Task Method_address_tools_map_a_method_to_its_function_and_back()
    {
        using var dir = new TempDir();
        var dummies = Path.Combine(dir.Path, "dump", "DummyDll");
        Directory.CreateDirectory(dummies);
        var dll = Path.Combine(dummies, Path.GetFileName(Env.FixturePath));
        File.Copy(Env.FixturePath, dll);
        File.WriteAllText(Path.Combine(dir.Path, "dump", "script.json"), AddressScript);
        await using var server = await AgreementServer.Open(dll);

        foreach (var (method, rva, size) in new[] { ("First", "0x1000", "0x100"), ("Second", "0x1100", "0x100") })
        {
            var forward = await server.Call("get_method_addresses", new() { ["symbol"] = $"Fixture.Native.NativeThing::{method}" });
            var member = Items(forward, "members").First(m => m.GetProperty("kind").GetString() == "method");
            Assert.Equal(rva, member.GetProperty("rva").GetString());
            var reverse = await server.Call("find_method_by_address", new() { ["address"] = rva });
            var match = Items(reverse).First(m => m.GetProperty("kind").GetString() == "method");
            Assert.Contains($"::{method}(", match.GetProperty("method").GetString());
            Assert.Equal(rva, match.GetProperty("function").GetString());
            Assert.Equal(member.GetProperty("size").GetString(), match.GetProperty("size").GetString());
            Assert.Equal(size, match.GetProperty("size").GetString());
        }
    }

    [R2RFrameworkFact]
    public async Task ReadyToRun_tools_map_a_method_to_its_code_and_back()
    {
        await using var server = await AgreementServer.Open(R2RFramework.Linq!);
        var code = await server.Call("get_r2r_code", new() { ["method"] = "System.Linq.Enumerable::Any", ["assembly"] = "System.Linq", ["maxBodies"] = 3 });
        var bodies = Items(code, "bodies").ToList();
        Assert.NotEmpty(bodies);
        foreach (var body in bodies)
        {
            var entry = body.GetProperty("entryVa").GetString()!;
            var found = await server.Call("find_r2r_method", new() { ["assembly"] = "System.Linq", ["address"] = entry });
            Assert.Equal("hot", found.GetProperty("kind").GetString());
            Assert.Equal(entry, found.GetProperty("begin").GetString());
            var methods = Items(found, "methods").ToList();
            Assert.Contains(methods, m => m.GetProperty("entryVa").GetString() == entry && m.GetProperty("size").GetInt32() == body.GetProperty("size").GetInt32()
                && m.GetProperty("label").GetString() == body.GetProperty("label").GetString());
        }
    }

    [Fact]
    public async Task Native_edit_tools_list_the_same_patches_of_an_edited_image()
    {
        using var dir = new TempDir();
        var (app, _, _) = LinkedImages.Trio(dir);
        await using var server = await AgreementServer.Open(app);
        await server.Call("patch_bytes", new() { ["image"] = "app.dll", ["address"] = "rva:0x1000", ["hex"] = "90 90 90 90 90 90", ["dryRun"] = false });
        await server.Call("patch_bytes", new() { ["image"] = "app.dll", ["address"] = "rva:0x1006", ["hex"] = "90 90 90 90 90 90", ["dryRun"] = false });
        await server.Call("rename_native", new() { ["image"] = "app.dll", ["address"] = "rva:0x100C", ["name"] = "after_patches", ["dryRun"] = false });

        var edits = await server.Call("list_native_edits", new() { ["image"] = "app.dll" });
        var rows = Items(edits).Where(e => e.GetProperty("kind").GetString() == "patch").ToList();
        var listed = rows.Select(e => e.GetProperty("address").GetString()!).Order().ToList();
        Assert.Equal(2, listed.Count);
        Assert.Contains(Items(edits), e => e.GetProperty("text").GetString()!.Contains("after_patches"));

        var output = dir.File("patches.json");
        var export = await server.Call("export_native_patches", new() { ["image"] = "app.dll", ["outputPath"] = output });
        using var json = JsonDocument.Parse(File.ReadAllText(output));
        var imageBase = Convert.ToUInt64(json.RootElement.GetProperty("image").GetProperty("imageBase").GetString()![2..], 16);
        var exported = json.RootElement.GetProperty("patches").EnumerateArray()
            .Select(p => "0x" + (imageBase + Convert.ToUInt64(p.GetProperty("rva").GetString()![2..], 16)).ToString("X")).Order().ToList();
        Assert.Equal(listed, exported);
        Assert.Equal(listed.Count, export.GetProperty("patches").GetInt32());
        // Patch bytes agree across tools; the rename is an annotation and stays out of the patch export.
        Assert.All(rows, r => Assert.EndsWith("-> 909090909090", r.GetProperty("text").GetString()));
        Assert.All(json.RootElement.GetProperty("patches").EnumerateArray(), p => Assert.Equal("909090909090", p.GetProperty("replacement").GetString()));
        Assert.DoesNotContain("after_patches", File.ReadAllText(output));
    }

    [Fact]
    public async Task Native_type_tools_report_the_same_layout_of_an_engine_type()
    {
        using var dir = new TempDir();
        var options = new ServerOptions { BackgroundIndexing = false };
        using var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new AnnotationStore(dir.File("annotations")));
        using var engines = new NativeEngineService([new NativeQuerySurfaceTests.FakeProvider()], dir.File("cache"), code, workspace, options);
        var image = workspace.LoadAny(McpProtocolTests.NativeSample(dir)).Native!.Id;
        var info = new NativeTypeInfoTools(workspace, code, engines);
        var types = new NativeTypeTools(workspace, engines, new NativeUserTypePush(code), code);

        var listed = await NativeQuerySurfaceTests.Structured<NativeTypeTools.TypeListReport>(() => types.ListNativeTypes(image, kind: "udt", members: true));
        Assert.Equal(["Header", "Packet"], listed.Items.Select(t => t.Name).Order().ToList());
        foreach (var entry in listed.Items)
        {
            var report = await NativeQuerySurfaceTests.Structured<NativeTypeInfoTools.NativeTypeReport>(() => info.GetNativeType(image, name: entry.Name, source: "engine"));
            var view = report.Type!;
            Assert.Equal(entry.Size, view.Size);
            Assert.Equal(entry.MemberCount, view.TotalFields);
            Assert.Equal(entry.Members!.Select(m => (m.Offset, m.Name, m.Type, m.Size)).Order().ToList(),
                view.Fields.Select(f => (f.Offset, f.Name, (string?)f.Type, (long?)f.Size)).Order().ToList());
        }
    }

    // A at 0 calls B directly, calls kernel32!Sleep through its import slot
    // and tail-jumps to C.
    private static string CallGraphImage(TempDir dir)
    {
        var path = dir.File("callgraph.dll");
        File.WriteAllBytes(path, LinkedImages.Build("callgraph.dll", [("A", 0), ("B", 0x20), ("C", 0x40)], [("kernel32.dll", ["Sleep"])],
            slots => new LinkedImages.Code(slots).Raw(0xE8, 0x1B, 0, 0, 0).CallImport("kernel32.dll!Sleep").Raw(0xE9, 0x30, 0, 0, 0).Pad(0x20).Ret().Pad(0x40).Ret().ToArray()));
        return path;
    }

    [Fact]
    public async Task Native_call_tools_report_the_same_callees_and_callers_of_a_built_image()
    {
        using var dir = new TempDir();
        await using var server = await AgreementServer.Open(CallGraphImage(dir));
        var xrefs = await server.Call("find_xrefs", new() { ["image"] = "callgraph.dll", ["address"] = "A", ["direction"] = "from" });
        var tree = await server.Call("native_call_tree", new() { ["image"] = "callgraph.dll", ["function"] = "A", ["depth"] = 1 });
        var targets = await server.Call("resolve_call_targets", new() { ["image"] = "callgraph.dll", ["address"] = "A", ["scope"] = "function" });

        var byXrefs = Items(xrefs).Select(x => x.GetProperty("target").GetString()!).Order().ToList();
        var byTree = Items(tree).Where(n => n.GetProperty("depth").GetInt32() == 1).Select(n => n.GetProperty("address").GetString()!).Order().ToList();
        var byTargets = Items(targets).SelectMany(s => Items(s, "targets")).Select(t => t.GetProperty("address").GetString()!).Order().ToList();
        Assert.Equal(3, byXrefs.Count);
        Assert.Equal(byXrefs, byTree);
        Assert.Equal(byXrefs, byTargets);
        Assert.Equal(Items(xrefs).Select(x => x.GetProperty("address").GetString()!).Order().ToList(),
            Items(targets).Select(s => s.GetProperty("address").GetString()!).Order().ToList());

        var callers = await server.Call("find_xrefs", new() { ["image"] = "callgraph.dll", ["address"] = "B" });
        var callerTree = await server.Call("native_call_tree", new() { ["image"] = "callgraph.dll", ["function"] = "B", ["direction"] = "callers" });
        Assert.Equal(Items(callers).Select(x => x.GetProperty("function").GetString()!.Split('+')[0]).Order().ToList(),
            Items(callerTree).Where(n => n.GetProperty("depth").GetInt32() == 1).Select(n => n.GetProperty("name").GetString()!).Order().ToList());
    }

    [Fact]
    public async Task Function_bound_tools_report_the_same_start_size_and_name_of_each_function_of_a_built_image()
    {
        using var dir = new TempDir();
        var symbols = new PdbBuilder();
        symbols.Modules.Add(("code.obj", [PdbBuilder.Proc("first", 1, 0, 6, global: true), PdbBuilder.End(), PdbBuilder.Proc("second", 1, 0x40, 6, global: true), PdbBuilder.End()]));
        File.WriteAllBytes(dir.File("tiny.pdb"), symbols.Build());
        File.WriteAllBytes(dir.File("tiny.dll"), PdbTests.TinyImage(symbols.Guid, symbols.Age));
        await using var server = await AgreementServer.Open(dir.File("tiny.dll"));
        await server.Call("load_pdb", new() { ["image"] = "tiny.dll" });

        var listed = Items(await server.Call("list_functions", new() { ["image"] = "tiny.dll" }))
            .Select(f => (f.GetProperty("address").GetString()!, f.GetProperty("size").GetInt32(), f.GetProperty("name").GetString()!)).Order().ToList();
        var named = Items(await server.Call("search_pdb_symbols", new() { ["image"] = "tiny.dll", ["kind"] = "function" }))
            .Select(f => (f.GetProperty("address").GetString()!, f.GetProperty("size").GetInt32(), f.GetProperty("name").GetString()!)).Order().ToList();
        // The PDB sizes end before the padding that follows each function: the
        // index extent stops at the return, so both tools report 6.
        Assert.Equal([("0x140001000", 6, "first"), ("0x140001040", 6, "second")], listed);
        Assert.Equal(listed, named);

        foreach (var (address, size, name) in listed)
        {
            var last = "0x" + (Convert.ToUInt64(address[2..], 16) + (uint)size - 1).ToString("X");
            foreach (var inside in new[] { address, last })
                Assert.Equal(name, (await server.Call("resolve_address", new() { ["image"] = "tiny.dll", ["address"] = inside })).GetProperty("function").GetString()!.Split('+')[0]);
            var code = (await server.Call("disassemble", new() { ["image"] = "tiny.dll", ["address"] = address })).GetProperty("code").GetString()!;
            Assert.StartsWith($"; {name} at {address}, {size} bytes", code);
        }
    }
}
