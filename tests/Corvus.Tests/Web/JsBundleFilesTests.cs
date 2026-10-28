using Corvus.Core;
using Corvus.Services.Analysis;
using Corvus.Services.Web;

namespace Corvus.Tests;

/// <summary>unpack_container on a bundle: one file per module, named by the source map, the bundler's key, or the id (.bin added: scripts are runnable).</summary>
public sealed class JsBundleFilesTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private List<string> Unpack(string name, string text, string? map = null)
    {
        var path = _dir.File(name);
        File.WriteAllText(path, text);
        if (map != null) File.WriteAllText(path + ".map", map);
        using var ws = new AssemblyWorkspace();
        var report = new UnpackService(ws).Unpack(path, _dir.File(name + "_out"), load: false, AnalysisLimits.Default, default);
        return report.Files.Select(f => Path.GetRelativePath(report.OutputDirectory, f.Path).Replace('\\', '/')).Order(StringComparer.Ordinal).ToList();
    }

    [Fact]
    public void Webpack_modules_are_named_from_the_source_map()
    {
        var files = Unpack("main.js", "(()=>{var m={\n12:(e,t,n)=>{e.exports=n(34)+1},\n34:(e,t,n)=>{e.exports=41},\n56:(e,t,n)=>{e.exports=0}\n};})();",
            """{"version":3,"sources":["webpack://app/./src/a.js","webpack://app/./src/b.js"],"names":[],"mappings":";AAAA;ACAA"}""");
        Assert.Equal(["modules.json", "modules/56.js.bin", "sources.json", "src/a.js.bin", "src/b.js.bin"], files);
        var a = File.ReadAllText(Path.Combine(_dir.File("main.js_out"), "src", "a.js.bin"));
        Assert.StartsWith("// module 12 (webpack, source map) of main.js", a);
        Assert.Contains("// requires: 34", a);
    }

    [Fact]
    public void Source_map_original_tree_is_written_with_every_source_accounted_for()
    {
        // webpack:// prefixes, a duplicate name, a source with no content but a file beside the map, and one missing.
        Directory.CreateDirectory(_dir.File("lib"));
        File.WriteAllText(_dir.File("lib/vendor.js"), "export const v = 1;\n");
        var map = """
            {"version":3,"sources":["webpack://app/./src/App.tsx","webpack://app/./src/api/client.ts","webpack:///./src/App.tsx","lib/vendor.js","webpack://app/./src/gone.ts","webpack://app/webpack/bootstrap"],
             "sourcesContent":["export const App = () => null;\n","export const get = (u: string) => fetch(u);\n","// second App.tsx\n",null,null,"// runtime\n"],
             "names":[],"mappings":"AAAA"}
            """;
        var files = Unpack("app.js", "console.log(1);\n//# sourceMappingURL=app.js.map\n", map);
        Assert.Equal(["original/lib/vendor.js.bin", "original/src/App.tsx", "original/src/App~2.tsx", "original/src/api/client.ts", "original/webpack/bootstrap", "sources.json"], files);
        var output = _dir.File("app.js_out");
        Assert.Equal("export const get = (u: string) => fetch(u);\n", File.ReadAllText(Path.Combine(output, "original", "src", "api", "client.ts")));
        Assert.Equal("export const v = 1;\n", File.ReadAllText(Path.Combine(output, "original", "lib", "vendor.js.bin")));
        using var manifest = System.Text.Json.JsonDocument.Parse(File.ReadAllText(Path.Combine(output, "sources.json")));
        var rows = manifest.RootElement.EnumerateArray().ToList();
        Assert.Equal(6, rows.Count);
        Assert.Equal(["sourcesContent", "sourcesContent", "sourcesContent", "file beside the map", "missing", "sourcesContent"], rows.Select(r => r.GetProperty("content").GetString()));
        Assert.Equal("src/gone.ts", rows[4].GetProperty("source").GetString());

        // The .map alone gives the same tree.
        Assert.Contains("original/src/api/client.ts", Unpack("other.js.map", map));
    }

    [Fact]
    public void The_summary_names_the_container_unpack_opens_a_script_as()
    {
        var map = """{"version":3,"sources":["src/api.js","src/main.js"],"sourcesContent":["export const a = 1;","import './api.js';"],"names":[],"mappings":"AAAA"}""";
        var inline = "console.log(1);\n//# sourceMappingURL=data:application/json;base64," + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(map)) + "\n";
        string Summarized(string name, string text)
        {
            File.WriteAllText(_dir.File(name), text);
            using var ws = new AssemblyWorkspace();
            return new InspectionService(ws).Summarize(null, _dir.File(name), default).Container;
        }

        Assert.Equal("source-mapped script (2 source(s))", Summarized("mapped.js", inline));
        Assert.Equal(["original/src/api.js.bin", "original/src/main.js.bin", "sources.json"], Unpack("mapped2.js", inline));
        Assert.Equal("webpack bundle (3 modules)", Summarized("main.js", "(()=>{var m={\n12:(e,t,n)=>{e.exports=n(34)+1},\n34:(e,t,n)=>{e.exports=41},\n56:(e,t,n)=>{e.exports=0}\n};})();"));
        Assert.Equal("none", Summarized("plain.js", "console.log(1);\n"));
    }

    [Fact]
    public void A_bundle_past_the_summary_bound_is_named_with_the_modules_read()
    {
        // Four small modules, then one holding a string that ends past the
        // bound, then one more.
        var padding = new string('x', JsBundleFiles.DescribeBytes + 1024);
        var bundle = "(()=>{var m={\n12:(e,t,n)=>{e.exports=n(34)+1},\n34:(e,t,n)=>{e.exports=41},\n56:(e,t,n)=>{e.exports=0},\n"
            + "61:(e,t,n)=>{e.exports=`a${1}b`},\n78:(e,t,n)=>{e.exports=\"" + padding + "\"},\n90:(e,t,n)=>{e.exports=2}\n};})();";
        var path = _dir.File("large.js");
        File.WriteAllText(path, bundle);
        using var ws = new AssemblyWorkspace();
        Assert.Equal("webpack bundle (at least 4 modules; read the first 8 MB)", new InspectionService(ws).Summarize(null, path, default).Container);
        Assert.Contains("modules/90.js.bin", Unpack("large2.js", bundle));
    }

    [Fact]
    public void A_bracket_run_past_the_summary_bound_summarizes_in_bounded_time()
    {
        var text = string.Concat(Enumerable.Repeat("(0,", JsBundleFiles.DescribeBytes / 3 + 1024));
        var path = _dir.File("brackets.js");
        File.WriteAllText(path, text);
        using var ws = new AssemblyWorkspace();
        var watch = System.Diagnostics.Stopwatch.StartNew();
        Assert.Equal("none", new InspectionService(ws).Summarize(null, path, default).Container);
        Assert.True(watch.Elapsed < TimeSpan.FromMinutes(1), watch.Elapsed.ToString());
    }

    [Fact]
    public void A_script_nested_too_deep_to_parse_is_not_a_container()
    {
        var text = new string('(', 1_000_000) + "0" + new string(')', 1_000_000);
        var notes = new List<string>();
        Assert.Null(JsModules.Parse(text, notes));
        Assert.Equal(["not parsed: nested too deep"], notes);

        var path = _dir.File("deep.js");
        File.WriteAllText(path, text);
        using var ws = new AssemblyWorkspace();
        Assert.Equal("none", new InspectionService(ws).Summarize(null, path, default).Container);
        Assert.Null(JsBundleFiles.Open(File.ReadAllBytes(path), path, default));
    }

    [Fact]
    public void A_map_past_the_summary_bound_counts_its_sources_only_when_read()
    {
        var mappings = new string('A', JsBundleFiles.DescribeBytes + 1024);
        string Summarized(string name, string map)
        {
            File.WriteAllText(_dir.File(name + ".map"), map);
            File.WriteAllText(_dir.File(name), "console.log(1);\n//# sourceMappingURL=" + name + ".map\n");
            using var ws = new AssemblyWorkspace();
            return new InspectionService(ws).Summarize(null, _dir.File(name), default).Container;
        }

        Assert.Equal("source-mapped script (2 source(s))",
            Summarized("first.js", "{\"version\":3,\"sources\":[\"a.js\",\"b.js\"],\"names\":[],\"mappings\":\"" + mappings + "\"}"));
        Assert.Equal("source-mapped script (sources not counted past the first 8 MB of its map)",
            Summarized("last.js", "{\"version\":3,\"mappings\":\"" + mappings + "\",\"names\":[],\"sources\":[\"a.js\"]}"));
    }

    [Fact]
    public void A_regular_expression_after_return_keeps_the_cuts_past_the_summary_bound()
    {
        // Each module holds a bracket inside a regular expression after return;
        // the last module's string ends past the bound.
        var modules = string.Concat(Enumerable.Range(1, 6).Select(n => $"{n}:(e,t,n)=>{{e.exports=function(s){{return/[(]/.test(s)}}}},\n"));
        var bundle = "(()=>{var m={\n" + modules + "78:(e,t,n)=>{e.exports=\"" + new string('x', JsBundleFiles.DescribeBytes + 1024) + "\"}\n};})();";
        var path = _dir.File("regex.js");
        File.WriteAllText(path, bundle);
        using var ws = new AssemblyWorkspace();
        Assert.Equal("webpack bundle (at least 6 modules; read the first 8 MB)", new InspectionService(ws).Summarize(null, path, default).Container);
    }

    [Fact]
    public void A_slash_after_a_postfix_increment_divides_past_the_summary_bound()
    {
        // Each module divides after i++ and i--, with a bracket between the
        // slashes; the last module's string ends past the bound.
        var modules = string.Concat(Enumerable.Range(1, 6).Select(n => $"{n}:(e,t,n)=>{{e.exports=function(i){{return i++/2+(i--/2)}}}},\n"));
        var bundle = "(()=>{var m={\n" + modules + "78:(e,t,n)=>{e.exports=\"" + new string('x', JsBundleFiles.DescribeBytes + 1024) + "\"}\n};})();";
        var path = _dir.File("postfix.js");
        File.WriteAllText(path, bundle);
        using var ws = new AssemblyWorkspace();
        Assert.Equal("webpack bundle (at least 6 modules; read the first 8 MB)", new InspectionService(ws).Summarize(null, path, default).Container);
    }

    [Fact]
    public void A_script_naming_a_refused_map_keeps_its_sources_unknown()
    {
        // A device name the map check refuses, outside the script's folder.
        var url = OperatingSystem.IsWindows() ? "../NUL" : "/dev/null";
        var path = _dir.File("refused.js");
        File.WriteAllText(path, "console.log(1);\n//# sourceMappingURL=" + url + "\n");
        using var ws = new AssemblyWorkspace();
        Assert.Equal("source-mapped script (sources not counted: its map was not read)", new InspectionService(ws).Summarize(null, path, default).Container);
    }

    [Fact]
    public void An_inline_map_counts_its_sources_from_the_first_bytes()
    {
        var map = "{\"version\":3,\"sources\":[\"a.js\",\"b.js\"],\"names\":[],\"mappings\":\"" + new string('A', JsBundleFiles.DescribeBytes) + "\"}";
        var script = "console.log(1);\n//# sourceMappingURL=data:application/json;base64," + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(map)) + "\n";
        var head = SourceMap.Head("inline.js", System.Text.Encoding.UTF8.GetBytes(script), JsBundleFiles.DescribeBytes)!.Value;
        Assert.Equal(JsBundleFiles.DescribeBytes, head.Head.Length);
        Assert.True(head.Length > head.Head.Length);
        Assert.Equal(2, SourceMap.CountSources(head.Head, whole: false));
    }

    [Fact]
    public void A_script_without_map_or_modules_is_not_a_container()
    {
        var path = _dir.File("plain.js");
        File.WriteAllText(path, "console.log(1);\n");
        Assert.Null(JsBundleFiles.Open(File.ReadAllBytes(path), path, default));
    }

    [Fact]
    public void Esbuild_and_metro_keys_name_their_modules()
    {
        Assert.Equal(["modules.json", "src/app.js.bin", "src/util.js.bin"],
            Unpack("out.js", """var a=__commonJS({"src/util.js"(e,m){m.exports=1}});var b=__commonJS({"src/app.js"(e,m){m.exports=a()}});"""));
        Assert.Equal(["App.js.bin", "index.js.bin", "modules.json"],
            Unpack("index.android.bundle.js", """__d(function(g,r,i,a,m,e,d){m.exports=r(d[0])},0,[1],"index.js");__d(function(g,r,i,a,m,e,d){m.exports=1},1,[],"App.js");"""));
    }

    [Fact]
    [FuzzEntry(typeof(JsBundleFiles))]
    public void Fuzzed_bundles_open_or_decline()
    {
        var seed = System.Text.Encoding.UTF8.GetBytes("""var a=__commonJS({"src/util.js"(e,m){m.exports=1}});var b=__commonJS({"../x/app.js"(e,m){m.exports=a()}});""");
        var failures = FormatFuzz.Run(seed, b =>
        {
            if (JsBundleFiles.Open(b, "out.js", default) is { } c)
                Assert.All(c.Items, i => Assert.DoesNotContain("..", i.Name.Split('/')));
        }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    /// <summary>The old builds of the bundle pairs written out: modules by key, map and id, and time.</summary>
    [RequiresRealDataFact(RealData.BundlePairs)]
    [Trait("Speed", "Slow")]
    public void Real_bundles_write_module_trees()
    {
        foreach (var folder in Directory.EnumerateDirectories(RealData.Path(RealData.BundlePairs)))
        {
            var old = Directory.GetFiles(folder).Single(f => Path.GetFileName(f).StartsWith("old.", StringComparison.Ordinal) && !f.EndsWith(".map", StringComparison.Ordinal));
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var c = JsBundleFiles.Open(File.ReadAllBytes(old), old, default);
            Console.WriteLine($"{Path.GetFileName(folder)}: {(c == null ? "not a bundle" : $"{c.Kind}, {c.Items.Count - 1} files; {c.Notes[^1]}")} in {sw.Elapsed.TotalSeconds:0.00} s");
        }
    }

    [Fact]
    public void Clean_keeps_names_inside_the_output()
    {
        Assert.Equal("app/src/x.ts", JsBundleFiles.Clean("webpack:///../app/./src/x.ts?abc"));
        Assert.Equal("a/b_c.js", JsBundleFiles.Clean("a/b:c.js"));
        Assert.Null(JsBundleFiles.Clean("../.."));
    }
}
