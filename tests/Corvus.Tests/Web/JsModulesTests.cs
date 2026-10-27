using Corvus.Services.Web;

namespace Corvus.Tests;

/// <summary>Module tables recovered from webpack, esbuild and Browserify bundle shapes.</summary>
public sealed class JsModulesTests
{
    private static List<JsModule> Modules(string text) => JsModules.Find(text, default).Modules;

    [Fact]
    public void Webpack_module_object_gives_ids_and_requires()
    {
        var m = Modules("""
            (()=>{var __webpack_modules__={12:(e,t,n)=>{const a=n(34);e.exports=a+1},34:(e,t,n)=>{e.exports=41}};
            function n(i){return __webpack_modules__[i]}n(12)})();
            """);
        Assert.Equal(["12", "34"], m.Select(x => x.Id));
        Assert.Equal(["34"], m[0].Requires);
        Assert.All(m, x => Assert.Equal("webpack", x.Family));
    }

    [Fact]
    public void Refs_and_search_name_modules_and_positions()
    {
        const string text = "(()=>{var m={12:(e,t,n)=>{const a=n(34);e.exports=a+\"apiKey\"},\n34:(e,t,n)=>{e.exports=41}}})();";
        var notes = new List<string>();
        var script = JsModules.Parse(text, notes)!;
        var modules = JsModules.Find(text, script, default);
        var (requires, by) = JsSearch.Refs(modules, modules.Single(x => x.Id == "34"));
        Assert.Empty(requires);
        Assert.Equal(["12"], by);
        var hit = Assert.Single(JsSearch.Find(text, script, modules, null, "apikey", default));
        Assert.Equal(("string", "apiKey", "12", 1), (hit.Kind, hit.Value, hit.Module, hit.Line));
    }

    [Fact]
    public void AMD_SystemJS_Parcel_and_ESM_chunks_name_their_modules()
    {
        var amd = Assert.Single(Modules("define(\"app/main\", [\"app/util\", \"jquery\"], function(u, $) { return 1; });"));
        Assert.Equal(("app/main", "amd", "app/util,jquery"), (amd.Id, amd.Family, string.Join(",", amd.Requires)));
        var system = Assert.Single(Modules("System.register([\"./dep.js\"], function (_export, _context) { return { setters: [], execute: function () {} }; });"));
        Assert.Equal(("systemjs", "./dep.js"), (system.Family, Assert.Single(system.Requires)));
        var parcel = Modules("parcelRegister(\"a1\", function(module, exports) {}); parcelRegister(\"b2\", function(module, exports) {});");
        Assert.Equal(["a1", "b2"], parcel.Select(x => x.Id));
        var chunk = Assert.Single(Modules("import { h } from \"./vendor-abc.js\"; export { x } from \"./x.js\"; export const app = h();"));
        Assert.Equal(("esm", "./vendor-abc.js,./x.js"), (chunk.Family, string.Join(",", chunk.Requires)));
    }

    /// <summary>Mutated source maps and bundles: typed errors or results, never a crash or a hang.</summary>
    [Fact]
    [FuzzEntry(typeof(SourceMap))]
    public void Fuzzed_maps_and_bundles_never_throw()
    {
        var map = System.Text.Encoding.UTF8.GetBytes("""{"version":3,"sources":["a.ts","b.ts"],"names":["x","y"],"mappings":"AAAA,IAAMA;ACAA,CAACC,GAAG;;AAAA"}""");
        var failures = FormatFuzz.Run(map, b =>
        {
            try
            {
                var m = SourceMap.Parse(b);
                for (int line = 0; line < 4; line++) m.Find(line, 3);
            }
            catch (Corvus.Core.ToolError) { }
        }, 1000);
        var bundle = System.Text.Encoding.UTF8.GetBytes("(()=>{var m={12:(e,t,n)=>{const a=n(34);e.exports=a+1},34:(e,t,n)=>{e.exports=41}}})();");
        failures.AddRange(FormatFuzz.Run(bundle, b => JsModules.Find(System.Text.Encoding.UTF8.GetString(b), default), 500));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    [Fact]
    public void Esbuild_commonjs_keys_keep_paths()
    {
        var m = Modules("""
            var require_util=__commonJS({"src/util.js"(exports,module){module.exports=1}});
            var require_app=__commonJS({"src/app.js"(exports,module){module.exports=require_util()}});
            """);
        Assert.Equal(["src/util.js", "src/app.js"], m.Select(x => x.Name));
        Assert.All(m, x => Assert.Equal("bundler_key", x.Provenance));
    }

    [Fact]
    public void Browserify_dependency_maps_name_requests()
    {
        var m = Modules("""
            (function(){function r(e,n,t){return e}return r})()({1:[function(require,module,exports){var b=require("./b")},{"./b":2}],
            2:[function(require,module,exports){module.exports=2},{}]},{},[1]);
            """);
        Assert.Equal(["1", "2"], m.Select(x => x.Id));
        Assert.Equal(["./b -> 2"], m[0].Requires);
        Assert.All(m, x => Assert.Equal("browserify", x.Family));
    }
}
