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
