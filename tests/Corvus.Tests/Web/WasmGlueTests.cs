using System.Text;
using Corvus.Core.WebAssembly;
using Corvus.Services.Analysis;
using static Corvus.Core.WebAssembly.WasmType;

namespace Corvus.Tests;

/// <summary>A module's imports joined to its JS glue by name: Emscripten, wasm-bindgen (object and ES module forms) and Go.</summary>
public sealed class WasmGlueTests
{
    private static WasmBinary Importing(params (string Module, string Name)[] imports)
    {
        var b = new WasmModuleBuilder();
        uint t = b.Type([I32, I32], []);
        foreach (var (module, name) in imports) b.ImportFunc(module, name, t);
        return WasmBinary.Read(b.Build());
    }

    private const string Bindgen = """
        function __wbg_get_imports() {
            const imports = {};
            imports.wbg = {};
            imports.wbg.__wbg_log_1a2b3c = function(arg0, arg1) { console.log(getStringFromWasm0(arg0, arg1)); };
            imports.wbg.__wbindgen_throw = function(arg0, arg1) { throw new Error(getStringFromWasm0(arg0, arg1)); };
            return imports;
        }
        async function __wbg_load(module, imports) {
            return await WebAssembly.instantiateStreaming(module, imports);
        }
        """;

    private const string Go = """
        this.importObject = {
            _gotest: { add: (a, b) => a + b },
            gojs: {
                // func wasmExit(code int32)
                "runtime.wasmExit": (sp) => { sp >>>= 0; this.exited = true; },
                "syscall/js.valueGet": (sp) => { const result = Reflect.get(loadValue(sp + 8), loadString(sp + 16)); },
            }
        };
        const result = await WebAssembly.instantiate(await fetch("main.wasm"), go.importObject);
        """;

    [Fact]
    public void Emscripten_runtime_imports_resolve_through_its_import_object()
    {
        var path = WasmTextTests.DotnetNative("10.0.11");
        var link = WasmGlue.Beside(WasmBinary.Read(File.ReadAllBytes(path)), path, default)!;
        Assert.Equal(("dotnet.native.js", "Emscripten"), (link.File, link.Toolchain));
        Assert.Equal(link.Total, link.Matched);
        Assert.Contains(link.ImportObject, o => o.StartsWith("env -> wasmImports", StringComparison.Ordinal));
        Assert.All(link.Imports, b => Assert.Equal("import object", b.How));
        Assert.Contains(link.Instantiate, i => i.StartsWith("WebAssembly.instantiate", StringComparison.Ordinal));
    }

    [Fact]
    public void Bindgen_and_go_glue_bind_by_import_name()
    {
        var bindgen = WasmGlue.Link(Importing(("wbg", "__wbg_log_1a2b3c"), ("wbg", "__wbindgen_throw"), ("wbg", "__wbg_missing")), "pkg.js", Bindgen);
        Assert.Equal(("wasm-bindgen", 2, 3), (bindgen.Toolchain, bindgen.Matched, bindgen.Total));
        Assert.Equal(("function", "4:5", "assignment"), (bindgen.Imports[0].Value, bindgen.Imports[0].At, bindgen.Imports[0].How));
        Assert.Equal("not found", bindgen.Imports[2].How);

        var go = WasmGlue.Link(Importing(("gojs", "runtime.wasmExit"), ("gojs", "syscall/js.valueGet")), "wasm_exec.js", Go);
        Assert.Equal(("Go (wasm_exec.js)", 2), (go.Toolchain, go.Matched));
        Assert.All(go.Imports, b => Assert.Equal("import object", b.How));
        Assert.Contains("gojs -> {…}", go.ImportObject[0]);

        var esm = WasmGlue.Link(Importing(("./pkg_bg.js", "__wbg_alert_9f")), "pkg_bg.js", "export function __wbg_alert_9f(arg0, arg1) { alert(arg0); }\n");
        Assert.Equal("ES module export", Assert.Single(esm.Imports).How);
    }

    [Fact]
    public void Wasm_view_names_the_glue_beside_the_module()
    {
        var path = WasmTextTests.DotnetNative("10.0.11");
        var bytes = File.ReadAllBytes(path);
        var view = new WasmFileView().Inspect(new FileInput(path, bytes, "wasm"), default)!;
        Assert.Contains(view.Highlights, h => h.StartsWith("JS glue dotnet.native.js (Emscripten):", StringComparison.Ordinal));
        Assert.Equal("Emscripten", ((WasmFileView.Facts)view.Detail).Glue!.Toolchain);
    }

    [Fact]
    public void Fuzzed_glue_never_throws()
    {
        var module = Importing(("gojs", "runtime.wasmExit"), ("wbg", "__wbg_log_1a2b3c"));
        var failures = FormatFuzz.Run(Encoding.UTF8.GetBytes(Go + Bindgen), b => WasmGlue.Link(module, "x.js", Encoding.UTF8.GetString(b)), 2000);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
