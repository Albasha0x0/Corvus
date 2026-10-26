using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Corvus.Core.WebAssembly;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>A WebAssembly component's world: its imports and exports with each interface's types and functions, as WIT declares them.</summary>
public sealed class WasmWorldTests
{
    private const string WasmTools = "CORVUS_WASM_TOOLS";
    private const string WasmComponents = "CORVUS_WASM_COMPONENTS";

    private static readonly byte[] Header = [0x00, 0x61, 0x73, 0x6D, 0x0D, 0x00, 0x01, 0x00];

    private static byte[] U32(uint n)
    {
        var b = new List<byte>();
        do { byte x = (byte)(n & 0x7F); n >>= 7; b.Add(n != 0 ? (byte)(x | 0x80) : x); } while (n != 0);
        return [.. b];
    }

    private static byte[] Name(string s) => [.. U32((uint)Encoding.UTF8.GetByteCount(s)), .. Encoding.UTF8.GetBytes(s)];

    private static byte[] Vec(params byte[][] items) => [.. U32((uint)items.Length), .. items.SelectMany(i => i)];

    private static byte[] Section(byte id, byte[] body) => [id, .. U32((uint)body.Length), .. body];

    // An extern name in the plain form.
    private static byte[] Extern(string s) => [0x00, .. Name(s)];

    /// <summary>
    /// Imports interface test:demo/api@1.0.0 (a record, a resource with a constructor and a method, an enum) and func
    /// log; exports func make (lifted, its type naming the record through an alias) and interface test:demo/out@1.0.0
    /// (an inline instance of make).
    /// </summary>
    private static byte[] Component()
    {
        byte[] api =
        [
            0x42, .. Vec(
                [0x01, 0x72, .. Vec([.. Name("a"), 0x79])],
                [0x04, .. Extern("point"), 0x03, 0x00, 0x00],
                [0x04, .. Extern("handle"), 0x03, 0x01],
                [0x01, 0x69, 0x02],
                [0x01, 0x68, 0x02],
                [0x01, 0x70, 0x7D],
                [0x01, 0x6A, 0x01, 0x01, 0x01, 0x73],
                [0x01, 0x40, .. Vec([.. Name("self"), 0x04], [.. Name("data"), 0x05]), 0x00, 0x06],
                [0x04, .. Extern("[method]handle.write"), 0x01, 0x07],
                [0x01, 0x6D, .. Vec(Name("a"), Name("b"))],
                [0x04, .. Extern("mode"), 0x03, 0x00, 0x08],
                [0x01, 0x40, 0x00, 0x00, 0x03],
                [0x04, .. Extern("[constructor]handle"), 0x01, 0x0A]),
        ];
        return
        [
            .. Header,
            .. Section(1, WasmTests.Sample()),
            .. Section(7, Vec([0x72, .. Vec([.. Name("id"), 0x77])], api, [0x40, .. Vec([.. Name("message"), 0x73]), 0x01, 0x00])),
            .. Section(10, Vec([.. Extern("test:demo/api@1.0.0"), 0x05, 0x01], [.. Extern("log"), 0x01, 0x02])),
            .. Section(6, Vec([0x03, 0x00, 0x00, .. Name("point")])),
            .. Section(7, Vec([0x40, 0x00, 0x00, 0x03])),
            .. Section(8, Vec([0x00, 0x00, 0x00, 0x00, 0x04])),
            .. Section(5, Vec([0x01, .. Vec([.. Extern("get"), 0x01, 0x01])])),
            .. Section(11, Vec([.. Extern("make"), 0x01, 0x01, 0x00], [.. Extern("test:demo/out@1.0.0"), 0x05, 0x01, 0x00])),
        ];
    }

    [Fact]
    public void A_component_declares_its_interfaces_types_and_functions()
    {
        var w = WasmWorld.Read(Component())!;
        Assert.Empty(w.Issues);
        var api = w.Imports[0];
        Assert.Equal(("import", "test:demo/api@1.0.0", "interface"), (api.Direction, api.Name, api.Kind));
        Assert.Equal(["point: record { a: u32 }", "handle: resource", "mode: enum { a, b }"], api.Types.Select(t => $"{t.Name}: {t.Definition}"));
        Assert.Equal(["[method]handle.write: func(self: borrow<handle>, data: list<u8>) -> result<point, string>", "[constructor]handle: func() -> handle"],
            api.Functions.Select(f => $"{f.Name}: {f.Signature}"));
        Assert.Equal(("func", "func(message: string)"), (w.Imports[1].Kind, w.Imports[1].Signature));
        Assert.Equal(("make", "func", "func() -> point"), (w.Exports[0].Name, w.Exports[0].Kind, w.Exports[0].Signature));
        var out_ = w.Exports[1];
        Assert.Equal(("interface", "get: func() -> point"), (out_.Kind, string.Join("; ", out_.Functions.Select(f => $"{f.Name}: {f.Signature}"))));
        Assert.Equal((1, 1, 2, 1), (w.Sections["core module"], w.Sections["canon lift"], w.Sections["import"], w.Sections["alias"]));
    }

    [Fact]
    public void An_instance_of_a_nested_component_exports_its_functions_with_the_arguments_in_place()
    {
        // The nested component imports resource r and a constructor of it; the outer one passes its own resource.
        byte[] inner =
        [
            .. Header,
            .. Section(10, Vec([.. Extern("r"), 0x03, 0x01])),
            .. Section(7, Vec([0x69, 0x00], [0x40, 0x00, 0x00, 0x01])),
            .. Section(10, Vec([.. Extern("mk"), 0x01, 0x02])),
            .. Section(11, Vec([.. Extern("make"), 0x01, 0x00, 0x00])),
        ];
        byte[] bytes =
        [
            .. Header,
            .. Section(7, Vec([0x42, .. Vec([0x04, .. Extern("thing"), 0x03, 0x01], [0x01, 0x69, 0x00], [0x01, 0x40, 0x00, 0x00, 0x01],
                [0x04, .. Extern("new"), 0x01, 0x02])])),
            .. Section(10, Vec([.. Extern("test:demo/things"), 0x05, 0x00])),
            .. Section(6, Vec([0x03, 0x00, 0x00, .. Name("thing")], [0x01, 0x00, 0x00, .. Name("new")])),
            .. Section(4, inner),
            .. Section(5, Vec([0x00, 0x00, .. Vec([.. Name("r"), 0x03, 0x01], [.. Name("mk"), 0x01, 0x00])])),
            .. Section(11, Vec([.. Extern("test:demo/maker"), 0x05, 0x01, 0x00])),
        ];
        var w = WasmWorld.Read(bytes)!;
        Assert.Empty(w.Issues);
        Assert.Equal("make: func() -> thing", string.Join("; ", w.Exports.Single().Functions.Select(f => $"{f.Name}: {f.Signature}")));
        Assert.Equal(1, w.Sections["component"]);
    }

    [Fact]
    public void An_unknown_definition_ends_the_walk_with_its_section_named()
    {
        byte[] bytes = [.. Header, .. Section(10, Vec([.. Extern("x"), 0x05, 0x00])), .. Section(7, Vec([0x55]))];
        var w = WasmWorld.Read(bytes)!;
        Assert.Contains("the import section at 0x8 is not read (type index 0 is out of range (0))", Assert.Single(w.Issues));
        Assert.Null(WasmWorld.Read([0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]));
    }

    [Fact]
    public void The_wasm_view_shows_the_world_of_a_component()
    {
        using var dir = new TempDir();
        var path = dir.File("app.wasm");
        File.WriteAllBytes(path, Component());
        var view = new WasmFileView().Inspect(new FileInput(path, File.ReadAllBytes(path), "wasm"), default)!;
        var component = ((WasmFileView.Facts)view.Detail).Component!;
        Assert.Equal(["test:demo/api@1.0.0", "log"], component.Imports.Select(i => i.Name));
        Assert.Contains("World: 2 (test:demo/api@1.0.0, log) imported, 2 (make, test:demo/out@1.0.0) exported.", view.Highlights);
    }

    [Fact]
    [FuzzEntry(typeof(WasmWorld))]
    public void Fuzzed_components_never_throw()
    {
        var failures = FormatFuzz.Run(Component(), b => WasmWorld.Read(b), 500);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    // wasm-tools (CORVUS_WASM_TOOLS) resolves each component under CORVUS_WASM_COMPONENTS (component wit --json);
    // compared: every world import and export, and each interface's named types and functions in WIT syntax.
    [RequiresRealDataFact(WasmTools, WasmComponents)]
    [Trait("Speed", "Slow")]
    public void Real_components_declare_the_world_wasm_tools_resolves()
    {
        var files = Directory.EnumerateFiles(Environment.GetEnvironmentVariable(WasmComponents)!, "*.wasm", SearchOption.AllDirectories)
            .Where(f => WasmComponent.Looks(File.ReadAllBytes(f))).ToList();
        Assert.NotEmpty(files);
        foreach (var file in files)
        {
            using var json = JsonDocument.Parse(Run(Environment.GetEnvironmentVariable(WasmTools)!, "component", "wit", "--json", file));
            var expected = Reference(json.RootElement);
            var w = WasmWorld.Read(File.ReadAllBytes(file))!;
            Assert.True(w.Issues.Count == 0, $"{file}: {string.Join("; ", w.Issues)}");
            var actual = w.Imports.Concat(w.Exports).SelectMany(Lines).Order(StringComparer.Ordinal).ToList();
            Assert.True(expected.SequenceEqual(actual), $"{file}:\n{string.Join("\n", expected)}\n---\n{string.Join("\n", actual)}");
        }
    }

    private static IEnumerable<string> Lines(WasmWorld.Item i) => i.Kind switch
    {
        "interface" => [$"{i.Direction} {i.Name}", .. i.Types.Select(t => $"{i.Name} type {t.Name}: {t.Definition}"),
            .. i.Functions.Select(f => $"{i.Name} func {f.Name}: {f.Signature}")],
        "func" => [$"{i.Direction} {i.Name}: {i.Signature}"],
        _ => [$"{i.Direction} {i.Name}: {i.Kind} {i.Signature}"],
    };

    // The same lines from wasm-tools' resolved world, its types rendered in WIT syntax.
    private static List<string> Reference(JsonElement root)
    {
        var types = root.GetProperty("types").EnumerateArray().ToList();
        var interfaces = root.GetProperty("interfaces").EnumerateArray().ToList();
        var packages = root.GetProperty("packages").EnumerateArray().ToList();
        string Ref(JsonElement t)
        {
            if (t.ValueKind == JsonValueKind.String) return t.GetString()!;
            var def = types[t.GetInt32()];
            return def.GetProperty("name").GetString() ?? Structure(def.GetProperty("kind"));
        }
        string Opt(JsonElement e) => e.ValueKind == JsonValueKind.Null ? "_" : Ref(e);
        string Structure(JsonElement kind)
        {
            var (key, v) = kind.ValueKind == JsonValueKind.String ? (kind.GetString()!, default) : kind.EnumerateObject().Select(p => (p.Name, p.Value)).Single();
            return key switch
            {
                "handle" => v.EnumerateObject().Single() is var h && h.Name == "own" ? Ref(h.Value) : $"borrow<{Ref(h.Value)}>",
                "list" => $"list<{Ref(v)}>",
                "option" => $"option<{Ref(v)}>",
                "tuple" => $"tuple<{string.Join(", ", v.GetProperty("types").EnumerateArray().Select(Ref))}>",
                "result" => (v.GetProperty("ok"), v.GetProperty("err")) switch
                {
                    ({ ValueKind: JsonValueKind.Null }, { ValueKind: JsonValueKind.Null }) => "result",
                    (var ok, { ValueKind: JsonValueKind.Null }) => $"result<{Ref(ok)}>",
                    (var ok, var err) => $"result<{Opt(ok)}, {Ref(err)}>",
                },
                "future" or "stream" => v.ValueKind == JsonValueKind.Null ? key : $"{key}<{Ref(v)}>",
                "type" => Ref(v),
                _ => key,
            };
        }
        string Definition(JsonElement def)
        {
            var kind = def.GetProperty("kind");
            if (kind.ValueKind == JsonValueKind.String && kind.GetString() == "resource") return "resource";
            if (kind.ValueKind == JsonValueKind.Object && kind.EnumerateObject().Single() is var p)
                switch (p.Name)
                {
                    case "record": return $"record {{ {string.Join(", ", p.Value.GetProperty("fields").EnumerateArray().Select(f => $"{f.GetProperty("name").GetString()}: {Ref(f.GetProperty("type"))}"))} }}";
                    case "variant":
                        return $"variant {{ {string.Join(", ", p.Value.GetProperty("cases").EnumerateArray().Select(c => c.GetProperty("type") is { ValueKind: JsonValueKind.Null } ? c.GetProperty("name").GetString() : $"{c.GetProperty("name").GetString()}({Ref(c.GetProperty("type"))})"))} }}";
                    case "enum": return $"enum {{ {string.Join(", ", p.Value.GetProperty("cases").EnumerateArray().Select(c => c.GetProperty("name").GetString()))} }}";
                    case "flags": return $"flags {{ {string.Join(", ", p.Value.GetProperty("flags").EnumerateArray().Select(c => c.GetProperty("name").GetString()))} }}";
                }
            return "type " + Structure(kind);
        }
        string Signature(JsonElement f)
        {
            var kind = f.GetProperty("kind");
            var kindName = kind.ValueKind == JsonValueKind.String ? kind.GetString()! : kind.EnumerateObject().Single().Name;
            var ps = string.Join(", ", f.GetProperty("params").EnumerateArray().Select(p => $"{p.GetProperty("name").GetString()}: {Ref(p.GetProperty("type"))}"));
            var result = f.TryGetProperty("result", out var r) && r.ValueKind != JsonValueKind.Null ? " -> " + Ref(r) : "";
            return (kindName.StartsWith("async", StringComparison.Ordinal) ? "async func(" : "func(") + ps + ")" + result;
        }
        string InterfaceName(int id, string key)
        {
            var iface = interfaces[id];
            if (iface.GetProperty("name").GetString() is not { } name) return key;
            var package = packages[iface.GetProperty("package").GetInt32()].GetProperty("name").GetString()!;
            int at = package.IndexOf('@');
            return at < 0 ? $"{package}/{name}" : $"{package[..at]}/{name}{package[at..]}";
        }
        var lines = new List<string>();
        var world = root.GetProperty("worlds").EnumerateArray().Single();
        foreach (var (direction, items) in new[] { ("import", world.GetProperty("imports")), ("export", world.GetProperty("exports")) })
            foreach (var item in items.EnumerateObject())
            {
                var (k, v) = item.Value.EnumerateObject().Select(p => (p.Name, p.Value)).Single();
                if (k == "interface")
                {
                    var iface = interfaces[v.GetProperty("id").GetInt32()];
                    var name = InterfaceName(v.GetProperty("id").GetInt32(), item.Name);
                    lines.Add($"{direction} {name}");
                    foreach (var t in iface.GetProperty("types").EnumerateObject()) lines.Add($"{name} type {t.Name}: {Definition(types[t.Value.GetInt32()])}");
                    foreach (var f in iface.GetProperty("functions").EnumerateObject()) lines.Add($"{name} func {f.Name}: {Signature(f.Value)}");
                }
                else if (k == "function") lines.Add($"{direction} {item.Name}: {Signature(v)}");
                else lines.Add($"{direction} {item.Name}: type {Definition(types[v.GetInt32()])}");
            }
        return [.. lines.Order(StringComparer.Ordinal)];
    }

    private static string Run(string tool, params string[] args)
    {
        var start = new ProcessStartInfo(tool) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) start.ArgumentList.Add(a);
        using var p = Process.Start(start)!;
        var output = p.StandardOutput.ReadToEndAsync();
        var error = p.StandardError.ReadToEndAsync();
        p.WaitForExit();
        Assert.True(p.ExitCode == 0, $"wasm-tools {string.Join(' ', args)}: exit {p.ExitCode}: {error.Result}");
        return output.Result;
    }
}
