using Corvus.Core.WebAssembly;
using Corvus.Native.Providers;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>In-process WebAssembly validation: section rules and type checking, against wasm-validate.</summary>
public sealed class WasmValidationTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    [Fact]
    public void Valid_fixtures_validate() => Validates(WasmTextTests.Fixtures());

    [Permit("reference-tool")]
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_WASM_DIR")]
    public void Real_builds_validate() => Validates(WasmTextTests.RealBuilds());

    private void Validates(IEnumerable<(string Name, byte[] Bytes)> corpus)
    {
        var empty = new List<string>();
        int fromComponents = 0;
        foreach (var (name, bytes) in corpus)
        {
            var modules = WasmTextTests.CoreModules(name, bytes);
            if (WasmComponent.Looks(bytes) && modules.Count == 0) empty.Add(name);
            if (WasmComponent.Looks(bytes)) fromComponents += modules.Count;
            foreach (var (module, code) in modules)
            {
                var v = WasmValidator.Validate(WasmBinary.Read(code));
                Assert.True(v.Valid, $"{module}: {string.Join("; ", v.Errors.Take(5))}");
            }
        }
        output.WriteLine($"{fromComponents} core modules of components validated");
        if (empty.Count > 0) output.WriteLine($"{empty.Count} components with no core module, not validated: {string.Join(", ", empty)}");
    }

    [Fact]
    public void Each_broken_fixture_is_invalid_with_a_located_error()
    {
        foreach (var (name, bytes) in WasmFixtures.Invalid())
        {
            var v = WasmValidator.Validate(WasmBinary.Read(bytes));
            Assert.True(v.Verdict == "invalid", $"{name}: {v.Verdict}");
            Assert.NotEmpty(v.Errors);
        }
        var typeError = WasmValidator.Validate(WasmBinary.Read(WasmFixtures.Invalid().First().Bytes));
        Assert.StartsWith("function 0 at 0x", Assert.Single(typeError.Errors), StringComparison.Ordinal);
    }

    [Fact]
    public void Wasm_view_gives_the_verdict()
    {
        var bytes = WasmFixtures.Invalid().First().Bytes;
        var view = new Corvus.Services.Analysis.WasmFileView().Inspect(new Corvus.Services.Analysis.FileInput("m.wasm", bytes, "wasm"), default)!;
        var facts = (Corvus.Services.Analysis.WasmFileView.Facts)view.Detail;
        Assert.Equal("invalid", facts.Validation);
        Assert.Contains(view.Highlights, h => h.StartsWith("Validation: invalid (function 0 at 0x", StringComparison.Ordinal));
    }

    [Fact]
    [FuzzEntry(typeof(WasmBinary))]
    public void Fuzzed_modules_never_throw_in_validation()
    {
        var seed = WasmFixtures.Valid().Single(f => f.Name == "control").Bytes;
        var failures = FormatFuzz.Run(seed, b => WasmValidator.Validate(WasmBinary.Read(b)), 2000);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    /// <summary>wasm-validate (CORVUS_WASM_VALIDATOR) gives the same verdict on the valid and broken fixtures and the real builds (a component's core modules).</summary>
    [Permit("reference-tool")]
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_WASM_VALIDATOR")]
    public void Verdicts_equal_wasm_validate()
    {
        var tool = ExternalTools.WasmValidator;
        var exe = ExternalTools.Locate(tool)!.Value.Path;
        int compared = 0;
        var differ = new List<string>();
        var gc = new List<string>();
        foreach (var (name, bytes) in WasmTextTests.Corpus().SelectMany(c => WasmTextTests.CoreModules(c.Name, c.Bytes)).Concat(WasmFixtures.Invalid()))
        {
            var module = WasmBinary.Read(bytes);
            if (module.Gc) { gc.Add(name); continue; }
            var path = _dir.File($"m{compared}.wasm");
            File.WriteAllBytes(path, bytes);
            var run = ExternalTools.Run(exe, ExternalTools.Arguments(tool, "validate", ("module", path)), TimeSpan.FromMinutes(5), 1 << 20, default);
            compared++;
            bool expected = run.ExitCode == 0;
            var ours = WasmValidator.Validate(module);
            if (expected != ours.Valid)
                differ.Add($"{name}: wasm-validate {(expected ? "valid" : "invalid: " + run.Stderr.Trim())}; ours {WasmValidator.Describe(ours)}");
        }
        foreach (var d in differ) output.WriteLine(d);
        output.WriteLine($"{compared - differ.Count} of {compared} verdicts equal");
        WasmTextTests.WriteNotCompared(output, gc, []);
        Assert.Empty(differ);
    }
}
