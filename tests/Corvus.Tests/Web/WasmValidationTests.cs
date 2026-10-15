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
    public void Valid_fixtures_and_real_builds_validate()
    {
        foreach (var (name, bytes) in WasmTextTests.Corpus())
        {
            var v = WasmValidator.Validate(WasmBinary.Read(bytes));
            Assert.True(v.Valid, $"{name}: {string.Join("; ", v.Errors.Take(5))}");
        }
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
    public void Fuzzed_modules_never_throw_in_validation()
    {
        var seed = WasmFixtures.Valid().Single(f => f.Name == "control").Bytes;
        var failures = FormatFuzz.Run(seed, b => WasmValidator.Validate(WasmBinary.Read(b)), 2000);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    /// <summary>wasm-validate (CORVUS_WASM_VALIDATOR) gives the same verdict on the valid and broken fixtures and the real builds.</summary>
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_WASM_VALIDATOR")]
    public void Verdicts_equal_wasm_validate()
    {
        var tool = ExternalTools.WasmValidator;
        var exe = ExternalTools.Locate(tool)!.Value.Path;
        int compared = 0;
        var differ = new List<string>();
        foreach (var (name, bytes) in WasmTextTests.Corpus().Concat(WasmFixtures.Invalid()))
        {
            var path = _dir.File($"m{compared}.wasm");
            File.WriteAllBytes(path, bytes);
            var run = ExternalTools.Run(exe, ExternalTools.Arguments(tool, "validate", ("module", path)), TimeSpan.FromMinutes(5), 1 << 20, default);
            compared++;
            bool expected = run.ExitCode == 0;
            var ours = WasmValidator.Validate(WasmBinary.Read(bytes));
            if (expected != ours.Valid)
                differ.Add($"{name}: wasm-validate {(expected ? "valid" : "invalid: " + run.Stderr.Trim())}; ours {WasmValidator.Describe(ours)}");
        }
        foreach (var d in differ) output.WriteLine(d);
        output.WriteLine($"{compared - differ.Count} of {compared} verdicts equal");
        Assert.Empty(differ);
    }
}
