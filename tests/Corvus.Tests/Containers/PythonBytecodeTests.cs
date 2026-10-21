using Corvus.Core;
using Corvus.Core.Python;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>.pyc files compiled from PythonFixtures/constructs*.py by CPython 2.7 and 3.0 to 3.14 (build.ps1), with the dis output of each.</summary>
public sealed class PythonBytecodeTests
{
    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Containers", "PythonFixtures", name);

    private static readonly string[] Built = ["2.7", .. Enumerable.Range(0, 15).Select(m => $"3.{m}")];

    public static TheoryData<string> Versions => [.. Built];

    private static (PyCode Code, (int, int) Version) Read(string version)
    {
        var data = File.ReadAllBytes(Fixture($"constructs-{version}.pyc"));
        var v = PyVersion.FromMagic(data)!.Value;
        return ((PyCode)PyMarshal.Read(data, v, PyVersion.HeaderLength(v)), v);
    }

    [Theory]
    [MemberData(nameof(Versions))]
    public void The_disassembly_equals_the_dis_output_of_the_same_python(string version)
    {
        var (code, v) = Read(version);
        Assert.Equal(PyVersion.Label(v), version);
        var text = PyDisassembler.Disassemble(code, v, int.MaxValue, default, out bool complete);
        Assert.True(complete);
        Assert.Equal(File.ReadAllText(Fixture($"constructs-{version}.dis")), text);
    }

    [Fact]
    public void Python_view_of_a_pyc_names_its_functions_and_imports_and_pages_the_disassembly()
    {
        var path = Fixture("constructs-3.12.pyc");
        var bytes = File.ReadAllBytes(path);
        var input = new FileInput(path, bytes, Blob.Identify(bytes)) { Options = new FileViewOptions("python", Offset: 100) };
        var facts = Assert.IsType<PythonFileView.Bytecode>(new PythonFileView().Inspect(input, default)!.Detail);
        Assert.Equal(("3.12", "constructs.py"), (facts.PythonVersion, facts.Filename));
        Assert.Equal(["os.path", "collections"], facts.Imports);
        Assert.Contains("counter.<locals>.bump", facts.Functions);
        Assert.Contains("Store.fetch", facts.Functions);
        Assert.Equal(File.ReadAllText(Fixture("constructs-3.12.dis"))[100..], facts.Disassembly);
        Assert.Null(facts.Next);

        // the overview names the view without disassembling
        var overview = new PythonFileView().Inspect(new FileInput(path, bytes, Blob.Identify(bytes)), default)!;
        Assert.Equal("", Assert.IsType<PythonFileView.Bytecode>(overview.Detail).Disassembly);
        Assert.Contains("view=python shows the disassembly", Assert.Single(overview.Highlights));
    }

    [Fact]
    public void Repr_of_floats_and_strings_follows_python()
    {
        Assert.Equal(["1e+16", "1234567890123456.0", "0.0001", "1.5e-05", "-0.0", "inf", "0.1"],
            new[] { 1e16, 1234567890123456.0, 0.0001, 1.5e-5, -0.0, double.PositiveInfinity, 0.1 }.Select(d => PyRepr.Of(d, (3, 12))));
        Assert.Equal("'\\ud800'", PyRepr.Of("\ud800", (3, 12)));
        Assert.Equal("\"it's\"", PyRepr.Of("it's", (3, 12)));
        // U+1C89 was assigned in Unicode 16.0: Python 3.13 (15.1) escapes it
        Assert.Equal("'\\u1c89'", PyRepr.Of("Ᲊ", (3, 13)));
        Assert.Equal("'Ᲊ'", PyRepr.Of("Ᲊ", (3, 14)));
        Assert.Equal("(1+0j)", PyRepr.Of(new PyComplex(1, 0), (3, 12)));
        Assert.Equal("2L", PyRepr.Of(new System.Numerics.BigInteger(2), (2, 7)));
    }

    [Fact]
    [FuzzEntry(typeof(PyDisassembler))]
    public void Fuzzed_bytecode_disassembles_or_fails_with_a_tool_error()
    {
        var failures = new List<string>();
        foreach (var version in Built)
        {
            var seed = File.ReadAllBytes(Fixture($"constructs-{version}.pyc"));
            failures.AddRange(FormatFuzz.Run(seed, b =>
            {
                if (PyVersion.FromMagic(b) is not { } v || PyMarshal.TryRead(b, v, out _, PyVersion.HeaderLength(v)) is not PyCode code) return;
                PyDisassembler.Disassemble(code, v, 1 << 20, default, out _);
                new PythonFileView().Inspect(new FileInput("fuzzed.pyc", b, "python bytecode") { Options = new FileViewOptions("python") }, default);
            }, 150));
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }
}

[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class PythonDecompilerTests
{
    [Fact]
    public void Python_view_shows_the_source_from_the_configured_decompiler()
    {
        using var fake = new FakeTool();
        fake.On(@"constructs-3\.12\.pyc$", stdout: "# Source Generated\ndef counter():\n    pass\n");
        using var env = new EnvironmentScope().Set("CORVUS_PY_DECOMPILER", fake.CopyAs("pycdc")).Set(FakeTool.ScriptVariable, fake.ScriptPath);
        var path = Path.Combine(AppContext.BaseDirectory, "Containers", "PythonFixtures", "constructs-3.12.pyc");
        var bytes = File.ReadAllBytes(path);
        var input = new FileInput(path, bytes, Blob.Identify(bytes)) { Options = new FileViewOptions("python") };
        var facts = Assert.IsType<PythonFileView.Bytecode>(new PythonFileView().Inspect(input, default)!.Detail);
        Assert.Equal("# Source Generated\ndef counter():\n    pass\n", facts.Source);
        Assert.Null(facts.SourceNext);
    }
}
