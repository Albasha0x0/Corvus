using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary>load_assembly import overrides: their form, their key (one database per set) and the checks against an engine's own names.</summary>
public sealed class ImportOverrideTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static RawCodeImage Image() => new(new byte[0x2000], "seeded.bin", RawLayout.Parse("x86", "0x400000", null, 0x2000));

    [Fact]
    public void Overrides_parse_to_one_canonical_form_and_key()
    {
        var image = Image();
        var a = EngineOverrides.Parse(image, null, "x86:LE:32:default", "borlandcpp", ["0x401000=WinMain", "label:rva:0x1800=table", "code:0x400100"], ["Stack", "AF_FLIRT"])!;
        var b = EngineOverrides.Parse(image, null, " x86:LE:32:default ", "borlandcpp", ["code:0x400100", "function:0x401000=WinMain", "label:0x401800=table"], ["AF_FLIRT", "Stack", "Stack"])!;
        Assert.Equal(a, b);
        Assert.Equal(a.Key, b.Key);
        Assert.Equal("language=x86:LE:32:default; compilerSpec=borlandcpp; seeds=code:rva:0x100,function:rva:0x1000=WinMain,label:rva:0x1800=table; disableAnalyzers=AF_FLIRT,Stack", a.Text);
        Assert.Equal(0x02, a.IdaCompiler);
        // Another override is another database.
        Assert.NotEqual(a.Key, EngineOverrides.Parse(image, null, "x86:LE:32:default", "windows", null, null)!.Key);
        Assert.Null(EngineOverrides.Parse(image, " ", null, null, [], null));

        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => EngineOverrides.Parse(image, null, "x86-32", null, null, null)).Code);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => EngineOverrides.Parse(image, null, null, null, ["label:0x401000"], null)).Code);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => EngineOverrides.Parse(image, null, null, null, ["0x401000=bad name"], null)).Code);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => EngineOverrides.Parse(image, null, null, null, null, ["Stack=false"])).Code);
        Assert.ThrowsAny<ToolError>(() => EngineOverrides.Parse(image, null, null, null, ["0x900000"], null));
    }

    [Fact]
    public void Names_are_checked_against_ldefs_and_processor_modules()
    {
        var languages = Directory.CreateDirectory(_dir.File("ghidra/Ghidra/Processors/x86/data/languages")).FullName;
        File.WriteAllText(Path.Combine(languages, "x86.ldefs"), """
            <language_definitions>
              <language processor="x86" endian="little" size="32" variant="default" id="x86:LE:32:default">
                <compiler name="Visual Studio" spec="x86win.cspec" id="windows"/>
                <compiler name="Borland C++" spec="x86borland.cspec" id="borlandcpp"/>
              </language>
              <language processor="x86" endian="little" size="64" variant="default" id="x86:LE:64:default">
                <compiler name="Visual Studio" spec="x86-64-win.cspec" id="windows"/>
              </language>
            </language_definitions>
            """);
        var ghidra = _dir.File("ghidra");
        var image = Image();
        EngineOverrideChecks.CheckGhidra(ghidra, EngineOverrides.Parse(image, null, "x86:LE:32:default", "borlandcpp", null, null)!);
        EngineOverrideChecks.CheckGhidra(ghidra, EngineOverrides.Parse(image, null, null, "borlandcpp", null, null)!);
        var noLanguage = Assert.Throws<ToolError>(() => EngineOverrideChecks.CheckGhidra(ghidra, EngineOverrides.Parse(image, null, "x86:LE:32:defualt", null, null, null)!));
        Assert.Contains("x86:LE:32:default", noLanguage.Remediation);
        Assert.Throws<ToolError>(() => EngineOverrideChecks.CheckGhidra(ghidra, EngineOverrides.Parse(image, null, "x86:LE:64:default", "borlandcpp", null, null)!));
        Assert.Throws<ToolError>(() => EngineOverrideChecks.CheckGhidra(ghidra, EngineOverrides.Parse(image, null, null, "borland", null, null)!));
        // A raw layout's language decides the compiler specs when no language is given.
        Assert.Throws<ToolError>(() => EngineOverrideChecks.CheckGhidra(ghidra, EngineOverrides.Parse(image, null, null, "borlandcpp", null, null)!, "x86:LE:64:default"));

        var procs = Directory.CreateDirectory(_dir.File("ida/procs")).FullName;
        File.WriteAllBytes(Path.Combine(procs, "pc.dll"), [0x4D, 0x5A, 0, .. "8086"u8, 0, .. "metapc"u8, 0, .. "80386p"u8, 0, 0xFF, .. "notaname"u8, 0]);
        File.WriteAllText(Path.Combine(procs, "spu.py"), "PLFM = 1\npsnames = ['spu']\n");
        var ida = _dir.File("ida");
        EngineOverrideChecks.CheckIda(ida, EngineOverrides.Parse(image, "METAPC", null, null, null, null)!);
        EngineOverrideChecks.CheckIda(ida, EngineOverrides.Parse(image, "spu", null, null, null, null)!);
        var noProcessor = Assert.Throws<ToolError>(() => EngineOverrideChecks.CheckIda(ida, EngineOverrides.Parse(image, "metapcc", null, null, null, null)!));
        Assert.Contains("metapc", noProcessor.Remediation);
        Assert.Throws<ToolError>(() => EngineOverrideChecks.CheckIda(ida, EngineOverrides.Parse(image, "notaname", null, null, null, null)!));
    }
}
