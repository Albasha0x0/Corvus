using System.Diagnostics;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>compare_native_images engine=: a file against IDA's and Ghidra's memory, before and after a byte patch, on PE and ELF.</summary>
public sealed partial class EngineMemoryCompareTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    // Initialized pointers (base relocations) and a zero-initialized array (zero fill past the file data).
    private const string Source = """
        #include <windows.h>
        static int counters[4096];
        static const char *names[] = { "alpha", "beta", "gamma" };
        __declspec(dllexport) const char *Name(int i) { counters[i & 4095]++; return names[i % 3]; }
        __declspec(dllexport) int Count(int i) { return counters[i & 4095]; }
        """;

    private (NativeDiffTools Diff, NativeEditTools Edits, AssemblyWorkspace Workspace, NativeEngineService Engines) Rig(string? seedInput = null)
    {
        var options = new ServerOptions { TimeoutSeconds = 600, BackgroundIndexing = false };
        var ws = new AssemblyWorkspace(options);
        var code = new NativeCodeService(ws, options, null, new Native.Annotations.AnnotationStore(_dir.File("ann")));
        var cache = _dir.File("cache");
        if (seedInput != null) EngineSeed.Copy(cache, seedInput);
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = cache }, code, ws, options, new GhidraProviderOptions { CacheRoot = cache });
        var edits = new NativeEditService(ws, code);
        _owned.Add(engines);
        _owned.Add(ws);
        return (new NativeDiffTools(ws, code, engines, edits), new NativeEditTools(ws, code, edits, null, engines), ws, engines);
    }

    [GeneratedRegex(@"^\s+0x[0-9A-F]+ \S+ \+0x[0-9A-F]+ (?<kind>[a-z_]+)", RegexOptions.Multiline)]
    private static partial Regex RowKind();

    private static List<string> Kinds(string text) => [.. RowKind().Matches(text).Select(m => m.Groups["kind"].Value)];

    private async Task Patched_bytes_are_the_only_difference_from_a_built_dll(string engine)
    {
        var vcvars = VisualStudio.VcVarsAll();
        if (vcvars == null) return;
        File.WriteAllText(_dir.File("fixture.c"), Source);
        var (exit, log) = Tools.Run(new ProcessStartInfo("cmd.exe")
        {
            WorkingDirectory = _dir.Path,
            Arguments = $"/s /c \"\"{vcvars}\" x64 >nul && cl /nologo /O2 /LD fixture.c /link /OUT:fixture.dll\"",
        }, 300_000);
        Assert.True(exit == 0, log);
        var (diff, edits, _, _) = Rig();
        var path = _dir.File("fixture.dll");

        var before = await diff.CompareNativeImages(oldImage: path, engine: engine, limit: 200);
        output.WriteLine(before);
        Assert.DoesNotContain("differs", Kinds(before));
        Assert.DoesNotContain("unclassified", Kinds(before));
        Assert.Matches(@"\.data 0x[0-9A-F]+ size 0x[0-9A-F]+: \d+ compared, \d+ equal, \d+ unknown, [1-9]\d* zero fill", before);

        var pe = Native.Pe.PeFile.Open(path);
        var export = Native.NativeAddress.Va(pe, pe.Exports.First(e => e.Name == "Name").Rva);
        await edits.PatchBytes(path, export, hex: "90 90", allowUnsafe: true, dryRun: false);
        var after = await diff.CompareNativeImages(oldImage: path, engine: engine, limit: 200);
        output.WriteLine(after);
        Assert.Equal(["patched"], Kinds(after).Where(k => k is "patched" or "differs" or "unclassified"));
        Assert.Matches(new Regex($@"^\s+{export} \.text \+0x2 patched file 0x[0-9A-F]+: session edit", RegexOptions.Multiline), after);
    }

    private async Task Loader_fixups_of_an_elf_library_are_named(string engine)
    {
        var (diff, _, _, _) = Rig();
        var text = await diff.CompareNativeImages(oldImage: NativeFormats.NativeFixtures.LinuxX64DbgShim, engine: engine, limit: 2000);
        output.WriteLine(string.Join("\n", text.Split('\n').Where(l => !l.Contains(" engine_fixup file ", StringComparison.Ordinal))));
        Assert.Matches(@"[1-9]\d* engine fixups", text);
        Assert.Contains("engine_fixup", Kinds(text));
        Assert.DoesNotContain("differs", Kinds(text));
        Assert.DoesNotContain("unclassified", Kinds(text));
    }

    /// <summary>The system DLL from a seeded analysis: the comparison's own time, bounded, with the session already open.</summary>
    private async Task A_system_dll_compares_within_the_bound(string engine)
    {
        var (_, _, ws, engines) = Rig(NativeIdaProviderTests.System64);
        var native = ws.LoadAny(NativeIdaProviderTests.System64).Native!;
        var session = await engines.Session(native, engine, null, default);
        var control = EngineControl.Require(session, "memory reads");
        var file = Native.Patching.NativePatchSet.FileBytesOf(native.Image).ToArray();
        var clock = Stopwatch.StartNew();
        var report = await Native.Diff.EngineMemoryDiff.CompareAsync(engine, native.Image, file, session.ImageBase, control, [], default);
        output.WriteLine($"{engine}: {clock.Elapsed.TotalMilliseconds:0} ms for {native.Image.SizeOfImage} mapped bytes, {report.Fixups} fixups, " +
                         $"{report.Ranges.Count} ranges: {string.Join(", ", report.Ranges.GroupBy(r => r.Kind).Select(g => $"{g.Count()} {g.Key}"))}");
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(30), $"{clock.Elapsed.TotalSeconds:0.0} s");
        Assert.DoesNotContain(report.Ranges, r => r.Kind is "differs" or "unclassified");
    }

    [IdaFact]
    [Trait("Speed", "Slow")]
    public Task Ida_patched_bytes_are_the_only_difference_from_a_built_dll() => Patched_bytes_are_the_only_difference_from_a_built_dll("ida");

    [GhidraFact]
    [Trait("Speed", "Slow")]
    public Task Ghidra_patched_bytes_are_the_only_difference_from_a_built_dll() => Patched_bytes_are_the_only_difference_from_a_built_dll("ghidra");

    [IdaFact]
    [Trait("Speed", "Slow")]
    public Task Ida_loader_fixups_of_an_elf_library_are_named() => Loader_fixups_of_an_elf_library_are_named("ida");

    [GhidraFact]
    [Trait("Speed", "Slow")]
    public Task Ghidra_loader_fixups_of_an_elf_library_are_named() => Loader_fixups_of_an_elf_library_are_named("ghidra");

    [IdaFact]
    [Trait("Speed", "Slow")]
    public Task Ida_compares_a_system_dll_within_the_bound() => A_system_dll_compares_within_the_bound("ida");

    [GhidraFact]
    [Trait("Speed", "Slow")]
    public Task Ghidra_compares_a_system_dll_within_the_bound() => A_system_dll_compares_within_the_bound("ghidra");
}
