using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Go;
using Xunit.Abstractions;

namespace Corvus.Tests.NativeFormats;

/// <summary>Go function tables of real Go programs: every file of the CORVUS_GO_SAMPLES folder (ELF, PE, Mach-O; never run).</summary>
[Trait("Speed", "Slow")]
public sealed class GoRealTests(ITestOutputHelper output)
{
    public const string Variable = "CORVUS_GO_SAMPLES";

    private static IEnumerable<(string Name, INativeImage Image)> Samples()
    {
        foreach (var path in Directory.EnumerateFiles(RealData.Path(Variable)).Order(StringComparer.Ordinal))
        {
            INativeImage image;
            try { image = NativeImageLoader.Open(path); }
            catch (Exception ex) when (ex is IOException or InvalidOperationException or ArgumentException) { continue; }
            if (GoFunctionTable.Of(image) != null) yield return (Path.GetFileName(path), image);
        }
    }

    [RequiresRealDataFact(Variable)]
    public void Function_sizes_are_their_own_code_not_the_gap_to_the_next()
    {
        int files = 0;
        foreach (var (name, image) in Samples())
        {
            files++;
            var go = GoFunctionTable.Of(image)!;
            int own = go.Functions.Count(f => f.OwnSize);
            // symbol sizes, where the linker kept its symbol table, are the code without alignment padding
            var symbols = image.Symbols.Where(s => s.Kind == ImageSymbolKind.Function && s.Size > 0).GroupBy(s => s.Rva).ToDictionary(g => g.Key, g => g.First().Size);
            int compared = 0, agree = 0, gapAgree = 0;
            for (int i = 0; i < go.Functions.Count; i++)
            {
                var f = go.Functions[i];
                if (!symbols.TryGetValue(f.Rva, out var size)) continue;
                compared++;
                if (Math.Abs((long)size - f.Size) <= 1) agree++;
                if (i + 1 < go.Functions.Count && Math.Abs((long)size - (go.Functions[i + 1].Rva - f.Rva)) <= 1) gapAgree++;
            }
            output.WriteLine($"{name}: {go.VersionText}, {go.Functions.Count} functions, {own} own sizes; symbol sizes matched {agree}/{compared} (gap to the next entry: {gapAgree})");
            Assert.True(own >= go.Functions.Count * 995L / 1000, $"{name}: {own} of {go.Functions.Count} sizes from the function's own tables");
            if (compared > 0) Assert.True(agree >= compared * 995L / 1000, $"{name}: {agree} of {compared} sizes match the symbol table");
        }
        Assert.True(files > 0, "no Go programs in the samples folder");
    }

    [RequiresRealDataFact(Variable)]
    public void Code_walks_stay_inside_the_tables_extents()
    {
        foreach (var (name, image) in Samples())
        {
            var go = GoFunctionTable.Of(image)!;
            var index = NativeCodeIndex.Build(image);
            // walks may end short (padding, literal pools, code after noreturn calls), never past
            int same = go.Functions.Count(g => g.OwnSize && index.FunctionByStart(g.Rva) is { } f && f.End == g.Rva + g.Size);
            output.WriteLine($"{name}: {same} of {go.Functions.Count} walks end where the table does; {string.Join("; ", index.Issues)}");
            int over = index.Issues.Count == 0 ? 0 : int.Parse(index.Issues.Single().Split(' ')[3]);
            Assert.True(over <= go.Functions.Count / 200, $"{name}: {over} functions decode past their end");
        }
    }

    [RequiresRealDataFact(Variable)]
    public void Build_info_names_the_toolchain_module_and_settings()
    {
        foreach (var (name, image) in Samples())
        {
            var build = GoBuildInfo.Of(image);
            Assert.NotNull(build);
            output.WriteLine($"{name}: {build.GoVersion}; path {build.Path}; main {build.Main}; {build.Dependencies.Count} deps; " +
                             string.Join(", ", build.Settings.Select(s => $"{s.Key}={s.Value}")));
            Assert.StartsWith("go1.", build.GoVersion);
        }
    }
}
