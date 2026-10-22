using System.Diagnostics;
using Corvus.Native;
using Corvus.Native.Code;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Code analysis over many Windows DLLs: no exceptions, bounded time, every x64 .pdata function found.
/// CORVUS_NATIVE_SWEEP_LIMIT caps the number of files per directory (default 400; 0 = all).
/// </summary>
[Trait("Speed", "Slow")]
public class NativeCodeSweepTests(ITestOutputHelper output)
{
    private static readonly TimeSpan PerFileLimit = TimeSpan.FromSeconds(120);

    public static IEnumerable<string> Sample(string directory)
    {
        if (!OperatingSystem.IsWindows() || !Directory.Exists(directory)) return [];
        int limit = int.TryParse(Environment.GetEnvironmentVariable("CORVUS_NATIVE_SWEEP_LIMIT"), out var l) ? l : SweepScope.Count(400);
        var files = Directory.EnumerateFiles(directory, "*.dll").Concat(Directory.EnumerateFiles(directory, "*.exe"))
            .Where(f => { try { return new FileInfo(f).Length is > 0 and < 200_000_000; } catch (IOException) { return false; } })
            .Order(StringComparer.OrdinalIgnoreCase).ToList();
        if (limit <= 0 || files.Count <= limit) return files;
        int step = files.Count / limit;
        return files.Where((_, i) => i % step == 0).Take(limit);
    }

    [Fact]
    public void System32_x64() => Sweep(Environment.SystemDirectory, NativeArch.X64);

    [Fact]
    public void SysWow64_x86()
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");
        Sweep(dir, NativeArch.X86);
    }

    /// <summary>One large image (CORVUS_NATIVE_LARGE_IMAGE, e.g. a game executable or a browser DLL): time, memory, completeness.</summary>
    [RequiresRealDataFact("CORVUS_NATIVE_LARGE_IMAGE")]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    [Trait("Tier", "Release")]
    public void Large_image()
    {
        var path = RealData.Path("CORVUS_NATIVE_LARGE_IMAGE");
        var image = Corvus.Native.Pe.PeFile.Open(path);
        long before = GC.GetTotalMemory(true);
        var phases = new List<string>();
        var sw = Stopwatch.StartNew();
        var index = NativeCodeIndex.Build(image, progress: p => { if (phases.Count == 0 || phases[^1] != p.Phase) phases.Add($"{p.Phase} @{sw.Elapsed.TotalSeconds:F1}s"); });
        sw.Stop();
        long retained = GC.GetTotalMemory(true) - before;
        output.WriteLine($"{path}: {new FileInfo(path).Length / 1048576} MB, {sw.Elapsed.TotalSeconds:F1} s, index {retained / 1048576} MB");
        output.WriteLine(string.Join(" | ", phases));
        output.WriteLine(index.Stats.ToString());
        foreach (var t in index.Truncations) output.WriteLine("truncated: " + t);
        if (image.Arch == NativeArch.X64) Assert.Empty(PdataStartsMissing(image, index).Missing);
        PerfBudget.Time("native/large-image-index", sw.Elapsed, TimeSpan.FromMinutes(5), output);
        GC.KeepAlive(index);
    }

    private void Sweep(string directory, NativeArch arch)
    {
        if (!OperatingSystem.IsWindows()) return;
        int files = 0, skipped = 0;
        long functions = 0, instructions = 0, xrefs = 0, pdata = 0, pdataMissing = 0, unresolved = 0, switches = 0, invalid = 0;
        long ehFrames = 0, ehChunks = 0, ehFunclets = 0, ehRejects = 0;
        var failures = new List<string>();
        var mostInvalid = new List<(string Name, int Invalid, int Functions)>();
        var slowest = (Name: "", Time: TimeSpan.Zero, Size: 0L);
        var total = Stopwatch.StartNew();
        foreach (var path in Sample(directory))
        {
            Corvus.Native.Pe.PeFile image;
            try { image = Corvus.Native.Pe.PeFile.Open(path); }
            catch (Corvus.Core.ToolError) { skipped++; continue; }
            if (image.Arch != arch) { skipped++; continue; }
            files++;
            using var cts = new CancellationTokenSource(PerFileLimit);
            var sw = Stopwatch.StartNew();
            NativeCodeIndex index;
            try { index = NativeCodeIndex.Build(image, ct: cts.Token); }
            catch (Exception ex)
            {
                failures.Add($"{Path.GetFileName(path)}: {ex.GetType().Name}: {ex.Message}");
                continue;
            }
            sw.Stop();
            if (sw.Elapsed > slowest.Time) slowest = (Path.GetFileName(path), sw.Elapsed, new FileInfo(path).Length);
            functions += index.Stats.Functions;
            instructions += index.Stats.Instructions;
            xrefs += index.Stats.Xrefs;
            unresolved += index.Stats.UnresolvedJumps;
            switches += index.Stats.ResolvedSwitches;
            invalid += index.Stats.FunctionsWithInvalidCode;
            mostInvalid.Add((Path.GetFileName(path), index.Stats.FunctionsWithInvalidCode, index.Stats.Functions));
            // exception metadata: decoded without internal errors, chunks part of their function
            ehFrames += index.ExceptionInfo.Stats.Frames;
            ehRejects += index.ExceptionInfo.RejectCount;
            ehChunks += index.Functions.Sum(f => f.Chunks.Count);
            ehFunclets += index.Functions.Count(f => f.Parent != null);
            if (index.Truncations.FirstOrDefault(t => t.StartsWith("exception metadata", StringComparison.Ordinal)) is { } ehError)
                failures.Add($"{Path.GetFileName(path)}: {ehError}");
            try
            {
                MsvcEhTests.CheckInvariants(image, index.ExceptionInfo);
                MsvcEhTests.CheckChunks(index, maxGraphs: 20);
            }
            catch (Xunit.Sdk.XunitException ex) { failures.Add($"{Path.GetFileName(path)}: exception metadata: {ex.Message}"); }
            var missing = PdataStartsMissing(image, index);
            pdata += missing.Total;
            pdataMissing += missing.Missing.Count;
            if (missing.Missing.Count > 0)
                failures.Add($"{Path.GetFileName(path)}: {missing.Missing.Count} .pdata starts not found, e.g. {string.Join(", ", missing.Missing.Take(5).Select(m => m.ToString("X")))}");
        }
        output.WriteLine($"{directory} ({arch}): {files} files, {skipped} skipped, {total.Elapsed.TotalSeconds:F1} s");
        output.WriteLine($"functions {functions}, instructions {instructions}, xrefs {xrefs}, switches {switches}, unresolved indirect jumps (functions) {unresolved}, functions with invalid code {invalid}");
        if (arch == NativeArch.X64) output.WriteLine($".pdata primary starts {pdata}, missing {pdataMissing}");
        output.WriteLine($"exception metadata: {ehFrames} frames, {ehChunks} chunks attached, {ehFunclets} funclets with a parent, {ehRejects} rejects");
        output.WriteLine($"slowest: {slowest.Name} ({slowest.Size / 1024} KB) {slowest.Time.TotalSeconds:F2} s");
        output.WriteLine("most functions with invalid code: " + string.Join(", ", mostInvalid.OrderByDescending(m => m.Invalid).Take(6).Select(m => $"{m.Name} {m.Invalid}/{m.Functions}")));
        foreach (var f in failures.Take(50)) output.WriteLine("FAIL " + f);
        Assert.Empty(failures);
    }

    /// <summary>Primary (not chained) .pdata starts in executable code that are neither function starts of the index nor chunks of a function.</summary>
    internal static (int Total, List<uint> Missing) PdataStartsMissing(INativeImage image, NativeCodeIndex index)
    {
        var primaries = new HashSet<uint>();
        var fragments = ChainedFragments(image);
        foreach (var rf in image.RuntimeFunctions)
            if (!fragments.Contains(rf.BeginRva) && image.SectionAt(rf.BeginRva) is { IsExecutable: true }) primaries.Add(rf.BeginRva);
        var missing = primaries.Where(p => index.FunctionByStart(p) == null && index.ChunkOwner(p) == null).Order().ToList();
        return (primaries.Count, missing);
    }

    /// <summary>Starts of x64 .pdata entries whose unwind info is chained to another entry.</summary>
    internal static HashSet<uint> ChainedFragments(INativeImage image)
    {
        var result = new HashSet<uint>();
        if (image.Arch != NativeArch.X64) return result;
        Span<byte> header = stackalloc byte[4];
        foreach (var rf in image.RuntimeFunctions)
        {
            if ((rf.UnwindInfoRva & 1) != 0) { result.Add(rf.BeginRva); continue; }
            if (image.Read(rf.UnwindInfoRva, header) == 4 && ((header[0] >> 3) & 4) != 0) result.Add(rf.BeginRva);
        }
        return result;
    }
}
