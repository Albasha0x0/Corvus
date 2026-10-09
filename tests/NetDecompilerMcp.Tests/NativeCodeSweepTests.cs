using System.Diagnostics;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Code analysis over many Windows DLLs: no exceptions, bounded time, every x64 .pdata function found.
/// NDM_NATIVE_SWEEP_LIMIT caps the number of files per directory (default 400; 0 = all).
/// </summary>
[Trait("Speed", "Slow")]
public class NativeCodeSweepTests(ITestOutputHelper output)
{
    private static readonly TimeSpan PerFileLimit = TimeSpan.FromSeconds(120);

    public static IEnumerable<string> Sample(string directory)
    {
        if (!OperatingSystem.IsWindows() || !Directory.Exists(directory)) return [];
        int limit = int.TryParse(Environment.GetEnvironmentVariable("NDM_NATIVE_SWEEP_LIMIT"), out var l) ? l : 400;
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

    private void Sweep(string directory, NativeArch arch)
    {
        if (!OperatingSystem.IsWindows()) return;
        int files = 0, skipped = 0;
        long functions = 0, instructions = 0, xrefs = 0, pdata = 0, pdataMissing = 0, unresolved = 0, switches = 0, invalid = 0;
        var failures = new List<string>();
        var slowest = (Name: "", Time: TimeSpan.Zero, Size: 0L);
        var total = Stopwatch.StartNew();
        foreach (var path in Sample(directory))
        {
            CodeTestImage image;
            try { image = CodeTestImage.Load(path); }
            catch (Exception ex) when (ex is BadImageFormatException or IOException or UnauthorizedAccessException or InvalidOperationException) { skipped++; continue; }
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
            var missing = PdataStartsMissing(image, index);
            pdata += missing.Total;
            pdataMissing += missing.Missing.Count;
            if (missing.Missing.Count > 0)
                failures.Add($"{Path.GetFileName(path)}: {missing.Missing.Count} .pdata starts not found, e.g. {string.Join(", ", missing.Missing.Take(5).Select(m => m.ToString("X")))}");
        }
        output.WriteLine($"{directory} ({arch}): {files} files, {skipped} skipped, {total.Elapsed.TotalSeconds:F1} s");
        output.WriteLine($"functions {functions}, instructions {instructions}, xrefs {xrefs}, switches {switches}, unresolved indirect jumps (functions) {unresolved}, functions with invalid code {invalid}");
        if (arch == NativeArch.X64) output.WriteLine($".pdata primary starts {pdata}, missing {pdataMissing}");
        output.WriteLine($"slowest: {slowest.Name} ({slowest.Size / 1024} KB) {slowest.Time.TotalSeconds:F2} s");
        foreach (var f in failures.Take(50)) output.WriteLine("FAIL " + f);
        Assert.Empty(failures);
    }

    /// <summary>Primary (not chained) .pdata starts in executable code that are not function starts of the index.</summary>
    internal static (int Total, List<uint> Missing) PdataStartsMissing(INativeImage image, NativeCodeIndex index)
    {
        var primaries = new HashSet<uint>();
        var fragments = ChainedFragments(image);
        foreach (var rf in image.RuntimeFunctions)
            if (!fragments.Contains(rf.BeginRva) && image.SectionAt(rf.BeginRva) is { IsExecutable: true }) primaries.Add(rf.BeginRva);
        var missing = primaries.Where(p => index.FunctionByStart(p) == null).Order().ToList();
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
