using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using Corvus.Core;
using Corvus.Native.Pe;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Mutation fuzzing of the native PE parser: real and synthetic images with bytes flipped or overwritten in the headers,
/// the section table and the directories (seeded, so a failure names the iteration that reproduces it).
/// CORVUS_PE_FUZZ_ITERATIONS sets the iteration count; CORVUS_PE_FUZZ_SEED the base seed.
/// </summary>
[Collection(SweepCollection.Name)]
public sealed class NativePeFuzzTests(ITestOutputHelper output)
{
    [Fact]
    [Trait("Speed", "Slow")]
    public void MutatedImages_NeverThrowAndStayBounded()
    {
        int iterations = int.TryParse(Environment.GetEnvironmentVariable("CORVUS_PE_FUZZ_ITERATIONS"), out int n) ? n : 20_000;
        int seed = int.TryParse(Environment.GetEnvironmentVariable("CORVUS_PE_FUZZ_SEED"), out int s) ? s : 20251010;
        var seeds = new List<(string, byte[])> { ("kitchen sink x64", NativePeTests.KitchenSink(true)), ("kitchen sink x86", NativePeTests.KitchenSink(false)) };
        foreach (var path in RealSeeds()) seeds.Add((path, File.ReadAllBytes(path)));
        var result = PeFuzzer.Run(seeds, iterations, seed);
        output.WriteLine($"{iterations} iterations over {seeds.Count} seeds in {result.Elapsed.TotalSeconds:0.0} s; " +
            $"slowest {result.MaxMilliseconds:0} ms, most allocated {result.MaxAllocatedBytes / (1 << 20)} MB, not a PE {result.NotPe}");
        foreach (var (name, _) in seeds) output.WriteLine("seed: " + name);
        Assert.True(result.Failures.Count == 0, string.Join("\n", result.Failures.Take(20)));
    }

    /// <summary>Small and varied Windows images: x64 and x86 DLLs, a driver, a resource-only DLL, an executable.</summary>
    private static IEnumerable<string> RealSeeds()
    {
        if (!OperatingSystem.IsWindows()) yield break;
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var system = Path.Combine(windows, "System32");
        string[] candidates =
        [
            Path.Combine(system, "kernel32.dll"),
            Path.Combine(windows, "SysWOW64", "kernel32.dll"),
            Path.Combine(system, "drivers", "null.sys"),
            Path.Combine(system, "notepad.exe"),
            Path.Combine(windows, "SysWOW64", "cmd.exe"),
        ];
        foreach (var c in candidates)
            if (File.Exists(c)) yield return c;
        if (Directory.Exists(system))
            foreach (var dir in Directory.EnumerateDirectories(system))
            {
                var mui = Path.Combine(dir, "user32.dll.mui");
                if (File.Exists(mui)) { yield return mui; break; }
            }
    }
}

/// <summary>Seeded mutation of PE images, focused on the bytes the parser reads first: headers and directory tables.</summary>
internal static class PeFuzzer
{
    public sealed record Result(List<string> Failures, TimeSpan Elapsed, double MaxMilliseconds, long MaxAllocatedBytes, int NotPe);

    /// <summary>A single parse (and full read) may take this long and allocate this much before it counts as a failure.</summary>
    private static readonly TimeSpan TimeBound = TimeSpan.FromMilliseconds(int.TryParse(Environment.GetEnvironmentVariable("CORVUS_PE_FUZZ_TIME_BOUND_MS"), out int ms) ? ms : 10_000);
    private const long AllocationBound = 512L << 20;

    public static Result Run(IReadOnlyList<(string Name, byte[] Bytes)> seeds, int iterations, int seed)
    {
        var targets = seeds.Select(s => Targets(s.Bytes)).ToArray();
        var failures = new ConcurrentBag<string>();
        double maxMs = 0;
        long maxAllocated = 0;
        int notPe = 0;
        var clock = Stopwatch.StartNew();
        Parallel.For(0, iterations, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, i =>
        {
            int which = i % seeds.Count;
            var rng = new Random(unchecked(seed * 1_000_003 + i)); // not HashCode.Combine: randomized per process
            var bytes = Mutate(seeds[which].Bytes, targets[which], rng, out string what);
            long before = GC.GetAllocatedBytesForCurrentThread();
            var timer = Stopwatch.StartNew();
            try
            {
                var pe = PeFile.FromBytes(bytes, "fuzz.bin");
                var issues = NativePeTests.TouchEverything(pe);
                foreach (var issue in issues.Where(x => x.Message.StartsWith("internal error", StringComparison.Ordinal)))
                    failures.Add($"iteration {i} ({seeds[which].Name}; {what}): {issue.Area}: {issue.Message}");
            }
            catch (ToolError e) when (e.Code == ErrorCode.MalformedInput) { Interlocked.Increment(ref notPe); }
            catch (Exception ex) { failures.Add($"iteration {i} ({seeds[which].Name}; {what}): {ex}"); }
            var elapsed = timer.Elapsed;
            long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
            if (elapsed > TimeBound) failures.Add($"iteration {i} ({seeds[which].Name}; {what}): took {elapsed.TotalSeconds:0.0} s");
            if (allocated > AllocationBound) failures.Add($"iteration {i} ({seeds[which].Name}; {what}): allocated {allocated >> 20} MB");
            if ((elapsed > TimeBound || allocated > AllocationBound || failures.Any(f => f.StartsWith($"iteration {i} ", StringComparison.Ordinal)))
                && Environment.GetEnvironmentVariable("CORVUS_PE_FUZZ_DUMP") is { Length: > 0 } dump)
                File.WriteAllBytes(Path.Combine(dump, $"fuzz-{seed}-{i}.bin"), bytes);
            InterlockedMax(ref maxMs, elapsed.TotalMilliseconds);
            InterlockedMax(ref maxAllocated, allocated);
        });
        return new Result([.. failures], clock.Elapsed, maxMs, maxAllocated, notPe);
    }

    /// <summary>File ranges worth mutating: the headers and the first bytes of every directory present in the seed.</summary>
    private static List<(int Start, int Length)> Targets(byte[] seed)
    {
        var pe = PeFile.FromBytes(seed);
        var targets = new List<(int, int)> { (0, (int)Math.Min(seed.Length, Math.Max(pe.Optional.SizeOfHeaders, 0x200))) };
        foreach (var dir in pe.DataDirectories.Where(d => d.IsPresent))
        {
            long offset;
            if (dir.Index == PeDirectory.Security) offset = dir.Rva;
            else if (!pe.TryRvaToFileOffset(dir.Rva, out offset)) continue;
            if (offset >= seed.Length) continue;
            targets.Add(((int)offset, (int)Math.Min(Math.Min(dir.Size, 0x400u), seed.Length - offset)));
        }
        // Tables the directories point at: import names and thunks, export tables, resource subdirectories.
        foreach (var m in pe.ImportModules.Take(4))
            if (pe.TryRvaToFileOffset(m.NameTableRva, out long o) && o < seed.Length) targets.Add(((int)o, (int)Math.Min(64, seed.Length - o)));
        if (pe.ExportDirectory is { } e && pe.TryRvaToFileOffset(e.NameTableRva, out long names) && names < seed.Length)
            targets.Add(((int)names, (int)Math.Min(64, seed.Length - names)));
        return targets.Where(t => t.Item2 > 0).ToList();
    }

    private static readonly uint[] Interesting = [0, 1, 2, 4, 8, 0x10, 0x40, 0x7F, 0x80, 0xFF, 0x100, 0x200, 0x1000, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF];

    private static byte[] Mutate(byte[] seed, List<(int Start, int Length)> targets, Random rng, out string what)
    {
        var bytes = (byte[])seed.Clone();
        var log = new List<string>();
        int count = 1 + rng.Next(8);
        for (int k = 0; k < count; k++)
        {
            var (start, length) = targets[rng.Next(targets.Count)];
            int at = start + rng.Next(length);
            switch (rng.Next(6))
            {
                case 0:
                    int bit = rng.Next(8);
                    bytes[at] ^= (byte)(1 << bit);
                    log.Add($"flip {at:X}.{bit}");
                    break;
                case 1:
                    bytes[at] = (byte)rng.Next(256);
                    log.Add($"byte {at:X}={bytes[at]:X2}");
                    break;
                case 2:
                case 3:
                    at &= ~3;
                    if (at + 4 > bytes.Length) break;
                    uint value = rng.Next(4) switch
                    {
                        0 => (uint)rng.NextInt64(0, 1L << 32),
                        1 => (uint)(start + rng.Next(length)), // points back into the same table: loops
                        2 => (uint)bytes.Length + (uint)rng.Next(-16, 16),
                        _ => Interesting[rng.Next(Interesting.Length)],
                    };
                    BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
                    log.Add($"u32 {at:X}={value:X}");
                    break;
                case 4:
                    at &= ~1;
                    if (at + 2 > bytes.Length) break;
                    ushort v16 = (ushort)Interesting[rng.Next(Interesting.Length)];
                    BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(at), v16);
                    log.Add($"u16 {at:X}={v16:X}");
                    break;
                default:
                    int len = Math.Min(rng.Next(1, 64), bytes.Length - at);
                    rng.NextBytes(bytes.AsSpan(at, len));
                    log.Add($"random {at:X}+{len}");
                    break;
            }
        }
        if (rng.Next(20) == 0)
        {
            int cut = rng.Next(0x40, bytes.Length);
            log.Add($"truncate {cut:X}");
            bytes = bytes[..cut];
        }
        what = string.Join(", ", log);
        return bytes;
    }

    private static void InterlockedMax(ref double target, double value)
    {
        double current;
        while (value > (current = Volatile.Read(ref target)) && Interlocked.CompareExchange(ref target, value, current) != current) { }
    }

    private static void InterlockedMax(ref long target, long value)
    {
        long current;
        while (value > (current = Volatile.Read(ref target)) && Interlocked.CompareExchange(ref target, value, current) != current) { }
    }
}
