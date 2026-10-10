using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Pe;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Mutation fuzzing through the tools: real and synthetic images with headers, the section table, directories, code,
/// .pdata, import/export tables, resources and RTTI structures mutated (seeded), each loaded through load_assembly and
/// given to every native tool. Typed errors are fine; an unexpected exception, an unclassified error, a hang or a
/// result over the response budget fails. NDM_NATIVE_TOOL_FUZZ_ITERATIONS sets the count (default 2500, about a minute on 16 cores),
/// NDM_NATIVE_TOOL_FUZZ_SEED the base seed; NDM_NATIVE_TOOL_FUZZ_DUMP a folder that receives the failing inputs.
/// </summary>
[Trait("Speed", "Slow")]
public class NativeToolFuzzTests(ITestOutputHelper output)
{
    [Fact]
    public async Task MutatedImagesThroughEveryTool()
    {
        int iterations = int.TryParse(Environment.GetEnvironmentVariable("NDM_NATIVE_TOOL_FUZZ_ITERATIONS"), out var n) ? n : 2500;
        int seed = int.TryParse(Environment.GetEnvironmentVariable("NDM_NATIVE_TOOL_FUZZ_SEED"), out var s) ? s : 20261010;
        var dump = Environment.GetEnvironmentVariable("NDM_NATIVE_TOOL_FUZZ_DUMP");
        var seeds = Seeds();
        var targets = seeds.Select(x => ToolFuzzer.Targets(x.Bytes)).ToArray();
        using var dir = new TempDir();
        var failures = new ConcurrentBag<string>();
        var slowest = new ConcurrentBag<(TimeSpan Elapsed, string What)>();
        long calls = 0, typed = 0, notLoaded = 0;
        int next = -1;
        var clock = Stopwatch.StartNew();
        int workers = Math.Clamp(Environment.ProcessorCount - 2, 2, 16);
        await Task.WhenAll(Enumerable.Range(0, workers).Select(w => Task.Run(async () =>
        {
            using var harness = new NativeToolHarness(backgroundIndexing: w % 2 == 0) { Lenient = true, CallLimit = TimeSpan.FromSeconds(30) };
            int i;
            while ((i = Interlocked.Increment(ref next)) < iterations)
            {
                int which = i % seeds.Count;
                var rng = new Random(unchecked(seed * 1_000_003 + i));
                var bytes = ToolFuzzer.Mutate(seeds[which].Bytes, targets[which], rng, out var what);
                var path = dir.File($"fuzz{i}.dll");
                File.WriteAllBytes(path, bytes);
                int before = harness.Calls.Count;
                var sw = Stopwatch.StartNew();
                await harness.Exercise(path, indexLimit: TimeSpan.FromSeconds(30));
                // An image the workspace kept after a failed unload would leak into the next iteration.
                foreach (var left in harness.Workspace.Read(() => harness.Workspace.Natives)) harness.Workspace.UnloadNative(left);
                slowest.Add((sw.Elapsed, $"iteration {i} ({seeds[which].Name}; {what})"));
                var mine = harness.Calls.Skip(before).ToList();
                Interlocked.Add(ref calls, mine.Count);
                Interlocked.Add(ref typed, mine.Count(c => c.Error != null));
                if (mine.Count == 1) Interlocked.Increment(ref notLoaded);
                var bad = mine.Where(c => c.Failed || c.Chars > NativeToolHarness.MaxChars).ToList();
                foreach (var c in bad) failures.Add($"iteration {i} ({seeds[which].Name}; {what}): {c}");
                if (bad.Count > 0 && dump is { Length: > 0 }) File.Copy(path, Path.Combine(dump, $"toolfuzz-{seed}-{i}.dll"), true);
                try { File.Delete(path); } catch (IOException) { }
            }
        })));
        output.WriteLine($"{iterations} iterations over {seeds.Count} seeds, {workers} workers, {clock.Elapsed.TotalSeconds:0.0} s; {calls} tool calls, " +
                         $"{typed} typed errors, {notLoaded} images rejected at load");
        foreach (var x in slowest.OrderByDescending(x => x.Elapsed).Take(5)) output.WriteLine($"slow: {x.Elapsed.TotalSeconds:0.0} s {x.What}");
        foreach (var (name, _) in seeds) output.WriteLine("seed: " + name);
        foreach (var f in failures.Take(30)) output.WriteLine("FAIL " + f);
        Assert.True(failures.IsEmpty, $"{failures.Count} failures; first: {failures.FirstOrDefault()}");
    }

    /// <summary>The synthetic kitchen-sink images and small real images: x64 and x86 code, C++ with RTTI, a driver, resources only.</summary>
    internal static List<(string Name, byte[] Bytes)> Seeds()
    {
        var seeds = new List<(string, byte[])> { ("kitchen sink x64", NativePeTests.KitchenSink(true)), ("kitchen sink x86", NativePeTests.KitchenSink(false)) };
        if (!OperatingSystem.IsWindows()) return seeds;
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string[] fixedSeeds =
        [
            Path.Combine(windows, "System32", "drivers", "null.sys"),
            Path.Combine(windows, "System32", "notepad.exe"),
            Path.Combine(windows, "SysWOW64", "cmd.exe"),
            Path.Combine(windows, "System32", "en-US", "user32.dll.mui"),
        ];
        foreach (var f in fixedSeeds.Where(File.Exists)) seeds.Add((f, File.ReadAllBytes(f)));
        // Small C++ DLLs with RTTI, one per architecture.
        foreach (var system in new[] { "System32", "SysWOW64" })
        {
            var dir = Path.Combine(windows, system);
            if (!Directory.Exists(dir)) continue;
            var rtti = Directory.EnumerateFiles(dir, "*.dll").Order(StringComparer.OrdinalIgnoreCase)
                .Where(f => new FileInfo(f).Length is > 60_000 and < 250_000)
                .FirstOrDefault(f => NativeToolHarness.IsNativePe(f) && File.ReadAllBytes(f).AsSpan().IndexOf(".?AV"u8) >= 0);
            if (rtti != null) seeds.Add((rtti, File.ReadAllBytes(rtti)));
        }
        return seeds;
    }
}

/// <summary>Seeded mutation of PE images aimed at what the native tools read: headers, directories, code, .pdata, resources, RTTI.</summary>
internal static class ToolFuzzer
{
    public static List<(int Start, int Length, string Area)> Targets(byte[] seed)
    {
        var pe = PeFile.FromBytes(seed);
        var targets = new List<(int, int, string)> { (0, (int)Math.Min(seed.Length, Math.Max(pe.Optional.SizeOfHeaders, 0x200)), "headers") };
        void Add(uint rva, int length, string area)
        {
            if (pe.TryRvaToFileOffset(rva, out long o) && o < seed.Length) targets.Add(((int)o, (int)Math.Min(length, seed.Length - o), area));
        }
        foreach (var dir in pe.DataDirectories.Where(d => d.IsPresent && d.Index != PeDirectory.Security))
            Add(dir.Rva, (int)Math.Min(dir.Size, dir.Index is PeDirectory.Exception or PeDirectory.Resource ? 0x4000u : 0x400u), $"directory {dir.Index}");
        foreach (var m in pe.ImportModules.Take(4)) Add(m.NameTableRva, 64, "import names");
        if (pe.ExportDirectory is { } e) { Add(e.NameTableRva, 64, "export names"); Add(e.FunctionTableRva, 64, "export addresses"); }
        if (pe.EntryPointRva != 0) Add(pe.EntryPointRva, 0x200, "entry code");
        foreach (var f in pe.RuntimeFunctions.Where((_, i) => i % Math.Max(1, pe.RuntimeFunctions.Count / 8) == 0).Take(8)) Add(f.BeginRva, 64, "function code");
        foreach (var s in pe.Sections.Where(s => s.IsExecutable)) Add(s.Rva, (int)Math.Min(s.RawSize, 0x10000), "code section");
        foreach (var r in pe.Resources.Take(4)) Add(r.Rva, (int)Math.Min(r.Size, 0x400), "resource data");
        // RTTI: type descriptor names and what precedes them (vftable pointer, spare), and locators referring to them.
        var bytes = seed.AsSpan();
        int at = 0, found = 0;
        while (found < 6 && at < bytes.Length && bytes[at..].IndexOf(".?AV"u8) is var k and >= 0)
        {
            int p = at + k;
            targets.Add((Math.Max(0, p - 16), Math.Min(64, seed.Length - Math.Max(0, p - 16)), "rtti"));
            at = p + 4;
            found++;
        }
        return targets.Where(t => t.Item2 > 0).ToList();
    }

    private static readonly uint[] Interesting = [0, 1, 2, 4, 8, 0x10, 0x40, 0x7F, 0x80, 0xFF, 0x100, 0x1000, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF];

    /// <summary>Byte flips, random bytes, interesting and self-referencing 32-bit values, random runs; sometimes truncation.</summary>
    public static byte[] Mutate(byte[] seed, List<(int Start, int Length, string Area)> targets, Random rng, out string what)
    {
        var bytes = (byte[])seed.Clone();
        var log = new List<string>();
        int count = 1 + rng.Next(6);
        for (int k = 0; k < count; k++)
        {
            var (start, length, area) = targets[rng.Next(targets.Count)];
            int at = start + rng.Next(length);
            switch (rng.Next(6))
            {
                case 0:
                    int bit = rng.Next(8);
                    bytes[at] ^= (byte)(1 << bit);
                    log.Add($"{area}: flip {at:X}.{bit}");
                    break;
                case 1:
                    bytes[at] = (byte)rng.Next(256);
                    log.Add($"{area}: byte {at:X}={bytes[at]:X2}");
                    break;
                case 2:
                case 3:
                    at &= ~3;
                    if (at + 4 > bytes.Length) break;
                    uint value = rng.Next(4) switch
                    {
                        0 => (uint)rng.NextInt64(0, 1L << 32),
                        1 => (uint)(start + rng.Next(length)),
                        2 => (uint)bytes.Length + (uint)rng.Next(-16, 16),
                        _ => Interesting[rng.Next(Interesting.Length)],
                    };
                    BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
                    log.Add($"{area}: u32 {at:X}={value:X}");
                    break;
                case 4:
                    // Code-like garbage: a run of one byte (0xFF, 0xCC, 0x00, prefixes) or of random bytes.
                    int run = Math.Min(rng.Next(1, 256), bytes.Length - at);
                    byte fill = (byte)(rng.Next(3) switch { 0 => 0xFF, 1 => 0x66, _ => rng.Next(256) });
                    bytes.AsSpan(at, run).Fill(fill);
                    log.Add($"{area}: fill {at:X}+{run}={fill:X2}");
                    break;
                default:
                    int len = Math.Min(rng.Next(1, 64), bytes.Length - at);
                    rng.NextBytes(bytes.AsSpan(at, len));
                    log.Add($"{area}: random {at:X}+{len}");
                    break;
            }
        }
        if (rng.Next(25) == 0)
        {
            int cut = rng.Next(0x40, bytes.Length);
            log.Add($"truncate {cut:X}");
            bytes = bytes[..cut];
        }
        what = string.Join(", ", log);
        return bytes;
    }
}
