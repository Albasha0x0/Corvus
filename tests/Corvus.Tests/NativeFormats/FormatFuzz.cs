using System.Collections.Concurrent;
using System.Diagnostics;
using Corvus.Core;
using Corvus.Native;

namespace Corvus.Tests.NativeFormats;

/// <summary>Seeded byte mutation for the ELF and Mach-O readers: construction may refuse a file, nothing after it may throw.</summary>
internal static class FormatFuzz
{
    private static readonly TimeSpan TimeBound = TimeSpan.FromSeconds(10);

    /// <summary>Failures as "iteration (seed): exception"; <paramref name="parse"/> builds and touches one image.</summary>
    public static List<string> Run(IReadOnlyList<byte[]> seeds, int iterations, int seed, Action<byte[]> parse)
    {
        var failures = new ConcurrentBag<string>();
        Parallel.For(0, iterations, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, i =>
        {
            int which = i % seeds.Count;
            var rng = new Random(unchecked(seed * 1_000_003 + i));
            var bytes = (byte[])seeds[which].Clone();
            int edits = rng.Next(1, 9);
            for (int e = 0; e < edits; e++)
            {
                // Mostly the headers and tables near the start, sometimes anywhere.
                int span = rng.Next(4) == 0 ? bytes.Length : Math.Min(bytes.Length, 0x1000);
                int at = rng.Next(span);
                switch (rng.Next(4))
                {
                    case 0: bytes[at] = (byte)rng.Next(256); break;
                    case 1: bytes[at] ^= (byte)(1 << rng.Next(8)); break;
                    case 2: bytes[at] = rng.Next(2) == 0 ? (byte)0 : (byte)0xFF; break;
                    default:
                        for (int k = 0; k < 4 && at + k < bytes.Length; k++) bytes[at + k] = (byte)rng.Next(256);
                        break;
                }
            }
            var timer = Stopwatch.StartNew();
            try { parse(bytes); }
            catch (ToolError ex) when (ex.Code is ErrorCode.MalformedInput or ErrorCode.LimitExceeded) { }
            catch (Exception ex) { failures.Add($"iteration {i} (seed {which}): {ex}"); }
            if (timer.Elapsed > TimeBound) failures.Add($"iteration {i} (seed {which}): took {timer.Elapsed.TotalSeconds:0.0} s");
        });
        return [.. failures];
    }

    /// <summary>Reads every member of the image contract, then <paramref name="extra"/>; an "internal error" issue fails.</summary>
    public static void Touch<T>(T image, Action<T> extra) where T : INativeImage
    {
        _ = image.Sections.Count + image.Imports.Count + image.Exports.Count + image.RelocationRvas.Count + image.Symbols.Count
            + image.DeclaredFunctions.Count + image.Dependencies.Count + image.EncryptedRanges.Count + (image.BuildId?.Length ?? 0);
        _ = (image.Arch, image.Is64Bit, image.IsDll, image.ImageBase, image.EntryPointRva, image.SizeOfImage, image.MachineName);
        var buffer = new byte[256];
        foreach (var s in image.Sections.Take(64))
        {
            image.Read(s.Rva, buffer);
            image.TryRvaToFileOffset(s.Rva, out _);
            image.SectionAt(s.Rva);
        }
        foreach (uint rva in new uint[] { 0, image.EntryPointRva, image.SizeOfImage - 1, uint.MaxValue - 8 }) image.Read(rva, buffer);
        image.TryFileOffsetToRva(0, out _);
        extra(image);
        if (image.Issues.FirstOrDefault(x => x.Message.StartsWith("internal error", StringComparison.Ordinal)) is { } bug)
            throw new InvalidOperationException($"{bug.Area}: {bug.Message}");
    }
}
