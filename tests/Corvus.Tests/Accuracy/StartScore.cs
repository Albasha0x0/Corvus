namespace Corvus.Tests.Accuracy;

/// <summary>An engine's function: start and the end of its main body (exclusive; null when unknown), RVAs.</summary>
public readonly record struct EngineFunction(uint Start, uint? End);

/// <summary>
/// Function-start precision / recall / F1 and extent agreement against symbol truth. Same rule as the research
/// scorer that captured the IDA and Ghidra numbers in baseline.json:
/// only engine starts in executable sections and outside PLT ranges count; a start on a truth chunk (GCC .cold part,
/// MSVC separated code or funclet) or thunk is neither a hit nor a false start; a start whose bytes up to the next
/// truth start are only alignment fill is padding (neutral). Every other engine start is a hit (truth function start)
/// or a false start. Extent: over hits with a truth size, the engine's main-body end equals the truth end (exact) or
/// is within 16 bytes of it.
/// </summary>
public sealed record StartScore(int Truth, int Engine, int Hits, int FalseStarts, int Neutral, int ExtentKnown, int ExtentExact, int Extent16)
{
    public double Precision => Hits + FalseStarts == 0 ? 1 : (double)Hits / (Hits + FalseStarts);
    public double Recall => Truth == 0 ? 1 : (double)Hits / Truth;
    public double F1 => Precision + Recall == 0 ? 0 : 2 * Precision * Recall / (Precision + Recall);
    public double ExactEnd => ExtentKnown == 0 ? 1 : (double)ExtentExact / ExtentKnown;
    public double End16 => ExtentKnown == 0 ? 1 : (double)Extent16 / ExtentKnown;

    public static StartScore Of(ElfTruth truth, IEnumerable<EngineFunction> engine, ReadOnlySpan<byte> image, Func<uint, int> fileOffset)
    {
        bool InAny(IReadOnlyList<(uint Start, uint End)> ranges, uint a) => ranges.Any(r => a >= r.Start && a < r.End);
        var functions = truth.Functions.Where(f => f.Class == TruthClass.Function && !InAny(truth.Plt, f.Start)).ToDictionary(f => f.Start);
        var neutral = truth.Functions.Where(f => f.Class != TruthClass.Function).Select(f => f.Start).ToHashSet();
        var starts = truth.Functions.Select(f => f.Start).Order().ToArray();
        int hits = 0, falseStarts = 0, neutralCount = 0, known = 0, exact = 0, near = 0, engineCount = 0;
        foreach (var e in engine)
        {
            if (!InAny(truth.Executable, e.Start) || InAny(truth.Plt, e.Start)) continue;
            engineCount++;
            if (functions.TryGetValue(e.Start, out var t))
            {
                hits++;
                if (t.Size > 0 && e.End is { } end)
                {
                    known++;
                    long diff = (long)end - (t.Start + t.Size);
                    if (diff == 0) exact++;
                    if (Math.Abs(diff) <= 16) near++;
                }
            }
            else if (neutral.Contains(e.Start) || IsPadding(truth.Arch, e.Start, starts, image, fileOffset)) neutralCount++;
            else falseStarts++;
        }
        return new StartScore(functions.Count, engineCount, hits, falseStarts, neutralCount, known, exact, near);
    }

    /// <summary>x86 / x64 alignment fill: nop forms, GCC's i386 no-op mov / lea, int3, zero (same table in score.py).</summary>
    private static readonly byte[][] X86Pad = [.. new[]
    {
        "0F1F840000000000", "0F1F8000000000", "0F1F440000", "0F1F4000", "0F1F00", "8DBC2700000000", "8DB42600000000",
        "8DB600000000", "8DBF00000000", "8D742600", "8D7600", "8D7F00", "89F6", "89FF", "6690", "90", "CC", "00",
    }.Select(Convert.FromHexString)];

    /// <summary>Bytes from <paramref name="start"/> to the next truth start are alignment fill only.</summary>
    private static bool IsPadding(string arch, uint start, uint[] truthStarts, ReadOnlySpan<byte> image, Func<uint, int> fileOffset)
    {
        int i = Array.BinarySearch(truthStarts, start);
        i = i < 0 ? ~i : i + 1;
        uint next = i < truthStarts.Length ? truthStarts[i] : start + 16;
        if (next - start > 64) return false;
        int o = fileOffset(start);
        if (o < 0 || o + (int)(next - start) > image.Length) return false;
        var bytes = image.Slice(o, (int)(next - start));
        if (arch is "x86" or "x64")
        {
            int k = 0;
            while (k < bytes.Length)
            {
                while (k < bytes.Length && bytes[k] is 0x66 or 0x2E) k++;
                if (k >= bytes.Length) break;
                int matched = 0;
                foreach (var p in X86Pad)
                    if (bytes[k..].StartsWith(p)) { matched = p.Length; break; }
                if (matched == 0) return false;
                k += matched;
            }
            return true;
        }
        int unit = arch == "arm64" ? 4 : 2;
        for (int k = 0; k + unit <= bytes.Length; k += unit)
        {
            uint w = unit == 4 ? BitConverter.ToUInt32(bytes[k..]) : BitConverter.ToUInt16(bytes[k..]);
            // ARM64 nop, the straight-line-speculation barrier after ret / br (dsb sy; isb), and Thumb fill.
            bool fill = unit == 4 ? w is 0 or 0xD503201F or 0xD5033F9F or 0xD5033FDF : w is 0 or 0xBF00 or 0x46C0 or 0xDEFE;
            if (!fill) return false;
        }
        return true;
    }
}
