namespace Corvus.Tests;

/// <summary>
/// Seeded mutation of a small seed file for readers that must never throw: bytes overwritten, flipped, truncated or
/// duplicated. A failure names the iteration that reproduces it.
/// </summary>
internal static class FormatFuzz
{
    private static readonly bool Full = Environment.GetEnvironmentVariable("CORVUS_ALL_TESTS") == "1";

    /// <summary>The least iterations of an entry in the full set.</summary>
    public const int FullFloor = 200;

    /// <summary>The least iterations of an entry in the quick set.</summary>
    public const int QuickFloor = 25;

    /// <summary>
    /// The iterations an entry runs: in the full set (full.runsettings) all it
    /// asks for and at least <see cref="FullFloor"/>; in the quick set a tenth,
    /// at least <see cref="QuickFloor"/> and never more than it asks for.
    /// </summary>
    public static int Iterations(int asked, bool full) => full ? Math.Max(asked, FullFloor) : Math.Min(asked, Math.Max(QuickFloor, asked / 10));

    public static List<string> Run(byte[] seed, Action<byte[]> read, int iterations, int baseSeed = 20261011)
    {
        iterations = Iterations(iterations, Full);
        var failures = new List<string>();
        for (int i = 0; i < iterations; i++)
        {
            var rng = new Random(unchecked(baseSeed * 1_000_003 + i));
            var bytes = Mutate(seed, rng);
            var cpu = ThreadCpuClock.Now();
            try { read(bytes); }
            catch (Exception ex) { failures.Add($"iteration {i}: {ex.GetType().Name}: {ex.Message} (in {Where(ex)})"); }
            // A few ms each; the bound is CPU time, so a starved machine does not trip it.
            if (ThreadCpuClock.Now() - cpu is var took && took > TimeSpan.FromSeconds(2)) failures.Add($"iteration {i}: took {took.TotalSeconds:0.0} s of CPU");
        }
        return failures;
    }

    /// <summary>Where an exception was thrown: the pattern for a regex timeout, whose throwing method is the regex runner.</summary>
    private static string Where(Exception ex) => ex is System.Text.RegularExpressions.RegexMatchTimeoutException t
        ? $"the regex '{t.Pattern}' ({t.MatchTimeout.TotalMilliseconds:0} ms limit) on {t.Input.Length:N0} chars"
        : $"{ex.TargetSite?.DeclaringType?.FullName}.{ex.TargetSite?.Name}";

    private static byte[] Mutate(byte[] seed, Random rng)
    {
        var b = (byte[])seed.Clone();
        switch (rng.Next(4))
        {
            case 0: // a few random bytes
                for (int n = rng.Next(1, 6); n > 0 && b.Length > 0; n--) b[rng.Next(b.Length)] = (byte)rng.Next(256);
                break;
            case 1: // an extreme 32-bit value at a 4-aligned position (sizes, counts, offsets)
                if (b.Length >= 4)
                {
                    int at = rng.Next(b.Length / 4) * 4;
                    uint[] extremes = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0xFFFF, (uint)rng.Next()];
                    BitConverter.GetBytes(extremes[rng.Next(extremes.Length)]).CopyTo(b, at);
                }
                break;
            case 2: // truncation
                Array.Resize(ref b, rng.Next(b.Length + 1));
                break;
            default: // a block copied over another place
                if (b.Length > 8)
                {
                    int len = rng.Next(1, Math.Min(64, b.Length / 2));
                    Array.Copy(seed, rng.Next(seed.Length - len), b, rng.Next(b.Length - len), len);
                }
                break;
        }
        return b;
    }
}
