namespace Corvus.Fuzz;

/// <summary>The smallest input found that fails the same way, and how the search ended.</summary>
public sealed record Minimized(byte[] Bytes, int Runs, bool Capped);

/// <summary>Reduces a failing input to a fixture.</summary>
public static class Minimizer
{
    /// <summary>
    /// Removes ever smaller chunks of <paramref name="input"/> while <paramref name="target"/> keeps failing with
    /// <paramref name="signature"/>, then zeroes the bytes that remain. Stops at <paramref name="maxRuns"/> reads and
    /// reports <see cref="Minimized.Capped"/>; the bytes returned fail whenever the input did.
    /// </summary>
    public static Minimized Reduce(FuzzTarget target, byte[] input, string signature, int maxRuns, TimeSpan timeout)
    {
        int runs = 0;
        bool Fails(byte[] candidate)
        {
            runs++;
            return FuzzTargets.Probe(target, candidate, timeout)?.Signature == signature;
        }
        var best = input;
        for (int chunk = Math.Max(1, best.Length / 2); chunk >= 1; chunk /= 2)
        {
            for (int at = 0; at < best.Length;)
            {
                if (runs >= maxRuns) return new Minimized(best, runs, true);
                int cut = Math.Min(chunk, best.Length - at);
                var smaller = new byte[best.Length - cut];
                best.AsSpan(0, at).CopyTo(smaller);
                best.AsSpan(at + cut).CopyTo(smaller.AsSpan(at));
                if (Fails(smaller)) best = smaller;
                else at += chunk;
            }
            if (chunk == 1) break;
        }
        for (int at = 0; at < best.Length; at++)
        {
            if (best[at] == 0) continue;
            if (runs >= maxRuns) return new Minimized(best, runs, true);
            var zeroed = (byte[])best.Clone();
            zeroed[at] = 0;
            if (Fails(zeroed)) best = zeroed;
        }
        return new Minimized(best, runs, false);
    }
}
