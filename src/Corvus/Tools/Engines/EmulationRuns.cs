using System.Collections.Concurrent;
using Corvus.Core;
using Corvus.Native.Emulation;

namespace Corvus.Tools;

/// <summary>Resumable emulator runs by id; the oldest past <see cref="Kept"/> are dropped.</summary>
internal static class EmulationRuns
{
    internal const int Kept = 4;

    private static readonly ConcurrentDictionary<string, (string Image, long Order, EmulationRun Run)> Runs = new(StringComparer.Ordinal);
    private static long _order;

    /// <summary>Forgets the run <paramref name="id"/>.</summary>
    internal static void Drop(string id) => Runs.TryRemove(id, out _);

    /// <summary>Keeps <paramref name="run"/> for <paramref name="image"/> and returns its id.</summary>
    internal static string Keep(string image, EmulationRun run, string? id = null)
    {
        id ??= "emu-" + Guid.NewGuid().ToString("N")[..8];
        Runs[id] = (image, Interlocked.Increment(ref _order), run);
        while (Runs.Count > Kept && Runs.OrderBy(r => r.Value.Order).First().Key is { } oldest) Runs.TryRemove(oldest, out _);
        return id;
    }

    /// <summary>Returns the kept run <paramref name="id"/> of <paramref name="image"/>; throws NotFound otherwise.</summary>
    internal static EmulationRun Find(string image, string id) =>
        Runs.TryGetValue(id, out var kept) && kept.Image == image
            ? kept.Run
            : throw new ToolError(ErrorCode.NotFound, $"No stopped run '{id}' for {image}; only the last {Kept} runs a budget stopped are kept.",
                "start the run again without resume");
}
