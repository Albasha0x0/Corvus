using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Code;
using Corvus.Native.Emulation;

namespace Corvus.Tools;

/// <summary>
/// Resumable emulator runs by id, held and saved under the data folder;
/// the oldest past <see cref="Kept"/> are dropped.
/// </summary>
internal static partial class EmulationRuns
{
    internal const int Kept = 4;

    private static readonly ConcurrentDictionary<string, (string Image, long Order, EmulationRun Run)> Runs = new(StringComparer.Ordinal);
    private static long _order;
    private static string? _folder;

    [GeneratedRegex("^emu-[0-9a-f]{8}$")]
    private static partial Regex IdShape();

    /// <summary>
    /// The folder that holds the saved runs, one folder per run id;
    /// tests point it elsewhere and reset it with null.
    /// </summary>
    internal static string Folder { get => _folder ?? Path.Combine(NativeEmulationTools.RunsRoot, "stopped"); set => _folder = value; }

    /// <summary>Points <see cref="Folder"/> back at the data folder.</summary>
    internal static void ResetFolder() => _folder = null;

    /// <summary>Forgets the run <paramref name="id"/>, held and saved.</summary>
    internal static void Drop(string id)
    {
        Runs.TryRemove(id, out _);
        Delete(id);
    }

    /// <summary>Forgets the runs held by this process, as a restart does; the saved runs stay.</summary>
    internal static void ReleaseHeld() => Runs.Clear();

    /// <summary>
    /// Keeps <paramref name="run"/> of the image with <paramref name="sha256"/> and returns its id.
    /// Saving is best-effort: a failed save leaves the run held only.
    /// </summary>
    internal static string Keep(string image, string sha256, EmulationRun run, string? id = null)
    {
        id ??= "emu-" + Guid.NewGuid().ToString("N")[..8];
        Runs[id] = (image, Interlocked.Increment(ref _order), run);
        while (Runs.Count > Kept && Runs.OrderBy(r => r.Value.Order).First().Key is { } oldest) Runs.TryRemove(oldest, out _);
        try
        {
            IntegerEmulation.SaveSnapshot(run, Path.Combine(Folder, id), sha256);
            foreach (var old in Directory.GetDirectories(Folder).Where(d => Path.GetFileName(d) != id)
                         .OrderByDescending(Directory.GetLastWriteTimeUtc).Skip(Kept - 1))
                Directory.Delete(old, recursive: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        return id;
    }

    private static void Delete(string id)
    {
        if (!IdShape().IsMatch(id)) return;
        try { Directory.Delete(Path.Combine(Folder, id), recursive: true); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>
    /// Returns the kept run <paramref name="id"/> of <paramref name="image"/>;
    /// throws NotFound otherwise.
    /// </summary>
    internal static EmulationRun Find(string image, string id) => Held(image, id) ?? throw NotKept(id, image);

    /// <summary>
    /// Returns the run <paramref name="id"/> of <paramref name="image"/> held by this process;
    /// null when it is not.
    /// </summary>
    internal static EmulationRun? Held(string image, string id) => Runs.TryGetValue(id, out var kept) && kept.Image == image ? kept.Run : null;

    private static ToolError NotKept(string id, string image) =>
        new(ErrorCode.NotFound, $"No stopped run '{id}' for {image}; only the last {Kept} runs a budget stopped are kept.", "start the run again without resume");

    /// <summary>
    /// The folder of the saved run <paramref name="id"/> for <paramref name="native"/>; NotFound when none is saved,
    /// MalformedInput when the folder cannot be read (it is removed),
    /// Conflict when it was saved for another build of the image.
    /// </summary>
    internal static string Saved(LoadedNative native, string id, string address)
    {
        var folder = Path.Combine(Folder, id);
        if (!IdShape().IsMatch(id) || !Directory.Exists(folder)) throw NotKept(id, native.Id);
        if (IntegerEmulation.SnapshotImage(folder) is not { } sha)
        {
            Drop(id);
            throw Unreadable(id, native.Id, address, "its state file is missing or damaged");
        }
        return sha == native.OriginalSha256
            ? folder
            : throw new ToolError(ErrorCode.Conflict, $"The stopped run '{id}' was saved for another build than {native.Id}; its state does not apply.",
                $"emulate_native image={native.Id} address={address} starts a new run");
    }

    /// <summary>
    /// Loads the saved run in <paramref name="folder"/> and holds it under <paramref name="id"/>;
    /// MalformedInput when the saved files cannot be read.
    /// </summary>
    internal static EmulationRun Restore(string folder, string id, LoadedNative native, string address, NativeCodeIndex? index)
    {
        try
        {
            var run = IntegerEmulation.LoadSnapshot(folder, native.Image, native.Image.ImageBase, index);
            Runs[id] = (native.Id, Interlocked.Increment(ref _order), run);
            return run;
        }
        catch (Exception e) when (e is IOException or InvalidDataException or System.Text.Json.JsonException or InvalidOperationException or FormatException or UnauthorizedAccessException)
        {
            Drop(id);
            throw Unreadable(id, native.Id, address, e.Message);
        }
    }

    private static ToolError Unreadable(string id, string image, string address, string why) =>
        new(ErrorCode.MalformedInput, $"The saved run '{id}' cannot be read: {why}.", $"emulate_native image={image} address={address} starts a new run");
}
