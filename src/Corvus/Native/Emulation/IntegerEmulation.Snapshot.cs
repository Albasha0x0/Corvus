using System.IO.Compression;
using System.Text.Json.Nodes;
using Corvus.Native.Code;

namespace Corvus.Native.Emulation;

public static partial class IntegerEmulation
{
    private const string StateFile = "state.json", MemoryFile = "memory.bin";
    private const int SnapshotVersion = 1;

    /// <summary>
    /// The sha256 of the image a snapshot in <paramref name="folder"/> was saved for;
    /// null when the folder holds no state file or its state cannot be parsed.
    /// </summary>
    internal static string? SnapshotImage(string folder)
    {
        try { return JsonNode.Parse(File.ReadAllText(Path.Combine(folder, StateFile)))?["image"]?.GetValue<string>(); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidOperationException) { return null; }
    }

    /// <summary>
    /// Saves the stopped <paramref name="run"/> of the image with <paramref name="sha256"/>
    /// to <paramref name="folder"/>: registers, changed pages, counters and inputs.
    /// </summary>
    internal static void SaveSnapshot(EmulationRun run, string folder, string sha256)
    {
        Directory.CreateDirectory(folder);
        using (var file = File.Create(Path.Combine(folder, MemoryFile)))
        using (var packed = new DeflateStream(file, CompressionLevel.Fastest))
        using (var w = new BinaryWriter(packed))
        {
            run.Cpu.Save(w);
            run.Heap.Save(w);
            run.Mem.Save(w);
        }
        var state = new JsonObject
        {
            ["version"] = SnapshotVersion, ["image"] = sha256, ["language"] = run.Cpu.Language, ["imageBase"] = Hex(run.ImageBase),
            ["start"] = Hex(run.Start), ["traceMax"] = run.TraceMax, ["executed"] = run.Executed, ["callCount"] = run.CallCount,
            ["lastSite"] = Hex(run.LastSite), ["afterCall"] = run.AfterCall, ["elapsed"] = run.Elapsed.TotalSeconds,
            ["stops"] = new JsonArray([.. run.Stops.Order().Select(s => (JsonNode)Hex(s))]),
            ["stubs"] = new JsonArray([.. run.Stubs.Select(s => (JsonNode)new JsonArray(s.Key, s.Value))]),
            ["before"] = new JsonArray([.. run.Before.Select(b => (JsonNode)Hex(b))]),
            ["reads"] = run.Reads?.DeepClone(), ["scratch"] = run.ScratchOut.DeepClone(), ["calls"] = run.Calls.DeepClone(),
            ["trace"] = new JsonArray([.. run.Trace.Select(t => (JsonNode)new JsonArray(Hex(t.Item1), t.Item2))]),
        };
        // State is written last and moved into place, so its presence marks a
        // complete save.
        var path = Path.Combine(folder, StateFile);
        File.WriteAllText(path + ".tmp", state.ToJsonString());
        File.Move(path + ".tmp", path, overwrite: true);
    }

    /// <summary>
    /// Rebuilds a run saved by <see cref="SaveSnapshot"/> for the same image;
    /// throws when the files are damaged or from another version.
    /// </summary>
    internal static EmulationRun LoadSnapshot(string folder, INativeImage image, ulong imageBase, NativeCodeIndex? index)
    {
        try { return Load(folder, image, imageBase, index); }
        catch (Exception e) when (e is NullReferenceException or InvalidCastException or KeyNotFoundException or ArgumentException)
        {
            throw new InvalidDataException("the saved state is incomplete", e);
        }
    }

    private static EmulationRun Load(string folder, INativeImage image, ulong imageBase, NativeCodeIndex? index)
    {
        var state = JsonNode.Parse(File.ReadAllText(Path.Combine(folder, StateFile)))!;
        if (state["version"]?.GetValue<int>() != SnapshotVersion || state["imageBase"]?.GetValue<string>() is not { } savedBase || Va(savedBase) != imageBase)
            throw new InvalidDataException("the saved run is from another version or load address");
        var cpu = Cpu(image);
        var (mem, heap, byAddress, sentinel, regionBase) = Layout(image, imageBase, cpu);
        using (var file = File.OpenRead(Path.Combine(folder, MemoryFile)))
        using (var packed = new DeflateStream(file, CompressionMode.Decompress))
        using (var r = new BinaryReader(packed))
        {
            cpu.Load(r);
            heap.Load(r);
            mem.Load(r);
        }
        JsonArray Items(string name) => (JsonArray)state[name]!;
        var stubs = Items("stubs").Select(s => (Key: s![0]!.GetValue<string>(), Value: s[1]!.GetValue<string>())).ToList();
        var run = new EmulationRun(image, imageBase, index, cpu, mem, heap, byAddress, sentinel, regionBase, regionBase + StackSize, cpu.MainRegisters,
            [.. Items("before").Select(b => Va(b!.GetValue<string>()))], (JsonArray)Items("scratch").DeepClone(),
            [.. Items("stops").Select(s => Va(s!.GetValue<string>()))],
            stubs, stubs.FirstOrDefault(s => s.Key == "*").Value,
            state["traceMax"]!.GetValue<int>(), Va(state["start"]!.GetValue<string>()), state["reads"] as JsonArray is { } reads ? (JsonArray)reads.DeepClone() : null)
        {
            Executed = state["executed"]!.GetValue<long>(),
            CallCount = state["callCount"]!.GetValue<int>(),
            LastSite = Va(state["lastSite"]!.GetValue<string>()),
            AfterCall = state["afterCall"]!.GetValue<bool>(),
            Elapsed = TimeSpan.FromSeconds(state["elapsed"]!.GetValue<double>()),
            Resumable = true,
        };
        foreach (var t in Items("trace")) run.Trace.Enqueue((Va(t![0]!.GetValue<string>()), t[1]!.GetValue<string>()));
        foreach (var row in Items("calls"))
        {
            var copy = (JsonObject)row!.DeepClone();
            run.Calls.Add(copy);
            run.CallRows[(Va(copy["site"]!.GetValue<string>()), Va(copy["target"]!.GetValue<string>()), copy["name"]?.GetValue<string>(), copy["action"]!.GetValue<string>(),
                copy["value"]?.GetValue<string>() is { } v ? Va(v) : null)] = copy;
        }
        return run;
    }
}
