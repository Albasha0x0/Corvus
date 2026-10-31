using System.Text.Json.Nodes;
using Corvus.Native.Calls;
using Corvus.Native.Code;

namespace Corvus.Native.Emulation;

/// <summary>The state of one built-in emulator run, continued by Resume.</summary>
internal sealed class EmulationRun(INativeImage image, ulong imageBase, NativeCodeIndex? index, IEmulatorCpu cpu, EmulatorMemory mem, EmulatorHeap heap,
    Dictionary<ulong, NativeImport> byAddress, ulong sentinel, ulong regionBase, ulong stackTop, IReadOnlyList<string> shown, List<ulong> before,
    JsonArray scratchOut, HashSet<ulong> stops, List<(string Key, string Value)> stubs, string? anyStub, int traceMax, ulong start, JsonArray? reads)
{
    internal INativeImage Image { get; } = image;
    internal ulong ImageBase { get; } = imageBase;
    internal NativeCodeIndex? Index { get; } = index;
    internal IEmulatorCpu Cpu { get; } = cpu;
    internal EmulatorMemory Mem { get; } = mem;
    internal EmulatorHeap Heap { get; } = heap;
    internal Dictionary<ulong, NativeImport> ByAddress { get; } = byAddress;
    internal ulong Sentinel { get; } = sentinel;
    internal ulong RegionBase { get; } = regionBase;
    internal ulong StackTop { get; } = stackTop;
    internal IReadOnlyList<string> Shown { get; } = shown;
    internal List<ulong> Before { get; } = before;
    internal JsonArray ScratchOut { get; } = scratchOut;
    internal HashSet<ulong> Stops { get; } = stops;
    internal List<(string Key, string Value)> Stubs { get; } = stubs;
    internal string? AnyStub { get; } = anyStub;
    internal int TraceMax { get; } = traceMax;
    internal ulong Start { get; } = start;
    internal JsonArray? Reads { get; } = reads;
    internal Queue<(ulong, string)> Trace { get; } = new();
    internal JsonArray Calls { get; } = [];
    internal long Executed { get; set; }
    internal int CallCount { get; set; }
    internal ulong LastSite { get; set; } = start;
    internal TimeSpan Elapsed { get; set; }

    /// <summary>True when the last stop was a budget or a cancel, so the run can continue.</summary>
    internal bool Resumable { get; set; }
}
