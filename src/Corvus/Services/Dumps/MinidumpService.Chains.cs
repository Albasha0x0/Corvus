using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Services;

public sealed partial class MinidumpService
{
    /// <summary>Text appended after a transfer target in a change description; empty when the target is not a stub or adds nothing.</summary>
    internal static string ChainText(IProcessMemory memory, ExportMap exports, ulong target, NativeArch machine)
    {
        var chain = StubChains.Follow(memory, target, machine, exports);
        if (chain.Hops.Count == 0) return "";

        string hops = chain.Hops.Count == 1 ? "1 hop" : $"{chain.Hops.Count} hops";
        return chain.End switch
        {
            "final" when chain.Address is { } end => $", then {EndName(memory, exports, end)} ({hops})",
            "unreadable" when chain.Address is { } at => $", then unreadable at 0x{at:X}",
            "loop" => ", then a loop",
            "limit" => $", then {hops}, limit",
            _ => $", then unknown ({chain.Detail ?? chain.End})",
        };
    }

    private static string EndName(IProcessMemory memory, ExportMap exports, ulong address)
    {
        if (exports.NameAt(address) is { } named) return named;
        if (memory.ModuleAt(address) is { } m) return $"{m.FileName}+0x{address - m.Base:X}";
        return memory.RegionAt(address) != null ? $"unbacked 0x{address:X}" : $"0x{address:X}";
    }
}
