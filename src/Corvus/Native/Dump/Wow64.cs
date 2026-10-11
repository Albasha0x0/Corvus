namespace Corvus.Native.Dump;

/// <summary>A WoW64 thread's 32-bit side: the x86 context WoW64 saved and the bounds of the thread's 32-bit stack.</summary>
public sealed record Wow64Thread(DumpContext Context, ulong StackLow, ulong StackHigh);

/// <summary>
/// The 32-bit side of a WoW64 process seen through a 64-bit dump. WoW64 keeps each thread's x86 context in the
/// WOW64_CPURESERVED area that 64-bit TEB TLS slot 1 points to (the CONTEXT follows a 4-byte header); the 32-bit TEB
/// follows the 64-bit one at +0x2000 and holds the 32-bit stack bounds.
/// </summary>
public static class Wow64
{
    private const ulong TlsSlots = 0x1480, CpuReservedSlot = 1, Teb32Offset = 0x2000;
    private const int ContextSize = 0x2CC;
    private const uint ContextI386 = 0x10000;

    /// <summary>A 64-bit dump of a 32-bit process: wow64cpu.dll (or wow64.dll) is loaded.</summary>
    public static bool IsWow64(IProcessMemory memory) => memory.Arch == NativeArch.X64 && memory.Modules.Any(m =>
        m.FileName.Equals("wow64cpu.dll", StringComparison.OrdinalIgnoreCase) || m.FileName.Equals("wow64.dll", StringComparison.OrdinalIgnoreCase));

    /// <summary>Where WoW64 keeps the thread's 32-bit state (WOW64_CPURESERVED), or null when the dump does not hold the TEB.</summary>
    public static ulong? CpuArea(IProcessMemory memory, ulong teb) =>
        teb != 0 && IsWow64(memory) && memory.TryReadU64(teb + TlsSlots + CpuReservedSlot * 8, out ulong cpu) && cpu != 0 ? cpu : null;

    /// <summary>The thread's 32-bit context and stack, or null when the dump does not hold them.</summary>
    public static Wow64Thread? Thread(IProcessMemory memory, ulong teb)
    {
        if (CpuArea(memory, teb) is not { } cpu) return null;
        var bytes = new byte[ContextSize];
        if (memory.ReadMemory(cpu + 4, bytes) < 0xCC) return null;
        var context = DumpContext.Parse(NativeArch.X86, bytes);
        if (context == null || (context.ContextFlags & ContextI386) == 0 || context.Ip == 0) return null;
        memory.TryReadU32(teb + Teb32Offset + 4, out uint high);
        memory.TryReadU32(teb + Teb32Offset + 8, out uint low);
        return new Wow64Thread(context, low, high);
    }

    /// <summary>The process as its 32-bit code sees it: the same memory and modules, x86 pointers.</summary>
    public static IProcessMemory View(IProcessMemory memory) => new X86View(memory);

    private sealed class X86View(IProcessMemory inner) : IProcessMemory
    {
        public NativeArch Arch => NativeArch.X86;
        public bool Is64Bit => false;
        public string Identity => inner.Identity + "|wow64";
        public IReadOnlyList<DumpModule> Modules => inner.Modules;
        public IReadOnlyList<DumpUnloadedModule> UnloadedModules => inner.UnloadedModules;
        public int ReadMemory(ulong address, Span<byte> destination) => inner.ReadMemory(address, destination);
        public DumpModule? ModuleAt(ulong address) => inner.ModuleAt(address);
        public DumpMemoryRegion? RegionAt(ulong address) => inner.RegionAt(address);
        public ulong ReadableExtent(ulong start, ulong size) => inner.ReadableExtent(start, size);
    }
}
