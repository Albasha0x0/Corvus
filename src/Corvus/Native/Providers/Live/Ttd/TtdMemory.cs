using Corvus.Native.Dump;
using Corvus.Native.Pe;

namespace Corvus.Native.Providers.Live.Ttd;

/// <summary>A recording's memory at the cursor for the stack walker; module images come from disk when headers match, since TTD keeps only touched pages.</summary>
internal sealed class TtdMemory(TtdReplay replay) : IProcessMemory
{
    private readonly Dictionary<ulong, PeFile?> _images = [];

    public NativeArch Arch => NativeArch.X64;
    public bool Is64Bit => true;
    public string Identity => $"ttd|{replay.ProcessId}|{replay.Position}";
    public IReadOnlyList<DumpModule> Modules { get; } = [.. replay.Modules.GroupBy(m => m.Base).Select(g => g.First()).OrderBy(m => m.Base)
        .Select(m => new DumpModule(m.Base, (uint)Math.Min(m.Size, uint.MaxValue), m.Checksum, m.Timestamp, m.Path, null, null, null))];
    public IReadOnlyList<DumpUnloadedModule> UnloadedModules => [];

    public int ReadMemory(ulong address, Span<byte> destination)
    {
        var bytes = replay.Read(address, destination.Length);
        bytes.CopyTo(destination);
        return bytes.Length;
    }

    public DumpModule? ModuleAt(ulong address) => ProcessMemoryExtensions.ModuleAt(Modules, address);

    public DumpMemoryRegion? RegionAt(ulong address) => null;

    public ulong ReadableExtent(ulong start, ulong size) => size;

    /// <summary>The frames of the current thread from its registers, at most <paramref name="max"/>; the stack walker's x64 unwind.</summary>
    public IReadOnlyList<ulong> Frames(Dictionary<string, ulong> registers, int max)
    {
        var context = new DumpContext(NativeArch.X64) { Ip = registers["rip"], Flags = (uint)registers["rflags"] };
        string[] names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
        for (int i = 0; i < names.Length; i++) context.Gpr[i] = registers[names[i]];
        var stackHigh = replay.ReadU64(replay.TebAddress + 8) is var high && high > context.Sp ? high : context.Sp + 0x100000;
        var walk = new StackWalker(this, Image).Walk(context, context.Sp, stackHigh, max);
        return [.. walk.Frames.Select(f => f.Ip)];
    }

    private PeFile? Image(DumpModule module)
    {
        if (_images.TryGetValue(module.Base, out var cached)) return cached;
        PeFile? image = null;
        try
        {
            image = File.Exists(module.Path) && DumpImages.Check(module.Path, module).Matches ? PeFile.Open(module.Path) : DumpImages.FromMemory(this, module, out _);
        }
        catch (Exception e) when (e is Core.ToolError or IOException or UnauthorizedAccessException) { }
        return _images[module.Base] = image;
    }
}
