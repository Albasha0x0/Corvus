using System.Collections.Concurrent;
using System.Globalization;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Elf;

namespace Corvus.Services;

/// <summary>
/// A stop's stack outside Windows, unwound from the bytes the session script sends with it: each ELF module's .eh_frame
/// CFI read from its file, else the frame pointer chain (<see cref="CoreUnwinder"/>, as dump_stack walks a core; on
/// ARM64 a stop at a function's first instruction returns through the link register first). Only the captured stack is
/// memory; the walk stops where it leaves it.
/// </summary>
internal sealed class LiveStackWalk : IProcessMemory
{
    public const int MaxFrames = 32;
    private const int MaxCachedFiles = 64;
    private static readonly ConcurrentDictionary<string, ElfFile?> Files = new(StringComparer.Ordinal);
    private readonly LiveSession _session;
    private readonly CoreArch _arch;
    private readonly Func<ulong, bool>? _atFunctionStart;
    private readonly ConcurrentDictionary<(ulong, string), CoreImage?> _images = new();
    private readonly object _gate = new();
    private ulong _sp;
    private byte[] _stack = [];
    private DumpModule[] _modules = [];

    private LiveStackWalk(LiveSession session, CoreArch arch, Func<ulong, bool>? atFunctionStart)
    {
        _session = session;
        _arch = arch;
        _atFunctionStart = atFunctionStart;
    }

    /// <summary>The walker for a session's architecture (Frida's names), or null when it has no register file here.</summary>
    public static LiveStackWalk? For(LiveSession session, Func<ulong, bool>? atFunctionStart = null) => session.Arch switch
    {
        "x64" => new(session, CoreArch.X64, atFunctionStart),
        "ia32" => new(session, CoreArch.X86, atFunctionStart),
        "arm64" => new(session, CoreArch.Arm64, atFunctionStart),
        "arm" => new(session, CoreArch.Arm, atFunctionStart),
        _ => null,
    };

    /// <summary>The frames from <paramref name="registers"/> (the stopped context) over <paramref name="stack"/> (bytes at its stack pointer).</summary>
    public WalkResult? Walk(IReadOnlyDictionary<string, string> registers, byte[] stack)
    {
        if (!registers.TryGetValue("pc", out var pc) || !registers.TryGetValue("sp", out var sp)) return null;
        var regs = new CoreRegisters(_arch);
        for (int i = 0; i < _arch.Count; i++)
            if (registers.TryGetValue(_arch.Names[i], out var v) || (Alias(_arch.Names[i]) is { } other && registers.TryGetValue(other, out v)))
                regs.Set(i, Hex(v));
        regs.Pc = Hex(pc);
        regs.Sp = Hex(sp);
        lock (_gate)
        {
            _sp = regs.Sp;
            _stack = stack;
            lock (_session.Modules)
                _modules = [.. _session.Modules.Select(m => new DumpModule(m.Base, (uint)Math.Min(m.Size, uint.MaxValue), 0, 0, m.Path, null, null, null)).OrderBy(m => m.Base)];
            return new CoreUnwinder(this, _arch, ImageAt, _atFunctionStart).Walk(regs, _sp, _sp + (ulong)stack.Length, MaxFrames);
        }
    }

    // Frida names ARM's r11 and r12 by number
    private static string? Alias(string name) => name switch { "fp" => "r11", "ip" => "r12", _ => null };

    private static ulong Hex(string s) =>
        ulong.TryParse(s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? s[2..] : s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v) ? v : 0;

    private CoreImage? ImageAt(ulong address) => ModuleAt(address) is { } m
        ? _images.GetOrAdd((m.Base, m.Path), _ => ElfAt(m.Path) is { } file ? CoreImage.FromFile(file, m, this, m.Path, "") : null)
        : null;

    private static ElfFile? ElfAt(string path)
    {
        if (!File.Exists(path)) return null;
        var info = new FileInfo(path);
        var key = $"{info.FullName}|{info.Length}|{info.LastWriteTimeUtc.Ticks}";
        if (Files.TryGetValue(key, out var cached)) return cached;
        ElfFile? file;
        try { file = ElfFile.Open(path); }
        catch (Exception e) when (e is ToolError or IOException or UnauthorizedAccessException) { file = null; }
        if (Files.Count >= MaxCachedFiles) Files.Clear();
        return Files[key] = file;
    }

    public NativeArch Arch => _arch.Arch;
    public bool Is64Bit => _arch.Is64;
    public string Identity => $"live|{_session.ProcessId}";
    public IReadOnlyList<DumpModule> Modules => _modules;
    public IReadOnlyList<DumpUnloadedModule> UnloadedModules => [];

    public int ReadMemory(ulong address, Span<byte> destination)
    {
        if (address < _sp || address - _sp >= (ulong)_stack.Length) return 0;
        var from = _stack.AsSpan((int)(address - _sp));
        int n = Math.Min(from.Length, destination.Length);
        from[..n].CopyTo(destination);
        return n;
    }

    public DumpModule? ModuleAt(ulong address) => ProcessMemoryExtensions.ModuleAt(_modules, address);

    public DumpMemoryRegion? RegionAt(ulong address)
    {
        const uint Commit = 0x1000, ReadWrite = 0x04, ExecuteRead = 0x20, Private = 0x20000, Image = 0x1000000;
        if (address >= _sp && address - _sp < (ulong)_stack.Length) return new(_sp, _sp, ReadWrite, (ulong)_stack.Length, Commit, ReadWrite, Private);
        return ModuleAt(address) is { } m ? new(m.Base, m.Base, ExecuteRead, m.Size, Commit, ExecuteRead, Image) : null;
    }

    public ulong ReadableExtent(ulong start, ulong size) =>
        start >= _sp && start - _sp < (ulong)_stack.Length ? Math.Min(size, (ulong)_stack.Length - (start - _sp)) : 0;
}
