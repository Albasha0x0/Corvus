using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Runtime;
using Corvus.Native.Live;

namespace Corvus.Native.Dump.Managed;

/// <summary>
/// ClrMD's view of a running process through <see cref="LiveProcess"/>: memory read with the inspector's read-only handle,
/// the module list read again on each flush. Thread contexts are only those handed in with <see cref="SetContext"/>
/// (a thread held at a stop point, as the stop captured it): a running thread's registers are never read.
/// </summary>
public sealed class LiveDataReader(LiveProcess process) : IDataReader, IDisposable
{
    private const int X64ContextSize = 0x4D0;
    private readonly ConcurrentDictionary<uint, byte[]> _contexts = new();

    public LiveProcess Process => process;
    public string DisplayName => $"process {process.Pid}";
    public bool IsThreadSafe => false;
    public OSPlatform TargetPlatform => OSPlatform.Windows;
    public Architecture Architecture => process.Arch switch
    {
        NativeArch.X86 => Architecture.X86,
        NativeArch.Arm64 => Architecture.Arm64,
        NativeArch.Arm => Architecture.Arm,
        _ => Architecture.X64,
    };
    public int ProcessId => process.Pid;
    public int PointerSize => process.Is64Bit ? 8 : 4;

    /// <summary>
    /// The x64 registers a thread was stopped with (Frida's names: rip or pc, rsp or sp, rax..r15); false when the
    /// process is not x64 or the stop has no instruction and stack pointer.
    /// </summary>
    public bool SetContext(uint threadId, IReadOnlyDictionary<string, string> registers)
    {
        if (process.Arch != NativeArch.X64) return false;
        ulong Reg(string name, string? alias = null) =>
            registers.TryGetValue(name, out var v) || (alias != null && registers.TryGetValue(alias, out v)) ? Hex(v) : 0;
        ulong ip = Reg("rip", "pc"), sp = Reg("rsp", "sp");
        if (ip == 0 || sp == 0) return false;
        var c = new byte[X64ContextSize];
        const uint ContextAmd64 = 0x100000, Control = 1, Integer = 2, Segments = 4;
        BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0x30), ContextAmd64 | Control | Integer | Segments);
        BinaryPrimitives.WriteUInt16LittleEndian(c.AsSpan(0x38), 0x33); // user-mode code segment
        BinaryPrimitives.WriteUInt16LittleEndian(c.AsSpan(0x42), 0x2B);
        for (int i = 0; i < 16; i++) BinaryPrimitives.WriteUInt64LittleEndian(c.AsSpan(0x78 + 8 * i), i == 4 ? sp : Reg(DumpContext.X64Names[i]));
        BinaryPrimitives.WriteUInt64LittleEndian(c.AsSpan(0xF8), ip);
        _contexts[threadId] = c;
        return true;
    }

    public void ClearContext(uint threadId) => _contexts.TryRemove(threadId, out _);

    private static ulong Hex(string s) =>
        ulong.TryParse(s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? s[2..] : s, System.Globalization.NumberStyles.HexNumber,
            System.Globalization.CultureInfo.InvariantCulture, out var v) ? v : 0;

    public IEnumerable<ModuleInfo> EnumerateModules()
    {
        foreach (var m in process.Modules)
            if (ModuleInfo.TryCreate(this, m.Base, m.Path, (int)m.Size, (int)m.TimeDateStamp, null) is { } info) yield return info;
    }

    public bool GetThreadContext(uint threadID, uint contextFlags, Span<byte> context)
    {
        if (!_contexts.TryGetValue(threadID, out var bytes)) return false;
        context.Clear();
        bytes.AsSpan(0, Math.Min(bytes.Length, context.Length)).CopyTo(context);
        return true;
    }

    public void FlushCachedData() => process.RefreshModules();

    public int Read(ulong address, Span<byte> buffer) => process.ReadMemory(address, buffer);

    public bool Read<T>(ulong address, out T value) where T : unmanaged
    {
        Span<byte> b = stackalloc byte[Unsafe.SizeOf<T>()];
        if (Read(address, b) == b.Length)
        {
            value = MemoryMarshal.Read<T>(b);
            return true;
        }
        value = default;
        return false;
    }

    public T Read<T>(ulong address) where T : unmanaged => Read(address, out T value) ? value : default;

    public bool ReadPointer(ulong address, out ulong value)
    {
        Span<byte> b = stackalloc byte[8];
        int size = PointerSize;
        if (Read(address, b[..size]) != size)
        {
            value = 0;
            return false;
        }
        value = size == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);
        return true;
    }

    public ulong ReadPointer(ulong address) => ReadPointer(address, out var value) ? value : 0;

    public void Dispose() => process.Dispose();
}
