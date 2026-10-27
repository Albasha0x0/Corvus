using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Runtime;
using Corvus.Native.Live;

namespace Corvus.Native.Dump.Managed;

/// <summary>ClrMD's view of a running process through a read-only handle; thread contexts come only from <see cref="SetContext"/>, never from a running thread.</summary>
public sealed class LiveDataReader(LiveProcess process) : ByteDataReader, IDataReader, IDisposable
{
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
    public override int PointerSize => process.Is64Bit ? 8 : 4;

    /// <summary>The registers a thread was stopped with (see <see cref="StopContext.From"/>); false when they make no context.</summary>
    public bool SetContext(uint threadId, IReadOnlyDictionary<string, string> registers)
    {
        if (StopContext.From(Architecture, registers) is not { } c) return false;
        _contexts[threadId] = c;
        return true;
    }

    public void ClearContext(uint threadId) => _contexts.TryRemove(threadId, out _);

    public IEnumerable<ModuleInfo> EnumerateModules()
    {
        foreach (var m in process.Modules)
            if (ModuleInfo.TryCreate(this, m.Base, m.Path, (int)m.Size, (int)m.TimeDateStamp, null) is { } info) yield return info;
    }

    public bool GetThreadContext(uint threadID, uint contextFlags, Span<byte> context)
    {
        return _contexts.TryGetValue(threadID, out var bytes) && CopyContext(bytes, context);
    }

    public void FlushCachedData() => process.RefreshModules();

    public override int Read(ulong address, Span<byte> buffer) => process.ReadMemory(address, buffer);

    public void Dispose() => process.Dispose();
}
