using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Corvus.Core;

namespace Corvus.Native.Providers.Live.Ttd;

/// <summary>A TTD position: sequence and steps, shown as WinDbg shows it (SEQUENCE:STEPS in hex).</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct TtdPosition(ulong sequence, ulong steps)
{
    public ulong Sequence = sequence;
    public ulong Steps = steps;

    public static readonly TtdPosition Max = new(ulong.MaxValue - 1, ulong.MaxValue - 1);
    public override readonly string ToString() => $"{Sequence:X}:{Steps:X}";

    /// <summary>Parses SEQUENCE:STEPS (hex, as WinDbg prints it); null when it does not parse.</summary>
    public static TtdPosition? Parse(string text)
    {
        var parts = text.Trim().Split(':');
        return parts.Length == 2 && ulong.TryParse(parts[0], System.Globalization.NumberStyles.HexNumber, null, out var s)
            && ulong.TryParse(parts[1], System.Globalization.NumberStyles.HexNumber, null, out var t) ? new TtdPosition(s, t) : null;
    }
}

/// <summary>A module instance of a recording: path, base, size and the header's checksum and timestamp.</summary>
internal sealed record TtdModule(string Path, ulong Base, ulong Size, uint Checksum, uint Timestamp)
{
    public string Name => System.IO.Path.GetFileName(Path);
}

/// <summary>Why a replay stopped: an execute watchpoint, or the end of the recording.</summary>
internal readonly record struct TtdStop(bool Watchpoint, string Reason);

// Interface slots and layouts follow the 0.9.5 API headers (Microsoft.TimeTravelDebugging.Apis) as MSVC lays them out.
/// <summary>One recording opened with TTDReplay.dll: its modules and one forward cursor. Not thread-safe; x64 only.</summary>
internal sealed class TtdReplay : IDisposable
{
    private static readonly Guid EngineView = new("4D3420A5-37EF-4114-AE91-63D0378C84A9");
    private static readonly Guid CursorView = new("B1D2E6AB-9052-4B72-999E-A88BA868F899");
    // ProcessorArchitecture in SystemInfo: PROCESSOR_ARCHITECTURE_AMD64.
    private const ushort Amd64 = 9;
    // CROSS_PLATFORM_CONTEXT: the x64 CONTEXT at offset 0, 2672 bytes in all.
    private const int ContextSize = 2672;

    private readonly IntPtr _engine, _cursor;

    private TtdReplay(IntPtr engine, IntPtr cursor)
    {
        (_engine, _cursor) = (engine, cursor);
        var info = Call<PtrFn>(_engine, 3)(_engine);
        ProcessId = (uint)Marshal.ReadInt32(info, 12);
        Architecture = (ushort)Marshal.ReadInt16(info, 56);
        First = Marshal.PtrToStructure<TtdPosition>(Call<PtrFn>(_engine, 4)(_engine));
        Modules = Read(21, 22, 24, p =>
        {
            var m = Marshal.ReadIntPtr(p);
            var name = Marshal.PtrToStringUni(Marshal.ReadIntPtr(m), (int)Marshal.ReadInt64(m, 8));
            return new TtdModule(name, (ulong)Marshal.ReadInt64(m, 16), (ulong)Marshal.ReadInt64(m, 24), (uint)Marshal.ReadInt32(m, 32), (uint)Marshal.ReadInt32(m, 36));
        });
        // MemoryWatchpoint events only: exceptions, gaps and thread boundaries do not stop a replay.
        Call<VoidU32Fn>(_cursor, 22)(_cursor, 1);
        SetPosition(First);
    }

    public uint ProcessId { get; }
    public ushort Architecture { get; }
    public TtdPosition First { get; }
    public IReadOnlyList<TtdModule> Modules { get; }

    /// <summary>Opens <paramref name="trace"/> with the TTDReplay.dll in <paramref name="folder"/>; a <see cref="ToolError"/> names what failed.</summary>
    public static TtdReplay Open(string folder, string trace)
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != System.Runtime.InteropServices.Architecture.X64)
            throw new ToolError(ErrorCode.Unsupported, "Recordings are replayed with the TTD Replay API, which runs on Windows x64 only.");
        var dll = Path.Combine(folder, "TTDReplay.dll");
        if (!File.Exists(dll) || !File.Exists(Path.Combine(folder, "TTDReplayCPU.dll")))
            throw new ToolError(ErrorCode.ProviderUnavailable, $"No TTDReplay.dll and TTDReplayCPU.dll in {folder}.", Remedy);
        IntPtr library;
        // TTDReplay.dll loads TTDReplayCPU.dll from its own folder.
        try { library = NativeLibrary.Load(dll, typeof(TtdReplay).Assembly, DllImportSearchPath.UseDllDirectoryForDependencies); }
        catch (DllNotFoundException ex) { throw new ToolError(ErrorCode.ProviderUnavailable, $"TTDReplay.dll did not load from {folder}: {ex.Message}", Remedy); }
        var create = Marshal.GetDelegateForFunctionPointer<CreateFn>(NativeLibrary.GetExport(library, "CreateReplayEngine"));
        var guid = EngineView;
        if (create(out var engine, ref guid) != 0 || engine == IntPtr.Zero)
            throw new ToolError(ErrorCode.Failed, "TTDReplay.dll could not create a replay engine.", Remedy);
        if (Call<InitializeFn>(engine, 51)(engine, trace) == 0)
        {
            Call<VoidFn>(engine, 50)(engine);
            throw new ToolError(ErrorCode.MalformedInput, $"{trace} is not a recording the TTD replay engine in {folder} opens.", "record with TTD.exe of the same or an older release");
        }
        var cursorGuid = CursorView;
        var cursor = Call<NewCursorFn>(engine, 42)(engine, ref cursorGuid);
        // The library stays loaded for the worker's life: the engine's threads may outlive Destroy briefly.
        var replay = new TtdReplay(engine, cursor);
        if (replay.Architecture != Amd64)
        {
            replay.Dispose();
            throw new ToolError(ErrorCode.Unsupported, $"{trace} records a program for processor architecture {replay.Architecture}; only x64 recordings are read.");
        }
        return replay;
    }

    public const string Remedy = "set CORVUS_TTD to a folder holding TTDReplay.dll and TTDReplayCPU.dll, copied from WinDbg's amd64\\ttd folder";

    /// <summary>The cursor's position on its current thread.</summary>
    public TtdPosition Position => Marshal.PtrToStructure<TtdPosition>(Call<PtrU32Fn>(_cursor, 10)(_cursor, 0));

    /// <summary>The OS thread id of the cursor's current thread.</summary>
    public uint Thread => (uint)Marshal.ReadInt32(Call<PtrU32Fn>(_cursor, 8)(_cursor, 0), 4);

    /// <summary>The TEB address of the cursor's current thread.</summary>
    public ulong TebAddress => Call<SizeU32Fn>(_cursor, 9)(_cursor, 0);

    public void SetPosition(TtdPosition position) => Call<SetPositionFn>(_cursor, 37)(_cursor, ref position);

    /// <summary>The current thread's x64 registers by Frida's names (pc, sp, rax ... r15, rflags).</summary>
    public Dictionary<string, ulong> Registers()
    {
        var buffer = Marshal.AllocHGlobal(ContextSize);
        try
        {
            Call<ContextFn>(_cursor, 16)(_cursor, buffer, 0);
            var r = new Dictionary<string, ulong>(StringComparer.Ordinal);
            string[] names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
            for (int i = 0; i < names.Length; i++) r[names[i]] = (ulong)Marshal.ReadInt64(buffer, 0x78 + 8 * i);
            r["rip"] = (ulong)Marshal.ReadInt64(buffer, 0xF8);
            r["rflags"] = (uint)Marshal.ReadInt32(buffer, 0x44);
            (r["pc"], r["sp"]) = (r["rip"], r["rsp"]);
            return r;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    /// <summary>Memory at the cursor's position: the bytes the recording holds from <paramref name="address"/>, up to the first it does not.</summary>
    public byte[] Read(ulong address, int length)
    {
        var data = Marshal.AllocHGlobal(Math.Max(length, 1));
        var result = Marshal.AllocHGlobal(24);
        try
        {
            var view = new BufferView(data, length);
            Call<QueryMemoryFn>(_cursor, 1)(_cursor, result, address, ref view, 0);
            var got = (int)Math.Min(Marshal.ReadInt64(result, 16), length);
            var bytes = new byte[Math.Max(got, 0)];
            if (got > 0) Marshal.Copy(Marshal.ReadIntPtr(result, 8), bytes, 0, got);
            return bytes;
        }
        finally
        {
            Marshal.FreeHGlobal(result);
            Marshal.FreeHGlobal(data);
        }
    }

    public ulong ReadU64(ulong address) => Read(address, 8) is { Length: 8 } b ? BinaryPrimitives.ReadUInt64LittleEndian(b) : 0;

    /// <summary>Adds an execute watchpoint at <paramref name="address"/>, optionally on one thread (unique id); false when the engine refuses it.</summary>
    public bool AddExecute(ulong address, uint uniqueThread = 0)
    {
        var w = new WatchpointData { Address = address, Size = 1, Access = 4, Thread = uniqueThread };
        return Call<WatchpointFn>(_cursor, 32)(_cursor, ref w) != 0;
    }

    public void RemoveExecute(ulong address, uint uniqueThread = 0)
    {
        var w = new WatchpointData { Address = address, Size = 1, Access = 4, Thread = uniqueThread };
        Call<WatchpointFn>(_cursor, 33)(_cursor, ref w);
    }

    /// <summary>The unique id of the cursor's current thread.</summary>
    public uint UniqueThread => (uint)Marshal.ReadInt32(Call<PtrU32Fn>(_cursor, 8)(_cursor, 0));

    /// <summary>Replays forward to the next watchpoint hit, or to the end of the recording; <paramref name="steps"/> bounds the instructions.</summary>
    public TtdStop Replay(ulong steps = ulong.MaxValue - 1)
    {
        var result = Marshal.AllocHGlobal(48);
        try
        {
            var limit = TtdPosition.Max;
            Call<ReplayFn>(_cursor, 48)(_cursor, result, ref limit, steps);
            var reason = Marshal.ReadByte(result);
            // EventType: 0 MemoryWatchpoint, 5 StepCount, 6 Position, 7 Process.
            return reason switch
            {
                0 => new TtdStop(true, "watchpoint"),
                5 => new TtdStop(false, "steps"),
                6 or 7 => new TtdStop(false, "the recording ends"),
                _ => new TtdStop(false, $"replay stopped (event {reason})"),
            };
        }
        finally { Marshal.FreeHGlobal(result); }
    }

    /// <summary>Stops a running replay soon; callable from any thread.</summary>
    public void Interrupt() => Call<VoidFn>(_cursor, 50)(_cursor);

    public void Dispose()
    {
        Call<VoidFn>(_cursor, 55)(_cursor);
        Call<VoidFn>(_engine, 50)(_engine);
    }

    private List<T> Read<T>(int countSlot, int listSlot, int size, Func<IntPtr, T> row)
    {
        var count = (long)Call<SizeFn>(_engine, countSlot)(_engine);
        var list = Call<PtrFn>(_engine, listSlot)(_engine);
        var rows = new List<T>((int)Math.Min(count, 100_000));
        for (long i = 0; i < count && list != IntPtr.Zero; i++) rows.Add(row(list + (int)(i * size)));
        return rows;
    }

    private static T Call<T>(IntPtr self, int slot) where T : Delegate =>
        Marshal.GetDelegateForFunctionPointer<T>(Marshal.ReadIntPtr(Marshal.ReadIntPtr(self), slot * IntPtr.Size));

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct BufferView(IntPtr data, long size)
    {
        public readonly IntPtr Data = data;
        public readonly long Size = size;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WatchpointData
    {
        public ulong Address;
        public ulong Size;
        public byte Access;
        public uint Thread;
    }

    // Member functions: this first, then the return buffer for a struct returned by value, then the arguments.
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint CreateFn(out IntPtr engine, ref Guid guid);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate byte InitializeFn(IntPtr self, [MarshalAs(UnmanagedType.LPWStr)] string path);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate IntPtr NewCursorFn(IntPtr self, ref Guid guid);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate IntPtr PtrFn(IntPtr self);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong SizeFn(IntPtr self);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void VoidFn(IntPtr self);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void VoidU32Fn(IntPtr self, uint value);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate IntPtr PtrU32Fn(IntPtr self, uint thread);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong SizeU32Fn(IntPtr self, uint thread);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate IntPtr ContextFn(IntPtr self, IntPtr result, uint thread);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate IntPtr QueryMemoryFn(IntPtr self, IntPtr result, ulong address, ref BufferView view, uint policy);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate byte WatchpointFn(IntPtr self, ref WatchpointData data);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void SetPositionFn(IntPtr self, ref TtdPosition position);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate IntPtr ReplayFn(IntPtr self, IntPtr result, ref TtdPosition limit, ulong steps);
}
