using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.Dump;

/// <summary>MINIDUMP_LOCATION_DESCRIPTOR: size and file offset of a block.</summary>
public readonly record struct DumpLocation(uint Size, uint Rva);

/// <summary>One stream directory entry.</summary>
public sealed record DumpStream(int Index, uint Type, string TypeName, uint Size, uint Rva);

/// <summary>MINIDUMP_SYSTEM_INFO.</summary>
public sealed record DumpSystemInfo(
    ushort ProcessorArchitecture, NativeArch Arch, ushort ProcessorLevel, ushort ProcessorRevision, byte Processors, byte ProductType,
    uint MajorVersion, uint MinorVersion, uint BuildNumber, uint PlatformId, string? CsdVersion, string? VendorId);

/// <summary>MINIDUMP_MISC_INFO (versions 1-5); fields the flags do not mark as valid are null.</summary>
public sealed record DumpMiscInfo(
    uint Size, uint Flags, uint? ProcessId, DateTime? ProcessCreateTime, uint? ProcessUserSeconds, uint? ProcessKernelSeconds,
    uint? ProcessorMaxMhz, uint? ProcessIntegrityLevel, uint? ProcessExecuteFlags, uint? ProtectedProcess, string? BuildString, string? DebugBuildString);

/// <summary>MINIDUMP_EXCEPTION_STREAM.</summary>
public sealed record DumpException(uint ThreadId, uint Code, uint Flags, ulong NestedRecord, ulong Address, IReadOnlyList<ulong> Parameters, DumpLocation Context);

/// <summary>A thread from the thread list (or extended thread list), with its name and MINIDUMP_THREAD_INFO when the dump has them.</summary>
public sealed record DumpThread(uint Id, uint SuspendCount, uint PriorityClass, uint Priority, ulong Teb, ulong StackStart, uint StackSize, uint StackRva, DumpLocation Context)
{
    public string? Name { get; init; }
    public ulong? StartAddress { get; init; }
    public DateTime? CreateTime { get; init; }
    public uint? ExitStatus { get; init; }
    public uint? DumpFlags { get; init; }
}

/// <summary>A loaded module (MINIDUMP_MODULE) with its CodeView record and file version.</summary>
public sealed record DumpModule(ulong Base, uint Size, uint CheckSum, uint TimeDateStamp, string Path, string? FileVersion, string? ProductVersion, PeCodeView? CodeView)
{
    public ulong End => Base + Size;
    public string FileName => System.IO.Path.GetFileName(Path.Replace('/', '\\').Split('\\')[^1]);
    public bool Contains(ulong address) => address >= Base && address - Base < Size;
}

/// <summary>MINIDUMP_UNLOADED_MODULE.</summary>
public sealed record DumpUnloadedModule(ulong Base, uint Size, uint CheckSum, uint TimeDateStamp, string Path);

/// <summary>Captured memory: <see cref="Size"/> bytes at <see cref="Start"/>, stored at <see cref="FileOffset"/>.</summary>
public readonly record struct DumpMemoryRange(ulong Start, ulong Size, long FileOffset)
{
    public ulong End => Start + Size;
}

/// <summary>MINIDUMP_MEMORY_INFO: a region of the address space (VirtualQuery).</summary>
public sealed record DumpMemoryRegion(ulong Base, ulong AllocationBase, uint AllocationProtect, ulong Size, uint State, uint Protect, uint Type)
{
    public bool IsExecutable => State == 0x1000 && (Protect & 0xF0) != 0;
    public bool Contains(ulong address) => address >= Base && address - Base < Size;
}

/// <summary>MINIDUMP_HANDLE_DESCRIPTOR(_2).</summary>
public sealed record DumpHandle(ulong Handle, string? TypeName, string? ObjectName, uint Attributes, uint GrantedAccess, uint HandleCount, uint PointerCount);

/// <summary>
/// A thread's register context. x64: <see cref="Gpr"/> in unwind-code order (rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi,
/// r8-r15); x86: eax, ecx, edx, ebx, esp, ebp, esi, edi. <see cref="Complete"/> is false when the dump held fewer bytes
/// than the CONTEXT structure (the missing registers read as 0).
/// </summary>
public sealed class DumpContext
{
    public DumpContext(NativeArch arch) => Arch = arch;

    public NativeArch Arch { get; }
    public ulong[] Gpr { get; } = new ulong[16];
    public ulong Ip { get; set; }
    public uint Flags { get; set; }
    public uint ContextFlags { get; set; }
    public ushort SegCs { get; set; }
    /// <summary>x64 only: xmm0-xmm15, 16 bytes each.</summary>
    public byte[] Xmm { get; } = new byte[256];
    public bool Complete { get; set; } = true;

    public ulong Sp { get => Gpr[4]; set => Gpr[4] = value; }
    public ulong Fp { get => Gpr[5]; set => Gpr[5] = value; }

    public DumpContext Clone()
    {
        var c = new DumpContext(Arch) { Ip = Ip, Flags = Flags, ContextFlags = ContextFlags, SegCs = SegCs, Complete = Complete };
        Gpr.CopyTo(c.Gpr, 0);
        Xmm.CopyTo(c.Xmm, 0);
        return c;
    }

    public static readonly string[] X64Names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
    public static readonly string[] X86Names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];

    /// <summary>"rax=... rbx=..." in the order debuggers print them.</summary>
    public string Format()
    {
        if (Arch == NativeArch.X64)
        {
            int[] order = [0, 3, 1, 2, 6, 7, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15];
            return string.Join(" ", order.Select(i => $"{X64Names[i]}={Gpr[i]:x16}")) + $" rip={Ip:x16} efl={Flags:x8}";
        }
        int[] order32 = [0, 3, 1, 2, 6, 7, 4, 5];
        return string.Join(" ", order32.Select(i => $"{X86Names[i]}={Gpr[i]:x8}")) + $" eip={Ip:x8} efl={Flags:x8}";
    }
}
