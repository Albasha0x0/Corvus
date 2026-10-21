using System.Buffers.Binary;
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Runtime;

namespace Corvus.Native.Dump.Managed;

/// <summary>The method whose code holds an address: its assembly file, signature and code start.</summary>
public sealed record LiveMethod(string Assembly, string Signature, ulong Start);

/// <summary>A method's prepared code (Code 0: none yet) and Kind (JIT or ReadyToRun); its module's mapping (Base 0: not loaded) and layout.</summary>
public sealed record LiveCode(ulong Code, string? Kind, ulong ModuleBase, bool Flat);

/// <summary>Where the runtime mapped a module, and whether as the file (flat) rather than as an image.</summary>
public sealed record LiveModuleImage(ulong Base, bool Flat);

/// <summary>
/// Reads of a running program's CLR through its DAC: code addresses named, held threads walked, prepared code found.
/// Shared with the 32-bit decoder process; calls are not thread-safe.
/// </summary>
public sealed class ClrLiveReads(ClrRuntime runtime)
{
    public ClrRuntime Runtime { get; } = runtime;

    /// <summary>Drops what was read before: the program has run since.</summary>
    public void Refresh() => Runtime.FlushCachedData();

    public LiveMethod? MethodAt(ulong ip)
    {
        if (Runtime.GetMethodByInstructionPointer(ip) is not { } m) return null;
        var hc = m.HotColdInfo;
        ulong start = hc.ColdSize > 0 && ip >= hc.ColdStart && ip - hc.ColdStart < hc.ColdSize ? hc.ColdStart : hc.HotStart;
        return new LiveMethod(FileName(m.Type?.Module), m.Signature ?? m.Name ?? "?", start == 0 || start > ip ? ip : start);
    }

    /// <summary>
    /// The managed frames of a thread whose context the data reader holds (instruction pointers of methods only),
    /// innermost first; empty when the runtime does not know the thread or the walk finds nothing.
    /// </summary>
    public IReadOnlyList<ulong> Frames(uint thread, int max)
    {
        try
        {
            var t = Runtime.Threads.FirstOrDefault(x => x.OSThreadId == thread);
            if (t == null) return [];
            return t.EnumerateStackTrace(false, max).Where(f => f.Kind == ClrStackFrameKind.ManagedMethod && f.InstructionPointer != 0).Select(f => f.InstructionPointer).ToList();
        }
        catch (Exception e) when (e is InvalidOperationException or ClrDiagnosticsException) { return []; }
    }

    /// <summary>The code the runtime prepared for a method of the module loaded from <paramref name="path"/>, and that module's mapping.</summary>
    public LiveCode CodeOf(string path, int typeToken, int methodToken)
    {
        var module = Runtime.EnumerateModules().FirstOrDefault(m => m.Name is { } n && SamePath(n, path));
        var type = module?.EnumerateTypeDefToMethodTableMap().FirstOrDefault(x => x.Token == typeToken) is { MethodTable: > 0 } map ? Runtime.GetTypeByMethodTable(map.MethodTable) : null;
        var method = type?.Methods.FirstOrDefault(m => m.MetadataToken == methodToken);
        ulong code = method != null && HasCode(method.NativeCode) ? method.NativeCode : 0;
        return new LiveCode(code, code == 0 ? null : method!.CompilationType == MethodCompilationType.Jit ? "JIT" : "ReadyToRun",
            module?.ImageBase ?? 0, module?.Layout == ModuleLayout.Flat);
    }

    public LiveModuleImage? ModuleImage(string path) =>
        Runtime.EnumerateModules().FirstOrDefault(m => m.Name is { } n && SamePath(n, path)) is { ImageBase: > 0 } m ? new LiveModuleImage(m.ImageBase, m.Layout == ModuleLayout.Flat) : null;

    /// <summary>The metadata tokens of the methods of an assembly the runtime has prepared code for (JIT-compiled, or ReadyToRun code bound).</summary>
    public IReadOnlyList<uint> Prepared(string path)
    {
        var found = new List<uint>();
        foreach (var module in Runtime.EnumerateModules().Where(m => m.Name is { } n && SamePath(n, path)))
            foreach (var type in module.EnumerateTypeDefToMethodTableMap().Select(x => Runtime.GetTypeByMethodTable(x.MethodTable)).OfType<ClrType>())
                foreach (var m in type.Methods)
                    if (m.Type == type && m.MetadataToken != 0 && HasCode(m.NativeCode)) found.Add((uint)m.MetadataToken);
        return found;
    }

    /// <summary>The DAC marks a method without code with all bits set, at the target's pointer size.</summary>
    private static bool HasCode(ulong code) => code != 0 && code != ulong.MaxValue && code != uint.MaxValue;

    /// <summary>True when the runtime's module <paramref name="name"/> is the file at <paramref name="path"/>; a bundled assembly is named by its bundle-relative path.</summary>
    private static bool SamePath(string name, string path) => Path.IsPathRooted(name)
        ? string.Equals(Path.GetFullPath(name), Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase)
        : path.Replace('\\', '/').EndsWith("/" + name.Replace('\\', '/'), StringComparison.OrdinalIgnoreCase);

    private static string FileName(ClrModule? module) =>
        module?.Name is { Length: > 0 } path ? Path.GetFileName(path) : module?.AssemblyName ?? "?";
}

/// <summary>Thread contexts (the CONTEXT record) built from the registers a stop captured, in Frida's names.</summary>
public static class StopContext
{
    private static readonly string[] X64Names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];

    /// <summary>
    /// An x64 (rip or pc, rsp or sp, rax..r15) or x86 (eip or pc, esp or sp, eax..edi) context; null for another
    /// architecture or a stop without an instruction and stack pointer.
    /// </summary>
    public static byte[]? From(Architecture arch, IReadOnlyDictionary<string, string> registers)
    {
        ulong Reg(string name, string? alias = null) =>
            registers.TryGetValue(name, out var v) || (alias != null && registers.TryGetValue(alias, out v)) ? Hex(v) : 0;
        if (arch == Architecture.X64)
        {
            ulong ip = Reg("rip", "pc"), sp = Reg("rsp", "sp");
            if (ip == 0 || sp == 0) return null;
            var c = new byte[0x4D0];
            const uint ContextAmd64 = 0x100000, Control = 1, Integer = 2, Segments = 4;
            BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0x30), ContextAmd64 | Control | Integer | Segments);
            BinaryPrimitives.WriteUInt16LittleEndian(c.AsSpan(0x38), 0x33); // user-mode code segment
            BinaryPrimitives.WriteUInt16LittleEndian(c.AsSpan(0x42), 0x2B);
            for (int i = 0; i < 16; i++) BinaryPrimitives.WriteUInt64LittleEndian(c.AsSpan(0x78 + 8 * i), i == 4 ? sp : Reg(X64Names[i]));
            BinaryPrimitives.WriteUInt64LittleEndian(c.AsSpan(0xF8), ip);
            return c;
        }
        if (arch == Architecture.X86)
        {
            ulong ip = Reg("eip", "pc"), sp = Reg("esp", "sp");
            if (ip == 0 || sp == 0) return null;
            var c = new byte[0x2CC];
            const uint ContextI386 = 0x10000, Control = 1, Integer = 2, Segments = 4;
            BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0), ContextI386 | Control | Integer | Segments);
            // Edi, Esi, Ebx, Edx, Ecx, Eax, Ebp, Eip, SegCs, EFlags, Esp, SegSs from 0x9C
            string[] order = ["edi", "esi", "ebx", "edx", "ecx", "eax", "ebp"];
            for (int i = 0; i < order.Length; i++) BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0x9C + 4 * i), (uint)Reg(order[i]));
            BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0xB8), (uint)ip);
            BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0xBC), 0x23); // user-mode code segment of a WoW64 thread
            BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0xC4), (uint)sp);
            BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0xC8), 0x2B);
            return c;
        }
        return null;
    }

    private static ulong Hex(string s) =>
        ulong.TryParse(s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? s.Substring(2) : s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v) ? v : 0;
}
