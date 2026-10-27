using System.Buffers.Binary;
using Corvus.Core;

namespace Corvus.Native.Live;

/// <summary>Statically linked ELF programs, which a session can neither start nor attach to (frida/frida#2533, Frida 17).</summary>
internal static class StaticProgram
{
    private const uint PtLoad = 1, PtInterp = 3;

    /// <summary>True for an ELF executable (or static PIE) that loads segments but names no program interpreter (PT_INTERP).</summary>
    public static bool Is(string path)
    {
        try
        {
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            Span<byte> h = stackalloc byte[64];
            if (file.Read(h) < 52 || BinaryPrimitives.ReadUInt32LittleEndian(h) != 0x464C457F || h[5] != 1) return false; // little-endian only
            bool is64 = h[4] == 2;
            ushort type = BinaryPrimitives.ReadUInt16LittleEndian(h[16..]);
            if (type is not (2 or 3)) return false; // ET_EXEC, ET_DYN
            long phoff = is64 ? (long)BinaryPrimitives.ReadUInt64LittleEndian(h[32..]) : BinaryPrimitives.ReadUInt32LittleEndian(h[28..]);
            int size = BinaryPrimitives.ReadUInt16LittleEndian(h[(is64 ? 54 : 42)..]), count = BinaryPrimitives.ReadUInt16LittleEndian(h[(is64 ? 56 : 44)..]);
            if (size < 8 || count is 0 or > 512) return false;
            var phdrs = new byte[size * count];
            file.Position = phoff;
            if (file.Read(phdrs) < phdrs.Length) return false;
            bool loads = false;
            for (int i = 0; i < count; i++)
                switch (BinaryPrimitives.ReadUInt32LittleEndian(phdrs.AsSpan(i * size)))
                {
                    case PtInterp: return false;
                    case PtLoad: loads = true; break;
                }
            return loads;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return false; }
    }

    public static ToolError Refusal(string path) => new(ErrorCode.Unsupported,
        $"{path} is statically linked (no program interpreter); Frida needs a dynamic loader to start or attach to it.",
        "read it statically (load_assembly path=<file>), or write a core of the running program with gcore and open it with open_minidump");
}
