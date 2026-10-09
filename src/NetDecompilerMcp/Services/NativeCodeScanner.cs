using System.Buffers;
using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>Reads the section table of a native x64 PE image and finds RIP-relative data references in its code.</summary>
public static class NativeCodeScanner
{
    public sealed record Section(string Name, uint Rva, uint VirtualSize, uint RawOffset, uint RawSize, bool Executable)
    {
        public bool Contains(ulong rva) => rva >= Rva && rva < Rva + (ulong)Math.Max(VirtualSize, RawSize);
    }

    /// <summary>Sections of an x64 PE file; ToolError when the file is not one.</summary>
    public static List<Section> Sections(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        PEHeaders headers;
        try { headers = new PEHeaders(stream); }
        catch (BadImageFormatException ex) { throw new ToolError($"{Path.GetFileName(path)} is not a PE image: {ex.Message}"); }
        if (headers.CoffHeader.Machine != Machine.Amd64)
            throw new ToolError($"{Path.GetFileName(path)} is a {headers.CoffHeader.Machine} image; only x64 code is scanned.");
        return headers.SectionHeaders.Select(s => new Section(s.Name, (uint)s.VirtualAddress, (uint)s.VirtualSize, (uint)s.PointerToRawData,
            (uint)s.SizeOfRawData, (s.SectionCharacteristics & SectionCharacteristics.MemExecute) != 0)).ToList();
    }

    private const int ChunkSize = 1 << 20;

    /// <summary>
    /// Every "mov r64, [rip+disp32]" (REX.W 8B /r) and "lea r64, [rip+disp32]" (REX.W 8D /r) in the executable
    /// sections whose target RVA is in [<paramref name="low"/>, <paramref name="high"/>]: reports the instruction's RVA
    /// and the target. A byte scan, not a disassembly: a match inside another instruction is possible but needs its
    /// target to land on a wanted address.
    /// </summary>
    public static void FindRipRelative(string path, IReadOnlyList<Section> sections, uint low, uint high, Action<uint, uint> found, CancellationToken ct)
    {
        using var file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        long fileLength = RandomAccess.GetLength(file);
        var buffer = ArrayPool<byte>.Shared.Rent(ChunkSize + 16);
        try
        {
            foreach (var s in sections.Where(s => s.Executable))
            {
                long size = Math.Min(Math.Min(s.RawSize, s.VirtualSize == 0 ? s.RawSize : s.VirtualSize), Math.Max(0, fileLength - s.RawOffset));
                for (long chunk = 0; chunk < size; chunk += ChunkSize)
                {
                    ct.ThrowIfCancellationRequested();
                    int length = RandomAccess.Read(file, buffer.AsSpan(0, (int)Math.Min(ChunkSize + 16, size - chunk)), s.RawOffset + chunk);
                    int limit = (int)Math.Min(ChunkSize, length); // instructions starting in this chunk
                    Scan(buffer.AsSpan(0, length), limit, s.Rva + (uint)chunk, low, high, found);
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static void Scan(ReadOnlySpan<byte> code, int limit, uint baseRva, uint low, uint high, Action<uint, uint> found)
    {
        // Opcode at p, REX prefix at p - 1, ModRM at p + 1 (mod 00, r/m 101: RIP-relative), disp32 at p + 2.
        int p = 1;
        while (p + 6 <= code.Length && p - 1 < limit)
        {
            int k = code[p..].IndexOfAny((byte)0x8B, (byte)0x8D);
            if (k < 0) return;
            p += k;
            if (p + 6 > code.Length || p - 1 >= limit) return;
            // REX.W with any of R and B (0x48, 0x49, 0x4C, 0x4D)
            if ((code[p - 1] & 0xFA) == 0x48 && (code[p + 1] & 0xC7) == 0x05)
            {
                uint site = baseRva + (uint)(p - 1);
                uint target = unchecked(site + 7 + (uint)BinaryPrimitives.ReadInt32LittleEndian(code.Slice(p + 2, 4)));
                if (target >= low && target <= high) found(site, target);
            }
            p++;
        }
    }
}
