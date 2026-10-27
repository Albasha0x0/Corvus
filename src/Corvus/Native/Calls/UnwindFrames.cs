using System.Buffers.Binary;
using Corvus.Native.Pe;

namespace Corvus.Native.Calls;

/// <summary>A function's frame from its unwind data: allocation, saved registers, frame pointer, prolog size and flags.</summary>
/// <param name="Format">x64 UNWIND_INFO, ARM64 packed or ARM64 xdata; DWARF CFI or compact unwind on ELF and Mach-O.</param>
/// <param name="Allocation">Bytes the prolog allocates below the saved registers (x64), or the whole frame (ARM64).</param>
public sealed record UnwindFrame(string Format, uint Begin, uint End, int PrologBytes, long Allocation, IReadOnlyList<string> Saved, string? FramePointer,
    IReadOnlyList<string> Notes);

/// <summary>Reads x64 UNWIND_INFO and ARM64 .pdata / .xdata records into <see cref="UnwindFrame"/>s.</summary>
public static class UnwindFrames
{
    private const int MaxChain = 4;
    private static readonly string[] X64Registers = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];

    /// <summary>The unwind data of the function covering <paramref name="rva"/>, or null when the image has none for it.</summary>
    public static UnwindFrame? Of(INativeImage image, uint rva)
    {
        if (image.Format != ImageFormat.Pe) return Itanium.ItaniumEh.Frame(image, rva);
        var table = image.RuntimeFunctions;
        int lo = 0, hi = table.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            var f = table[mid];
            if (rva < f.BeginRva) hi = mid - 1;
            else if (rva >= f.EndRva) lo = mid + 1;
            else return image.Arch switch
            {
                NativeArch.X64 => X64(image, f),
                NativeArch.Arm64 => f.UnwindInfoRva != 0 ? Xdata(image, f) : Packed(image, f),
                _ => null,
            };
        }
        return null;
    }

    private static UnwindFrame? X64(INativeImage image, RuntimeFunction function)
    {
        var saved = new List<string>();
        var notes = new List<string>();
        long allocation = 0;
        string? frame = null;
        int prolog = 0;
        var fn = function;
        Span<byte> head = stackalloc byte[4];
        for (int level = 0; level < MaxChain; level++)
        {
            if (image.Read(fn.UnwindInfoRva, head) < 4) return null;
            int count = head[2];
            var body = new byte[4 + (count + 1) / 2 * 4 + 12];
            int n = image.Read(fn.UnwindInfoRva, body);
            if (n < 4 + count * 2) return null;
            byte flags = (byte)(head[0] >> 3);
            if (level == 0)
            {
                prolog = head[1];
                if ((flags & 3) != 0) notes.Add((flags & 1) != 0 ? "has an exception handler" : "has a termination handler");
            }
            if ((head[3] & 0xF) is var reg and not 0) frame = $"{X64Registers[reg]} = rsp + 0x{(head[3] >> 4) * 16:X}";
            ushort Code(int i) => BinaryPrimitives.ReadUInt16LittleEndian(body.AsSpan(4 + i * 2));
            for (int i = 0; i < count;)
            {
                int op = (Code(i) >> 8) & 0xF, info = Code(i) >> 12;
                switch (op)
                {
                    case 0: saved.Add(X64Registers[info]); i += 1; break;
                    case 1:
                        allocation += info == 0 ? Code(i + 1) * 8L : Code(i + 1) | (long)Code(i + 2) << 16;
                        i += info == 0 ? 2 : 3;
                        break;
                    case 2: allocation += info * 8 + 8; i += 1; break;
                    case 3: i += 1; break;
                    case 4: saved.Add($"{X64Registers[info]} at [rsp+{Code(i + 1) * 8:X}h]"); i += 2; break;
                    case 5: saved.Add($"{X64Registers[info]} at [rsp+{Code(i + 1) | Code(i + 2) << 16:X}h]"); i += 3; break;
                    case 6: i += 2; break;
                    case 7: i += 3; break;
                    case 8: saved.Add($"xmm{info} at [rsp+{Code(i + 1) * 16:X}h]"); i += 2; break;
                    case 9: saved.Add($"xmm{info} at [rsp+{Code(i + 1) | Code(i + 2) << 16:X}h]"); i += 3; break;
                    case 10: notes.Add(info == 0 ? "pushes a machine frame (an interrupt or exception handler)" : "pushes a machine frame with an error code"); i += 1; break;
                    default: notes.Add($"unknown unwind code {op}"); i = count; break;
                }
            }
            if ((flags & 4) == 0) break;
            int at = 4 + ((count + 1) & ~1) * 2;
            if (n < at + 12) break;
            fn = new RuntimeFunction(BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(at)), BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(at + 4)),
                BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(at + 8)));
            notes.Add($"chained to the unwind data of 0x{image.ImageBase + fn.BeginRva:X} (a separated part of a larger function)");
        }
        return new UnwindFrame("x64 UNWIND_INFO", function.BeginRva, function.EndRva, prolog, allocation, saved, frame, notes);
    }

    /// <summary>The second word of the .pdata entry of <paramref name="function"/> (packed unwind data).</summary>
    private static uint? PdataWord(INativeImage image, RuntimeFunction function)
    {
        if (image is not PeFile pe || pe.Directory(PeDirectory.Exception) is not { IsPresent: true } dir) return null;
        int lo = 0, hi = (int)(dir.Size / 8) - 1;
        Span<byte> entry = stackalloc byte[8];
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (image.Read(dir.Rva + (uint)mid * 8, entry) < 8) return null;
            uint begin = BinaryPrimitives.ReadUInt32LittleEndian(entry);
            if (begin == function.BeginRva) return BinaryPrimitives.ReadUInt32LittleEndian(entry[4..]);
            if (begin < function.BeginRva) lo = mid + 1;
            else hi = mid - 1;
        }
        return null;
    }

    /// <summary>ARM64 packed unwind data (RegI, RegF, H, CR, FrameSize in 16-byte units) as a frame.</summary>
    private static UnwindFrame? Packed(INativeImage image, RuntimeFunction function)
    {
        if (PdataWord(image, function) is not { } w || (w & 3) == 0) return null;
        int regF = (int)(w >> 13) & 7, regI = (int)(w >> 16) & 0xF, cr = (int)(w >> 21) & 3;
        bool homes = (w >> 20 & 1) != 0;
        long frame = (w >> 23) * 16L;
        var saved = new List<string>();
        if (regI > 0) saved.Add(regI == 1 ? "x19" : $"x19-x{18 + regI}");
        if (cr == 1) saved.Add("lr");
        if (regF > 0) saved.Add($"d8-d{8 + regF}");
        if (cr == 3) saved.Add("fp, lr");
        var notes = new List<string>();
        if (homes) notes.Add("homes x0-x7 (the parameters are stored to the frame)");
        if (cr == 2) notes.Add("signs the return address (pac)");
        if ((w & 3) == 2) notes.Add("a fragment without its own prolog");
        return new UnwindFrame("ARM64 packed", function.BeginRva, function.EndRva, 0, frame, saved, cr == 3 ? "x29 = sp (chained frame record)" : null, notes);
    }

    private static UnwindFrame? Xdata(INativeImage image, RuntimeFunction function)
    {
        Span<byte> word = stackalloc byte[4];
        uint at = function.UnwindInfoRva;
        if (image.Read(at, word) < 4) return null;
        uint header = BinaryPrimitives.ReadUInt32LittleEndian(word);
        int epilogs = (int)(header >> 22) & 0x1F, codeWords = (int)(header >> 27) & 0x1F;
        bool single = (header >> 21 & 1) != 0, handler = (header >> 20 & 1) != 0;
        at += 4;
        if (epilogs == 0 && codeWords == 0)
        {
            if (image.Read(at, word) < 4) return null;
            uint extended = BinaryPrimitives.ReadUInt32LittleEndian(word);
            epilogs = (int)(extended & 0xFFFF);
            codeWords = (int)(extended >> 16) & 0xFF;
            at += 4;
        }
        if (!single) at += (uint)epilogs * 4;
        var codes = new byte[codeWords * 4];
        if (image.Read(at, codes) < codes.Length) return null;
        var saved = new List<string>();
        var notes = new List<string>();
        string? frame = null;
        long allocation = 0;
        int i = 0, prolog = 0;
        string X(int n) => n == 29 ? "fp" : $"x{n}";
        while (i < codes.Length)
        {
            byte b = codes[i];
            int next = i + 1 < codes.Length ? codes[i + 1] : 0;
            prolog++;
            if (b < 0x20) { allocation += (b & 0x1F) * 16; i += 1; }
            else if (b < 0x40) { saved.Add("x19, x20"); allocation += (b & 0x1F) * 8; i += 1; }
            else if (b < 0x80) { saved.Add("fp, lr"); i += 1; }
            else if (b < 0xC0) { saved.Add("fp, lr"); allocation += ((b & 0x3F) + 1) * 8; i += 1; }
            else if (b < 0xC8) { allocation += ((b & 7) << 8 | next) * 16; i += 2; }
            else if (b < 0xD0)
            {
                int reg = 19 + ((b & 3) << 2 | next >> 6);
                saved.Add($"{X(reg)}, {X(reg + 1)}");
                if (b >= 0xCC) allocation += ((next & 0x3F) + 1) * 8;
                i += 2;
            }
            else if (b < 0xD4) { saved.Add(X(19 + ((b & 3) << 2 | next >> 6))); i += 2; }
            else if (b < 0xD6) { saved.Add(X(19 + ((b & 1) << 3 | next >> 5))); allocation += ((next & 0x1F) + 1) * 8; i += 2; }
            else if (b < 0xD8) { saved.Add($"{X(19 + 2 * ((b & 1) << 2 | next >> 6))}, lr"); i += 2; }
            else if (b < 0xDE)
            {
                int reg = 8 + ((b & 1) << 2 | next >> 6);
                saved.Add(b < 0xDC ? $"d{reg}, d{reg + 1}" : $"d{reg}");
                if (b is 0xDA or 0xDB) allocation += ((next & 0x3F) + 1) * 8;
                i += 2;
            }
            else if (b == 0xDE) { saved.Add($"d{8 + (next >> 5)}"); allocation += ((next & 0x1F) + 1) * 8; i += 2; }
            else if (b == 0xE0)
            {
                if (i + 3 >= codes.Length) break;
                allocation += (codes[i + 1] << 16 | codes[i + 2] << 8 | codes[i + 3]) * 16L;
                i += 4;
            }
            else if (b == 0xE1) { frame = "x29 = sp"; i += 1; }
            else if (b == 0xE2) { frame = $"x29 = sp + 0x{next * 8:X}"; i += 2; }
            else if (b is 0xE4 or 0xE5) break;
            else if (b == 0xE7) i += 3;
            else i += 1;
        }
        if (handler) notes.Add("has an exception handler");
        return new UnwindFrame("ARM64 xdata", function.BeginRva, function.EndRva, prolog * 4, allocation, saved, frame, notes);
    }
}
