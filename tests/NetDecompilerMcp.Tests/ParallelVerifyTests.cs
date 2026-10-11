using System.Buffers.Binary;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Tests;

/// <summary>Verifying data pointer candidates in parallel first gives the same index as verifying them one by one.</summary>
public sealed class ParallelVerifyTests
{
    [Theory]
    [InlineData(NativeArch.X64)]
    [InlineData(NativeArch.X86)]
    public void Parallel_verification_finds_the_same_functions(NativeArch arch)
    {
        const int Count = 3000, Stride = 16;
        bool is64 = arch == NativeArch.X64;
        var rng = new Random(7);
        var code = new byte[Count * Stride];
        Array.Fill(code, (byte)0xCC);
        for (int i = 0; i < Count; i++)
        {
            int at = i * Stride;
            switch (rng.Next(7))
            {
                case 0: new byte[] { 0x31, 0xC0, 0xC3 }.CopyTo(code, at); break; // xor eax, eax; ret
                case 1: // jmp to a later candidate (a tail call into the batch)
                    code[at] = 0xE9;
                    BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(at + 1), (int)((uint)Math.Min(Count - 1, i + 1 + rng.Next(3)) * Stride - (uint)(at + 5)));
                    break;
                case 2: Array.Fill(code, (byte)0x90, at, Stride); break; // nops into the next candidate
                case 3: new byte[] { 0xFF, 0xFF }.CopyTo(code, at); break; // invalid
                case 4: // call an earlier candidate; ret
                    code[at] = 0xE8;
                    BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(at + 1), (int)((uint)rng.Next(i + 1) * Stride - (uint)(at + 5)));
                    code[at + 5] = 0xC3;
                    break;
                case 5: new byte[] { 0x8B, 0x45, 0x08, 0xC3 }.CopyTo(code, at); break; // mov eax, [ebp+8]; ret (x86: a funclet)
                default: // jz into the middle of the previous candidate; ret
                    code[at] = 0x74;
                    code[at + 1] = unchecked((byte)(sbyte)-(Stride / 2 + 2));
                    code[at + 2] = 0xC3;
                    break;
            }
        }
        int ptr = is64 ? 8 : 4;
        var data = new byte[Count * ptr];
        var relocs = new List<uint>();
        ulong imageBase = is64 ? 0x140000000UL : 0x10000000UL;
        for (int i = 0; i < Count; i++)
        {
            ulong va = imageBase + CodeTestImage.SyntheticCodeRva + (ulong)(i * Stride);
            if (is64) BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(i * ptr), va);
            else BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(i * ptr), (uint)va);
            relocs.Add(CodeTestImage.SyntheticDataRva + (uint)(i * ptr));
        }
        var image = CodeTestImage.Synthetic(arch, code, data, relocations: relocs);
        static string Shape(NativeCodeIndex index) => string.Join("\n", index.Functions.Select(f =>
            $"{f.Start:X} {f.Sources} {f.Flags} {string.Join(",", index.Ranges(f).Select(r => $"{r.Start:X}-{r.End:X}"))}"));
        var parallel = NativeCodeIndex.Build(image, new CodeIndexOptions { ParallelVerifyBatch = 0 });
        var serial = NativeCodeIndex.Build(image, new CodeIndexOptions { ParallelVerifyBatch = int.MaxValue });
        Assert.True(serial.Functions.Count > Count / 4, Shape(serial));
        Assert.Equal(Shape(serial), Shape(parallel));
    }
}
