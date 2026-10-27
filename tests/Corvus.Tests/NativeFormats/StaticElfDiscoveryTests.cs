using System.Buffers.Binary;
using Corvus.Native.Code;
using Corvus.Native.Elf;

namespace Corvus.Tests.NativeFormats;

/// <summary>Function discovery in fixed-address ELF executables without relocations (static musl builds).</summary>
public sealed class StaticElfDiscoveryTests
{
    private const ulong Base = 0x400000;
    private const uint Text = ElfWriter.TextRva;

    private static NativeCodeIndex Build(byte[] text, bool is64 = true, byte[]? data = null, List<(uint, uint)>? fdes = null) =>
        NativeCodeIndex.Build(ElfFile.FromBytes(new ElfWriter
        {
            Machine = is64 ? ElfWriter.EmX64 : ElfWriter.EmX86, Is64 = is64, Type = 2, Base = Base, Entry = Text, Text = text,
            Data = data ?? new byte[0x100], Hash = ElfWriter.HashKind.None, Fdes = fdes ?? [],
        }.Build(), "static"));

    private static string Starts(NativeCodeIndex index) => string.Join(", ", index.Functions.Select(f => $"0x{f.Start:X} {f.Sources}"));

    [Fact]
    public void Runs_of_code_pointers_in_data_are_functions_and_hlt_ends_one()
    {
        // entry: ret; f1: mov eax, 1; hlt (a crash path); f2: xor eax, eax; ret; each reached only through a table in .data
        var text = new byte[0x60];
        Array.Fill(text, (byte)0xFF);
        text[0] = 0xC3;
        uint f1 = Text + 0x20, f2 = Text + 0x40;
        new byte[] { 0xB8, 1, 0, 0, 0, 0xF4 }.CopyTo(text, 0x20);
        new byte[] { 0x31, 0xC0, 0xC3 }.CopyTo(text, 0x40);
        var data = new byte[0x100];
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x10), Base + f1);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x18), Base + f2);
        var index = Build(text, data: data);
        foreach (var f in new[] { f1, f2 })
            Assert.True(index.FunctionByStart(f)?.Sources.HasFlag(FunctionSource.DataPointer) == true, Starts(index));
        // A pointer standing alone is not taken without relocations.
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x18), 0);
        Assert.Null(Build(text, data: data).FunctionByStart(f1));
    }

    [Fact]
    public void A_jump_past_another_functions_start_is_a_tail_call()
    {
        // entry: nop; jmp t (over g, which unwind data declares); g: ret; t: xor eax, eax; ret
        var text = new byte[0x60];
        Array.Fill(text, (byte)0xFF);
        uint g = Text + 0x20, t = Text + 0x40;
        new byte[] { 0x90, 0xE9 }.CopyTo(text, 0);
        BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan(2), (int)(t - (Text + 6)));
        text[0x20] = 0xC3;
        new byte[] { 0x31, 0xC0, 0xC3 }.CopyTo(text, 0x40);
        var index = Build(text, fdes: [(g, 1)]);
        Assert.True(index.FunctionByStart(t)?.Sources.HasFlag(FunctionSource.TailJump) == true, Starts(index));
        Assert.Equal(Text + 6, index.FunctionByStart(Text)!.End);
    }

    [Fact]
    public void I386_position_independent_address_through_the_got_pointer_is_a_function()
    {
        // entry: call thunk; add ebx, 0x100 (ebx = rva 0x1105); lea eax, [ebx - 0xC5] (f); ret
        // thunk: mov ebx, [esp]; ret; f: xchg esi, eax; xor eax, eax; ret (one-byte xchg, as GCC -Os writes)
        var text = new byte[0x60];
        Array.Fill(text, (byte)0xFF);
        uint thunk = Text + 0x30, f = Text + 0x40;
        text[0] = 0xE8;
        BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan(1), (int)(thunk - (Text + 5)));
        new byte[] { 0x81, 0xC3, 0x00, 0x01, 0, 0 }.CopyTo(text, 5);
        new byte[] { 0x8D, 0x83 }.CopyTo(text, 11);
        BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan(13), (int)f - (int)(Text + 5 + 0x100));
        text[17] = 0xC3;
        new byte[] { 0x8B, 0x1C, 0x24, 0xC3 }.CopyTo(text, 0x30);
        new byte[] { 0x96, 0x31, 0xC0, 0xC3 }.CopyTo(text, 0x40);
        var index = Build(text, is64: false);
        Assert.True(index.FunctionByStart(f)?.Sources.HasFlag(FunctionSource.CodeAddress) == true, Starts(index));
    }

    [Fact]
    public void Code_after_a_function_and_its_nop_fill_is_scanned()
    {
        // entry: ret; nopw cs:[rax+rax] (GCC fill); f: push rbx; pop rbx; ret, which nothing references
        var text = new byte[0x40];
        Array.Fill(text, (byte)0xFF);
        text[0] = 0xC3;
        new byte[] { 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0, 0, 0, 0, 0 }.CopyTo(text, 1);
        new byte[] { 0x8D, 0x76, 0x00 }.CopyTo(text, 11);
        new byte[] { 0x53, 0x5B, 0xC3 }.CopyTo(text, 14);
        var index = Build(text);
        Assert.True(index.FunctionByStart(Text + 14)?.Sources.HasFlag(FunctionSource.CodeGap) == true, Starts(index));
    }
}
