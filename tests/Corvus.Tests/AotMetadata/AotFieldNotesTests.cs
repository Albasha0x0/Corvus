using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Native.Code;
using Corvus.Services;
using Corvus.Tests.NativeFormats;
using Corvus.Tools;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Corvus.Tests;

/// <summary>Operands based on the first argument register are named after the owning type's metadata fields.</summary>
public sealed class AotFieldNotesTests : IDisposable
{
    private const string Source = """
        using System;
        namespace Il2CppDummyDll
        {
            public class FieldOffsetAttribute : Attribute { public string Offset; }
            public class AddressAttribute : Attribute { public string RVA; public string Offset; public string VA; }
        }
        namespace Fixture.Native
        {
            using Il2CppDummyDll;
            public class StreamHost
            {
                [FieldOffset(Offset = "0x48")] public object mReadMemStream;
                [Address(RVA = "0x1000", Offset = "0x400", VA = "0x180001000")]
                public void Read() { }
            }
        }
        """;

    private const string ScriptJson = """
        {
          "ScriptMethod": [ { "Address": 4096, "Name": "Fixture.Native.StreamHost$$Read" } ],
          "ScriptMetadata": []
        }
        """;

    // Windows x64: this in rcx, copied to rbx; rdx and a gap offset are not fields.
    private static readonly byte[] X64Code =
    [
        // 1000 mov rax, [rcx+48h]
        0x48, 0x8B, 0x41, 0x48,
        // 1004 mov rbx, rcx
        0x48, 0x89, 0xCB,
        // 1007 mov rdx, [rbx+48h]
        0x48, 0x8B, 0x53, 0x48,
        // 100B mov rax, [rdx+48h]
        0x48, 0x8B, 0x42, 0x48,
        // 100F mov rax, [rcx+40h]
        0x48, 0x8B, 0x41, 0x40,
        // 1013 ret
        0xC3,
    ];

    // System V x64: this in rdi, copied to rbx.
    private static readonly byte[] ElfCode =
    [
        // 1000 mov rax, [rdi+48h]
        0x48, 0x8B, 0x47, 0x48,
        // 1004 mov rbx, rdi
        0x48, 0x89, 0xFB,
        // 1007 mov rdx, [rbx+48h]
        0x48, 0x8B, 0x53, 0x48,
        // 100B mov rax, [rdx+48h]
        0x48, 0x8B, 0x42, 0x48,
        // 100F ret
        0xC3,
    ];

    // A field read, a copy into rdx, a call, then reads through rdx and rcx.
    private static readonly byte[] CallCode =
    [
        // 1000 mov rax, [rcx+48h]
        0x48, 0x8B, 0x41, 0x48,
        // 1004 mov rdx, rcx
        0x48, 0x89, 0xCA,
        // 1007 call 1100
        0xE8, 0xF4, 0x00, 0x00, 0x00,
        // 100C mov rax, [rdx+48h]
        0x48, 0x8B, 0x42, 0x48,
        // 1010 mov rax, [rcx+48h]
        0x48, 0x8B, 0x41, 0x48,
        // 1014 ret
        0xC3,
    ];

    // A field read, rcx cleared, then a read through it.
    private static readonly byte[] WriteCode =
    [
        // 1000 mov rax, [rcx+48h]
        0x48, 0x8B, 0x41, 0x48,
        // 1004 xor rcx, rcx
        0x48, 0x31, 0xC9,
        // 1007 mov rax, [rcx+48h]
        0x48, 0x8B, 0x41, 0x48,
        // 100B ret
        0xC3,
    ];

    // An rbx copy read on the fall-through path and at the jz target.
    private static readonly byte[] SavedCopyAtTargetCode =
    [
        // 1000 mov rbx, rcx
        0x48, 0x89, 0xCB,
        // 1003 test rdx, rdx
        0x48, 0x85, 0xD2,
        // 1006 jz 100C
        0x74, 0x04,
        // 1008 mov rax, [rbx+48h]
        0x48, 0x8B, 0x43, 0x48,
        // 100C mov rdx, [rbx+48h]
        0x48, 0x8B, 0x53, 0x48,
        // 1010 ret
        0xC3,
    ];

    // An rbx copy read in an else block that follows a jmp.
    private static readonly byte[] SavedCopyAfterJumpCode =
    [
        // 1000 mov rbx, rcx
        0x48, 0x89, 0xCB,
        // 1003 test rdx, rdx
        0x48, 0x85, 0xD2,
        // 1006 jz 100E
        0x74, 0x06,
        // 1008 mov rax, [rbx+48h]
        0x48, 0x8B, 0x43, 0x48,
        // 100C jmp 1012
        0xEB, 0x04,
        // 100E mov rdx, [rbx+48h]
        0x48, 0x8B, 0x53, 0x48,
        // 1012 ret
        0xC3,
    ];

    // An rdx copy read on the fall-through path and at the jz target.
    private static readonly byte[] VolatileCopyAtTargetCode =
    [
        // 1000 mov rdx, rcx
        0x48, 0x89, 0xCA,
        // 1003 test rbx, rbx
        0x48, 0x85, 0xDB,
        // 1006 jz 100C
        0x74, 0x04,
        // 1008 mov rax, [rdx+48h]
        0x48, 0x8B, 0x42, 0x48,
        // 100C mov rax, [rdx+48h]
        0x48, 0x8B, 0x42, 0x48,
        // 1010 ret
        0xC3,
    ];

    // No write to rcx and no call: it still holds this at the jz target.
    private static readonly byte[] UnwrittenThisAtTargetCode =
    [
        // 1000 test rdx, rdx
        0x48, 0x85, 0xD2,
        // 1003 jz 1009
        0x74, 0x04,
        // 1005 mov rax, [rcx+48h]
        0x48, 0x8B, 0x41, 0x48,
        // 1009 mov rdx, [rcx+48h]
        0x48, 0x8B, 0x51, 0x48,
        // 100D ret
        0xC3,
    ];

    // AAPCS64: this in x0, copied to x19; x4 and a gap offset are not fields.
    private static readonly byte[] Arm64Code = Words(
        // 1000 mov x19, x0
        0xAA0003F3,
        // 1004 ldr x1, [x0, #0x48]
        0xF9402401,
        // 1008 ldr x2, [x19, #0x48]
        0xF9402662,
        // 100C ldr x3, [x4, #0x48]
        0xF9402483,
        // 1010 ldr x5, [x0, #0x40]
        0xF9402005,
        // 1014 ret
        0xD65F03C0);

    private readonly TempDir _dir = new();

    public void Dispose()
    {
        foreach (var env in _envs) env.Dispose();
        _dir.Dispose();
    }

    private static byte[] Words(params uint[] words) => words.SelectMany(BitConverter.GetBytes).ToArray();

    private readonly List<Env> _envs = [];

    private (Env Env, NativeCodeService Service, LoadedNative Native, NativeCodeIndex Index) Open(byte[] code, ushort machine, bool elf = false, string? source = null)
    {
        var dump = Path.Combine(_dir.Path, "dump" + _envs.Count);
        var dummies = Path.Combine(dump, "DummyDll");
        Directory.CreateDirectory(dummies);
        var dll = Path.Combine(dummies, "Fixture.dll");
        File.WriteAllBytes(dll, Roslyn.Compile("Fixture", source ?? Source, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary)));
        File.WriteAllText(Path.Combine(dump, "script.json"), ScriptJson);
        File.WriteAllText(Path.Combine(dump, "stringliteral.json"), "[]");

        var text = Enumerable.Repeat((byte)0xCC, 0x200).ToArray();
        code.CopyTo(text, 0);
        string binary;
        if (elf)
        {
            binary = Path.Combine(dump, "GameAssembly.so");
            File.WriteAllBytes(binary, new ElfWriter { Machine = ElfWriter.EmX64, Type = 3, Base = 0, Entry = ElfWriter.TextRva, Text = text }.Build());
        }
        else
        {
            var b = new PeBuilder { ImageBase = 0x180000000, Machine = machine };
            b.EntryPoint = b.Add(".text", text, 0x60000020).Rva;
            b.Add(".data", new byte[0x100], 0xC0000040);
            binary = Path.Combine(dump, "GameAssembly.dll");
            File.WriteAllBytes(binary, b.Build());
        }

        var env = new Env(dll);
        _envs.Add(env);
        var service = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(_dir.File("ann" + _envs.Count)));
        var native = env.Workspace.LoadAny(binary).Native!;
        var index = service.Index(native, null, default).GetAwaiter().GetResult();
        new AotNativeNames(env.AotMetadata, env.AotNavigator, service).Apply(native, index, env.Workspace.Assemblies, default);
        return (env, service, native, index);
    }

    private Dictionary<uint, string> Notes(byte[] code, ushort machine = 0x8664, bool elf = false, string? source = null)
    {
        var (_, _, native, index) = Open(code, machine, elf, source);
        return AotFieldNotes.Comments(native, index, index.FunctionAt(0x1000)!, default);
    }

    [Fact]
    public void An_x64_operand_on_this_or_its_copy_is_named_after_the_field_at_that_offset()
    {
        var notes = Notes(X64Code);
        Assert.Contains("mReadMemStream", notes[0x1000]);
        Assert.Contains("mReadMemStream", notes[0x1007]);
        Assert.Equal(2, notes.Count);
    }

    [Fact]
    public void An_arm64_operand_on_this_or_its_copy_is_named_after_the_field_at_that_offset()
    {
        var notes = Notes(Arm64Code, 0xAA64);
        Assert.Contains("mReadMemStream", notes[0x1004]);
        Assert.Contains("mReadMemStream", notes[0x1008]);
        Assert.Equal(2, notes.Count);
    }

    [Fact]
    public void An_x64_elf_operand_on_rdi_or_its_copy_is_named_after_the_field()
    {
        Assert.Equal([0x1000u, 0x1007u], Notes(ElfCode, elf: true).Keys.Order());
    }

    [Fact]
    public async Task Disassemble_shows_the_field_note_on_the_operand()
    {
        var (env, service, native, _) = Open(ElfCode, 0, elf: true);
        var listing = await new NativeCodeTools(env.Workspace, service, env.Pager).Disassemble(native.Id, "Fixture_Native_StreamHost__Read");
        Assert.Contains("this->mReadMemStream (StreamHost+0x48)", listing);
    }

    [Fact]
    public void A_copy_in_a_volatile_register_is_dropped_after_a_call()
    {
        Assert.Equal([0x1000u], Notes(CallCode).Keys.Order());
    }

    [Fact]
    public void This_is_dropped_after_a_write_to_its_register()
    {
        Assert.Equal([0x1000u], Notes(WriteCode).Keys.Order());
    }

    [Fact]
    public void A_callee_saved_copy_survives_a_conditional_branch_target()
    {
        Assert.Equal([0x1008u, 0x100Cu], Notes(SavedCopyAtTargetCode).Keys.Order());
    }

    [Fact]
    public void A_callee_saved_copy_survives_into_a_block_that_follows_a_jump()
    {
        Assert.Equal([0x1008u, 0x100Eu], Notes(SavedCopyAfterJumpCode).Keys.Order());
    }

    [Fact]
    public void A_volatile_copy_is_dropped_at_a_branch_target()
    {
        Assert.Equal([0x1008u], Notes(VolatileCopyAtTargetCode).Keys.Order());
    }

    [Fact]
    public void An_unwritten_this_register_survives_a_branch_target()
    {
        Assert.Equal([0x1005u, 0x1009u], Notes(UnwrittenThisAtTargetCode).Keys.Order());
    }

    [Theory]
    [InlineData("public void Read()", "public static void Read()")]
    [InlineData("public class StreamHost", "public struct StreamHost")]
    [InlineData("public class StreamHost", "public class StreamHost<T>")]
    public void Static_value_type_and_generic_owners_get_no_notes(string from, string to)
    {
        Assert.Empty(Notes(X64Code, source: Source.Replace(from, to)));
    }
}
