using Corvus.Services;
using Corvus.Tools;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>Calls to a slot-indexed virtual call helper are named after the method in that vtable slot.</summary>
public sealed partial class AotFieldNotesTests
{
    private const string SlotSource = """
        using System;
        namespace Il2CppDummyDll
        {
            public class FieldOffsetAttribute : Attribute { public string Offset; }
            public class AddressAttribute : Attribute { public string RVA; public string Offset; public string VA; public string Slot; }
        }
        namespace Fixture.Native
        {
            using Il2CppDummyDll;
            public class BinaryReader
            {
                [Address(Slot = "25")] public virtual byte[] ReadBytes(int count) { return null; }
            }
            public class StreamHost
            {
                [FieldOffset(Offset = "0x48")] public BinaryReader mReader;
                [Address(Slot = "3")] public virtual void Dispatch() { }
                [Address(RVA = "0x1000", Offset = "0x400", VA = "0x180001000")]
                public void Read(BinaryReader reader) { }
            }
        }
        """;

    private static byte[] SlotCode(Action<Assembler> caller)
    {
        var code = Enumerable.Repeat((byte)0xCC, 0x80).ToArray();
        byte[] Assemble(uint rva, Action<Assembler> build)
        {
            var a = new Assembler(64);
            build(a);
            var stream = new MemoryStream();
            a.Assemble(new StreamCodeWriter(stream), 0x180000000UL + rva);
            return stream.ToArray();
        }
        Assemble(0x1000, caller).CopyTo(code, 0);
        Assemble(0x1040, a =>
        {
            a.mov(rax, __qword_ptr[rdx]);
            a.shl(ecx, 4);
            a.movsxd(rcx, ecx);
            a.add(rax, rcx);
            a.mov(rcx, rdx);
            a.jmp(__qword_ptr[rax + 0x138]);
        }).CopyTo(code, 0x40);
        return code;
    }

    private Dictionary<uint, string> SlotNotes(Action<Assembler> caller)
    {
        var (_, _, native, index) = Open(SlotCode(caller), 0x8664, source: SlotSource);
        return AotSlotNotes.Comments(native, index, index.FunctionAt(0x1000)!, default);
    }

    private const ulong Helper = 0x180000000UL + 0x1040;

    [Fact]
    public void A_receiver_loaded_from_a_field_names_the_method_in_the_slot()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rdx, __qword_ptr[rcx + 0x48]);
            a.mov(ecx, 25);
            a.call(Helper);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Equal("BinaryReader::ReadBytes (slot 25)", Assert.Single(notes).Value);
    }

    [Fact]
    public void A_receiver_that_is_this_names_the_method_in_the_slot()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rdx, rcx);
            a.mov(ecx, 3);
            a.call(Helper);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Equal("StreamHost::Dispatch (slot 3)", Assert.Single(notes).Value);
    }

    [Fact]
    public void A_receiver_that_is_a_typed_parameter_names_the_method_in_the_slot()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(ecx, 25);
            a.call(Helper);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Equal("BinaryReader::ReadBytes (slot 25)", Assert.Single(notes).Value);
    }

    [Fact]
    public void An_unknown_receiver_lists_the_slot_and_the_candidate_count()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rdx, r8);
            a.mov(ecx, 25);
            a.call(Helper);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Equal("virtual call, slot 25, receiver unknown, 1 candidates", Assert.Single(notes).Value);
    }

    [Fact]
    public void A_receiver_of_known_type_with_no_method_in_the_slot_is_reported_as_unknown()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(ecx, 7);
            a.call(Helper);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Equal("BinaryReader slot 7: method unknown", Assert.Single(notes).Value);
    }

    [Fact]
    public void A_slot_that_is_not_a_constant_gets_no_note()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(ecx, r8d);
            a.call(Helper);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_register_overwritten_by_a_call_gets_no_note()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(ecx, 25);
            a.call(0x180000000UL + 0x1060);
            a.call(Helper);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_branch_target_drops_tracked_values()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(ecx, 25);
            var join = a.CreateLabel();
            a.jmp(join);
            a.nop();
            a.Label(ref join);
            a.call(Helper);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_byte_write_to_the_slot_register_gets_no_note()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(ecx, 25);
            a.mov(cl, 3);
            a.call(Helper);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_slot_outside_the_index_range_gets_no_note()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rcx, 0x100000019L);
            a.call(Helper);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_slot_with_no_metadata_method_and_unknown_receiver_says_so()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rdx, r8);
            a.mov(ecx, 99);
            a.call(Helper);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Equal("virtual call, slot 99, receiver unknown, no metadata method in slot 99", Assert.Single(notes).Value);
    }

    [Fact]
    public async Task Disassemble_lists_the_slot_note_on_the_helper_call()
    {
        var (env, service, native, _) = Open(SlotCode(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rdx, __qword_ptr[rcx + 0x48]);
            a.mov(ecx, 25);
            a.call(Helper);
            a.add(rsp, 0x28); a.ret();
        }), 0x8664, source: SlotSource);
        var listing = await new NativeCodeTools(env.Workspace, service, env.Pager).Disassemble(native.Id, "Fixture_Native_StreamHost__Read");
        Assert.Contains("BinaryReader::ReadBytes (slot 25)", listing);
    }
}
