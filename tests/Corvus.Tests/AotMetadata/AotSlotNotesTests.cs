using Corvus.Native.Providers;
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
        // A callee that returns, so the code after a call to it belongs to the caller.
        code[0x60] = 0xC3;
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
    public void A_direct_call_through_the_class_pointer_names_the_method_in_the_slot()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rax, __qword_ptr[rcx]);
            a.call(__qword_ptr[rax + 0x138 + 16 * 3]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Equal("StreamHost::Dispatch (slot 3)", Assert.Single(notes).Value);
    }

    [Fact]
    public void A_call_through_a_register_loaded_from_the_class_pointer_names_the_method_in_the_slot()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rdx, __qword_ptr[rcx]);
            a.mov(rax, __qword_ptr[rdx + 0x138 + 16 * 3]);
            a.call(rax);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Equal("StreamHost::Dispatch (slot 3)", Assert.Single(notes).Value);
    }

    [Fact]
    public void A_register_overwritten_between_the_slot_load_and_the_call_has_no_note()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rbx, __qword_ptr[rcx]);
            a.mov(rax, __qword_ptr[rbx + 0x138 + 16 * 3]);
            a.mov(rax, r8);
            a.call(rax);
            a.mov(rax, __qword_ptr[rbx + 0x138 + 16 * 3]);
            a.call(rax);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Equal(0x101Au, Assert.Single(notes).Key);
    }

    [Fact]
    public void A_32_bit_copy_of_a_slot_entry_gets_no_note()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rdx, __qword_ptr[rcx]);
            a.mov(rax, __qword_ptr[rdx + 0x138 + 16 * 3]);
            a.mov(eax, eax);
            a.call(rax);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    private async Task<NativeVirtualCallTools.VirtualCallReport> SlotReport(string? status, int offset = 0, int limit = 100)
    {
        var (env, service, native, _) = Open(SlotCode(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rbx, __qword_ptr[rcx]);
            a.mov(rdx, __qword_ptr[rcx + 0x48]);
            a.mov(ecx, 25);
            a.call(Helper);
            a.call(__qword_ptr[rbx + 0x138 + 16 * 3]);
            a.mov(rdx, r8);
            a.mov(ecx, 99);
            a.call(Helper);
            a.add(rsp, 0x28); a.ret();
        }), 0x8664, source: SlotSource);
        return await new NativeVirtualCallTools(env.Workspace, service)
            .Report(native.Id, "Fixture_Native_StreamHost__Read", status, offset, limit);
    }

    [Fact]
    public async Task The_status_filter_keeps_the_slot_calls_of_that_status()
    {
        var exact = await SlotReport("exact");
        Assert.Equal(2, exact.Total);
        Assert.All(exact.Items, r => Assert.Equal("exact", r.Status));
        var unresolved = await SlotReport("unresolved");
        var row = Assert.Single(unresolved.Items);
        Assert.Equal(99, row.Slot);
        Assert.Equal("receiver_unknown", row.Reason);
        Assert.Equal("unknown", row.Receiver);
    }

    [Fact]
    public async Task Paging_continues_across_the_slot_calls()
    {
        var first = await SlotReport(null, 0, 2);
        Assert.Equal(3, first.Total);
        Assert.True(first.Truncated);
        var rest = await SlotReport(null, 2, 2);
        Assert.Single(rest.Items);
        Assert.False(rest.Truncated);
    }

    // The slot calls that disassemble notes are the ones find_virtual_calls lists.
    [Fact]
    public async Task Find_virtual_calls_lists_each_slot_call_of_a_function_with_slot_and_method()
    {
        var (env, service, native, _) = Open(SlotCode(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rbx, __qword_ptr[rcx]);
            a.mov(rdx, __qword_ptr[rcx + 0x48]);
            a.mov(ecx, 25);
            a.call(Helper);
            a.call(__qword_ptr[rbx + 0x138 + 16 * 3]);
            a.add(rsp, 0x28); a.ret();
        }), 0x8664, source: SlotSource);
        var report = await new NativeVirtualCallTools(env.Workspace, service)
            .Report(native.Id, "Fixture_Native_StreamHost__Read");
        Assert.Equal(2, report.Total);
        Assert.Contains(report.Items, r => r.Slot == 3 && r.Status == "exact" && r.Targets.Single() == "StreamHost::Dispatch (slot 3)");
        Assert.Contains(report.Items, r => r.Slot == 25 && r.Class == "BinaryReader" && r.Targets.Single() == "BinaryReader::ReadBytes (slot 25)");
    }

    [Fact]
    public void A_call_offset_below_the_vtable_start_has_no_note()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rax, __qword_ptr[rcx]);
            a.call(__qword_ptr[rax + 0x138 - 8]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_call_offset_off_a_slot_boundary_has_no_note()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rax, __qword_ptr[rcx]);
            a.call(__qword_ptr[rax + 0x138 + 5]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_call_through_a_register_that_is_not_a_class_pointer_has_no_note()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rax, r8);
            a.call(__qword_ptr[rax + 0x138 + 16 * 3]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_class_pointer_overwritten_before_the_call_has_no_note()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rax, __qword_ptr[rcx]);
            a.mov(rax, r8);
            a.call(__qword_ptr[rax + 0x138 + 16 * 3]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_truncated_class_pointer_gets_no_note()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rax, __qword_ptr[rcx]);
            a.mov(edx, eax);
            a.call(__qword_ptr[rdx + 0x138 + 16 * 3]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void The_vtable_start_is_0x128_below_metadata_24_2_and_0x138_from_it()
    {
        Assert.Equal(0x128, AotSlotNotes.VtableStart(24.1f));
        Assert.Equal(0x138, AotSlotNotes.VtableStart(24.2f));
        Assert.Equal(0x138, AotSlotNotes.VtableStart(29f));
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
    public void A_backward_branch_target_drops_tracked_values()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(ecx, 25);
            var join = a.CreateLabel();
            a.Label(ref join);
            a.call(Helper);
            a.cmp(__byte_ptr[rsp + 0x20], 0);
            a.jne(join);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_target_reached_only_by_a_forward_jump_keeps_the_values_at_the_jump()
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
        Assert.Equal("BinaryReader::ReadBytes (slot 25)", Assert.Single(notes).Value);
    }

    private static void InitPrologue(Assembler a, Action<Assembler> initPath)
    {
        a.push(rbx);
        a.sub(rsp, 0x20);
        a.mov(rbx, rcx);
        var join = a.CreateLabel();
        a.cmp(__byte_ptr[rsp + 0x28], 0);
        a.jne(join);
        initPath(a);
        a.Label(ref join);
        a.mov(rax, __qword_ptr[rbx]);
        a.call(__qword_ptr[rax + 0x138 + 16 * 3]);
        a.add(rsp, 0x20); a.pop(rbx); a.ret();
    }

    [Fact]
    public void A_receiver_in_a_preserved_register_survives_an_init_call_and_the_join()
    {
        var notes = SlotNotes(a => InitPrologue(a, p => p.call(0x180000000UL + 0x1060)));
        Assert.Equal("StreamHost::Dispatch (slot 3)", Assert.Single(notes).Value);
    }

    // A setup call sits between the class pointer load and the slot call.
    [Fact]
    public void A_receiver_in_a_preserved_register_keeps_its_note_across_a_class_setup_call()
    {
        var notes = SlotNotes(a =>
        {
            a.push(rdi);
            a.sub(rsp, 0x20);
            a.mov(rdi, rcx);
            a.mov(rcx, __qword_ptr[rdi]);
            a.call(0x180000000UL + 0x1060);
            a.mov(rax, __qword_ptr[rdi]);
            a.call(__qword_ptr[rax + 0x138 + 16 * 3]);
            a.add(rsp, 0x20); a.pop(rdi); a.ret();
        });
        Assert.Equal("StreamHost::Dispatch (slot 3)", Assert.Single(notes).Value);
    }

    [Fact]
    public void A_join_where_one_predecessor_overwrote_the_receiver_has_no_note()
    {
        var notes = SlotNotes(a => InitPrologue(a, p => p.xor(ebx, ebx)));
        Assert.Empty(notes);
    }

    [Fact]
    public void Code_after_a_return_starts_from_the_state_at_the_branch_to_it()
    {
        var notes = SlotNotes(a =>
        {
            a.push(rbx);
            a.sub(rsp, 0x20);
            a.mov(rbx, rcx);
            var join = a.CreateLabel();
            a.cmp(__byte_ptr[rsp + 0x28], 0);
            a.jne(join);
            a.add(rsp, 0x20); a.pop(rbx); a.ret();
            a.Label(ref join);
            a.mov(rax, __qword_ptr[rbx]);
            a.call(__qword_ptr[rax + 0x138 + 16 * 3]);
            a.add(rsp, 0x20); a.pop(rbx); a.ret();
        });
        Assert.Equal("StreamHost::Dispatch (slot 3)", Assert.Single(notes).Value);
    }

    [Fact]
    public void Two_forward_branches_with_different_receivers_leave_no_note()
    {
        var notes = SlotNotes(a =>
        {
            a.push(rbx);
            a.sub(rsp, 0x20);
            a.mov(rbx, rcx);
            var join = a.CreateLabel();
            a.cmp(__byte_ptr[rsp + 0x28], 0);
            a.jne(join);
            a.mov(rbx, rdx);
            a.cmp(__byte_ptr[rsp + 0x29], 0);
            a.jne(join);
            a.xor(ebx, ebx);
            a.Label(ref join);
            a.mov(rax, __qword_ptr[rbx]);
            a.call(__qword_ptr[rax + 0x138 + 16 * 3]);
            a.add(rsp, 0x20); a.pop(rbx); a.ret();
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

    [Fact]
    public void The_slot_note_becomes_an_engine_mark_at_the_helper_call()
    {
        var (_, _, native, index) = Open(SlotCode(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rdx, __qword_ptr[rcx + 0x48]);
            a.mov(ecx, 25);
            a.call(Helper);
            a.add(rsp, 0x28); a.ret();
        }), 0x8664, source: SlotSource);
        var mark = Assert.Single(NoteMarks.SlotMarks(native, index, 0x1000, default));
        Assert.Equal("BinaryReader::ReadBytes (slot 25)", mark.Text);
        Assert.Equal(0x100Du, mark.Rva);
    }

    [Fact]
    public void An_address_outside_any_function_gets_no_slot_marks()
    {
        var (_, _, native, index) = Open(SlotCode(a => a.ret()), 0x8664, source: SlotSource);
        Assert.Empty(NoteMarks.SlotMarks(native, index, 0x70, default));
    }

    [Fact]
    public async Task Slot_marks_accumulate_per_session_and_join_the_notes_at_one_address()
    {
        var (_, _, native, _) = Open(SlotCode(a => a.ret()), 0x8664, source: SlotSource);
        var engine = new ScriptedEngine();
        var session = await engine.OpenAsync("");
        var first = new[] { new NativeMark(0x20, "slot A") };
        var second = new[] { new NativeMark(0x10, "slot B"), new NativeMark(0x20, "slot A") };
        var note = new[] { new NativeMark(0x20, "[note] n") };

        NoteMarks.Combine([], session, first);
        var both = NoteMarks.Combine([], session, second);
        Assert.Equal([(0x10u, "slot B"), (0x20u, "slot A")], both.Select(m => (m.Rva, m.Text)));
        var joined = NoteMarks.Combine(note, session, []);
        Assert.Equal("slot A; [note] n", joined.Single(m => m.Rva == 0x20).Text);
        Assert.Equal(2, joined.Count);

        var one = await NoteMarks.EnsureAsync(native, session, null, first, default);
        Assert.NotNull(one);
        Assert.Null(await NoteMarks.EnsureAsync(native, session, null, first, default));
        Assert.Single(engine.MarkPushes);
        Assert.Equal(2, engine.MarkPushes[0].Marks.Count);
    }
}
