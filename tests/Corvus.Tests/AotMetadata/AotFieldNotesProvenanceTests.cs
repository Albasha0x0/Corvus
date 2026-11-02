using Corvus.Native.Code;
using Corvus.Services;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>
/// Slot calls are found from where the class pointer came from, not from the
/// order of the instructions.
/// </summary>
public sealed partial class AotFieldNotesTests
{
    private const string Dispatch = "StreamHost::Dispatch (slot 3)";

    private const int EntryOffset = 0x138 + 16 * 3;

    [Fact]
    public void A_class_pointer_loaded_early_names_the_slot_after_unrelated_instructions()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rax, __qword_ptr[rcx]);
            a.mov(r9d, 1);
            a.add(edx, 5);
            a.mov(r8, rdx);
            a.call(__qword_ptr[rax + EntryOffset]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Equal(Dispatch, Assert.Single(notes).Value);
    }

    [Fact]
    public void A_class_pointer_in_another_register_names_the_slot()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(r10, __qword_ptr[rcx]);
            a.mov(r11, __qword_ptr[r10 + EntryOffset]);
            a.call(r11);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Equal(Dispatch, Assert.Single(notes).Value);
    }

    [Fact]
    public void A_class_pointer_spilled_to_the_stack_and_reloaded_names_the_slot()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rax, __qword_ptr[rcx]);
            a.mov(__qword_ptr[rsp + 0x20], rax);
            a.xor(eax, eax);
            a.mov(rdx, __qword_ptr[rsp + 0x20]);
            a.call(__qword_ptr[rdx + EntryOffset]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Equal(Dispatch, Assert.Single(notes).Value);
    }

    [Fact]
    public void A_receiver_spilled_through_a_frame_pointer_names_the_slot()
    {
        var notes = SlotNotes(a =>
        {
            a.push(rbp);
            a.mov(rbp, rsp);
            a.sub(rsp, 0x20);
            a.mov(__qword_ptr[rbp - 8], rcx);
            a.mov(rax, __qword_ptr[rbp - 8]);
            a.mov(rax, __qword_ptr[rax]);
            a.call(__qword_ptr[rax + EntryOffset]);
            a.leave(); a.ret();
        });
        Assert.Equal(Dispatch, Assert.Single(notes).Value);
    }

    [Fact]
    public void A_slot_index_scaled_in_a_register_names_the_slot()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rdx, __qword_ptr[rcx]);
            a.mov(eax, 16);
            a.imul(rax, rax, 3);
            a.call(__qword_ptr[rdx + rax + 0x138]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Equal(Dispatch, Assert.Single(notes).Value);
    }

    [Fact]
    public void A_stack_slot_overwritten_between_the_spill_and_the_reload_has_no_note()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rax, __qword_ptr[rcx]);
            a.mov(__qword_ptr[rsp + 0x20], rax);
            a.mov(__qword_ptr[rsp + 0x20], r8);
            a.mov(rdx, __qword_ptr[rsp + 0x20]);
            a.call(__qword_ptr[rdx + EntryOffset]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_stack_slot_whose_address_is_taken_has_no_note()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rax, __qword_ptr[rcx]);
            a.mov(__qword_ptr[rsp + 0x20], rax);
            a.lea(r8, __qword_ptr[rsp + 0x20]);
            a.mov(rdx, __qword_ptr[rsp + 0x20]);
            a.call(__qword_ptr[rdx + EntryOffset]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_class_pointer_from_two_different_sources_has_no_note()
    {
        var notes = SlotNotes(a =>
        {
            var other = a.CreateLabel();
            var join = a.CreateLabel();
            a.sub(rsp, 0x28);
            a.test(r8d, r8d);
            a.je(other);
            a.mov(rax, __qword_ptr[rcx]);
            a.jmp(join);
            a.Label(ref other);
            a.mov(rax, __qword_ptr[rdx]);
            a.Label(ref join);
            a.call(__qword_ptr[rax + EntryOffset]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_class_pointer_from_the_same_source_on_both_paths_names_the_slot()
    {
        var notes = SlotNotes(a =>
        {
            var other = a.CreateLabel();
            var join = a.CreateLabel();
            a.sub(rsp, 0x28);
            a.test(r8d, r8d);
            a.je(other);
            a.mov(rax, __qword_ptr[rcx]);
            a.jmp(join);
            a.Label(ref other);
            a.mov(rax, __qword_ptr[rcx]);
            a.Label(ref join);
            a.call(__qword_ptr[rax + EntryOffset]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Equal(Dispatch, Assert.Single(notes).Value);
    }

    [Fact]
    public void A_register_overwritten_before_the_call_has_no_note()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rax, __qword_ptr[rcx]);
            a.mov(rax, r8);
            a.call(__qword_ptr[rax + EntryOffset]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_call_clobbers_a_volatile_register_holding_a_vtable_entry()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(r10, __qword_ptr[rcx]);
            a.mov(r11, __qword_ptr[r10 + EntryOffset]);
            a.call(r9);
            a.call(r11);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_class_pointer_kept_in_a_preserved_register_names_the_slot_in_every_loop_pass()
    {
        var notes = SlotNotes(a =>
        {
            var top = a.CreateLabel();
            a.sub(rsp, 0x28);
            a.mov(rbx, __qword_ptr[rcx]);
            a.mov(edi, 3);
            a.Label(ref top);
            a.call(__qword_ptr[rbx + EntryOffset]);
            a.dec(edi);
            a.jne(top);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Equal(Dispatch, Assert.Single(notes).Value);
    }

    [Fact]
    public void A_class_pointer_reloaded_by_the_loop_body_has_no_note_at_the_loop_head()
    {
        var notes = SlotNotes(a =>
        {
            var top = a.CreateLabel();
            a.sub(rsp, 0x28);
            a.mov(rbx, __qword_ptr[rcx]);
            a.mov(edi, 3);
            a.Label(ref top);
            a.call(__qword_ptr[rbx + EntryOffset]);
            a.mov(rbx, __qword_ptr[rdi]);
            a.dec(edi);
            a.jne(top);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_class_pointer_loaded_before_and_after_a_call_has_no_note_at_the_merge()
    {
        var notes = SlotNotes(a =>
        {
            var other = a.CreateLabel();
            var join = a.CreateLabel();
            a.sub(rsp, 0x28);
            a.mov(rsi, rcx);
            a.test(r8d, r8d);
            a.je(other);
            a.mov(rax, __qword_ptr[rsi]);
            a.jmp(join);
            a.Label(ref other);
            a.call(r9);
            a.mov(rax, __qword_ptr[rsi]);
            a.Label(ref join);
            a.call(__qword_ptr[rax + EntryOffset]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_pointer_copied_from_the_stack_pointer_stops_slot_tracking()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rax, __qword_ptr[rcx]);
            a.mov(__qword_ptr[rsp + 0x20], rax);
            a.mov(r8, rsp);
            a.mov(rdx, __qword_ptr[rsp + 0x20]);
            a.call(__qword_ptr[rdx + EntryOffset]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_class_pointer_pushed_and_popped_names_the_slot()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rax, __qword_ptr[rcx]);
            a.push(rax);
            a.xor(eax, eax);
            a.pop(rdx);
            a.call(__qword_ptr[rdx + EntryOffset]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Equal(Dispatch, Assert.Single(notes).Value);
    }

    [Fact]
    public void A_write_through_an_indexed_frame_operand_forgets_the_spilled_slots()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rax, __qword_ptr[rcx]);
            a.mov(__qword_ptr[rsp + 0x20], rax);
            a.mov(__qword_ptr[rsp + r8 * 8 + 0x20], r9);
            a.mov(rdx, __qword_ptr[rsp + 0x20]);
            a.call(__qword_ptr[rdx + EntryOffset]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void A_call_forgets_a_slot_in_the_shadow_space()
    {
        var notes = SlotNotes(a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rax, __qword_ptr[rcx]);
            a.mov(__qword_ptr[rsp + 8], rax);
            a.call(r9);
            a.mov(rdx, __qword_ptr[rsp + 8]);
            a.call(__qword_ptr[rdx + EntryOffset]);
            a.add(rsp, 0x28); a.ret();
        });
        Assert.Empty(notes);
    }

    [Fact]
    public void Blocks_are_visited_with_nothing_known_when_the_passes_do_not_converge()
    {
        var (_, _, _, index) = Open(SlotCode(a =>
        {
            var top = a.CreateLabel();
            a.sub(rsp, 0x28);
            a.mov(rbx, __qword_ptr[rcx]);
            a.Label(ref top);
            a.call(__qword_ptr[rbx + EntryOffset]);
            a.jne(top);
            a.add(rsp, 0x28); a.ret();
        }), 0x8664, source: SlotSource);
        var fn = index.FunctionAt(0x1000)!;
        var code = FunctionInstructions.Decode(index.Image, index.Ranges(fn), default);
        var graph = index.GetGraph(fn);
        var reached = new List<bool>();
        ValueProvenance.Walk(code, graph, index.Image.ImageBase, true, (_, s) => reached.Add(s.Reached), default, maxPasses: 1);
        Assert.NotEmpty(reached);
        Assert.DoesNotContain(true, reached);
        reached.Clear();
        ValueProvenance.Walk(code, graph, index.Image.ImageBase, true, (_, s) => reached.Add(s.Reached));
        Assert.Contains(true, reached);
    }
}
