using Corvus.Native;
using Corvus.Native.Calls;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>AArch64 vtable calls are named from the value flow of hand-assembled code.</summary>
public sealed partial class AotFieldNotesTests
{
    private const uint LdrClass = 0xF9400001;
    private const uint LdrEntry = 0xF940B422;
    private const uint BlrX2 = 0xD63F0040;
    private const uint Ret = 0xD65F03C0;
    private const uint StrClassToSlot = 0xF90007E1;
    private const uint LdrClassFromSlot = 0xF94007E1;

    private Dictionary<uint, string> Arm64SlotNotes(params uint[] words)
    {
        var (_, _, native, index) = Open(Words(words), 0xAA64, source: SlotSource);
        return AotSlotNotes.Comments(native, index, index.FunctionAt(0x1000)!, default);
    }

    private bool Arm64NullCheckedAt(uint thrower, params uint[] words)
    {
        var (_, _, _, index) = Open(Words(words), 0xAA64, source: SlotSource);
        return AotRuntimeHelpers.Arm64NullChecked(new A64Function(index, index.FunctionAt(0x1000)!, default), thrower);
    }

    [Fact]
    public void An_arm64_call_through_an_entry_loaded_from_the_class_pointer_names_the_method()
    {
        var notes = Arm64SlotNotes(LdrClass, LdrEntry, BlrX2, Ret);
        Assert.Equal("StreamHost::Dispatch (slot 3)", Assert.Single(notes).Value);
    }

    [Fact]
    public void An_arm64_class_pointer_spilled_to_the_stack_and_reloaded_names_the_method()
    {
        var notes = Arm64SlotNotes(LdrClass, StrClassToSlot, LdrClassFromSlot, LdrEntry, BlrX2, Ret);
        Assert.Single(notes);
    }

    [Fact]
    public void An_arm64_stack_slot_overwritten_before_the_reload_has_no_note()
    {
        // str xzr, [sp, #8] replaces the spilled class pointer.
        Assert.Empty(Arm64SlotNotes(LdrClass, StrClassToSlot, 0xF90007FF, LdrClassFromSlot, LdrEntry, BlrX2, Ret));
    }

    [Fact]
    public void An_arm64_stack_slot_whose_address_is_taken_has_no_note()
    {
        // add x3, sp, #8 lets any later store reach the slot.
        Assert.Empty(Arm64SlotNotes(LdrClass, StrClassToSlot, 0x910023E3, LdrClassFromSlot, LdrEntry, BlrX2, Ret));
    }

    [Fact]
    public void An_arm64_call_clobbers_a_volatile_register_holding_a_vtable_entry()
    {
        // bl 0x1014, a function that returns, sits between the load and the blr.
        Assert.Empty(Arm64SlotNotes(LdrClass, LdrEntry, 0x94000003, BlrX2, Ret, Ret));
    }

    [Fact]
    public void An_arm64_register_branch_that_is_no_slot_entry_leaves_the_function_unnoted()
    {
        // br x9 has a target the pass cannot read.
        Assert.Empty(Arm64SlotNotes(LdrClass, LdrEntry, BlrX2, 0xD61F0120));
    }

    [Fact]
    public void An_arm64_entry_copied_through_a_64_bit_register_names_the_method()
    {
        // mov x3, x2 ; blr x3.
        Assert.Single(Arm64SlotNotes(LdrClass, LdrEntry, 0xAA0203E3, 0xD63F0060, Ret));
    }

    [Fact]
    public void An_arm64_entry_truncated_by_a_32_bit_copy_has_no_note()
    {
        // mov w3, w2 ; blr x3.
        Assert.Empty(Arm64SlotNotes(LdrClass, LdrEntry, 0x2A0203E3, 0xD63F0060, Ret));
    }

    [Fact]
    public void An_arm64_cbz_to_the_throwing_call_is_a_null_check()
    {
        // cbz x0, +8 ; ret ; bl 0x1010 ; ret ; ret.
        Assert.True(Arm64NullCheckedAt(0x1010, 0xB4000040, Ret, 0x94000002, Ret, Ret));
    }

    [Fact]
    public void An_arm64_cbnz_to_the_throwing_call_is_no_null_check()
    {
        Assert.False(Arm64NullCheckedAt(0x1010, 0xB5000040, Ret, 0x94000002, Ret, Ret));
    }

    [Fact]
    public void An_arm64_cbnz_over_the_throwing_call_is_a_null_check()
    {
        // cbnz x0, +8 ; bl 0x100C ; ret ; ret.
        Assert.True(Arm64NullCheckedAt(0x100C, 0xB5000040, 0x94000002, Ret, Ret));
    }

    [Fact]
    public void An_arm64_cbz_over_the_throwing_call_is_no_null_check()
    {
        Assert.False(Arm64NullCheckedAt(0x100C, 0xB4000040, 0x94000002, Ret, Ret));
    }
}
