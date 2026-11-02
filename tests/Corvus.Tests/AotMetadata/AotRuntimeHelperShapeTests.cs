using Iced.Intel;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Services;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>Runtime helpers named from call-site shapes in small x64 images.</summary>
public sealed class AotRuntimeHelperShapeTests
{
    private const ulong Base = 0x140000000UL;
    private const uint Code = CodeTestImage.SyntheticCodeRva;

    private sealed record Built(INativeImage Image, NativeCodeIndex Index, Dictionary<string, uint> At);

    // Functions are laid out in order and labels name their addresses.
    // Methods are exported so they are function starts.
    private static Built Build(Action<Assembler, Func<string, Label>, Action<string>> emit, Func<string, bool> isMethod)
    {
        var a = new Assembler(64);
        var labels = new Dictionary<string, Label>();
        Label L(string name) => labels.TryGetValue(name, out var l) ? l : labels[name] = a.CreateLabel(name);
        void Here(string name) { var l = L(name); a.Label(ref l); labels[name] = l; }
        emit(a, L, Here);
        var stream = new MemoryStream();
        var result = a.Assemble(new StreamCodeWriter(stream), Base + Code, BlockEncoderOptions.ReturnNewInstructionOffsets);
        var at = labels.ToDictionary(kv => kv.Key, kv => (uint)(result.GetLabelRIP(kv.Value) - Base));
        var exports = at.Where(kv => isMethod(kv.Key)).Select((kv, i) => new NativeExport(kv.Key, (uint)i + 1, kv.Value, null)).ToList();
        var image = CodeTestImage.Synthetic(NativeArch.X64, stream.ToArray(), exports: exports, entry: at.Values.Min());
        return new Built(image, NativeCodeIndex.Build(image), at);
    }

    private static IReadOnlySet<uint> Methods(Built b) => b.At.Where(kv => kv.Key.StartsWith('M')).Select(kv => kv.Value).ToHashSet();

    // Each method first calls a leaf of its own, so no shared initializer
    // leads the methods. A null check branches to a block holding one call
    // to a thrower, which calls a wrapper that builds and raises.
    private static Built NullChecks(int methods, bool nullCheck, bool wrapperReturns, bool twoThrowers = false, bool loopBranch = false)
    {
        return Build((a, L, Here) =>
        {
            for (int i = 0; i < methods; i++)
            {
                Here("M" + i);
                var fail = a.CreateLabel();
                a.sub(rsp, 0x28);
                a.call(L("Leaf" + i));
                if (loopBranch)
                {
                    // A backward branch on non-zero, with the thrower call after it.
                    var top = a.CreateLabel();
                    a.Label(ref top);
                    a.test(rdi, rdi); a.jne(top);
                    a.call(L("Thrower")); a.int3();
                    continue;
                }
                if (nullCheck) { a.test(rdi, rdi); a.je(fail); }
                else { a.cmp(rdi, 5); a.jae(fail); }
                a.mov(eax, 1); a.add(rsp, 0x28); a.ret();
                a.Label(ref fail);
                a.call(L(twoThrowers && i % 2 == 1 ? "Thrower2" : "Thrower"));
                a.int3();
            }
            for (int i = 0; i < methods; i++) { Here("Leaf" + i); a.mov(eax, i + 2); a.ret(); a.int3(); }
            Here("Thrower"); a.sub(rsp, 0x28); a.call(L("Wrapper")); a.int3();
            if (twoThrowers) { Here("Thrower2"); a.sub(rsp, 0x28); a.call(L("Wrapper")); a.int3(); }
            Here("Wrapper");
            a.sub(rsp, 0x38); a.lea(rcx, __[rsp + 0x20]); a.call(L("Make")); a.mov(rcx, rax); a.call(L("Raise"));
            if (wrapperReturns) { a.add(rsp, 0x38); a.ret(); }
            a.int3();
            Here("Make"); a.mov(eax, 1); a.ret(); a.int3();
            Here("Raise"); a.ret();
        }, n => n.StartsWith('M'));
    }

    // Each method loads the receiver's class pointer, calls Setup through a
    // thunk, reloads the class pointer and calls a slot.
    private static Built ClassSetups(int methods, bool sameReceiver, int? entryOffset = null)
    {
        return Build((a, L, Here) =>
        {
            for (int i = 0; i < methods; i++)
            {
                Here("M" + i);
                a.sub(rsp, 0x28);
                a.call(L("Init"));
                a.mov(rcx, __qword_ptr[rdi]);
                a.call(L("Thunk"));
                a.mov(rax, __qword_ptr[sameReceiver ? rdi : rsi]);
                if (entryOffset is { } disp) { a.mov(rdx, __qword_ptr[rax + disp]); a.call(rdx); }
                else a.call(__qword_ptr[rax + 0x338]);
                a.add(rsp, 0x28); a.ret(); a.int3();
            }
            Here("Init"); a.ret(); a.int3();
            Here("Thunk"); a.jmp(L("Impl")); a.int3();
            Here("Impl"); a.ret();
        }, n => n.StartsWith('M'));
    }

    // As ClassSetups, with the receiver kept in a stack slot as an
    // unoptimized build does; the variant changes what the reload reads.
    private static Built SlotSetups(string variant)
    {
        return Build((a, L, Here) =>
        {
            for (int i = 0; i < 4; i++)
            {
                Here("M" + i);
                a.sub(rsp, 0x48);
                a.mov(__qword_ptr[rsp + 0x30], rdi);
                a.call(L("Init"));
                a.mov(rdx, __qword_ptr[rsp + 0x30]);
                a.mov(rcx, __qword_ptr[rdx]);
                a.call(L("Thunk"));
                if (variant == "other-slot") a.mov(rax, __qword_ptr[rsp + 0x38]);
                else if (variant == "moved-stack") { a.sub(rsp, 8); a.mov(rax, __qword_ptr[rsp + 0x30]); }
                else if (variant == "stored") { a.mov(__qword_ptr[rsp + 0x30], rsi); a.mov(rax, __qword_ptr[rsp + 0x30]); }
                else a.mov(rax, __qword_ptr[rsp + 0x30]);
                a.mov(rax, __qword_ptr[rax]);
                a.call(__qword_ptr[rax + 0x338]);
                a.add(rsp, 0x48); a.ret(); a.int3();
            }
            Here("Init"); a.ret(); a.int3();
            Here("Thunk"); a.jmp(L("Impl")); a.int3();
            Here("Impl"); a.ret();
        }, n => n.StartsWith('M'));
    }

    private static AotRuntimeHelpers.Helper? Named(Built b, string name) =>
        AotRuntimeHelpers.Find(b.Image, b.Index, Methods(b)).FirstOrDefault(h => h.Name == name);

    [Fact]
    public void A_throw_behind_a_no_return_wrapper_reached_by_null_checks_is_the_null_reference_throw()
    {
        // FT-314 M26.
        var b = NullChecks(4, nullCheck: true, wrapperReturns: false);
        var helper = Named(b, "Runtime_ThrowNullReference");
        Assert.Equal(b.At["Thrower"], helper?.Rva);
        Assert.Contains("called by 4 named functions", helper?.Evidence);
    }

    [Fact]
    public void Two_wrapped_throws_reached_by_null_checks_leave_both_unnamed()
    {
        Assert.Null(Named(NullChecks(6, nullCheck: true, wrapperReturns: false, twoThrowers: true), "Runtime_ThrowNullReference"));
    }

    [Fact]
    public void A_throw_reached_by_bounds_checks_is_not_named_the_null_reference_throw()
    {
        Assert.Null(Named(NullChecks(4, nullCheck: false, wrapperReturns: false), "Runtime_ThrowNullReference"));
    }

    [Fact]
    public void A_throw_behind_a_wrapper_that_returns_is_not_named_the_null_reference_throw()
    {
        Assert.Null(Named(NullChecks(4, nullCheck: true, wrapperReturns: true), "Runtime_ThrowNullReference"));
    }

    [Fact]
    public void A_throw_called_by_two_methods_is_not_named_the_null_reference_throw()
    {
        Assert.Null(Named(NullChecks(2, nullCheck: true, wrapperReturns: false), "Runtime_ThrowNullReference"));
    }

    [Fact]
    public void The_function_called_with_the_class_pointer_before_a_virtual_call_is_the_class_setup()
    {
        // FT-314 M26.
        var b = ClassSetups(4, sameReceiver: true);
        var helper = Named(b, "Runtime_ClassSetup");
        Assert.Equal(b.At["Thunk"], helper?.Rva);
        Assert.Contains("4 of 4 named functions scanned", helper?.Evidence);
    }

    [Fact]
    public void A_call_before_a_virtual_call_through_another_object_is_not_the_class_setup()
    {
        Assert.Null(Named(ClassSetups(4, sameReceiver: false), "Runtime_ClassSetup"));
    }

    [Fact]
    public void A_call_with_a_class_pointer_in_two_methods_is_not_the_class_setup()
    {
        Assert.Null(Named(ClassSetups(2, sameReceiver: true), "Runtime_ClassSetup"));
    }

    [Fact]
    public void A_backward_branch_on_non_zero_before_a_throw_call_is_not_a_null_check()
    {
        Assert.Null(Named(NullChecks(4, nullCheck: true, wrapperReturns: false, loopBranch: true), "Runtime_ThrowNullReference"));
    }

    [Fact]
    public void A_call_through_a_register_loaded_from_a_slot_entry_after_the_class_setup_names_it()
    {
        var b = ClassSetups(4, sameReceiver: true, entryOffset: 0x338);
        Assert.Equal(b.At["Thunk"], Named(b, "Runtime_ClassSetup")?.Rva);
    }

    [Fact]
    public void A_call_through_a_register_loaded_from_a_field_is_not_a_slot_call_for_the_class_setup()
    {
        Assert.Null(Named(ClassSetups(4, sameReceiver: true, entryOffset: 0x8), "Runtime_ClassSetup"));
    }

    [Fact]
    public void A_receiver_reloaded_from_its_stack_slot_after_the_call_is_the_class_setup_receiver()
    {
        var b = SlotSetups("same");
        Assert.Equal(b.At["Thunk"], Named(b, "Runtime_ClassSetup")?.Rva);
    }

    [Theory]
    [InlineData("other-slot")]
    [InlineData("moved-stack")]
    [InlineData("stored")]
    public void A_reload_from_another_slot_or_after_the_slot_changed_is_not_the_class_setup(string variant)
    {
        Assert.Null(Named(SlotSetups(variant), "Runtime_ClassSetup"));
    }
}
