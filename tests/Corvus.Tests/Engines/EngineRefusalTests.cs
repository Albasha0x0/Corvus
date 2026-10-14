using Corvus.Native.Providers;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Engine edit refusals (EL-7): each worker reason maps to a code with its own Next; no Next lists nothing.</summary>
public sealed class EngineRefusalTests
{
    [Theory]
    [InlineData("the function has no stack frame", "no_frame", "set_native_local")]
    [InlineData("+0x28 is __return_address (return address or saved registers)", "reserved_slot", "below +0x28")]
    [InlineData("+0x8 is the return address", "reserved_slot", "below +0x28")]
    [InlineData("the function already has a local named harness_local", "name_in_use", "clear=true")]
    [InlineData("the function has no local v9 (locals: a1, a2)", "no_local", "stack:<offset>")]
    [InlineData("uVar3 has no storage the decompiler uses; it is not in the pseudocode, so the edit would not take", "no_storage", "decompile_native shows")]
    [InlineData("the decompiler kept the name uVar3; the edit did not take", "no_effect", "decompile_native shows")]
    [InlineData("the type does not parse (types it names must be declared first)", "parse_error", "declare_native_types")]
    [InlineData("no function contains rva 0x39B48", "no_function", "define_native kind=function")]
    public void Each_refusal_has_its_own_Next(string message, string code, string next)
    {
        Assert.Equal(code, NativeTypeTools.RefusalCode(message));
        var frame = new NativeFrame(0x1000, "f", 0x20, 8, 0x28, [], [], null);
        Assert.Contains(next, NativeTypeTools.Refusal(message, "ida", frame));
        Assert.DoesNotContain("check the spelling", NativeTypeTools.Refusal(message, "ida", frame));
    }

    [Fact]
    public void A_frame_without_members_names_an_offset_not_an_empty_list()
    {
        var empty = NativeTypeTools.MissingMember(new NativeFrame(0x1000, "f", 0, 0, 0x28, [], [], null), "var_8");
        Assert.DoesNotContain("members: ;", empty.Remediation);
        Assert.Contains("0x20", empty.Remediation);
        var some = NativeTypeTools.MissingMember(new NativeFrame(0x1000, "f", 0x10, 0, 0x28, [new NativeFrameMember(0x10, "var_18", "int", 4, "local")], [], null), "x");
        Assert.Contains("members: var_18", some.Remediation);
    }
}
