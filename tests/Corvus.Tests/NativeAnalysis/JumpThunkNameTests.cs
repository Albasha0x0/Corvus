using Corvus.Native;
using Corvus.Native.Code;

namespace Corvus.Tests;

/// <summary>Jump thunks (incremental-link table entries) are named j_&lt;target&gt; and follow the target's name.</summary>
public sealed class JumpThunkNameTests
{
    [Fact]
    public void Thunk_takes_the_name_of_its_target_until_named_itself()
    {
        // 0x1000: jmp 0x1010 (the entry, unnamed); 0x1010: xor eax, eax; ret (exported as Target)
        var code = new byte[0x20];
        Array.Fill(code, (byte)0xCC);
        new byte[] { 0xE9, 0x0B, 0, 0, 0 }.CopyTo(code, 0);
        new byte[] { 0x31, 0xC0, 0xC3 }.CopyTo(code, 0x10);
        const uint Thunk = CodeTestImage.SyntheticCodeRva, Target = Thunk + 0x10;
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, code, entry: Thunk, exports: [new NativeExport("Target", 1, Target, null)]));
        Assert.Equal("j_Target", index.FunctionByStart(Thunk)!.Name);
        Assert.Equal(Thunk, index.AddressOfName("j_Target"));

        index.SetSourceName(Target, "Real::Target", NativeNameSource.Pdb);
        Assert.Equal("j_Real::Target", index.FunctionByStart(Thunk)!.Name);
        index.SetSourceName(Target, null, NativeNameSource.Pdb);
        Assert.Equal("j_Target", index.FunctionByStart(Thunk)!.Name);

        index.SetUserName(Thunk, "mine");
        index.SetUserName(Target, "renamed");
        Assert.Equal("mine", index.FunctionByStart(Thunk)!.Name);
    }
}
