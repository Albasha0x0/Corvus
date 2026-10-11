using System.Text;
using Iced.Intel;
using Corvus.Mcp;
using Corvus.Services;
using Corvus.Tools;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>resolve_address facets from the code index: function and offset, instruction boundary, data item, references.</summary>
public sealed class ResolveAddressFacetTests : IDisposable
{
    private const ulong Base = 0x180000000;
    private readonly TempDir _dir = new();
    private readonly Env _env = new();

    public void Dispose()
    {
        _env.Dispose();
        _dir.Dispose();
    }

    /// <summary>.text: main (mov rax, [rcx+8]; lea rcx, text; call helper; ret) and helper (ret); .rdata: "Hello, resolve".</summary>
    private string Sample()
    {
        var a = new Assembler(64);
        var helper = a.CreateLabel();
        a.mov(rax, __qword_ptr[rcx + 8]);
        a.AddInstruction(Instruction.Create(Iced.Intel.Code.Lea_r64_m, Register.RCX, new MemoryOperand(Register.RIP, (long)(Base + 0x2000), 8)));
        a.call(helper);
        a.ret();
        a.Label(ref helper);
        a.ret();
        var stream = new MemoryStream();
        a.Assemble(new StreamCodeWriter(stream), Base + 0x1000);
        var b = new PeBuilder { ImageBase = Base, Characteristics = 0x2022 };
        b.EntryPoint = b.Add(".text", stream.ToArray(), 0x60000020).Rva;
        b.Add(".rdata", Encoding.ASCII.GetBytes("Hello, resolve\0"));
        var path = _dir.File("facets.dll");
        File.WriteAllBytes(path, b.Build());
        return path;
    }

    private async Task<(string Text, AddressInfo Info)> Resolve(NativeTools tools, string id, string address)
    {
        var collector = StructuredOutput.Begin();
        var text = await tools.ResolveAddress(id, address);
        return (text, Assert.IsType<AddressInfo>(collector.Value));
    }

    [Fact]
    public async Task Function_boundary_data_item_and_references_are_reported()
    {
        var code = new NativeCodeService(_env.Workspace, _env.Options);
        var native = _env.Workspace.LoadAny(Sample()).Native!;
        await code.Index(native, null, default);
        var tools = new NativeTools(_env.Workspace, _env.Pager, code);

        var (mid, info) = await Resolve(tools, native.Id, "0x180001002");
        Assert.Contains("in function sub_1000+0x2", mid);
        Assert.Contains("inside the instruction at 0x180001000 (mov    rax, [rcx+8]): not an instruction boundary", mid);
        Assert.Equal(("sub_1000+0x2", "mid_instruction", "0x180001000"), (info.Function, info.Status, info.ContainingInstruction));

        var (text, str) = await Resolve(tools, native.Id, "0x180002003");
        Assert.Contains("string 0x180002000-0x18000200F (+0x3 into it): \"Hello, resolve\"", text);
        Assert.Equal(("data", "string: \"Hello, resolve\""), (str.Status, str.DataItem));

        var (start, helper) = await Resolve(tools, native.Id, "0x180001011");
        Assert.Contains("an instruction start", start);
        Assert.Contains("referenced 1 time: 1 Call", start);
        Assert.Equal(("sub_1011", "decoded", 1), (helper.Function, helper.Status, helper.ReferencesTo!["Call"]));
    }
}
