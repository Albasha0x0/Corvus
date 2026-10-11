using System.Text.Json;
using Iced.Intel;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ida;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using static Iced.Intel.AssemblerRegisters;

namespace NetDecompilerMcp.Tests;

/// <summary>inspect_instruction through an engine: the worker reply parsed and rendered (no engine), and IDA's and Ghidra's items against the built-in decoder.</summary>
public sealed class EngineInspectTests(Xunit.Abstractions.ITestOutputHelper output) : IDisposable
{
    private const ulong Base = 0x140000000UL;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const string Reply = """
        {"items": [
          {"rva": 4098, "head": 4096, "end": 4100, "function": 4096, "status": "mid_instruction"},
          {"rva": 4096, "head": 4096, "function": 4096, "status": "decoded", "insn": {"size": 4, "bytes": "488b4108", "text": "mov     rax, [rcx+8]",
            "mnemonic": "mov", "flow": "next", "target": null, "fallthrough": 4100, "references": [],
            "operands": [{"index": 0, "kind": "register", "text": "rax", "size": 8, "access": "write", "register": "rax"},
                         {"index": 1, "kind": "memory", "text": "[rcx+8]", "size": 8, "access": "read", "base": "rcx", "displacement": 8}]}},
          {"rva": 4100, "head": 4100, "function": 4096, "status": "decoded", "insn": {"size": 5, "bytes": "e800000000", "text": "call    sub_1009",
            "mnemonic": "call", "flow": "call", "target": 4105, "fallthrough": 4105, "references": [[4105, "call"]],
            "operands": [{"index": 0, "kind": "near_branch", "text": "sub_1009", "size": 8, "access": "read", "target": 4105}]}},
          {"rva": 524288, "head": 524288, "end": 524301, "function": null, "status": "data", "kind": "string", "text": "\"Hello, world\""}
        ]}
        """;

    [Fact]
    public void Worker_reply_is_parsed_and_rendered_with_absent_fields_null()
    {
        var items = EngineInstructions.Parse(JsonDocument.Parse(Reply).RootElement);
        Assert.Equal([AddressStatus.MidInstruction, AddressStatus.Decoded, AddressStatus.Decoded, AddressStatus.Data], items.Select(i => i.Status));
        Assert.Equal(4096u, items[0].Head);
        var mem = items[1].Instruction!.Operands[1];
        Assert.Equal(("rcx", 8L, 8, "read"), (mem.Base, mem.Displacement!.Value, mem.Size!.Value, mem.Access));
        Assert.Equal(("call", 4105u, 4105u), (items[2].Instruction!.Flow, items[2].Instruction!.BranchTarget!.Value, items[2].Instruction!.Fallthrough!.Value));
        Assert.Equal(new DataItem("string", 0x80000, 0x8000D, "\"Hello, world\""), items[3].Item);

        var a = new Assembler(64);
        a.mov(rax, __qword_ptr[rcx + 8]);
        a.ret();
        var stream = new MemoryStream();
        a.Assemble(new StreamCodeWriter(stream), Base + 0x1000);
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, stream.ToArray(), entry: 0x1000));
        var (text, report) = NativeCodeTools.EngineReport("sample", index, items, new EngineChoice("ida", "test"), CancellationToken.None);
        Assert.Equal(["mid_instruction", "decoded", "decoded", "data"], report.Items.Select(i => i.Status));
        Assert.Equal(("sub_1000+0x2", "0x140001000"), (report.Items[0].Function, report.Items[0].ContainingInstruction));
        var mov = report.Items[1].Instruction!;
        Assert.Null(mov.RegistersRead);
        Assert.Null(mov.Prefixes);
        Assert.Equal("0x8", mov.Operands[1].Displacement);
        Assert.Equal("call", report.Items[2].Instruction!.ReferencesFrom.Single().Kind);
        Assert.Contains("string 0x140080000-0x14008000D (13 bytes): \"Hello, world\"", text);
        Assert.Contains("IDA does not report prefixes", text);
        Assert.Equal("ida", report.Engine);
    }

    [IdaFact]
    [Trait("Speed", "Slow")]
    public Task Ida_items_agree_with_the_built_in_decoder() => Agree("ida");

    [GhidraFact]
    [Trait("Speed", "Slow")]
    public Task Ghidra_items_agree_with_the_built_in_decoder() => Agree("ghidra");

    private async Task Agree(string engine)
    {
        var options = new ServerOptions { TimeoutSeconds = 300, BackgroundIndexing = false };
        using var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        using var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = _dir.File("cache") }, code, workspace, options,
            new Native.Providers.Ghidra.GhidraProviderOptions { CacheRoot = _dir.File("cache") });
        var tools = new NativeCodeTools(workspace, code, new OutputPager(options), null, engines, new NativeNamePush(code));
        var native = workspace.LoadAny(NativeIdaProviderTests.System64).Native!;
        var index = await code.Index(native, null, default);
        var f = index.Functions.First(x => x.KnownName == "CheckSumMappedFile");
        var at = NativeAddress.Va(index.Image, f.Start);

        async Task<InstructionReport> Run(string which, string address, int count)
        {
            var collector = StructuredOutput.Begin();
            await tools.InspectInstruction(native.Id, address, count: count, engine: which);
            return Assert.IsType<InstructionReport>(collector.Value);
        }
        var ours = await Run("ours", at, 40);
        var ida = await Run(engine, at, 40);
        Assert.Equal(engine, ida.Engine);
        var byRva = ours.Items.Where(i => i.Instruction != null).ToDictionary(i => i.Rva);
        int compared = 0, memory = 0;
        foreach (var item in ida.Items.Where(i => i.Instruction != null && byRva.ContainsKey(i.Rva)))
        {
            var (a, b) = (byRva[item.Rva].Instruction!, item.Instruction!);
            Assert.True(a.Length == b.Length, $"{item.Address}: length {a.Length} vs {engine} {b.Length}");
            Assert.True(a.Flow.Kind == b.Flow.Kind || a.Flow.Kind == "next" && b.Flow.Kind == "trap", $"{item.Address} {a.Text}: flow {a.Flow.Kind} vs {engine} {b.Flow.Kind}");
            foreach (var o in b.Operands.Where(o => o.Kind == "memory" && o.Index < a.Operands.Count && a.Operands[o.Index].Kind == "memory"))
            {
                var mine = a.Operands[o.Index];
                if (mine.RipRelative) continue;
                Assert.True(mine.Base == o.Base && mine.IndexRegister == o.IndexRegister && mine.Scale == o.Scale && (mine.Displacement ?? "0x0") == (o.Displacement ?? "0x0"),
                    $"{item.Address} {a.Text}: [{mine.Base} {mine.IndexRegister}*{mine.Scale} {mine.Displacement}] vs {engine} [{o.Base} {o.IndexRegister}*{o.Scale} {o.Displacement}]");
                memory++;
            }
            compared++;
        }
        Assert.True(compared >= 20, $"only {compared} instructions compared");
        Assert.True(memory > 0, "no memory operand compared");
        output.WriteLine($"{engine}: {compared} instructions and {memory} memory operands agree with the built-in decoder");

        var mid = await Run(engine, NativeAddress.Va(index.Image, f.Start + 1), 1);
        Assert.Equal(("mid_instruction", at), (mid.Items[0].Status, mid.Items[0].ContainingInstruction));
    }
}
