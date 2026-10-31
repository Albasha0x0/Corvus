using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Services;
using Corvus.Tools;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>emulate_native engine=ours on routines that call memcpy, memset and strlen through import slots.</summary>
public sealed class LibraryModelEmulationTests(LibraryModelEmulationTests.Rig rig) : IClassFixture<LibraryModelEmulationTests.Rig>
{
    private const int MaxBytes = 1 << 20;
    private const ulong Base = NativeEmulationGhidraTests.Base;

    /// <summary>
    /// models.dll exports: Copy(dst, src, n) returns memcpy(dst, src, n);
    /// Fill(dst, c, n) returns memset(dst, c, n); Measure(s) returns strlen(s);
    /// Grow(buf, piece) appends piece to buf with strlen and memcpy and
    /// returns strlen(buf); Indirect(dst, src, n) calls memcpy through a
    /// register; Span(buf) fills 1 MiB + 16 bytes with 0x41 and returns strlen(buf).
    /// </summary>
    public sealed class Rig : IDisposable
    {
        private readonly TempDir _dir = new();
        public AssemblyWorkspace Workspace { get; }
        public NativeEngineService Engines { get; }
        public NativeEmulationTools Tools { get; }

        public Rig()
        {
            var at = new Dictionary<string, uint>();
            byte[] Code(Dictionary<string, uint> slots)
            {
                var a = new Assembler(64);
                void Call(string import) =>
                    a.AddInstruction(Instruction.Create(Iced.Intel.Code.Call_rm64, new MemoryOperand(Register.RIP, (long)(Base + slots["msvcrt.dll!" + import]), 8)));
                Label copy = a.CreateLabel(), fill = a.CreateLabel(), measure = a.CreateLabel(), grow = a.CreateLabel(), indirect = a.CreateLabel(), span = a.CreateLabel();
                void Wrapper(ref Label label, string import)
                {
                    a.Label(ref label);
                    a.sub(rsp, 0x28);
                    Call(import);
                    a.add(rsp, 0x28);
                    a.ret();
                    Pad(a);
                }
                Wrapper(ref copy, "memcpy");
                Wrapper(ref fill, "memset");
                Wrapper(ref measure, "strlen");
                a.Label(ref grow);
                a.push(rbx);
                a.push(rsi);
                a.push(rdi);
                a.sub(rsp, 0x20);
                a.mov(rbx, rcx);
                a.mov(rsi, rdx);
                Call("strlen");
                a.mov(rdi, rax);
                a.mov(rcx, rsi);
                Call("strlen");
                a.lea(r8, __[rax + 1]);
                a.lea(rcx, __[rbx + rdi]);
                a.mov(rdx, rsi);
                Call("memcpy");
                a.mov(rcx, rbx);
                Call("strlen");
                a.add(rsp, 0x20);
                a.pop(rdi);
                a.pop(rsi);
                a.pop(rbx);
                a.ret();
                a.Label(ref indirect);
                a.sub(rsp, 0x28);
                a.AddInstruction(Instruction.Create(Iced.Intel.Code.Mov_r64_rm64, rax, new MemoryOperand(Register.RIP, (long)(Base + slots["msvcrt.dll!memcpy"]), 8)));
                a.call(rax);
                a.add(rsp, 0x28);
                a.ret();
                Pad(a);
                a.Label(ref span);
                a.push(rbx);
                a.sub(rsp, 0x20);
                a.mov(rbx, rcx);
                a.mov(edx, 0x41);
                a.mov(r8d, MaxBytes);
                Call("memset");
                a.lea(rcx, __[rbx + MaxBytes]);
                a.mov(edx, 0x41);
                a.mov(r8d, 16);
                Call("memset");
                a.mov(rcx, rbx);
                Call("strlen");
                a.add(rsp, 0x20);
                a.pop(rbx);
                a.ret();
                var stream = new MemoryStream();
                var result = a.Assemble(new StreamCodeWriter(stream), Base + LinkedImages.Text, BlockEncoderOptions.ReturnNewInstructionOffsets);
                uint Rva(Label l) => (uint)(result.GetLabelRIP(l) - Base);
                at["Copy"] = Rva(copy);
                at["Fill"] = Rva(fill);
                at["Measure"] = Rva(measure);
                at["Grow"] = Rva(grow);
                at["Indirect"] = Rva(indirect);
                at["Span"] = Rva(span);
                return stream.ToArray();
            }
            (string, string[])[] imports = [("msvcrt.dll", ["memcpy", "memset", "strlen"])];
            LinkedImages.Build("models.dll", [], imports, Code);
            string[] exported = ["Copy", "Fill", "Measure", "Grow", "Indirect", "Span"];
            var path = _dir.File("models.dll");
            File.WriteAllBytes(path, LinkedImages.Build("models.dll", [.. exported.Select(n => (n, (object)(int)(at[n] - LinkedImages.Text)))], imports, Code));
            var options = new ServerOptions { TimeoutSeconds = 600, BackgroundIndexing = false };
            Workspace = new AssemblyWorkspace(options);
            Engines = new NativeEngineService(Array.Empty<INativeDecompilerProvider>(), _dir.File("cache"));
            Workspace.LoadAny(path);
            Tools = new NativeEmulationTools(Workspace, Engines, new NativeCodeService(Workspace, options));
        }

        public void Dispose()
        {
            Engines.Dispose();
            Workspace.Dispose();
            _dir.Dispose();
        }

        private static void Pad(Assembler a)
        {
            for (int i = 0; i < 8; i++) a.int3();
        }
    }

    private Task<string> Run(string address, string? args = null, string? registers = null, string? stubs = null, string? memory = null) =>
        rig.Tools.EmulateNative("models.dll", address, args, registers, memory, stubs: stubs, engine: "ours");

    [Fact]
    public async Task A_memcpy_call_copies_the_source_into_the_destination()
    {
        var text = await Run("Copy", args: "buf:16, \"hello\", 6");
        Assert.Contains("memcpy: modelled", text);
        Assert.Contains("68 65 6C 6C 6F 00", text);
    }

    [Fact]
    public async Task A_memset_call_fills_the_destination_with_the_byte()
    {
        var text = await Run("Fill", args: "buf:16, 0x41, 4");
        Assert.Contains("memset: modelled", text);
        Assert.Contains("41 41 41 41", text);
        Assert.DoesNotContain("41 41 41 41 41", text);
    }

    [Fact]
    public async Task A_strlen_call_returns_the_length_of_the_string()
    {
        var text = await Run("Measure", args: "\"hello world\"");
        Assert.Contains("strlen: modelled", text);
        Assert.Contains("Return value: RAX = 0xb", text);
    }

    [Fact]
    public async Task A_string_growing_routine_returns_the_length_of_the_joined_string()
    {
        var text = await Run("Grow", args: "hex:666F6F00000000000000000000000000, \"bar\"");
        Assert.Contains("Return value: RAX = 0x6", text);
        Assert.Contains("strlen: modelled", text);
        Assert.Contains("memcpy: modelled", text);
        Assert.Contains("62 61 72 00", text);
    }

    [Fact]
    public async Task A_strlen_of_unmapped_memory_stops_naming_the_address()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Run("Measure", registers: "rcx=0x1234"));
        Assert.Equal(ErrorCode.Failed, e.Code);
        Assert.Contains("strlen", e.Message);
        Assert.Contains("0x1234", e.Message);
    }

    [Fact]
    public async Task A_memcpy_from_unmapped_memory_stops_naming_the_address()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Run("Copy", args: "buf:16, 0x5000, 4"));
        Assert.Equal(ErrorCode.Failed, e.Code);
        Assert.Contains("memcpy", e.Message);
        Assert.Contains("0x5000", e.Message);
    }

    [Fact]
    public async Task A_memcpy_larger_than_the_model_limit_is_refused()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Run("Copy", args: "buf:16, buf:16, 0x7FFFFFFF"));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Contains("exceeds", e.Message);
    }

    [Fact]
    public async Task A_named_stub_answers_before_the_model()
    {
        var text = await Run("Measure", args: "\"hello\"", stubs: "strlen=0x99");
        Assert.Contains("strlen: stubbed, returned 0x99", text);
        Assert.Contains("Return value: RAX = 0x99", text);
    }

    [Fact]
    public async Task A_memcpy_through_a_register_call_is_modelled()
    {
        var text = await Run("Indirect", args: "buf:16, \"hello\", 6");
        Assert.Contains("memcpy: modelled", text);
        Assert.Contains("68 65 6C 6C 6F 00", text);
    }

    [Fact]
    public async Task A_model_answers_before_the_any_call_stub()
    {
        var text = await Run("Measure", args: "\"hello\"", stubs: "*=0x99");
        Assert.Contains("strlen: modelled", text);
        Assert.Contains("Return value: RAX = 0x5", text);
    }

    [Fact]
    public async Task A_memset_larger_than_the_model_limit_is_refused()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Run("Fill", args: "buf:16, 0, 0x7FFFFFFF"));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Contains("exceeds", e.Message);
    }

    [Fact]
    public async Task A_strlen_without_a_terminator_within_the_limit_is_refused()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Run("Span", registers: "rcx=0x10000000", memory: "va:0x10000000=zero:1048576, va:0x10100000=zero:16"));
        Assert.Contains("no terminator", e.Message);
    }

    [Theory]
    [InlineData("memcpy", "memcpy")]
    [InlineData("msvcrt!memcpy", "memcpy")]
    [InlineData("_memset", "memset")]
    [InlineData("__imp_strlen", "strlen")]
    [InlineData("memcpy@plt", "memcpy")]
    [InlineData("j_strlen", "strlen")]
    [InlineData("memmove", null)]
    public void Callee_names_resolve_to_a_model(string name, string? model) =>
        Assert.Equal(model, Corvus.Native.Emulation.LibraryModels.Find(name));
}
