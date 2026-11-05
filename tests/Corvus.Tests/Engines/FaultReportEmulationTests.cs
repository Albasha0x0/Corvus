using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Services;
using Corvus.Tools;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>emulate_native engine=ours on a faulting load and a call to a runtime throw helper.</summary>
public sealed class FaultReportEmulationTests(FaultReportEmulationTests.Rig rig) : IClassFixture<FaultReportEmulationTests.Rig>
{
    private const ulong Base = NativeEmulationGhidraTests.Base;

    /// <summary>
    /// faults.dll exports: Load(p) pads with one nop and reads [rcx];
    /// The Native AOT mangled System.ThrowHelper.ThrowNullReferenceException is a throw helper; Check(p) calls it.
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
                Label load = a.CreateLabel(), thrower = a.CreateLabel(), check = a.CreateLabel();
                a.Label(ref load);
                a.nop();
                a.mov(rax, __[rcx]);
                a.ret();
                for (int i = 0; i < 8; i++) a.int3();
                a.Label(ref thrower);
                a.int3();
                for (int i = 0; i < 8; i++) a.int3();
                a.Label(ref check);
                a.sub(rsp, 0x28);
                a.call(thrower);
                a.add(rsp, 0x28);
                a.ret();
                var stream = new MemoryStream();
                var result = a.Assemble(new StreamCodeWriter(stream), Base + LinkedImages.Text, BlockEncoderOptions.ReturnNewInstructionOffsets);
                uint Rva(Label l) => (uint)(result.GetLabelRIP(l) - Base);
                at["Load"] = Rva(load);
                at["S_P_CoreLib_System_ThrowHelper__ThrowNullReferenceException"] = Rva(thrower);
                at["Check"] = Rva(check);
                return stream.ToArray();
            }
            (string, string[])[] imports = [];
            LinkedImages.Build("faults.dll", [], imports, Code);
            string[] exported = ["Load", "S_P_CoreLib_System_ThrowHelper__ThrowNullReferenceException", "Check"];
            var path = _dir.File("faults.dll");
            File.WriteAllBytes(path, LinkedImages.Build("faults.dll", [.. exported.Select(n => (n, (object)(int)(at[n] - LinkedImages.Text)))], imports, Code));
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
    }

    private Task<string> Run(string address, string? registers = null) =>
        rig.Tools.EmulateNative("faults.dll", address, null, registers, null, engine: "ours");

    [Fact]
    public async Task A_faulting_load_reports_its_own_address_as_RIP()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Run("Load", registers: "rcx=0"));
        Assert.Equal(ErrorCode.Failed, e.Code);
        var partial = e.Partial?.ToString() ?? "";
        var rip = System.Text.RegularExpressions.Regex.Match(partial, @"RIP=0x([0-9a-fA-F]+)");
        var at = System.Text.RegularExpressions.Regex.Match(e.Message, @"0x([0-9a-fA-F]+)");
        Assert.True(rip.Success, partial);
        Assert.True(at.Success, e.Message);
        Assert.Equal(Convert.ToUInt64(at.Groups[1].Value, 16), Convert.ToUInt64(rip.Groups[1].Value, 16));
    }

    [Fact]
    public async Task A_call_to_a_named_throw_helper_stops_with_the_exception_named()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Run("Check"));
        Assert.Equal(ErrorCode.Failed, e.Code);
        Assert.Contains("System.NullReferenceException", e.Message);
        Assert.Contains("S_P_CoreLib_System_ThrowHelper__ThrowNullReferenceException", e.Message);
    }
}
