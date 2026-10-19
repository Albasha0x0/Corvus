using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>
/// Stop points and watches on a jump: the backend places them where the jump leads, so the server follows direct and
/// memory jumps itself and refuses a jump through the CFG dispatch pointer, whose target runs for every indirect call.
/// </summary>
public sealed class LiveJumpTests : IDisposable
{
    private const ulong Base = 0x7ff6_2000_0000;
    private const ulong ImageBase = 0x140000000;
    private const uint CfgStub = 0x1000, DirectJump = 0x1010, Function = 0x1020, SlotJump = 0x1030;
    private const uint DispatchSlot = 0x2010, PointerSlot = 0x2018, LoadConfig = 0x2040;
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new();
    private readonly LiveSessionService _service;
    private readonly ScriptedLiveBackend _backend;
    private readonly LiveSessionTools _tools;

    public LiveJumpTests()
    {
        var path = Path.Combine(_dir.Path, "stubs.exe");
        File.WriteAllBytes(path, Image());
        _backend = new ScriptedLiveBackend(path, Base, 0x3000);
        _service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, new ServerOptions())) { Backend = _backend };
        _tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, _service);
    }

    public void Dispose()
    {
        _service.Dispose();
        _workspace.Dispose();
        _dir.Dispose();
    }

    /// <summary>A PE32+ with three jumps and the function they reach; the load configuration names the CFG dispatch pointer.</summary>
    private static byte[] Image()
    {
        static byte[] Rel(uint from, int length, uint to) => BitConverter.GetBytes((int)(to - (from + (uint)length)));
        var text = Enumerable.Repeat((byte)0xCC, 0x40).ToArray();
        void Put(uint rva, params byte[][] parts) => parts.SelectMany(p => p).ToArray().CopyTo(text, (int)(rva - 0x1000));
        Put(CfgStub, [0xFF, 0x25], Rel(CfgStub, 6, DispatchSlot));        // jmp [__guard_dispatch_icall_fptr]
        Put(DirectJump, [0xE9], Rel(DirectJump, 5, Function));             // jmp Function
        Put(Function, [0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3]);    // push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret
        Put(SlotJump, [0xFF, 0x25], Rel(SlotJump, 6, PointerSlot));        // jmp [pointer]

        var rdata = new PeBlob(0x2000);
        rdata.Zero((int)(DispatchSlot - 0x2000));
        rdata.U64(ImageBase + Function);
        rdata.U64(ImageBase + Function);
        rdata.Zero((int)(LoadConfig - rdata.Here));
        var config = new byte[0x140];
        BitConverter.GetBytes(config.Length).CopyTo(config, 0);
        BitConverter.GetBytes(ImageBase + DispatchSlot).CopyTo(config, 120);  // GuardCFDispatchFunctionPointer
        rdata.Bytes(config);

        var pe = new PeBuilder { EntryPoint = Function, ImageBase = ImageBase };
        pe.Add(".text", text, 0x60000020);
        pe.Add(".rdata", rdata.ToArray());
        pe.Directories[10] = (LoadConfig, (uint)config.Length);
        return pe.Build();
    }

    private static string At(uint rva) => $"0x{ImageBase + rva:X}";

    [Fact]
    public async Task A_jump_through_the_CFG_dispatch_pointer_is_refused_before_the_backend()
    {
        await _tools.LiveSession("attach", program: "4242");
        var e = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveBreak("live-1", "set", at: At(CfgStub)));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Contains("Control Flow Guard dispatch pointer", e.Message);
        await Assert.ThrowsAsync<ToolError>(() => _tools.LiveWatchCalls("live-1", "set", at: At(CfgStub)));
        lock (_backend.Ops) Assert.DoesNotContain(_backend.Ops, op => op is "set" or "watch");
    }

    [Fact]
    public async Task Direct_and_memory_jumps_are_followed_and_said()
    {
        await _tools.LiveSession("attach", program: "4242");
        _backend.Memory[Base + PointerSlot] = BitConverter.GetBytes(Base + Function); // the pointer as the loader left it

        var direct = await _tools.LiveBreak("live-1", "set", at: At(DirectJump));
        Assert.Contains($"set at 0x{Base + Function:X}", direct);
        Assert.Contains("jumps to", direct);
        var slot = await _tools.LiveBreak("live-1", "set", at: At(SlotJump));
        Assert.Contains($"set at 0x{Base + Function:X}", slot);
        var plain = await _tools.LiveBreak("live-1", "set", at: At(Function));
        Assert.DoesNotContain("jumps to", plain);

        var watch = await _tools.LiveWatchCalls("live-1", "set", at: At(DirectJump));
        Assert.Contains($"set at 0x{Base + Function:X}", watch);
    }
}
