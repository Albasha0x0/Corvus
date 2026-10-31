using Iced.Intel;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Pe;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>Virtual calls through generated-metadata vtables of {methodPtr, MethodInfo*} entries.</summary>
public class MetadataVirtualCallTests
{
    private const ulong Base = 0x140000000UL;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const int VtableOffset = 0x138;

    private const int ReadBytesSlot = 25;
    private const int CloseSlot = 1;

    private static readonly string[] Functions =
    [
        "Reader_ReadBytes", "Reader_Close", "CallSlot",
        "VirtFuncInvoker1", "CallThroughInvoker",
    ];

    private static uint At(string name) => 0x1000u + 0x40u * (uint)Array.IndexOf(Functions, name);

    private static byte[] Assemble(uint rva, Action<Assembler> build)
    {
        var a = new Assembler(64);
        build(a);
        var stream = new MemoryStream();
        a.Assemble(new StreamCodeWriter(stream), Base + rva);
        return stream.ToArray();
    }

    /// <summary>
    /// A class with {methodPtr, MethodInfo*} entries at slots 1 and 25, a
    /// direct slot call and an invoker call.
    /// </summary>
    private static CodeTestImage Fixture()
    {
        var d = new PeBlob(Data);
        d.Zero(16);
        d.Align(8);
        uint info0 = d.U64(0), info1 = d.U64(0);
        d.Align(16);
        // The klass record: its vtable starts VtableOffset bytes in.
        d.U64(0);
        d.Zero(VtableOffset - 8);
        for (int slot = 0; slot <= ReadBytesSlot; slot++)
        {
            if (slot == CloseSlot) { d.U64(Base + At("Reader_Close")); d.U64(Base + info1); }
            else if (slot == ReadBytesSlot) { d.U64(Base + At("Reader_ReadBytes")); d.U64(Base + info0); }
            else { d.U64(0); d.U64(0); }
        }
        d.Zero(16);

        var code = new byte[0x40 * Functions.Length];
        Array.Fill(code, (byte)0xCC);
        void Put(string name, Action<Assembler> build)
        {
            var bytes = Assemble(At(name), build);
            Assert.True(bytes.Length <= 0x40, name);
            bytes.CopyTo(code, At(name) - 0x1000);
        }
        Put("Reader_ReadBytes", a => { a.xor(eax, eax); a.ret(); });
        Put("Reader_Close", a => { a.mov(eax, 1); a.ret(); });
        // A direct call of slot 1: the klass is loaded from the object header.
        Put("CallSlot", a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rax, __qword_ptr[rcx]);
            a.call(__qword_ptr[rax + (VtableOffset + 16 * CloseSlot)]);
            a.add(rsp, 0x28); a.ret();
        });
        // helper(slot, obj): indexes the vtable by a runtime slot and tail calls.
        Put("VirtFuncInvoker1", a =>
        {
            a.mov(rax, __qword_ptr[rdx]);
            a.shl(ecx, 4);
            a.movsxd(rcx, ecx);
            a.add(rax, rcx);
            a.mov(rcx, rdx);
            a.jmp(__qword_ptr[rax + VtableOffset]);
        });
        Put("CallThroughInvoker", a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rdx, rcx);
            a.mov(ecx, ReadBytesSlot);
            a.call(Base + At("VirtFuncInvoker1"));
            a.add(rsp, 0x28); a.ret();
        });
        var exports = Functions.Select((n, i) => new NativeExport(n, (uint)i + 1, At(n), null));
        return CodeTestImage.Synthetic(NativeArch.X64, code, d.ToArray(), exports: exports);
    }

    // x64 image with two vtable entries, one direct slot call, one invoker call.
    [Fact(Skip = "Needs the metadata slot readers and invoker recognition")]
    public void Metadata_vtable_slot_and_invoker_calls_resolve_to_their_methods()
    {
        var index = NativeCodeIndex.Build(Fixture());
        Assert.Equal(2, index.VirtualCalls.Stats.Sites);
        bool Resolves(string caller, string target) => index.VirtualEdges.Any(e =>
            e.From >= At(caller) && e.From < At(caller) + 0x40 && e.To == At(target));
        Assert.True(Resolves("CallSlot", "Reader_Close"));
        Assert.True(Resolves("VirtFuncInvoker1", "Reader_ReadBytes")
            || Resolves("CallThroughInvoker", "Reader_ReadBytes"));
    }
}
