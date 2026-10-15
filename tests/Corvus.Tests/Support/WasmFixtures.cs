using System.Text;
using Corvus.Core.WebAssembly;
using static Corvus.Core.WebAssembly.WasmType;

namespace Corvus.Tests;

/// <summary>
/// Generated WebAssembly modules that between them use every opcode the reader knows and every section form: the valid
/// ones (for the text and validation oracles) and invalid ones, each broken in one way.
/// </summary>
internal static class WasmFixtures
{
    private static readonly WasmType[] None = [];

    public static IEnumerable<(string Name, byte[] Bytes)> Valid() =>
    [
        ("empty", new WasmModuleBuilder().Build()),
        ("sample", WasmTests.Sample()),
        ("numeric", Numeric(simd: false)),
        ("simd", Numeric(simd: true)),
        ("memory", MemoryAccess()),
        ("atomics", Atomics()),
        ("control", Control()),
        ("floats", Floats()),
        ("integers", Integers()),
        ("names", Names()),
        ("elements", Elements()),
        ("bulk", Bulk()),
        ("tables", Tables()),
        ("exceptions", Exceptions()),
        ("tailcalls", TailCalls()),
        ("multivalue", MultiValue()),
        ("memory64", Memory64()),
        ("globals", Globals()),
        ("bytes", DataBytes()),
        ("locals", Locals()),
    ];

    /// <summary>Every opcode without immediates whose operands are numbers: constants in, the op, results dropped.</summary>
    private static byte[] Numeric(bool simd)
    {
        var b = new WasmModuleBuilder();
        uint t = b.Type(None, None);
        var a = new WasmAsm();
        for (int code = 0; code < (WasmOps.Fe | 0xFFFF); code++)
        {
            if (WasmOps.Get(code) is not { } op || op.Signature == "*" || op.Signature.Contains('a')) continue;
            bool isSimd = code >> 16 == 0xFD;
            if (isSimd != simd || op.Imm is not (WasmImm.None or WasmImm.Lane or WasmImm.Shuffle) || op.Signature == ":") continue;
            var (pops, pushes) = Split(op.Signature);
            foreach (char c in pops) a.Const(c);
            if (code >> 16 != 0) a.Prefixed((byte)(code >> 16), (uint)(code & 0xFFFF)); else a.Op((byte)code);
            if (op.Imm == WasmImm.Lane) a.Op(1);
            if (op.Imm == WasmImm.Shuffle) a.Raw([.. Enumerable.Range(0, 16).Select(i => (byte)(31 - i))]);
            foreach (char _ in pushes) a.Op(0x1A);
        }
        if (simd) a.Prefixed(0xFD, 12).Raw([.. Enumerable.Range(0, 16).Select(i => (byte)(i * 17))]).Op(0x1A);
        b.Func(t, a.Bytes);
        return b.Build();
    }

    private static (string Pops, string Pushes) Split(string sig) => (sig[..sig.IndexOf(':')], sig[(sig.IndexOf(':') + 1)..]);

    /// <summary>Every load and store, natural and smaller alignments, with and without offsets; SIMD lane loads and stores.</summary>
    private static byte[] MemoryAccess()
    {
        var b = new WasmModuleBuilder();
        uint t = b.Type(None, None);
        b.Memory(1, 2);
        var a = new WasmAsm();
        foreach (var round in new[] { 0, 1 })
            for (int code = 0; code < (WasmOps.Fd | 0xFFFF); code++)
            {
                if (WasmOps.Get(code) is not { IsMemoryAccess: true } op || code >> 16 == 0xFE) continue;
                var (pops, pushes) = Split(op.Signature);
                a.I32(round * 64);
                foreach (char c in pops[1..]) a.Const(c);
                if (code >> 16 != 0) a.Prefixed((byte)(code >> 16), (uint)(code & 0xFFFF)); else a.Op((byte)code);
                a.U(round == 0 ? (ulong)op.Align : 0).U(round == 0 ? 0UL : 1000);
                if (op.Imm == WasmImm.MemArgLane) a.Op(0);
                foreach (char _ in pushes) a.Op(0x1A);
            }
        a.Op(0x3F, 0).Op(0x1A).I32(1).Op(0x40, 0).Op(0x1A);
        b.Func(t, a.Bytes);
        return b.Build();
    }

    private static byte[] Atomics()
    {
        var b = new WasmModuleBuilder();
        uint t = b.Type(None, None);
        b.Memory(1, 1, shared: true);
        var a = new WasmAsm();
        for (int code = WasmOps.Fe; code < (WasmOps.Fe | 0xFF); code++)
        {
            if (WasmOps.Get(code) is not { } op) continue;
            if (op.Imm == WasmImm.Fence) { a.Prefixed(0xFE, 3).Op(0); continue; }
            var (pops, pushes) = Split(op.Signature);
            a.I32(0);
            foreach (char c in pops[1..]) a.Const(c);
            a.Prefixed(0xFE, (uint)(code & 0xFFFF)).U((ulong)op.Align).U(8);
            foreach (char _ in pushes) a.Op(0x1A);
        }
        b.Func(t, a.Bytes);
        return b.Build();
    }

    /// <summary>Blocks, loops, if with and without else (an empty else too), br, br_if, br_table, return, select, typed select.</summary>
    private static byte[] Control()
    {
        var b = new WasmModuleBuilder();
        uint v = b.Type(None, None), ii = b.Type([I32], [I32]), pair = b.Type([I32, I32], [I32]);
        var a = new WasmAsm()
            .Op(0x02, 0x40).Op(0x03, 0x40).Op(0x20).U(0).Op(0x0D).U(1).Op(0x0C).U(0).End().End() // block / loop / br_if / br
            .Op(0x02, 0x7F).I32(7).Op(0x20).U(0).Op(0x04, 0x7F).I32(1).Op(0x05).I32(2).End().Op(0x6A).End().Op(0x1A) // if/else with results
            .Op(0x20).U(0).Op(0x04, 0x40).Op(0x01).Op(0x05).End() // an empty else: dropped from the text
            .Op(0x20).U(0).Op(0x04, 0x40).End() // an empty if
            .Op(0x02, 0x40).Op(0x02, 0x40).Op(0x02, 0x40).Op(0x20).U(0).Op(0x0E).U(3).U(0).U(1).U(2).U(1).End().End().End() // br_table
            .I32(1).I32(2).Op(0x20).U(0).Op(0x1B).Op(0x1A) // select
            .I32(1).I32(2).Op(0x20).U(0).Op(0x1C).U(1).Op(0x7F).Op(0x1A) // typed select
            .I32(3).I32(4).Op(0x02).S((long)pair).Op(0x6A).End().Op(0x1A) // a block typed by index, with params
            .Op(0x20).U(0).Op(0x0F); // return
        b.Func(ii, a.Bytes);
        b.Func(v, new WasmAsm().Op(0x00).Op(0x6A).Op(0x1A).Bytes); // unreachable makes the rest polymorphic
        b.Func(v, []);
        return b.Build();
    }

    private static byte[] Floats()
    {
        var b = new WasmModuleBuilder();
        uint t = b.Type(None, None);
        var a = new WasmAsm();
        uint[] f32 = [0, 0x80000000, 0x3FC00000, 0x7F800000, 0xFF800000, 0x7FC00000, 0xFFC00000, 0x7FA00000, 0x7F800001, 1, 0x00400000, 0x7F7FFFFF,
            0x00800000, 0x3727C5AC, 0x47F12065, 0x49742400, 0x4974240A, 0xC2F6E979, 0x3DCCCCCD];
        ulong[] f64 = [0, 0x8000000000000000, 0x3FF8000000000000, 0x7FF0000000000000, 0xFFF0000000000000, 0x7FF8000000000000, 0xFFF8000000000000,
            0x7FF4000000000000, 0x7FF0000000000001, 1, 0x0008000000000000, 0x7FEFFFFFFFFFFFFF, 0x0010000000000000, 0x3EE4F8B588E368F1,
            0x40FE240CCCCCCCCD, 0x412E848000000000, 0x412E848000000001, 0xC05EDD2F1A9FBE77, 0x3FB999999999999A, 0x4415AF1D78B58C40, 0x3FD5555555555555];
        foreach (var bits in f32) a.F32Bits(bits).Op(0x1A);
        foreach (var bits in f64) a.F64Bits(bits).Op(0x1A);
        b.Func(t, a.Bytes);
        return b.Build();
    }

    private static byte[] Integers()
    {
        var b = new WasmModuleBuilder();
        uint t = b.Type(None, None);
        var a = new WasmAsm();
        foreach (var v in new[] { 0, 1, -1, 63, 64, -64, -65, int.MaxValue, int.MinValue, 123456789 }) a.I32(v).Op(0x1A);
        foreach (var v in new[] { 0L, -1, long.MaxValue, long.MinValue, 1L << 40, -(1L << 40) }) a.I64(v).Op(0x1A);
        b.Func(t, a.Bytes);
        return b.Build();
    }

    /// <summary>A name section with every subsection, duplicate names, names with spaces, parentheses and non-ASCII letters.</summary>
    private static byte[] Names()
    {
        var b = new WasmModuleBuilder();
        uint t = b.Type([I32, I64], [I32]);
        uint v = b.Type(None, None);
        uint log = b.ImportFunc("env", "log", v);
        b.ImportGlobal("env", "g", I32, false);
        b.Memory(1);
        b.Table(FuncRef, 2);
        b.Global(I32, true, new WasmAsm().I32(5).Bytes);
        uint f1 = b.Func(t, new WasmAsm().Op(0x20).U(0).Op(0x20).U(2).Op(0x6A).Op(0x23).U(1).Op(0x6A).Op(0x10).U(log).Bytes, (2, I32));
        uint f2 = b.Func(v, new WasmAsm().I32(0).I64(0).Op(0x10).U(1).Op(0x1A).I32(0).Op(0x24).U(1).Bytes);
        uint f3 = b.Func(v, []);
        uint f4 = b.Func(v, new WasmAsm().I32(0).Op(0x11).U(v).U(0).Bytes);
        b.Export("run", WasmExternal.Func, f1);
        b.Export("memory", WasmExternal.Memory, 0);
        b.Export("counter", WasmExternal.Global, 1);
        b.Element(0, f2, f3);
        b.Data(16, "hi"u8.ToArray());
        b.Names("my module", new Dictionary<int, Dictionary<uint, string>>
        {
            [1] = new() { [log] = "log", [f1] = "add(int, long)", [f2] = "dup", [f3] = "dup", [f4] = "café" },
            [4] = new() { [t] = "binary" },
            [5] = new() { [0] = "fns" },
            [6] = new() { [0] = "mem" },
            [7] = new() { [0] = "imported", [1] = "counter" },
            [8] = new() { [0] = "fn list" },
            [9] = new() { [0] = "greeting" },
        }, new Dictionary<uint, Dictionary<uint, string>> { [f1] = new() { [0] = "x", [2] = "sum", [3] = "x" } });
        return b.Build();
    }

    /// <summary>The eight element segment encodings.</summary>
    private static byte[] Elements()
    {
        var b = new WasmModuleBuilder();
        uint v = b.Type(None, None);
        b.Table(FuncRef, 10);
        b.Table(FuncRef, 10);
        uint f = b.Func(v, []), g = b.Func(v, []);
        byte[] at0 = new WasmAsm().I32(0).End().Bytes, at4 = new WasmAsm().I32(4).End().Bytes;
        byte[] refF = new WasmAsm().Op(0xD2).U(f).Bytes, refG = new WasmAsm().Op(0xD2).U(g).Bytes, nul = new WasmAsm().Op(0xD0, 0x70).Bytes;
        b.ElementRaw(0, [.. at0, .. WasmModuleBuilder.FunctionList(f, g)]);
        b.ElementRaw(1, [0, .. WasmModuleBuilder.FunctionList(g)]);
        b.ElementRaw(2, [1, .. at4, 0, .. WasmModuleBuilder.FunctionList(f)]);
        b.ElementRaw(3, [0, .. WasmModuleBuilder.FunctionList(f)]);
        b.ElementRaw(4, [.. at4, .. WasmModuleBuilder.ExprList(refF, refG)]);
        b.ElementRaw(5, [(byte)FuncRef, .. WasmModuleBuilder.ExprList(refF, nul)]);
        b.ElementRaw(6, [0, .. at0, (byte)FuncRef, .. WasmModuleBuilder.ExprList(nul)]);
        b.ElementRaw(7, [(byte)FuncRef, .. WasmModuleBuilder.ExprList(refG)]);
        b.ElementRaw(2, [0, .. at4, 0, .. WasmModuleBuilder.FunctionList(g)]);
        return b.Build();
    }

    /// <summary>Two memories, active data in each, passive data, memory.init / data.drop / memory.copy / memory.fill.</summary>
    private static byte[] Bulk()
    {
        var b = new WasmModuleBuilder();
        uint v = b.Type(None, None);
        b.Memory(1);
        b.Memory(1, 4);
        b.Data(0, "abc"u8.ToArray());
        b.PassiveData("passive"u8.ToArray());
        b.DataIn(1, 8, "second"u8.ToArray());
        b.DataCount(3);
        var a = new WasmAsm()
            .I32(0).I32(0).I32(3).Prefixed(0xFC, 8).U(1).U(0)
            .I32(0).I32(0).I32(1).Prefixed(0xFC, 8).U(1).U(1)
            .Prefixed(0xFC, 9).U(1)
            .I32(0).I32(1).I32(2).Prefixed(0xFC, 10).U(0).U(0)
            .I32(0).I32(1).I32(2).Prefixed(0xFC, 10).U(1).U(0)
            .I32(0).I32(0).I32(4).Prefixed(0xFC, 11).U(0)
            .I32(0).I32(0).I32(4).Prefixed(0xFC, 11).U(1)
            .I32(0).Op(0x28, 0x42, 1, 4).Op(0x1A)
            .Op(0x3F, 1).Op(0x1A).I32(1).Op(0x40, 1).Op(0x1A);
        b.Func(v, a.Bytes);
        return b.Build();
    }

    /// <summary>Two tables (funcref, externref): every table instruction, call_indirect through table 1, reference instructions.</summary>
    private static byte[] Tables()
    {
        var b = new WasmModuleBuilder();
        uint v = b.Type(None, None);
        b.Table(FuncRef, 4, 8);
        b.Table(ExternRef, 2);
        b.Table(FuncRef, 4);
        uint f = b.Func(v, new WasmAsm()
            .I32(0).Op(0x25).U(0).Op(0x1A)
            .I32(0).Op(0xD0, 0x6F).Op(0x26).U(1)
            .Prefixed(0xFC, 16).U(1).Op(0x1A)
            .Op(0xD0, 0x6F).I32(1).Prefixed(0xFC, 15).U(1).Op(0x1A)
            .I32(0).Op(0xD0, 0x70).I32(1).Prefixed(0xFC, 17).U(0)
            .I32(0).I32(0).I32(1).Prefixed(0xFC, 14).U(0).U(2)
            .I32(0).I32(0).I32(1).Prefixed(0xFC, 12).U(0).U(2)
            .Prefixed(0xFC, 13).U(0)
            .I32(0).Op(0x11).U(v).U(2)
            .Op(0xD2).U(0).Op(0xD1).Op(0x1A)
            .Bytes);
        b.ElementRaw(1, [0, .. WasmModuleBuilder.FunctionList(f)]);
        b.ElementRaw(3, [0, .. WasmModuleBuilder.FunctionList(f)]);
        return b.Build();
    }

    private static byte[] Exceptions()
    {
        var b = new WasmModuleBuilder();
        uint v = b.Type(None, None), takes = b.Type([I32], None);
        b.Tag(takes);
        b.Func(v, new WasmAsm()
            .Op(0x06, 0x40).I32(1).Op(0x08).U(0).Op(0x07).U(0).Op(0x1A).Op(0x19).Op(0x09).U(0).End()
            .Op(0x06, 0x40).Op(0x06, 0x40).Op(0x01).Op(0x18).U(0).Op(0x19).End()
            .Bytes);
        return b.Build();
    }

    private static byte[] TailCalls()
    {
        var b = new WasmModuleBuilder();
        uint v = b.Type(None, None);
        b.Table(FuncRef, 1);
        uint f = b.Func(v, new WasmAsm().Op(0x12).U(0).Bytes);
        b.Func(v, new WasmAsm().I32(0).Op(0x13).U(v).U(0).Bytes);
        b.Element(0, f);
        return b.Build();
    }

    private static byte[] MultiValue()
    {
        var b = new WasmModuleBuilder();
        uint two = b.Type(None, [I32, I64]), swap = b.Type([I32, I64], [I64, I32]);
        uint f = b.Func(two, new WasmAsm().I32(1).I64(2).Bytes);
        b.Func(swap, new WasmAsm().Op(0x10).U(f).Op(0x02).S((long)swap).Op(0x1A).Op(0x1A).I64(3).I32(4).End().Op(0x1A).Op(0x1A).Op(0x20).U(1).Op(0x20).U(0).Bytes);
        return b.Build();
    }

    private static byte[] Memory64()
    {
        var b = new WasmModuleBuilder();
        uint v = b.Type(None, None);
        b.Memory(1, 2, is64: true);
        b.Func(v, new WasmAsm().I64(8).Op(0x28, 2).U(16).Op(0x1A).I64(0).I32(1).Op(0x36, 2, 0).Op(0x3F, 0).Op(0x1A).I64(1).Op(0x40, 0).Op(0x1A).Bytes);
        return b.Build();
    }

    private static byte[] Globals()
    {
        var b = new WasmModuleBuilder();
        uint v = b.Type(None, None);
        b.ImportGlobal("env", "base", I32, false);
        b.ImportGlobal("env", "sp", I32, true);
        b.Global(I32, false, new WasmAsm().Op(0x23).U(0).I32(16).Op(0x6A).Bytes);
        b.Global(I64, true, new WasmAsm().I64(-5).Bytes);
        b.Global(F64, false, new WasmAsm().F64(2.5).Bytes);
        b.Global(FuncRef, false, new WasmAsm().Op(0xD0, 0x70).Bytes);
        uint f = b.Func(v, new WasmAsm().Op(0x23).U(1).I32(1).Op(0x6A).Op(0x24).U(1).Bytes);
        b.Export("sp", WasmExternal.Global, 1);
        b.Export("init", WasmExternal.Func, f);
        b.Start(f);
        return b.Build();
    }

    private static byte[] DataBytes()
    {
        var b = new WasmModuleBuilder();
        b.Memory(1);
        b.Data(0, [.. Enumerable.Range(0, 256).Select(i => (byte)i)]);
        b.Data(1024, Encoding.UTF8.GetBytes("quote \" backslash \\ tab \t done"));
        return b.Build();
    }

    private static byte[] Locals()
    {
        var b = new WasmModuleBuilder();
        uint t = b.Type([I32, F32], [F64]);
        b.Func(t, new WasmAsm().Op(0x20).U(8).Op(0x22).U(9).Op(0x21).U(8).Op(0x20).U(9).Bytes, (3, I32), (2, I64), (1, F32), (2, F64), (1, V128));
        return b.Build();
    }
}
