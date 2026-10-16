namespace Corvus.Core.WebAssembly;

/// <summary>What follows an opcode in the binary.</summary>
public enum WasmImm : byte
{
    None,
    BlockType,
    Label,
    BrTable,
    Func,
    CallIndirect,
    TypeIndex,
    Local,
    Global,
    Table,
    MemArg,
    Memory,
    I32,
    I64,
    F32,
    F64,
    HeapType,
    SelectTypes,
    Tag,
    TryTable,
    Lane,
    MemArgLane,
    V128,
    Shuffle,
    DataMemory,
    Data,
    TwoMemories,
    ElemTable,
    Elem,
    TwoTables,
    Fence,
    /// <summary>A type index and a field index (struct.get).</summary>
    TypeField,
    /// <summary>A type index and an element count (array.new_fixed).</summary>
    TypeCount,
    TypeData,
    TypeElem,
    TwoTypes,
    /// <summary>br_on_cast flags, label and two heap types.</summary>
    BrOnCast,
}

/// <summary>
/// One opcode: its text name, immediate kind, operand signature ("pops:pushes" over i i32, l i64, f f32, d f64, v v128, a an
/// address of the instruction's memory; "*" when the type rules are the instruction's own) and, for memory accesses, the
/// natural alignment as a power of two.
/// </summary>
public sealed record WasmOp(int Code, string Name, WasmImm Imm, string Signature, int Align = -1)
{
    public bool IsMemoryAccess => Imm is WasmImm.MemArg or WasmImm.MemArgLane;
}

/// <summary>
/// The opcode table: MVP, sign extension, saturating truncation, bulk memory, reference types, SIMD and relaxed SIMD,
/// threads, tail calls, exception handling (legacy and try_table), typed function references and GC. A prefixed opcode's
/// code is prefix &lt;&lt; 16 | sub-opcode.
/// </summary>
public static class WasmOps
{
    public const int Fb = 0xFB << 16, Fc = 0xFC << 16, Fd = 0xFD << 16, Fe = 0xFE << 16;

    private static readonly Dictionary<int, WasmOp> ByCode = [];

    public static WasmOp? Get(int code) => ByCode.GetValueOrDefault(code);

    private static void Add(int code, string name, WasmImm imm = WasmImm.None, string sig = "*", int align = -1) => ByCode[code] = new WasmOp(code, name, imm, sig, align);

    static WasmOps()
    {
        Add(0x00, "unreachable"); Add(0x01, "nop", sig: ":");
        Add(0x02, "block", WasmImm.BlockType); Add(0x03, "loop", WasmImm.BlockType); Add(0x04, "if", WasmImm.BlockType);
        Add(0x05, "else"); Add(0x06, "try", WasmImm.BlockType); Add(0x07, "catch", WasmImm.Tag); Add(0x08, "throw", WasmImm.Tag);
        Add(0x09, "rethrow", WasmImm.Label); Add(0x0A, "throw_ref"); Add(0x0B, "end");
        Add(0x0C, "br", WasmImm.Label); Add(0x0D, "br_if", WasmImm.Label); Add(0x0E, "br_table", WasmImm.BrTable); Add(0x0F, "return");
        Add(0x10, "call", WasmImm.Func); Add(0x11, "call_indirect", WasmImm.CallIndirect);
        Add(0x12, "return_call", WasmImm.Func); Add(0x13, "return_call_indirect", WasmImm.CallIndirect);
        Add(0x14, "call_ref", WasmImm.TypeIndex); Add(0x15, "return_call_ref", WasmImm.TypeIndex);
        Add(0x18, "delegate", WasmImm.Label); Add(0x19, "catch_all");
        Add(0x1A, "drop"); Add(0x1B, "select"); Add(0x1C, "select", WasmImm.SelectTypes); Add(0x1F, "try_table", WasmImm.TryTable);
        Add(0x20, "local.get", WasmImm.Local); Add(0x21, "local.set", WasmImm.Local); Add(0x22, "local.tee", WasmImm.Local);
        Add(0x23, "global.get", WasmImm.Global); Add(0x24, "global.set", WasmImm.Global);
        Add(0x25, "table.get", WasmImm.Table); Add(0x26, "table.set", WasmImm.Table);

        (int, string, string, int)[] memory =
        [
            (0x28, "i32.load", "a:i", 2), (0x29, "i64.load", "a:l", 3), (0x2A, "f32.load", "a:f", 2), (0x2B, "f64.load", "a:d", 3),
            (0x2C, "i32.load8_s", "a:i", 0), (0x2D, "i32.load8_u", "a:i", 0), (0x2E, "i32.load16_s", "a:i", 1), (0x2F, "i32.load16_u", "a:i", 1),
            (0x30, "i64.load8_s", "a:l", 0), (0x31, "i64.load8_u", "a:l", 0), (0x32, "i64.load16_s", "a:l", 1), (0x33, "i64.load16_u", "a:l", 1),
            (0x34, "i64.load32_s", "a:l", 2), (0x35, "i64.load32_u", "a:l", 2),
            (0x36, "i32.store", "ai:", 2), (0x37, "i64.store", "al:", 3), (0x38, "f32.store", "af:", 2), (0x39, "f64.store", "ad:", 3),
            (0x3A, "i32.store8", "ai:", 0), (0x3B, "i32.store16", "ai:", 1), (0x3C, "i64.store8", "al:", 0), (0x3D, "i64.store16", "al:", 1),
            (0x3E, "i64.store32", "al:", 2),
        ];
        foreach (var (code, name, sig, align) in memory) Add(code, name, WasmImm.MemArg, sig, align);
        Add(0x3F, "memory.size", WasmImm.Memory, ":a"); Add(0x40, "memory.grow", WasmImm.Memory, "a:a");
        Add(0x41, "i32.const", WasmImm.I32, ":i"); Add(0x42, "i64.const", WasmImm.I64, ":l");
        Add(0x43, "f32.const", WasmImm.F32, ":f"); Add(0x44, "f64.const", WasmImm.F64, ":d");

        Simple(0x45, "i:i", "i32.eqz");
        Simple(0x46, "ii:i", "i32.eq", "i32.ne", "i32.lt_s", "i32.lt_u", "i32.gt_s", "i32.gt_u", "i32.le_s", "i32.le_u", "i32.ge_s", "i32.ge_u");
        Simple(0x50, "l:i", "i64.eqz");
        Simple(0x51, "ll:i", "i64.eq", "i64.ne", "i64.lt_s", "i64.lt_u", "i64.gt_s", "i64.gt_u", "i64.le_s", "i64.le_u", "i64.ge_s", "i64.ge_u");
        Simple(0x5B, "ff:i", "f32.eq", "f32.ne", "f32.lt", "f32.gt", "f32.le", "f32.ge");
        Simple(0x61, "dd:i", "f64.eq", "f64.ne", "f64.lt", "f64.gt", "f64.le", "f64.ge");
        Simple(0x67, "i:i", "i32.clz", "i32.ctz", "i32.popcnt");
        Simple(0x6A, "ii:i", "i32.add", "i32.sub", "i32.mul", "i32.div_s", "i32.div_u", "i32.rem_s", "i32.rem_u", "i32.and", "i32.or", "i32.xor",
            "i32.shl", "i32.shr_s", "i32.shr_u", "i32.rotl", "i32.rotr");
        Simple(0x79, "l:l", "i64.clz", "i64.ctz", "i64.popcnt");
        Simple(0x7C, "ll:l", "i64.add", "i64.sub", "i64.mul", "i64.div_s", "i64.div_u", "i64.rem_s", "i64.rem_u", "i64.and", "i64.or", "i64.xor",
            "i64.shl", "i64.shr_s", "i64.shr_u", "i64.rotl", "i64.rotr");
        Simple(0x8B, "f:f", "f32.abs", "f32.neg", "f32.ceil", "f32.floor", "f32.trunc", "f32.nearest", "f32.sqrt");
        Simple(0x92, "ff:f", "f32.add", "f32.sub", "f32.mul", "f32.div", "f32.min", "f32.max", "f32.copysign");
        Simple(0x99, "d:d", "f64.abs", "f64.neg", "f64.ceil", "f64.floor", "f64.trunc", "f64.nearest", "f64.sqrt");
        Simple(0xA0, "dd:d", "f64.add", "f64.sub", "f64.mul", "f64.div", "f64.min", "f64.max", "f64.copysign");
        (int, string, string)[] conversions =
        [
            (0xA7, "i32.wrap_i64", "l:i"), (0xA8, "i32.trunc_f32_s", "f:i"), (0xA9, "i32.trunc_f32_u", "f:i"), (0xAA, "i32.trunc_f64_s", "d:i"),
            (0xAB, "i32.trunc_f64_u", "d:i"), (0xAC, "i64.extend_i32_s", "i:l"), (0xAD, "i64.extend_i32_u", "i:l"), (0xAE, "i64.trunc_f32_s", "f:l"),
            (0xAF, "i64.trunc_f32_u", "f:l"), (0xB0, "i64.trunc_f64_s", "d:l"), (0xB1, "i64.trunc_f64_u", "d:l"), (0xB2, "f32.convert_i32_s", "i:f"),
            (0xB3, "f32.convert_i32_u", "i:f"), (0xB4, "f32.convert_i64_s", "l:f"), (0xB5, "f32.convert_i64_u", "l:f"), (0xB6, "f32.demote_f64", "d:f"),
            (0xB7, "f64.convert_i32_s", "i:d"), (0xB8, "f64.convert_i32_u", "i:d"), (0xB9, "f64.convert_i64_s", "l:d"), (0xBA, "f64.convert_i64_u", "l:d"),
            (0xBB, "f64.promote_f32", "f:d"), (0xBC, "i32.reinterpret_f32", "f:i"), (0xBD, "i64.reinterpret_f64", "d:l"), (0xBE, "f32.reinterpret_i32", "i:f"),
            (0xBF, "f64.reinterpret_i64", "l:d"), (0xC0, "i32.extend8_s", "i:i"), (0xC1, "i32.extend16_s", "i:i"), (0xC2, "i64.extend8_s", "l:l"),
            (0xC3, "i64.extend16_s", "l:l"), (0xC4, "i64.extend32_s", "l:l"),
        ];
        foreach (var (code, name, sig) in conversions) Add(code, name, sig: sig);
        Add(0xD0, "ref.null", WasmImm.HeapType); Add(0xD1, "ref.is_null"); Add(0xD2, "ref.func", WasmImm.Func);
        Add(0xD3, "ref.eq"); Add(0xD4, "ref.as_non_null"); Add(0xD5, "br_on_null", WasmImm.Label); Add(0xD6, "br_on_non_null", WasmImm.Label);

        string[] saturating = ["i32.trunc_sat_f32_s", "i32.trunc_sat_f32_u", "i32.trunc_sat_f64_s", "i32.trunc_sat_f64_u",
            "i64.trunc_sat_f32_s", "i64.trunc_sat_f32_u", "i64.trunc_sat_f64_s", "i64.trunc_sat_f64_u"];
        string[] satSig = ["f:i", "f:i", "d:i", "d:i", "f:l", "f:l", "d:l", "d:l"];
        for (int i = 0; i < 8; i++) Add(Fc | i, saturating[i], sig: satSig[i]);
        Add(Fc | 8, "memory.init", WasmImm.DataMemory); Add(Fc | 9, "data.drop", WasmImm.Data, ":"); Add(Fc | 10, "memory.copy", WasmImm.TwoMemories);
        Add(Fc | 11, "memory.fill", WasmImm.Memory); Add(Fc | 12, "table.init", WasmImm.ElemTable); Add(Fc | 13, "elem.drop", WasmImm.Elem, ":");
        Add(Fc | 14, "table.copy", WasmImm.TwoTables); Add(Fc | 15, "table.grow", WasmImm.Table); Add(Fc | 16, "table.size", WasmImm.Table);
        Add(Fc | 17, "table.fill", WasmImm.Table);

        Atomics();
        Simd();
        Gc();
    }

    private static void Gc()
    {
        Add(Fb | 0, "struct.new", WasmImm.TypeIndex); Add(Fb | 1, "struct.new_default", WasmImm.TypeIndex);
        Add(Fb | 2, "struct.get", WasmImm.TypeField); Add(Fb | 3, "struct.get_s", WasmImm.TypeField); Add(Fb | 4, "struct.get_u", WasmImm.TypeField);
        Add(Fb | 5, "struct.set", WasmImm.TypeField);
        Add(Fb | 6, "array.new", WasmImm.TypeIndex); Add(Fb | 7, "array.new_default", WasmImm.TypeIndex); Add(Fb | 8, "array.new_fixed", WasmImm.TypeCount);
        Add(Fb | 9, "array.new_data", WasmImm.TypeData); Add(Fb | 10, "array.new_elem", WasmImm.TypeElem);
        Add(Fb | 11, "array.get", WasmImm.TypeIndex); Add(Fb | 12, "array.get_s", WasmImm.TypeIndex); Add(Fb | 13, "array.get_u", WasmImm.TypeIndex);
        Add(Fb | 14, "array.set", WasmImm.TypeIndex); Add(Fb | 15, "array.len"); Add(Fb | 16, "array.fill", WasmImm.TypeIndex);
        Add(Fb | 17, "array.copy", WasmImm.TwoTypes); Add(Fb | 18, "array.init_data", WasmImm.TypeData); Add(Fb | 19, "array.init_elem", WasmImm.TypeElem);
        Add(Fb | 20, "ref.test", WasmImm.HeapType); Add(Fb | 21, "ref.test", WasmImm.HeapType);
        Add(Fb | 22, "ref.cast", WasmImm.HeapType); Add(Fb | 23, "ref.cast", WasmImm.HeapType);
        Add(Fb | 24, "br_on_cast", WasmImm.BrOnCast); Add(Fb | 25, "br_on_cast_fail", WasmImm.BrOnCast);
        Add(Fb | 26, "any.convert_extern"); Add(Fb | 27, "extern.convert_any");
        Add(Fb | 28, "ref.i31"); Add(Fb | 29, "i31.get_s"); Add(Fb | 30, "i31.get_u");
    }

    private static void Simple(int first, string sig, params string[] names)
    {
        for (int i = 0; i < names.Length; i++) Add(first + i, names[i], sig: sig);
    }

    private static void Atomics()
    {
        Add(Fe | 0x00, "memory.atomic.notify", WasmImm.MemArg, "ai:i", 2);
        Add(Fe | 0x01, "memory.atomic.wait32", WasmImm.MemArg, "ail:i", 2);
        Add(Fe | 0x02, "memory.atomic.wait64", WasmImm.MemArg, "all:i", 3);
        Add(Fe | 0x03, "atomic.fence", WasmImm.Fence, ":");
        (string, string, int)[] loads = [("i32.atomic.load", "a:i", 2), ("i64.atomic.load", "a:l", 3), ("i32.atomic.load8_u", "a:i", 0), ("i32.atomic.load16_u", "a:i", 1),
            ("i64.atomic.load8_u", "a:l", 0), ("i64.atomic.load16_u", "a:l", 1), ("i64.atomic.load32_u", "a:l", 2)];
        for (int i = 0; i < loads.Length; i++) Add(Fe | (0x10 + i), loads[i].Item1, WasmImm.MemArg, loads[i].Item2, loads[i].Item3);
        (string, string, int)[] stores = [("i32.atomic.store", "ai:", 2), ("i64.atomic.store", "al:", 3), ("i32.atomic.store8", "ai:", 0), ("i32.atomic.store16", "ai:", 1),
            ("i64.atomic.store8", "al:", 0), ("i64.atomic.store16", "al:", 1), ("i64.atomic.store32", "al:", 2)];
        for (int i = 0; i < stores.Length; i++) Add(Fe | (0x17 + i), stores[i].Item1, WasmImm.MemArg, stores[i].Item2, stores[i].Item3);
        string[] ops = ["add", "sub", "and", "or", "xor", "xchg"];
        for (int o = 0; o < ops.Length; o++)
        {
            int at = 0x1E + o * 7;
            (string, string, int)[] rmw = [($"i32.atomic.rmw.{ops[o]}", "ai:i", 2), ($"i64.atomic.rmw.{ops[o]}", "al:l", 3), ($"i32.atomic.rmw8.{ops[o]}_u", "ai:i", 0),
                ($"i32.atomic.rmw16.{ops[o]}_u", "ai:i", 1), ($"i64.atomic.rmw8.{ops[o]}_u", "al:l", 0), ($"i64.atomic.rmw16.{ops[o]}_u", "al:l", 1),
                ($"i64.atomic.rmw32.{ops[o]}_u", "al:l", 2)];
            for (int i = 0; i < rmw.Length; i++) Add(Fe | (at + i), rmw[i].Item1, WasmImm.MemArg, rmw[i].Item2, rmw[i].Item3);
        }
        (string, string, int)[] cmpxchg = [("i32.atomic.rmw.cmpxchg", "aii:i", 2), ("i64.atomic.rmw.cmpxchg", "all:l", 3), ("i32.atomic.rmw8.cmpxchg_u", "aii:i", 0),
            ("i32.atomic.rmw16.cmpxchg_u", "aii:i", 1), ("i64.atomic.rmw8.cmpxchg_u", "all:l", 0), ("i64.atomic.rmw16.cmpxchg_u", "all:l", 1),
            ("i64.atomic.rmw32.cmpxchg_u", "all:l", 2)];
        for (int i = 0; i < cmpxchg.Length; i++) Add(Fe | (0x48 + i), cmpxchg[i].Item1, WasmImm.MemArg, cmpxchg[i].Item2, cmpxchg[i].Item3);
    }

    private static void Simd()
    {
        (int, string, string, int)[] loads =
        [
            (0, "v128.load", "a:v", 4), (1, "v128.load8x8_s", "a:v", 3), (2, "v128.load8x8_u", "a:v", 3), (3, "v128.load16x4_s", "a:v", 3),
            (4, "v128.load16x4_u", "a:v", 3), (5, "v128.load32x2_s", "a:v", 3), (6, "v128.load32x2_u", "a:v", 3), (7, "v128.load8_splat", "a:v", 0),
            (8, "v128.load16_splat", "a:v", 1), (9, "v128.load32_splat", "a:v", 2), (10, "v128.load64_splat", "a:v", 3), (11, "v128.store", "av:", 4),
            (92, "v128.load32_zero", "a:v", 2), (93, "v128.load64_zero", "a:v", 3),
        ];
        foreach (var (code, name, sig, align) in loads) Add(Fd | code, name, WasmImm.MemArg, sig, align);
        Add(Fd | 12, "v128.const", WasmImm.V128, ":v");
        Add(Fd | 13, "i8x16.shuffle", WasmImm.Shuffle, "vv:v");
        Add(Fd | 14, "i8x16.swizzle", sig: "vv:v");
        string[] splats = ["i8x16", "i16x8", "i32x4", "i64x2", "f32x4", "f64x2"];
        string[] scalars = ["i", "i", "i", "l", "f", "d"];
        for (int i = 0; i < 6; i++) Add(Fd | (15 + i), splats[i] + ".splat", sig: scalars[i] + ":v");
        (int, string, string)[] lanes =
        [
            (21, "i8x16.extract_lane_s", "v:i"), (22, "i8x16.extract_lane_u", "v:i"), (23, "i8x16.replace_lane", "vi:v"),
            (24, "i16x8.extract_lane_s", "v:i"), (25, "i16x8.extract_lane_u", "v:i"), (26, "i16x8.replace_lane", "vi:v"),
            (27, "i32x4.extract_lane", "v:i"), (28, "i32x4.replace_lane", "vi:v"), (29, "i64x2.extract_lane", "v:l"), (30, "i64x2.replace_lane", "vl:v"),
            (31, "f32x4.extract_lane", "v:f"), (32, "f32x4.replace_lane", "vf:v"), (33, "f64x2.extract_lane", "v:d"), (34, "f64x2.replace_lane", "vd:v"),
        ];
        foreach (var (code, name, sig) in lanes) Add(Fd | code, name, WasmImm.Lane, sig);
        string[] compare = ["eq", "ne", "lt_s", "lt_u", "gt_s", "gt_u", "le_s", "le_u", "ge_s", "ge_u"];
        for (int i = 0; i < 10; i++)
        {
            Add(Fd | (35 + i), "i8x16." + compare[i], sig: "vv:v");
            Add(Fd | (45 + i), "i16x8." + compare[i], sig: "vv:v");
            Add(Fd | (55 + i), "i32x4." + compare[i], sig: "vv:v");
        }
        string[] fcompare = ["eq", "ne", "lt", "gt", "le", "ge"];
        for (int i = 0; i < 6; i++)
        {
            Add(Fd | (65 + i), "f32x4." + fcompare[i], sig: "vv:v");
            Add(Fd | (71 + i), "f64x2." + fcompare[i], sig: "vv:v");
        }
        Add(Fd | 77, "v128.not", sig: "v:v"); Add(Fd | 78, "v128.and", sig: "vv:v"); Add(Fd | 79, "v128.andnot", sig: "vv:v");
        Add(Fd | 80, "v128.or", sig: "vv:v"); Add(Fd | 81, "v128.xor", sig: "vv:v"); Add(Fd | 82, "v128.bitselect", sig: "vvv:v");
        Add(Fd | 83, "v128.any_true", sig: "v:i");
        string[] laneLoads = ["v128.load8_lane", "v128.load16_lane", "v128.load32_lane", "v128.load64_lane"];
        string[] laneStores = ["v128.store8_lane", "v128.store16_lane", "v128.store32_lane", "v128.store64_lane"];
        for (int i = 0; i < 4; i++)
        {
            Add(Fd | (84 + i), laneLoads[i], WasmImm.MemArgLane, "av:v", i);
            Add(Fd | (88 + i), laneStores[i], WasmImm.MemArgLane, "av:", i);
        }
        (int, string, string)[] ops =
        [
            (94, "f32x4.demote_f64x2_zero", "v:v"), (95, "f64x2.promote_low_f32x4", "v:v"),
            (96, "i8x16.abs", "v:v"), (97, "i8x16.neg", "v:v"), (98, "i8x16.popcnt", "v:v"), (99, "i8x16.all_true", "v:i"), (100, "i8x16.bitmask", "v:i"),
            (101, "i8x16.narrow_i16x8_s", "vv:v"), (102, "i8x16.narrow_i16x8_u", "vv:v"),
            (103, "f32x4.ceil", "v:v"), (104, "f32x4.floor", "v:v"), (105, "f32x4.trunc", "v:v"), (106, "f32x4.nearest", "v:v"),
            (107, "i8x16.shl", "vi:v"), (108, "i8x16.shr_s", "vi:v"), (109, "i8x16.shr_u", "vi:v"),
            (110, "i8x16.add", "vv:v"), (111, "i8x16.add_sat_s", "vv:v"), (112, "i8x16.add_sat_u", "vv:v"), (113, "i8x16.sub", "vv:v"),
            (114, "i8x16.sub_sat_s", "vv:v"), (115, "i8x16.sub_sat_u", "vv:v"), (116, "f64x2.ceil", "v:v"), (117, "f64x2.floor", "v:v"),
            (118, "i8x16.min_s", "vv:v"), (119, "i8x16.min_u", "vv:v"), (120, "i8x16.max_s", "vv:v"), (121, "i8x16.max_u", "vv:v"),
            (122, "f64x2.trunc", "v:v"), (123, "i8x16.avgr_u", "vv:v"),
            (124, "i16x8.extadd_pairwise_i8x16_s", "v:v"), (125, "i16x8.extadd_pairwise_i8x16_u", "v:v"),
            (126, "i32x4.extadd_pairwise_i16x8_s", "v:v"), (127, "i32x4.extadd_pairwise_i16x8_u", "v:v"),
            (128, "i16x8.abs", "v:v"), (129, "i16x8.neg", "v:v"), (130, "i16x8.q15mulr_sat_s", "vv:v"), (131, "i16x8.all_true", "v:i"),
            (132, "i16x8.bitmask", "v:i"), (133, "i16x8.narrow_i32x4_s", "vv:v"), (134, "i16x8.narrow_i32x4_u", "vv:v"),
            (135, "i16x8.extend_low_i8x16_s", "v:v"), (136, "i16x8.extend_high_i8x16_s", "v:v"), (137, "i16x8.extend_low_i8x16_u", "v:v"),
            (138, "i16x8.extend_high_i8x16_u", "v:v"), (139, "i16x8.shl", "vi:v"), (140, "i16x8.shr_s", "vi:v"), (141, "i16x8.shr_u", "vi:v"),
            (142, "i16x8.add", "vv:v"), (143, "i16x8.add_sat_s", "vv:v"), (144, "i16x8.add_sat_u", "vv:v"), (145, "i16x8.sub", "vv:v"),
            (146, "i16x8.sub_sat_s", "vv:v"), (147, "i16x8.sub_sat_u", "vv:v"), (148, "f64x2.nearest", "v:v"), (149, "i16x8.mul", "vv:v"),
            (150, "i16x8.min_s", "vv:v"), (151, "i16x8.min_u", "vv:v"), (152, "i16x8.max_s", "vv:v"), (153, "i16x8.max_u", "vv:v"),
            (155, "i16x8.avgr_u", "vv:v"), (156, "i16x8.extmul_low_i8x16_s", "vv:v"), (157, "i16x8.extmul_high_i8x16_s", "vv:v"),
            (158, "i16x8.extmul_low_i8x16_u", "vv:v"), (159, "i16x8.extmul_high_i8x16_u", "vv:v"),
            (160, "i32x4.abs", "v:v"), (161, "i32x4.neg", "v:v"), (163, "i32x4.all_true", "v:i"), (164, "i32x4.bitmask", "v:i"),
            (167, "i32x4.extend_low_i16x8_s", "v:v"), (168, "i32x4.extend_high_i16x8_s", "v:v"), (169, "i32x4.extend_low_i16x8_u", "v:v"),
            (170, "i32x4.extend_high_i16x8_u", "v:v"), (171, "i32x4.shl", "vi:v"), (172, "i32x4.shr_s", "vi:v"), (173, "i32x4.shr_u", "vi:v"),
            (174, "i32x4.add", "vv:v"), (177, "i32x4.sub", "vv:v"), (181, "i32x4.mul", "vv:v"), (182, "i32x4.min_s", "vv:v"),
            (183, "i32x4.min_u", "vv:v"), (184, "i32x4.max_s", "vv:v"), (185, "i32x4.max_u", "vv:v"), (186, "i32x4.dot_i16x8_s", "vv:v"),
            (188, "i32x4.extmul_low_i16x8_s", "vv:v"), (189, "i32x4.extmul_high_i16x8_s", "vv:v"), (190, "i32x4.extmul_low_i16x8_u", "vv:v"),
            (191, "i32x4.extmul_high_i16x8_u", "vv:v"),
            (192, "i64x2.abs", "v:v"), (193, "i64x2.neg", "v:v"), (195, "i64x2.all_true", "v:i"), (196, "i64x2.bitmask", "v:i"),
            (199, "i64x2.extend_low_i32x4_s", "v:v"), (200, "i64x2.extend_high_i32x4_s", "v:v"), (201, "i64x2.extend_low_i32x4_u", "v:v"),
            (202, "i64x2.extend_high_i32x4_u", "v:v"), (203, "i64x2.shl", "vi:v"), (204, "i64x2.shr_s", "vi:v"), (205, "i64x2.shr_u", "vi:v"),
            (206, "i64x2.add", "vv:v"), (209, "i64x2.sub", "vv:v"), (213, "i64x2.mul", "vv:v"),
            (214, "i64x2.eq", "vv:v"), (215, "i64x2.ne", "vv:v"), (216, "i64x2.lt_s", "vv:v"), (217, "i64x2.gt_s", "vv:v"), (218, "i64x2.le_s", "vv:v"),
            (219, "i64x2.ge_s", "vv:v"), (220, "i64x2.extmul_low_i32x4_s", "vv:v"), (221, "i64x2.extmul_high_i32x4_s", "vv:v"),
            (222, "i64x2.extmul_low_i32x4_u", "vv:v"), (223, "i64x2.extmul_high_i32x4_u", "vv:v"),
            (224, "f32x4.abs", "v:v"), (225, "f32x4.neg", "v:v"), (227, "f32x4.sqrt", "v:v"), (228, "f32x4.add", "vv:v"), (229, "f32x4.sub", "vv:v"),
            (230, "f32x4.mul", "vv:v"), (231, "f32x4.div", "vv:v"), (232, "f32x4.min", "vv:v"), (233, "f32x4.max", "vv:v"), (234, "f32x4.pmin", "vv:v"),
            (235, "f32x4.pmax", "vv:v"),
            (236, "f64x2.abs", "v:v"), (237, "f64x2.neg", "v:v"), (239, "f64x2.sqrt", "v:v"), (240, "f64x2.add", "vv:v"), (241, "f64x2.sub", "vv:v"),
            (242, "f64x2.mul", "vv:v"), (243, "f64x2.div", "vv:v"), (244, "f64x2.min", "vv:v"), (245, "f64x2.max", "vv:v"), (246, "f64x2.pmin", "vv:v"),
            (247, "f64x2.pmax", "vv:v"),
            (248, "i32x4.trunc_sat_f32x4_s", "v:v"), (249, "i32x4.trunc_sat_f32x4_u", "v:v"), (250, "f32x4.convert_i32x4_s", "v:v"),
            (251, "f32x4.convert_i32x4_u", "v:v"), (252, "i32x4.trunc_sat_f64x2_s_zero", "v:v"), (253, "i32x4.trunc_sat_f64x2_u_zero", "v:v"),
            (254, "f64x2.convert_low_i32x4_s", "v:v"), (255, "f64x2.convert_low_i32x4_u", "v:v"),
            (256, "i8x16.relaxed_swizzle", "vv:v"), (257, "i32x4.relaxed_trunc_f32x4_s", "v:v"), (258, "i32x4.relaxed_trunc_f32x4_u", "v:v"),
            (259, "i32x4.relaxed_trunc_f64x2_s_zero", "v:v"), (260, "i32x4.relaxed_trunc_f64x2_u_zero", "v:v"), (261, "f32x4.relaxed_madd", "vvv:v"),
            (262, "f32x4.relaxed_nmadd", "vvv:v"), (263, "f64x2.relaxed_madd", "vvv:v"), (264, "f64x2.relaxed_nmadd", "vvv:v"),
            (265, "i8x16.relaxed_laneselect", "vvv:v"), (266, "i16x8.relaxed_laneselect", "vvv:v"), (267, "i32x4.relaxed_laneselect", "vvv:v"),
            (268, "i64x2.relaxed_laneselect", "vvv:v"), (269, "f32x4.relaxed_min", "vv:v"), (270, "f32x4.relaxed_max", "vv:v"),
            (271, "f64x2.relaxed_min", "vv:v"), (272, "f64x2.relaxed_max", "vv:v"), (273, "i16x8.relaxed_q15mulr_s", "vv:v"),
            (274, "i16x8.relaxed_dot_i8x16_i7x16_s", "vv:v"), (275, "i32x4.relaxed_dot_i8x16_i7x16_add_s", "vvv:v"),
        ];
        foreach (var (code, name, sig) in ops) Add(Fd | code, name, sig: sig);
    }
}
