using System.Numerics;

namespace NetDecompilerMcp.Native.Code;

/// <summary>
/// Table-driven decoding of A32 (ARM) and T32 (Thumb / Thumb-2) instructions in the classes compilers emit: data
/// processing, multiplies and divides, loads and stores (single, dual, exclusive, multiple), branches (CBZ / CBNZ, IT,
/// table branches), MOVW / MOVT, system and hint instructions, VFP and NEON loads, stores and moves, VFP arithmetic.
/// NEON data processing goes to <see cref="Arm32Neon"/>; anything unallocated is invalid.
/// </summary>
internal static class Arm32Decode
{
    private const int Pc = 15, Lr = 14, Sp = 13;

    private static void Init(out ArmInstruction i, uint address, int length, bool thumb, uint raw)
    {
        i = default;
        i.Address = address;
        i.Length = (byte)length;
        i.Thumb = thumb;
        i.Raw = raw;
        i.Mnemonic = "(bad)";
        i.Cond = ArmInstruction.Always;
        i.Flow = ArmFlow.Invalid;
    }

    private static void Set(ref ArmInstruction i, string mnemonic)
    {
        i.Mnemonic = mnemonic;
        i.Flow = ArmFlow.Next;
    }

    private static void Bad(ref ArmInstruction i)
    {
        i.Mnemonic = "(bad)";
        i.Flow = ArmFlow.Invalid;
        i.ResetOperands();
    }

    private static int SignExtend(uint value, int bits) => (int)(value << (32 - bits)) >> (32 - bits);

    /// <summary>Length of the Thumb instruction whose first halfword is <paramref name="hw1"/>.</summary>
    public static int ThumbLength(ushort hw1) => (hw1 >> 11) is 0b11101 or 0b11110 or 0b11111 ? 4 : 2;

    // ---------------------------------------------------------------- T32

    /// <summary>
    /// Decodes the Thumb instruction at <paramref name="address"/> from <paramref name="bytes"/> (2 or 4 bytes, little-endian).
    /// <paramref name="inIt"/>: inside an IT block, where 16-bit data processing does not set the flags.
    /// </summary>
    public static void Thumb(ReadOnlySpan<byte> bytes, uint address, bool inIt, out ArmInstruction i)
    {
        if (bytes.Length < 2) { Init(out i, address, Math.Max(1, bytes.Length), true, 0); return; }
        ushort hw1 = (ushort)(bytes[0] | bytes[1] << 8);
        if (ThumbLength(hw1) == 2)
        {
            Init(out i, address, 2, true, hw1);
            T16(ref i, hw1, inIt);
        }
        else
        {
            if (bytes.Length < 4) { Init(out i, address, 2, true, hw1); return; }
            ushort hw2 = (ushort)(bytes[2] | bytes[3] << 8);
            Init(out i, address, 4, true, (uint)hw1 << 16 | hw2);
            T32(ref i, hw1, hw2);
        }
        Finish(ref i);
    }

    private static void T16(ref ArmInstruction i, uint h, bool inIt)
    {
        uint pc = i.Address + 4;
        int rd = (int)(h & 7), rn = (int)((h >> 3) & 7), rm = (int)((h >> 6) & 7);
        bool s = !inIt;
        switch (h >> 11)
        {
            case 0 or 1 or 2:
            {
                int imm5 = (int)((h >> 6) & 31);
                int op = (int)(h >> 11);
                if (op == 0 && imm5 == 0) { Set(ref i, "mov"); i.SetsFlags = s; i.Reg(rd, true); i.Reg(rn); }
                else
                {
                    Set(ref i, op switch { 0 => "lsl", 1 => "lsr", _ => "asr" });
                    i.SetsFlags = s;
                    i.Reg(rd, true); i.Reg(rn); i.Imm(imm5 == 0 ? 32 : imm5);
                }
                i.WritesFlags = s;
                return;
            }
            case 3:
            {
                int op = (int)((h >> 9) & 3);
                Set(ref i, (op & 1) == 0 ? "add" : "sub");
                i.SetsFlags = i.WritesFlags = s;
                i.Reg(rd, true); i.Reg(rn);
                if (op < 2) i.Reg(rm); else i.Imm(rm);
                return;
            }
            case 4: Set(ref i, "mov"); i.SetsFlags = i.WritesFlags = s; i.Reg((int)(h >> 8) & 7, true); i.Imm(h & 0xFF); return;
            case 5: Set(ref i, "cmp"); i.WritesFlags = true; i.Reg((int)(h >> 8) & 7); i.Imm(h & 0xFF); return;
            case 6 or 7:
            {
                int r = (int)(h >> 8) & 7;
                Set(ref i, (h >> 11) == 6 ? "add" : "sub");
                i.SetsFlags = i.WritesFlags = s;
                i.Reg(r, true); i.Use(r, false); i.Imm(h & 0xFF);
                return;
            }
            case 9: // ldr rt, [pc, #imm8*4]
                Set(ref i, "ldr");
                Load(ref i, 4);
                i.Reg((int)(h >> 8) & 7, true);
                i.MemImm(Pc, (h & 0xFF) * 4);
                return;
            case 0x14: // adr
                Set(ref i, "adr");
                i.Reg((int)(h >> 8) & 7, true);
                i.Label((uint)(((pc & ~3u) + (h & 0xFF) * 4)), true, branch: false);
                return;
            case 0x15: Set(ref i, "add"); i.Reg((int)(h >> 8) & 7, true); i.Reg(Sp); i.Imm((h & 0xFF) * 4); return;
            case 0x18 or 0x19:
            {
                bool load = (h >> 11) == 0x19;
                int rb = (int)(h >> 8) & 7;
                int list = (int)(h & 0xFF);
                if (list == 0) return;
                Set(ref i, load ? "ldm" : "stm");
                if (load) Load(ref i, 4); else Store(ref i, 4);
                bool wb = !load || (list & (1 << rb)) == 0;
                i.Reg(rb);
                if (wb) { i.Use(rb, true); i.Operands[0].Text = "!"; }
                i.List(list, load);
                return;
            }
            case 0x1C: Set(ref i, "b"); i.Flow = ArmFlow.Jump; i.Label((uint)(pc + SignExtend((h & 0x7FF) << 1, 12)), true); return;
        }
        switch (h >> 10)
        {
            case 0x10: // data processing, two registers
            {
                int op = (int)((h >> 6) & 15);
                string[] names = ["and", "eor", "lsl", "lsr", "asr", "adc", "sbc", "ror", "tst", "rsb", "cmp", "cmn", "orr", "mul", "bic", "mvn"];
                Set(ref i, names[op]);
                bool compare = op is 8 or 10 or 11;
                i.SetsFlags = compare || s;
                i.WritesFlags = i.SetsFlags;
                i.ReadsFlags = op is 5 or 6;
                if (op == 9) { i.Reg(rd, true); i.Reg(rn); i.Imm(0); return; }
                if (op == 13) { i.Reg(rd, true); i.Reg(rn); i.Reg(rd); return; }
                i.Reg(rd, !compare);
                if (!compare && op != 15) i.Use(rd, false);
                i.Reg(rn);
                return;
            }
            case 0x11:
            {
                int op = (int)((h >> 8) & 3);
                int dn = (int)((h >> 4) & 8 | h & 7);
                int m = (int)((h >> 3) & 15);
                switch (op)
                {
                    case 0:
                        Set(ref i, "add");
                        if (m == Sp) { i.Reg(dn, true); i.Reg(Sp); i.Reg(dn); }
                        else { i.Reg(dn, true); i.Use(dn, false); i.Reg(m); }
                        return;
                    case 1: Set(ref i, "cmp"); i.WritesFlags = true; i.Reg(dn); i.Reg(m); return;
                    case 2: Set(ref i, "mov"); i.Reg(dn, true); i.Reg(m); return;
                    default:
                        if ((h & 7) != 0) return;
                        bool link = (h & 0x80) != 0;
                        Set(ref i, link ? "blx" : "bx");
                        i.Reg(m);
                        i.Flow = link ? ArmFlow.IndirectCall : m == Lr ? ArmFlow.Return : ArmFlow.IndirectJump;
                        if (link) i.Use(Lr, true);
                        return;
                }
            }
        }
        if ((h >> 12) == 5)
        {
            int op = (int)((h >> 9) & 7);
            string[] names = ["str", "strh", "strb", "ldrsb", "ldr", "ldrh", "ldrb", "ldrsh"];
            int[] sizes = [4, 2, 1, 1, 4, 2, 1, 2];
            Set(ref i, names[op]);
            if (op < 3) Store(ref i, sizes[op]); else Load(ref i, sizes[op]);
            i.Reg(rd, op >= 3);
            i.MemReg(rn, rm);
            return;
        }
        if ((h >> 13) == 3 || (h >> 12) == 8)
        {
            bool load = (h & 0x800) != 0;
            int size = (h >> 12) == 8 ? 2 : (h & 0x1000) != 0 ? 1 : 4;
            Set(ref i, (load ? "ldr" : "str") + size switch { 1 => "b", 2 => "h", _ => "" });
            if (load) Load(ref i, size); else Store(ref i, size);
            i.Reg(rd, load);
            i.MemImm(rn, ((h >> 6) & 31) * size);
            return;
        }
        if ((h >> 12) == 9)
        {
            bool load = (h & 0x800) != 0;
            Set(ref i, load ? "ldr" : "str");
            if (load) Load(ref i, 4); else Store(ref i, 4);
            i.Reg((int)(h >> 8) & 7, load);
            i.MemImm(Sp, (h & 0xFF) * 4);
            return;
        }
        if ((h >> 12) == 0xB) { T16Misc(ref i, h, pc); return; }
        if ((h >> 12) == 0xD)
        {
            uint cond = (h >> 8) & 15;
            if (cond == 14) { Set(ref i, (h & 0xFF) == 0xFE ? "trap" : "udf"); if (i.Mnemonic == "udf") i.Imm(h & 0xFF); i.Flow = ArmFlow.Trap; return; }
            if (cond == 15) { Set(ref i, "svc"); i.Imm(h & 0xFF); return; }
            Set(ref i, "b");
            i.Cond = (byte)cond;
            i.ReadsFlags = true;
            i.Flow = ArmFlow.Jump;
            i.Label((uint)(pc + SignExtend((h & 0xFF) << 1, 9)), true);
        }
    }

    private static void T16Misc(ref ArmInstruction i, uint h, uint pc)
    {
        int rd = (int)(h & 7), rm = (int)((h >> 3) & 7);
        switch ((h >> 8) & 15)
        {
            case 0:
                Set(ref i, (h & 0x80) != 0 ? "sub" : "add");
                i.Reg(Sp, true); i.Use(Sp, false); i.Imm((h & 0x7F) * 4);
                return;
            case 1 or 3 or 9 or 11:
                Set(ref i, (h & 0x800) != 0 ? "cbnz" : "cbz");
                i.Flow = ArmFlow.Jump;
                i.Reg(rd);
                i.Label(pc + ((h >> 3) & 0x40 | (h >> 2) & 0x3E), true);
                return;
            case 2:
                Set(ref i, ((h >> 6) & 3) switch { 0 => "sxth", 1 => "sxtb", 2 => "uxth", _ => "uxtb" });
                i.Reg(rd, true); i.Reg(rm);
                return;
            case 4 or 5:
            {
                int list = (int)(h & 0xFF) | ((h & 0x100) != 0 ? 1 << Lr : 0);
                if (list == 0) return;
                Set(ref i, "push");
                Store(ref i, 4);
                i.List(list, load: false);
                i.Use(Sp, false); i.Use(Sp, true);
                return;
            }
            case 6:
                if ((h & 0xE0) == 0x60) { Set(ref i, (h & 0x10) != 0 ? "cpsid" : "cpsie"); i.Text(((h & 4) != 0 ? "a" : "") + ((h & 2) != 0 ? "i" : "") + ((h & 1) != 0 ? "f" : "")); }
                else if ((h & 0xF7) == 0x50) { Set(ref i, "setend"); i.Text((h & 8) != 0 ? "be" : "le"); }
                return;
            case 10:
            {
                int op = (int)((h >> 6) & 3);
                if (op == 2) { Set(ref i, "hlt"); i.Imm(h & 0x3F); i.Flow = ArmFlow.Trap; return; }
                Set(ref i, op switch { 0 => "rev", 1 => "rev16", _ => "revsh" });
                i.Reg(rd, true); i.Reg(rm);
                return;
            }
            case 12 or 13:
            {
                int list = (int)(h & 0xFF) | ((h & 0x100) != 0 ? 1 << Pc : 0);
                if (list == 0) return;
                Set(ref i, "pop");
                Load(ref i, 4);
                i.List(list, load: true);
                i.Use(Sp, false); i.Use(Sp, true);
                return;
            }
            case 14: Set(ref i, "bkpt"); i.Imm(h & 0xFF); i.Flow = ArmFlow.Trap; return;
            case 15:
                if ((h & 15) != 0)
                {
                    int first = (int)((h >> 4) & 15), mask = (int)(h & 15);
                    if (first == 15 || (first == 14 && BitOperations.PopCount((uint)mask) != 1)) return;
                    Set(ref i, "it" + ItPattern(first, mask));
                    i.ItFirst = (byte)first;
                    i.ItMask = (byte)mask;
                    i.Text(ArmInstruction.ConditionNames[first] is { Length: > 0 } c ? c : "al");
                    return;
                }
                Set(ref i, ((h >> 4) & 15) switch { 0 => "nop", 1 => "yield", 2 => "wfe", 3 => "wfi", 4 => "sev", _ => "hint" });
                if (i.Mnemonic == "hint") i.Imm((h >> 4) & 15);
                return;
        }
    }

    /// <summary>The t / e letters after "it" for the instructions after the first.</summary>
    private static string ItPattern(int first, int mask)
    {
        int count = 4 - BitOperations.TrailingZeroCount(mask);
        var letters = new char[count - 1];
        for (int k = 0; k < count - 1; k++) letters[k] = ((mask >> (3 - k)) & 1) == (first & 1) ? 't' : 'e';
        return new string(letters);
    }

    /// <summary>Instructions an IT instruction with <paramref name="mask"/> makes conditional (1-4).</summary>
    public static int ItCount(int mask) => 4 - BitOperations.TrailingZeroCount(mask);

    /// <summary>Condition of instruction <paramref name="k"/> (0-based) of an IT block.</summary>
    public static byte ItCondition(int first, int mask, int k) =>
        k == 0 ? (byte)first : (byte)(first & 0xE | (mask >> (4 - k)) & 1);

    private static void T32(ref ArmInstruction i, uint hw1, uint hw2)
    {
        uint op1 = (hw1 >> 11) & 3, op2 = (hw1 >> 4) & 0x7F;
        switch (op1)
        {
            case 1:
                if ((op2 & 0x64) == 0x00) T32LoadStoreMultiple(ref i, hw1, hw2);
                else if ((op2 & 0x64) == 0x04) T32DualExclusive(ref i, hw1, hw2);
                else if ((op2 & 0x60) == 0x20) T32ShiftedRegister(ref i, hw1, hw2);
                else Coprocessor(ref i, ThumbToArm(hw1, hw2));
                return;
            case 2:
                if ((hw2 & 0x8000) != 0) T32Branch(ref i, hw1, hw2);
                else if ((op2 & 0x20) == 0) T32ModifiedImmediate(ref i, hw1, hw2);
                else T32PlainImmediate(ref i, hw1, hw2);
                return;
            default:
                if ((op2 & 0x71) == 0x10) { Coprocessor(ref i, ThumbToArm(hw1, hw2)); return; }
                if ((op2 & 0x60) == 0x00) { T32LoadStoreSingle(ref i, hw1, hw2); return; }
                if ((op2 & 0x70) == 0x20) { T32DataRegister(ref i, hw1, hw2); return; }
                if ((op2 & 0x78) == 0x30) { T32Multiply(ref i, hw1, hw2); return; }
                if ((op2 & 0x78) == 0x38) { T32LongMultiply(ref i, hw1, hw2); return; }
                if ((op2 & 0x40) != 0) Coprocessor(ref i, ThumbToArm(hw1, hw2));
                return;
        }
    }

    /// <summary>The A32 word of a T32 coprocessor, VFP or NEON encoding (the same fields in the same places).</summary>
    private static uint ThumbToArm(uint hw1, uint hw2)
    {
        uint w = hw1 << 16 | hw2;
        if ((hw1 & 0xEF00) == 0xEF00) return 0xF2000000 | ((hw1 >> 12) & 1) << 24 | (w & 0x00FFFFFF); // NEON data processing
        if ((hw1 & 0xFF10) == 0xF900) return 0xF4000000 | (w & 0x00FFFFFF);                            // NEON element / structure load-store
        return (hw1 & 0x1000) != 0 ? 0xF0000000 | (w & 0x0FFFFFFF) : 0xE0000000 | (w & 0x0FFFFFFF);
    }

    private static void T32LoadStoreMultiple(ref ArmInstruction i, uint hw1, uint hw2)
    {
        uint op = (hw1 >> 7) & 3;
        bool load = (hw1 & 0x10) != 0, wb = (hw1 & 0x20) != 0;
        int rn = (int)(hw1 & 15);
        if (op is 0 or 3)
        {
            if (load) { Set(ref i, op == 0 ? "rfedb" : "rfeia"); i.Reg(rn); i.Use(Pc, true); }
            else { Set(ref i, op == 0 ? "srsdb" : "srsia"); i.Reg(Sp); i.Imm(hw2 & 31); }
            return;
        }
        int list = (int)(hw2 & 0xDFFF);
        if (list == 0 || (!load && (list & 0x8000) != 0)) return;
        if (rn == Sp && wb && BitOperations.PopCount((uint)list) > 1 && (op == 1) == load)
        {
            Set(ref i, load ? "pop" : "push");
            i.Wide = true;
            if (load) Load(ref i, 4); else Store(ref i, 4);
            i.List(list, load);
            i.Use(Sp, false); i.Use(Sp, true);
            return;
        }
        Set(ref i, (load ? "ldm" : "stm") + (op == 2 ? "db" : ""));
        i.Wide = op == 1;
        if (load) Load(ref i, 4); else Store(ref i, 4);
        i.Reg(rn);
        if (wb) { i.Use(rn, true); i.Operands[0].Text = "!"; }
        i.List(list, load);
    }

    private static void T32DualExclusive(ref ArmInstruction i, uint hw1, uint hw2)
    {
        bool p = (hw1 & 0x100) != 0, u = (hw1 & 0x80) != 0, w = (hw1 & 0x20) != 0, load = (hw1 & 0x10) != 0;
        int rn = (int)(hw1 & 15), rt = (int)(hw2 >> 12), rt2 = (int)((hw2 >> 8) & 15);
        if (!p && !w)
        {
            if (!u)
            {
                if (load) { Set(ref i, "ldrex"); Load(ref i, 4); i.Reg(rt, true); i.MemImm(rn, (hw2 & 0xFF) * 4); }
                else { Set(ref i, "strex"); Store(ref i, 4); i.Reg(rt2, true); i.Reg(rt); i.MemImm(rn, (hw2 & 0xFF) * 4); }
                return;
            }
            uint op3 = (hw2 >> 4) & 15;
            int rd = (int)(hw2 & 15);
            if (load && op3 is 0 or 1)
            {
                Set(ref i, op3 == 0 ? "tbb" : "tbh");
                Load(ref i, op3 == 0 ? 1 : 2);
                i.MemReg(rn, rd, shift: op3 == 1 ? ArmShift.Lsl : ArmShift.None, amount: (int)op3);
                i.Flow = ArmFlow.IndirectJump;
                return;
            }
            // exclusive and (ARMv8) acquire / release byte, halfword, doubleword
            string size = (op3 & 3) switch { 0 => "b", 1 => "h", 3 => "d", _ => "" };
            if ((op3 & 3) == 2) return;
            string kind = (op3 & 0xC) switch { 4 => "ex", 8 => "", 12 => "ex", _ => "?" };
            if (kind == "?") return;
            string prefix = load ? ((op3 & 8) != 0 ? "lda" : "ldr") : ((op3 & 8) != 0 ? "stl" : "str");
            Set(ref i, prefix + kind + size);
            int bytes = (op3 & 3) switch { 0 => 1, 1 => 2, _ => 4 };
            if (load) { Load(ref i, bytes); i.Reg(rt, true); if (size == "d") i.Reg(rt2, true); }
            else
            {
                Store(ref i, bytes);
                if (kind == "ex") i.Reg(rd, true);
                i.Reg(rt);
                if (size == "d") i.Reg(rt2);
            }
            i.MemImm(rn, 0);
            return;
        }
        Set(ref i, load ? "ldrd" : "strd");
        if (load) Load(ref i, 4); else Store(ref i, 4);
        i.Reg(rt, load); i.Reg(rt2, load);
        long off = (hw2 & 0xFF) * 4;
        i.MemImm(rn, u ? off : -off, !p ? ArmIndexing.PostIndex : w ? ArmIndexing.PreIndex : ArmIndexing.Offset);
    }

    private static readonly string?[] DpNames = ["and", "bic", "orr", "orn", "eor", null, "pkh", null, "add", null, "adc", "sbc", null, "sub", "rsb", null];

    private static void T32ShiftedRegister(ref ArmInstruction i, uint hw1, uint hw2)
    {
        int op = (int)((hw1 >> 5) & 15);
        bool s = (hw1 & 0x10) != 0;
        int rn = (int)(hw1 & 15), rd = (int)((hw2 >> 8) & 15), rm = (int)(hw2 & 15);
        int imm5 = (int)((hw2 >> 10) & 0x1C | (hw2 >> 6) & 3);
        int type = (int)((hw2 >> 4) & 3);
        var (shift, amount) = DecodeShift(type, imm5);
        if (op == 6)
        {
            if (s) return;
            bool tb = (hw2 & 0x20) != 0;
            Set(ref i, tb ? "pkhtb" : "pkhbt");
            i.Reg(rd, true); i.Reg(rn); i.Shifted(rm, tb ? ArmShift.Asr : ArmShift.Lsl, imm5 == 0 && tb ? 32 : imm5);
            return;
        }
        if (DpNames[op] is not { } name) return;
        if (op == 2 && rn == Pc)
        {
            // mov.w and the shifts
            if (shift == ArmShift.None || (shift == ArmShift.Lsl && amount == 0)) { Set(ref i, "mov"); i.Reg(rd, true); i.Reg(rm); }
            else
            {
                Set(ref i, shift switch { ArmShift.Lsl => "lsl", ArmShift.Lsr => "lsr", ArmShift.Asr => "asr", ArmShift.Ror => "ror", _ => "rrx" });
                i.Reg(rd, true); i.Reg(rm);
                if (shift != ArmShift.Rrx) i.Imm(amount);
            }
            i.Wide = true;
            Flags(ref i, s);
            return;
        }
        if (op == 3 && rn == Pc) { Set(ref i, "mvn"); i.Wide = true; i.Reg(rd, true); i.Shifted(rm, shift, amount); Flags(ref i, s); return; }
        if (rd == Pc && s && op is 0 or 4 or 8 or 13)
        {
            Set(ref i, op switch { 0 => "tst", 4 => "teq", 8 => "cmn", _ => "cmp" });
            i.Wide = true;
            i.WritesFlags = true;
            i.Reg(rn); i.Shifted(rm, shift, amount);
            return;
        }
        Set(ref i, name);
        i.Wide = op != 3;
        Flags(ref i, s);
        i.ReadsFlags = op is 10 or 11;
        i.Reg(rd, true); i.Reg(rn); i.Shifted(rm, shift, amount);
    }

    private static void Flags(ref ArmInstruction i, bool s)
    {
        i.SetsFlags = s;
        i.WritesFlags = s;
    }

    private static (ArmShift, int) DecodeShift(int type, int imm5) => type switch
    {
        0 => (ArmShift.Lsl, imm5),
        1 => (ArmShift.Lsr, imm5 == 0 ? 32 : imm5),
        2 => (ArmShift.Asr, imm5 == 0 ? 32 : imm5),
        _ => imm5 == 0 ? (ArmShift.Rrx, 0) : (ArmShift.Ror, imm5),
    };

    /// <summary>ThumbExpandImm.</summary>
    private static uint ThumbExpand(uint imm12)
    {
        uint b = imm12 & 0xFF;
        if ((imm12 >> 10) == 0)
            return ((imm12 >> 8) & 3) switch { 0 => b, 1 => b << 16 | b, 2 => b << 24 | b << 8, _ => b << 24 | b << 16 | b << 8 | b };
        return BitOperations.RotateRight(0x80 | (imm12 & 0x7F), (int)(imm12 >> 7));
    }

    private static void T32ModifiedImmediate(ref ArmInstruction i, uint hw1, uint hw2)
    {
        int op = (int)((hw1 >> 5) & 15);
        bool s = (hw1 & 0x10) != 0;
        int rn = (int)(hw1 & 15), rd = (int)((hw2 >> 8) & 15);
        uint imm = ThumbExpand(((hw1 >> 10) & 1) << 11 | (hw2 >> 4) & 0x700 | hw2 & 0xFF);
        if (DpNames[op] is not { } name || op == 6) return;
        i.Wide = true;
        if (op == 2 && rn == Pc) { Set(ref i, "mov"); i.Wide = true; i.Reg(rd, true); i.Imm(imm); Flags(ref i, s); return; }
        if (op == 3 && rn == Pc) { Set(ref i, "mvn"); i.Wide = true; i.Reg(rd, true); i.Imm(imm); Flags(ref i, s); return; }
        if (rd == Pc && s && op is 0 or 4 or 8 or 13)
        {
            Set(ref i, op switch { 0 => "tst", 4 => "teq", 8 => "cmn", _ => "cmp" });
            i.Wide = true;
            i.WritesFlags = true;
            i.Reg(rn); i.Imm(imm);
            return;
        }
        Set(ref i, name);
        i.Wide = op != 3;
        Flags(ref i, s);
        i.ReadsFlags = op is 10 or 11;
        i.Reg(rd, true); i.Reg(rn); i.Imm(imm);
    }

    private static void T32PlainImmediate(ref ArmInstruction i, uint hw1, uint hw2)
    {
        int op = (int)((hw1 >> 4) & 31);
        int rn = (int)(hw1 & 15), rd = (int)((hw2 >> 8) & 15);
        uint imm12 = ((hw1 >> 10) & 1) << 11 | (hw2 >> 4) & 0x700 | hw2 & 0xFF;
        int lsb = (int)((hw2 >> 10) & 0x1C | (hw2 >> 6) & 3), low5 = (int)(hw2 & 31);
        switch (op)
        {
            case 0 or 10:
                if (rn == Pc)
                {
                    Set(ref i, "adr");
                    i.Wide = true;
                    i.Reg(rd, true);
                    uint basePc = (i.Address + 4) & ~3u;
                    i.Label(op == 0 ? basePc + imm12 : basePc - imm12, true, branch: false);
                    return;
                }
                Set(ref i, op == 0 ? "addw" : "subw");
                i.Reg(rd, true); i.Reg(rn); i.Imm(imm12);
                return;
            case 4 or 12:
                Set(ref i, op == 4 ? "movw" : "movt");
                i.Reg(rd, true);
                if (op == 12) i.Use(rd, false);
                i.Imm((hw1 & 15) << 12 | imm12);
                return;
            case 16 or 18 or 24 or 26:
            {
                bool unsigned = op >= 24;
                bool sixteen = op is 18 or 26 && lsb == 0;
                Set(ref i, (unsigned ? "usat" : "ssat") + (sixteen ? "16" : ""));
                i.Reg(rd, true);
                i.Imm(unsigned ? (hw2 & (sixteen ? 15u : 31u)) : (hw2 & (sixteen ? 15u : 31u)) + 1);
                if (sixteen) i.Reg(rn);
                else i.Shifted(rn, (op & 2) != 0 ? ArmShift.Asr : ArmShift.Lsl, lsb);
                return;
            }
            case 20 or 28:
                Set(ref i, op == 20 ? "sbfx" : "ubfx");
                i.Reg(rd, true); i.Reg(rn); i.Imm(lsb); i.Imm(low5 + 1);
                return;
            case 22:
                if (low5 < lsb) return;
                if (rn == Pc) { Set(ref i, "bfc"); i.Reg(rd, true); i.Use(rd, false); }
                else { Set(ref i, "bfi"); i.Reg(rd, true); i.Use(rd, false); i.Reg(rn); }
                i.Imm(lsb); i.Imm(low5 - lsb + 1);
                return;
        }
    }

    private static void T32Branch(ref ArmInstruction i, uint hw1, uint hw2)
    {
        uint op1 = (hw2 >> 12) & 7, op = (hw1 >> 4) & 0x7F;
        uint pc = i.Address + 4;
        uint s = (hw1 >> 10) & 1, j1 = (hw2 >> 13) & 1, j2 = (hw2 >> 11) & 1;
        if ((op1 & 5) == 0)
        {
            if ((op & 0x38) != 0x38)
            {
                uint imm = s << 20 | j2 << 19 | j1 << 18 | (hw1 & 0x3F) << 12 | (hw2 & 0x7FF) << 1;
                Set(ref i, "b");
                i.Wide = true;
                i.Cond = (byte)((hw1 >> 6) & 15);
                i.ReadsFlags = true;
                i.Flow = ArmFlow.Jump;
                i.Label((uint)(pc + SignExtend(imm, 21)), true);
                return;
            }
            if (op == 0x7F && op1 == 2) { Set(ref i, "udf"); i.Wide = true; i.Imm((hw1 & 15) << 12 | hw2 & 0xFFF); i.Flow = ArmFlow.Trap; return; }
            if (op == 0x7F && op1 == 0) { Set(ref i, "smc"); i.Imm(hw1 & 15); return; }
            if (op1 != 0) return;
            switch (op)
            {
                case 0x38 or 0x39:
                    Set(ref i, "msr");
                    i.Text((hw2 & 0x0C00) == 0x0800 ? "apsr_nzcvq" : "apsr");
                    i.Reg((int)(hw1 & 15));
                    if ((hw2 & 0x0800) != 0) i.WritesFlags = true;
                    return;
                case 0x3A:
                    if ((hw2 & 0x700) != 0) { Set(ref i, "cps"); return; }
                    Set(ref i, (hw2 & 0xFF) switch { 0 => "nop", 1 => "yield", 2 => "wfe", 3 => "wfi", 4 => "sev", >= 0xF0 => "dbg", _ => "hint" });
                    i.Wide = i.Mnemonic is not ("dbg" or "hint");
                    if (i.Mnemonic == "dbg") i.Imm(hw2 & 15);
                    return;
                case 0x3B:
                    switch ((hw2 >> 4) & 15)
                    {
                        case 2: Set(ref i, "clrex"); return;
                        case 4: Set(ref i, "dsb"); i.Text(Barrier(hw2 & 15)); return;
                        case 5: Set(ref i, "dmb"); i.Text(Barrier(hw2 & 15)); return;
                        case 6: Set(ref i, "isb"); i.Text(Barrier(hw2 & 15)); return;
                    }
                    return;
                case 0x3C: Set(ref i, "bxj"); i.Reg((int)(hw1 & 15)); i.Flow = ArmFlow.IndirectJump; return;
                case 0x3D:
                    Set(ref i, "subs");
                    i.Reg(Pc, true); i.Reg(Lr); i.Imm(hw2 & 0xFF);
                    i.Flow = ArmFlow.Return;
                    return;
                case 0x3E or 0x3F:
                    Set(ref i, "mrs");
                    i.Reg((int)((hw2 >> 8) & 15), true);
                    i.Text((hw1 & 0x10) != 0 ? "spsr" : "apsr");
                    i.ReadsFlags = true;
                    return;
            }
            return;
        }
        uint i1 = ~(j1 ^ s) & 1, i2 = ~(j2 ^ s) & 1;
        uint offset = s << 24 | i1 << 23 | i2 << 22 | (hw1 & 0x3FF) << 12 | (hw2 & 0x7FF) << 1;
        if ((op1 & 5) == 1)
        {
            Set(ref i, "b");
            i.Wide = true;
            i.Flow = ArmFlow.Jump;
            i.Label((uint)(pc + SignExtend(offset, 25)), true);
            return;
        }
        if ((op1 & 5) == 4)
        {
            if ((hw2 & 1) != 0) return;
            Set(ref i, "blx");
            i.Flow = ArmFlow.Call;
            i.Use(Lr, true);
            i.Label((uint)((pc & ~3u) + SignExtend(offset & ~2u, 25)), false);
            return;
        }
        Set(ref i, "bl");
        i.Flow = ArmFlow.Call;
        i.Use(Lr, true);
        i.Label((uint)(pc + SignExtend(offset, 25)), true);
    }

    private static string Barrier(uint option) => option switch
    {
        15 => "sy", 14 => "st", 13 => "ld", 11 => "ish", 10 => "ishst", 9 => "ishld", 7 => "nsh", 6 => "nshst", 5 => "nshld",
        3 => "osh", 2 => "oshst", 1 => "oshld", _ => $"#{option}",
    };

    private static void T32LoadStoreSingle(ref ArmInstruction i, uint hw1, uint hw2)
    {
        bool signed = (hw1 & 0x100) != 0, a = (hw1 & 0x80) != 0, load = (hw1 & 0x10) != 0;
        int size = (int)((hw1 >> 5) & 3);
        int rn = (int)(hw1 & 15), rt = (int)(hw2 >> 12);
        if (size == 3 || (!load && signed) || (signed && size == 2)) return;
        int bytes = 1 << size;
        bool hint = load && rt == Pc && size < 2;
        string name = hint ? (signed ? "pli" : size == 0 ? "pld" : "pldw") : (load ? "ldr" : "str") + (signed ? "s" : "") + size switch { 0 => "b", 1 => "h", _ => "" };
        if (rn == Pc)
        {
            if (!load) return;
            Set(ref i, name);
            if (!hint) { Load(ref i, bytes); i.Reg(rt, true); }
            i.Wide = !hint;
            long off = hw2 & 0xFFF;
            i.MemImm(Pc, a ? off : -off);
            return;
        }
        if (a)
        {
            Set(ref i, name);
            i.Wide = !hint;
            if (!hint) { if (load) Load(ref i, bytes); else Store(ref i, bytes); i.Reg(rt, load); }
            i.MemImm(rn, hw2 & 0xFFF);
            return;
        }
        if ((hw2 & 0x800) != 0)
        {
            bool p = (hw2 & 0x400) != 0, u = (hw2 & 0x200) != 0, w = (hw2 & 0x100) != 0;
            long off = hw2 & 0xFF;
            if (!p && !w) return;
            if (p && u && !w)
            {
                if (hint) return;
                Set(ref i, name + "t");
                if (load) Load(ref i, bytes); else Store(ref i, bytes);
                i.Reg(rt, load);
                i.MemImm(rn, off);
                return;
            }
            Set(ref i, name);
            if (!hint) { if (load) Load(ref i, bytes); else Store(ref i, bytes); i.Reg(rt, load); }
            i.MemImm(rn, u ? off : -off, !p ? ArmIndexing.PostIndex : w ? ArmIndexing.PreIndex : ArmIndexing.Offset);
            return;
        }
        if ((hw2 & 0xFC0) != 0) return;
        Set(ref i, name);
        i.Wide = !hint;
        if (!hint) { if (load) Load(ref i, bytes); else Store(ref i, bytes); i.Reg(rt, load); }
        int shift = (int)((hw2 >> 4) & 3);
        i.MemReg(rn, (int)(hw2 & 15), shift: shift != 0 ? ArmShift.Lsl : ArmShift.None, amount: shift);
    }

    private static void T32DataRegister(ref ArmInstruction i, uint hw1, uint hw2)
    {
        if ((hw2 & 0xF000) != 0xF000) return;
        uint op1 = (hw1 >> 4) & 15, op2 = (hw2 >> 4) & 15;
        int rn = (int)(hw1 & 15), rd = (int)((hw2 >> 8) & 15), rm = (int)(hw2 & 15);
        if ((op1 & 8) == 0 && op2 == 0)
        {
            Set(ref i, ((op1 >> 1) & 3) switch { 0 => "lsl", 1 => "lsr", 2 => "asr", _ => "ror" });
            i.Wide = true;
            Flags(ref i, (op1 & 1) != 0);
            i.Reg(rd, true); i.Reg(rn); i.Reg(rm);
            return;
        }
        if ((op1 & 8) == 0 && (op2 & 8) != 0)
        {
            string[] names = ["sxtah", "uxtah", "sxtab16", "uxtab16", "sxtab", "uxtab"];
            if ((op1 & 7) > 5) return;
            string name = names[op1 & 7];
            int rotate = (int)((hw2 >> 4) & 3) * 8;
            if (rn == Pc) { Set(ref i, name.Remove(3, 1)); i.Wide = (op1 & 7) is 0 or 1 or 4 or 5; i.Reg(rd, true); }
            else { Set(ref i, name); i.Reg(rd, true); i.Reg(rn); }
            i.Shifted(rm, rotate != 0 ? ArmShift.Ror : ArmShift.None, rotate);
            return;
        }
        if ((op1 & 8) != 0 && (op2 & 8) == 0)
        {
            string? op = (op1 & 7) switch { 1 => "add16", 2 => "asx", 6 => "sax", 5 => "sub16", 0 => "add8", 4 => "sub8", _ => null };
            if (op == null || Parallel(op, (op2 & 4) != 0, (int)(op2 & 3)) is not { } name) return;
            Set(ref i, name);
            i.Reg(rd, true); i.Reg(rn); i.Reg(rm);
            return;
        }
        if ((op1 & 0xC) == 8 && (op2 & 0xC) == 8)
        {
            string? name = (op1 & 3, op2 & 3) switch
            {
                (0, 0) => "qadd", (0, 1) => "qdadd", (0, 2) => "qsub", (0, 3) => "qdsub",
                (1, 0) => "rev", (1, 1) => "rev16", (1, 2) => "rbit", (1, 3) => "revsh",
                (2, 0) => "sel", (3, 0) => "clz", _ => null,
            };
            if (name == null) return;
            Set(ref i, name);
            i.Wide = name is "rev" or "rev16" or "revsh";
            i.Reg(rd, true);
            if ((op1 & 3) is 1 or 3) i.Reg(rm);
            else if (name.StartsWith('q')) { i.Reg(rm); i.Reg(rn); }
            else { i.Reg(rn); i.Reg(rm); }
            return;
        }
    }

    /// <summary>A parallel add / subtract: <paramref name="prefix"/> 0 plain, 1 saturating, 2 halving.</summary>
    private static string? Parallel(string op, bool unsigned, int prefix) =>
        prefix switch { 0 => unsigned ? "u" : "s", 1 => unsigned ? "uq" : "q", 2 => unsigned ? "uh" : "sh", _ => null } is { } p ? p + op : null;

    private static void T32Multiply(ref ArmInstruction i, uint hw1, uint hw2)
    {
        uint op1 = (hw1 >> 4) & 7, op2 = (hw2 >> 4) & 3;
        int rn = (int)(hw1 & 15), ra = (int)(hw2 >> 12), rd = (int)((hw2 >> 8) & 15), rm = (int)(hw2 & 15);
        bool acc = ra != Pc;
        string? name = op1 switch
        {
            0 when op2 == 0 => acc ? "mla" : "mul",
            0 when op2 == 1 => "mls",
            1 => (acc ? "smla" : "smul") + ((op2 & 2) != 0 ? "t" : "b") + ((op2 & 1) != 0 ? "t" : "b"),
            2 when op2 <= 1 => (acc ? "smlad" : "smuad") + (op2 == 1 ? "x" : ""),
            3 when op2 <= 1 => (acc ? "smlaw" : "smulw") + (op2 == 1 ? "t" : "b"),
            4 when op2 <= 1 => (acc ? "smlsd" : "smusd") + (op2 == 1 ? "x" : ""),
            5 when op2 <= 1 => (acc ? "smmla" : "smmul") + (op2 == 1 ? "r" : ""),
            6 when op2 <= 1 => "smmls" + (op2 == 1 ? "r" : ""),
            7 when op2 == 0 => acc ? "usada8" : "usad8",
            _ => null,
        };
        if (name == null) return;
        Set(ref i, name);
        i.Reg(rd, true); i.Reg(rn); i.Reg(rm);
        if (acc || name == "mls") i.Reg(ra);
    }

    private static void T32LongMultiply(ref ArmInstruction i, uint hw1, uint hw2)
    {
        uint op1 = (hw1 >> 4) & 7, op2 = (hw2 >> 4) & 15;
        int rn = (int)(hw1 & 15), lo = (int)(hw2 >> 12), hi = (int)((hw2 >> 8) & 15), rm = (int)(hw2 & 15);
        if (op1 is 1 or 3 && op2 == 15)
        {
            Set(ref i, op1 == 1 ? "sdiv" : "udiv");
            i.Reg(hi, true); i.Reg(rn); i.Reg(rm);
            return;
        }
        string? name = (op1, op2) switch
        {
            (0, 0) => "smull", (2, 0) => "umull", (4, 0) => "smlal", (6, 0) => "umlal", (6, 6) => "umaal",
            (4, 8) => "smlalbb", (4, 9) => "smlalbt", (4, 10) => "smlaltb", (4, 11) => "smlaltt",
            (4, 12) => "smlald", (4, 13) => "smlaldx", (5, 12) => "smlsld", (5, 13) => "smlsldx",
            _ => null,
        };
        if (name == null) return;
        Set(ref i, name);
        i.Reg(lo, true); i.Reg(hi, true);
        if (name != "smull" && name != "umull") { i.Use(lo, false); i.Use(hi, false); }
        i.Reg(rn); i.Reg(rm);
    }

    // ---------------------------------------------------------------- A32

    /// <summary>Decodes the A32 instruction <paramref name="w"/> at <paramref name="address"/>.</summary>
    public static void Arm(uint w, uint address, out ArmInstruction i)
    {
        Init(out i, address, 4, false, w);
        uint cond = w >> 28;
        if (cond == 15) ArmUnconditional(ref i, w);
        else
        {
            switch ((w >> 25) & 7)
            {
                case 0 or 1: ArmDataMisc(ref i, w); break;
                case 2: ArmLoadStore(ref i, w); break;
                case 3:
                    if ((w & 0x10) == 0) ArmLoadStore(ref i, w);
                    else ArmMedia(ref i, w);
                    break;
                case 4: ArmLoadStoreMultiple(ref i, w); break;
                case 5:
                {
                    bool link = (w & 0x01000000) != 0;
                    Set(ref i, link ? "bl" : "b");
                    i.Flow = link ? ArmFlow.Call : ArmFlow.Jump;
                    if (link) i.Use(Lr, true);
                    i.Label((uint)(address + 8 + (SignExtend(w & 0xFFFFFF, 24) << 2)), false);
                    break;
                }
                default:
                    if ((w & 0x0F000000) == 0x0F000000) { Set(ref i, "svc"); i.Imm(w & 0xFFFFFF); }
                    else Coprocessor(ref i, w);
                    break;
            }
            if (i.Flow != ArmFlow.Invalid)
            {
                i.Cond = (byte)cond;
                if (cond != ArmInstruction.Always) i.ReadsFlags = true;
            }
        }
        Finish(ref i);
    }

    private static void ArmUnconditional(ref ArmInstruction i, uint w)
    {
        i.Cond = ArmInstruction.Unconditional;
        if ((w & 0x0E000000) == 0x0A000000)
        {
            Set(ref i, "blx");
            i.Flow = ArmFlow.Call;
            i.Use(Lr, true);
            i.Label((uint)(i.Address + 8 + (SignExtend(w & 0xFFFFFF, 24) << 2) + ((w >> 23) & 2)), true);
            return;
        }
        if ((w & 0xFE000000) == 0xF2000000 || (w & 0xFF100000) == 0xF4000000) { Coprocessor(ref i, w); return; }
        if ((w & 0xFFFFFFF0) == 0xF57FF010 && (w & 15) == 15) { Set(ref i, "clrex"); return; }
        if ((w & 0xFFFFFF00) == 0xF57FF000)
        {
            switch ((w >> 4) & 15)
            {
                case 4: Set(ref i, "dsb"); i.Text(Barrier(w & 15)); return;
                case 5: Set(ref i, "dmb"); i.Text(Barrier(w & 15)); return;
                case 6: Set(ref i, "isb"); i.Text(Barrier(w & 15)); return;
            }
            return;
        }
        // pld / pldw / pli (immediate and register)
        if ((w & 0x0F300000) == 0x05100000 || (w & 0x0F300010) == 0x07100000 || (w & 0x0F700000) == 0x04500000 || (w & 0x0F700010) == 0x06500000)
        {
            bool reg = (w & 0x02000000) != 0;
            if (reg && (w & 0x10) != 0) return;
            Set(ref i, (w & 0x01000000) == 0 ? "pli" : (w & 0x00400000) != 0 ? "pld" : "pldw");
            bool u = (w & 0x00800000) != 0;
            int rn = (int)((w >> 16) & 15);
            if (!reg) i.MemImm(rn, u ? w & 0xFFF : -(long)(w & 0xFFF));
            else
            {
                var (shift, amount) = DecodeShift((int)((w >> 5) & 3), (int)((w >> 7) & 31));
                i.MemReg(rn, (int)(w & 15), !u, shift, amount);
            }
            return;
        }
        if ((w & 0xFFF10020) == 0xF1000000) { Set(ref i, (w & 0x80000) != 0 ? ((w & 0x40000) != 0 ? "cpsid" : "cpsie") : "cps"); return; }
        if ((w & 0xFFFFFDFF) == 0xF1010000) { Set(ref i, "setend"); i.Text((w & 0x200) != 0 ? "be" : "le"); return; }
        if ((w & 0x0E000000) == 0x0C000000 || (w & 0x0F000000) == 0x0E000000) Coprocessor(ref i, w);
    }

    private static uint ArmExpand(uint imm12) => BitOperations.RotateRight(imm12 & 0xFF, (int)((imm12 >> 8) * 2));

    private static readonly string[] ArmDp = ["and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc", "tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn"];

    private static void ArmDataMisc(ref ArmInstruction i, uint w)
    {
        uint op1 = (w >> 20) & 31, op2 = (w >> 4) & 15;
        int rn = (int)((w >> 16) & 15), rd = (int)((w >> 12) & 15), rm = (int)(w & 15);
        if ((w & 0x02000000) != 0)
        {
            if (op1 is 0x10 or 0x14)
            {
                Set(ref i, op1 == 0x10 ? "movw" : "movt");
                i.Reg(rd, true);
                if (op1 == 0x14) i.Use(rd, false);
                i.Imm((w >> 4) & 0xF000 | w & 0xFFF);
                return;
            }
            if (op1 is 0x12 or 0x16)
            {
                if (op1 == 0x12 && ((w >> 16) & 15) == 0)
                {
                    Set(ref i, (w & 0xFF) switch { 0 => "nop", 1 => "yield", 2 => "wfe", 3 => "wfi", 4 => "sev", >= 0xF0 => "dbg", _ => "hint" });
                    if (i.Mnemonic == "dbg") i.Imm(w & 15);
                    return;
                }
                Set(ref i, "msr");
                i.Text(op1 == 0x16 ? "spsr" : (w & 0x80000) != 0 ? "apsr_nzcvq" : "apsr_g");
                i.Imm(ArmExpand(w & 0xFFF));
                if ((w & 0x80000) != 0) i.WritesFlags = true;
                return;
            }
            DataProcessing(ref i, w, rn, rd, imm: ArmExpand(w & 0xFFF));
            return;
        }
        if (op2 == 9)
        {
            if ((op1 & 0x10) == 0) ArmMultiply(ref i, w);
            else ArmSync(ref i, w);
            return;
        }
        if (op2 == 11 || (op2 & 13) == 13)
        {
            ArmExtraLoadStore(ref i, w);
            return;
        }
        if ((op1 & 0x19) == 0x10)
        {
            if ((op2 & 8) == 0) ArmMisc(ref i, w);
            else if ((op2 & 9) == 8) ArmHalfMultiply(ref i, w);
            return;
        }
        if ((op2 & 1) == 0)
        {
            var (shift, amount) = DecodeShift((int)((w >> 5) & 3), (int)((w >> 7) & 31));
            DataProcessing(ref i, w, rn, rd, shift: shift, amount: amount, rm: rm);
            return;
        }
        if ((op2 & 9) == 1)
        {
            var shift = (ArmShift)(((w >> 5) & 3) + 1);
            DataProcessing(ref i, w, rn, rd, shift: shift, rm: rm, rs: (int)((w >> 8) & 15));
        }
    }

    /// <summary>A32 data processing with an immediate (<paramref name="imm"/>) or a register shifted by an immediate or a register.</summary>
    private static void DataProcessing(ref ArmInstruction i, uint w, int rn, int rd, uint? imm = null, ArmShift shift = ArmShift.None, int amount = 0, int rm = 0,
        int rs = ArmOperand.NoReg)
    {
        int op = (int)((w >> 21) & 15);
        bool s = (w & 0x100000) != 0;
        bool compare = op is >= 8 and <= 11;
        if (compare && !s) return;
        void Second(ref ArmInstruction x)
        {
            if (imm is { } v) x.Imm(v);
            else x.Shifted(rm, shift, amount, rs);
        }
        if (op == 13 && imm == null && rs == ArmOperand.NoReg && shift != ArmShift.None && !(shift == ArmShift.Lsl && amount == 0))
        {
            Set(ref i, shift switch { ArmShift.Lsl => "lsl", ArmShift.Lsr => "lsr", ArmShift.Asr => "asr", ArmShift.Ror => "ror", _ => "rrx" });
            Flags(ref i, s);
            i.Reg(rd, true); i.Reg(rm);
            if (shift != ArmShift.Rrx) i.Imm(amount);
            return;
        }
        if (op == 13 && rs != ArmOperand.NoReg)
        {
            Set(ref i, shift switch { ArmShift.Lsl => "lsl", ArmShift.Lsr => "lsr", ArmShift.Asr => "asr", _ => "ror" });
            Flags(ref i, s);
            i.Reg(rd, true); i.Reg(rm); i.Reg(rs);
            return;
        }
        if (imm != null && rn == Pc && op is 2 or 4 && !s)
        {
            Set(ref i, "adr");
            i.Reg(rd, true);
            uint pc = i.Address + 8;
            i.Label(op == 4 ? pc + imm.Value : pc - imm.Value, false, branch: false);
            return;
        }
        Set(ref i, ArmDp[op]);
        Flags(ref i, s);
        i.ReadsFlags = op is 5 or 6 or 7 || (shift == ArmShift.Rrx);
        if (compare) { i.WritesFlags = true; i.Reg(rn); Second(ref i); return; }
        i.Reg(rd, true);
        if (op is not (13 or 15)) i.Reg(rn);
        Second(ref i);
    }

    private static void ArmMisc(ref ArmInstruction i, uint w)
    {
        uint op = (w >> 21) & 3, op2 = (w >> 4) & 7;
        int rd = (int)((w >> 12) & 15), rm = (int)(w & 15), rn = (int)((w >> 16) & 15);
        switch (op2)
        {
            case 0:
                if ((op & 1) == 0) { Set(ref i, "mrs"); i.Reg(rd, true); i.Text((op & 2) != 0 ? "spsr" : "apsr"); i.ReadsFlags = true; }
                else
                {
                    Set(ref i, "msr");
                    i.Text((op & 2) != 0 ? "spsr" : (w & 0x80000) != 0 ? "apsr_nzcvq" : "apsr_g");
                    i.Reg(rm);
                    if ((w & 0x80000) != 0) i.WritesFlags = true;
                }
                return;
            case 1:
                if (op == 1) { Set(ref i, "bx"); i.Reg(rm); i.Flow = rm == Lr ? ArmFlow.Return : ArmFlow.IndirectJump; }
                else if (op == 3) { Set(ref i, "clz"); i.Reg(rd, true); i.Reg(rm); }
                return;
            case 2:
                if (op == 1) { Set(ref i, "bxj"); i.Reg(rm); i.Flow = ArmFlow.IndirectJump; }
                return;
            case 3:
                if (op == 1) { Set(ref i, "blx"); i.Reg(rm); i.Use(Lr, true); i.Flow = ArmFlow.IndirectCall; }
                return;
            case 5:
                Set(ref i, op switch { 0 => "qadd", 1 => "qsub", 2 => "qdadd", _ => "qdsub" });
                i.Reg(rd, true); i.Reg(rm); i.Reg(rn);
                return;
            case 6:
                if (op == 3) { Set(ref i, "eret"); i.Flow = ArmFlow.Return; }
                return;
            case 7:
                uint imm = (w >> 4) & 0xFFF0 | w & 15;
                if (op == 1) { Set(ref i, "bkpt"); i.Imm(imm); i.Flow = ArmFlow.Trap; }
                else if (op == 2) { Set(ref i, "hvc"); i.Imm(imm); }
                else if (op == 3) { Set(ref i, "smc"); i.Imm(w & 15); }
                return;
        }
    }

    private static void ArmHalfMultiply(ref ArmInstruction i, uint w)
    {
        uint op = (w >> 21) & 3;
        int rd = (int)((w >> 16) & 15), ra = (int)((w >> 12) & 15), rm = (int)((w >> 8) & 15), rn = (int)(w & 15);
        string xy = ((w & 0x20) != 0 ? "t" : "b") + ((w & 0x40) != 0 ? "t" : "b");
        switch (op)
        {
            case 0: Set(ref i, "smla" + xy); i.Reg(rd, true); i.Reg(rn); i.Reg(rm); i.Reg(ra); return;
            case 1:
                string y = (w & 0x40) != 0 ? "t" : "b";
                if ((w & 0x20) == 0) { Set(ref i, "smlaw" + y); i.Reg(rd, true); i.Reg(rn); i.Reg(rm); i.Reg(ra); }
                else { Set(ref i, "smulw" + y); i.Reg(rd, true); i.Reg(rn); i.Reg(rm); }
                return;
            case 2: Set(ref i, "smlal" + xy); i.Reg(ra, true); i.Reg(rd, true); i.Use(ra, false); i.Use(rd, false); i.Reg(rn); i.Reg(rm); return;
            default: Set(ref i, "smul" + xy); i.Reg(rd, true); i.Reg(rn); i.Reg(rm); return;
        }
    }

    private static void ArmMultiply(ref ArmInstruction i, uint w)
    {
        uint op = (w >> 20) & 15;
        bool s = (op & 1) != 0;
        int hi = (int)((w >> 16) & 15), lo = (int)((w >> 12) & 15), rm = (int)((w >> 8) & 15), rn = (int)(w & 15);
        switch (op >> 1)
        {
            case 0: Set(ref i, "mul"); Flags(ref i, s); i.Reg(hi, true); i.Reg(rn); i.Reg(rm); return;
            case 1: Set(ref i, "mla"); Flags(ref i, s); i.Reg(hi, true); i.Reg(rn); i.Reg(rm); i.Reg(lo); return;
            case 2 when op == 4: Set(ref i, "umaal"); break;
            case 3 when op == 6: Set(ref i, "mls"); i.Reg(hi, true); i.Reg(rn); i.Reg(rm); i.Reg(lo); return;
            case 4: Set(ref i, "umull"); Flags(ref i, s); break;
            case 5: Set(ref i, "umlal"); Flags(ref i, s); break;
            case 6: Set(ref i, "smull"); Flags(ref i, s); break;
            case 7: Set(ref i, "smlal"); Flags(ref i, s); break;
            default: return;
        }
        i.Reg(lo, true); i.Reg(hi, true);
        if (i.Mnemonic is not ("umull" or "smull")) { i.Use(lo, false); i.Use(hi, false); }
        i.Reg(rn); i.Reg(rm);
    }

    private static void ArmSync(ref ArmInstruction i, uint w)
    {
        uint op = (w >> 20) & 15;
        int rn = (int)((w >> 16) & 15), rd = (int)((w >> 12) & 15), rt = (int)(w & 15);
        uint kind = (w >> 8) & 3; // ARMv8: 0 lda/stl, 2 ldaex/stlex, 3 ldrex/strex
        if (op is 0 or 4)
        {
            Set(ref i, op == 0 ? "swp" : "swpb");
            Load(ref i, op == 0 ? 4 : 1);
            i.Stores = true;
            i.Reg(rd, true); i.Reg(rt); i.MemImm(rn, 0);
            return;
        }
        if (op < 8 || kind == 1) return;
        bool load = (op & 1) != 0;
        string size = ((op >> 1) & 3) switch { 0 => "", 1 => "d", 2 => "b", _ => "h" };
        int bytes = ((op >> 1) & 3) switch { 2 => 1, 3 => 2, _ => 4 };
        string name = kind switch { 3 => load ? "ldrex" : "strex", 2 => load ? "ldaex" : "stlex", _ => load ? "lda" : "stl" };
        if (kind == 0 && size == "d") return;
        Set(ref i, name + size);
        if (load)
        {
            Load(ref i, bytes);
            i.Reg(rd, true);
            if (size == "d") i.Reg(rd + 1, true);
        }
        else
        {
            Store(ref i, bytes);
            if (kind != 0) i.Reg(rd, true);
            i.Reg(rt);
            if (size == "d") i.Reg(rt + 1);
        }
        i.MemImm(rn, 0);
    }

    private static void ArmExtraLoadStore(ref ArmInstruction i, uint w)
    {
        bool p = (w & 0x01000000) != 0, u = (w & 0x00800000) != 0, imm = (w & 0x00400000) != 0, wb = (w & 0x00200000) != 0, l = (w & 0x00100000) != 0;
        int rn = (int)((w >> 16) & 15), rt = (int)((w >> 12) & 15), rm = (int)(w & 15);
        uint op2 = (w >> 5) & 3;
        (string name, int size, bool load, bool dual) = (op2, l) switch
        {
            (1, false) => ("strh", 2, false, false),
            (1, true) => ("ldrh", 2, true, false),
            (2, false) => ("ldrd", 4, true, true),
            (2, true) => ("ldrsb", 1, true, false),
            (3, false) => ("strd", 4, false, true),
            _ => ("ldrsh", 2, true, false),
        };
        if (dual && (rt & 1) != 0) return;
        bool unprivileged = !p && wb;
        Set(ref i, name + (unprivileged ? "t" : ""));
        if (load) Load(ref i, size); else Store(ref i, size);
        i.Reg(rt, load);
        if (dual) i.Reg(rt + 1, load);
        var indexing = !p ? ArmIndexing.PostIndex : wb ? ArmIndexing.PreIndex : ArmIndexing.Offset;
        if (imm)
        {
            long off = (w >> 4) & 0xF0 | w & 15;
            i.MemImm(rn, u ? off : -off, indexing);
        }
        else i.MemReg(rn, rm, !u, indexing: indexing);
    }

    private static void ArmLoadStore(ref ArmInstruction i, uint w)
    {
        bool reg = (w & 0x02000000) != 0, p = (w & 0x01000000) != 0, u = (w & 0x00800000) != 0, b = (w & 0x00400000) != 0,
            wb = (w & 0x00200000) != 0, l = (w & 0x00100000) != 0;
        int rn = (int)((w >> 16) & 15), rt = (int)((w >> 12) & 15);
        bool unprivileged = !p && wb;
        // a single-register push / pop
        if (!reg && !b && rn == Sp)
        {
            if (!l && p && !u && wb && (w & 0xFFF) == 4) { Set(ref i, "push"); Store(ref i, 4); i.List(1 << rt, false); i.Use(Sp, false); i.Use(Sp, true); return; }
            if (l && !p && u && !wb && (w & 0xFFF) == 4) { Set(ref i, "pop"); Load(ref i, 4); i.List(1 << rt, true); i.Use(Sp, false); i.Use(Sp, true); return; }
        }
        Set(ref i, (l ? "ldr" : "str") + (b ? "b" : "") + (unprivileged ? "t" : ""));
        if (l) Load(ref i, b ? 1 : 4); else Store(ref i, b ? 1 : 4);
        i.Reg(rt, l);
        var indexing = !p ? ArmIndexing.PostIndex : wb ? ArmIndexing.PreIndex : ArmIndexing.Offset;
        if (!reg)
        {
            long off = w & 0xFFF;
            i.MemImm(rn, u ? off : -off, indexing);
        }
        else
        {
            var (shift, amount) = DecodeShift((int)((w >> 5) & 3), (int)((w >> 7) & 31));
            i.MemReg(rn, (int)(w & 15), !u, shift, amount, indexing);
        }
    }

    private static void ArmLoadStoreMultiple(ref ArmInstruction i, uint w)
    {
        bool p = (w & 0x01000000) != 0, u = (w & 0x00800000) != 0, user = (w & 0x00400000) != 0, wb = (w & 0x00200000) != 0, l = (w & 0x00100000) != 0;
        int rn = (int)((w >> 16) & 15);
        int list = (int)(w & 0xFFFF);
        if (list == 0) return;
        if (rn == Sp && wb && !user && BitOperations.PopCount((uint)list) > 1 && ((l && !p && u) || (!l && p && !u)))
        {
            Set(ref i, l ? "pop" : "push");
            if (l) Load(ref i, 4); else Store(ref i, 4);
            i.List(list, l);
            i.Use(Sp, false); i.Use(Sp, true);
            return;
        }
        Set(ref i, (l ? "ldm" : "stm") + (p, u) switch { (false, false) => "da", (false, true) => "", (true, false) => "db", _ => "ib" });
        if (l) Load(ref i, 4); else Store(ref i, 4);
        i.Reg(rn);
        if (wb) { i.Use(rn, true); i.Operands[0].Text = "!"; }
        i.List(list, l);
        if (user) i.Operands[1].Text = "^";
    }

    private static void ArmMedia(ref ArmInstruction i, uint w)
    {
        uint op1 = (w >> 20) & 31, op2 = (w >> 5) & 7;
        int rn = (int)((w >> 16) & 15), rd = (int)((w >> 12) & 15), rs = (int)((w >> 8) & 15), rm = (int)(w & 15);
        if (op1 < 8)
        {
            string? op = op2 switch { 0 => "add16", 1 => "asx", 2 => "sax", 3 => "sub16", 4 => "add8", 7 => "sub8", _ => null };
            if (op == null || (op1 & 3) == 0 || Parallel(op, (op1 & 4) != 0, (int)(op1 & 3) - 1) is not { } name) return;
            Set(ref i, name);
            i.Reg(rd, true); i.Reg(rn); i.Reg(rm);
            return;
        }
        if (op1 < 16)
        {
            int rotate = (int)((w >> 10) & 3) * 8;
            string? extend = (op1, op2) switch
            {
                (8, 3) => "sxtab16", (10, 3) => "sxtab", (11, 3) => "sxtah", (12, 3) => "uxtab16", (14, 3) => "uxtab", (15, 3) => "uxtah",
                _ => null,
            };
            if (extend != null)
            {
                if (rn == Pc) { Set(ref i, extend.Remove(3, 1)); i.Reg(rd, true); }
                else { Set(ref i, extend); i.Reg(rd, true); i.Reg(rn); }
                i.Shifted(rm, rotate != 0 ? ArmShift.Ror : ArmShift.None, rotate);
                return;
            }
            string? two = (op1, op2) switch { (11, 1) => "rev", (11, 5) => "rev16", (15, 1) => "rbit", (15, 5) => "revsh", _ => null };
            if (two != null) { Set(ref i, two); i.Reg(rd, true); i.Reg(rm); return; }
            if (op1 == 8 && op2 == 5) { Set(ref i, "sel"); i.Reg(rd, true); i.Reg(rn); i.Reg(rm); return; }
            if (op1 == 8 && (op2 & 1) == 0)
            {
                bool tb = (w & 0x40) != 0;
                Set(ref i, tb ? "pkhtb" : "pkhbt");
                i.Reg(rd, true); i.Reg(rn); i.Shifted(rm, tb ? ArmShift.Asr : ArmShift.Lsl, (int)((w >> 7) & 31));
                return;
            }
            if ((op1 & 0xA) == 0xA && (op2 & 1) == 0)
            {
                bool unsigned = (op1 & 4) != 0;
                Set(ref i, unsigned ? "usat" : "ssat");
                i.Reg(rd, true);
                i.Imm(unsigned ? (w >> 16) & 31 : ((w >> 16) & 31) + 1);
                i.Shifted(rm, (w & 0x40) != 0 ? ArmShift.Asr : ArmShift.Lsl, (int)((w >> 7) & 31));
                return;
            }
            if (op1 is 10 or 14 && op2 == 1)
            {
                Set(ref i, op1 == 14 ? "usat16" : "ssat16");
                i.Reg(rd, true);
                i.Imm(op1 == 14 ? (w >> 16) & 15 : ((w >> 16) & 15) + 1);
                i.Reg(rm);
            }
            return;
        }
        if (op1 < 24)
        {
            // rd at 19:16, ra at 15:12, rm at 11:8, rn at 3:0
            int d = rn, a = rd, m = rs, n = rm;
            bool acc = a != Pc;
            bool x = (w & 0x20) != 0;
            string? name = (op1, op2 & 6) switch
            {
                (16, 0) => (acc ? "smlad" : "smuad") + (x ? "x" : ""),
                (16, 2) => (acc ? "smlsd" : "smusd") + (x ? "x" : ""),
                (20, 0) => "smlald" + (x ? "x" : ""),
                (20, 2) => "smlsld" + (x ? "x" : ""),
                (21, 0) => (acc ? "smmla" : "smmul") + (x ? "r" : ""),
                (21, 6) => "smmls" + (x ? "r" : ""),
                _ => null,
            };
            if (op1 is 17 or 19 && op2 == 0)
            {
                Set(ref i, op1 == 17 ? "sdiv" : "udiv");
                i.Reg(d, true); i.Reg(n); i.Reg(m);
                return;
            }
            if (name == null) return;
            Set(ref i, name);
            if (op1 == 20) { i.Reg(a, true); i.Reg(d, true); i.Use(a, false); i.Use(d, false); i.Reg(n); i.Reg(m); return; }
            i.Reg(d, true); i.Reg(n); i.Reg(m);
            if (acc) i.Reg(a);
            return;
        }
        if (op1 == 24 && op2 == 0)
        {
            Set(ref i, rd == Pc ? "usad8" : "usada8");
            i.Reg(rn, true); i.Reg(rm); i.Reg(rs);
            if (rd != Pc) i.Reg(rd);
            return;
        }
        int lsb = (int)((w >> 7) & 31), high = (int)((w >> 16) & 31);
        if ((op1 & 0x1E) is 0x1A or 0x1E && (op2 & 3) == 2)
        {
            Set(ref i, (op1 & 0x1E) == 0x1A ? "sbfx" : "ubfx");
            i.Reg(rd, true); i.Reg(rm); i.Imm(lsb); i.Imm(high + 1);
            return;
        }
        if ((op1 & 0x1E) == 0x1C && (op2 & 3) == 0)
        {
            if (high < lsb) return;
            if (rm == Pc) { Set(ref i, "bfc"); i.Reg(rd, true); i.Use(rd, false); }
            else { Set(ref i, "bfi"); i.Reg(rd, true); i.Use(rd, false); i.Reg(rm); }
            i.Imm(lsb); i.Imm(high - lsb + 1);
            return;
        }
        if (op1 == 31 && op2 == 7)
        {
            Set(ref i, w == 0xE7FFDEFE ? "trap" : "udf");
            if (i.Mnemonic == "udf") i.Imm((w >> 4) & 0xFFF0 | w & 15);
            i.Flow = ArmFlow.Trap;
        }
    }

    // ---------------------------------------------------------------- coprocessor, VFP, NEON (A32 word form)

    private static void Coprocessor(ref ArmInstruction i, uint w)
    {
        bool unconditional = w >> 28 == 15;
        if (unconditional && (w & 0xFE000000) == 0xF2000000) { Arm32Neon.DataProcessing(ref i, w); return; }
        if (unconditional && (w & 0xFF100000) == 0xF4000000) { NeonLoadStore(ref i, w); return; }
        uint coproc = (w >> 8) & 15;
        bool vfp = (coproc & 0xE) == 0xA && !unconditional;
        int rt = (int)((w >> 12) & 15), rn = (int)((w >> 16) & 15);
        switch ((w >> 24) & 15)
        {
            case 0xC or 0xD:
            {
                uint op1 = (w >> 20) & 0x3F;
                if ((op1 & 0x3E) == 0x04)
                {
                    bool toCore = (w & 0x100000) != 0;
                    int rt2 = rn;
                    if (vfp)
                    {
                        Set(ref i, "vmov");
                        int m = (int)(w & 15 | (w >> 1) & 0x10);
                        bool dbl = coproc == 11;
                        int sm = (int)((w & 15) << 1 | (w >> 5) & 1);
                        if (toCore) { i.Reg(rt, true); i.Reg(rt2, true); }
                        if (dbl) i.Vec(ArmVector.D, m);
                        else { i.Vec(ArmVector.S, sm); i.Vec(ArmVector.S, sm + 1); }
                        if (!toCore) { i.Reg(rt); i.Reg(rt2); }
                        return;
                    }
                    Set(ref i, toCore ? "mrrc" : "mcrr");
                    i.Text($"p{coproc}"); i.Imm((w >> 4) & 15); i.Reg(rt, toCore); i.Reg(rt2, toCore); i.Text($"c{w & 15}");
                    return;
                }
                if ((op1 & 0x3E) == 0) return;
                bool p = (w & 0x01000000) != 0, u = (w & 0x00800000) != 0, wb = (w & 0x00200000) != 0, l = (w & 0x00100000) != 0;
                long imm8 = w & 0xFF;
                if (!vfp)
                {
                    Set(ref i, (l ? "ldc" : "stc") + (unconditional ? "2" : "") + ((w & 0x400000) != 0 ? "l" : ""));
                    i.Text($"p{coproc}"); i.Text($"c{rt}");
                    i.MemImm(rn, u ? imm8 * 4 : -imm8 * 4, !p ? ArmIndexing.PostIndex : wb ? ArmIndexing.PreIndex : ArmIndexing.Offset);
                    return;
                }
                bool dbl2 = coproc == 11;
                int d = dbl2 ? (int)((w >> 18) & 0x10 | (w >> 12) & 15) : (int)((w >> 11) & 0x1E | (w >> 22) & 1);
                if (p && !wb)
                {
                    Set(ref i, l ? "vldr" : "vstr");
                    if (l) Load(ref i, dbl2 ? 8 : 4); else Store(ref i, dbl2 ? 8 : 4);
                    i.Vec(dbl2 ? ArmVector.D : ArmVector.S, d);
                    i.MemImm(rn, u ? imm8 * 4 : -imm8 * 4);
                    return;
                }
                if (p == u) return;
                int count = dbl2 ? (int)(imm8 / 2) : (int)imm8;
                if (count == 0) return;
                if (rn == Sp && wb && ((l && u) || (!l && p)))
                {
                    Set(ref i, l ? "vpop" : "vpush");
                    if (l) Load(ref i, dbl2 ? 8 : 4); else Store(ref i, dbl2 ? 8 : 4);
                    i.VecList(dbl2 ? ArmVector.D : ArmVector.S, d, count);
                    i.Use(Sp, false); i.Use(Sp, true);
                    return;
                }
                Set(ref i, (l ? "vldm" : "vstm") + (p ? "db" : "ia"));
                if (l) Load(ref i, dbl2 ? 8 : 4); else Store(ref i, dbl2 ? 8 : 4);
                i.Reg(rn);
                if (wb) { i.Use(rn, true); i.Operands[0].Text = "!"; }
                i.VecList(dbl2 ? ArmVector.D : ArmVector.S, d, count);
                return;
            }
            case 0xE:
                if ((w & 0x10) == 0)
                {
                    if (vfp) VfpData(ref i, w);
                    else { Set(ref i, "cdp"); i.Text($"p{coproc}"); i.Imm((w >> 20) & 15); i.Text($"c{rt}"); i.Text($"c{rn}"); i.Text($"c{w & 15}"); i.Imm((w >> 5) & 7); }
                    return;
                }
                VfpTransfer(ref i, w, vfp, coproc);
                return;
        }
    }

    private static void VfpTransfer(ref ArmInstruction i, uint w, bool vfp, uint coproc)
    {
        bool toCore = (w & 0x100000) != 0;
        int rt = (int)((w >> 12) & 15), crn = (int)((w >> 16) & 15);
        uint opc1 = (w >> 21) & 7;
        if (!vfp)
        {
            Set(ref i, toCore ? "mrc" : "mcr");
            i.Text($"p{coproc}"); i.Imm(opc1);
            if (toCore && rt == Pc) { i.Text("apsr_nzcv"); i.WritesFlags = true; }
            else i.Reg(rt, toCore);
            i.Text($"c{crn}"); i.Text($"c{w & 15}"); i.Imm((w >> 5) & 7);
            return;
        }
        if (coproc == 10)
        {
            if (opc1 == 0)
            {
                Set(ref i, "vmov");
                int sn = (int)((w >> 15) & 0x1E | (w >> 7) & 1);
                if (toCore) { i.Reg(rt, true); i.Vec(ArmVector.S, sn); }
                else { i.Vec(ArmVector.S, sn); i.Reg(rt); }
                return;
            }
            if (opc1 == 7)
            {
                string reg = crn switch { 1 => "fpscr", 0 => "fpsid", 8 => "fpexc", 6 => "mvfr1", 7 => "mvfr0", 5 => "mvfr2", _ => $"fpcr{crn}" };
                if (toCore)
                {
                    Set(ref i, "vmrs");
                    if (rt == Pc) { i.Text("apsr_nzcv"); i.WritesFlags = true; } else i.Reg(rt, true);
                    i.Text(reg);
                }
                else { Set(ref i, "vmsr"); i.Text(reg); i.Reg(rt); }
            }
            return;
        }
        // coproc 11: scalar moves and vdup
        int dn = (int)((w >> 3) & 0x10 | (w >> 16) & 15);
        uint opc = ((w >> 21) & 3) << 2 | (w >> 5) & 3;
        if (!toCore && (w & 0x00800000) != 0)
        {
            if ((w & 0x40) != 0) return;
            Set(ref i, "vdup");
            i.Suffix = ((w >> 21) & 2 | (w >> 5) & 1) switch { 2 => ".8", 1 => ".16", 0 => ".32", _ => null };
            bool q = (w & 0x200000) != 0;
            i.Vec(q ? ArmVector.Q : ArmVector.D, q ? dn >> 1 : dn);
            i.Reg(rt);
            return;
        }
        (string? size, int lane) = (opc & 0x8) != 0 ? (".8", (int)(opc & 7)) : (opc & 1) != 0 ? (".16", (int)(opc >> 1 & 3)) : (opc & 2) == 0 ? (".32", (int)(opc >> 2 & 1)) : (null, 0);
        if (size == null) return;
        Set(ref i, "vmov");
        if (toCore)
        {
            i.Suffix = size == ".32" ? ".32" : ((w & 0x00800000) != 0 ? ".u" : ".s") + size[1..];
            i.Reg(rt, true); i.Vec(ArmVector.D, dn, lane);
        }
        else { i.Suffix = size; i.Vec(ArmVector.D, dn, lane); i.Reg(rt); }
    }

    private static void VfpData(ref ArmInstruction i, uint w)
    {
        bool dbl = (w & 0x100) != 0;
        var kind = dbl ? ArmVector.D : ArmVector.S;
        int Reg(int four, int extra) => dbl ? extra << 4 | four : four << 1 | extra;
        int d = Reg((int)((w >> 12) & 15), (int)((w >> 22) & 1));
        int n = Reg((int)((w >> 16) & 15), (int)((w >> 7) & 1));
        int m = Reg((int)(w & 15), (int)((w >> 5) & 1));
        bool op = (w & 0x40) != 0;
        string type = dbl ? ".f64" : ".f32";
        uint opc1 = (w >> 20) & 0xB;
        string? three = opc1 switch
        {
            0 => op ? "vmls" : "vmla",
            1 => op ? "vnmla" : "vnmls",
            2 => op ? "vnmul" : "vmul",
            3 => op ? "vsub" : "vadd",
            8 when !op => "vdiv",
            9 => op ? "vfnma" : "vfnms",
            10 => op ? "vfms" : "vfma",
            _ => null,
        };
        if (three != null)
        {
            Set(ref i, three);
            i.Suffix = type;
            i.Vec(kind, d); i.Vec(kind, n); i.Vec(kind, m);
            return;
        }
        if (opc1 != 0xB) return;
        if (!op)
        {
            Set(ref i, "vmov");
            i.Suffix = type;
            i.Vec(kind, d);
            i.Text(VfpImmediate((w >> 12) & 0xF0 | w & 15));
            return;
        }
        uint opc2 = (w >> 16) & 15;
        bool bit7 = (w & 0x80) != 0;
        switch (opc2)
        {
            case 0: Set(ref i, bit7 ? "vabs" : "vmov"); i.Suffix = type; i.Vec(kind, d); i.Vec(kind, m); return;
            case 1: Set(ref i, bit7 ? "vsqrt" : "vneg"); i.Suffix = type; i.Vec(kind, d); i.Vec(kind, m); return;
            case 4 or 5:
                Set(ref i, bit7 ? "vcmpe" : "vcmp");
                i.Suffix = type;
                i.Vec(kind, d);
                if (opc2 == 5) i.Text("#0"); else i.Vec(kind, m);
                return;
            case 7 when bit7:
                Set(ref i, "vcvt");
                i.Suffix = dbl ? ".f32.f64" : ".f64.f32";
                i.Vec(dbl ? ArmVector.S : ArmVector.D, dbl ? (int)((w >> 11) & 0x1E | (w >> 22) & 1) : (int)((w >> 18) & 0x10 | (w >> 12) & 15));
                i.Vec(kind, m);
                return;
            case 8:
                Set(ref i, "vcvt");
                i.Suffix = type + (bit7 ? ".s32" : ".u32");
                i.Vec(kind, d);
                i.Vec(ArmVector.S, (int)((w & 15) << 1 | (w >> 5) & 1));
                return;
            case 12 or 13:
                Set(ref i, bit7 ? "vcvt" : "vcvtr");
                i.Suffix = (opc2 == 13 ? ".s32" : ".u32") + type;
                i.Vec(ArmVector.S, (int)((w >> 11) & 0x1E | (w >> 22) & 1));
                i.Vec(kind, m);
                return;
            case 2 or 3:
                Set(ref i, bit7 ? "vcvtt" : "vcvtb");
                i.Suffix = opc2 == 2 ? ".f32.f16" : ".f16.f32";
                i.Vec(ArmVector.S, (int)((w >> 11) & 0x1E | (w >> 22) & 1));
                i.Vec(ArmVector.S, (int)((w & 15) << 1 | (w >> 5) & 1));
                return;
            case 10 or 11 or 14 or 15:
            {
                // fixed point: the fraction bits are size - imm5
                bool sixteen = !bit7;
                string fixedType = ((opc2 & 1) != 0 ? ".u" : ".s") + (sixteen ? "16" : "32");
                Set(ref i, "vcvt");
                i.Suffix = opc2 < 14 ? type + fixedType : fixedType + type;
                i.Vec(kind, d); i.Vec(kind, d);
                i.Imm((sixteen ? 16 : 32) - (int)((w & 15) << 1 | (w >> 5) & 1));
                return;
            }
        }
    }

    /// <summary>VFPExpandImm: ±(16 + fraction) / 16 × 2^n, n in [-3, 4].</summary>
    private static string VfpImmediate(uint imm8)
    {
        int exp = (int)(imm8 >> 4) & 7, frac = (int)imm8 & 15;
        int n = (exp & 4) == 0 ? (exp & 3) + 1 : (exp & 3) - 3;
        double v = (16 + frac) / 16.0 * Math.Pow(2, n) * ((imm8 & 0x80) != 0 ? -1 : 1);
        return "#" + v.ToString("0.000000e+00", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static void NeonLoadStore(ref ArmInstruction i, uint w)
    {
        bool load = (w & 0x200000) != 0, all = (w & 0x800000) != 0;
        int rn = (int)((w >> 16) & 15), rm = (int)(w & 15);
        int d = (int)((w >> 18) & 0x10 | (w >> 12) & 15);
        uint type = (w >> 8) & 15;
        int n, regs, stride = 1, align = 0;
        string lanes = "";
        string? size;
        if (!all)
        {
            (n, regs, stride) = type switch
            {
                7 => (1, 1, 1), 10 => (1, 2, 1), 6 => (1, 3, 1), 2 => (1, 4, 1),
                8 => (2, 2, 1), 9 => (2, 2, 2), 3 => (2, 4, 1),
                4 => (3, 3, 1), 5 => (3, 3, 2), 0 => (4, 4, 1), 1 => (4, 4, 2), _ => (0, 0, 0),
            };
            if (n == 0) return;
            size = ((w >> 6) & 3) switch { 0 => ".8", 1 => ".16", 2 => ".32", _ => ".64" };
            if (((w >> 4) & 3) is var a and > 0) align = 64 << (int)(a - 1);
        }
        else
        {
            int s = (int)((w >> 10) & 3);
            n = (int)((w >> 8) & 3) + 1;
            regs = n;
            if (s == 3)
            {
                lanes = "[]";
                size = ((w >> 6) & 3) switch { 0 => ".8", 1 => ".16", _ => ".32" };
                bool t = (w & 0x20) != 0;
                if (n == 1) regs = t ? 2 : 1; else stride = t ? 2 : 1;
            }
            else
            {
                int index = s switch { 0 => (int)(w >> 5) & 7, 1 => (int)(w >> 6) & 3, _ => (int)(w >> 7) & 1 };
                lanes = $"[{index}]";
                size = s switch { 0 => ".8", 1 => ".16", _ => ".32" };
                if (n > 1 && (s == 1 && (w & 0x20) != 0 || s == 2 && (w & 0x40) != 0)) stride = 2;
                if (n == 1) align = s switch { 1 when (w & 0x10) != 0 => 16, 2 when (w & 0x30) == 0x30 => 32, _ => 0 };
            }
        }
        Set(ref i, (load ? "vld" : "vst") + n);
        i.Suffix = size;
        if (load) Load(ref i, 8); else Store(ref i, 8);
        i.VecList(ArmVector.D, d, regs, lanes.Length > 0 ? lanes : null, stride);
        if (rm == Pc) i.MemImm(rn, 0);
        else if (rm == Sp) i.MemImm(rn, 0, ArmIndexing.PreIndex);
        else i.MemReg(rn, rm, indexing: ArmIndexing.PostIndex);
        if (align != 0) i.Operands[i.OperandCount - 1].Text = $":{align}";
    }

    // ---------------------------------------------------------------- shared

    private static void Load(ref ArmInstruction i, int size)
    {
        i.Loads = true;
        i.AccessSize = (byte)size;
    }

    private static void Store(ref ArmInstruction i, int size)
    {
        i.Stores = true;
        i.AccessSize = (byte)size;
    }

    /// <summary>Control flow of instructions that write the PC (returns and indirect jumps) and invalid leftovers.</summary>
    private static void Finish(ref ArmInstruction i)
    {
        if (i.Flow == ArmFlow.Invalid) { Bad(ref i); return; }
        if (i.Flow != ArmFlow.Next || !i.WritesPc) return;
        // pop {.., pc}, ldm sp!, {.., pc}, ldr pc, [sp], #4, mov pc, lr: returns; any other write to pc jumps
        bool fromStack = i.Loads && (i.Mnemonic == "pop" || i.OperandCount > 0 && (i.Op(0).Kind == ArmOperandKind.Register && i.Op(0).Reg == Sp && i.Mnemonic.StartsWith("ldm", StringComparison.Ordinal)
            || i.OperandCount > 1 && i.Op(1).Kind == ArmOperandKind.Memory && i.Op(1).Reg == Sp && i.Op(1).Indexing == ArmIndexing.PostIndex));
        bool fromLr = i.Mnemonic == "mov" && i.OperandCount == 2 && i.Op(1).Kind == ArmOperandKind.Register && i.Op(1).Reg == Lr;
        i.Flow = fromStack || fromLr ? ArmFlow.Return : ArmFlow.IndirectJump;
    }
}
