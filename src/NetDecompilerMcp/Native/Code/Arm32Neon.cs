namespace NetDecompilerMcp.Native.Code;

/// <summary>
/// Advanced SIMD (NEON) data processing in the A32 word form (T32 encodings are converted first): three registers of
/// the same or different lengths, a register and a modified immediate, shifts by an immediate, two-register
/// miscellaneous operations, scalars, VEXT, VTBL / VTBX and VDUP. An encoding outside these classes stays "simd"
/// without operands; every one is valid, flows on and touches no core register.
/// </summary>
internal static class Arm32Neon
{
    private static void Set(ref ArmInstruction i, string mnemonic, string? suffix = null)
    {
        i.Mnemonic = mnemonic;
        i.Suffix = suffix;
        i.Flow = ArmFlow.Next;
    }

    public static void DataProcessing(ref ArmInstruction i, uint w)
    {
        Set(ref i, "simd");
        bool u = (w & 0x01000000) != 0;
        if ((w & 0x00800000) == 0) { ThreeSame(ref i, w, u); return; }
        if ((w & 0x10) != 0)
        {
            if ((w & 0x00380080) == 0) Immediate(ref i, w);
            else Shift(ref i, w, u);
            return;
        }
        if ((w & 0x00300000) != 0x00300000)
        {
            if ((w & 0x40) == 0) ThreeDifferent(ref i, w, u);
            else Scalar(ref i, w, u);
            return;
        }
        if (!u) { Ext(ref i, w); return; }
        if ((w & 0x800) == 0) Misc(ref i, w);
        else if ((w & 0xC00) == 0x800) Table(ref i, w);
        else if ((w & 0xF90) == 0xC00) Dup(ref i, w);
        if (i.Mnemonic == "simd") i.ResetOperands();
    }

    private static int D(uint w) => (int)((w >> 18) & 0x10 | (w >> 12) & 15);
    private static int N(uint w) => (int)((w >> 3) & 0x10 | (w >> 16) & 15);
    private static int M(uint w) => (int)((w >> 1) & 0x10 | w & 15);

    /// <summary>A D or Q register operand (Q registers are numbered by pairs of D registers).</summary>
    private static void Reg(ref ArmInstruction i, bool q, int d) => i.Vec(q ? ArmVector.Q : ArmVector.D, q ? d >> 1 : d);

    private static void Three(ref ArmInstruction i, uint w, bool q)
    {
        Reg(ref i, q, D(w)); Reg(ref i, q, N(w)); Reg(ref i, q, M(w));
    }

    private static string Signed(bool u, int size) => (u ? ".u" : ".s") + (8 << size);
    private static string Int(int size) => ".i" + (8 << size);

    private static void ThreeSame(ref ArmInstruction i, uint w, bool u)
    {
        int a = (int)((w >> 8) & 15), size = (int)((w >> 20) & 3);
        bool b = (w & 0x10) != 0, q = (w & 0x40) != 0, high = (size & 2) != 0;
        string? name = null, suffix = null;
        switch (a)
        {
            case 0: name = b ? "vqadd" : "vhadd"; suffix = Signed(u, size); break;
            case 1:
                if (!b) { name = "vrhadd"; suffix = Signed(u, size); break; }
                name = (u, size) switch { (false, 0) => "vand", (false, 1) => "vbic", (false, 2) => "vorr", (false, _) => "vorn", (true, 0) => "veor", (true, 1) => "vbsl", (true, 2) => "vbit", _ => "vbif" };
                break;
            case 2: name = b ? "vqsub" : "vhsub"; suffix = Signed(u, size); break;
            case 3: name = b ? "vcge" : "vcgt"; suffix = Signed(u, size); break;
            case 4 or 5:
                name = (a, b) switch { (4, false) => "vshl", (4, true) => "vqshl", (5, false) => "vrshl", _ => "vqrshl" };
                Set(ref i, name, Signed(u, size));
                Reg(ref i, q, D(w)); Reg(ref i, q, M(w)); Reg(ref i, q, N(w));
                return;
            case 6: name = b ? "vmin" : "vmax"; suffix = Signed(u, size); break;
            case 7: name = b ? "vaba" : "vabd"; suffix = Signed(u, size); break;
            case 8: name = (b, u) switch { (false, false) => "vadd", (false, true) => "vsub", (true, false) => "vtst", _ => "vceq" }; suffix = name == "vtst" ? "." + (8 << size) : Int(size); break;
            case 9:
                name = b ? "vmul" : u ? "vmls" : "vmla";
                suffix = b && u ? ".p8" : Int(size);
                break;
            case 10: name = b ? "vpmin" : "vpmax"; suffix = Signed(u, size); break;
            case 11:
                if (!b) { name = u ? "vqrdmulh" : "vqdmulh"; suffix = ".s" + (8 << size); }
                else if (!u) { name = "vpadd"; suffix = Int(size); }
                break;
            case 12 when b && !u: name = high ? "vfms" : "vfma"; suffix = ".f32"; break;
            case 13:
                suffix = ".f32";
                name = (b, u, high) switch
                {
                    (false, false, false) => "vadd", (false, false, true) => "vsub", (false, true, false) => "vpadd", (false, true, true) => "vabd",
                    (true, false, false) => "vmla", (true, false, true) => "vmls", (true, true, false) => "vmul", _ => null,
                };
                break;
            case 14:
                suffix = ".f32";
                name = (b, u, high) switch { (false, false, false) => "vceq", (false, true, false) => "vcge", (false, true, true) => "vcgt", (true, true, false) => "vacge", (true, true, true) => "vacgt", _ => null };
                break;
            case 15:
                suffix = ".f32";
                name = (b, u, high) switch { (false, false, false) => "vmax", (false, false, true) => "vmin", (false, true, false) => "vpmax", (false, true, true) => "vpmin", (true, false, false) => "vrecps", (true, false, true) => "vrsqrts", _ => null };
                break;
        }
        if (name == null) return;
        // pairwise operations work on D registers only
        if (q && name is "vpadd" or "vpmax" or "vpmin") return;
        Set(ref i, name, suffix);
        Three(ref i, w, q);
    }

    /// <summary>VMOV / VORR / VMVN / VBIC with a modified immediate (AdvSIMDExpandImm).</summary>
    private static void Immediate(ref ArmInstruction i, uint w)
    {
        int cmode = (int)((w >> 8) & 15);
        bool op = (w & 0x20) != 0, q = (w & 0x40) != 0;
        ulong imm8 = (w >> 17) & 0x80 | (w >> 12) & 0x70 | w & 15;
        string? name;
        string suffix;
        ulong value;
        switch (cmode)
        {
            case < 8:
                name = (cmode & 1) == 0 ? op ? "vmvn" : "vmov" : op ? "vbic" : "vorr";
                suffix = ".i32";
                value = imm8 << (8 * (cmode >> 1));
                break;
            case < 12:
                name = (cmode & 1) == 0 ? op ? "vmvn" : "vmov" : op ? "vbic" : "vorr";
                suffix = ".i16";
                value = imm8 << (8 * ((cmode >> 1) & 1));
                break;
            case 12 or 13:
                name = op ? "vmvn" : "vmov";
                suffix = ".i32";
                value = cmode == 12 ? imm8 << 8 | 0xFF : imm8 << 16 | 0xFFFF;
                break;
            case 14:
                name = "vmov";
                suffix = op ? ".i64" : ".i8";
                value = imm8;
                if (op)
                {
                    value = 0;
                    for (int k = 0; k < 8; k++) if ((imm8 & (1UL << k)) != 0) value |= 0xFFUL << (8 * k);
                }
                break;
            default:
                if (op) return;
                Set(ref i, "vmov", ".f32");
                Reg(ref i, q, D(w));
                int exp = (int)(imm8 >> 4) & 7, frac = (int)imm8 & 15;
                int n = (exp & 4) == 0 ? (exp & 3) + 1 : (exp & 3) - 3;
                double v = (16 + frac) / 16.0 * Math.Pow(2, n) * ((imm8 & 0x80) != 0 ? -1 : 1);
                i.Text("#" + v.ToString("0.000000e+00", System.Globalization.CultureInfo.InvariantCulture));
                return;
        }
        Set(ref i, name, suffix);
        Reg(ref i, q, D(w));
        i.Imm((long)value);
    }

    private static void Shift(ref ArmInstruction i, uint w, bool u)
    {
        int a = (int)((w >> 8) & 15), imm6 = (int)((w >> 16) & 63);
        bool l = (w & 0x80) != 0, q = (w & 0x40) != 0;
        int esize = l ? 64 : imm6 >= 32 ? 32 : imm6 >= 16 ? 16 : 8;
        int right = l ? 64 - imm6 : 2 * esize - imm6, left = l ? imm6 : imm6 - esize;
        string su = (u ? ".u" : ".s") + esize;
        switch (a)
        {
            case 0 or 1 or 2 or 3:
                Set(ref i, a switch { 0 => "vshr", 1 => "vsra", 2 => "vrshr", _ => "vrsra" }, su);
                Reg(ref i, q, D(w)); Reg(ref i, q, M(w)); i.Imm(right);
                return;
            case 4 when u:
                Set(ref i, "vsri", "." + esize);
                Reg(ref i, q, D(w)); Reg(ref i, q, M(w)); i.Imm(right);
                return;
            case 5:
                Set(ref i, u ? "vsli" : "vshl", u ? "." + esize : ".i" + esize);
                Reg(ref i, q, D(w)); Reg(ref i, q, M(w)); i.Imm(left);
                return;
            case 6 or 7:
                Set(ref i, a == 6 ? "vqshlu" : "vqshl", a == 6 ? ".s" + esize : su);
                if (a == 6 && !u) return;
                Reg(ref i, q, D(w)); Reg(ref i, q, M(w)); i.Imm(left);
                return;
            case 8 or 9 when !l:
            {
                // narrowing: the source elements are twice the size
                string name = (a, u, q) switch
                {
                    (8, false, false) => "vshrn", (8, false, true) => "vrshrn", (8, true, false) => "vqshrun", (8, true, true) => "vqrshrun",
                    (9, _, false) => "vqshrn", _ => "vqrshrn",
                };
                string suffix = a == 8 && !u ? ".i" + 2 * esize : (a == 8 || u ? ".u" : ".s") + 2 * esize;
                if (a == 8 && u) suffix = ".s" + 2 * esize;
                Set(ref i, name, suffix);
                i.Vec(ArmVector.D, D(w)); i.Vec(ArmVector.Q, M(w) >> 1); i.Imm(right);
                return;
            }
            case 10 when !l && !q:
                Set(ref i, left == 0 ? "vmovl" : "vshll", su);
                i.Vec(ArmVector.Q, D(w) >> 1); i.Vec(ArmVector.D, M(w));
                if (left != 0) i.Imm(left);
                return;
            case 14 or 15 when !l && imm6 >= 32:
                Set(ref i, "vcvt", a == 14 ? (u ? ".f32.u32" : ".f32.s32") : (u ? ".u32.f32" : ".s32.f32"));
                Reg(ref i, q, D(w)); Reg(ref i, q, M(w)); i.Imm(64 - imm6);
                return;
        }
    }

    private static void ThreeDifferent(ref ArmInstruction i, uint w, bool u)
    {
        int a = (int)((w >> 8) & 15), size = (int)((w >> 20) & 3);
        string su = Signed(u, size);
        string? name = a switch
        {
            0 => "vaddl", 1 => "vaddw", 2 => "vsubl", 3 => "vsubw", 4 => u ? "vraddhn" : "vaddhn", 5 => "vabal", 6 => u ? "vrsubhn" : "vsubhn", 7 => "vabdl",
            8 => "vmlal", 9 => u ? null : "vqdmlal", 10 => "vmlsl", 11 => u ? null : "vqdmlsl", 12 => "vmull", 13 => u ? null : "vqdmull", 14 => u ? null : "vmull", _ => null,
        };
        if (name == null) return;
        string suffix = a is 4 or 6 ? ".i" + (16 << size) : a is 9 or 11 or 13 ? ".s" + (8 << size) : a == 14 ? ".p8" : su;
        Set(ref i, name, suffix);
        if (a is 4 or 6) { i.Vec(ArmVector.D, D(w)); i.Vec(ArmVector.Q, N(w) >> 1); i.Vec(ArmVector.Q, M(w) >> 1); return; }
        i.Vec(ArmVector.Q, D(w) >> 1);
        if (a is 1 or 3) i.Vec(ArmVector.Q, N(w) >> 1); else i.Vec(ArmVector.D, N(w));
        i.Vec(ArmVector.D, M(w));
    }

    private static void Scalar(ref ArmInstruction i, uint w, bool u)
    {
        int a = (int)((w >> 8) & 15), size = (int)((w >> 20) & 3);
        if (size is 0 or 3) return;
        bool f = (a & 1) != 0 && a is 1 or 5 or 9;
        string? name = a switch
        {
            0 or 1 => "vmla", 4 or 5 => "vmls", 2 => "vmlal", 6 => "vmlsl", 8 or 9 => "vmul", 10 => "vmull",
            3 when !u => "vqdmlal", 7 when !u => "vqdmlsl", 11 when !u => "vqdmull", 12 => "vqdmulh", 13 => "vqrdmulh", _ => null,
        };
        if (name == null) return;
        int m = size == 1 ? (int)(w & 7) : (int)(w & 15);
        int index = size == 1 ? (int)((w >> 4) & 2 | (w >> 3) & 1) : (int)((w >> 5) & 1);
        bool longer = a is 2 or 3 or 6 or 7 or 10 or 11;
        string suffix = f ? ".f32" : a is 2 or 6 or 10 ? Signed(u, size) : a is 3 or 7 or 11 or 12 or 13 ? ".s" + (8 << size) : ".i" + (8 << size);
        Set(ref i, name, suffix);
        if (longer) { i.Vec(ArmVector.Q, D(w) >> 1); i.Vec(ArmVector.D, N(w)); }
        else { Reg(ref i, u, D(w)); Reg(ref i, u, N(w)); }
        i.Vec(ArmVector.D, m, index);
    }

    /// <summary>VEXT names the widest element size the byte offset is a multiple of.</summary>
    private static void Ext(ref ArmInstruction i, uint w)
    {
        bool q = (w & 0x40) != 0;
        int imm = (int)((w >> 8) & 15), e = 1;
        foreach (int size in q ? [8, 4, 2] : new[] { 4, 2 })
            if (imm > 0 && imm % size == 0) { e = size; break; }
        Set(ref i, "vext", "." + 8 * e);
        Three(ref i, w, q);
        i.Imm(imm / e);
    }

    private static void Misc(ref ArmInstruction i, uint w)
    {
        int a = (int)((w >> 16) & 3), b = (int)((w >> 6) & 31), size = (int)((w >> 18) & 3);
        bool q = (w & 0x40) != 0;
        string? name = null, suffix = null;
        bool zero = false;
        switch (a)
        {
            case 0:
                (name, suffix) = (b >> 1) switch
                {
                    0 => ("vrev64", "." + (8 << size)), 1 => ("vrev32", "." + (8 << size)), 2 => ("vrev16", "." + (8 << size)),
                    4 or 5 => ("vpaddl", Signed((b & 2) != 0, size)), 8 => ("vcls", ".s" + (8 << size)), 9 => ("vclz", ".i" + (8 << size)),
                    10 => ("vcnt", ".8"), 11 => ("vmvn", null), 12 or 13 => ("vpadal", Signed((b & 2) != 0, size)),
                    14 => ("vqabs", ".s" + (8 << size)), 15 => ("vqneg", ".s" + (8 << size)), _ => (null, null),
                };
                break;
            case 1:
            {
                bool fl = (b & 0x10) != 0;
                name = ((b >> 1) & 7) switch { 0 => "vcgt", 1 => "vcge", 2 => "vceq", 3 => "vcle", 4 => "vclt", 6 => "vabs", 7 => "vneg", _ => null };
                suffix = fl ? ".f32" : name is "vceq" ? ".i" + (8 << size) : ".s" + (8 << size);
                zero = name is not ("vabs" or "vneg");
                break;
            }
            case 2:
                if (b >> 1 is 0 or 1 or 2 or 3)
                {
                    name = (b >> 1) switch { 0 => "vswp", 1 => "vtrn", 2 => "vuzp", _ => "vzip" };
                    suffix = name == "vswp" ? null : "." + (8 << size);
                    break;
                }
                if (b == 12)
                {
                    // shift left long by the element size
                    Set(ref i, "vshll", ".i" + (8 << size));
                    i.Vec(ArmVector.Q, D(w) >> 1); i.Vec(ArmVector.D, M(w)); i.Imm(8 << size);
                    return;
                }
                if (b is 8 or 9 or 10 or 11)
                {
                    // narrowing moves: Dd, Qm
                    (name, suffix) = b switch { 8 => ("vmovn", ".i" + (16 << size)), 9 => ("vqmovun", ".s" + (16 << size)), 10 => ("vqmovn", ".s" + (16 << size)), _ => ("vqmovn", ".u" + (16 << size)) };
                    Set(ref i, name, suffix);
                    i.Vec(ArmVector.D, D(w)); i.Vec(ArmVector.Q, M(w) >> 1);
                    return;
                }
                return;
            case 3:
                if ((b & 0x18) == 0x18)
                {
                    Set(ref i, "vcvt", ((b >> 1) & 3) switch { 0 => ".f32.s32", 1 => ".f32.u32", 2 => ".s32.f32", _ => ".u32.f32" });
                    Reg(ref i, q, D(w)); Reg(ref i, q, M(w));
                    return;
                }
                if ((b & 0x1A) == 0x10) { name = "vrecpe"; suffix = (b & 4) != 0 ? ".f32" : ".u32"; }
                else if ((b & 0x1A) == 0x12) { name = "vrsqrte"; suffix = (b & 4) != 0 ? ".f32" : ".u32"; }
                break;
        }
        if (name == null) return;
        Set(ref i, name, suffix);
        Reg(ref i, q, D(w)); Reg(ref i, q, M(w));
        if (zero) i.Imm(0);
    }

    private static void Table(ref ArmInstruction i, uint w)
    {
        int len = (int)((w >> 8) & 3) + 1;
        Set(ref i, (w & 0x40) != 0 ? "vtbx" : "vtbl", ".8");
        i.Vec(ArmVector.D, D(w));
        i.VecList(ArmVector.D, N(w), len);
        i.Vec(ArmVector.D, M(w));
    }

    private static void Dup(ref ArmInstruction i, uint w)
    {
        int imm4 = (int)((w >> 16) & 15);
        bool q = (w & 0x40) != 0;
        (string? size, int index) = (imm4 & 1) != 0 ? (".8", imm4 >> 1) : (imm4 & 2) != 0 ? (".16", imm4 >> 2) : (imm4 & 4) != 0 ? (".32", imm4 >> 3) : (null, 0);
        if (size == null) return;
        Set(ref i, "vdup", size);
        Reg(ref i, q, D(w));
        i.Vec(ArmVector.D, M(w), index);
    }
}
