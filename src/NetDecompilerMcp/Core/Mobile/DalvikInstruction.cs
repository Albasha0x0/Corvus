namespace NetDecompilerMcp.Core.Mobile;

/// <summary>Instruction formats of the Dalvik bytecode spec ("12x": 1 code unit, 2 registers, no extra data).</summary>
public enum DalvikFormat
{
    F10x, F12x, F11n, F11x, F10t, F20t, F22x, F21t, F21s, F21h, F21c, F23x, F22b, F22t, F22s, F22c, F30t, F32x, F31i, F31t, F31c,
    F35c, F3rc, F45cc, F4rcc, F51l, Unused, PackedSwitchPayload, SparseSwitchPayload, FillArrayPayload,
}

/// <summary>What a pool index operand refers to.</summary>
public enum DalvikRef : byte { None, String, Type, Field, Method, Proto, CallSite, MethodHandle }

/// <summary>
/// One decoded instruction. Offsets and branch targets are in 16-bit code units from the start of the method's code.
/// Registers: A, B, C as the format numbers them, or the argument list of a call / filled-new-array (<see cref="Arguments"/>).
/// </summary>
public sealed record DalvikInstruction(int Offset, int Opcode, string Name, DalvikFormat Format, int Length, int A, int B, int C, long Literal,
    DalvikRef Ref, int Index, int Index2, int Target, IReadOnlyList<int> Arguments)
{
    public bool IsPayload => Format is DalvikFormat.PackedSwitchPayload or DalvikFormat.SparseSwitchPayload or DalvikFormat.FillArrayPayload;
    public bool IsRange => Format is DalvikFormat.F3rc or DalvikFormat.F4rcc;
    public bool IsInvoke => Name.StartsWith("invoke-", StringComparison.Ordinal);
    /// <summary>Field reads (iget, sget) and writes (iput, sput).</summary>
    public bool IsFieldRead => Ref == DalvikRef.Field && Name[1] == 'g';
    public bool IsFieldWrite => Ref == DalvikRef.Field && Name[1] == 'p';
}

/// <summary>The opcode table and a bounds-checked decoder (an instruction that runs past the end decodes as truncated, never throws).</summary>
public static class Dalvik
{
    public sealed record Op(string Name, DalvikFormat Format, DalvikRef Ref);

    public static readonly Op[] Ops = Build();

    private static Op[] Build()
    {
        var ops = new Op[256];
        for (int i = 0; i < 256; i++) ops[i] = new($"unused-{i:x2}", DalvikFormat.Unused, DalvikRef.None);
        void Set(int op, string name, DalvikFormat f, DalvikRef r = DalvikRef.None) => ops[op] = new(name, f, r);
        void Seq(int first, DalvikFormat f, DalvikRef r, params string[] names) { for (int i = 0; i < names.Length; i++) Set(first + i, names[i], f, r); }

        Set(0x00, "nop", DalvikFormat.F10x);
        Seq(0x01, DalvikFormat.F12x, DalvikRef.None, "move");
        Set(0x02, "move/from16", DalvikFormat.F22x); Set(0x03, "move/16", DalvikFormat.F32x);
        Set(0x04, "move-wide", DalvikFormat.F12x); Set(0x05, "move-wide/from16", DalvikFormat.F22x); Set(0x06, "move-wide/16", DalvikFormat.F32x);
        Set(0x07, "move-object", DalvikFormat.F12x); Set(0x08, "move-object/from16", DalvikFormat.F22x); Set(0x09, "move-object/16", DalvikFormat.F32x);
        Seq(0x0a, DalvikFormat.F11x, DalvikRef.None, "move-result", "move-result-wide", "move-result-object", "move-exception");
        Set(0x0e, "return-void", DalvikFormat.F10x);
        Seq(0x0f, DalvikFormat.F11x, DalvikRef.None, "return", "return-wide", "return-object");
        Set(0x12, "const/4", DalvikFormat.F11n); Set(0x13, "const/16", DalvikFormat.F21s); Set(0x14, "const", DalvikFormat.F31i); Set(0x15, "const/high16", DalvikFormat.F21h);
        Set(0x16, "const-wide/16", DalvikFormat.F21s); Set(0x17, "const-wide/32", DalvikFormat.F31i); Set(0x18, "const-wide", DalvikFormat.F51l);
        Set(0x19, "const-wide/high16", DalvikFormat.F21h);
        Set(0x1a, "const-string", DalvikFormat.F21c, DalvikRef.String); Set(0x1b, "const-string/jumbo", DalvikFormat.F31c, DalvikRef.String);
        Set(0x1c, "const-class", DalvikFormat.F21c, DalvikRef.Type);
        Set(0x1d, "monitor-enter", DalvikFormat.F11x); Set(0x1e, "monitor-exit", DalvikFormat.F11x);
        Set(0x1f, "check-cast", DalvikFormat.F21c, DalvikRef.Type); Set(0x20, "instance-of", DalvikFormat.F22c, DalvikRef.Type);
        Set(0x21, "array-length", DalvikFormat.F12x);
        Set(0x22, "new-instance", DalvikFormat.F21c, DalvikRef.Type); Set(0x23, "new-array", DalvikFormat.F22c, DalvikRef.Type);
        Set(0x24, "filled-new-array", DalvikFormat.F35c, DalvikRef.Type); Set(0x25, "filled-new-array/range", DalvikFormat.F3rc, DalvikRef.Type);
        Set(0x26, "fill-array-data", DalvikFormat.F31t);
        Set(0x27, "throw", DalvikFormat.F11x);
        Set(0x28, "goto", DalvikFormat.F10t); Set(0x29, "goto/16", DalvikFormat.F20t); Set(0x2a, "goto/32", DalvikFormat.F30t);
        Set(0x2b, "packed-switch", DalvikFormat.F31t); Set(0x2c, "sparse-switch", DalvikFormat.F31t);
        Seq(0x2d, DalvikFormat.F23x, DalvikRef.None, "cmpl-float", "cmpg-float", "cmpl-double", "cmpg-double", "cmp-long");
        Seq(0x32, DalvikFormat.F22t, DalvikRef.None, "if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le");
        Seq(0x38, DalvikFormat.F21t, DalvikRef.None, "if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez");
        string[] kinds = ["", "-wide", "-object", "-boolean", "-byte", "-char", "-short"];
        Seq(0x44, DalvikFormat.F23x, DalvikRef.None, [.. kinds.Select(k => "aget" + k), .. kinds.Select(k => "aput" + k)]);
        Seq(0x52, DalvikFormat.F22c, DalvikRef.Field, [.. kinds.Select(k => "iget" + k), .. kinds.Select(k => "iput" + k)]);
        Seq(0x60, DalvikFormat.F21c, DalvikRef.Field, [.. kinds.Select(k => "sget" + k), .. kinds.Select(k => "sput" + k)]);
        string[] invokes = ["invoke-virtual", "invoke-super", "invoke-direct", "invoke-static", "invoke-interface"];
        Seq(0x6e, DalvikFormat.F35c, DalvikRef.Method, invokes);
        Seq(0x74, DalvikFormat.F3rc, DalvikRef.Method, [.. invokes.Select(i => i + "/range")]);
        Seq(0x7b, DalvikFormat.F12x, DalvikRef.None, "neg-int", "not-int", "neg-long", "not-long", "neg-float", "neg-double", "int-to-long", "int-to-float",
            "int-to-double", "long-to-int", "long-to-float", "long-to-double", "float-to-int", "float-to-long", "float-to-double", "double-to-int",
            "double-to-long", "double-to-float", "int-to-byte", "int-to-char", "int-to-short");
        string[] binops =
        [
            "add-int", "sub-int", "mul-int", "div-int", "rem-int", "and-int", "or-int", "xor-int", "shl-int", "shr-int", "ushr-int",
            "add-long", "sub-long", "mul-long", "div-long", "rem-long", "and-long", "or-long", "xor-long", "shl-long", "shr-long", "ushr-long",
            "add-float", "sub-float", "mul-float", "div-float", "rem-float", "add-double", "sub-double", "mul-double", "div-double", "rem-double",
        ];
        Seq(0x90, DalvikFormat.F23x, DalvikRef.None, binops);
        Seq(0xb0, DalvikFormat.F12x, DalvikRef.None, [.. binops.Select(b => b + "/2addr")]);
        Seq(0xd0, DalvikFormat.F22s, DalvikRef.None, "add-int/lit16", "rsub-int", "mul-int/lit16", "div-int/lit16", "rem-int/lit16", "and-int/lit16", "or-int/lit16", "xor-int/lit16");
        Seq(0xd8, DalvikFormat.F22b, DalvikRef.None, "add-int/lit8", "rsub-int/lit8", "mul-int/lit8", "div-int/lit8", "rem-int/lit8", "and-int/lit8", "or-int/lit8",
            "xor-int/lit8", "shl-int/lit8", "shr-int/lit8", "ushr-int/lit8");
        Set(0xfa, "invoke-polymorphic", DalvikFormat.F45cc, DalvikRef.Method); Set(0xfb, "invoke-polymorphic/range", DalvikFormat.F4rcc, DalvikRef.Method);
        Set(0xfc, "invoke-custom", DalvikFormat.F35c, DalvikRef.CallSite); Set(0xfd, "invoke-custom/range", DalvikFormat.F3rc, DalvikRef.CallSite);
        Set(0xfe, "const-method-handle", DalvikFormat.F21c, DalvikRef.MethodHandle); Set(0xff, "const-method-type", DalvikFormat.F21c, DalvikRef.Proto);
        return ops;
    }

    /// <summary>Code units per format (payloads are sized from their header).</summary>
    public static int Units(DalvikFormat f) => f switch
    {
        DalvikFormat.F10x or DalvikFormat.F12x or DalvikFormat.F11n or DalvikFormat.F11x or DalvikFormat.F10t or DalvikFormat.Unused => 1,
        DalvikFormat.F20t or DalvikFormat.F22x or DalvikFormat.F21t or DalvikFormat.F21s or DalvikFormat.F21h or DalvikFormat.F21c or DalvikFormat.F23x
            or DalvikFormat.F22b or DalvikFormat.F22t or DalvikFormat.F22s or DalvikFormat.F22c => 2,
        DalvikFormat.F30t or DalvikFormat.F32x or DalvikFormat.F31i or DalvikFormat.F31t or DalvikFormat.F31c or DalvikFormat.F35c or DalvikFormat.F3rc => 3,
        DalvikFormat.F45cc or DalvikFormat.F4rcc => 4,
        DalvikFormat.F51l => 5,
        _ => 1,
    };

    /// <summary>Decodes the instructions of <paramref name="code"/> in order; a truncated last instruction ends the list.</summary>
    public static List<DalvikInstruction> Decode(ushort[] code, int maxInstructions = 1_000_000)
    {
        var list = new List<DalvikInstruction>();
        for (int at = 0; at < code.Length && list.Count < maxInstructions;)
        {
            var i = DecodeOne(code, at);
            if (i == null) break;
            list.Add(i);
            at += i.Length;
        }
        return list;
    }

    /// <summary>The instruction at <paramref name="at"/>, or null when it does not fit.</summary>
    public static DalvikInstruction? DecodeOne(ushort[] code, int at)
    {
        ushort u0 = code[at];
        int op = u0 & 0xFF, hi = u0 >> 8;
        if (op == 0 && hi is 1 or 2 or 3) return Payload(code, at, hi);
        var o = Ops[op];
        int units = Units(o.Format);
        if (at + units > code.Length) return null;
        ushort U(int k) => code[at + k];
        int a = 0, b = 0, c = 0, index = 0, index2 = 0, target = 0;
        long lit = 0;
        IReadOnlyList<int> args = [];
        switch (o.Format)
        {
            case DalvikFormat.F12x: a = hi & 0xF; b = hi >> 4; break;
            case DalvikFormat.F11n: a = hi & 0xF; lit = (sbyte)(hi & 0xF0) >> 4; break;
            case DalvikFormat.F11x: a = hi; break;
            case DalvikFormat.F10t: target = at + (sbyte)hi; break;
            case DalvikFormat.F20t: target = at + (short)U(1); break;
            case DalvikFormat.F22x: a = hi; b = U(1); break;
            case DalvikFormat.F21t: a = hi; target = at + (short)U(1); break;
            case DalvikFormat.F21s: a = hi; lit = (short)U(1); break;
            case DalvikFormat.F21h: a = hi; lit = op == 0x15 ? (long)(int)((uint)U(1) << 16) : (long)((ulong)U(1) << 48); break;
            case DalvikFormat.F21c: a = hi; index = U(1); break;
            case DalvikFormat.F23x: a = hi; b = U(1) & 0xFF; c = U(1) >> 8; break;
            case DalvikFormat.F22b: a = hi; b = U(1) & 0xFF; lit = (sbyte)(U(1) >> 8); break;
            case DalvikFormat.F22t: a = hi & 0xF; b = hi >> 4; target = at + (short)U(1); break;
            case DalvikFormat.F22s: a = hi & 0xF; b = hi >> 4; lit = (short)U(1); break;
            case DalvikFormat.F22c: a = hi & 0xF; b = hi >> 4; index = U(1); break;
            case DalvikFormat.F30t: target = at + (int)(U(1) | (uint)U(2) << 16); break;
            case DalvikFormat.F32x: a = U(1); b = U(2); break;
            case DalvikFormat.F31i: a = hi; lit = (int)(U(1) | (uint)U(2) << 16); break;
            case DalvikFormat.F31t: a = hi; target = at + (int)(U(1) | (uint)U(2) << 16); break;
            case DalvikFormat.F31c: a = hi; index = (int)(U(1) | (uint)U(2) << 16); break;
            case DalvikFormat.F35c or DalvikFormat.F45cc:
            {
                int count = hi >> 4, g = hi & 0xF;
                index = U(1);
                ushort regs = U(2);
                int[] all = [regs & 0xF, (regs >> 4) & 0xF, (regs >> 8) & 0xF, regs >> 12, g];
                args = all[..Math.Min(count, 5)];
                a = count;
                if (o.Format == DalvikFormat.F45cc) index2 = U(3);
                break;
            }
            case DalvikFormat.F3rc or DalvikFormat.F4rcc:
            {
                a = hi;
                index = U(1);
                int first = U(2);
                args = Enumerable.Range(first, hi).ToArray();
                if (o.Format == DalvikFormat.F4rcc) index2 = U(3);
                break;
            }
            case DalvikFormat.F51l: a = hi; lit = (long)(U(1) | (ulong)U(2) << 16 | (ulong)U(3) << 32 | (ulong)U(4) << 48); break;
        }
        return new DalvikInstruction(at, op, o.Name, o.Format, units, a, b, c, lit, o.Ref, index, index2, target, args);
    }

    /// <summary>A switch or array-data payload; its data stays in the code (read through <see cref="SwitchTargets"/> / <see cref="ArrayData"/>).</summary>
    private static DalvikInstruction? Payload(ushort[] code, int at, int kind)
    {
        if (at + 2 > code.Length) return null;
        long units;
        DalvikFormat f;
        if (kind == 1) { f = DalvikFormat.PackedSwitchPayload; units = 4 + code[at + 1] * 2L; }
        else if (kind == 2) { f = DalvikFormat.SparseSwitchPayload; units = 2 + code[at + 1] * 4L; }
        else
        {
            if (at + 4 > code.Length) return null;
            f = DalvikFormat.FillArrayPayload;
            long size = code[at + 2] | (long)code[at + 3] << 16;
            units = 4 + (size * code[at + 1] + 1) / 2;
        }
        if (at + units > code.Length) return null;
        var name = kind switch { 1 => "packed-switch-payload", 2 => "sparse-switch-payload", _ => "array-data-payload" };
        return new DalvikInstruction(at, 0, name, f, (int)units, 0, 0, 0, 0, DalvikRef.None, 0, 0, 0, []);
    }

    /// <summary>(key, target offset) of a switch, given the switch instruction's offset and its payload.</summary>
    public static List<(int Key, int Target)> SwitchTargets(ushort[] code, DalvikInstruction payload, int switchOffset)
    {
        var result = new List<(int, int)>();
        int at = payload.Offset, size = code[at + 1];
        int I32(int u) => (int)(code[u] | (uint)code[u + 1] << 16);
        if (payload.Format == DalvikFormat.PackedSwitchPayload)
        {
            int first = I32(at + 2);
            for (int i = 0; i < size; i++) result.Add((first + i, switchOffset + I32(at + 4 + i * 2)));
        }
        else if (payload.Format == DalvikFormat.SparseSwitchPayload)
            for (int i = 0; i < size; i++) result.Add((I32(at + 2 + i * 2), switchOffset + I32(at + 2 + size * 2 + i * 2)));
        return result;
    }

    /// <summary>The elements of an array-data payload, sign-extended from their width.</summary>
    public static List<long> ArrayData(ushort[] code, DalvikInstruction payload, out int width)
    {
        int at = payload.Offset;
        width = code[at + 1];
        long size = code[at + 2] | (long)code[at + 3] << 16;
        var bytes = System.Runtime.InteropServices.MemoryMarshal.AsBytes(code.AsSpan(at + 4, payload.Length - 4));
        var result = new List<long>();
        for (long i = 0; i < size && i < 1_000_000; i++)
        {
            long v = 0;
            for (int k = 0; k < width; k++) v |= (long)bytes[(int)(i * width + k)] << (8 * k);
            if (width is > 0 and < 8) v = v << (64 - 8 * width) >> (64 - 8 * width);
            result.Add(v);
        }
        return result;
    }
}
