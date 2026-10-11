using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Services.Simplify;
using static NetDecompilerMcp.Tests.IlLab;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// The engine contract (<see cref="SimplifyManifest"/>): every instruction on the manifest is evaluated with the runtime's
/// semantics (checked against the runtime itself, case by case), everything else stops evaluation cleanly, every fallback
/// reason can occur and is reported, and the resource limits hold on every path.
/// </summary>
public sealed class SimplifyContractTests
{
    private static Instruction I(OpCode op, object? operand = null) => new(op, operand);

    private sealed record Case(string Name, MethodDef Method, bool MayDependOnPlatform);

    private sealed class Programs
    {
        public IlLab Lab { get; } = new("Contract");
        public List<Case> Cases { get; } = new();
        private int _n;

        public void Add(string name, TypeSig ret, bool platform, IEnumerable<Instruction> code, TypeSig[]? locals = null) =>
            Cases.Add(new(name, Lab.Method($"{name}_{_n++}", ret, [], code, locals), platform));
    }

    private static Instruction[] Push(object v) => v switch
    {
        int i => [Ldc(i)],
        long l => [I(OpCodes.Ldc_I8, l)],
        float f => [I(OpCodes.Ldc_R4, f)],
        double d => [I(OpCodes.Ldc_R8, d)],
        nint n => [Ldc((int)n), I(OpCodes.Conv_I)],
        _ => throw new ArgumentException(v.GetType().Name),
    };

    private static TypeSig SigOf(ICorLibTypes t, object v) => v switch
    {
        int => t.Int32,
        long => t.Int64,
        float => t.Single,
        double => t.Double,
        nint => t.IntPtr,
        _ => throw new ArgumentException(v.GetType().Name),
    };

    /// <summary>One small method per manifest entry and operand combination.</summary>
    private static Programs Build()
    {
        var p = new Programs();
        var lab = p.Lab;
        var t = lab.T;

        // Arithmetic and bit operations on every numeric stack type.
        var intOps = new[] { OpCodes.Add, OpCodes.Sub, OpCodes.Mul, OpCodes.Div, OpCodes.Div_Un, OpCodes.Rem, OpCodes.Rem_Un, OpCodes.And, OpCodes.Or,
                             OpCodes.Xor, OpCodes.Add_Ovf, OpCodes.Add_Ovf_Un, OpCodes.Sub_Ovf, OpCodes.Sub_Ovf_Un, OpCodes.Mul_Ovf, OpCodes.Mul_Ovf_Un };
        var pairs = new List<(object A, object B)>();
        foreach (var (a, b) in new[] { (7, 3), (-7, 3), (7, -3), (int.MaxValue, 1), (int.MinValue, -1), (5, 0), (-1, -1), (0x10000, 0x10000), (-2, 3) })
        {
            pairs.Add((a, b));
            pairs.Add(((nint)a, (nint)b));
        }
        foreach (var (a, b) in new[] { (7L, 3L), (-7L, 3L), (long.MaxValue, 1L), (long.MinValue, -1L), (5L, 0L), (-1L, -1L), (1L << 32, 1L << 32), (-2L, 3L) })
            pairs.Add((a, b));
        foreach (var op in intOps)
            foreach (var (a, b) in pairs)
                p.Add(op.Name, SigOf(t, a), a is nint, [.. Push(a), .. Push(b), I(op), Ret()]);

        var floatOps = new[] { OpCodes.Add, OpCodes.Sub, OpCodes.Mul, OpCodes.Div, OpCodes.Rem };
        var floatPairs = new (object, object)[]
        {
            (1.5f, 2.25f), (16777216f, 1f), (1e38f, 10f), (0f, 0f), (-7.5f, 2f), (1f, 3f),
            (0.1, 0.2), (1e308, 10.0), (0.0, 0.0), (-7.5, 2.0), (1.0, 3.0),
        };
        foreach (var op in floatOps)
            foreach (var (a, b) in floatPairs)
                p.Add("f" + op.Name, SigOf(t, a), false, [.. Push(a), .. Push(b), I(op), Ret()]);
        // float32 arithmetic runs in single precision; mixed with float64 it widens.
        p.Add("single", t.Int32, false, [I(OpCodes.Ldc_R4, 16777216f), I(OpCodes.Ldc_R4, 1f), I(OpCodes.Add), I(OpCodes.Ldc_R8, 16777217.0), I(OpCodes.Ceq), Ret()]);
        p.Add("mixed", t.Double, false, [I(OpCodes.Ldc_R4, 0.1f), I(OpCodes.Ldc_R8, 0.0), I(OpCodes.Add), Ret()]);

        foreach (var op in new[] { OpCodes.Shl, OpCodes.Shr, OpCodes.Shr_Un })
        {
            foreach (var v in new[] { 1, -8, int.MinValue })
                foreach (var s in new[] { 0, 1, 31, 32, -1 })
                {
                    p.Add(op.Name, t.Int32, s is < 0 or > 31, [Ldc(v), Ldc(s), I(op), Ret()]);
                    p.Add(op.Name, t.IntPtr, true, [.. Push((nint)v), Ldc(s), I(op), Ret()]);
                }
            foreach (var v in new[] { 1L, -8L, long.MinValue })
                foreach (var s in new[] { 0, 1, 63, 64 })
                    p.Add(op.Name, t.Int64, s > 63, [I(OpCodes.Ldc_I8, v), Ldc(s), I(op), Ret()]);
            p.Add(op.Name, t.IntPtr, true, [.. Push((nint)1), .. Push((nint)3), I(op), Ret()]); // native int shift amount
        }

        foreach (var v in new object[] { 5, int.MinValue, 0, 5L, long.MinValue, (nint)5, (nint)int.MinValue, 1.5f, 0f, -2.5, 0.0 })
            p.Add("neg", SigOf(t, v), v is nint, [.. Push(v), I(OpCodes.Neg), Ret()]);
        foreach (var v in new object[] { 5, -1, 5L, (nint)(-6) })
            p.Add("not", SigOf(t, v), v is nint, [.. Push(v), I(OpCodes.Not), Ret()]);
        foreach (var v in new object[] { 1.5f, float.NaN, float.PositiveInfinity, 2.5, double.NegativeInfinity })
            p.Add("ckfinite", SigOf(t, v), false, [.. Push(v), I(OpCodes.Ckfinite), Ret()]);

        // Comparisons.
        var comparePairs = new (object, object)[]
        {
            (1, 2), (2, 1), (2, 2), (-1, 1), (-1L, 1L), (5L, 5L), ((nint)(-1), (nint)1), ((nint)3, (nint)3), ((nint)(-1), 1),
            (1f, float.NaN), (1f, 2f), (2f, 2f), (double.NaN, 1.0), (1.0, 2.0), (2f, 2.0),
        };
        foreach (var op in new[] { OpCodes.Ceq, OpCodes.Cgt, OpCodes.Cgt_Un, OpCodes.Clt, OpCodes.Clt_Un })
        {
            foreach (var (a, b) in comparePairs)
                p.Add(op.Name, t.Int32, false, [.. Push(a), .. Push(b), I(op), Ret()]);
            if (op.Code is Code.Ceq or Code.Cgt_Un or Code.Clt_Un) // the comparisons verifiable on references
            {
                p.Add(op.Name + "null", t.Int32, false, [I(OpCodes.Ldstr, "a"), I(OpCodes.Ldnull), I(op), Ret()]);
                p.Add(op.Name + "null", t.Int32, false, [I(OpCodes.Ldnull), I(OpCodes.Ldstr, "a"), I(op), Ret()]);
            }
        }

        // Conversions from every numeric stack type.
        var convs = new[]
        {
            OpCodes.Conv_I1, OpCodes.Conv_I2, OpCodes.Conv_I4, OpCodes.Conv_I8, OpCodes.Conv_U1, OpCodes.Conv_U2, OpCodes.Conv_U4, OpCodes.Conv_U8,
            OpCodes.Conv_I, OpCodes.Conv_U, OpCodes.Conv_R4, OpCodes.Conv_R8, OpCodes.Conv_R_Un, OpCodes.Conv_Ovf_I1, OpCodes.Conv_Ovf_I2,
            OpCodes.Conv_Ovf_I4, OpCodes.Conv_Ovf_I8, OpCodes.Conv_Ovf_U1, OpCodes.Conv_Ovf_U2, OpCodes.Conv_Ovf_U4, OpCodes.Conv_Ovf_U8,
            OpCodes.Conv_Ovf_I, OpCodes.Conv_Ovf_U, OpCodes.Conv_Ovf_I1_Un, OpCodes.Conv_Ovf_I2_Un, OpCodes.Conv_Ovf_I4_Un, OpCodes.Conv_Ovf_I8_Un,
            OpCodes.Conv_Ovf_U1_Un, OpCodes.Conv_Ovf_U2_Un, OpCodes.Conv_Ovf_U4_Un, OpCodes.Conv_Ovf_U8_Un, OpCodes.Conv_Ovf_I_Un, OpCodes.Conv_Ovf_U_Un,
        };
        var sources = new List<object> { 0, 1, -1, 127, 128, -129, 255, 256, 32767, 32768, -32769, 65535, 65536, int.MaxValue, int.MinValue,
                                         -1L, 0xFFFFFFFFL, 1L << 32, long.MaxValue, long.MinValue, 0x7FFFFFFFL,
                                         0.5, -0.5, 255.9, -128.9, 3e9, -3e9, 1e19, 1.8e19, -1e20, double.NaN, double.PositiveInfinity,
                                         0.5f, -1.5f, 3e9f, float.NaN, 1e20f, (nint)(-1), (nint)5, (nint)int.MaxValue };
        foreach (var op in convs)
        {
            var ret = op.Code switch
            {
                Code.Conv_I8 or Code.Conv_U8 or Code.Conv_Ovf_I8 or Code.Conv_Ovf_U8 or Code.Conv_Ovf_I8_Un or Code.Conv_Ovf_U8_Un => t.Int64,
                Code.Conv_I or Code.Conv_U or Code.Conv_Ovf_I or Code.Conv_Ovf_U or Code.Conv_Ovf_I_Un or Code.Conv_Ovf_U_Un => t.IntPtr,
                Code.Conv_R4 => t.Single,
                Code.Conv_R8 or Code.Conv_R_Un => t.Double,
                _ => (TypeSig)t.Int32,
            };
            foreach (var v in sources)
            {
                if (op.Code == Code.Conv_R_Un && v is float or double) continue; // unsigned integer sources only
                bool platform = v is float or double or nint || ret == t.IntPtr;
                p.Add(op.Name, ret, platform, [.. Push(v), I(op), Ret()]);
            }
        }

        // Branches, both ways.
        var branches = new[]
        {
            OpCodes.Beq, OpCodes.Beq_S, OpCodes.Bne_Un, OpCodes.Bne_Un_S, OpCodes.Bge, OpCodes.Bge_S, OpCodes.Bge_Un, OpCodes.Bge_Un_S,
            OpCodes.Bgt, OpCodes.Bgt_S, OpCodes.Bgt_Un, OpCodes.Bgt_Un_S, OpCodes.Ble, OpCodes.Ble_S, OpCodes.Ble_Un, OpCodes.Ble_Un_S,
            OpCodes.Blt, OpCodes.Blt_S, OpCodes.Blt_Un, OpCodes.Blt_Un_S,
        };
        foreach (var op in branches)
            foreach (var (a, b) in new (object, object)[] { (1, 2), (2, 1), (2, 2), (-1, 1), (1.0, double.NaN), (2.0, 1.0), (1L, 2L) })
            {
                var taken = Ldc(1);
                p.Add(op.Name, t.Int32, false, [.. Push(a), .. Push(b), I(op, taken), Ldc(0), Ret(), taken, Ret()]);
            }
        foreach (var op in new[] { OpCodes.Brtrue, OpCodes.Brtrue_S, OpCodes.Brfalse, OpCodes.Brfalse_S })
            foreach (var v in new[] { Push(0), Push(7), Push(0L), [I(OpCodes.Ldnull)], [I(OpCodes.Ldstr, "s")] })
            {
                var taken = Ldc(1);
                p.Add(op.Name, t.Int32, false, [.. v, I(op, taken), Ldc(0), Ret(), taken, Ret()]);
            }
        foreach (var index in new[] { 0, 1, 5, -1 })
        {
            Instruction l0 = Ldc(10), l1 = Ldc(11);
            p.Add("switch", t.Int32, false, [Ldc(index), I(OpCodes.Switch, new[] { l0, l1 }), Ldc(9), Ret(), l0, Ret(), l1, Ret()]);
        }
        foreach (var op in new[] { OpCodes.Br, OpCodes.Br_S })
        {
            var target = Ldc(1);
            p.Add(op.Name, t.Int32, false, [I(op, target), Ldc(0), Ret(), target, Ret()]);
        }

        // Constants and the stack.
        p.Add("consts", t.Int32, false,
        [
            I(OpCodes.Nop), I(OpCodes.Ldc_I4_M1), I(OpCodes.Ldc_I4_0), I(OpCodes.Add), I(OpCodes.Ldc_I4_1), I(OpCodes.Add), I(OpCodes.Ldc_I4_2), I(OpCodes.Add),
            I(OpCodes.Ldc_I4_3), I(OpCodes.Add), I(OpCodes.Ldc_I4_4), I(OpCodes.Add), I(OpCodes.Ldc_I4_5), I(OpCodes.Add), I(OpCodes.Ldc_I4_6), I(OpCodes.Add),
            I(OpCodes.Ldc_I4_7), I(OpCodes.Add), I(OpCodes.Ldc_I4_8), I(OpCodes.Add), I(OpCodes.Ldc_I4_S, (sbyte)-100), I(OpCodes.Add),
            I(OpCodes.Ldc_I4, 100000), I(OpCodes.Add), I(OpCodes.Dup), I(OpCodes.Pop), Ret(),
        ]);
        p.Add("ldnull", t.Int32, false, [I(OpCodes.Ldnull), I(OpCodes.Ldnull), I(OpCodes.Ceq), Ret()]);
        p.Add("ldstr", t.String, false, [I(OpCodes.Ldstr, "abc"), Ret()]);
        p.Add("ldc.i8", t.Int64, false, [I(OpCodes.Ldc_I8, 0x123456789L), Ret()]);

        // Arguments and locals in every encoding.
        var six = Enumerable.Repeat((TypeSig)t.Int32, 6).ToArray();
        var helper = lab.Method("Args6", t.Int32, six, []);
        var prm = helper.Parameters;
        foreach (var i in new[]
                 {
                     I(OpCodes.Ldarg_0), I(OpCodes.Ldarg_1), I(OpCodes.Add), I(OpCodes.Ldarg_2), I(OpCodes.Add), I(OpCodes.Ldarg_3), I(OpCodes.Add),
                     I(OpCodes.Ldarg_S, prm[4]), I(OpCodes.Add), I(OpCodes.Ldarg, prm[5]), I(OpCodes.Add), I(OpCodes.Starg_S, prm[0]),
                     I(OpCodes.Ldarg_0), Ldc(10), I(OpCodes.Mul), I(OpCodes.Starg, prm[1]),
                     I(OpCodes.Ldarga_S, prm[0]), I(OpCodes.Ldind_I4), I(OpCodes.Ldarga, prm[1]), I(OpCodes.Ldind_I4), I(OpCodes.Add), Ret(),
                 })
            helper.Body.Instructions.Add(i);
        p.Add("args", t.Int32, false, [Ldc(1), Ldc(2), Ldc(3), Ldc(4), Ldc(5), Ldc(6), I(OpCodes.Call, helper), Ret()]);
        {
            var m = lab.Method("Locals6", t.Int32, [], [], six);
            var v = m.Body.Variables;
            foreach (var i in new[]
                     {
                         Ldc(1), I(OpCodes.Stloc_0), Ldc(2), I(OpCodes.Stloc_1), Ldc(3), I(OpCodes.Stloc_2), Ldc(4), I(OpCodes.Stloc_3),
                         Ldc(5), I(OpCodes.Stloc_S, v[4]), Ldc(6), I(OpCodes.Stloc, v[5]),
                         I(OpCodes.Ldloc_0), I(OpCodes.Ldloc_1), I(OpCodes.Add), I(OpCodes.Ldloc_2), I(OpCodes.Add), I(OpCodes.Ldloc_3), I(OpCodes.Add),
                         I(OpCodes.Ldloc_S, v[4]), I(OpCodes.Add), I(OpCodes.Ldloc, v[5]), I(OpCodes.Add),
                         I(OpCodes.Ldloca_S, v[0]), I(OpCodes.Ldind_I4), I(OpCodes.Add), I(OpCodes.Ldloca, v[5]), I(OpCodes.Ldind_I4), I(OpCodes.Add), Ret(),
                     })
                m.Body.Instructions.Add(i);
            p.Cases.Add(new("locals", m, false));
        }

        // Arrays of every element kind.
        var elements = new (TypeSig Type, OpCode Store, OpCode Load, object Value, TypeSig Ret)[]
        {
            (t.SByte, OpCodes.Stelem_I1, OpCodes.Ldelem_I1, 300, t.Int32), (t.Byte, OpCodes.Stelem_I1, OpCodes.Ldelem_U1, 200, t.Int32),
            (t.Int16, OpCodes.Stelem_I2, OpCodes.Ldelem_I2, -300, t.Int32), (t.Char, OpCodes.Stelem_I2, OpCodes.Ldelem_U2, 50000, t.Int32),
            (t.Int32, OpCodes.Stelem_I4, OpCodes.Ldelem_I4, -5, t.Int32), (t.UInt32, OpCodes.Stelem_I4, OpCodes.Ldelem_U4, -5, t.Int32),
            (t.Int64, OpCodes.Stelem_I8, OpCodes.Ldelem_I8, -5L, t.Int64), (t.IntPtr, OpCodes.Stelem_I, OpCodes.Ldelem_I, (nint)7, t.IntPtr),
            (t.Single, OpCodes.Stelem_R4, OpCodes.Ldelem_R4, 0.1, t.Single), (t.Double, OpCodes.Stelem_R8, OpCodes.Ldelem_R8, 0.1, t.Double),
            (t.Boolean, OpCodes.Stelem_I1, OpCodes.Ldelem_U1, 2, t.Int32),
        };
        foreach (var e in elements)
            p.Add("array", e.Ret, false,
                [Ldc(3), I(OpCodes.Newarr, e.Type.ToTypeDefOrRef()), I(OpCodes.Dup), Ldc(1), .. Push(e.Value), I(e.Store), Ldc(1), I(e.Load), Ret()]);
        p.Add("array", t.String, false,
            [Ldc(3), I(OpCodes.Newarr, t.String.ToTypeDefOrRef()), I(OpCodes.Dup), Ldc(2), I(OpCodes.Ldstr, "e"), I(OpCodes.Stelem_Ref), Ldc(2), I(OpCodes.Ldelem_Ref), Ret()]);
        p.Add("array", t.Int32, false,
            [Ldc(3), I(OpCodes.Newarr, t.Int32.ToTypeDefOrRef()), I(OpCodes.Dup), Ldc(0), Ldc(42), I(OpCodes.Stelem, t.Int32.ToTypeDefOrRef()),
             Ldc(0), I(OpCodes.Ldelem, t.Int32.ToTypeDefOrRef()), Ret()]);
        p.Add("ldlen", t.Int32, false, [Ldc(7), I(OpCodes.Newarr, t.Int32.ToTypeDefOrRef()), I(OpCodes.Ldlen), I(OpCodes.Conv_I4), Ret()]);
        p.Add("ldelema", t.Int32, false,
            [Ldc(2), I(OpCodes.Newarr, t.Int32.ToTypeDefOrRef()), I(OpCodes.Dup), Ldc(1), I(OpCodes.Ldelema, t.Int32.ToTypeDefOrRef()), Ldc(9), I(OpCodes.Stind_I4),
             Ldc(1), I(OpCodes.Ldelem_I4), Ret()]);
        p.Add("bounds", t.Int32, false, [Ldc(3), I(OpCodes.Newarr, t.Int32.ToTypeDefOrRef()), Ldc(3), I(OpCodes.Ldelem_I4), Ret()]);
        p.Add("bounds", t.Int32, false, [I(OpCodes.Ldnull), Ldc(0), I(OpCodes.Ldelem_I4), Ret()]);
        p.Add("bounds", t.Int32, false, [Ldc(-1), I(OpCodes.Newarr, t.Int32.ToTypeDefOrRef()), I(OpCodes.Ldlen), I(OpCodes.Conv_I4), Ret()]);

        // Indirect access through local addresses.
        var indirect = new (TypeSig Type, OpCode Store, OpCode Load, object Value, TypeSig Ret)[]
        {
            (t.SByte, OpCodes.Stind_I1, OpCodes.Ldind_I1, 300, t.Int32), (t.Byte, OpCodes.Stind_I1, OpCodes.Ldind_U1, 200, t.Int32),
            (t.Int16, OpCodes.Stind_I2, OpCodes.Ldind_I2, 40000, t.Int32), (t.UInt16, OpCodes.Stind_I2, OpCodes.Ldind_U2, -1, t.Int32),
            (t.Int32, OpCodes.Stind_I4, OpCodes.Ldind_I4, -7, t.Int32), (t.UInt32, OpCodes.Stind_I4, OpCodes.Ldind_U4, -7, t.Int32),
            (t.Int64, OpCodes.Stind_I8, OpCodes.Ldind_I8, 1L << 40, t.Int64), (t.IntPtr, OpCodes.Stind_I, OpCodes.Ldind_I, (nint)(-3), t.IntPtr),
            (t.Single, OpCodes.Stind_R4, OpCodes.Ldind_R4, 0.1, t.Single), (t.Double, OpCodes.Stind_R8, OpCodes.Ldind_R8, 0.1, t.Double),
        };
        foreach (var e in indirect)
        {
            var m = lab.Method($"Ind_{p.Cases.Count}", e.Ret, [], [], [e.Type]);
            foreach (var i in new[] { I(OpCodes.Ldloca_S, m.Body.Variables[0]) }.Concat(Push(e.Value)).Concat(
                         [I(e.Store), I(OpCodes.Ldloca_S, m.Body.Variables[0]), I(e.Load), Ret()]))
                m.Body.Instructions.Add(i);
            p.Cases.Add(new("indirect", m, false));
        }
        {
            var m = lab.Method("IndRef", t.String, [], [], [t.String]);
            foreach (var i in new[] { I(OpCodes.Ldloca_S, m.Body.Variables[0]), I(OpCodes.Ldstr, "r"), I(OpCodes.Stind_Ref),
                                      I(OpCodes.Ldloca_S, m.Body.Variables[0]), I(OpCodes.Ldind_Ref), Ret() })
                m.Body.Instructions.Add(i);
            p.Cases.Add(new("indirect", m, false));
        }

        // Prefixes.
        var answer = lab.Method("Answer", t.Int32, Ldc(42), Ret());
        p.Add("tail", t.Int32, false, [I(OpCodes.Tailcall), I(OpCodes.Call, answer), Ret()]);
        {
            var m = lab.Method("Unaligned", t.Int32, [], [], [t.Int32]);
            foreach (var i in new[] { I(OpCodes.Ldloca_S, m.Body.Variables[0]), Ldc(5), I(OpCodes.Unaligned, (byte)1), I(OpCodes.Stind_I4),
                                      I(OpCodes.Ldloca_S, m.Body.Variables[0]), I(OpCodes.Volatile), I(OpCodes.Ldind_I4), Ret() })
                m.Body.Instructions.Add(i);
            p.Cases.Add(new("prefix", m, false));
        }

        // Static state: readonly fields set by a static constructor (an RVA blob through ldtoken + InitializeArray).
        var data = lab.NewType("Lab", "Data", abstractSealed: true, beforeFieldInit: false);
        var num = lab.StaticField(data, "Num", t.Int32, readOnly: true);
        var arr = lab.StaticField(data, "Arr", new SZArraySig(t.Int32), readOnly: true);
        var name = lab.StaticField(data, "Name", t.String, readOnly: true);
        var blobType = new TypeDefUser("", "Blob12", t.GetTypeRef("System", "ValueType"))
        {
            Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed | TypeAttributes.ExplicitLayout,
            ClassLayout = new ClassLayoutUser(1, 12),
        };
        lab.Module.Types.Add(blobType);
        var blob = new FieldDefUser("Bytes", new FieldSig(new ValueTypeSig(blobType)),
            FieldAttributes.Assembly | FieldAttributes.Static | FieldAttributes.InitOnly | FieldAttributes.HasFieldRVA)
        {
            InitialValue = [1, 0, 0, 0, 2, 0, 0, 0, 30, 0, 0, 0],
        };
        data.Fields.Add(blob);
        var initArray = lab.Module.Import(typeof(System.Runtime.CompilerServices.RuntimeHelpers).GetMethod("InitializeArray"));
        lab.StaticConstructor(data,
            Ldc(41), I(OpCodes.Stsfld, num),
            Ldc(3), I(OpCodes.Newarr, t.Int32.ToTypeDefOrRef()), I(OpCodes.Dup), I(OpCodes.Ldtoken, blob), I(OpCodes.Call, initArray), I(OpCodes.Stsfld, arr),
            I(OpCodes.Ldstr, "data"), I(OpCodes.Stsfld, name), Ret());
        p.Add("static", t.Int32, false, [I(OpCodes.Volatile), I(OpCodes.Ldsfld, num), I(OpCodes.Ldsfld, arr), Ldc(2), I(OpCodes.Ldelem_I4), I(OpCodes.Add), Ret()]);
        p.Add("static", t.String, false, [I(OpCodes.Ldsfld, name), Ret()]);
        p.Add("readonly", t.Int32, false,
            [I(OpCodes.Ldsfld, arr), Ldc(1), I(OpCodes.Readonly), I(OpCodes.Ldelema, t.Int32.ToTypeDefOrRef()), I(OpCodes.Ldind_I4), Ret()]);
        p.Add("ldsflda", t.Int32, false, [I(OpCodes.Ldsflda, num), I(OpCodes.Ldind_I4), Ret()]);
        p.Add("IntPtr.Zero", t.Int32, false, [I(OpCodes.Ldsfld, lab.Module.Import(typeof(IntPtr).GetField("Zero"))), I(OpCodes.Conv_I4), Ret()]);
        var toInt32 = lab.Module.Import(typeof(Convert).GetMethod(nameof(Convert.ToInt32), [typeof(string)]));
        p.Add("ToInt32", t.Int32, false, [I(OpCodes.Ldstr, "0042"), I(OpCodes.Call, toInt32), Ret()]);
        p.Add("ToInt32", t.Int32, false, [I(OpCodes.Ldnull), I(OpCodes.Call, toInt32), Ret()]);
        p.Add("ToInt32", t.Int32, false, [I(OpCodes.Ldstr, "99999999999"), I(OpCodes.Call, toInt32), Ret()]);
        p.Add("ToInt32", t.Int32, true, [I(OpCodes.Ldstr, "-5"), I(OpCodes.Call, toInt32), Ret()]);
        IMethod Conv(string name, Type from) => lab.Module.Import(typeof(System.Convert).GetMethod(name, [from]));
        p.Add("ToInt32", t.Int32, false, [I(OpCodes.Ldc_I8, -7L), I(OpCodes.Call, Conv("ToInt32", typeof(long))), Ret()]);
        p.Add("ToInt32", t.Int32, false, [I(OpCodes.Ldc_I8, 1L << 40), I(OpCodes.Call, Conv("ToInt32", typeof(long))), Ret()]);
        p.Add("ToInt32", t.Int32, false, [Ldc(-1), I(OpCodes.Call, Conv("ToInt32", typeof(uint))), Ret()]);
        p.Add("ToInt32", t.Int32, false, [Ldc(200), I(OpCodes.Call, Conv("ToInt32", typeof(byte))), Ret()]);
        p.Add("ToInt32", t.Int32, false, [Ldc(-3), I(OpCodes.Call, Conv("ToInt32", typeof(short))), Ret()]);
        p.Add("ToInt32", t.Int32, false, [Ldc(0x263A), I(OpCodes.Call, Conv("ToInt32", typeof(char))), Ret()]);
        p.Add("ToInt64", t.Int64, false, [Ldc(-9), I(OpCodes.Call, Conv("ToInt64", typeof(int))), Ret()]);
        p.Add("ToByte", t.Int32, false, [Ldc(255), I(OpCodes.Call, Conv("ToByte", typeof(int))), Ret()]);
        p.Add("ToByte", t.Int32, false, [Ldc(256), I(OpCodes.Call, Conv("ToByte", typeof(int))), Ret()]);
        p.Add("ToChar", t.Int32, false, [Ldc(-1), I(OpCodes.Call, Conv("ToChar", typeof(int))), Ret()]);
        {
            // constrained. int32 callvirt Object::ToString on a local's address.
            var m = lab.Method("Constrained", t.String, [], [], [t.Int32]);
            foreach (var i in new[]
                     {
                         Ldc(42), I(OpCodes.Stloc_0), I(OpCodes.Ldloca_S, m.Body.Variables[0]), I(OpCodes.Constrained, t.Int32.ToTypeDefOrRef()),
                         I(OpCodes.Callvirt, lab.Module.Import(typeof(object).GetMethod(nameof(ToString)))), Ret(),
                     })
                m.Body.Instructions.Add(i);
            p.Cases.Add(new("constrained", m, false));
        }

        // Stack memory: an int and a byte written and read back through pointers that moved.
        var pointer = new PtrSig(t.Void);
        p.Add("localloc", t.Int32, false,
        [
            Ldc(16), I(OpCodes.Localloc), I(OpCodes.Stloc_0),
            I(OpCodes.Ldloc_0), Ldc(4), I(OpCodes.Add), Ldc(77), I(OpCodes.Stind_I4),
            I(OpCodes.Ldloc_0), Ldc(9), I(OpCodes.Add), Ldc(-3), I(OpCodes.Stind_I1),
            I(OpCodes.Ldloc_0), Ldc(4), I(OpCodes.Add), I(OpCodes.Ldind_I4),
            I(OpCodes.Ldloc_0), Ldc(9), I(OpCodes.Add), I(OpCodes.Ldind_U1), I(OpCodes.Add),
            I(OpCodes.Ldloc_0), Ldc(12), I(OpCodes.Add), I(OpCodes.Ldind_I4), I(OpCodes.Add), Ret(),
        ], [pointer]);

        // Exception regions: try { x++ } finally { x *= 10 }, left by leave; nothing throws.
        {
            Instruction tryStart = I(OpCodes.Ldloc_0), handler = I(OpCodes.Ldloc_0), end = I(OpCodes.Ldloc_0);
            var m = lab.Method("Finally", t.Int32, [],
            [
                Ldc(4), I(OpCodes.Stloc_0),
                tryStart, Ldc(1), I(OpCodes.Add), I(OpCodes.Stloc_0), I(OpCodes.Leave_S, end),
                handler, Ldc(10), I(OpCodes.Mul), I(OpCodes.Stloc_0), I(OpCodes.Endfinally),
                end, Ret(),
            ], [t.Int32], handlers: [new ExceptionHandler(ExceptionHandlerType.Finally) { TryStart = tryStart, TryEnd = handler, HandlerStart = handler, HandlerEnd = end }]);
            p.Cases.Add(new("finally", m, false));
        }
        // Nested: try { try { x = 3 } finally { x += 4 } } finally { x *= 5 }, both left by one leave; inner finally first.
        {
            Instruction outerTry = I(OpCodes.Nop), innerTry = Ldc(3), innerHandler = I(OpCodes.Ldloc_0), outerHandler = I(OpCodes.Ldloc_0), end = I(OpCodes.Ldloc_0);
            var m = lab.Method("NestedFinally", t.Int32, [],
            [
                outerTry, innerTry, I(OpCodes.Stloc_0), I(OpCodes.Leave, end),
                innerHandler, Ldc(4), I(OpCodes.Add), I(OpCodes.Stloc_0), I(OpCodes.Endfinally),
                outerHandler, Ldc(5), I(OpCodes.Mul), I(OpCodes.Stloc_0), I(OpCodes.Endfinally),
                end, Ret(),
            ], [t.Int32], handlers:
            [
                new ExceptionHandler(ExceptionHandlerType.Finally) { TryStart = innerTry, TryEnd = innerHandler, HandlerStart = innerHandler, HandlerEnd = outerHandler },
                new ExceptionHandler(ExceptionHandlerType.Finally) { TryStart = outerTry, TryEnd = outerHandler, HandlerStart = outerHandler, HandlerEnd = end },
            ]);
            p.Cases.Add(new("nested finally", m, false));
        }

        // Delegates: ldftn, the delegate constructor and Invoke.
        {
            var twice = lab.Method("TwiceTarget", t.Int32, [t.Int32], [I(OpCodes.Ldarg_0), Ldc(2), I(OpCodes.Mul), Ret()]);
            var func = typeof(Func<int, int>);
            p.Add("delegate", t.Int32, false,
            [
                I(OpCodes.Ldnull), I(OpCodes.Ldftn, twice), I(OpCodes.Newobj, lab.Module.Import(func.GetConstructors()[0])),
                Ldc(21), I(OpCodes.Callvirt, lab.Module.Import(func.GetMethod("Invoke"))), Ret(),
            ]);
        }

        // Value types: a struct of the module, nested structs, constructors and instance methods.
        var pt = lab.NewStruct("Pt", ("X", t.Int32), ("Y", t.Int64), ("Name", t.String));
        var outer = lab.NewStruct("Outer", ("Inner", new ValueTypeSig(pt)), ("Z", t.Int32));
        var ptSig = new ValueTypeSig(pt);
        var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(t.Void, t.Int32), MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName);
        pt.Methods.Add(ctor);
        ctor.Body = new CilBody();
        foreach (var i in new[] { I(OpCodes.Ldarg_0), I(OpCodes.Initobj, pt), I(OpCodes.Ldarg_0), I(OpCodes.Ldarg_1), I(OpCodes.Stfld, pt.Fields[0]), Ret() })
            ctor.Body.Instructions.Add(i);
        var sum = new MethodDefUser("Sum", MethodSig.CreateInstance(t.Int64), MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Public | MethodAttributes.HideBySig);
        pt.Methods.Add(sum);
        sum.Body = new CilBody();
        foreach (var i in new[] { I(OpCodes.Ldarg_0), I(OpCodes.Ldfld, pt.Fields[0]), I(OpCodes.Conv_I8), I(OpCodes.Ldarg_0), I(OpCodes.Ldfld, pt.Fields[1]), I(OpCodes.Add), Ret() })
            sum.Body.Instructions.Add(i);
        {
            var m = lab.Method("StructCopy", t.Int32, [], [], [ptSig, ptSig]);
            var (s, c) = (m.Body.Variables[0], m.Body.Variables[1]);
            foreach (var i in new[]
                     {
                         I(OpCodes.Ldloca_S, s), I(OpCodes.Initobj, pt), I(OpCodes.Ldloca_S, s), Ldc(5), I(OpCodes.Stfld, pt.Fields[0]),
                         I(OpCodes.Ldloca_S, s), I(OpCodes.Ldc_I8, 7L), I(OpCodes.Stfld, pt.Fields[1]),
                         I(OpCodes.Ldloc_0), I(OpCodes.Stloc_1), I(OpCodes.Ldloca_S, c), Ldc(100), I(OpCodes.Stfld, pt.Fields[0]),
                         I(OpCodes.Ldloca_S, s), I(OpCodes.Call, sum), I(OpCodes.Conv_I4), I(OpCodes.Ldloc_1), I(OpCodes.Ldfld, pt.Fields[0]), I(OpCodes.Add), Ret(),
                     })
                m.Body.Instructions.Add(i);
            p.Cases.Add(new("struct", m, false));
        }
        {
            var m = lab.Method("StructObj", t.Int32, [], [], [ptSig, ptSig]);
            var (s, c) = (m.Body.Variables[0], m.Body.Variables[1]);
            foreach (var i in new[]
                     {
                         I(OpCodes.Ldloca_S, s), Ldc(3), I(OpCodes.Call, ctor), I(OpCodes.Ldloca_S, c), I(OpCodes.Ldloca_S, s), I(OpCodes.Ldobj, pt),
                         I(OpCodes.Stobj, pt), I(OpCodes.Ldloca_S, c), I(OpCodes.Ldflda, pt.Fields[0]), I(OpCodes.Ldind_I4), Ret(),
                     })
                m.Body.Instructions.Add(i);
            p.Cases.Add(new("struct", m, false));
        }
        p.Add("struct", t.Int32, false, [Ldc(9), I(OpCodes.Newobj, ctor), I(OpCodes.Ldfld, pt.Fields[0]), Ret()]);
        {
            var m = lab.Method("StructNested", t.Int32, [], [], [new ValueTypeSig(outer)]);
            var o = m.Body.Variables[0];
            foreach (var i in new[]
                     {
                         I(OpCodes.Ldloca_S, o), I(OpCodes.Ldflda, outer.Fields[0]), Ldc(4), I(OpCodes.Stfld, pt.Fields[0]),
                         I(OpCodes.Ldloc_0), I(OpCodes.Ldfld, outer.Fields[0]), I(OpCodes.Ldfld, pt.Fields[0]), Ret(),
                     })
                m.Body.Instructions.Add(i);
            p.Cases.Add(new("struct", m, false));
        }

        // Type tests.
        p.Add("isinst", t.Int32, false, [I(OpCodes.Ldstr, "s"), I(OpCodes.Isinst, t.String.ToTypeDefOrRef()), I(OpCodes.Ldnull), I(OpCodes.Cgt_Un), Ret()]);
        p.Add("isinst", t.Int32, false,
            [Ldc(1), I(OpCodes.Newarr, t.Int32.ToTypeDefOrRef()), I(OpCodes.Isinst, t.String.ToTypeDefOrRef()), I(OpCodes.Ldnull), I(OpCodes.Ceq), Ret()]);
        p.Add("castclass", t.Object, false, [I(OpCodes.Ldstr, "s"), I(OpCodes.Castclass, t.Object.ToTypeDefOrRef()), Ret()]);
        p.Add("castclass", t.String, false, [Ldc(1), I(OpCodes.Newarr, t.Int32.ToTypeDefOrRef()), I(OpCodes.Castclass, t.String.ToTypeDefOrRef()), Ret()]);

        // Boxing and sizes; a generic method of the module instantiated with a value type and with a class.
        var i4 = t.Int32.ToTypeDefOrRef();
        p.Add("box", t.Int32, false, [Ldc(-5), I(OpCodes.Box, i4), I(OpCodes.Unbox_Any, i4), Ret()]);
        p.Add("box", t.Int32, false, [Ldc(6), I(OpCodes.Box, i4), I(OpCodes.Unbox, i4), I(OpCodes.Ldind_I4), Ret()]);
        p.Add("box", t.Int32, false, [Ldc(6), I(OpCodes.Box, i4), I(OpCodes.Isinst, i4), I(OpCodes.Ldnull), I(OpCodes.Cgt_Un), Ret()]);
        p.Add("box", t.Int64, false, [Ldc(6), I(OpCodes.Box, i4), I(OpCodes.Unbox_Any, t.Int64.ToTypeDefOrRef()), Ret()]);
        p.Add("box", t.String, false, [I(OpCodes.Ldstr, "s"), I(OpCodes.Box, t.String.ToTypeDefOrRef()), I(OpCodes.Unbox_Any, t.String.ToTypeDefOrRef()), Ret()]);
        p.Add("sizeof", t.Int32, false, [I(OpCodes.Sizeof, t.Int64.ToTypeDefOrRef()), I(OpCodes.Sizeof, t.Char.ToTypeDefOrRef()), I(OpCodes.Add), Ret()]);
        {
            var roundTrip = new MethodDefUser("RoundTrip", MethodSig.CreateStaticGeneric(1, new GenericMVar(0), new GenericMVar(0)), MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.Static);
            roundTrip.GenericParameters.Add(new GenericParamUser(0, 0, "T"));
            lab.Type.Methods.Add(roundTrip);
            roundTrip.Body = new CilBody();
            var mvar = new TypeSpecUser(new GenericMVar(0));
            foreach (var i in new[] { Ldc(1), I(OpCodes.Newarr, mvar), I(OpCodes.Dup), Ldc(0), I(OpCodes.Ldarg_0), I(OpCodes.Box, mvar), I(OpCodes.Unbox_Any, mvar),
                                      I(OpCodes.Stelem, mvar), Ldc(0), I(OpCodes.Ldelem, mvar), Ret() })
                roundTrip.Body.Instructions.Add(i);
            p.Add("generic", t.Int32, false, [Ldc(7), I(OpCodes.Call, new MethodSpecUser(roundTrip, new GenericInstMethodSig(t.Int32))), Ret()]);
            p.Add("generic", t.String, false, [I(OpCodes.Ldstr, "g"), I(OpCodes.Call, new MethodSpecUser(roundTrip, new GenericInstMethodSig(t.String))), Ret()]);
        }

        // Calls: intrinsics through call, callvirt and newobj.
        var length = lab.Module.Import(typeof(string).GetMethod("get_Length"));
        var repeat = lab.Module.Import(typeof(string).GetConstructor([typeof(char), typeof(int)]));
        p.Add("calls", t.Int32, false, [I(OpCodes.Ldstr, "abcd"), I(OpCodes.Callvirt, length), I(OpCodes.Call, answer), I(OpCodes.Add), Ret()]);
        p.Add("calls", t.String, false, [Ldc('x'), Ldc(3), I(OpCodes.Newobj, repeat), Ret()]);
        return p;
    }

    private static bool Same(object? a, object? b) => (a, b) switch
    {
        (float x, float y) => BitConverter.SingleToInt32Bits(x) == BitConverter.SingleToInt32Bits(y) || (float.IsNaN(x) && float.IsNaN(y)),
        (double x, double y) => BitConverter.DoubleToInt64Bits(x) == BitConverter.DoubleToInt64Bits(y) || (double.IsNaN(x) && double.IsNaN(y)),
        _ => Equals(a, b),
    };

    [Fact]
    public void EveryManifestInstructionMatchesTheRuntime()
    {
        var p = Build();
        var image = p.Lab.Write();
        using var runner = new LabRunner(image);
        var evaluator = new IlEvaluator(p.Lab.Module, new EvaluationLimits());
        var failures = new List<string>();
        int folded = 0, platformCases = 0, platformBails = 0;
        foreach (var c in p.Cases)
        {
            var (expected, error) = runner.Call("Lab.P", c.Method.Name);
            object? actual = null;
            EvaluationBailout? bail = null;
            try
            {
                actual = evaluator.EvaluateSlice([I(OpCodes.Call, c.Method)]).Single();
            }
            catch (EvaluationBailout ex)
            {
                bail = ex;
            }

            if (c.MayDependOnPlatform && error == null) platformCases++;
            string Show() => $"{c.Method.Name}: {string.Join("; ", c.Method.Body.Instructions.Select(i => i.ToString()))}";
            if (bail == null)
            {
                folded++;
                if (error != null) failures.Add($"{Show()} -> evaluated to {actual ?? "null"}, the runtime throws {error.GetType().Name}");
                else if (!Same(expected, actual)) failures.Add($"{Show()} -> evaluated to {actual ?? "null"} ({actual?.GetType().Name}), the runtime returns {expected ?? "null"} ({expected?.GetType().Name})");
            }
            else if (error != null)
            {
                if (bail.Reason is not (FallbackReason.RuntimeError or FallbackReason.PlatformDependent))
                    failures.Add($"{Show()} -> the runtime throws {error.GetType().Name}, bail-out reason {bail.Describe()}");
            }
            else if (c.MayDependOnPlatform && bail.Reason == FallbackReason.PlatformDependent)
            {
                platformBails++;
            }
            else
            {
                failures.Add($"{Show()} -> bailed out ({bail.Describe()}), the runtime returns {expected ?? "null"}");
            }
        }
        Assert.True(failures.Count == 0, $"{failures.Count} of {p.Cases.Count} case(s):\n" + string.Join("\n", failures.Take(40)));
        // Platform-dependent bail-outs are allowed only for the cases marked so; most of those still evaluate.
        Assert.True(platformBails < platformCases / 2, $"{platformBails} of {platformCases} platform-sensitive cases bailed out");
        Assert.True(folded > 1500, $"only {folded} of {p.Cases.Count} cases evaluated");

        // Every manifest instruction is exercised by at least one case.
        var used = p.Lab.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody)
            .SelectMany(m => m.Body.Instructions).Select(i => i.OpCode.Code).ToHashSet();
        var missing = SimplifyManifest.SupportedInstructions.Where(c => !used.Contains(c)).ToList();
        Assert.True(missing.Count == 0, "manifest instructions without a case: " + string.Join(", ", missing));
    }

    [Fact]
    public void InstructionsOffTheManifestStopEvaluationCleanly()
    {
        var lab = new IlLab();
        var evaluator = new IlEvaluator(lab.Module, new EvaluationLimits());
        var all = typeof(OpCodes).GetFields().Select(f => f.GetValue(null)).OfType<OpCode>().Where(o => o.Code is not (Code.UNKNOWN1 or Code.UNKNOWN2)).ToList();
        Assert.True(all.Count > 200);
        foreach (var op in all.Where(o => !SimplifyManifest.SupportedInstructions.Contains(o.Code)))
        {
            var bail = Assert.Throws<EvaluationBailout>(() => evaluator.EvaluateSlice([I(op)]));
            Assert.True(bail.Reason is FallbackReason.UnsupportedInstruction or FallbackReason.ExceptionHandling or FallbackReason.UnsupportedValue,
                $"{op.Name}: {bail.Describe()}");
        }
    }

    /// <summary>One program per evaluation fallback reason.</summary>
    [Fact]
    public void EveryEvaluationFallbackReasonOccurs()
    {
        var lab = new IlLab();
        var t = lab.T;
        var cases = new List<(FallbackReason Reason, MethodDef Method, EvaluationLimits? Limits)>();
        void Add(FallbackReason r, MethodDef m, EvaluationLimits? limits = null) => cases.Add((r, m, limits));

        Add(FallbackReason.UnsupportedInstruction, lab.Method("Cpblk", t.Int32, I(OpCodes.Ldnull), I(OpCodes.Ldnull), Ldc(0), I(OpCodes.Cpblk), Ldc(0), Ret()));
        Add(FallbackReason.ExternalIo, lab.Method("Io", t.Int32, I(OpCodes.Ldstr, "x"), I(OpCodes.Call, lab.Module.Import(typeof(File).GetMethod("Exists"))), Ret()));
        Add(FallbackReason.UnsupportedCall, lab.Method("Console", t.Int32, I(OpCodes.Call, lab.Module.Import(typeof(Console).GetMethod("Read"))), Ret()));
        Add(FallbackReason.WritableStream, lab.Method("Writable", t.Int32, I(OpCodes.Newobj, lab.Module.Import(typeof(MemoryStream).GetConstructor(Type.EmptyTypes))), I(OpCodes.Pop), IlLab.Ldc(0), Ret()));
        var native = new MethodDefUser("Native", MethodSig.CreateStatic(t.Int32), MethodImplAttributes.InternalCall,
            MethodAttributes.Public | MethodAttributes.Static);
        lab.Type.Methods.Add(native);
        Add(FallbackReason.NoBody, lab.Method("CallsNative", t.Int32, I(OpCodes.Call, native), Ret()));
        // Native code of a module built in memory: no image to run it from as 32-bit x86 code.
        var x86 = new MethodDefUser("X86", MethodSig.CreateStatic(t.Int32), MethodImplAttributes.Native | MethodImplAttributes.Unmanaged,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl);
        lab.Type.Methods.Add(x86);
        Add(FallbackReason.NativeCode, lab.Method("CallsX86", t.Int32, I(OpCodes.Call, x86), Ret()));
        Add(FallbackReason.OtherModule, lab.Method("Foreign", t.Int32,
            I(OpCodes.Ldsfld, lab.Module.Import(typeof(Type).GetField(nameof(Type.EmptyTypes)))), I(OpCodes.Ldlen), I(OpCodes.Conv_I4), Ret()));
        var id = new MethodDefUser("Id", MethodSig.CreateStaticGeneric(1, new GenericMVar(0), new GenericMVar(0)), MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.Static);
        id.GenericParameters.Add(new GenericParamUser(0, 0, "T"));
        lab.Type.Methods.Add(id);
        id.Body = new CilBody();
        id.Body.Instructions.Add(I(OpCodes.Ldarg_0));
        id.Body.Instructions.Add(Ret());
        // An instantiation of the module's own static generic method is evaluated; one of another module is not.
        Add(FallbackReason.Generic, lab.Method("CallsGeneric", t.Object, I(OpCodes.Call, lab.Module.Import(typeof(Array).GetMethod(nameof(Array.Empty))!.MakeGenericMethod(typeof(int)))), Ret()));
        {
            // try { } filter { 1 } { }: exception filters are not modelled (try / catch / finally run as long as nothing throws).
            var end = Ldc(1);
            var tryStart = I(OpCodes.Nop);
            var filter = I(OpCodes.Pop);
            var handler = I(OpCodes.Pop);
            var guarded = lab.Method("Guarded", t.Int32, [],
                [tryStart, I(OpCodes.Leave, end), filter, Ldc(1), I(OpCodes.Endfilter), handler, I(OpCodes.Leave, end), end, Ret()], handlers:
                [new ExceptionHandler(ExceptionHandlerType.Filter) { TryStart = tryStart, TryEnd = filter, FilterStart = filter, HandlerStart = handler, HandlerEnd = end }]);
            Add(FallbackReason.ExceptionHandling, lab.Method("CallsGuarded", t.Int32, I(OpCodes.Call, guarded), Ret()));
            Add(FallbackReason.ExceptionHandling, lab.Method("Throws", t.Int32, I(OpCodes.Ldnull), I(OpCodes.Throw)));
        }
        // Classes: one case per path outside the modelled subset.
        MethodDef Ctor(TypeDef type)
        {
            var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(t.Void), MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName);
            type.Methods.Add(ctor);
            ctor.Body = new CilBody();
            ctor.Body.Instructions.Add(Ret());
            return ctor;
        }
        MethodDef NewOf(string name, TypeDef type) => lab.Method(name, t.Object, I(OpCodes.Newobj, Ctor(type)), Ret());
        var cls = lab.NewType("Lab", "Cls");
        cls.Fields.Add(new FieldDefUser("state", new FieldSig(t.Int32), FieldAttributes.Public)); // a delegate bound to an instance with no fields is evaluated
        var clsCtor = Ctor(cls);
        var target = lab.Method("Target", t.Int32, Ldc(1), Ret());
        var instanceTarget = new MethodDefUser("Get", MethodSig.CreateInstance(t.Int32), MethodImplAttributes.IL, MethodAttributes.Public);
        cls.Methods.Add(instanceTarget);
        instanceTarget.Body = new CilBody();
        foreach (var i in new[] { Ldc(1), Ret() }) instanceTarget.Body.Instructions.Add(i);
        var func = typeof(Func<int>);
        Add(FallbackReason.InstanceObject, lab.Method("BoundDelegate", t.Object,
            I(OpCodes.Newobj, clsCtor), I(OpCodes.Ldftn, instanceTarget), I(OpCodes.Newobj, lab.Module.Import(func.GetConstructors()[0])), Ret()));
        {
            var finalized = lab.NewType("Lab", "Finalized");
            var finalize = new MethodDefUser("Finalize", MethodSig.CreateInstance(t.Void), MethodImplAttributes.IL,
                MethodAttributes.Family | MethodAttributes.Virtual | MethodAttributes.HideBySig);
            finalized.Methods.Add(finalize);
            finalize.Body = new CilBody();
            finalize.Body.Instructions.Add(Ret());
            Add(FallbackReason.UnmodeledInstance, NewOf("NewFinalized", finalized));
            var withEvent = lab.NewType("Lab", "WithEvent");
            withEvent.Events.Add(new EventDefUser("Changed", lab.Module.Import(typeof(EventHandler))));
            Add(FallbackReason.UnmodeledInstance, NewOf("NewWithEvent", withEvent));
            var generic = lab.NewType("Lab", "Generic`1");
            generic.GenericParameters.Add(new GenericParamUser(0, 0, "T"));
            Add(FallbackReason.UnmodeledInstance, NewOf("NewGeneric", generic));
            Add(FallbackReason.UnmodeledInstance, NewOf("NewException", lab.NewType("Lab", "Failure", baseType: lab.Module.Import(typeof(Exception)))));
            var explicitLayout = lab.NewType("Lab", "Overlay");
            explicitLayout.Attributes |= TypeAttributes.ExplicitLayout;
            Add(FallbackReason.UnmodeledInstance, NewOf("NewInterop", explicitLayout));
            TypeDef deep = lab.NewType("Lab", "Level0");
            for (int level = 1; level <= 10; level++) deep = lab.NewType("Lab", "Level" + level, baseType: deep);
            Add(FallbackReason.UnmodeledInstance, NewOf("NewDeep", deep));
        }
        Add(FallbackReason.VirtualDispatch, lab.Method("FrameworkVirtual", t.String,
            I(OpCodes.Newobj, clsCtor), I(OpCodes.Callvirt, lab.Module.Import(typeof(object).GetMethod(nameof(ToString)))), Ret()));
        Add(FallbackReason.VirtualDispatch, lab.Method("PlainObject", t.Int32,
            I(OpCodes.Newobj, lab.Module.Import(typeof(object).GetConstructor(Type.EmptyTypes))), I(OpCodes.Callvirt, lab.Module.Import(typeof(object).GetMethod(nameof(GetHashCode)))), Ret()));
        Add(FallbackReason.UnsupportedValue, lab.Method("UnboxOtherSign", t.Int32, Ldc(1), I(OpCodes.Box, t.Int32.ToTypeDefOrRef()), I(OpCodes.Unbox_Any, t.UInt32.ToTypeDefOrRef()), Ret()));
        {
            // A static dictionary that escapes (a method returns it) is not a cache.
            var holder = lab.NewType("Lab", "CacheHolder", abstractSealed: true, beforeFieldInit: false);
            var dictionary = typeof(Dictionary<string, string>);
            var cache = new FieldDefUser("Cache", new FieldSig(lab.Module.Import(dictionary).ToTypeSig()), FieldAttributes.Private | FieldAttributes.Static);
            holder.Fields.Add(cache);
            lab.StaticConstructor(holder, I(OpCodes.Newobj, lab.Module.Import(dictionary.GetConstructor(Type.EmptyTypes))), I(OpCodes.Stsfld, cache), Ret());
            var escapes = lab.Method("Escapes", lab.Module.Import(dictionary).ToTypeSig(), [], [I(OpCodes.Ldsfld, cache), Ret()], owner: holder);
            Add(FallbackReason.CacheDependent, lab.Method("ReturnsCache", t.Object, I(OpCodes.Call, escapes), Ret()));
        }
        var counter = lab.StaticField(lab.Type, "Counter", t.Int32, readOnly: false);
        Add(FallbackReason.MutableStatic, lab.Method("ReadsCounter", t.Int32, I(OpCodes.Ldsfld, counter), Ret()));
        var broken = lab.NewType("Lab", "Broken", abstractSealed: true, beforeFieldInit: false);
        var brokenValue = lab.StaticField(broken, "Value", t.Int32, readOnly: true);
        lab.StaticConstructor(broken, I(OpCodes.Ldstr, "x"), I(OpCodes.Call, lab.Module.Import(typeof(File).GetMethod("Exists"))), I(OpCodes.Pop), Ret());
        Add(FallbackReason.StaticInitializer, lab.Method("ReadsBroken", t.Int32, I(OpCodes.Ldsfld, brokenValue), Ret()));
        Add(FallbackReason.RuntimeError, lab.Method("DivZero", t.Int32, Ldc(1), Ldc(0), I(OpCodes.Div), Ret()));
        Add(FallbackReason.PlatformDependent, lab.Method("Wide", t.IntPtr, I(OpCodes.Ldc_I8, 1L << 40), I(OpCodes.Conv_I), Ret()));
        Add(FallbackReason.InvalidCode, lab.Method("Mismatch", t.Int32, Ldc(1), I(OpCodes.Ldc_I8, 1L), I(OpCodes.Add), Ret()));
        var rec = lab.Method("Rec", t.Int32, []);
        rec.Body.Instructions.Add(I(OpCodes.Call, rec));
        rec.Body.Instructions.Add(Ret());
        Add(FallbackReason.CallDepth, rec, new EvaluationLimits(MaxDepth: 4));
        var spin = I(OpCodes.Nop);
        Add(FallbackReason.InstructionBudget, lab.Method("Spin", t.Int32, spin, I(OpCodes.Br, spin)), new EvaluationLimits(InstructionBudget: 1000));
        Add(FallbackReason.MemoryLimit, lab.Method("Big", t.Int32, Ldc(1_000_000), I(OpCodes.Newarr, t.Int32.ToTypeDefOrRef()), I(OpCodes.Ldlen), I(OpCodes.Conv_I4), Ret()),
            new EvaluationLimits(MemoryLimit: 1024 * 1024));

        foreach (var (reason, method, limits) in cases)
        {
            var evaluator = new IlEvaluator(lab.Module, limits ?? new EvaluationLimits());
            var bail = Assert.Throws<EvaluationBailout>(() => evaluator.EvaluateSlice([I(OpCodes.Call, method)]));
            Assert.True(bail.Reason == reason, $"{method.Name}: expected {reason}, got {bail.Describe()}");
        }

        // Every evaluation reason of the manifest is covered here (method-level reasons have their own tests).
        // Method-level reasons, and flattened-shape (a skipped rewrite), have their own tests.
        var methodLevel = new[] { FallbackReason.TimeLimit, FallbackReason.OriginalUnverifiable, FallbackReason.ResultUnverifiable, FallbackReason.Unexpected, FallbackReason.FlattenedShape };
        var uncovered = Enum.GetValues<FallbackReason>().Where(r => r <= FallbackReason.MemoryLimit).Except(cases.Select(c => c.Reason)).Except(methodLevel).ToList();
        Assert.True(uncovered.Count == 0, "reasons without a case: " + string.Join(", ", uncovered));
        Assert.All(Enum.GetValues<FallbackReason>(), r => Assert.False(string.IsNullOrEmpty(SimplifyManifest.Info(r).Description)));
    }

    [Fact]
    public void MethodLevelFallbacksLeaveTheMethodUnchanged()
    {
        var lab = new IlLab();
        var t = lab.T;
        var spinStart = I(OpCodes.Nop);
        var spin = lab.Method("SpinString", t.String, spinStart, I(OpCodes.Br, spinStart));
        var slow = lab.Method("Slow", t.String, I(OpCodes.Call, spin), Ret());
        var invalid = lab.Method("Invalid", t.Void, Ldc(1), Ret());
        var foldable = lab.Method("Foldable", t.String, I(OpCodes.Ldstr, "a"), I(OpCodes.Ldstr, "b"),
            I(OpCodes.Call, lab.Module.Import(typeof(string).GetMethod("Concat", [typeof(string), typeof(string)]))), Ret());

        var limits = new EvaluationLimits(InstructionBudget: int.MaxValue, MethodInstructionBudget: long.MaxValue, MethodTimeLimitMs: 50);
        var timed = new MethodSimplifier(lab.Module, new SimplifyOptions(Limits: limits)).Simplify(slow)!;
        Assert.Equal(FallbackReason.TimeLimit, timed.Rejected?.Reason);
        Assert.Contains("[time-limit]", timed.Rejected!.ToString());
        Assert.False(timed.Changed);

        // The other fallbacks run under the default time limit: 50 ms is not enough for them on a loaded machine.
        var simplifier = new MethodSimplifier(lab.Module, new SimplifyOptions());

        Assert.Equal(FallbackReason.OriginalUnverifiable, simplifier.Simplify(invalid)!.Rejected?.Reason);

        simplifier.AfterPasses = body => body.Instructions.RemoveAt(body.Instructions.Count - 1);
        var unverified = simplifier.Simplify(foldable)!;
        Assert.Equal(FallbackReason.ResultUnverifiable, unverified.Rejected?.Reason);
        Assert.False(unverified.Changed);

        simplifier.AfterPasses = _ => throw new InvalidOperationException("boom");
        var crashed = Assert.Single(simplifier.Run([foldable], default));
        Assert.Equal(FallbackReason.Unexpected, crashed.Rejected?.Reason);
        Assert.Contains("boom", crashed.Rejected!.Detail);

        simplifier.AfterPasses = null;
        Assert.True(simplifier.Simplify(foldable)!.Changed);
        Assert.Equal(4, foldable.Body.Instructions.Count); // the simplifier works on copies
    }

    [Fact]
    public void StaticConstructorsShareTheEvaluationBudgetAndRetryWhenItRunsOut()
    {
        var lab = new IlLab();
        var t = lab.T;
        var heavy = lab.NewType("Lab", "Heavy", abstractSealed: true, beforeFieldInit: false);
        var value = lab.StaticField(heavy, "Value", t.String, readOnly: true);
        // for (i = 0; i < 2000; i++) {}  Value = "ready";
        var cctor = lab.StaticConstructor(heavy);
        cctor.Body.Variables.Add(new Local(t.Int32));
        var check = I(OpCodes.Ldloc_0);
        var body = I(OpCodes.Ldloc_0);
        foreach (var i in new[] { I(OpCodes.Br, check), body, Ldc(1), I(OpCodes.Add), I(OpCodes.Stloc_0), check, Ldc(2000), I(OpCodes.Blt, body),
                                  I(OpCodes.Ldstr, "ready"), I(OpCodes.Stsfld, value), Ret() })
            cctor.Body.Instructions.Add(i);
        var read = lab.Method("Read", t.String, I(OpCodes.Ldsfld, value), Ret());

        var evaluator = new IlEvaluator(lab.Module, new EvaluationLimits(InstructionBudget: 50_000)) { Meter = new MethodMeter(new EvaluationLimits()) { InstructionsLeft = 500 } };
        var bail = Assert.Throws<EvaluationBailout>(() => evaluator.EvaluateSlice([I(OpCodes.Call, read)]));
        Assert.Equal(FallbackReason.InstructionBudget, bail.Reason);
        Assert.Contains("total instruction budget", bail.Message);

        evaluator.Meter = new MethodMeter(new EvaluationLimits());
        Assert.Equal("ready", evaluator.EvaluateSlice([I(OpCodes.Call, read)]).Single()); // not cached as a failure
        Assert.True(evaluator.Meter.InstructionsLeft < new EvaluationLimits().MethodInstructionBudget - 8000); // the constructor's loop was charged

        // The constructor's work counts against the per-evaluation budget as well.
        var small = new IlEvaluator(lab.Module, new EvaluationLimits(InstructionBudget: 3000));
        Assert.Equal(FallbackReason.InstructionBudget, Assert.Throws<EvaluationBailout>(() => small.EvaluateSlice([I(OpCodes.Call, read)])).Reason);
    }

    [Fact]
    public void StaticArraysModifiedElsewhereAreNotTrusted()
    {
        var lab = new IlLab();
        var t = lab.T;
        TypeDef Holder(string name, out FieldDef field)
        {
            var type = lab.NewType("Lab", name, abstractSealed: true, beforeFieldInit: false);
            field = lab.StaticField(type, "Key", new SZArraySig(t.Byte), readOnly: true);
            lab.StaticConstructor(type, Ldc(2), I(OpCodes.Newarr, t.Byte.ToTypeDefOrRef()), I(OpCodes.Dup), Ldc(0), Ldc(65), I(OpCodes.Stelem_I1),
                I(OpCodes.Dup), Ldc(1), Ldc(66), I(OpCodes.Stelem_I1), I(OpCodes.Stsfld, field), Ret());
            return type;
        }
        var getString = lab.Module.Import(typeof(System.Text.Encoding).GetMethod("GetString", [typeof(byte[])]));
        var ascii = lab.Module.Import(typeof(System.Text.Encoding).GetProperty("ASCII")!.GetMethod);
        MethodDef Decode(string name, FieldDef key, TypeDef owner) =>
            lab.Method(name, t.String, [], [I(OpCodes.Call, ascii), I(OpCodes.Ldsfld, key), I(OpCodes.Callvirt, getString), Ret()], owner: owner);

        var stable = Holder("Stable", out var stableKey);
        var stableDecode = Decode("Decode", stableKey, stable);
        // Only read elsewhere: through a helper parameter, a local and ldlen.
        var reader = lab.Method("Sum", t.Int32, [new SZArraySig(t.Byte)], [I(OpCodes.Ldarg_0), Ldc(0), I(OpCodes.Ldelem_U1), I(OpCodes.Ldarg_0), I(OpCodes.Ldlen), I(OpCodes.Conv_I4), I(OpCodes.Add), Ret()]);
        lab.Method("UsesStable", t.Int32, [], [I(OpCodes.Ldsfld, stableKey), I(OpCodes.Stloc_0), I(OpCodes.Ldloc_0), I(OpCodes.Call, reader), Ret()], [new SZArraySig(t.Byte)]);

        var mutated = Holder("Mutated", out var mutatedKey);
        var mutatedDecode = Decode("Decode", mutatedKey, mutated);
        var poke = lab.Method("Poke", t.Int32, [new SZArraySig(t.Byte)], [I(OpCodes.Ldarg_0), Ldc(0), Ldc(90), I(OpCodes.Stelem_I1), Ldc(0), Ret()]);
        lab.Method("Modify", t.Int32, [], [I(OpCodes.Ldsfld, mutatedKey), I(OpCodes.Call, poke), Ret()]);

        var evaluator = new IlEvaluator(lab.Module, new EvaluationLimits());
        Assert.Equal("AB", evaluator.EvaluateSlice([I(OpCodes.Call, stableDecode)]).Single());
        var bail = Assert.Throws<EvaluationBailout>(() => evaluator.EvaluateSlice([I(OpCodes.Call, mutatedDecode)]));
        Assert.Equal(FallbackReason.MutableStatic, bail.Reason);
        Assert.Contains("may be modified by other code", bail.Message);
    }

    [Fact]
    public void CodeThatRunsDuringAStaticConstructorDoesNotUseItsFinalState()
    {
        // Init.cctor: Prefix = Make(); Suffix = "!"   Make() reads Suffix (still null when the constructor calls it).
        var lab = new IlLab();
        var t = lab.T;
        var init = lab.NewType("Lab", "Init", abstractSealed: true, beforeFieldInit: false);
        var prefix = lab.StaticField(init, "Prefix", t.String, readOnly: true);
        var suffix = lab.StaticField(init, "Suffix", t.String, readOnly: true);
        var concat = lab.Module.Import(typeof(string).GetMethod("Concat", [typeof(string), typeof(string)]));
        var make = lab.Method("Make", t.String, [], [I(OpCodes.Ldstr, "p"), I(OpCodes.Ldsfld, suffix), I(OpCodes.Call, concat), Ret()], owner: init);
        lab.StaticConstructor(init, I(OpCodes.Call, make), I(OpCodes.Stsfld, prefix), I(OpCodes.Ldstr, "!"), I(OpCodes.Stsfld, suffix), Ret());
        var outside = lab.Method("Outside", t.String, I(OpCodes.Call, make), Ret());

        var simplifier = new MethodSimplifier(lab.Module, new SimplifyOptions());
        var inMake = simplifier.Simplify(make)!;
        Assert.False(inMake.Changed); // Make's own slice reads Suffix, which is partial while the constructor runs Make
        var outsideChange = simplifier.Simplify(outside)!;
        Assert.True(outsideChange.Changed);
        Assert.Equal("p!", outsideChange.NewBody!.Instructions[0].Operand);

        using var runner = new LabRunner(lab.Write());
        Assert.Equal("p!", runner.Call("Lab.P", "Outside").Value);
    }

    [Fact]
    public void ManifestDocumentIsCurrent()
    {
        var root = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(root, "NetDecompilerMcp.slnx"))) root = Path.GetDirectoryName(root) ?? throw new InvalidOperationException("repository root not found");
        var path = Path.Combine(root, "docs", "simplify.md");
        var expected = SimplifyManifest.Markdown().ReplaceLineEndings("\n");
        if (Environment.GetEnvironmentVariable("NDM_UPDATE_DOCS") == "1")
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, expected);
        }
        Assert.True(File.Exists(path) && File.ReadAllText(path).ReplaceLineEndings("\n") == expected,
            "docs/simplify.md is out of date: run the tests once with NDM_UPDATE_DOCS=1");
    }
}
