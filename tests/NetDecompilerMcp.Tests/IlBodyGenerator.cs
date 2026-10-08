using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Generates a module of random but valid IL methods from a seed, for fuzzing simplify_methods. Bodies come from a
/// structured grammar, so they are type-correct for the JIT, not only stack-balanced: typed expressions (int32, int64,
/// float64, string, a struct), nested statements (if / else, bounded loops, switches, flattened switch dispatchers in
/// clean and unclean forms, try / catch / finally / fault / filter, throws, early returns through leave, dead blocks,
/// constant and opaque conditions), many locals and value-type operations (ldloca, ldfld, stfld, ldflda, stind,
/// initobj, ldobj, stobj, box). Every method terminates (loops are bounded, dispatchers only move forward, nothing
/// recurses) and is <c>static int Mi(int, long, string)</c>, so the original and the simplified image can be run and
/// compared. The same seed always gives the same module.
/// </summary>
internal sealed class IlBodyGenerator
{
    public const string TypeName = "Lab.P";

    private enum VT { I4, I8, R8, Str, Struct }

    private sealed class Label
    {
        public Instruction? Target;
    }

    private readonly Random _r;
    private readonly IlLab _lab;
    private readonly ICorLibTypes _t;
    private readonly TypeDef _struct;
    private readonly FieldDef _fieldA, _fieldB;
    private readonly MethodDef _add, _addW, _twice, _opaque, _decrypt;
    private readonly FieldDef _twiceField, _addField, _decryptField; // static readonly delegates of Twice, Add and Decrypt
    private readonly IMethod _invoke1, _invoke2, _invokeString;
    private readonly IMethod _concat, _length, _upper, _toString, _invalidOpCtor;
    private readonly ITypeDefOrRef[] _catchTypes;

    // Per method.
    private List<Instruction> _code = new();
    private List<ExceptionHandler> _handlers = new();
    private List<(ExceptionHandler Handler, Label TryStart, Label HandlerStart, Label HandlerEnd, Label? Filter)> _regions = new();
    private List<Label> _pending = new();
    private List<Local> _locals = new();
    private Dictionary<VT, List<Local>> _pool = new();
    private Local _result = null!;
    private Label _ret = null!;
    private MethodDef _method = null!;
    private int _budget;
    private int _maxDepth;
    private int _topStatements;

    public IlBodyGenerator(int seed)
    {
        _r = new Random(seed);
        _lab = new IlLab("Fuzz" + seed);
        _t = _lab.T;
        var module = _lab.Module;
        _struct = _lab.NewStruct("S", ("A", _t.Int32), ("B", _t.Int64));
        _fieldA = _struct.Fields[0];
        _fieldB = _struct.Fields[1];

        static Instruction I(OpCode op, object? operand = null) => operand == null ? op.ToInstruction() : new Instruction(op, operand);
        _add = _lab.Method("Add", _t.Int32, [_t.Int32, _t.Int32], [I(OpCodes.Ldarg_0), I(OpCodes.Ldarg_1), I(OpCodes.Add), I(OpCodes.Ret)]);
        _addW = _lab.Method("AddW", _t.Int32, [_t.Int32, _t.Int32], [I(OpCodes.Ldarg_0), I(OpCodes.Ldarg_1), I(OpCodes.Call, _add), I(OpCodes.Ret)]);
        _twice = _lab.Method("Twice", _t.Int32, [_t.Int32], [I(OpCodes.Ldarg_0), IlLab.Ldc(2), I(OpCodes.Mul), I(OpCodes.Ret)]);
        _opaque = _lab.Method("Opaque", _t.Int32, IlLab.Ldc(6), IlLab.Ldc(7), I(OpCodes.Mul), I(OpCodes.Ret));

        // Decrypt(key): new string of 4 chars 'a' + ((key + i) & 15), built in a loop over a char array.
        var charArray = new SZArraySig(_t.Char);
        var stringCtor = module.Import(typeof(string).GetConstructor([typeof(char[])]));
        var body = I(OpCodes.Ldloc_0);
        var cond = I(OpCodes.Ldloc_1);
        _decrypt = _lab.Method("Decrypt", _t.String, [_t.Int32],
        [
            IlLab.Ldc(4), I(OpCodes.Newarr, _t.Char.ToTypeDefOrRef()), I(OpCodes.Stloc_0), IlLab.Ldc(0), I(OpCodes.Stloc_1), I(OpCodes.Br, cond),
            body, I(OpCodes.Ldloc_1), IlLab.Ldc('a'), I(OpCodes.Ldarg_0), I(OpCodes.Ldloc_1), I(OpCodes.Add), IlLab.Ldc(15), I(OpCodes.And),
            I(OpCodes.Add), I(OpCodes.Conv_U2), I(OpCodes.Stelem_I2),
            I(OpCodes.Ldloc_1), IlLab.Ldc(1), I(OpCodes.Add), I(OpCodes.Stloc_1),
            cond, IlLab.Ldc(4), I(OpCodes.Blt, body),
            I(OpCodes.Ldloc_0), I(OpCodes.Newobj, stringCtor), I(OpCodes.Ret),
        ], locals: [charArray, _t.Int32]);

        // Delegate fields of Twice, Add and Decrypt, set by the type initializer.
        var func1 = typeof(Func<int, int>);
        var func2 = typeof(Func<int, int, int>);
        var funcString = typeof(Func<int, string>);
        _twiceField = _lab.StaticField(_lab.Type, "TwiceF", module.Import(func1).ToTypeSig(), readOnly: true);
        _addField = _lab.StaticField(_lab.Type, "AddF", module.Import(func2).ToTypeSig(), readOnly: true);
        _decryptField = _lab.StaticField(_lab.Type, "DecryptF", module.Import(funcString).ToTypeSig(), readOnly: true);
        _invoke1 = module.Import(func1.GetMethod("Invoke"));
        _invoke2 = module.Import(func2.GetMethod("Invoke"));
        _invokeString = module.Import(funcString.GetMethod("Invoke"));
        _lab.StaticConstructor(_lab.Type,
            I(OpCodes.Ldnull), I(OpCodes.Ldftn, _twice), I(OpCodes.Newobj, module.Import(func1.GetConstructors()[0])), I(OpCodes.Stsfld, _twiceField),
            I(OpCodes.Ldnull), I(OpCodes.Ldftn, _add), I(OpCodes.Newobj, module.Import(func2.GetConstructors()[0])), I(OpCodes.Stsfld, _addField),
            I(OpCodes.Ldnull), I(OpCodes.Ldftn, _decrypt), I(OpCodes.Newobj, module.Import(funcString.GetConstructors()[0])), I(OpCodes.Stsfld, _decryptField),
            I(OpCodes.Ret));

        _concat = module.Import(typeof(string).GetMethod(nameof(string.Concat), [typeof(string), typeof(string)]));
        _length = module.Import(typeof(string).GetProperty(nameof(string.Length))!.GetGetMethod());
        _upper = module.Import(typeof(string).GetMethod(nameof(string.ToUpperInvariant), Type.EmptyTypes));
        _toString = module.Import(typeof(object).GetMethod(nameof(ToString), Type.EmptyTypes));
        _invalidOpCtor = module.Import(typeof(InvalidOperationException).GetConstructor([typeof(string)]));
        _catchTypes = new[] { typeof(Exception), typeof(ArithmeticException), typeof(DivideByZeroException), typeof(OverflowException),
            typeof(InvalidOperationException) }.Select(t => (ITypeDefOrRef)module.Import(t)).ToArray();
    }

    /// <summary>Generates <paramref name="count"/> methods M0..; returns the image and the method names.</summary>
    public (byte[] Image, List<string> Methods) Generate(int count)
    {
        var names = new List<string>();
        for (int i = 0; i < count; i++)
        {
            var name = "M" + i;
            // Mostly small and mid-size bodies; now and then a large one.
            int budget = _r.Next(10) == 0 ? _r.Next(1_500, 4_000) : _r.Next(30, 500);
            GenerateMethod(name, budget);
            names.Add(name);
        }
        return (_lab.Write(), names);
    }

    private void GenerateMethod(string name, int budget)
    {
        _method = _lab.Method(name, _t.Int32, [_t.Int32, _t.Int64, _t.String], []);
        _code = new();
        _handlers = new();
        _regions = new();
        _pending = new();
        _locals = new();
        _pool = Enum.GetValues<VT>().ToDictionary(v => v, _ => new List<Local>());
        _budget = budget;
        _maxDepth = _r.Next(2, 7);
        _topStatements = Math.Max(3, budget / 25);
        _ret = new Label();

        // Many locals of every type; at least one of each.
        foreach (var vt in Enum.GetValues<VT>()) NewLocal(vt, pooled: true);
        for (int i = _r.Next(0, 40); i > 0; i--) NewLocal(Pick(Enum.GetValues<VT>()), pooled: true);
        _result = _pool[VT.I4][0];

        // Strings start non-null, so string operations do not throw on locals.
        foreach (var s in _pool[VT.Str])
        {
            Op(OpCodes.Ldstr, RandomString());
            Op(OpCodes.Stloc, s);
        }
        Block(0, inProtected: false, noExit: false);
        Mark(_ret);
        Op(OpCodes.Ldloc, _result);
        Op(OpCodes.Ret);

        Resolve();
        _method.Body = new CilBody(true, _code, _handlers, _locals);
    }

    // ---- statements

    private void Block(int depth, bool inProtected, bool noExit)
    {
        int statements = depth == 0 ? _topStatements : _r.Next(1, 6);
        for (int i = 0; i < statements && _budget > 0; i++) Statement(depth, inProtected, noExit);
    }

    private void Statement(int depth, bool inProtected, bool noExit)
    {
        bool nest = depth < _maxDepth && _budget > 20;
        int kind = _r.Next(nest ? 24 : 8);
        switch (kind)
        {
            case 0: case 1: case 2: Assign(); break;
            case 3: StructOp(); break;
            case 4: CallStatement(); break;
            case 5:
                if (!noExit) Return(inProtected);
                else Assign();
                break;
            case 6: ConditionalThrow(); break;
            case 7: Op(OpCodes.Nop); break;
            case 8: case 9: If(depth, inProtected, noExit); break;
            case 10: ConstantIf(depth, inProtected, noExit); break;
            case 11: case 12: Loop(depth, inProtected, noExit); break;
            case 13: Switch(depth, inProtected, noExit); break;
            case 14: case 15: Flattened(depth, inProtected, noExit); break;
            case 16: TryCatch(depth, inProtected, noExit); break;
            case 17: TryFinally(depth, inProtected, noExit, fault: _r.Next(3) == 0); break;
            case 18: TryFilter(depth, inProtected, noExit); break;
            case 19: DeadBlock(); break;
            case 20: OpaqueIf(depth, inProtected, noExit); break;
            case 21: LocalConstantIf(depth, inProtected, noExit); break;
            case 22: ObfuscatedFlattened(depth, inProtected, noExit); break;
            case 23: DelegateCall(); break;
            default: Assign(); break;
        }
    }

    private void Assign()
    {
        var vt = Pick(Enum.GetValues<VT>());
        if (vt == VT.Struct)
        {
            Op(OpCodes.Ldloc, Pick(_pool[VT.Struct]));
            Op(OpCodes.Stloc, Pick(_pool[VT.Struct]));
            return;
        }
        Expr(vt, _r.Next(0, 4));
        if (_r.Next(6) == 0)
        {
            Op(OpCodes.Dup);
            Op(OpCodes.Stloc, Pick(_pool[vt]));
        }
        Op(OpCodes.Stloc, Pick(_pool[vt]));
    }

    private void StructOp()
    {
        var s = Pick(_pool[VT.Struct]);
        switch (_r.Next(5))
        {
            case 0:
                Op(OpCodes.Ldloca, s);
                Expr(VT.I4, 2);
                Op(OpCodes.Stfld, _fieldA);
                break;
            case 1:
                Op(OpCodes.Ldloca, s);
                Expr(VT.I8, 2);
                Op(OpCodes.Stfld, _fieldB);
                break;
            case 2:
                Op(OpCodes.Ldloca, s);
                Op(OpCodes.Initobj, _struct);
                break;
            case 3:
                Op(OpCodes.Ldloca, s);
                Op(OpCodes.Ldflda, _fieldB);
                Expr(VT.I8, 2);
                Op(OpCodes.Stind_I8);
                break;
            default:
                Op(OpCodes.Ldloca, s);
                Op(OpCodes.Ldloca, Pick(_pool[VT.Struct]));
                Op(OpCodes.Ldobj, _struct);
                Op(OpCodes.Stobj, _struct);
                break;
        }
    }

    /// <summary>
    /// A call through a static delegate field: <c>ldsfld F; arguments; callvirt Invoke</c>, the arguments any expression
    /// (or a constant, which string folding then evaluates through Decrypt).
    /// </summary>
    private void DelegateCall()
    {
        switch (_r.Next(3))
        {
            case 0:
                Op(OpCodes.Ldsfld, _twiceField);
                Expr(VT.I4, _r.Next(0, 3));
                Op(OpCodes.Callvirt, _invoke1);
                Op(OpCodes.Stloc, Pick(_pool[VT.I4]));
                break;
            case 1:
                Op(OpCodes.Ldsfld, _addField);
                Expr(VT.I4, _r.Next(0, 3));
                Expr(VT.I4, _r.Next(0, 3));
                Op(OpCodes.Callvirt, _invoke2);
                Op(OpCodes.Stloc, Pick(_pool[VT.I4]));
                break;
            default:
                Op(OpCodes.Ldsfld, _decryptField);
                if (_r.Next(2) == 0) Ldc(_r.Next(100));
                else Expr(VT.I4, 1);
                Op(OpCodes.Callvirt, _invokeString);
                Op(OpCodes.Stloc, Pick(_pool[VT.Str]));
                break;
        }
    }

    private void CallStatement()
    {
        switch (_r.Next(3))
        {
            case 0:
                Expr(VT.I4, 2);
                Op(OpCodes.Call, _twice);
                Op(OpCodes.Pop);
                break;
            case 1:
                Expr(VT.I4, 1);
                Op(OpCodes.Box, _t.Int32.ToTypeDefOrRef());
                Op(OpCodes.Callvirt, _toString);
                Op(OpCodes.Stloc, Pick(_pool[VT.Str]));
                break;
            default:
                Op(OpCodes.Ldc_I4, _r.Next(100));
                Op(OpCodes.Call, _decrypt);
                Op(OpCodes.Stloc, Pick(_pool[VT.Str]));
                break;
        }
    }

    private void Return(bool inProtected)
    {
        Expr(VT.I4, 2);
        Op(OpCodes.Stloc, _result);
        Op(inProtected ? OpCodes.Leave : OpCodes.Br, _ret);
    }

    private void ConditionalThrow()
    {
        var skip = new Label();
        Condition(skip, 2);
        Op(OpCodes.Ldstr, "generated");
        Op(OpCodes.Newobj, _invalidOpCtor);
        Op(OpCodes.Throw);
        Mark(skip);
    }

    /// <summary>Branches to <paramref name="skip"/> when a random condition is false.</summary>
    private void Condition(Label skip, int depth)
    {
        switch (_r.Next(3))
        {
            case 0:
                Expr(VT.I4, depth);
                Op(_r.Next(2) == 0 ? OpCodes.Brfalse : OpCodes.Brtrue, skip);
                break;
            default:
                var vt = Pick(new[] { VT.I4, VT.I8, VT.R8 });
                Expr(vt, depth);
                Expr(vt, depth);
                Op(Pick(new[] { OpCodes.Beq, OpCodes.Bne_Un, OpCodes.Blt, OpCodes.Bgt, OpCodes.Ble, OpCodes.Bge, OpCodes.Blt_Un, OpCodes.Bge_Un }), skip);
                break;
        }
    }

    private void If(int depth, bool inProtected, bool noExit)
    {
        var otherwise = new Label();
        Condition(otherwise, 2);
        Block(depth + 1, inProtected, noExit);
        if (_r.Next(2) == 0)
        {
            var end = new Label();
            Op(OpCodes.Br, end);
            Mark(otherwise);
            Block(depth + 1, inProtected, noExit);
            Mark(end);
        }
        else Mark(otherwise);
    }

    /// <summary>A condition the cfg pass can decide: a literal or constant arithmetic.</summary>
    private void ConstantIf(int depth, bool inProtected, bool noExit)
    {
        var skip = new Label();
        if (_r.Next(2) == 0) Ldc(_r.Next(2));
        else
        {
            Ldc(6);
            Ldc(7);
            Op(OpCodes.Mul);
            Ldc(_r.Next(41, 44));
            Op(OpCodes.Ceq);
        }
        Op(OpCodes.Brfalse, skip);
        Block(depth + 1, inProtected, noExit);
        Mark(skip);
    }

    /// <summary>if (Opaque() == 42): a call the evaluator can run.</summary>
    /// <summary>
    /// A condition that is the same on every run though computed through fresh locals: <c>k = c</c>, then statements
    /// that leave k alone or an if / else whose arms both store c, then <c>m = k * a + b</c> (int32 or int64, or a xor),
    /// and a comparison of m or a switch on <c>m &amp; 7</c>.
    /// </summary>
    private void LocalConstantIf(int depth, bool inProtected, bool noExit)
    {
        var k = NewLocal(VT.I4, pooled: false);
        int value = _r.Next(-50, 50);
        Ldc(value);
        Op(OpCodes.Stloc, k);
        if (_r.Next(2) == 0) Block(depth + 1, inProtected, noExit);
        else
        {
            Label other = new(), joined = new();
            Expr(VT.I4, 1);
            Op(OpCodes.Brfalse, other);
            Ldc(value);
            Op(OpCodes.Stloc, k);
            Op(OpCodes.Br, joined);
            Mark(other);
            Ldc(value);
            Op(OpCodes.Stloc, k);
            Mark(joined);
        }

        bool wide = _r.Next(2) == 0;
        var m = NewLocal(wide ? VT.I8 : VT.I4, pooled: false);
        int a = _r.Next(1, 9), b = _r.Next(-20, 20);
        Op(OpCodes.Ldloc, k);
        if (wide)
        {
            Op(OpCodes.Conv_I8);
            Op(OpCodes.Ldc_I8, (long)a);
            Op(OpCodes.Mul);
            Op(OpCodes.Ldc_I8, (long)b);
            Op(OpCodes.Add);
        }
        else
        {
            Ldc(a);
            Op(OpCodes.Mul);
            Ldc(b);
            Op(_r.Next(2) == 0 ? OpCodes.Add : OpCodes.Xor);
        }
        Op(OpCodes.Stloc, m);

        var skip = new Label();
        if (!wide && _r.Next(3) == 0)
        {
            var cases = Enumerable.Range(0, _r.Next(2, 6)).Select(_ => new Label()).ToArray();
            Op(OpCodes.Ldloc, m);
            Ldc(7);
            Op(OpCodes.And);
            Op(OpCodes.Switch, cases);
            Block(depth + 1, inProtected, noExit); // default
            Op(OpCodes.Br, skip);
            foreach (var c in cases)
            {
                Mark(c);
                Block(depth + 1, inProtected, noExit);
                Op(OpCodes.Br, skip);
            }
            Mark(skip);
            return;
        }
        Op(OpCodes.Ldloc, m);
        int bound = _r.Next(-100, 100);
        if (wide) Op(OpCodes.Ldc_I8, (long)bound);
        else Ldc(bound);
        Op(Pick(new[] { OpCodes.Beq, OpCodes.Bne_Un, OpCodes.Blt, OpCodes.Bge, OpCodes.Bgt, OpCodes.Ble, OpCodes.Blt_Un, OpCodes.Bge_Un }), skip);
        Block(depth + 1, inProtected, noExit);
        Mark(skip);
    }

    private void OpaqueIf(int depth, bool inProtected, bool noExit)
    {
        var skip = new Label();
        Op(OpCodes.Call, _opaque);
        Ldc(42);
        Op(OpCodes.Bne_Un, skip);
        Block(depth + 1, inProtected, noExit);
        Mark(skip);
    }

    private void Loop(int depth, bool inProtected, bool noExit)
    {
        var counter = NewLocal(VT.I4, pooled: false);
        Label body = new(), cond = new();
        Ldc(0);
        Op(OpCodes.Stloc, counter);
        Op(OpCodes.Br, cond);
        Mark(body);
        Block(depth + 1, inProtected, noExit);
        Op(OpCodes.Ldloc, counter);
        Ldc(1);
        Op(OpCodes.Add);
        Op(OpCodes.Stloc, counter);
        Mark(cond);
        Op(OpCodes.Ldloc, counter);
        Ldc(_r.Next(1, 4));
        Op(OpCodes.Blt, body);
    }

    private void Switch(int depth, bool inProtected, bool noExit)
    {
        int n = _r.Next(2, 7);
        var cases = Enumerable.Range(0, n).Select(_ => new Label()).ToArray();
        var table = Enumerable.Range(0, _r.Next(n, n + 3)).Select(_ => Pick(cases)).ToArray(); // shared targets
        var end = new Label();
        Expr(VT.I4, 2);
        if (_r.Next(2) == 0)
        {
            Ldc(table.Length + 1);
            Op(OpCodes.Rem_Un);
        }
        Op(OpCodes.Switch, table);
        Block(depth + 1, inProtected, noExit); // default
        Op(OpCodes.Br, end);
        foreach (var c in cases)
        {
            Mark(c);
            Block(depth + 1, inProtected, noExit);
            Op(OpCodes.Br, end);
        }
        Mark(end);
    }

    /// <summary>
    /// Flattened control flow as obfuscators emit it, over cases 0..n-1 run in a forward order (the last one leaves):
    /// <list type="bullet">
    /// <item>computed (ConfuserEx): the dispatcher switches on <c>(d = state ^ K) % n</c> and each case computes the next
    /// state from d, <c>state = d * A ^ B</c>, also through a ternary;</item>
    /// <item>stack (.NET Reactor): cases push the next case number and branch to the switch itself; a conditional
    /// transition pushes one number, branches to the switch on a condition, else pops it and pushes another;</item>
    /// <item>laundered: the clean form with every constant passed through a temporary read by address
    /// (<c>stloc t; ldloca t; ldind.i4</c>).</item>
    /// </list>
    /// </summary>
    private void ObfuscatedFlattened(int depth, bool inProtected, bool noExit)
    {
        int n = _r.Next(2, 7);
        int style = _r.Next(3);
        var state = NewLocal(VT.I4, pooled: false);
        var derived = NewLocal(VT.I4, pooled: false);
        var temp = NewLocal(VT.I4, pooled: false);
        var cases = Enumerable.Range(0, n).Select(_ => new Label()).ToArray();
        Label head = new(), sw = new(), exit = new();
        uint key = (uint)_r.Next(1, int.MaxValue), mul = (uint)_r.Next(1, int.MaxValue) | 1;
        int m = _r.Next(1, 1000);
        uint S(int c) => (uint)(c + n * m) ^ key; // selects case c: (S ^ key) % n == c
        int B(int from, int to) => unchecked((int)((uint)(from + n * m) * mul ^ S(to)));

        void Push(int value)
        {
            Ldc(value);
            if (style != 2) return;
            Op(OpCodes.Stloc, temp);
            Op(OpCodes.Ldloca, temp);
            Op(OpCodes.Ldind_I4);
        }
        void Computed(int from, int to)
        {
            Op(OpCodes.Ldloc, derived);
            Ldc(unchecked((int)mul));
            Op(OpCodes.Mul);
            Ldc(B(from, to));
            Op(OpCodes.Xor);
        }

        // Entry and dispatcher.
        if (style == 0) Ldc(unchecked((int)S(0)));
        else Push(0);
        Op(OpCodes.Stloc, state);
        if (_r.Next(2) == 0) Op(OpCodes.Br, head);
        Mark(head);
        Op(OpCodes.Ldloc, state);
        if (style == 0)
        {
            Ldc(unchecked((int)key));
            Op(OpCodes.Xor);
            Op(OpCodes.Dup);
            Op(OpCodes.Stloc, derived);
            Ldc(n);
            Op(OpCodes.Rem_Un);
        }
        Mark(sw);
        Op(OpCodes.Switch, cases);
        Op(OpCodes.Br, exit);

        foreach (int s in Enumerable.Range(0, n).OrderBy(_ => _r.Next()))
        {
            Mark(cases[s]);
            Block(depth + 1, inProtected, noExit);
            if (s == n - 1)
            {
                Op(OpCodes.Br, exit);
                continue;
            }
            int next = s + 1, other = Math.Min(s + 2, n - 1);
            bool conditional = _r.Next(3) == 0;
            switch (style)
            {
                case 0 when conditional:
                {
                    Label no = new(), store = new();
                    Expr(VT.I4, 1);
                    Op(OpCodes.Brfalse, no);
                    Computed(s, next);
                    Op(OpCodes.Br, store);
                    Mark(no);
                    Computed(s, other);
                    Mark(store);
                    Op(OpCodes.Stloc, state);
                    Op(OpCodes.Br, head);
                    break;
                }
                case 0:
                    Computed(s, next);
                    Op(OpCodes.Stloc, state);
                    Op(OpCodes.Br, head);
                    break;
                case 1 when conditional:
                    Ldc(next);
                    Expr(VT.I4, 1);
                    Op(OpCodes.Brtrue, sw);
                    Op(OpCodes.Pop);
                    Ldc(other);
                    Op(OpCodes.Br, sw);
                    break;
                case 1:
                    Ldc(next);
                    Op(OpCodes.Br, sw);
                    break;
                default:
                    Push(next);
                    Op(OpCodes.Stloc, state);
                    Op(OpCodes.Br, head);
                    break;
            }
        }
        Mark(exit);
    }

    /// <summary>
    /// Flattened control flow over a fresh state local: states 0..n-1 run in a forward order, each case stores the next
    /// state and goes back to the dispatcher. Mostly the clean form; sometimes keyed, a ternary next state, or an unclean
    /// variant (a computed state, or the state read in a case) that the engine must leave alone.
    /// </summary>
    private void Flattened(int depth, bool inProtected, bool noExit)
    {
        int n = _r.Next(2, 7);
        var state = NewLocal(VT.I4, pooled: false);
        int key = _r.Next(3) == 0 ? _r.Next(1, 1000) : 0;
        int Enc(int s) => s ^ key;
        var cases = Enumerable.Range(0, n).Select(_ => new Label()).ToArray();
        Label head = new(), exit = new();
        int unclean = _r.Next(5) == 0 ? _r.Next(n) : -1;

        Ldc(Enc(0));
        Op(OpCodes.Stloc, state);
        if (_r.Next(2) == 0) Op(OpCodes.Br, head); // otherwise fall into the dispatcher
        Mark(head);
        Op(OpCodes.Ldloc, state);
        if (key != 0)
        {
            Ldc(key);
            Op(OpCodes.Xor);
        }
        Op(OpCodes.Switch, cases);
        Op(OpCodes.Br, exit);

        foreach (int s in Enumerable.Range(0, n).OrderBy(_ => _r.Next()))
        {
            Mark(cases[s]);
            Block(depth + 1, inProtected, noExit);
            if (s == n - 1)
            {
                Op(OpCodes.Br, exit);
                continue;
            }
            if (s == unclean && _r.Next(2) == 0)
            {
                Op(OpCodes.Ldloc, state); // read outside the dispatcher
                Op(OpCodes.Stloc, Pick(_pool[VT.I4]));
            }
            if (s == unclean && _r.Next(2) == 0)
            {
                // A computed state that equals the next one: ldarg.0 * 0 + next.
                Op(OpCodes.Ldarg_0);
                Ldc(0);
                Op(OpCodes.Mul);
                Ldc(Enc(s + 1));
                Op(OpCodes.Add);
            }
            else if (_r.Next(3) == 0)
            {
                // next = cond ? s + 1 : s + 2 (both forward)
                Label other = new(), store = new();
                Expr(VT.I4, 1);
                Op(OpCodes.Brfalse, other);
                Ldc(Enc(s + 1));
                Op(OpCodes.Br, store);
                Mark(other);
                Ldc(Enc(Math.Min(s + 2, n - 1)));
                Mark(store);
            }
            else Ldc(Enc(s + 1));
            Op(OpCodes.Stloc, state);
            Op(OpCodes.Br, head);
        }
        Mark(exit);
    }

    private void TryCatch(int depth, bool inProtected, bool noExit)
    {
        Label tryStart = new(), handler = new(), after = new();
        Mark(tryStart);
        Block(depth + 1, inProtected: true, noExit);
        Op(OpCodes.Leave, after);
        Mark(handler);
        Op(OpCodes.Pop);
        Block(depth + 1, inProtected: true, noExit);
        Op(OpCodes.Leave, after);
        Mark(after);
        AddRegion(new ExceptionHandler(ExceptionHandlerType.Catch) { CatchType = Pick(_catchTypes) }, tryStart, handler, after, null);
    }

    private void TryFinally(int depth, bool inProtected, bool noExit, bool fault)
    {
        Label tryStart = new(), handler = new(), after = new();
        Mark(tryStart);
        Block(depth + 1, inProtected: true, noExit);
        Op(OpCodes.Leave, after);
        Mark(handler);
        // No leave out of a finally or fault block: early returns are off inside it.
        Block(depth + 1, inProtected: true, noExit: true);
        Op(OpCodes.Endfinally);
        Mark(after);
        AddRegion(new ExceptionHandler(fault ? ExceptionHandlerType.Fault : ExceptionHandlerType.Finally), tryStart, handler, after, null);
    }

    private void TryFilter(int depth, bool inProtected, bool noExit)
    {
        Label tryStart = new(), filter = new(), handler = new(), after = new();
        Mark(tryStart);
        Block(depth + 1, inProtected: true, noExit);
        Op(OpCodes.Leave, after);
        Mark(filter);
        Op(OpCodes.Pop);
        Expr(VT.I4, 2);
        Ldc(0);
        Op(OpCodes.Cgt_Un); // 0 or 1, as endfilter requires
        Op(OpCodes.Endfilter);
        Mark(handler);
        Op(OpCodes.Pop);
        Block(depth + 1, inProtected: true, noExit);
        Op(OpCodes.Leave, after);
        Mark(after);
        AddRegion(new ExceptionHandler(ExceptionHandlerType.Filter), tryStart, handler, after, filter);
    }

    /// <summary>br over a few statements nothing else reaches.</summary>
    private void DeadBlock()
    {
        var skip = new Label();
        Op(OpCodes.Br, skip);
        for (int i = _r.Next(1, 4); i > 0; i--) Assign();
        Mark(skip);
    }

    // ---- expressions: each pushes one value of the given type

    private void Expr(VT vt, int depth)
    {
        _budget--;
        bool leaf = depth <= 0 || _r.Next(4) == 0;
        switch (vt)
        {
            case VT.I4: I4(depth, leaf); break;
            case VT.I8: I8(depth, leaf); break;
            case VT.R8: R8(depth, leaf); break;
            case VT.Str: Str(depth, leaf); break;
            default: throw new InvalidOperationException();
        }
    }

    private void I4(int depth, bool leaf)
    {
        int kind = leaf ? _r.Next(4) : _r.Next(4, 17);
        switch (kind)
        {
            case 0: Ldc(_r.Next(3) == 0 ? _r.Next() - int.MaxValue / 2 : _r.Next(-10, 100)); break;
            case 1: Op(OpCodes.Ldloc, Pick(_pool[VT.I4])); break;
            case 2: Op(OpCodes.Ldarg_0); break;
            case 3:
                Op(OpCodes.Ldloca, Pick(_pool[VT.Struct]));
                Op(OpCodes.Ldfld, _fieldA);
                break;
            case 4: case 5: case 6:
            {
                Expr(VT.I4, depth - 1);
                Expr(VT.I4, depth - 1);
                var op = Pick(new[] { OpCodes.Add, OpCodes.Sub, OpCodes.Mul, OpCodes.And, OpCodes.Or, OpCodes.Xor, OpCodes.Shl, OpCodes.Shr,
                    OpCodes.Shr_Un, OpCodes.Div, OpCodes.Rem, OpCodes.Div_Un, OpCodes.Rem_Un, OpCodes.Add_Ovf, OpCodes.Sub_Ovf, OpCodes.Mul_Ovf });
                if (op.Code is Code.Shl or Code.Shr or Code.Shr_Un)
                {
                    // A shift by 32 or more is unspecified in IL, and the JIT's constant folding and the processor disagree on
                    // it: mask the count as C# does, so the program has one meaning to compare.
                    Ldc(31);
                    Op(OpCodes.And);
                }
                Op(op);
                break;
            }
            case 7:
                Expr(VT.I4, depth - 1);
                Op(_r.Next(2) == 0 ? OpCodes.Neg : OpCodes.Not);
                break;
            case 8:
                Expr(VT.I8, depth - 1);
                Op(Pick(new[] { OpCodes.Conv_I4, OpCodes.Conv_U2, OpCodes.Conv_I1, OpCodes.Conv_Ovf_I4 }));
                break;
            case 9:
                Expr(VT.R8, depth - 1);
                Op(OpCodes.Conv_I4);
                break;
            case 10:
                var cmp = Pick(new[] { VT.I4, VT.I8, VT.R8 });
                Expr(cmp, depth - 1);
                Expr(cmp, depth - 1);
                Op(Pick(new[] { OpCodes.Ceq, OpCodes.Cgt, OpCodes.Clt, OpCodes.Cgt_Un, OpCodes.Clt_Un }));
                break;
            case 11:
            {
                // cond ? a : b
                Label other = new(), done = new();
                Expr(VT.I4, depth - 1);
                Op(OpCodes.Brfalse, other);
                Expr(VT.I4, depth - 1);
                Op(OpCodes.Br, done);
                Mark(other);
                Expr(VT.I4, depth - 1);
                Mark(done);
                break;
            }
            case 12:
                Expr(VT.I4, depth - 1);
                Op(OpCodes.Call, _twice);
                break;
            case 13:
                Expr(VT.I4, depth - 1);
                Expr(VT.I4, depth - 1);
                Op(OpCodes.Call, _r.Next(2) == 0 ? _add : _addW);
                break;
            case 14: Op(OpCodes.Call, _opaque); break;
            case 15:
                Expr(VT.Str, depth - 1);
                Op(OpCodes.Callvirt, _length);
                break;
            default:
                Op(OpCodes.Ldloca, Pick(_pool[VT.Struct]));
                Op(OpCodes.Ldflda, _fieldA);
                Op(OpCodes.Ldind_I4);
                break;
        }
    }

    private void I8(int depth, bool leaf)
    {
        switch (leaf ? _r.Next(4) : _r.Next(4, 7))
        {
            case 0: Op(OpCodes.Ldc_I8, _r.Next(3) == 0 ? _r.NextInt64() : _r.Next(-50, 1000)); break;
            case 1: Op(OpCodes.Ldloc, Pick(_pool[VT.I8])); break;
            case 2: Op(OpCodes.Ldarg_1); break;
            case 3:
                Op(OpCodes.Ldloc, Pick(_pool[VT.Struct]));
                Op(OpCodes.Ldfld, _fieldB);
                break;
            case 4: case 5:
                Expr(VT.I8, depth - 1);
                Expr(VT.I8, depth - 1);
                Op(Pick(new[] { OpCodes.Add, OpCodes.Sub, OpCodes.Mul, OpCodes.And, OpCodes.Or, OpCodes.Xor, OpCodes.Div, OpCodes.Rem }));
                break;
            default:
                Expr(VT.I4, depth - 1);
                Op(_r.Next(2) == 0 ? OpCodes.Conv_I8 : OpCodes.Conv_U8);
                break;
        }
    }

    private void R8(int depth, bool leaf)
    {
        switch (leaf ? _r.Next(2) : _r.Next(2, 5))
        {
            case 0: Op(OpCodes.Ldc_R8, Math.Round(_r.NextDouble() * 200 - 100, 3)); break;
            case 1: Op(OpCodes.Ldloc, Pick(_pool[VT.R8])); break;
            case 2: case 3:
                Expr(VT.R8, depth - 1);
                Expr(VT.R8, depth - 1);
                Op(Pick(new[] { OpCodes.Add, OpCodes.Sub, OpCodes.Mul, OpCodes.Div }));
                break;
            default:
                var from = Pick(new[] { VT.I4, VT.I8 });
                Expr(from, depth - 1);
                Op(OpCodes.Conv_R8);
                break;
        }
    }

    private void Str(int depth, bool leaf)
    {
        switch (leaf ? _r.Next(3) : _r.Next(3, 6))
        {
            case 0: Op(OpCodes.Ldstr, RandomString()); break;
            case 1: Op(OpCodes.Ldloc, Pick(_pool[VT.Str])); break;
            case 2: Op(OpCodes.Ldarg_2); break;
            case 3:
                Expr(VT.Str, depth - 1);
                Expr(VT.Str, depth - 1);
                Op(OpCodes.Call, _concat);
                break;
            case 4:
                Ldc(_r.Next(100));
                Op(OpCodes.Call, _decrypt);
                break;
            default:
                Expr(VT.Str, depth - 1);
                Op(OpCodes.Callvirt, _upper);
                break;
        }
    }

    // ---- emission

    private Local NewLocal(VT vt, bool pooled)
    {
        var local = new Local(vt switch
        {
            VT.I4 => _t.Int32,
            VT.I8 => _t.Int64,
            VT.R8 => _t.Double,
            VT.Str => _t.String,
            _ => new ValueTypeSig(_struct),
        });
        _locals.Add(local);
        if (pooled) _pool[vt].Add(local);
        return local;
    }

    private void Ldc(int value) => Add(Instruction.CreateLdcI4(value));

    private void Op(OpCode op, object? operand = null) => Add(operand == null ? op.ToInstruction() : new Instruction(op, operand));

    private void Add(Instruction ins)
    {
        _code.Add(ins);
        _budget--;
        foreach (var label in _pending) label.Target = ins;
        _pending.Clear();
    }

    /// <summary>The label stands for the next instruction emitted.</summary>
    private void Mark(Label label) => _pending.Add(label);

    /// <summary>Handlers are added when their region is complete, so nested regions precede the ones enclosing them.</summary>
    private void AddRegion(ExceptionHandler handler, Label tryStart, Label handlerStart, Label handlerEnd, Label? filter)
    {
        _handlers.Add(handler);
        _regions.Add((handler, tryStart, handlerStart, handlerEnd, filter));
    }

    private void Resolve()
    {
        static Instruction At(Label l) => l.Target ?? throw new InvalidOperationException("unplaced label");
        foreach (var ins in _code)
        {
            ins.Operand = ins.Operand switch
            {
                Label l => At(l),
                Label[] ls => ls.Select(At).ToArray(),
                var other => other,
            };
        }
        foreach (var (eh, tryStart, handlerStart, handlerEnd, filter) in _regions)
        {
            eh.TryStart = At(tryStart);
            eh.TryEnd = filter != null ? At(filter) : At(handlerStart);
            eh.FilterStart = filter != null ? At(filter) : null;
            eh.HandlerStart = At(handlerStart);
            eh.HandlerEnd = At(handlerEnd);
        }
    }

    private T Pick<T>(IReadOnlyList<T> items) => items[_r.Next(items.Count)];

    private string RandomString() => new(Enumerable.Range(0, _r.Next(0, 8)).Select(_ => (char)_r.Next('a', 'z' + 1)).ToArray());
}
