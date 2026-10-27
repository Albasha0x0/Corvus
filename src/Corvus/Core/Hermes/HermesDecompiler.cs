using System.Globalization;
using System.Numerics;
using System.Text;

namespace Corvus.Core.Hermes;

/// <summary>A function's bytecode as structured JavaScript-like code; goto appears only where the graph is not reducible.</summary>
public static class HermesDecompiler
{
    /// <summary>Functions larger than this are listed as disassembly instead (the structurer is quadratic in blocks).</summary>
    public const int MaxBytecode = 256 * 1024;

    /// <summary>The name a closure of <paramref name="function"/> reads as: fnN, or fnN_name when the function is named.</summary>
    public static string ClosureName(HermesFile file, int function)
    {
        var name = file.FunctionName(function);
        var clean = new string([.. name.Select(c => char.IsLetterOrDigit(c) || c is '_' or '$' ? c : '_')]);
        return clean.Length == 0 || name is "global" ? $"fn{function}" : $"fn{function}_{clean}";
    }

    /// <summary>The decompiled text of <paramref name="function"/>, with a header comment naming its place in the bundle.</summary>
    public static string Function(HermesIndex index, int function, CancellationToken ct = default)
    {
        var file = index.File;
        if (function < 0 || function >= file.Functions.Count) throw new ToolError(ErrorCode.NotFound, $"no function {function} (the bundle has {file.Functions.Count}).");
        var f = file.Functions[function];
        var sb = new StringBuilder();
        var name = file.FunctionName(function);
        sb.Append(CultureInfo.InvariantCulture, $"// #{function} {(name.Length > 0 ? name : "(anonymous)")}: {f.ParamCount - 1} params, {f.FrameSize} registers, {f.Size} bytes at 0x{f.Offset:x}");
        if (file.Locations(f, 1) is [var loc]) sb.Append(CultureInfo.InvariantCulture, $"; {loc.File}:{loc.Line}:{loc.Column}");
        sb.Append('\n');
        if (index.ModuleOf(function) is { } module)
            sb.Append(CultureInfo.InvariantCulture, $"// Metro module {module.Id}{(module.Name != null ? $" ({module.Name})" : "")}{(module.Function == function ? ", its factory" : "")}\n");
        if (index.Parent(function) is >= 0 and var parent) sb.Append(CultureInfo.InvariantCulture, $"// created in #{parent} {ClosureName(file, parent)} at 0x{index.ParentOffset(function):x4}\n");
        if (f.Size > MaxBytecode)
        {
            sb.Append(CultureInfo.InvariantCulture, $"// {f.Size:N0} bytes is past the decompiler's {MaxBytecode:N0}-byte limit: disassembly follows\n");
            foreach (var ins in HermesCode.Decode(file, f)) sb.Append(CultureInfo.InvariantCulture, $"  {ins.Offset:x4}  {HermesCode.Text(file, ins)}\n");
            return sb.ToString();
        }
        var d = new Decompilation(index, f, ct);
        d.Run();
        d.Print(sb);
        return sb.ToString();
    }

    private sealed class Block(int start)
    {
        public int Start { get; } = start;
        public int End { get; set; }
        public List<St> Body { get; } = [];
        public St? Exit { get; set; }
        public List<Block> Succ { get; } = [];
        public List<Block> Pred { get; } = [];
        public List<Block> Throws { get; } = [];
        public int Order { get; set; }
        /// <summary>Where a branch or a plain block continues when it does not jump: the next block, unless conditions were merged.</summary>
        public int Fall { get; set; }
        public HashSet<long> LiveOut { get; set; } = [];
        public HashSet<long> LiveIn { get; set; } = [];
    }

    private sealed class Decompilation(HermesIndex index, HermesFunction f, CancellationToken ct)
    {
        private readonly HermesFile _file = index.File;
        private readonly List<string> _notes = [];
        // Register to depth: -1 for the own environment, d for GetEnvironment d.
        private readonly Dictionary<long, int> _envDepth = [];
        private List<HermesInstruction> _code = [];
        private readonly List<HermesSwitch> _switches = [];
        private IReadOnlyList<HermesHandler> _handlers = [];
        private readonly SortedDictionary<int, Block> _blocks = [];
        private List<St> _result = [];
        private string[] _params = [];
        private readonly HashSet<int> _labelsUsed = [];
        private int _loops;

        public void Run()
        {
            _code = HermesCode.Decode(_file, f, _notes, _switches);
            _handlers = _file.Handlers(f);
            _params = ParamNames();
            BuildBlocks();
            ResumeValues();
            Constants();
            Liveness();
            foreach (var b in _blocks.Values)
            {
                ct.ThrowIfCancellationRequested();
                Fold(b);
            }
            Thread();
            Liveness();
            Conditions();
            try { _result = Structure(); }
            catch (InvalidOperationException ex) { _notes.Add("not structured: " + ex.Message); _result = Flat(); }
            Rewrite(_result);
            // A module factory's dependencyMap[n] names the module it resolves to.
            if (index.ModuleOf(f.Index) is { } module && module.Function == f.Index && module.Dependencies.Count > 0)
                _result = MapTree(_result, x => x is IndexEx { Obj: LitEx { Text: "dependencyMap" }, Key: LitEx k }
                    && int.TryParse(k.Text, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n < module.Dependencies.Count
                    ? new LitEx($"dependencyMap[{n}] /* module {module.Dependencies[n].ToString(CultureInfo.InvariantCulture)} */") : x);
        }

        private static List<St> MapTree(List<St> list, Func<Ex, Ex> f) => [.. list.Select(s => MapTree(s, f))];

        private static St MapTree(St s, Func<Ex, Ex> f)
        {
            switch (s)
            {
                case IfSt i: i.Cond = i.Cond.Map(f); i.Then = MapTree(i.Then, f); i.Else = MapTree(i.Else, f); return i;
                case LoopSt l:
                    l.Body = MapTree(l.Body, f);
                    if (l.While != null) l.While = l.While.Map(f);
                    if (l.DoWhile != null) l.DoWhile = l.DoWhile.Map(f);
                    return l;
                case TrySt t: return new TrySt(MapTree(t.Body, f), MapTree(t.Handler, f));
                case SwitchBlockSt w:
                    return new SwitchBlockSt(w.Value.Map(f), [.. w.Cases.Select(c => (c.Values, c.Default, MapTree(c.Body, f)))], w.Label);
                default: return s.Map(f);
            }
        }

        /// <summary>The body of an async function (a generator made inside the generator an async closure passes to spawnAsync): its yields are awaits.</summary>
        private readonly bool _awaits = index.Kind(f.Index) == HermesClosureKind.GeneratorBody && index.Parent(f.Index) is >= 0 and var g
                                         && index.Kind(g) == HermesClosureKind.Generator && index.Kind(index.Parent(g)) == HermesClosureKind.Async;

        private string[] ParamNames()
        {
            // A damaged large header may claim billions.
            int n = Math.Clamp(f.ParamCount - 1, 0, 1024);
            var module = index.ModuleOf(f.Index);
            if (module?.Function == f.Index && n >= 7)
                return ["global", "require", "importDefault", "importAll", "module", "exports", "dependencyMap", .. Enumerable.Range(7, n - 7).Select(i => $"a{i}")];
            return [.. Enumerable.Range(0, n).Select(i => $"a{i}")];
        }

        private Ex Param(long n) => n == 0 ? new LitEx("this") : n - 1 < _params.Length ? new LitEx(_params[n - 1]) : new LitEx($"arguments[{n - 1}]");

        private Ex Str(long id) => _file.String(id) is { } s ? new LitEx(HermesCode.Quote(s, 4000)) : new LitEx($"string#{id}");
        private string StrName(long id) => _file.String(id) ?? $"string#{id}";
        private static RegEx R(long r) => new(r);

        private string EnvVar(long envReg, long slot)
        {
            if (_envDepth.TryGetValue(envReg, out var depth) && index.EnvironmentOwner(f.Index, depth) is >= 0 and var owner)
                return $"v{owner}_{slot}";
            return $"env_r{envReg}[{slot}]";
        }

        private Ex Closure(long fid, string kind)
        {
            int id = (int)fid;
            string name = id >= 0 && id < _file.Functions.Count ? ClosureName(_file, id) : $"fn{id}";
            return new FuncEx(id, kind + name);
        }

        /// <summary>The 'this' and argument registers of a frame-based call: 'this' at frameSize-7, the arguments below it.</summary>
        private (Ex This, Ex[] Args) FrameArgs(long argc)
        {
            long top = f.FrameSize - 7;
            argc = Math.Clamp(argc, 0, 256);
            var args = new Ex[Math.Max(0, (int)argc - 1)];
            for (int i = 0; i < args.Length; i++) args[i] = R(top - 1 - i);
            return (R(top), args);
        }

        private string Builtin(long i) => _file.Opcodes is { } t && i < t.Builtins.Count ? t.Builtins[(int)i] : $"builtin#{i}";

        private static readonly Dictionary<string, string> Binary = new(StringComparer.Ordinal)
        {
            ["Add"] = "+", ["AddN"] = "+", ["Sub"] = "-", ["SubN"] = "-", ["Mul"] = "*", ["MulN"] = "*", ["Div"] = "/", ["DivN"] = "/",
            ["Mod"] = "%", ["LShift"] = "<<", ["RShift"] = ">>", ["URshift"] = ">>>", ["BitAnd"] = "&", ["BitOr"] = "|", ["BitXor"] = "^",
            ["Eq"] = "==", ["Neq"] = "!=", ["StrictEq"] = "===", ["StrictNeq"] = "!==", ["Less"] = "<", ["LessEq"] = "<=",
            ["Greater"] = ">", ["GreaterEq"] = ">=", ["InstanceOf"] = "instanceof",
        };

        private static readonly Dictionary<string, (string Op, bool Negate)> Compare = new(StringComparer.Ordinal)
        {
            ["JLess"] = ("<", false), ["JLessN"] = ("<", false), ["JNotLess"] = ("<", true), ["JNotLessN"] = ("<", true),
            ["JLessEqual"] = ("<=", false), ["JLessEqualN"] = ("<=", false), ["JNotLessEqual"] = ("<=", true), ["JNotLessEqualN"] = ("<=", true),
            ["JGreater"] = (">", false), ["JGreaterN"] = (">", false), ["JNotGreater"] = (">", true), ["JNotGreaterN"] = (">", true),
            ["JGreaterEqual"] = (">=", false), ["JGreaterEqualN"] = (">=", false), ["JNotGreaterEqual"] = (">=", true), ["JNotGreaterEqualN"] = (">=", true),
            ["JEqual"] = ("==", false), ["JNotEqual"] = ("!=", false), ["JStrictEqual"] = ("===", false), ["JStrictNotEqual"] = ("!==", false),
        };

        /// <summary>The statement of one instruction, or null when it only feeds later instructions (environments, checks).</summary>
        private St? Translate(HermesInstruction ins)
        {
            string name = ins.Name;
            string bare = name.EndsWith("Long", StringComparison.Ordinal) && Compare.ContainsKey(name[..^4]) ? name[..^4] : name;
            if (Binary.TryGetValue(name, out var op)) return new AssignSt(ins.A, new BinEx(op, R(ins.B), R(ins.C), BinEx.PrecOf(op)));
            if (Compare.TryGetValue(bare, out var cmp))
            {
                Ex c = new BinEx(cmp.Op, R(ins.B), R(ins.C), BinEx.PrecOf(cmp.Op));
                return new BranchSt(cmp.Negate ? UnEx.Not(c) : c, (int)ins.A);
            }
            switch (name)
            {
                case "Mov" or "MovLong": return new AssignSt(ins.A, R(ins.B));
                case "LoadConstUndefined": return new AssignSt(ins.A, new LitEx("undefined"));
                case "LoadConstNull": return new AssignSt(ins.A, new LitEx("null"));
                case "LoadConstTrue": return new AssignSt(ins.A, new LitEx("true"));
                case "LoadConstFalse": return new AssignSt(ins.A, new LitEx("false"));
                case "LoadConstZero": return new AssignSt(ins.A, new LitEx("0"));
                case "LoadConstEmpty": return new AssignSt(ins.A, new LitEx("$empty"));
                case "LoadConstUInt8": return new AssignSt(ins.A, new LitEx(HermesNames.Index(ins.B)));
                case "LoadConstInt": return new AssignSt(ins.A, new LitEx(((int)ins.B).ToString(CultureInfo.InvariantCulture)));
                case "LoadConstDouble": return new AssignSt(ins.A, new LitEx(HermesCode.Number(ins.Double)));
                case "LoadConstString" or "LoadConstStringLongIndex": return new AssignSt(ins.A, Str(ins.B));
                case "LoadConstBigInt" or "LoadConstBigIntLongIndex": return new AssignSt(ins.A, new LitEx(BigInt(ins.B)));
                case "LoadParam" or "LoadParamLong": return new AssignSt(ins.A, Param(ins.B));
                case "LoadThisNS": return new AssignSt(ins.A, new LitEx("this"));
                case "CoerceThisNS" or "ThrowIfEmpty": return new AssignSt(ins.A, R(ins.B));
                case "GetNewTarget": return new AssignSt(ins.A, new LitEx("new.target"));
                case "GetGlobalObject": return new AssignSt(ins.A, GlobalEx.Value);
                case "DeclareGlobalVar": return new RawSt($"var {StrName(ins.A)};");
                case "Negate": return new AssignSt(ins.A, new UnEx("-", R(ins.B)));
                case "Not": return new AssignSt(ins.A, new UnEx("!", R(ins.B)));
                case "BitNot": return new AssignSt(ins.A, new UnEx("~", R(ins.B)));
                case "TypeOf": return new AssignSt(ins.A, new UnEx("typeof", R(ins.B)));
                case "ToNumber" or "ToNumeric": return new AssignSt(ins.A, new UnEx("+", R(ins.B)));
                case "ToInt32": return new AssignSt(ins.A, new BinEx("|", R(ins.B), new LitEx("0"), 6));
                case "Inc": return new AssignSt(ins.A, new BinEx("+", R(ins.B), new LitEx("1"), 12));
                case "Dec": return new AssignSt(ins.A, new BinEx("-", R(ins.B), new LitEx("1"), 12));
                case "AddEmptyString": return new AssignSt(ins.A, new BinEx("+", new LitEx("\"\""), R(ins.B), 12));
                case "IsIn": return new AssignSt(ins.A, new BinEx("in", R(ins.B), R(ins.C), 10));
                case "GetByIdShort" or "GetById" or "GetByIdLong" or "TryGetById" or "TryGetByIdLong":
                    return new AssignSt(ins.A, new MemberEx(R(ins.B), StrName(ins.D)));
                case "PutById" or "PutByIdLong" or "TryPutById" or "TryPutByIdLong":
                    return new StoreSt(new MemberEx(R(ins.A), StrName(ins.D)), R(ins.B));
                case "PutNewOwnByIdShort" or "PutNewOwnById" or "PutNewOwnByIdLong" or "PutNewOwnNEById" or "PutNewOwnNEByIdLong":
                    return new StoreSt(new MemberEx(R(ins.A), StrName(ins.C)), R(ins.B), "own");
                case "GetByVal": return new AssignSt(ins.A, new IndexEx(R(ins.B), R(ins.C)));
                case "PutByVal": return new StoreSt(new IndexEx(R(ins.A), R(ins.B)), R(ins.C));
                case "PutOwnByVal": return new StoreSt(new IndexEx(R(ins.A), R(ins.C)), R(ins.B), "own");
                case "PutOwnByIndex" or "PutOwnByIndexL": return new StoreSt(new IndexEx(R(ins.A), new LitEx(HermesNames.Index(ins.C))), R(ins.B), "own");
                case "DelById" or "DelByIdLong": return new AssignSt(ins.A, new UnEx("delete", new MemberEx(R(ins.B), StrName(ins.C))));
                case "DelByVal": return new AssignSt(ins.A, new UnEx("delete", new IndexEx(R(ins.B), R(ins.C))));
                case "PutOwnGetterSetterByVal":
                    return new ExprSt(new CallEx(new LitEx("$defineAccessor"), null, [R(ins.A), R(ins.B), R(ins.C), R(ins.D)], false));
                case "NewObject": return new AssignSt(ins.A, new ObjEx([]));
                case "NewObjectWithParent": return new AssignSt(ins.A, new CallEx(new LitEx("Object.create"), null, [R(ins.B)], false));
                case "NewObjectWithBuffer" or "NewObjectWithBufferLong": return new AssignSt(ins.A, ObjectLiteral(ins.D, ins.E, ins.C));
                case "NewArray": return new AssignSt(ins.A, new ArrEx([]));
                case "NewArrayWithBuffer" or "NewArrayWithBufferLong":
                    return new AssignSt(ins.A, new ArrEx([.. HermesLiterals.Read(_file, _file.ArrayBuffer, ins.D, ins.C).Select(l => (Ex)new LitEx(l.Text(_file)))]));
                case "CreateRegExp":
                    return new AssignSt(ins.A, new LitEx("/" + (StrName(ins.B).Length == 0 ? "(?:)" : StrName(ins.B).Replace("/", "\\/", StringComparison.Ordinal)) + "/" + StrName(ins.C)));
                case "CreateEnvironment" or "CreateInnerEnvironment": _envDepth[ins.A] = -1; return null;
                case "GetEnvironment": _envDepth[ins.A] = (int)ins.B; return null;
                case "LoadFromEnvironment" or "LoadFromEnvironmentL": return new AssignSt(ins.A, new NameEx(EnvVar(ins.B, ins.C)));
                case "StoreToEnvironment" or "StoreToEnvironmentL" or "StoreNPToEnvironment" or "StoreNPToEnvironmentL":
                    return new StoreSt(new NameEx(EnvVar(ins.A, ins.B)), R(ins.C));
                case "CreateClosure" or "CreateClosureLongIndex": return new AssignSt(ins.A, Closure(ins.C, ""));
                case "CreateGeneratorClosure" or "CreateGeneratorClosureLongIndex": return new AssignSt(ins.A, Closure(ins.C, ""));
                case "CreateAsyncClosure" or "CreateAsyncClosureLongIndex": return new AssignSt(ins.A, Closure(ins.C, ""));
                case "CreateGenerator" or "CreateGeneratorLongIndex":
                    return new AssignSt(ins.A, new CallEx(new LitEx("$createGenerator"), null, [Closure(ins.C, "")], false));
                case "CreateThis": return new AssignSt(ins.A, new ThisAllocEx(R(ins.B)));
                case "SelectObject": return new AssignSt(ins.A, R(ins.C));
                case "Call1" or "Call2" or "Call3" or "Call4":
                {
                    Ex[] args = name switch { "Call1" => [], "Call2" => [R(ins.D)], "Call3" => [R(ins.D), R(ins.E)], _ => [R(ins.D), R(ins.E), R(ins.F)] };
                    return new AssignSt(ins.A, new CallEx(R(ins.B), R(ins.C), args, false));
                }
                case "Call" or "CallLong":
                {
                    var (self, args) = FrameArgs(ins.C);
                    return new AssignSt(ins.A, new CallEx(R(ins.B), self, args, false));
                }
                case "Construct" or "ConstructLong":
                    return new AssignSt(ins.A, new CallEx(R(ins.B), null, FrameArgs(ins.C).Args, true));
                case "CallDirect" or "CallDirectLongIndex":
                {
                    var (self, args) = FrameArgs(ins.B);
                    return new AssignSt(ins.A, new CallEx(Closure(ins.C, ""), self, args, false));
                }
                case "CallBuiltin" or "CallBuiltinLong":
                    return new AssignSt(ins.A, new CallEx(new LitEx(Builtin(ins.B)), null, FrameArgs(ins.C).Args, false));
                case "GetBuiltinClosure": return new AssignSt(ins.A, new LitEx(Builtin(ins.B)));
                case "GetArgumentsLength": return new AssignSt(ins.A, new LitEx("arguments.length", false));
                case "GetArgumentsPropByVal": return new AssignSt(ins.A, new IndexEx(new LitEx("arguments"), R(ins.B)));
                case "ReifyArguments": return new AssignSt(ins.A, new LitEx("arguments"));
                case "DirectEval": return new AssignSt(ins.A, new CallEx(new LitEx("eval"), null, [R(ins.B)], false));
                case "Ret": return new ExitSt("return", R(ins.A));
                case "Throw": return new ExitSt("throw", R(ins.A));
                case "Catch": return new AssignSt(ins.A, new CaughtEx());
                case "Jmp" or "JmpLong": return new JumpSt((int)ins.A);
                case "JmpTrue" or "JmpTrueLong": return new BranchSt(R(ins.B), (int)ins.A);
                case "JmpFalse" or "JmpFalseLong": return new BranchSt(new UnEx("!", R(ins.B)), (int)ins.A);
                case "JmpUndefined" or "JmpUndefinedLong": return new BranchSt(new BinEx("===", R(ins.B), new LitEx("undefined"), 9), (int)ins.A);
                case "SwitchImm":
                    return _switches.FirstOrDefault(s => s.Offset == ins.Offset) is { } table ? new SwitchSt(R(ins.A), table) : new RawSt("/* SwitchImm without a table */");
                // Iteration writes its state registers too: the iterator (undefined when done), the for-in index and size.
                case "IteratorBegin": return new AssignSt(ins.A, new CallEx(new LitEx("$iteratorBegin"), null, [R(ins.B)], false), [ins.B]);
                case "IteratorNext": return new AssignSt(ins.A, new CallEx(new LitEx("$iteratorNext"), null, [R(ins.B), R(ins.C)], false), [ins.B]);
                case "IteratorClose": return new ExprSt(new CallEx(new LitEx("$iteratorClose"), null, [R(ins.A)], false));
                case "GetPNameList": return new AssignSt(ins.A, new CallEx(new LitEx("$forInNames"), null, [R(ins.B)], false), [ins.C, ins.D]);
                case "GetNextPName": return new AssignSt(ins.A, new CallEx(new LitEx("$forInNext"), null, [R(ins.B), R(ins.C), R(ins.D), R(ins.E)], false), [ins.D]);
                case "StartGenerator" or "CompleteGenerator": return null;
                case "ResumeGenerator": return new SeqSt([new AssignSt(ins.A, new LitEx("$sent", false)), new AssignSt(ins.B, new LitEx("$returning", false))]);
                case "Debugger": return new RawSt("debugger;");
                case "AsyncBreakCheck" or "DebuggerCheckBreak" or "ProfilePoint" or "ThrowIfUndefinedInst" or "ThrowIfHasRestrictedGlobalProperty": return null;
            }
            // Generators and anything newer stay as the instruction, reading and writing its register operands.
            var regs = Enumerable.Range(0, ins.Op.Operands.Length).Where(i => ins.Op.Operands[i].IsRegister).Select(i => (Ex)R(ins[i])).ToArray();
            return new OpaqueSt($"/* {HermesCode.Text(_file, ins)} */", regs);
        }

        private string BigInt(long id)
        {
            if (id < 0 || id >= _file.BigInts.Count) return $"bigint#{id}n";
            var (offset, length) = _file.BigInts[(int)id];
            var data = _file.Bytes.Span;
            if (length < 0 || length > 4096 || _file.BigIntStorage + offset + length > data.Length) return $"bigint#{id}n";
            var value = new BigInteger(data.Slice(_file.BigIntStorage + offset, length), isUnsigned: false, isBigEndian: false);
            return value.ToString(CultureInfo.InvariantCulture) + "n";
        }

        private ObjEx ObjectLiteral(long keys, long values, long count)
        {
            var k = HermesLiterals.Read(_file, _file.ObjectKeyBuffer, keys, count);
            var v = HermesLiterals.Read(_file, _file.ObjectValueBuffer, values, count);
            return new ObjEx([.. k.Select((key, i) => (key.Text(_file, key: true), (Ex)new LitEx(i < v.Count ? v[i].Text(_file) : "undefined")))]);
        }

        // Blocks and liveness.

        private void BuildBlocks()
        {
            var leaders = new SortedSet<int> { 0 };
            foreach (var ins in _code)
            {
                if (ins.Op.IsJump) { leaders.Add((int)ins.A); if (ins.Name is not ("SaveGenerator" or "SaveGeneratorLong")) leaders.Add(ins.End); }
                if (ins.Name is "Ret" or "Throw" or "SwitchImm") leaders.Add(ins.End);
            }
            foreach (var s in _switches) { leaders.Add(s.Default); foreach (var t in s.Targets) leaders.Add(t); }
            foreach (var h in _handlers) { leaders.Add(h.Start); leaders.Add(h.End); leaders.Add(h.Target); }
            int codeEnd = _code.Count > 0 ? _code[^1].End : 0;
            leaders.RemoveWhere(l => l < 0 || l >= codeEnd);
            var starts = new HashSet<int>(_code.Select(i => i.Offset));
            leaders.RemoveWhere(l => !starts.Contains(l));
            foreach (var l in leaders) _blocks[l] = new Block(l);
            Block? current = null;
            int resume = -1;
            foreach (var ins in _code)
            {
                if (_blocks.TryGetValue(ins.Offset, out var next))
                {
                    if (current != null && current.Exit == null) current.Exit = new JumpSt(ins.Offset);
                    current = next;
                }
                if (current == null) continue;
                current.End = ins.End;
                // Dead code after a terminator in the same block.
                if (current.Exit != null) continue;
                if (ins.Name is "SaveGenerator" or "SaveGeneratorLong") { resume = (int)ins.A; continue; }
                var st = Translate(ins);
                // A generator suspends with SaveGenerator then Ret: the value is yielded and code resumes at the resume point.
                if (resume >= 0 && st is ExitSt { Keyword: "return" } yielded)
                {
                    current.Body.Add(new ExprSt(new UnEx(_awaits ? "await " : "yield ", yielded.Value)));
                    st = new JumpSt(resume);
                }
                resume = -1;
                if (st is BranchSt or JumpSt or SwitchSt or ExitSt) current.Exit = st;
                else if (st is SeqSt seq) current.Body.AddRange(seq.Items);
                else if (st != null) current.Body.Add(st);
            }
            int order = 0;
            foreach (var b in _blocks.Values)
            {
                b.Order = order++;
                b.Fall = b.End;
                b.Exit ??= new JumpSt(b.End);
                foreach (var h in _handlers)
                    if (b.Start >= h.Start && b.Start < h.End && _blocks.TryGetValue(h.Target, out var handler) && !b.Throws.Contains(handler)) b.Throws.Add(handler);
            }
            Link();
        }

        /// <summary>Successor and predecessor lists from each block's exit and fall-through.</summary>
        private void Link()
        {
            foreach (var b in _blocks.Values) { b.Succ.Clear(); b.Pred.Clear(); }
            foreach (var b in _blocks.Values)
            {
                IEnumerable<int> targets = b.Exit switch
                {
                    BranchSt br => [br.Target, b.Fall],
                    JumpSt j => [j.Target],
                    SwitchSt s => [.. s.Table.Targets, s.Table.Default],
                    ExitSt => [],
                    _ => [b.Fall],
                };
                foreach (var t in targets.Distinct())
                    if (_blocks.TryGetValue(t, out var to)) { b.Succ.Add(to); to.Pred.Add(b); }
            }
        }

        /// <summary>Merges a branch whose empty fall-through branches again to a shared target into one branch on a || b or a &amp;&amp; b.</summary>
        private void Conditions()
        {
            var handlerTargets = new HashSet<int>(_handlers.Select(h => h.Target));
            bool changed = true;
            for (int round = 0; changed && round < 1000; round++)
            {
                changed = false;
                foreach (var b in _blocks.Values.ToList())
                {
                    if (b.Exit is not BranchSt b1 || !_blocks.TryGetValue(b.Fall, out var next) || next == b) continue;
                    if (next.Exit is not BranchSt b2 || next.Pred.Count != 1 || handlerTargets.Contains(next.Start)) continue;
                    if (!next.Throws.SequenceEqual(b.Throws)) continue;
                    Ex cond;
                    int target, fall;
                    if (b2.Target == b1.Target) (cond, target, fall) = (Or(b1.Cond, b2.Cond), b1.Target, next.Fall);
                    else if (next.Fall == b1.Target) (cond, target, fall) = (Or(b1.Cond, UnEx.Not(b2.Cond)), b1.Target, b2.Target);
                    else continue;
                    // Pure assignments before the second test move above the first when the shared target does not read them.
                    if (next.Body.Count != 0)
                    {
                        if (!_blocks.TryGetValue(b1.Target, out var shared)) continue;
                        bool movable = next.Body.All(st => st is AssignSt a && a.Value.Pure && !Reads(b1.Cond, a.Reg) && !shared.LiveIn.Contains(a.Reg));
                        if (!movable) continue;
                        b.Body.AddRange(next.Body);
                    }
                    b.Exit = new BranchSt(cond, target);
                    b.Fall = fall;
                    b.End = next.End;
                    _blocks.Remove(next.Start);
                    Link();
                    changed = true;
                    break;
                }
            }
        }

        private static Ex Or(Ex a, Ex b) => new BinEx("||", a, b, 4);

        /// <summary>Blocks that only jump on are bypassed: their users jump straight to the target.</summary>
        private void Thread()
        {
            var keep = new HashSet<int>(_handlers.Select(h => h.Target)) { 0 };
            int Final(int at)
            {
                for (int guard = 0; guard < 64 && _blocks.TryGetValue(at, out var b) && b.Body.Count == 0 && b.Exit is JumpSt j && j.Target != at && !keep.Contains(at); guard++)
                    at = j.Target;
                return at;
            }
            foreach (var b in _blocks.Values)
            {
                b.Fall = Final(b.Fall);
                b.Exit = b.Exit switch
                {
                    JumpSt j => new JumpSt(Final(j.Target)),
                    BranchSt br => new BranchSt(br.Cond, Final(br.Target)),
                    SwitchSt sw => new SwitchSt(sw.Value, sw.Table with { Default = Final(sw.Table.Default), Targets = [.. sw.Table.Targets.Select(Final)] }),
                    var other => other,
                };
            }
            Link();
            foreach (var b in _blocks.Values.ToList())
                if (b.Pred.Count == 0 && !keep.Contains(b.Start) && b.Body.Count == 0 && b.Exit is JumpSt) _blocks.Remove(b.Start);
            Link();
        }

        private static void Uses(St s, HashSet<long> into)
        {
            foreach (var e in s.Exprs) e.Visit(x => { if (x is RegEx r) into.Add(r.Reg); });
        }

        private static IEnumerable<long> Defs(St s) => s is OpaqueSt o ? o.Reads.OfType<RegEx>().Select(r => r.Reg)
            : s is AssignSt { Extra.Length: > 0 } a ? [a.Reg, .. a.Extra] : s.Def is { } d ? [d] : [];

        private void Liveness()
        {
            var blocks = _blocks.Values.ToList();
            var use = new Dictionary<Block, HashSet<long>>();
            var def = new Dictionary<Block, HashSet<long>>();
            foreach (var b in blocks)
            {
                var u = new HashSet<long>();
                var d = new HashSet<long>();
                foreach (var s in b.Body.Append(b.Exit!))
                {
                    var su = new HashSet<long>();
                    Uses(s, su);
                    foreach (var r in su) if (!d.Contains(r)) u.Add(r);
                    foreach (var r in Defs(s)) d.Add(r);
                }
                use[b] = u;
                def[b] = d;
            }
            var liveIn = blocks.ToDictionary(b => b, _ => new HashSet<long>());
            bool changed = true;
            for (int round = 0; changed && round < 1000; round++)
            {
                changed = false;
                for (int i = blocks.Count - 1; i >= 0; i--)
                {
                    var b = blocks[i];
                    var o = new HashSet<long>();
                    foreach (var s in b.Succ.Concat(b.Throws)) o.UnionWith(liveIn[s]);
                    // A handler may run from any point of the protected range: what it reads stays live through the block.
                    foreach (var h in b.Throws) use[b].UnionWith(liveIn[h]);
                    var inn = new HashSet<long>(o);
                    inn.ExceptWith(def[b]);
                    inn.UnionWith(use[b]);
                    if (!inn.SetEquals(liveIn[b])) { liveIn[b] = inn; changed = true; }
                    b.LiveOut = o;
                    b.LiveIn = inn;
                }
            }
        }

        /// <summary>Replaces registers holding the same constant on every path with that constant, by forward data flow.</summary>
        private void Constants()
        {
            var blocks = _blocks.Values.ToList();
            if (blocks.Count == 0) return;
            var into = new Dictionary<Block, Dictionary<long, Ex>?>();
            var outOf = new Dictionary<Block, Dictionary<long, Ex>>();
            var throwers = new Dictionary<Block, List<Block>>();
            foreach (var b in blocks) foreach (var h in b.Throws) (throwers.TryGetValue(h, out var l) ? l : throwers[h] = []).Add(b);
            Dictionary<long, Ex> Transfer(Block b, Dictionary<long, Ex> state)
            {
                var s = new Dictionary<long, Ex>(state);
                foreach (var st in b.Body)
                {
                    foreach (var d in Defs(st)) s.Remove(d);
                    if (st is AssignSt a && Duplicable(a.Value)) s[a.Reg] = a.Value;
                }
                return s;
            }
            static Dictionary<long, Ex>? Meet(Dictionary<long, Ex>? a, Dictionary<long, Ex> b)
            {
                if (a == null) return new Dictionary<long, Ex>(b);
                foreach (var k in a.Keys.ToList())
                    if (!b.TryGetValue(k, out var v) || !SameConstant(a[k], v)) a.Remove(k);
                return a;
            }
            bool changed = true;
            for (int round = 0; changed && round < 50; round++)
            {
                changed = false;
                foreach (var b in blocks)
                {
                    Dictionary<long, Ex>? inn = b.Order == 0 ? [] : null;
                    foreach (var p in b.Pred) if (outOf.TryGetValue(p, out var o)) inn = Meet(inn, o);
                    if (throwers.TryGetValue(b, out var ts))
                        foreach (var t in ts)
                        {
                            if (into.GetValueOrDefault(t) is { } ti) inn = Meet(inn, ti);
                            if (outOf.TryGetValue(t, out var to)) inn = Meet(inn, to);
                        }
                    if (inn == null) continue;
                    var old = into.GetValueOrDefault(b);
                    if (old != null && old.Count == inn.Count && old.All(kv => inn.TryGetValue(kv.Key, out var v) && SameConstant(v, kv.Value))) continue;
                    into[b] = inn;
                    outOf[b] = Transfer(b, inn);
                    changed = true;
                }
            }
            foreach (var b in blocks)
            {
                if (into.GetValueOrDefault(b) is not { Count: > 0 } state) continue;
                state = new Dictionary<long, Ex>(state);
                for (int i = 0; i < b.Body.Count; i++)
                {
                    var st = b.Body[i];
                    if (st is not OpaqueSt && state.Count > 0) b.Body[i] = st = st.Map(x => x is RegEx r && state.TryGetValue(r.Reg, out var c) ? c : x);
                    foreach (var d in Defs(st)) state.Remove(d);
                    if (st is AssignSt a && Duplicable(a.Value)) state[a.Reg] = a.Value;
                }
                if (state.Count > 0) b.Exit = b.Exit!.Map(x => x is RegEx r && state.TryGetValue(r.Reg, out var c) ? c : x);
            }
        }

        private static bool SameConstant(Ex a, Ex b) => a is GlobalEx && b is GlobalEx || a is LitEx la && b is LitEx lb && la.Text == lb.Text;

        // Folding.

        /// <summary>Object and array literals rebuilt from the stores that follow their allocation.</summary>
        private static bool Literals(List<St> body)
        {
            bool any = false;
            for (int i = 0; i < body.Count; i++)
            {
                if (body[i] is not AssignSt { Value: ObjEx or ArrEx } a) continue;
                var value = a.Value;
                int j = i + 1;
                for (; j < body.Count; j++)
                {
                    if (body[j] is not StoreSt { Op: "own" } s) break;
                    if (value is ObjEx o && s.Target is MemberEx { Obj: RegEx r } m && r.Reg == a.Reg && !Reads(s.Value, a.Reg))
                        value = new ObjEx([.. o.Entries, (HermesNames.IsPropertyName(m.Name) ? m.Name : HermesCode.Quote(m.Name), s.Value)]);
                    else if (value is ArrEx arr && s.Target is IndexEx { Obj: RegEx r2, Key: LitEx k } && r2.Reg == a.Reg && k.Text == HermesNames.Index(arr.Items.Length) && !Reads(s.Value, a.Reg))
                        value = new ArrEx([.. arr.Items, s.Value]);
                    else break;
                }
                if (j == i + 1) continue;
                body[i] = new AssignSt(a.Reg, value);
                body.RemoveRange(i + 1, j - i - 1);
                any = true;
            }
            return any;
        }

        /// <summary>The value a resumed generator receives joins the yield that suspended it: r = yield v.</summary>
        private void ResumeValues()
        {
            foreach (var b in _blocks.Values)
                if (b.Body is [.., ExprSt { Value: UnEx { Op: "yield " or "await " } y }] && b.Exit is JumpSt j && _blocks.TryGetValue(j.Target, out var next)
                    && next.Pred.Count == 1 && next.Body is [AssignSt { Value: LitEx { Text: "$sent" } } sent, ..])
                {
                    b.Body[^1] = new AssignSt(sent.Reg, y);
                    next.Body.RemoveAt(0);
                }
        }

        /// <summary>yield v; r = $sent  ->  r = yield v (and await).</summary>
        private static bool Resumes(List<St> body)
        {
            bool any = false;
            for (int i = 0; i + 1 < body.Count; i++)
                if (body[i] is ExprSt { Value: UnEx { Op: "yield " or "await " } y } && body[i + 1] is AssignSt { Value: LitEx { Text: "$sent" } } sent)
                {
                    body[i] = new AssignSt(sent.Reg, y);
                    body.RemoveAt(i + 1);
                    any = true;
                }
            return any;
        }

        /// <summary>A value cheap and constant enough to repeat at every reader: the global object, short literals, parameters.</summary>
        private static bool Duplicable(Ex e) => e is GlobalEx || e is LitEx { Pure: true } l && l.Text.Length <= 40;

        /// <summary>Constants copied into every reader up to the register's next assignment; the assignment goes when nothing else reads it.</summary>
        private static bool Propagate(Block b)
        {
            var body = b.Body;
            St At(int k) => k < body.Count ? body[k] : b.Exit!;
            bool any = false;
            for (int i = 0; i < body.Count; i++)
            {
                if (body[i] is not AssignSt a || !Duplicable(a.Value)) continue;
                int total = body.Count + 1, limit = Math.Min(total, i + 1 + Window);
                bool ended = false, kept = false;
                int k = i + 1;
                for (; k < limit; k++)
                {
                    var st = At(k);
                    if (Count(st, a.Reg) > 0)
                    {
                        if (st is OpaqueSt) { kept = true; break; }
                        var replaced = st.Map(x => x is RegEx r && r.Reg == a.Reg ? a.Value : x);
                        if (k == body.Count) b.Exit = replaced;
                        else body[k] = replaced;
                        any = true;
                    }
                    if (Defs(At(k)).Contains(a.Reg)) { ended = true; break; }
                }
                if (!kept && (ended || (k == total && !b.LiveOut.Contains(a.Reg))))
                {
                    body.RemoveAt(i--);
                    any = true;
                }
            }
            return any;
        }

        private static bool Reads(Ex e, long reg)
        {
            bool found = false;
            e.Visit(x => { if (x is RegEx r && r.Reg == reg) found = true; });
            return found;
        }

        private static int Count(St s, long reg)
        {
            int n = 0;
            foreach (var e in s.Exprs) e.Visit(x => { if (x is RegEx r && r.Reg == reg) n++; });
            return n;
        }

        /// <summary>How far a value may move to its reader, in statements; also bounds the scans in long straight-line blocks.</summary>
        private const int Window = 256;

        /// <summary>Values assigned once and read once in the same block move into their reader; dead pure assignments go.</summary>
        private static void Fold(Block b)
        {
            var body = b.Body;
            St At(int k) => k < body.Count ? body[k] : b.Exit!;
            bool changed = true;
            for (int pass = 0; changed && pass < 8; pass++)
            {
                changed = Propagate(b);
                if (Literals(body)) changed = true;
                if (Resumes(body)) changed = true;
                for (int i = 0; i < body.Count; i++)
                {
                    if (body[i] is not AssignSt { Extra.Length: 0 } a) continue;
                    int total = body.Count + 1, limit = Math.Min(total, i + 1 + Window);
                    int j = -1;
                    for (int k = i + 1; k < limit; k++)
                        if (Count(At(k), a.Reg) > 0 || Defs(At(k)).Contains(a.Reg)) { j = k; break; }
                    if (j < 0)
                    {
                        if (limit < total || b.LiveOut.Contains(a.Reg)) continue;
                        if (a.Value.Pure) body.RemoveAt(i);
                        else if (a.Value is CallEx or UnEx { Op: "delete" or "yield " or "await " }) body[i] = new ExprSt(a.Value);
                        else continue;
                        changed = true;
                        i--;
                        continue;
                    }
                    var target = At(j);
                    if (Count(target, a.Reg) != 1) continue;
                    var targetDefs = Defs(target).ToList();
                    if (targetDefs.Contains(a.Reg) && target is not AssignSt) continue;
                    if (!targetDefs.Contains(a.Reg) && UsedLater(j + 1)) continue;
                    var reads = new HashSet<long>();
                    a.Value.Visit(x => { if (x is RegEx r) reads.Add(r.Reg); });
                    bool blocked = false;
                    for (int k = i + 1; k < j && !blocked; k++)
                        blocked = Defs(At(k)).Any(reads.Contains) || (!a.Value.Pure && At(k).SideEffects);
                    if (blocked) continue;
                    var value = a.Value;
                    var replaced = target.Map(x => x is RegEx r && r.Reg == a.Reg ? value : x);
                    if (j == body.Count) b.Exit = replaced;
                    else body[j] = replaced;
                    body.RemoveAt(i);
                    changed = true;
                    i--;

                    // Read again before the next assignment, or live out of the block (unknown past the window).
                    bool UsedLater(int from)
                    {
                        int end = Math.Min(total, from + Window);
                        for (int k = from; k < end; k++)
                        {
                            if (Count(At(k), a.Reg) > 0) return true;
                            if (Defs(At(k)).Contains(a.Reg)) return false;
                        }
                        return end < total || b.LiveOut.Contains(a.Reg);
                    }
                }
            }
        }

        // Structuring.

        private sealed class Context
        {
            public Block? Header;
            public Block? Follow;
            public HashSet<Block>? Nodes;
            public string? Label;
            public Block? SwitchFollow;
            public string? SwitchLabel;
            public Context? Outer;
            /// <summary>Where the enclosing try statement continues; emission inside it stops there.</summary>
            public Block? TryFollow;
        }

        private Dictionary<Block, Block?> _ipdom = [];
        private Dictionary<Block, int> _rpo = [];
        private readonly HashSet<Block> _emitted = [];
        private readonly HashSet<int> _opened = [];
        private int _budget;

        private List<St> Structure()
        {
            var blocks = _blocks.Values.ToList();
            if (blocks.Count == 0) return [];
            _budget = blocks.Count * 8 + 1000;
            var entry = blocks[0];
            var rpo = Rpo(entry);
            _rpo = rpo.Select((b, i) => (b, i)).ToDictionary(x => x.b, x => x.i);
            var idom = Dominators(rpo, b => b.Pred.Where(_rpo.ContainsKey), entry);
            PostDominators(blocks);
            var loops = new Dictionary<Block, HashSet<Block>>();
            foreach (var b in rpo)
                foreach (var s in b.Succ)
                    if (Dominates(idom, s, b))
                    {
                        if (!loops.TryGetValue(s, out var nodes)) loops[s] = nodes = [s];
                        var stack = new Stack<Block>([b]);
                        while (stack.Count > 0)
                        {
                            var x = stack.Pop();
                            if (nodes.Add(x)) foreach (var p in x.Pred) if (_rpo.ContainsKey(p)) stack.Push(p);
                        }
                    }
            _loopNodes = loops;
            var result = Emit(entry, null, new Context());
            // Code not reached from the entry (generator resume points, handlers of unreached ranges).
            foreach (var b in blocks)
                if (!_emitted.Contains(b) && b.Order > 0)
                {
                    _labelsUsed.Add(b.Start);
                    result.AddRange(Emit(b, null, new Context()));
                }
            return result;
        }

        private Dictionary<Block, HashSet<Block>> _loopNodes = [];

        private static List<Block> Rpo(Block entry)
        {
            var seen = new HashSet<Block>();
            var post = new List<Block>();
            var stack = new Stack<(Block B, int I)>();
            stack.Push((entry, 0));
            seen.Add(entry);
            while (stack.Count > 0)
            {
                var (b, i) = stack.Pop();
                var next = b.Succ.Concat(b.Throws).ToList();
                if (i < next.Count)
                {
                    stack.Push((b, i + 1));
                    if (seen.Add(next[i])) stack.Push((next[i], 0));
                }
                else post.Add(b);
            }
            post.Reverse();
            return post;
        }

        private Dictionary<Block, Block> Dominators(List<Block> rpo, Func<Block, IEnumerable<Block>> preds, Block entry)
        {
            var idom = new Dictionary<Block, Block> { [entry] = entry };
            var handlerPreds = new Dictionary<Block, List<Block>>();
            foreach (var b in rpo)
                foreach (var h in b.Throws)
                    (handlerPreds.TryGetValue(h, out var l) ? l : handlerPreds[h] = []).Add(b);
            bool changed = true;
            while (changed)
            {
                changed = false;
                foreach (var b in rpo)
                {
                    if (b == entry) continue;
                    Block? newIdom = null;
                    foreach (var p in preds(b).Concat(handlerPreds.GetValueOrDefault(b) ?? []))
                    {
                        if (!idom.ContainsKey(p)) continue;
                        newIdom = newIdom == null ? p : Intersect(idom, p, newIdom);
                    }
                    if (newIdom != null && (!idom.TryGetValue(b, out var old) || old != newIdom)) { idom[b] = newIdom; changed = true; }
                }
            }
            return idom;
        }

        private Block Intersect(Dictionary<Block, Block> idom, Block a, Block b)
        {
            int guard = 0;
            while (a != b && guard++ < 100_000)
            {
                while (_rpo[a] > _rpo[b]) a = idom[a];
                while (_rpo[b] > _rpo[a]) b = idom[b];
            }
            return a;
        }

        private static bool Dominates(Dictionary<Block, Block> idom, Block a, Block b)
        {
            for (int guard = 0; guard < 100_000; guard++)
            {
                if (a == b) return true;
                if (!idom.TryGetValue(b, out var up) || up == b) return false;
                b = up;
            }
            return false;
        }

        /// <summary>Immediate post-dominators over normal edges, with one virtual exit after every return and throw.</summary>
        private void PostDominators(List<Block> blocks)
        {
            var exit = new Block(-1);
            var succ = blocks.ToDictionary(b => b, b => b.Succ.Count == 0 ? [exit] : b.Succ.ToList());
            var pred = new Dictionary<Block, List<Block>> { [exit] = [] };
            foreach (var b in blocks) pred[b] = [];
            foreach (var (b, ss) in succ) foreach (var s in ss) pred[s].Add(b);
            // Reverse post order of the reverse graph from the exit; blocks that never reach it get no post-dominator.
            var seen = new HashSet<Block> { exit };
            var post = new List<Block>();
            var stack = new Stack<(Block B, int I)>();
            stack.Push((exit, 0));
            while (stack.Count > 0)
            {
                var (b, i) = stack.Pop();
                var next = pred[b];
                if (i < next.Count)
                {
                    stack.Push((b, i + 1));
                    if (seen.Add(next[i])) stack.Push((next[i], 0));
                }
                else post.Add(b);
            }
            post.Reverse();
            var order = post.Select((b, i) => (b, i)).ToDictionary(x => x.b, x => x.i);
            var ipdom = new Dictionary<Block, Block> { [exit] = exit };
            bool changed = true;
            while (changed)
            {
                changed = false;
                foreach (var b in post)
                {
                    if (b == exit) continue;
                    Block? n = null;
                    foreach (var s in succ[b])
                    {
                        if (!ipdom.ContainsKey(s)) continue;
                        if (n == null) { n = s; continue; }
                        var x = s;
                        var y = n;
                        int guard = 0;
                        while (x != y && guard++ < 100_000)
                        {
                            while (order[x] > order[y]) x = ipdom[x];
                            while (order[y] > order[x]) y = ipdom[y];
                        }
                        n = x;
                    }
                    if (n != null && (!ipdom.TryGetValue(b, out var old) || old != n)) { ipdom[b] = n; changed = true; }
                }
            }
            _ipdom = blocks.ToDictionary(b => b, b => ipdom.TryGetValue(b, out var p) && p != exit ? p : null);
        }

        private string NewLabel() => "loop" + (++_loops).ToString(CultureInfo.InvariantCulture);

        private Block? At(int offset) => _blocks.GetValueOrDefault(offset);

        /// <summary>Statements from <paramref name="start"/> until <paramref name="stop"/>, a loop edge or an exit.</summary>
        private List<St> Emit(Block? start, Block? stop, Context ctx, bool loopEntry = false)
        {
            if (++_depth > MaxDepth) throw new InvalidOperationException($"nesting deeper than {MaxDepth}");
            try { return EmitRegion(start, stop, ctx, loopEntry); }
            finally { _depth--; }
        }

        private const int MaxDepth = 300;
        private int _depth;

        /// <summary>Whether <paramref name="to"/> can be reached from <paramref name="from"/> inside the current loop, without the code already written.</summary>
        private bool Reaches(Block from, Block to, Context ctx)
        {
            var loop = FirstLoop(ctx);
            var seen = new HashSet<Block> { from };
            var queue = new Queue<Block>([from]);
            while (queue.Count > 0)
            {
                var b = queue.Dequeue();
                if (b == to) return true;
                foreach (var s in b.Succ)
                {
                    if (loop?.Nodes != null && !loop.Nodes.Contains(s)) continue;
                    if (s == loop?.Header || _emitted.Contains(s)) continue;
                    if (seen.Add(s)) queue.Enqueue(s);
                }
            }
            return false;
        }

        private List<St> EmitRegion(Block? start, Block? stop, Context ctx, bool loopEntry)
        {
            var output = new List<St>();
            var n = start;
            bool first = true;
            while (n != null)
            {
                if (--_budget < 0) throw new InvalidOperationException("the structuring budget ran out");
                ct.ThrowIfCancellationRequested();
                if (n == stop || n == ctx.TryFollow) break;
                if (JumpOut(n, ctx, first && loopEntry) is { } jump) { output.Add(jump); break; }
                if (_emitted.Contains(n)) { output.Add(new GotoSt(n.Start)); _labelsUsed.Add(n.Start); break; }
                if (!(first && loopEntry) && _loopNodes.TryGetValue(n, out var nodes) && ctx.Header != n)
                {
                    var follow = Follow(n, nodes);
                    var inner = new Context { Header = n, Follow = follow, Nodes = nodes, Label = NewLabel(), Outer = ctx, TryFollow = ctx.TryFollow };
                    output.Add(new LoopSt(Emit(n, null, inner, loopEntry: true), inner.Label!));
                    n = follow;
                    first = false;
                    continue;
                }
                // Handlers with one target form a try; the one starting here and reaching furthest opens first.
                if (TryAt(n) is { } group)
                {
                    _opened.Add(group.Target);
                    var target = At(group.Target)!;
                    var tryFollow = TryFollow(n, group.Ranges, target);
                    var tryCtx = Clone(ctx);
                    tryCtx.TryFollow = tryFollow;
                    var body = Emit(n, stop, tryCtx, first && loopEntry);
                    var handlerCtx = Clone(ctx);
                    handlerCtx.TryFollow = tryFollow ?? ctx.TryFollow;
                    List<St> catchBody = _emitted.Contains(target) ? [new GotoSt(target.Start)] : Emit(target, stop, handlerCtx);
                    if (catchBody is [GotoSt g]) _labelsUsed.Add(g.Target);
                    output.Add(new TrySt(body, catchBody));
                    n = tryFollow;
                    first = false;
                    continue;
                }
                first = false;
                _emitted.Add(n);
                output.Add(new LabelSt(n.Start));
                output.AddRange(n.Body);
                switch (n.Exit)
                {
                    case ExitSt e: output.Add(e); n = null; break;
                    case JumpSt j: n = At(j.Target); break;
                    case BranchSt br:
                    {
                        var taken = At(br.Target);
                        var fall = At(n.Fall);
                        var join = Join(n, ctx);
                        // No join: the arm that cannot reach the other is the if body, and the other continues here.
                        if (join == null && taken != null && fall != null && taken != fall)
                        {
                            if (!Reaches(taken, fall, ctx)) { output.Add(new IfSt(br.Cond, Emit(taken, fall, ctx), [])); n = fall; break; }
                            if (!Reaches(fall, taken, ctx)) { output.Add(new IfSt(UnEx.Not(br.Cond), Emit(fall, taken, ctx), [])); n = taken; break; }
                        }
                        var thenPart = Emit(fall, join, ctx);
                        var elsePart = Emit(taken, join, ctx);
                        output.Add(new IfSt(UnEx.Not(br.Cond), thenPart, elsePart));
                        n = join;
                        break;
                    }
                    case SwitchSt sw:
                    {
                        var join = Join(n, ctx);
                        var label = "switch" + (++_loops).ToString(CultureInfo.InvariantCulture);
                        var swCtx = new Context { SwitchFollow = join, SwitchLabel = label, Outer = ctx, TryFollow = ctx.TryFollow };
                        var cases = new List<(List<long>, bool, List<St>)>();
                        var groups = sw.Table.Targets.Select((t, i) => (t, v: sw.Table.Min + i)).Where(x => x.t != sw.Table.Default).GroupBy(x => x.t);
                        foreach (var g in groups)
                            cases.Add(([.. g.Select(x => x.v)], false, Emit(At(g.Key), join, swCtx)));
                        cases.Add(([], true, Emit(At(sw.Table.Default), join, swCtx)));
                        output.Add(new SwitchBlockSt(sw.Value, cases, label));
                        n = join;
                        break;
                    }
                    default: n = null; break;
                }
            }
            return output;
        }

        /// <summary>The not yet opened handler group (one catch target) whose earliest range starts at <paramref name="n"/>.</summary>
        private (int Target, List<(int Start, int End)> Ranges)? TryAt(Block n)
        {
            (int, List<(int, int)>)? best = null;
            int bestEnd = -1;
            foreach (var g in _handlers.GroupBy(h => h.Target))
            {
                if (_opened.Contains(g.Key) || g.Min(h => h.Start) != n.Start || At(g.Key) == null) continue;
                int end = g.Max(h => h.End);
                if (end > bestEnd) { best = (g.Key, [.. g.Select(h => (h.Start, h.End))]); bestEnd = end; }
            }
            return best;
        }

        /// <summary>Where a try statement continues: the first post-dominator of its start outside its ranges and handler.</summary>
        private Block? TryFollow(Block start, List<(int Start, int End)> ranges, Block handler)
        {
            for (var p = _ipdom.GetValueOrDefault(start); p != null; p = _ipdom.GetValueOrDefault(p))
                if (p != handler && !ranges.Any(r => p.Start >= r.Start && p.Start < r.End)) return p;
            return null;
        }

        private static Context Clone(Context c) => new()
        {
            Header = c.Header, Follow = c.Follow, Nodes = c.Nodes, Label = c.Label, Outer = c.Outer,
            SwitchFollow = c.SwitchFollow, SwitchLabel = c.SwitchLabel, TryFollow = c.TryFollow,
        };

        /// <summary>A break or continue when <paramref name="n"/> leaves the current loop or switch; labelled when it is not the innermost.</summary>
        private St? JumpOut(Block n, Context ctx, bool entering)
        {
            bool innermostBreakable = true;
            for (var c = ctx; c != null; c = c.Outer)
            {
                if (c.SwitchFollow != null && n == c.SwitchFollow)
                    return new JumpOutSt("break", innermostBreakable ? null : c.SwitchLabel);
                if (c.Header != null)
                {
                    if (n == c.Header && !(entering && c == ctx)) return new JumpOutSt("continue", c == FirstLoop(ctx) ? null : c.Label);
                    if (n == c.Follow) return new JumpOutSt("break", innermostBreakable ? null : c.Label);
                }
                if (c.Header != null || c.SwitchFollow != null) innermostBreakable = false;
            }
            return null;
        }

        private static Context? FirstLoop(Context ctx)
        {
            for (var c = ctx; c != null; c = c.Outer) if (c.Header != null) return c;
            return null;
        }

        /// <summary>Where a loop continues: its exit block, preferring the one that post-dominates the header.</summary>
        private Block? Follow(Block header, HashSet<Block> nodes)
        {
            var exits = nodes.SelectMany(b => b.Succ).Where(s => !nodes.Contains(s)).Distinct().ToList();
            if (exits.Count == 0) return null;
            if (exits.Count == 1) return exits[0];
            for (var p = _ipdom.GetValueOrDefault(header); p != null; p = _ipdom.GetValueOrDefault(p))
                if (exits.Contains(p)) return p;
            return exits.OrderBy(e => e.Start).First();
        }

        /// <summary>Where both arms of a branch meet: the immediate post-dominator, unless it lies outside the current loop.</summary>
        private Block? Join(Block b, Context ctx)
        {
            var join = _ipdom.GetValueOrDefault(b);
            var loop = FirstLoop(ctx);
            if (join != null && loop?.Nodes != null && !loop.Nodes.Contains(join) && join != loop.Follow) return null;
            return join;
        }

        private List<St> Flat()
        {
            var output = new List<St>();
            foreach (var b in _blocks.Values)
            {
                output.Add(new LabelSt(b.Start));
                _labelsUsed.Add(b.Start);
                output.AddRange(b.Body);
                switch (b.Exit)
                {
                    case BranchSt br: output.Add(new IfSt(br.Cond, [new GotoSt(br.Target)], [])); break;
                    case JumpSt j: output.Add(new GotoSt(j.Target)); break;
                    case SwitchSt s:
                        output.Add(new SwitchBlockSt(s.Value, [.. s.Table.Targets.Select((t, i) => (new List<long> { s.Table.Min + i }, false, new List<St> { new GotoSt(t) })),
                            (new List<long>(), true, new List<St> { new GotoSt(s.Table.Default) })], "switch0"));
                        break;
                    case ExitSt e: output.Add(e); break;
                }
            }
            foreach (var t in _blocks.Keys) _labelsUsed.Add(t);
            return output;
        }

        // Rewrites on the structured tree.

        private void Rewrite(List<St> list)
        {
            for (int i = 0; i < list.Count; i++)
            {
                switch (list[i])
                {
                    // A generator's resume checks for return() are protocol, not the program's code.
                    case IfSt { Cond: LitEx { Text: "$returning" } } r1:
                        list.RemoveAt(i);
                        list.InsertRange(i--, r1.Else);
                        continue;
                    case IfSt { Cond: UnEx { Op: "!", Operand: LitEx { Text: "$returning" } } } r2:
                        list.RemoveAt(i);
                        list.InsertRange(i--, r2.Then);
                        continue;
                    case IfSt s:
                        Rewrite(s.Then);
                        Rewrite(s.Else);
                        if (Trim(s.Then).Count == 0 && Trim(s.Else).Count > 0) { s.Cond = UnEx.Not(s.Cond); (s.Then, s.Else) = (s.Else, s.Then); }
                        // The branch that leaves goes first, and what follows it moves out of the else.
                        if (Terminal(s.Else) && (!Terminal(s.Then) || Trim(s.Else).Count < Trim(s.Then).Count)) { s.Cond = UnEx.Not(s.Cond); (s.Then, s.Else) = (s.Else, s.Then); }
                        if (Terminal(s.Then) && Trim(s.Else).Count > 0)
                        {
                            list.InsertRange(i + 1, s.Else);
                            s.Else = [];
                        }
                        // rN = a; if (rN) rN = b becomes rN = a && b (and ||, and the ternary form).
                        if (i > 0 && list[i - 1] is AssignSt prev && Trim(s.Else).Count == 0 && Trim(s.Then) is [AssignSt only] && only.Reg == prev.Reg && !Reads(only.Value, prev.Reg))
                        {
                            if (s.Cond is RegEx c && c.Reg == prev.Reg) { list[i - 1] = new AssignSt(prev.Reg, new BinEx("&&", prev.Value, only.Value, 5)); list.RemoveAt(i--); continue; }
                            if (s.Cond is UnEx { Op: "!", Operand: RegEx c2 } && c2.Reg == prev.Reg) { list[i - 1] = new AssignSt(prev.Reg, new BinEx("||", prev.Value, only.Value, 4)); list.RemoveAt(i--); continue; }
                        }
                        // rN = a; if (c) rN = b becomes rN = c ? b : a when a has no side effect.
                        if (i > 0 && list[i - 1] is AssignSt p0 && p0.Value.Pure && Trim(s.Else).Count == 0 && Trim(s.Then) is [AssignSt only2] && only2.Reg == p0.Reg
                            && !Reads(s.Cond, p0.Reg) && !Reads(only2.Value, p0.Reg))
                        {
                            list[i - 1] = new AssignSt(p0.Reg, new CondEx(s.Cond, only2.Value, p0.Value));
                            list.RemoveAt(i--);
                            continue;
                        }
                        if (Trim(s.Then) is [AssignSt t1] && Trim(s.Else) is [AssignSt e1] && t1.Reg == e1.Reg)
                        {
                            list[i] = new AssignSt(t1.Reg, new CondEx(s.Cond, t1.Value, e1.Value));
                            continue;
                        }
                        break;
                    case LoopSt l:
                        Rewrite(l.Body);
                        var body = Trim(l.Body);
                        // while (true) { if (c) break; ... } becomes while (!c) { ... }.
                        if (body.Count > 0 && body[0] is IfSt { Else.Count: 0 } head && Trim(head.Then) is [JumpOutSt { Keyword: "break", Label: null }])
                        {
                            l.While = UnEx.Not(head.Cond);
                            l.Body.Remove(head);
                        }
                        // while (true) { ...; if (c) continue; break; } becomes do { ... } while (c).
                        else if (body.Count >= 2 && body[^1] is JumpOutSt { Keyword: "break", Label: null } && body[^2] is IfSt { Else.Count: 0 } tail
                                 && Trim(tail.Then) is [JumpOutSt { Keyword: "continue", Label: null }])
                        {
                            l.DoWhile = tail.Cond;
                            l.Body.Remove(body[^1]);
                            l.Body.Remove(tail);
                        }
                        else if (body.Count > 0 && body[^1] is JumpOutSt { Keyword: "continue", Label: null } last) l.Body.Remove(last);
                        break;
                    case TrySt t: Rewrite(t.Body); Rewrite(t.Handler); break;
                    case SwitchBlockSt sw: foreach (var c in sw.Cases) Rewrite(c.Body); break;
                }
            }
        }

        private static List<St> Trim(List<St> list) => [.. list.Where(s => s is not LabelSt)];

        private static bool ReadsAnywhere(IEnumerable<St> list, long reg) => list.Any(s => s switch
        {
            IfSt i => Reads(i.Cond, reg) || ReadsAnywhere(i.Then, reg) || ReadsAnywhere(i.Else, reg),
            LoopSt l => l.While != null && Reads(l.While, reg) || l.DoWhile != null && Reads(l.DoWhile, reg) || ReadsAnywhere(l.Body, reg),
            TrySt t => ReadsAnywhere(t.Body, reg) || ReadsAnywhere(t.Handler, reg),
            SwitchBlockSt w => Reads(w.Value, reg) || w.Cases.Any(c => ReadsAnywhere(c.Body, reg)),
            _ => s.Exprs.Any(e => Reads(e, reg)),
        });

        private static bool Terminal(List<St> list) => Trim(list) is [.., ExitSt or JumpOutSt or GotoSt];

        // Printing.

        public void Print(StringBuilder sb)
        {
            var name = ClosureName(_file, f.Index);
            sb.Append(f.Index == _file.GlobalCodeIndex ? "// global code\n" : "")
              .Append(index.Kind(f.Index) switch
              {
                  HermesClosureKind.Async => "async function ",
                  HermesClosureKind.Generator or HermesClosureKind.GeneratorBody => _awaits ? "async function /* body */ " : "function* ",
                  _ => "function ",
              }).Append(name).Append('(').AppendJoin(", ", _params).Append(") {\n");
            if (Trim(_result) is [.., ExitSt { Keyword: "return", Value: LitEx { Text: "undefined" } } last]) _result.Remove(last);
            // A generator's first resume value is never the program's.
            if (Trim(_result) is [AssignSt { Value: LitEx { Text: "$sent" } } start, ..] && !ReadsAnywhere(_result.Where(x => x != start), start.Reg)) _result.Remove(start);
            MarkLabels(_result);
            PrintList(sb, _result, 1);
            sb.Append("}\n");
            foreach (var note in _notes.Take(5)) sb.Append("// note: ").Append(note).Append('\n');
        }

        private void MarkLabels(List<St> list)
        {
            foreach (var s in list)
                switch (s)
                {
                    case IfSt i: MarkLabels(i.Then); MarkLabels(i.Else); break;
                    case LoopSt l: MarkLabels(l.Body); break;
                    case TrySt t: MarkLabels(t.Body); MarkLabels(t.Handler); break;
                    case SwitchBlockSt sw: foreach (var c in sw.Cases) MarkLabels(c.Body); break;
                    case JumpOutSt { Label: { } label }: _jumpLabels.Add(label); break;
                }
        }

        private readonly HashSet<string> _jumpLabels = [];

        private void PrintList(StringBuilder sb, List<St> list, int depth)
        {
            foreach (var s in list) PrintSt(sb, s, depth);
        }

        private void PrintSt(StringBuilder sb, St s, int depth)
        {
            var pad = new string(' ', depth * 2);
            switch (s)
            {
                case LabelSt l:
                    if (_labelsUsed.Contains(l.Offset)) sb.Append(new string(' ', Math.Max(0, depth * 2 - 2))).Append(HermesCode.Label(l.Offset)).Append(":\n");
                    break;
                case AssignSt a: sb.Append(pad).Append('r').Append(a.Reg.ToString(CultureInfo.InvariantCulture)).Append(" = "); a.Value.Write(sb, 2); sb.Append(";\n"); break;
                case StoreSt st: sb.Append(pad); st.Target.Write(sb, 18); sb.Append(" = "); st.Value.Write(sb, 2); sb.Append(";\n"); break;
                case ExprSt e: sb.Append(pad); e.Value.Write(sb, 2); sb.Append(";\n"); break;
                case ExitSt x: sb.Append(pad).Append(x.Keyword); if (!(x.Keyword == "return" && x.Value is LitEx { Text: "undefined" })) { sb.Append(' '); x.Value.Write(sb, 2); } sb.Append(";\n"); break;
                case OpaqueSt o: sb.Append(pad).Append(o.Text).Append('\n'); break;
                case RawSt r: sb.Append(pad).Append(r.Text).Append('\n'); break;
                case GotoSt g: sb.Append(pad).Append("goto ").Append(HermesCode.Label(g.Target)).Append(";\n"); break;
                case JumpOutSt j: sb.Append(pad).Append(j.Keyword).Append(j.Label != null ? " " + j.Label : "").Append(";\n"); break;
                case IfSt i:
                    sb.Append(pad).Append("if (");
                    i.Cond.Write(sb, 2);
                    sb.Append(") {\n");
                    PrintList(sb, i.Then, depth + 1);
                    // Else-if chains stay flat.
                    while (Trim(i.Else) is [IfSt next] && i.Else.Count >= 1)
                    {
                        sb.Append(pad).Append("} else if (");
                        next.Cond.Write(sb, 2);
                        sb.Append(") {\n");
                        foreach (var l in i.Else.OfType<LabelSt>()) PrintSt(sb, l, depth + 1);
                        PrintList(sb, next.Then, depth + 1);
                        i = next;
                    }
                    if (Trim(i.Else).Count > 0 || i.Else.OfType<LabelSt>().Any(l => _labelsUsed.Contains(l.Offset)))
                    {
                        sb.Append(pad).Append("} else {\n");
                        PrintList(sb, i.Else, depth + 1);
                    }
                    sb.Append(pad).Append("}\n");
                    break;
                case LoopSt loop:
                    if (_jumpLabels.Contains(loop.Label)) sb.Append(pad).Append(loop.Label).Append(":\n");
                    if (loop.DoWhile != null)
                    {
                        sb.Append(pad).Append("do {\n");
                        PrintList(sb, loop.Body, depth + 1);
                        sb.Append(pad).Append("} while (");
                        loop.DoWhile.Write(sb, 2);
                        sb.Append(");\n");
                    }
                    else
                    {
                        sb.Append(pad).Append("while (");
                        if (loop.While != null) loop.While.Write(sb, 2);
                        else sb.Append("true");
                        sb.Append(") {\n");
                        PrintList(sb, loop.Body, depth + 1);
                        sb.Append(pad).Append("}\n");
                    }
                    break;
                case TrySt t:
                    sb.Append(pad).Append("try {\n");
                    PrintList(sb, t.Body, depth + 1);
                    sb.Append(pad).Append("} catch (e) {\n");
                    PrintList(sb, t.Handler, depth + 1);
                    sb.Append(pad).Append("}\n");
                    break;
                case SwitchBlockSt sw:
                    if (_jumpLabels.Contains(sw.Label)) sb.Append(pad).Append(sw.Label).Append(":\n");
                    sb.Append(pad).Append("switch (");
                    sw.Value.Write(sb, 2);
                    sb.Append(") {\n");
                    foreach (var (values, isDefault, body) in sw.Cases)
                    {
                        foreach (var v in values) sb.Append(pad).Append("  case ").Append(v.ToString(CultureInfo.InvariantCulture)).Append(":\n");
                        if (isDefault) sb.Append(pad).Append("  default:\n");
                        PrintList(sb, body, depth + 2);
                    }
                    sb.Append(pad).Append("}\n");
                    break;
                case BranchSt b: sb.Append(pad).Append("if ("); b.Cond.Write(sb, 2); sb.Append(") goto ").Append(HermesCode.Label(b.Target)).Append(";\n"); break;
                case JumpSt j2: sb.Append(pad).Append("goto ").Append(HermesCode.Label(j2.Target)).Append(";\n"); break;
            }
        }
    }
}

/// <summary>An object literal: rebuilt from the object buffers and the own-property stores after an allocation.</summary>
internal sealed class ObjEx((string Key, Ex Value)[] entries) : Ex
{
    public (string Key, Ex Value)[] Entries { get; } = entries;
    public override bool Pure => Entries.All(e => e.Value.Pure);

    public override void Write(StringBuilder sb)
    {
        if (Entries.Length == 0) { sb.Append("{}"); return; }
        sb.Append("{ ");
        for (int i = 0; i < Entries.Length; i++)
        {
            if (i > 0) sb.Append(", ");
            sb.Append(Entries[i].Key).Append(": ");
            Entries[i].Value.Write(sb, 3);
        }
        sb.Append(" }");
    }

    public override Ex Map(Func<Ex, Ex> f) => f(new ObjEx([.. Entries.Select(e => (e.Key, e.Value.Map(f)))]));
    public override void Visit(Action<Ex> f) { f(this); foreach (var e in Entries) e.Value.Visit(f); }
}

internal sealed class ArrEx(Ex[] items) : Ex
{
    public Ex[] Items { get; } = items;
    public override bool Pure => Items.All(e => e.Pure);

    public override void Write(StringBuilder sb)
    {
        sb.Append('[');
        for (int i = 0; i < Items.Length; i++)
        {
            if (i > 0) sb.Append(", ");
            Items[i].Write(sb, 3);
        }
        sb.Append(']');
    }

    public override Ex Map(Func<Ex, Ex> f) => f(new ArrEx([.. Items.Select(e => e.Map(f))]));
    public override void Visit(Action<Ex> f) { f(this); foreach (var e in Items) e.Visit(f); }
}

/// <summary>An instruction kept as text: it reads and may write each register it names.</summary>
internal sealed class OpaqueSt(string text, Ex[] regs) : St
{
    public string Text { get; } = text;
    public Ex[] Reads { get; } = regs;
    public override IEnumerable<Ex> Exprs => Reads;
}
