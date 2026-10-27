using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace Corvus.Core.WebAssembly;

/// <summary>The WebAssembly text format byte-equal to wasm2wat (WABT) defaults; GC types use the specification's text format.</summary>
public sealed class WatWriter
{
    private enum Next { None, Space, Newline, ForceNewline }

    private readonly WasmBinary _m;
    private readonly byte[] _b;
    private readonly StringBuilder _o;
    private int _indent;
    private Next _next;
    private int _labels;
    private readonly string?[] _funcNames, _typeNames, _tableNames, _memoryNames, _globalNames, _elemNames, _dataNames, _tagNames;

    private WatWriter(WasmBinary m, StringBuilder output)
    {
        _m = m;
        _b = m.Bytes;
        _o = output;
        _funcNames = Bind(m.Names.Functions, m.FunctionCount);
        _typeNames = Bind(m.Names.Types, m.Types.Count);
        _tableNames = Bind(m.Names.Tables, m.TableCount);
        _memoryNames = Bind(m.Names.Memories, m.MemoryCount);
        _globalNames = Bind(m.Names.Globals, m.GlobalCount);
        _elemNames = Bind(m.Names.Elements, m.Elements.Count);
        _dataNames = Bind(m.Names.Data, m.Data.Count);
        _tagNames = Bind(m.Names.Tags, m.TagCount);
    }

    /// <summary>The whole module; null when it holds something this writer does not model (see <see cref="WasmBinary.Unsupported"/>).</summary>
    public static string? Module(WasmBinary m, CancellationToken ct = default)
    {
        if (m.Unsupported != null) return null;
        var o = new StringBuilder(m.Bytes.Length * 12);
        new WatWriter(m, o).WriteModule(ct);
        return o.ToString();
    }

    /// <summary>One function's "(func …)" text exactly as it appears in <see cref="Module"/>, at module indentation; an import gives its import line.</summary>
    public static string? Function(WasmBinary m, uint index)
    {
        if (m.Unsupported != null || index >= m.FunctionCount) return null;
        var o = new StringBuilder();
        var w = new WatWriter(m, o) { _indent = 2 };
        if (index < m.ImportedFunctions) w.WriteImport(m.ImportAt(WasmExternal.Func, index)!, index);
        else w.WriteFunc(index);
        w.WriteNextChar();
        return "  " + o.ToString().TrimEnd() + "\n";
    }

    /// <summary>One instruction of function <paramref name="function"/> as its line reads in the module text, branch depths without their label comments.</summary>
    internal static string Instruction(WasmBinary m, uint function, in WasmInstr ins)
    {
        var o = new StringBuilder();
        var w = new WatWriter(m, o) { _plainLabels = true };
        w._localNames = m.Names.Locals.GetValueOrDefault(function);
        int locals = (m.FunctionType(function)?.Params.Length ?? 0) + (int)Math.Min(m.BodyOf(function)?.LocalCount ?? 0, 50_000);
        w._locals = w.LocalNames(locals);
        if (ins.Op is 0x02 or 0x03 or 0x04 or 0x06 or 0x1F)
        {
            w.PutsSpace(ins.Info.Name);
            if (ins.Op == 0x1F) w.TryTableCatches(ins);
            w.BlockType(ins.BlockType);
        }
        else if (ins.Op is 0x05 or 0x0B or 0x19) w.PutsNewline(ins.Info.Name);
        else if (ins.Op == 0x07) { w.PutsSpace("catch"); w.Var(w._tagNames, ins.A, Next.Newline); }
        else w.Instruction(ins);
        return o.ToString().Trim();
    }

    private bool _plainLabels;

    /// <summary>Unique "$name" per index, as WABT binds name-section names (a repeat gets ".1", ".2"…).</summary>
    private static string?[] Bind(Dictionary<uint, string> names, int count)
    {
        var result = new string?[Math.Max(count, 0)];
        var used = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (index, name) in names.OrderBy(n => n.Key))
        {
            if (name.Length == 0 || index >= result.Length) continue;
            result[index] = Unique(used, "$" + name);
        }
        return result;
    }

    private static string Unique(HashSet<string> used, string name)
    {
        var unique = name;
        for (int n = 1; !used.Add(unique); n++) unique = name + "." + n.ToString(CultureInfo.InvariantCulture);
        return unique;
    }

    // The pending-separator writer.

    private void WriteNextChar()
    {
        switch (_next)
        {
            case Next.Space: _o.Append(' '); break;
            case Next.Newline or Next.ForceNewline: _o.Append('\n').Append(' ', _indent); break;
        }
        _next = Next.None;
    }

    private void Data(string s) { WriteNextChar(); _o.Append(s); }
    private void Puts(string s, Next next) { Data(s); _next = next; }
    private void PutsSpace(string s) => Puts(s, Next.Space);
    private void PutsNewline(string s) => Puts(s, Next.Newline);
    private void Writef(string s) { Data(s); _next = Next.Space; }

    private void Newline(bool force)
    {
        if (_next == Next.ForceNewline) WriteNextChar();
        _next = force ? Next.ForceNewline : Next.Newline;
    }

    private void Open(string name, Next next) { Puts("(", Next.None); Puts(name, next); _indent += 2; }
    private void OpenSpace(string name) => Open(name, Next.Space);

    private void Close(Next next)
    {
        if (_next != Next.ForceNewline) _next = Next.None;
        _indent -= 2;
        Puts(")", next);
    }

    private void CloseSpace() => Close(Next.Space);
    private void CloseNewline() => Close(Next.Newline);

    /// <summary>A $name, each UTF-8 byte outside the identifier set written as '_'.</summary>
    private void Name(string name, Next next)
    {
        WriteNextChar();
        foreach (byte c in Encoding.UTF8.GetBytes(name)) _o.Append(c < 128 && ValidNameChar[c] ? (char)c : '_');
        _next = next;
    }

    private static readonly bool[] ValidNameChar = BuildValid();

    private static bool[] BuildValid()
    {
        var valid = new bool[128];
        for (int c = 0; c < 128; c++) valid[c] = char.IsAsciiLetterOrDigit((char)c) || "!#$%&'*+-./:<=>?@\\^_`|~".Contains((char)c);
        return valid;
    }

    private void NameOrIndex(string? name, uint index, Next next)
    {
        if (name != null) Name(name, next);
        else { Writef($"(;{index};)"); _next = next; }
    }

    private void Var(string?[] names, uint index, Next next)
    {
        if (index < names.Length && names[index] is { } name) Name(name, next);
        else { Writef(index.ToString(CultureInfo.InvariantCulture)); _next = next; }
    }

    private void BrVar(uint depth, Next next)
    {
        Writef(_plainLabels ? depth.ToString(CultureInfo.InvariantCulture) : depth < _labels ? $"{depth} (;@{_labels - depth - 1};)" : $"{depth} (;@invalid;)");
        _next = next;
    }

    private void Quoted(ReadOnlySpan<byte> data, Next next)
    {
        WriteNextChar();
        _o.EnsureCapacity(_o.Length + data.Length + 2);
        _o.Append('"');
        foreach (byte c in data)
        {
            if (c < 0x20 || c >= 0x7F || c == '"' || c == '\\') _o.Append('\\').Append(Hex[c >> 4]).Append(Hex[c & 15]);
            else _o.Append((char)c);
        }
        _o.Append('"');
        _next = next;
    }

    private const string Hex = "0123456789abcdef";

    private void Type(WasmType t, Next next) => Puts(TypeText(t), next);

    /// <summary>A value type's text; a defined heap type by its $name or index.</summary>
    private string TypeText(WasmType t) => WasmBinary.TypeName(t, TypeRef);

    private string TypeRef(int index) => index < _typeNames.Length && _typeNames[index] is { } name ? Sanitized(name) : index.ToString(CultureInfo.InvariantCulture);

    private static string Sanitized(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (byte c in Encoding.UTF8.GetBytes(name)) sb.Append(c < 128 && ValidNameChar[c] ? (char)c : '_');
        return sb.ToString();
    }

    private void Types(IReadOnlyList<WasmType> types, string name)
    {
        if (types.Count == 0) return;
        OpenSpace(name);
        foreach (var t in types) Type(t, Next.Space);
        CloseSpace();
    }

    /// <summary>Named bindings each in their own group; unnamed ones share one ("(param i32 i64) (param $x f32)").</summary>
    private void TypeBindings(string prefix, IReadOnlyList<WasmType> types, Dictionary<uint, string>? names, uint offset, HashSet<string> used)
    {
        bool first = true, prevNamed = false;
        for (int i = 0; i < types.Count; i++)
        {
            string? name = names != null && names.TryGetValue(offset + (uint)i, out var n) && n.Length > 0 ? n : null;
            bool named = name != null;
            if ((named || prevNamed) && !first) CloseSpace();
            if (named || prevNamed || first) OpenSpace(prefix);
            if (named) Name(Unique(used, "$" + name), Next.Space);
            Type(types[i], Next.Space);
            prevNamed = named;
            first = false;
        }
        if (types.Count != 0) CloseSpace();
    }

    // Module fields.

    private void WriteModule(CancellationToken ct)
    {
        OpenSpace("module");
        if (_m.Names.Module is { Length: > 0 } module) Name("$" + module, Next.Newline);
        else Newline(false);
        for (int i = 0; i < _m.Types.Count;)
        {
            var def = i < _m.TypeDefs.Count ? _m.TypeDefs[i] : null;
            if (def == null || def.GroupSize <= 1) { WriteType((uint)i++); continue; }
            // A recursion group of several types (one of one reads the same as a lone type).
            OpenSpace("rec");
            Newline(false);
            int end = Math.Min(_m.Types.Count, def.Group + def.GroupSize);
            for (; i < end; i++) WriteType((uint)i);
            CloseNewline();
        }
        uint func = 0, table = 0, memory = 0, global = 0, tag = 0;
        foreach (var import in _m.Imports)
        {
            uint index = import.Kind switch
            {
                WasmExternal.Func => func++, WasmExternal.Table => table++, WasmExternal.Memory => memory++, WasmExternal.Global => global++, _ => tag++,
            };
            WriteImport(import, index);
        }
        for (int i = 0; i < _m.Functions.Count; i++)
        {
            if ((i & 0xFF) == 0) ct.ThrowIfCancellationRequested();
            WriteFunc((uint)(_m.ImportedFunctions + i));
        }
        for (int i = 0; i < _m.Tables.Count; i++) WriteTable(_m.Tables[i].Type, (uint)(_m.ImportedTables + i));
        for (int i = 0; i < _m.Memories.Count; i++) WriteMemory(_m.Memories[i], (uint)(_m.ImportedMemories + i));
        for (int i = 0; i < _m.Tags.Count; i++) { WriteTag(_m.Tags[i], (uint)(_m.ImportedTags + i)); }
        for (int i = 0; i < _m.Globals.Count; i++)
        {
            WriteBeginGlobal(_m.Globals[i].Type, (uint)(_m.ImportedGlobals + i));
            InitExpr(_m.Globals[i].Init);
            CloseNewline();
        }
        foreach (var e in _m.Exports)
        {
            OpenSpace("export");
            Quoted(Encoding.UTF8.GetBytes(e.Name), Next.Space);
            OpenSpace(e.Kind switch { WasmExternal.Func => "func", WasmExternal.Table => "table", WasmExternal.Memory => "memory", WasmExternal.Global => "global", _ => "tag" });
            Var(e.Kind switch
            {
                WasmExternal.Func => _funcNames, WasmExternal.Table => _tableNames, WasmExternal.Memory => _memoryNames, WasmExternal.Global => _globalNames, _ => _tagNames,
            }, e.Index, Next.Space);
            CloseSpace();
            CloseNewline();
        }
        if (_m.Start is { } start)
        {
            OpenSpace("start");
            Var(_funcNames, start, Next.None);
            CloseNewline();
        }
        for (int i = 0; i < _m.Elements.Count; i++) WriteElement(_m.Elements[i], (uint)i);
        for (int i = 0; i < _m.Data.Count; i++) WriteData(_m.Data[i], (uint)i);
        // Every custom section, the name section too, as an annotation after the fields.
        foreach (var (name, from, to) in _m.Customs)
        {
            OpenSpace("@custom");
            Quoted(Encoding.UTF8.GetBytes(name), Next.Space);
            Quoted(_b.AsSpan(from, to - from), Next.Space);
            CloseNewline();
        }
        CloseNewline();
        WriteNextChar();
    }

    private void WriteType(uint index)
    {
        var t = _m.Types[(int)index];
        var def = index < _m.TypeDefs.Count ? _m.TypeDefs[(int)index] : null;
        OpenSpace("type");
        NameOrIndex(_typeNames[index], index, Next.Space);
        bool sub = def != null && (!def.Final || def.Supers.Length > 0);
        if (sub)
        {
            OpenSpace("sub");
            if (def!.Final) Writef("final");
            foreach (var s in def.Supers) Var(_typeNames, s, Next.Space);
        }
        switch (def?.Kind ?? WasmComposite.Func)
        {
            case WasmComposite.Func:
                OpenSpace("func");
                Types(t.Params, "param");
                Types(t.Results, "result");
                CloseSpace();
                break;
            case WasmComposite.Struct:
                OpenSpace("struct");
                foreach (var f in def!.Fields) Field(f);
                CloseSpace();
                break;
            default:
                OpenSpace("array");
                FieldType(def!.Fields[0]);
                CloseSpace();
                break;
        }
        if (sub) CloseSpace();
        CloseNewline();
    }

    private void Field(WasmField f)
    {
        OpenSpace("field");
        FieldType(f);
        CloseSpace();
    }

    /// <summary>A storage type (i8, i16 or a value type), in (mut ...) when mutable.</summary>
    private void FieldType(WasmField f)
    {
        string text = f.Packed switch { 8 => "i8", 16 => "i16", _ => TypeText(f.Type) };
        if (!f.Mutable) { Puts(text, Next.Space); return; }
        OpenSpace("mut");
        Puts(text, Next.Space);
        CloseSpace();
    }

    private void TypeUse(uint type)
    {
        OpenSpace("type");
        Var(_typeNames, type, Next.None);
        CloseSpace();
    }

    private void WriteImport(WasmImport import, uint index)
    {
        OpenSpace("import");
        Quoted(Encoding.UTF8.GetBytes(import.Module), Next.Space);
        Quoted(Encoding.UTF8.GetBytes(import.Name), Next.Space);
        switch (import.Kind)
        {
            case WasmExternal.Func:
                OpenSpace("func");
                NameOrIndex(_funcNames.ElementAtOrDefault((int)index), index, Next.Space);
                TypeUse(import.TypeIndex);
                CloseSpace();
                break;
            case WasmExternal.Table: WriteTable(import.Table!, index); break;
            case WasmExternal.Memory: WriteMemory(import.Memory!.Value, index); break;
            case WasmExternal.Global:
                WriteBeginGlobal(import.Global!.Value, index);
                CloseSpace();
                break;
            case WasmExternal.Tag: WriteTag(import.TypeIndex, index); break;
        }
        CloseNewline();
    }

    private void Limits(WasmLimits l)
    {
        if (l.Is64) Writef("i64");
        Writef(l.Min.ToString(CultureInfo.InvariantCulture));
        if (l.Max is { } max) Writef(max.ToString(CultureInfo.InvariantCulture));
        if (l.Shared) Writef("shared");
    }

    private void WriteTable(WasmTableType t, uint index)
    {
        OpenSpace("table");
        NameOrIndex(_tableNames.ElementAtOrDefault((int)index), index, Next.Space);
        Limits(t.Limits);
        Type(t.Element, Next.None);
        CloseNewline();
    }

    private void WriteMemory(WasmLimits l, uint index)
    {
        OpenSpace("memory");
        NameOrIndex(_memoryNames.ElementAtOrDefault((int)index), index, Next.Space);
        Limits(l);
        CloseNewline();
    }

    private void WriteTag(uint type, uint index)
    {
        OpenSpace("tag");
        NameOrIndex(_tagNames.ElementAtOrDefault((int)index), index, Next.Space);
        TypeUse(type);
        if (type < _m.Types.Count) Types(_m.Types[(int)type].Params, "param");
        CloseNewline();
    }

    private void WriteBeginGlobal(WasmGlobalType g, uint index)
    {
        OpenSpace("global");
        NameOrIndex(_globalNames.ElementAtOrDefault((int)index), index, Next.Space);
        if (g.Mutable)
        {
            OpenSpace("mut");
            Type(g.Type, Next.Space);
            CloseSpace();
        }
        else Type(g.Type, Next.Space);
    }

    private sealed record Tree(WasmInstr Ins, List<Tree> Children);

    /// <summary>A constant expression folded as WABT folds it: one tree per value, operands nested ("(i32.add (global.get 0) (i32.const 16))").</summary>
    private void InitExpr(WasmExpr e)
    {
        var stack = new List<Tree>();
        var code = new WasmCode(_b, e.Start, e.End);
        while (code.Next(out var ins) && ins.Op != 0x0B)
        {
            var sig = ins.Info.Signature;
            int arity = ins.Op >> 16 == 0xFB ? ConstArity(ins) : sig == "*" ? 0 : sig.IndexOf(':');
            int take = Math.Min(arity, stack.Count);
            var node = new Tree(ins, stack.GetRange(stack.Count - take, take));
            stack.RemoveRange(stack.Count - take, take);
            stack.Add(node);
        }
        _labels = 0;
        foreach (var tree in stack) WriteTree(tree);
        _next = Next.Space;
    }

    /// <summary>The operand count of a constant GC instruction, for folding.</summary>
    private int ConstArity(in WasmInstr ins) => (ins.Op & 0xFFFF) switch
    {
        0 => ins.A < _m.TypeDefs.Count ? _m.TypeDefs[(int)ins.A].Fields.Length : 0,
        6 => 2,
        8 => (int)Math.Min(ins.B, 100_000u),
        7 or 26 or 27 or 28 => 1,
        _ => 0,
    };

    private void WriteTree(Tree t)
    {
        Puts("(", Next.None);
        Instruction(t.Ins);
        _indent += 2;
        foreach (var child in t.Children) WriteTree(child);
        _indent -= 2;
        if (_next != Next.ForceNewline) _next = Next.None;
        Puts(")", Next.Newline);
    }

    private void WriteElement(WasmElement e, uint index)
    {
        OpenSpace("elem");
        NameOrIndex(_elemNames.ElementAtOrDefault((int)index), index, Next.Space);
        // WABT recomputes the flags: an explicit table only when it is not 0, expressions only when not all ref.func.
        var funcs = e.Functions ?? (e.Type == WasmType.FuncRef ? RefFuncs(e.Exprs!) : null);
        if (e.Mode == WasmSegmentMode.Active && e.Table != 0)
        {
            OpenSpace("table");
            Var(_tableNames, e.Table, Next.Space);
            CloseSpace();
        }
        if (e.Mode == WasmSegmentMode.Active) InitExpr(e.Offset!.Value);
        if (e.Mode == WasmSegmentMode.Declarative) Puts("declare", Next.Space);
        if (funcs != null)
        {
            Puts("func", Next.Space);
            foreach (var f in funcs) Var(_funcNames, f, Next.Space);
        }
        else
        {
            Type(e.Type, Next.Space);
            foreach (var x in e.Exprs!) InitExpr(x);
        }
        CloseNewline();
    }

    /// <summary>The function indexes of an expression list that is all single ref.func instructions, else null.</summary>
    private uint[]? RefFuncs(WasmExpr[] exprs)
    {
        var funcs = new uint[exprs.Length];
        for (int i = 0; i < exprs.Length; i++)
        {
            var code = new WasmCode(_b, exprs[i].Start, exprs[i].End);
            if (!code.Next(out var ins) || ins.Op != 0xD2 || !code.Next(out var end) || end.Op != 0x0B || code.Pos != exprs[i].End) return null;
            funcs[i] = ins.A;
        }
        return funcs;
    }

    private void WriteData(WasmData d, uint index)
    {
        OpenSpace("data");
        NameOrIndex(_dataNames.ElementAtOrDefault((int)index), index, Next.Space);
        if (d.Mode != WasmSegmentMode.Passive)
        {
            if (d.Memory != 0)
            {
                OpenSpace("memory");
                Var(_memoryNames, d.Memory, Next.Space);
                CloseSpace();
            }
            InitExpr(d.Offset!.Value);
        }
        Quoted(_b.AsSpan(d.Start, d.Length), Next.Space);
        CloseNewline();
    }

    // Functions.

    private Dictionary<uint, string>? _localNames;
    private string?[] _locals = [];

    private void WriteFunc(uint index)
    {
        var body = _m.BodyOf(index);
        uint typeIndex = _m.FunctionTypeIndex(index) ?? 0;
        var type = _m.FunctionType(index) ?? new WasmFuncType([], []);
        OpenSpace("func");
        NameOrIndex(_funcNames.ElementAtOrDefault((int)index), index, Next.Space);
        TypeUse(typeIndex);
        _localNames = _m.Names.Locals.GetValueOrDefault(index);
        var used = new HashSet<string>(StringComparer.Ordinal);
        TypeBindings("param", type.Params, _localNames, 0, used);
        Types(type.Results, "result");
        Newline(false);
        var locals = new List<WasmType>();
        if (body != null)
            foreach (var (count, t) in body.Locals)
                for (uint i = 0; i < count && locals.Count < 50_000; i++) locals.Add(t);
        if (locals.Count > 0) TypeBindings("local", locals, _localNames, (uint)type.Params.Length, used);
        _locals = LocalNames(type.Params.Length + locals.Count);
        Newline(false);
        _labels = 1;
        if (body != null) Instructions(body.CodeStart, body.End);
        CloseNewline();
    }

    /// <summary>The $names locals are referenced by, unique in the function as bound in its header.</summary>
    private string?[] LocalNames(int count)
    {
        var names = new string?[count];
        if (_localNames == null) return names;
        var used = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (i, n) in _localNames.OrderBy(n => n.Key))
            if (i < count && n.Length > 0) names[i] = Unique(used, "$" + n);
        return names;
    }

    /// <summary>The instructions of a body; its closing end is not written.</summary>
    private void Instructions(int start, int end)
    {
        var code = new WasmCode(_b, start, end);
        int depth = 0;
        while (code.Next(out var ins))
        {
            switch (ins.Op)
            {
                case 0x0B: // end
                    if (depth == 0) return;
                    depth--;
                    _indent -= 2;
                    _labels--;
                    PutsNewline("end");
                    continue;
                // else: dropped when its branch is empty.
                case 0x05:
                    {
                        var peek = code;
                        if (peek.Next(out var following) && following.Op == 0x0B) continue;
                        _indent -= 2;
                        PutsSpace("else");
                        _indent += 2;
                        Newline(true);
                        continue;
                    }
                case 0x02 or 0x03 or 0x04 or 0x06:
                    BeginBlock(ins);
                    depth++;
                    continue;
                case 0x07 or 0x19: // catch, catch_all
                    _indent -= 2;
                    if (ins.Op == 0x19) PutsNewline("catch_all");
                    else { PutsSpace("catch"); Var(_tagNames, ins.A, Next.Newline); }
                    _indent += 2;
                    continue;
                // delegate ends the try.
                case 0x18:
                    depth--;
                    _indent -= 2;
                    _labels--;
                    PutsSpace("delegate");
                    Writef(ins.A.ToString(CultureInfo.InvariantCulture));
                    _next = Next.Newline;
                    continue;
                case 0x1F:
                    BeginBlock(ins);
                    depth++;
                    continue;
            }
            Instruction(ins);
        }
    }

    private void BeginBlock(in WasmInstr ins)
    {
        PutsSpace(ins.Info.Name);
        if (ins.Op == 0x1F) TryTableCatches(ins);
        BlockType(ins.BlockType);
        Writef($" ;; label = @{_labels}");
        Newline(true);
        _labels++;
        _indent += 2;
    }

    private void BlockType(long blockType)
    {
        if (blockType == -0x40) return;
        if (WasmBinary.BlockResult(blockType) is { } single)
        {
            OpenSpace("result");
            Type(single, Next.Space);
            CloseSpace();
            return;
        }
        // Written inline, without its (type n).
        if (blockType >= 0)
        {
            if (blockType < _m.Types.Count)
            {
                Types(_m.Types[(int)blockType].Params, "param");
                Types(_m.Types[(int)blockType].Results, "result");
            }
            return;
        }
        OpenSpace("result");
        Type((WasmType)(byte)(blockType & 0x7F), Next.Space);
        CloseSpace();
    }

    private void TryTableCatches(in WasmInstr ins)
    {
        var r = new WasmReader(_b, ins.ImmStart, ins.Offset + ins.Length);
        for (int i = 0; i < ins.Count; i++)
        {
            byte kind = r.Byte();
            OpenSpace(kind switch { 0 => "catch", 1 => "catch_ref", 2 => "catch_all", _ => "catch_all_ref" });
            if (kind < 2) Var(_tagNames, r.U32(), Next.Space);
            Writef(r.U32().ToString(CultureInfo.InvariantCulture));
            CloseSpace();
        }
    }

    private void Instruction(in WasmInstr ins)
    {
        var info = ins.Info;
        switch (info.Imm)
        {
            case WasmImm.None:
                if (ins.Op == 0x1B) { PutsSpace("select"); Newline(false); return; }
                PutsNewline(info.Name);
                return;
            case WasmImm.Label: PutsSpace(info.Name); BrVar(ins.A, Next.Newline); return;
            case WasmImm.BrTable:
                PutsSpace(info.Name);
                foreach (var t in WasmCode.Targets(_b, ins)[..^1]) BrVar(t, Next.Space);
                BrVar(ins.A, Next.Newline);
                return;
            case WasmImm.Func: PutsSpace(info.Name); Var(_funcNames, ins.A, Next.Newline); return;
            case WasmImm.CallIndirect:
                PutsSpace(info.Name);
                if (ins.B != 0 || _tableNames.ElementAtOrDefault(0) != null) Var(_tableNames, ins.B, Next.Space);
                OpenSpace("type");
                Var(_typeNames, ins.A, Next.Space);
                CloseNewline();
                return;
            case WasmImm.TypeIndex:
                PutsSpace(info.Name);
                Var(_typeNames, ins.A, Next.Newline);
                return;
            case WasmImm.Local: PutsSpace(info.Name); Var(_locals, ins.A, Next.Newline); return;
            case WasmImm.Global: PutsSpace(info.Name); Var(_globalNames, ins.A, Next.Newline); return;
            case WasmImm.Table: PutsSpace(info.Name); Var(_tableNames, ins.A, Next.Newline); return;
            case WasmImm.Tag: PutsSpace(info.Name); Var(_tagNames, ins.A, Next.Newline); return;
            case WasmImm.Data: PutsSpace(info.Name); Var(_dataNames, ins.A, Next.Newline); return;
            case WasmImm.Elem: PutsSpace(info.Name); Var(_elemNames, ins.A, Next.Newline); return;
            case WasmImm.MemArg or WasmImm.MemArgLane:
                PutsSpace(info.Name);
                MemoryUnlessZero(ins.Memory, Next.Space);
                if (ins.MemOffset != 0) Writef("offset=" + ins.MemOffset.ToString(CultureInfo.InvariantCulture));
                if (ins.Align != info.Align) Writef("align=" + (ins.Align < 64 ? (1UL << (int)ins.Align).ToString(CultureInfo.InvariantCulture) : "0"));
                if (info.Imm == WasmImm.MemArgLane) Writef(ins.Lane.ToString(CultureInfo.InvariantCulture));
                Newline(false);
                return;
            case WasmImm.Memory: PutsSpace(info.Name); MemoryUnlessZero(ins.Memory, Next.Newline); return;
            case WasmImm.I32: PutsSpace(info.Name); Writef(((int)ins.Value).ToString(CultureInfo.InvariantCulture)); Newline(false); return;
            case WasmImm.I64: PutsSpace(info.Name); Writef(ins.Value.ToString(CultureInfo.InvariantCulture)); Newline(false); return;
            case WasmImm.F32:
                PutsSpace(info.Name);
                PutsSpace(WasmFloat.Hex32((uint)ins.Value));
                Writef("(;=" + WasmFloat.G(BitConverter.Int32BitsToSingle((int)ins.Value)) + ";)");
                Newline(false);
                return;
            case WasmImm.F64:
                PutsSpace(info.Name);
                PutsSpace(WasmFloat.Hex64((ulong)ins.Value));
                Writef("(;=" + WasmFloat.G(BitConverter.Int64BitsToDouble(ins.Value)) + ";)");
                Newline(false);
                return;
            case WasmImm.HeapType:
                PutsSpace(info.Name);
                // ref.test / ref.cast name a reference type, ref.null a heap type.
                if (ins.Op >> 16 == 0xFB) Puts(TypeText(WasmRef.Make((ins.Op & 1) != 0, ins.Value)), Next.Newline);
                else Puts(WasmBinary.HeapText(ins.Value, TypeRef), Next.Newline);
                return;
            case WasmImm.SelectTypes:
                {
                    PutsSpace("select");
                    var types = new WasmType[ins.Count];
                    var r = new WasmReader(_b, ins.ImmStart, ins.Offset + ins.Length);
                    for (int i = 0; i < ins.Count; i++) types[i] = WasmBinary.ReadValType(ref r);
                    Types(types, "result");
                    Newline(false);
                    return;
                }
            case WasmImm.TypeField or WasmImm.TypeCount:
                PutsSpace(info.Name);
                Var(_typeNames, ins.A, Next.Space);
                Writef(ins.B.ToString(CultureInfo.InvariantCulture));
                Newline(false);
                return;
            case WasmImm.TypeData:
                PutsSpace(info.Name);
                Var(_typeNames, ins.A, Next.Space);
                Var(_dataNames, ins.B, Next.Newline);
                return;
            case WasmImm.TypeElem:
                PutsSpace(info.Name);
                Var(_typeNames, ins.A, Next.Space);
                Var(_elemNames, ins.B, Next.Newline);
                return;
            case WasmImm.TwoTypes:
                PutsSpace(info.Name);
                Var(_typeNames, ins.A, Next.Space);
                Var(_typeNames, ins.B, Next.Newline);
                return;
            case WasmImm.BrOnCast:
                PutsSpace(info.Name);
                BrVar(ins.A, Next.Space);
                Puts(TypeText(WasmRef.Make((ins.Lane & 1) != 0, ins.Value)), Next.Space);
                Puts(TypeText(WasmRef.Make((ins.Lane & 2) != 0, ins.BlockType)), Next.Newline);
                return;
            case WasmImm.Lane: PutsSpace(info.Name); Writef(ins.Lane.ToString(CultureInfo.InvariantCulture)); Newline(false); return;
            case WasmImm.V128:
                {
                    PutsSpace(info.Name);
                    PutsSpace("i32x4");
                    var lanes = new string[4];
                    for (int i = 0; i < 4; i++) lanes[i] = "0x" + BinaryPrimitives.ReadUInt32LittleEndian(_b.AsSpan(ins.ImmStart + i * 4)).ToString("x8", CultureInfo.InvariantCulture);
                    Writef(string.Join(" ", lanes));
                    Newline(false);
                    return;
                }
            case WasmImm.Shuffle:
                PutsSpace(info.Name);
                for (int i = 0; i < 16; i++) Writef(_b[ins.ImmStart + i].ToString(CultureInfo.InvariantCulture));
                Newline(false);
                return;
            case WasmImm.DataMemory:
                PutsSpace(info.Name);
                MemoryUnlessZero(ins.Memory, Next.Space);
                Var(_dataNames, ins.A, Next.Newline);
                return;
            case WasmImm.TwoMemories:
                PutsSpace(info.Name);
                if (ins.A != 0 || ins.B != 0) { Var(_memoryNames, ins.A, Next.Space); Var(_memoryNames, ins.B, Next.Newline); }
                else _next = Next.Newline;
                return;
            case WasmImm.ElemTable:
                PutsSpace(info.Name);
                Var(_tableNames, ins.B, Next.Space);
                Var(_elemNames, ins.A, Next.Newline);
                return;
            case WasmImm.TwoTables:
                PutsSpace(info.Name);
                Var(_tableNames, ins.A, Next.Space);
                Var(_tableNames, ins.B, Next.Newline);
                return;
            case WasmImm.Fence: PutsNewline(info.Name); return;
            default: PutsNewline(info.Name); return;
        }
    }

    private void MemoryUnlessZero(uint memory, Next next)
    {
        if (memory != 0) Var(_memoryNames, memory, next);
        else _next = next;
    }
}

/// <summary>Float literals as WABT writes them: hexadecimal significand with a binary exponent, and C's %g for the comment.</summary>
public static class WasmFloat
{
    public static string Hex32(uint bits) => Hex(bits >> 31 != 0, (int)((bits >> 23) & 0xFF), bits & 0x7FFFFF, 23, 127, 0x400000);

    public static string Hex64(ulong bits) => Hex(bits >> 63 != 0, (int)((bits >> 52) & 0x7FF), bits & 0xFFFFFFFFFFFFF, 52, 1023, 0x8000000000000);

    private static string Hex(bool negative, int biased, ulong sig, int sigBits, int bias, ulong quietNan)
    {
        var sb = new StringBuilder(negative ? "-" : "");
        int maxExp = bias * 2 + 1;
        if (biased == maxExp)
        {
            if (sig == 0) return sb.Append("inf").ToString();
            sb.Append("nan");
            if (sig != quietNan) sb.Append(":0x").Append(sig.ToString("x", CultureInfo.InvariantCulture));
            return sb.ToString();
        }
        bool zero = biased == 0 && sig == 0;
        int exp = biased - bias;
        sb.Append("0x").Append(zero ? '0' : '1');
        // The significand left-aligned in 64 bits, as nybbles from the top.
        ulong top = sig << (64 - sigBits);
        if (top != 0)
        {
            if (biased == 0)
            {
                // Subnormal: the leading one becomes the implicit one ("0x1.p-149" when nothing follows it).
                int zeros = System.Numerics.BitOperations.LeadingZeroCount(top);
                top = zeros < 63 ? top << (zeros + 1) : 0;
                exp = -bias - zeros;
            }
            sb.Append('.');
            while (top != 0) { sb.Append("0123456789abcdef"[(int)(top >> 60)]); top <<= 4; }
        }
        sb.Append('p');
        if (zero) return sb.Append("+0").ToString();
        sb.Append(exp < 0 ? '-' : '+').Append(Math.Abs(exp).ToString(CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    /// <summary>C printf's %g: six significant digits, exponent form below 1e-4 or from 1e6, trailing zeros dropped; nan / inf as glibc writes them.</summary>
    public static string G(double v)
    {
        if (double.IsNaN(v)) return BitConverter.DoubleToInt64Bits(v) < 0 ? "-nan" : "nan";
        if (double.IsInfinity(v)) return v < 0 ? "-inf" : "inf";
        if (v == 0) return BitConverter.DoubleToInt64Bits(v) < 0 ? "-0" : "0";
        // d.ddddde±xxx, correctly rounded.
        var e = v.ToString("e5", CultureInfo.InvariantCulture);
        int at = e.IndexOf('e');
        int exp = int.Parse(e.AsSpan(at + 1), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
        if (exp < -4 || exp >= 6)
        {
            var mantissa = e[..at];
            if (mantissa.Contains('.')) mantissa = mantissa.TrimEnd('0').TrimEnd('.');
            return mantissa + "e" + (exp < 0 ? "-" : "+") + Math.Abs(exp).ToString("00", CultureInfo.InvariantCulture);
        }
        var fixedText = v.ToString("F" + (5 - exp).ToString(CultureInfo.InvariantCulture), CultureInfo.InvariantCulture);
        if (fixedText.Contains('.')) fixedText = fixedText.TrimEnd('0').TrimEnd('.');
        return fixedText;
    }
}
