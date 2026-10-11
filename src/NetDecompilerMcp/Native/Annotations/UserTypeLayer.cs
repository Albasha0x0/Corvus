using System.Security.Cryptography;
using System.Text;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Native.Annotations;

/// <summary>
/// The user's engine types of one image: C declarations, analysis edits (code, functions, data, undefined ranges), types of
/// functions and globals by RVA, stack frame members and decompiler locals by function, operand display formats. Immutable;
/// every change makes a new layer.
/// </summary>
public sealed class UserTypeLayer
{
    public static readonly UserTypeLayer Empty = new([], new Dictionary<uint, string>(), new Dictionary<uint, IReadOnlyList<NativeLocalEdit>>(),
        new Dictionary<uint, IReadOnlyList<NativeStackVarEdit>>());

    public IReadOnlyList<string> Declarations { get; }
    /// <summary>C type of a global, or prototype of a function, by RVA.</summary>
    public IReadOnlyDictionary<uint, string> Types { get; }
    public IReadOnlyDictionary<uint, IReadOnlyList<NativeLocalEdit>> Locals { get; }
    public IReadOnlyDictionary<uint, IReadOnlyList<NativeStackVarEdit>> StackVars { get; }
    /// <summary>Analysis edits in the order made, one per start address.</summary>
    public IReadOnlyList<NativeAnalysisEdit> Analysis { get; }
    /// <summary>Operand display formats by instruction and operand.</summary>
    public IReadOnlyDictionary<(uint Rva, int Operand), NativeOperandEdit> Operands { get; }

    public UserTypeLayer(IReadOnlyList<string> declarations, IReadOnlyDictionary<uint, string> types, IReadOnlyDictionary<uint, IReadOnlyList<NativeLocalEdit>> locals,
        IReadOnlyDictionary<uint, IReadOnlyList<NativeStackVarEdit>> stackVars, IReadOnlyList<NativeAnalysisEdit>? analysis = null,
        IReadOnlyDictionary<(uint, int), NativeOperandEdit>? operands = null)
    {
        Declarations = declarations;
        Types = types;
        Locals = locals;
        StackVars = stackVars;
        Analysis = analysis ?? [];
        Operands = operands ?? new Dictionary<(uint, int), NativeOperandEdit>();
    }

    private UserTypeLayer With(IReadOnlyList<string>? declarations = null, IReadOnlyDictionary<uint, string>? types = null,
        IReadOnlyDictionary<uint, IReadOnlyList<NativeLocalEdit>>? locals = null, IReadOnlyDictionary<uint, IReadOnlyList<NativeStackVarEdit>>? stackVars = null,
        IReadOnlyList<NativeAnalysisEdit>? analysis = null, IReadOnlyDictionary<(uint, int), NativeOperandEdit>? operands = null) =>
        new(declarations ?? Declarations, types ?? Types, locals ?? Locals, stackVars ?? StackVars, analysis ?? Analysis, operands ?? Operands);

    public bool IsEmpty => Declarations.Count == 0 && Types.Count == 0 && Locals.Count == 0 && StackVars.Count == 0 && Analysis.Count == 0 && Operands.Count == 0;

    /// <summary>Declaration blocks, analysis edits, types, locals, stack members and operand formats.</summary>
    public int Count => Declarations.Count + Analysis.Count + Types.Count + Locals.Values.Sum(l => l.Count) + StackVars.Values.Sum(s => s.Count) + Operands.Count;

    /// <summary>Everything, in the order an engine applies it.</summary>
    public NativeUserTypeBatch ToBatch() => new(Declarations,
        Types.OrderBy(t => t.Key).Select(t => new NativePrototype(t.Key, t.Value)).ToList(),
        StackVars.OrderBy(s => s.Key).SelectMany(s => s.Value).ToList(),
        Locals.OrderBy(l => l.Key).SelectMany(l => l.Value).ToList())
    {
        Analysis = Analysis,
        Operands = Operands.OrderBy(o => o.Key).Select(o => o.Value).ToList(),
    };

    private string? _stamp;

    /// <summary>SHA-256 of the content.</summary>
    public string Stamp => _stamp ??= ComputeStamp();

    private string ComputeStamp()
    {
        if (IsEmpty) return "";
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        void Add(string s) => hash.AppendData(Encoding.UTF8.GetBytes(s + "\0"));
        foreach (var d in Declarations) Add("D" + d);
        foreach (var a in Analysis) Add(FormattableString.Invariant($"A{a.Rva:X}:{a.Kind}:{a.End:X}:{a.Type}"));
        foreach (var (rva, type) in Types.OrderBy(t => t.Key)) Add(FormattableString.Invariant($"T{rva:X}:{type}"));
        foreach (var s in StackVars.OrderBy(s => s.Key).SelectMany(s => s.Value)) Add(FormattableString.Invariant($"S{s.Function:X}:{s.Offset}:{s.Name}:{s.Type}"));
        foreach (var l in Locals.OrderBy(l => l.Key).SelectMany(l => l.Value)) Add(FormattableString.Invariant($"L{l.Function:X}:{l.Local}:{l.Stack}:{l.Name}:{l.Type}"));
        foreach (var o in Operands.OrderBy(o => o.Key).Select(o => o.Value)) Add(FormattableString.Invariant($"O{o.Rva:X}:{o.Operand}:{o.Display}:{o.Detail}"));
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    /// <summary>With an operand's display format set; default removes it.</summary>
    public UserTypeLayer WithOperand(NativeOperandEdit edit)
    {
        var operands = new Dictionary<(uint, int), NativeOperandEdit>(Operands);
        if (edit.Display == "default") operands.Remove((edit.Rva, edit.Operand));
        else operands[(edit.Rva, edit.Operand)] = edit;
        return With(operands: operands);
    }

    /// <summary>With the type at <paramref name="rva"/> set, or removed when <paramref name="type"/> is empty.</summary>
    public UserTypeLayer WithType(uint rva, string? type)
    {
        var types = new Dictionary<uint, string>(Types);
        if (string.IsNullOrWhiteSpace(type)) types.Remove(rva);
        else types[rva] = type.Trim();
        return With(types: types);
    }

    /// <summary>With a declaration block added (an identical block is kept once).</summary>
    public UserTypeLayer WithDeclarations(string block)
    {
        var text = block.Trim();
        if (text.Length == 0 || Declarations.Contains(text, StringComparer.Ordinal)) return this;
        return With(declarations: [.. Declarations, text]);
    }

    /// <summary>
    /// With an analysis edit appended; it replaces an earlier edit at the same address. Data or an undefined range drops the
    /// user types of globals it covers (applied after the analysis edits, they would undo it).
    /// </summary>
    public UserTypeLayer WithAnalysis(NativeAnalysisEdit edit)
    {
        var list = Analysis.Where(a => a.Rva != edit.Rva).Append(edit).ToList();
        var types = Types;
        if (edit.Kind is NativeAnalysisEdit.Data or NativeAnalysisEdit.Undefine)
        {
            uint end = edit.End is { } e && e > edit.Rva ? e : edit.Rva + 1;
            if (Types.Keys.Any(k => k >= edit.Rva && k < end))
                types = Types.Where(t => t.Key < edit.Rva || t.Key >= end).ToDictionary(t => t.Key, t => t.Value);
        }
        return With(analysis: list, types: types);
    }

    /// <summary>
    /// With a local edit merged into the edit of the same variable (same stack offset, or a name it had or got), whose
    /// identity is kept; fields the new edit leaves null keep their value.
    /// </summary>
    public UserTypeLayer WithLocal(NativeLocalEdit edit)
    {
        var list = Locals.TryGetValue(edit.Function, out var existing) ? existing.ToList() : [];
        int i = list.FindIndex(e => (edit.Stack != null && e.Stack == edit.Stack) || e.Local == edit.Local || (e.Name != null && e.Name == edit.Local));
        if (i >= 0)
            list[i] = list[i] with { Stack = list[i].Stack ?? edit.Stack, Name = edit.Name ?? list[i].Name, Type = edit.Type ?? list[i].Type };
        else list.Add(edit);
        return With(locals: new Dictionary<uint, IReadOnlyList<NativeLocalEdit>>(Locals) { [edit.Function] = list });
    }

    /// <summary>With a stack member edit merged into the edit at the same offset.</summary>
    public UserTypeLayer WithStackVar(NativeStackVarEdit edit)
    {
        var list = StackVars.TryGetValue(edit.Function, out var existing) ? existing.ToList() : [];
        int i = list.FindIndex(e => e.Offset == edit.Offset);
        if (i >= 0) list[i] = list[i] with { Name = edit.Name ?? list[i].Name, Type = edit.Type ?? list[i].Type };
        else list.Add(edit);
        return With(stackVars: new Dictionary<uint, IReadOnlyList<NativeStackVarEdit>>(StackVars) { [edit.Function] = list });
    }
}
