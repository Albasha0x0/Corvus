using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Native.Annotations;

/// <summary>
/// The user's engine types of one image: C declarations, type renames and deletions, enum and struct members, analysis edits (code,
/// functions, data, undefined ranges), types of functions and globals by RVA, stack frame members and decompiler locals by
/// function, operand display formats. Immutable; every change makes a new layer.
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
    /// <summary>Enum members added, changed or (a null value) removed, by enum and member.</summary>
    public IReadOnlyDictionary<(string Enum, string Member), NativeEnumMemberEdit> EnumMembers { get; }
    /// <summary>Type renames and deletions in the order made, one per name.</summary>
    public IReadOnlyList<NativeTypeEdit> TypeEdits { get; }
    /// <summary>Struct and union member edits in the order made, one per type and member (<see cref="NativeFieldEdit.Key"/>).</summary>
    public IReadOnlyList<NativeFieldEdit> Fields { get; }

    public UserTypeLayer(IReadOnlyList<string> declarations, IReadOnlyDictionary<uint, string> types, IReadOnlyDictionary<uint, IReadOnlyList<NativeLocalEdit>> locals,
        IReadOnlyDictionary<uint, IReadOnlyList<NativeStackVarEdit>> stackVars, IReadOnlyList<NativeAnalysisEdit>? analysis = null,
        IReadOnlyDictionary<(uint, int), NativeOperandEdit>? operands = null, IReadOnlyDictionary<(string, string), NativeEnumMemberEdit>? enumMembers = null,
        IReadOnlyList<NativeTypeEdit>? typeEdits = null, IReadOnlyList<NativeFieldEdit>? fields = null)
    {
        Declarations = declarations;
        Types = types;
        Locals = locals;
        StackVars = stackVars;
        Analysis = analysis ?? [];
        Operands = operands ?? new Dictionary<(uint, int), NativeOperandEdit>();
        EnumMembers = enumMembers ?? new Dictionary<(string, string), NativeEnumMemberEdit>();
        TypeEdits = typeEdits ?? [];
        Fields = fields ?? [];
    }

    private UserTypeLayer With(IReadOnlyList<string>? declarations = null, IReadOnlyDictionary<uint, string>? types = null,
        IReadOnlyDictionary<uint, IReadOnlyList<NativeLocalEdit>>? locals = null, IReadOnlyDictionary<uint, IReadOnlyList<NativeStackVarEdit>>? stackVars = null,
        IReadOnlyList<NativeAnalysisEdit>? analysis = null, IReadOnlyDictionary<(uint, int), NativeOperandEdit>? operands = null,
        IReadOnlyDictionary<(string, string), NativeEnumMemberEdit>? enumMembers = null, IReadOnlyList<NativeTypeEdit>? typeEdits = null,
        IReadOnlyList<NativeFieldEdit>? fields = null) =>
        new(declarations ?? Declarations, types ?? Types, locals ?? Locals, stackVars ?? StackVars, analysis ?? Analysis, operands ?? Operands, enumMembers ?? EnumMembers,
            typeEdits ?? TypeEdits, fields ?? Fields);

    public bool IsEmpty => Declarations.Count == 0 && Types.Count == 0 && Locals.Count == 0 && StackVars.Count == 0 && Analysis.Count == 0 && Operands.Count == 0
                           && EnumMembers.Count == 0 && TypeEdits.Count == 0 && Fields.Count == 0;

    /// <summary>Declaration blocks, type edits, enum and struct members, analysis edits, types, locals, stack members and operand formats.</summary>
    public int Count => Declarations.Count + TypeEdits.Count + EnumMembers.Count + Fields.Count + Analysis.Count + Types.Count + Locals.Values.Sum(l => l.Count) + StackVars.Values.Sum(s => s.Count)
                        + Operands.Count;

    /// <summary>Everything, in the order an engine applies it.</summary>
    public NativeUserTypeBatch ToBatch() => new(Declarations,
        Types.OrderBy(t => t.Key).Select(t => new NativePrototype(t.Key, t.Value)).ToList(),
        StackVars.OrderBy(s => s.Key).SelectMany(s => s.Value).ToList(),
        Locals.OrderBy(l => l.Key).SelectMany(l => l.Value).ToList())
    {
        TypeEdits = TypeEdits,
        EnumMembers = EnumMembers.OrderBy(e => e.Key, KeyOrder).Select(e => e.Value).ToList(),
        Fields = Fields,
        Analysis = Analysis,
        Operands = Operands.OrderBy(o => o.Key).Select(o => o.Value).ToList(),
    };

    private static readonly Comparer<(string, string)> KeyOrder =
        Comparer<(string, string)>.Create((a, b) => string.CompareOrdinal(a.Item1, b.Item1) is var c and not 0 ? c : string.CompareOrdinal(a.Item2, b.Item2));

    private string? _stamp;

    /// <summary>SHA-256 of the content.</summary>
    public string Stamp => _stamp ??= ComputeStamp();

    private string ComputeStamp()
    {
        if (IsEmpty) return "";
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        void Add(string s) => hash.AppendData(Encoding.UTF8.GetBytes(s + "\0"));
        foreach (var d in Declarations) Add("D" + d);
        foreach (var r in TypeEdits) Add($"R{r.Name}:{r.NewName}");
        foreach (var e in EnumMembers.OrderBy(e => e.Key, KeyOrder).Select(e => e.Value)) Add(FormattableString.Invariant($"E{e.Enum}:{e.Member}:{e.Value}"));
        foreach (var f in Fields) Add(FormattableString.Invariant($"F{f.Type}:{f.Name}:{f.Offset}:{f.FieldType}"));
        foreach (var a in Analysis) Add(FormattableString.Invariant($"A{a.Rva:X}:{a.Kind}:{a.End:X}:{a.Type}"));
        foreach (var (rva, type) in Types.OrderBy(t => t.Key)) Add(FormattableString.Invariant($"T{rva:X}:{type}"));
        foreach (var s in StackVars.OrderBy(s => s.Key).SelectMany(s => s.Value))
            Add(FormattableString.Invariant($"S{s.Function:X}:{s.Offset}:{s.Name}:{s.Type}") + (s.Delete ? ":delete" : ""));
        foreach (var l in Locals.OrderBy(l => l.Key).SelectMany(l => l.Value)) Add(FormattableString.Invariant($"L{l.Function:X}:{l.Local}:{l.Stack}:{l.Name}:{l.Type}"));
        foreach (var o in Operands.OrderBy(o => o.Key).Select(o => o.Value)) Add(FormattableString.Invariant($"O{o.Rva:X}:{o.Operand}:{o.Display}:{o.Detail}"));
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    /// <summary>With an enum member edit, replacing an earlier edit of the same member.</summary>
    public UserTypeLayer WithEnumMember(NativeEnumMemberEdit edit) =>
        With(enumMembers: new Dictionary<(string, string), NativeEnumMemberEdit>(EnumMembers) { [(edit.Enum, edit.Member)] = edit });

    /// <summary>With a struct or union member edit, replacing (and moving after the others) an earlier edit of the same member.</summary>
    public UserTypeLayer WithField(NativeFieldEdit edit) =>
        With(fields: Fields.Where(f => f.Type != edit.Type || f.Key != edit.Key).Append(edit).ToList());

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

    /// <summary>With a declaration block added (an identical block is kept once); a rename or deletion of a type it declares is dropped.</summary>
    public UserTypeLayer WithDeclarations(string block, IEnumerable<string>? declared = null)
    {
        var text = block.Trim();
        var names = declared?.ToHashSet(StringComparer.Ordinal) ?? [];
        var edits = TypeEdits.Any(e => names.Contains(e.Name)) ? TypeEdits.Where(e => !names.Contains(e.Name)).ToList() : null;
        if (text.Length == 0 || Declarations.Contains(text, StringComparer.Ordinal)) return edits == null ? this : With(typeEdits: edits);
        return With(declarations: [.. Declarations, text], typeEdits: edits);
    }

    /// <summary>
    /// With a type renamed or deleted, replacing an earlier edit of the same name. A rename renames the type in the other
    /// edits (declarations, types, locals, stack members, data, operands, enum and struct members); a deletion drops its member edits.
    /// </summary>
    public UserTypeLayer WithTypeEdit(NativeTypeEdit edit)
    {
        var layer = edit.NewName is { } to ? Renamed(edit.Name, to)
            : With(enumMembers: EnumMembers.Where(e => e.Key.Enum != edit.Name).ToDictionary(e => e.Key, e => e.Value),
                fields: Fields.Where(f => f.Type != edit.Name).ToList());
        return layer.With(typeEdits: layer.TypeEdits.Where(e => e.Name != edit.Name).Append(edit).ToList());
    }

    private UserTypeLayer Renamed(string from, string to)
    {
        var word = new Regex($@"(?<![\w$]){Regex.Escape(from)}(?![\w$])", RegexOptions.CultureInvariant);
        string R(string text) => word.Replace(text, to);
        string? N(string? text) => text == null ? null : R(text);
        return With(declarations: Declarations.Select(R).Distinct(StringComparer.Ordinal).ToList(),
            types: Types.ToDictionary(t => t.Key, t => R(t.Value)),
            locals: Locals.ToDictionary(l => l.Key, l => (IReadOnlyList<NativeLocalEdit>)[.. l.Value.Select(e => e with { Type = N(e.Type) })]),
            stackVars: StackVars.ToDictionary(s => s.Key, s => (IReadOnlyList<NativeStackVarEdit>)[.. s.Value.Select(e => e with { Type = N(e.Type) })]),
            analysis: Analysis.Select(a => a with { Type = N(a.Type) }).ToList(),
            operands: Operands.ToDictionary(o => o.Key, o => o.Value.Display is "enum" or "struct" ? o.Value with { Detail = N(o.Value.Detail) } : o.Value),
            enumMembers: EnumMembers.Values.Select(e => e.Enum == from ? e with { Enum = to } : e).ToDictionary(e => (e.Enum, e.Member)),
            typeEdits: TypeEdits.Select(e => e.NewName == from ? e with { NewName = to } : e).ToList(),
            fields: Fields.Select(f => f with { Type = f.Type == from ? to : f.Type, FieldType = N(f.FieldType) }).ToList());
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

    /// <summary>The edit of the function's local that <paramref name="local"/> names (by stack offset, its first name or the name it got), or null.</summary>
    public NativeLocalEdit? LocalEdit(uint function, string local, int? stack) =>
        Locals.TryGetValue(function, out var list)
            ? list.FirstOrDefault(e => (stack != null && e.Stack == stack) || e.Local == local || (e.Name != null && e.Name == local)) : null;

    /// <summary>Without <paramref name="edit"/> (a cleared local).</summary>
    public UserTypeLayer WithoutLocal(NativeLocalEdit edit)
    {
        if (!Locals.TryGetValue(edit.Function, out var list) || !list.Contains(edit)) return this;
        var locals = new Dictionary<uint, IReadOnlyList<NativeLocalEdit>>(Locals);
        var rest = list.Where(e => e != edit).ToList();
        if (rest.Count == 0) locals.Remove(edit.Function);
        else locals[edit.Function] = rest;
        return With(locals: locals);
    }

    /// <summary>Without the stack member edit at <paramref name="offset"/> of <paramref name="function"/> (a cleared member).</summary>
    public UserTypeLayer WithoutStackVar(uint function, int offset)
    {
        if (!StackVars.TryGetValue(function, out var list) || list.All(e => e.Offset != offset)) return this;
        var stack = new Dictionary<uint, IReadOnlyList<NativeStackVarEdit>>(StackVars);
        var rest = list.Where(e => e.Offset != offset).ToList();
        if (rest.Count == 0) stack.Remove(function);
        else stack[function] = rest;
        return With(stackVars: stack);
    }

    /// <summary>With a stack member edit merged into the edit at the same offset; a deletion, or an edit after one, replaces it.</summary>
    public UserTypeLayer WithStackVar(NativeStackVarEdit edit)
    {
        var list = StackVars.TryGetValue(edit.Function, out var existing) ? existing.ToList() : [];
        int i = list.FindIndex(e => e.Offset == edit.Offset);
        if (i >= 0) list[i] = edit.Delete || list[i].Delete ? edit : list[i] with { Name = edit.Name ?? list[i].Name, Type = edit.Type ?? list[i].Type };
        else list.Add(edit);
        return With(stackVars: new Dictionary<uint, IReadOnlyList<NativeStackVarEdit>>(StackVars) { [edit.Function] = list });
    }
}
