using Corvus.Native.Providers;

namespace Corvus.Native.Annotations;

/// <summary>
/// What one edit changed in a <see cref="UserTypeLayer"/>: per keyed item (a declaration block, a type at an RVA, a local,
/// a stack member, ...) the value before and after; null is absent. Undo puts the before values back where an item still
/// holds its after value.
/// </summary>
public sealed record UserTypeDelta(IReadOnlyList<UserTypeDelta.Item> Items)
{
    /// <summary>One changed item: <see cref="Key"/> is the component letter and the item's key ("T:4a10", "L:4a10:v1").</summary>
    public sealed record Item(string Key, object? Before, object? After);

    public bool IsEmpty => Items.Count == 0;

    public static UserTypeDelta Between(UserTypeLayer before, UserTypeLayer after)
    {
        if (ReferenceEquals(before, after)) return new([]);
        var b = Flatten(before).ToDictionary(i => i.Key, i => i.Value, StringComparer.Ordinal);
        var a = Flatten(after).ToDictionary(i => i.Key, i => i.Value, StringComparer.Ordinal);
        var items = new List<Item>();
        foreach (var (key, value) in b)
            if (!a.TryGetValue(key, out var now) || !Equals(now, value)) items.Add(new(key, value, a.GetValueOrDefault(key)));
        foreach (var (key, value) in a)
            if (!b.ContainsKey(key)) items.Add(new(key, null, value));
        return new(items);
    }

    /// <summary>
    /// <paramref name="current"/> with this edit's items put back to their before values; an item changed again since (it no
    /// longer holds the after value) is left and named in <paramref name="conflicts"/>.
    /// </summary>
    public UserTypeLayer Revert(UserTypeLayer current, out IReadOnlyList<string> conflicts)
    {
        var list = Flatten(current).ToList();
        var found = new List<string>();
        foreach (var item in Items)
        {
            int i = list.FindIndex(x => x.Key == item.Key);
            var now = i >= 0 ? list[i].Value : null;
            if (!Equals(now, item.After)) { found.Add(item.Key); continue; }
            if (item.Before == null) { if (i >= 0) list.RemoveAt(i); }
            else if (i >= 0) list[i] = (item.Key, item.Before);
            else list.Add((item.Key, item.Before));
        }
        conflicts = found;
        return Build(list);
    }

    /// <summary>
    /// The engine batch that puts the before values back: before values as edits, and for items the edit added, the
    /// clearing form (an empty type, a cleared local or stack member, a removed enum or struct member, the default operand
    /// display, the reverse rename). Items an engine cannot take back (a declaration, a type deletion, an analysis edit
    /// with nothing before it) are named in <paramref name="irreversible"/>.
    /// </summary>
    public NativeUserTypeBatch Inverse(UserTypeLayer reverted, out IReadOnlyList<string> irreversible)
    {
        var types = new List<NativePrototype>();
        var stack = new List<NativeStackVarEdit>();
        var locals = new List<NativeLocalEdit>();
        var enums = new List<NativeEnumMemberEdit>();
        var fields = new List<NativeFieldEdit>();
        var analysis = new List<NativeAnalysisEdit>();
        var operands = new List<NativeOperandEdit>();
        var renames = new List<NativeTypeEdit>();
        var declarations = new List<string>();
        var lost = new List<string>();
        foreach (var item in Items)
            switch (item.Before ?? item.After)
            {
                case string when item.Key.StartsWith("T:", StringComparison.Ordinal):
                    types.Add(new NativePrototype(Rva(item.Key), item.Before as string ?? ""));
                    break;
                case string block:
                    if (item.Before != null) declarations.Add(block);
                    else lost.Add($"declaration '{Clip(block)}'");
                    break;
                case NativeLocalEdit l:
                    locals.Add(item.Before as NativeLocalEdit ?? l with { Local = l.Name ?? l.Local, Name = null, Type = null, Clear = true });
                    break;
                case NativeStackVarEdit s:
                    stack.Add(item.Before as NativeStackVarEdit ?? s with { Name = null, Type = null, Delete = false, Clear = true });
                    break;
                case NativeEnumMemberEdit e:
                    enums.Add(item.Before as NativeEnumMemberEdit ?? e with { Value = null });
                    break;
                case NativeFieldEdit f:
                    fields.Add(item.Before as NativeFieldEdit ?? f with { FieldType = null });
                    break;
                case NativeOperandEdit o:
                    operands.Add(item.Before as NativeOperandEdit ?? o with { Display = "default", Detail = null });
                    break;
                case NativeAnalysisEdit a:
                    if (item.Before is NativeAnalysisEdit was) analysis.Add(was);
                    else if (a.Kind == NativeAnalysisEdit.Undefine) analysis.Add(a with { Kind = NativeAnalysisEdit.Code, End = null, Type = null });
                    else
                    {
                        analysis.Add(a with { Kind = NativeAnalysisEdit.Undefine, Type = null });
                        if (a.Kind is NativeAnalysisEdit.Function or NativeAnalysisEdit.Code) analysis.Add(a with { Kind = NativeAnalysisEdit.Code, End = null, Type = null });
                    }
                    break;
                case NativeTypeEdit t:
                    if (item.Before is NativeTypeEdit) lost.Add($"type edit of '{t.Name}' (the engine keeps the later one)");
                    else if (t.NewName is { } to) renames.Add(new NativeTypeEdit(to, t.Name));
                    else lost.Add($"deletion of type '{t.Name}'");
                    break;
            }
        irreversible = lost;
        return new NativeUserTypeBatch(declarations, types, stack, locals)
        {
            EnumMembers = enums,
            Fields = fields,
            Analysis = analysis,
            Operands = operands,
            TypeEdits = renames.Count == 0 ? null : [.. reverted.TypeEdits, .. renames],
        };
    }

    /// <summary>One line per item: "type at rva 0x4A10: int f(void) -> (none)".</summary>
    public IEnumerable<(string Kind, string Target, string? Before, string? After)> Describe() => Items.Select(i =>
    {
        var (kind, target) = KindAndTarget(i.Key, i.Before ?? i.After);
        return (kind, target, Text(i.Before), Text(i.After));
    });

    private static (string Kind, string Target) KindAndTarget(string key, object? value) => value switch
    {
        string when key.StartsWith("T:", StringComparison.Ordinal) => ("type", $"rva 0x{Rva(key):X}"),
        string block => ("declaration", Clip(block)),
        NativeLocalEdit l => ("local", $"{l.Local} in rva 0x{l.Function:X}"),
        NativeStackVarEdit s => ("stack", $"+0x{s.Offset:X} in rva 0x{s.Function:X}"),
        NativeEnumMemberEdit e => ("enum", $"{e.Enum}::{e.Member}"),
        NativeFieldEdit f => ("field", $"{f.Type}::{f.Key}"),
        NativeOperandEdit o => ("operand", $"rva 0x{o.Rva:X} operand {o.Operand}"),
        NativeAnalysisEdit a => ("analysis", $"rva 0x{a.Rva:X}"),
        NativeTypeEdit t => ("type_edit", t.Name),
        _ => ("type", key),
    };

    private static string? Text(object? value) => value switch
    {
        null => null,
        string s => Clip(s),
        NativeLocalEdit l => l.Clear ? "(cleared)" : string.Join(" ", new[] { l.Type, l.Name }.Where(x => x != null)),
        NativeStackVarEdit s => s.Delete ? "(deleted)" : s.Clear ? "(cleared)" : string.Join(" ", new[] { s.Type, s.Name }.Where(x => x != null)),
        NativeEnumMemberEdit e => e.Value?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "(removed)",
        NativeFieldEdit f => f.FieldType ?? "(removed)",
        NativeOperandEdit o => o.Detail is { } d ? $"{o.Display} {d}" : o.Display,
        NativeAnalysisEdit a => a.Kind + (a.Type is { } t ? $" {t}" : "") + (a.End is { } e ? $" to rva 0x{e:X}" : ""),
        NativeTypeEdit t => t.NewName ?? "(deleted)",
        _ => value.ToString(),
    };

    private static string Clip(string s)
    {
        var line = s.ReplaceLineEndings(" ");
        return line.Length > 80 ? line[..77] + "..." : line;
    }

    private static uint Rva(string key) => uint.Parse(key.AsSpan(2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);

    private static string H(uint v) => v.ToString("x", System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>The layer as keyed items, in the order the layer keeps them.</summary>
    private static IEnumerable<(string Key, object Value)> Flatten(UserTypeLayer layer)
    {
        foreach (var d in layer.Declarations) yield return ("D:" + d, d);
        foreach (var t in layer.TypeEdits) yield return ("R:" + t.Name, t);
        foreach (var e in layer.EnumMembers.Values) yield return ($"E:{e.Enum}::{e.Member}", e);
        foreach (var f in layer.Fields) yield return ($"F:{f.Type}::{f.Key}", f);
        foreach (var a in layer.Analysis) yield return ("A:" + H(a.Rva), a);
        foreach (var (rva, type) in layer.Types) yield return ("T:" + H(rva), type);
        foreach (var l in layer.Locals.Values.SelectMany(l => l)) yield return ($"L:{H(l.Function)}:{l.Local}", l);
        foreach (var s in layer.StackVars.Values.SelectMany(s => s)) yield return (FormattableString.Invariant($"S:{H(s.Function)}:{s.Offset}"), s);
        foreach (var o in layer.Operands.Values) yield return (FormattableString.Invariant($"O:{H(o.Rva)}:{o.Operand}"), o);
    }

    private static UserTypeLayer Build(List<(string Key, object Value)> items)
    {
        var declarations = new List<string>();
        var types = new Dictionary<uint, string>();
        var locals = new Dictionary<uint, List<NativeLocalEdit>>();
        var stack = new Dictionary<uint, List<NativeStackVarEdit>>();
        var analysis = new List<NativeAnalysisEdit>();
        var operands = new Dictionary<(uint, int), NativeOperandEdit>();
        var enums = new Dictionary<(string, string), NativeEnumMemberEdit>();
        var typeEdits = new List<NativeTypeEdit>();
        var fields = new List<NativeFieldEdit>();
        foreach (var (key, value) in items)
            switch (value)
            {
                case string t when key.StartsWith("T:", StringComparison.Ordinal): types[Rva(key)] = t; break;
                case string d: declarations.Add(d); break;
                case NativeTypeEdit t: typeEdits.Add(t); break;
                case NativeEnumMemberEdit e: enums[(e.Enum, e.Member)] = e; break;
                case NativeFieldEdit f: fields.Add(f); break;
                case NativeAnalysisEdit a: analysis.Add(a); break;
                case NativeLocalEdit l: (locals.TryGetValue(l.Function, out var ll) ? ll : locals[l.Function] = []).Add(l); break;
                case NativeStackVarEdit s: (stack.TryGetValue(s.Function, out var sl) ? sl : stack[s.Function] = []).Add(s); break;
                case NativeOperandEdit o: operands[(o.Rva, o.Operand)] = o; break;
            }
        return new UserTypeLayer(declarations, types, locals.ToDictionary(l => l.Key, l => (IReadOnlyList<NativeLocalEdit>)l.Value),
            stack.ToDictionary(s => s.Key, s => (IReadOnlyList<NativeStackVarEdit>)s.Value), analysis, operands, enums, typeEdits, fields);
    }
}
