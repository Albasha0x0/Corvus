using System.Security.Cryptography;
using System.Text;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Native.Annotations;

/// <summary>
/// The user's engine types of one image: C declarations, types of functions and globals by RVA, stack frame members and
/// decompiler locals by function. Immutable; every change makes a new layer.
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

    public UserTypeLayer(IReadOnlyList<string> declarations, IReadOnlyDictionary<uint, string> types, IReadOnlyDictionary<uint, IReadOnlyList<NativeLocalEdit>> locals,
        IReadOnlyDictionary<uint, IReadOnlyList<NativeStackVarEdit>> stackVars)
    {
        Declarations = declarations;
        Types = types;
        Locals = locals;
        StackVars = stackVars;
    }

    public bool IsEmpty => Declarations.Count == 0 && Types.Count == 0 && Locals.Count == 0 && StackVars.Count == 0;

    /// <summary>Declaration blocks, types, locals and stack members.</summary>
    public int Count => Declarations.Count + Types.Count + Locals.Values.Sum(l => l.Count) + StackVars.Values.Sum(s => s.Count);

    /// <summary>Everything, in the order an engine applies it.</summary>
    public NativeUserTypeBatch ToBatch() => new(Declarations,
        Types.OrderBy(t => t.Key).Select(t => new NativePrototype(t.Key, t.Value)).ToList(),
        StackVars.OrderBy(s => s.Key).SelectMany(s => s.Value).ToList(),
        Locals.OrderBy(l => l.Key).SelectMany(l => l.Value).ToList());

    private string? _stamp;

    /// <summary>SHA-256 of the content.</summary>
    public string Stamp => _stamp ??= ComputeStamp();

    private string ComputeStamp()
    {
        if (IsEmpty) return "";
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        void Add(string s) => hash.AppendData(Encoding.UTF8.GetBytes(s + "\0"));
        foreach (var d in Declarations) Add("D" + d);
        foreach (var (rva, type) in Types.OrderBy(t => t.Key)) Add(FormattableString.Invariant($"T{rva:X}:{type}"));
        foreach (var s in StackVars.OrderBy(s => s.Key).SelectMany(s => s.Value)) Add(FormattableString.Invariant($"S{s.Function:X}:{s.Offset}:{s.Name}:{s.Type}"));
        foreach (var l in Locals.OrderBy(l => l.Key).SelectMany(l => l.Value)) Add(FormattableString.Invariant($"L{l.Function:X}:{l.Local}:{l.Stack}:{l.Name}:{l.Type}"));
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    /// <summary>With the type at <paramref name="rva"/> set, or removed when <paramref name="type"/> is empty.</summary>
    public UserTypeLayer WithType(uint rva, string? type)
    {
        var types = new Dictionary<uint, string>(Types);
        if (string.IsNullOrWhiteSpace(type)) types.Remove(rva);
        else types[rva] = type.Trim();
        return new(Declarations, types, Locals, StackVars);
    }

    /// <summary>With a declaration block added (an identical block is kept once).</summary>
    public UserTypeLayer WithDeclarations(string block)
    {
        var text = block.Trim();
        if (text.Length == 0 || Declarations.Contains(text, StringComparer.Ordinal)) return this;
        return new([.. Declarations, text], Types, Locals, StackVars);
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
        return new(Declarations, Types, new Dictionary<uint, IReadOnlyList<NativeLocalEdit>>(Locals) { [edit.Function] = list }, StackVars);
    }

    /// <summary>With a stack member edit merged into the edit at the same offset.</summary>
    public UserTypeLayer WithStackVar(NativeStackVarEdit edit)
    {
        var list = StackVars.TryGetValue(edit.Function, out var existing) ? existing.ToList() : [];
        int i = list.FindIndex(e => e.Offset == edit.Offset);
        if (i >= 0) list[i] = list[i] with { Name = edit.Name ?? list[i].Name, Type = edit.Type ?? list[i].Type };
        else list.Add(edit);
        return new(Declarations, Types, Locals, new Dictionary<uint, IReadOnlyList<NativeStackVarEdit>>(StackVars) { [edit.Function] = list });
    }
}
