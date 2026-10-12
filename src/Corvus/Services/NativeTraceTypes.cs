using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Calls;
using Corvus.Native.Code;
using Corvus.Native.Msvc;
using Corvus.Native.Pdb;

namespace Corvus.Services;

/// <summary>
/// Pointer types of function parameters for value tracing through struct fields, per loaded image: the user's function
/// types (set_native_type), the PDB's procedure types and RTTI (a vftable slot's this is its class; a primary vftable
/// stored at +0 constructs its class). The user's types win over the PDB's, the PDB's over RTTI.
/// </summary>
internal sealed partial class NativeTraceTypes : ITraceTypes
{
    private const int MaxProcedures = 200_000;
    private readonly Dictionary<NativeCodeIndex, Image> _images = [];
    private readonly Func<NativeCodeIndex, LoadedNative?> _native;
    private readonly Func<LoadedNative, UserTypeLayer> _userTypes;

    public NativeTraceTypes(AssemblyWorkspace workspace, NativeCodeService code)
    {
        var natives = workspace.Read(() => workspace.Natives.ToList());
        _native = index => natives.FirstOrDefault(n => code.Ready(n) == index);
        _userTypes = n => code.Annotations(n).UserTypes;
        Key = string.Join(",", natives.Select(n => $"{n.Id}:{_userTypes(n).Types.Count}:{(PdbService.StateOf(n)?.Pdb is { } p ? PdbService.Identity(p) : "")}"));
    }

    /// <param name="native">The loaded image of a code index.</param>
    internal NativeTraceTypes(Func<NativeCodeIndex, LoadedNative?> native, Func<LoadedNative, UserTypeLayer> userTypes, string key)
    {
        _native = native;
        _userTypes = userTypes;
        Key = key;
    }

    private sealed class Image
    {
        public readonly Dictionary<uint, Dictionary<string, string>> ByFunction = [];
        public readonly Dictionary<string, List<(uint Start, string Location)>> ByType = new(StringComparer.Ordinal);
        public PdbTypeModel? Model;
        public readonly Dictionary<string, List<uint>> Vftables = new(StringComparer.Ordinal);
        public string Key = "";

        public void Add(uint start, string location, string type)
        {
            if (!ByFunction.TryGetValue(start, out var ps)) ByFunction[start] = ps = new Dictionary<string, string>(StringComparer.Ordinal);
            if (!ps.TryAdd(location, type)) return;
            if (!ByType.TryGetValue(type, out var list)) ByType[type] = list = [];
            list.Add((start, location));
        }
    }

    public string Key { get; }

    public string? ParameterType(ITraceHost host, NativeFunction f, string location) =>
        Of(host).ByFunction.GetValueOrDefault(f.Start)?.GetValueOrDefault(location);

    public IReadOnlyList<(NativeFunction Function, string Location)> Holders(ITraceHost host, string type)
    {
        var list = Of(host).ByType.GetValueOrDefault(type) ?? [];
        return list.Select(h => (host.Index.FunctionByStart(h.Start), h.Location)).Where(h => h.Item1 != null).Select(h => (h.Item1!, h.Location))
            .OrderBy(h => h.Item1.Start).ToList();
    }

    public string? Member(ITraceHost host, string type, long offset)
    {
        if (Of(host).Model is not { } model) return null;
        foreach (var index in model.Named(type))
            if (model.Node(model.DefinitionOf(index) is > 0 and var d ? d : index) is { IsAggregate: true } node)
                return node.Members.FirstOrDefault(m => m.Kind == PdbMemberKind.Data && m.Offset == offset)?.Name;
        return null;
    }

    public IReadOnlyList<uint> Vftables(ITraceHost host, string type)
    {
        var image = Of(host);
        return image.Vftables.GetValueOrDefault(type) ?? [];
    }

    private Image Of(ITraceHost host)
    {
        lock (_images)
        {
            if (_images.TryGetValue(host.Index, out var hit)) return hit;
            var image = new Image();
            if (_native(host.Index) is { } native)
            {
                foreach (var (rva, decl) in _userTypes(native).Types)
                    if (host.Index.FunctionByStart(rva) != null) Prototype(host, rva, decl, image);
                if (PdbService.StateOf(native)?.Pdb is { } pdb) Pdb(host, pdb, image);
                if (native.Image.Format == ImageFormat.Pe) Rtti(host, native, image);
            }
            _images[host.Index] = image;
            return image;
        }
    }

    /// <summary>The pointee types of a C prototype's parameters ("int __fastcall f(struct Widget *w, int n)").</summary>
    private static void Prototype(ITraceHost host, uint start, string decl, Image image)
    {
        int close = decl.LastIndexOf(')'), depth = 0, open = -1;
        for (int i = close; i >= 0; i--)
        {
            if (decl[i] == ')') depth++;
            else if (decl[i] == '(' && --depth == 0) { open = i; break; }
        }
        if (open < 0) return;
        var head = decl[..open];
        var parts = Split(decl[(open + 1)..close]);
        var types = parts.Select(Pointee).ToList();
        var floats = parts.Select(p => FloatType().IsMatch(p)).ToList();
        Place(host, start, types, floats, head.Contains("__thiscall", StringComparison.Ordinal), head.Contains("__fastcall", StringComparison.Ordinal), image);
    }

    private static List<string> Split(string list)
    {
        var result = new List<string>();
        int depth = 0, from = 0;
        for (int i = 0; i < list.Length; i++)
        {
            if (list[i] is '(' or '<' or '[') depth++;
            else if (list[i] is ')' or '>' or ']') depth--;
            else if (list[i] == ',' && depth == 0) { result.Add(list[from..i].Trim()); from = i + 1; }
        }
        if (list[from..].Trim() is { Length: > 0 } last && last != "void") result.Add(last);
        return result;
    }

    /// <summary>"struct Widget *w" -> Widget; null when not a single pointer to a named type.</summary>
    private static string? Pointee(string parameter)
    {
        var m = PointerParameter().Match(parameter);
        if (!m.Success) return null;
        var name = m.Groups[1].Value;
        return Primitive().IsMatch(name) ? null : name;
    }

    /// <summary>Entry locations by parameter position: x86 thiscall / fastcall registers, AAPCS64 integer registers counted apart from floating point.</summary>
    private static void Place(ITraceHost host, uint start, List<string?> types, List<bool> floats, bool thiscall, bool fastcall, Image image)
    {
        bool x86 = !host.Is64, arm = host is Arm64Trace;
        int stack = 0, ints = 0;
        for (int i = 0; i < types.Count; i++)
        {
            string location;
            if (x86 && thiscall && i == 0) location = "ecx";
            else if (x86 && fastcall && ints < 2 && !floats[i]) location = ints++ == 0 ? "ecx" : "edx";
            else if (arm) location = floats[i] ? "" : host.ParameterLocation(ints++);
            else location = host.ParameterLocation(x86 ? stack++ : i);
            if (types[i] is { } t && location.Length > 0) image.Add(start, location, t);
        }
    }

    private static void Pdb(ITraceHost host, PdbFile pdb, Image image)
    {
        PdbTypeModel model;
        try { model = PdbTypeModel.Of(pdb, host.Is64 ? 8 : 4); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException) { return; }
        image.Model = model;
        int n = 0;
        foreach (var s in pdb.Symbols)
        {
            if (s.Kind is not (PdbSymbolKind.GlobalProc or PdbSymbolKind.LocalProc) || s.Rva is not { } rva || s.TypeIndex == 0) continue;
            if (++n > MaxProcedures) break;
            if (model.FunctionTypeOf(s.TypeIndex) is not (> 0 and var type) || model.Node(type)?.Function is not { } fn) continue;
            var parameters = new List<uint>();
            if (fn.This != 0) parameters.Add(fn.This);
            parameters.AddRange(fn.Parameters);
            var types = parameters.Select(p => PdbPointee(model, p)).ToList();
            var floats = parameters.Select(p => model.Spell(p) is "float" or "double" or "long double").ToList();
            Place(host, rva, types, floats, fn.Convention == "__thiscall" || fn.This != 0 && !host.Is64, fn.Convention == "__fastcall", image);
        }
    }

    private static string? PdbPointee(PdbTypeModel model, uint type)
    {
        var node = model.Node(type);
        while (node is { Kind: PdbTypeKind.Modifier }) node = model.Node(node.Element);
        if (node is not { Kind: PdbTypeKind.Pointer }) return null;
        var target = model.Node(node.Element);
        while (target is { Kind: PdbTypeKind.Modifier }) target = model.Node(target.Element);
        return target is { IsAggregate: true } a ? a.Name : null;
    }

    private static void Rtti(ITraceHost host, LoadedNative native, Image image)
    {
        var rtti = native.GetAnalysis(n => Native.Itanium.CppRtti.Analyze(n.Image));
        var location = host.Is64 ? host.ParameterLocation(0) : "ecx";
        foreach (var c in rtti.Classes)
            foreach (var v in c.Vtables.Where(v => v.Offset == 0))
            {
                if (!image.Vftables.TryGetValue(c.Name, out var list)) image.Vftables[c.Name] = list = [];
                list.Add(v.VftableRva);
                foreach (var slot in v.SlotRvas)
                    if (host.Index.FunctionByStart(slot) != null) image.Add(slot, location, c.Name);
            }
    }

    [GeneratedRegex(@"^(?:const\s+|volatile\s+)*(?:struct\s+|class\s+|union\s+)?((?:\w+::)*\w+)\s*(?:const\s*)?\*\s*(?:const\s*)?\w*$", RegexOptions.CultureInvariant)]
    private static partial Regex PointerParameter();

    [GeneratedRegex(@"^(?:void|char|short|int|long|float|double|bool|signed|unsigned|wchar_t|__int\d+|u?int\d+_t|size_t|BYTE|WORD|DWORD|QWORD|CHAR|WCHAR|BOOL|HANDLE|LPVOID)$", RegexOptions.CultureInvariant)]
    private static partial Regex Primitive();

    [GeneratedRegex(@"^(?:const\s+)?(?:float|double|long double)(?:\s+\w+)?$", RegexOptions.CultureInvariant)]
    private static partial Regex FloatType();
}
