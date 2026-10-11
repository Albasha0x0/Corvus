using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Resources;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services.Analysis;

/// <summary>Textual location such as "Ns.Type::Method(int) @IL_0012"; Api is the API the item is passed to.</summary>
public sealed record Location(string Where, string? Api = null)
{
    public override string ToString() => Api == null ? Where : $"{Where} -> {Api}";
}

/// <summary>
/// Single pass over a module collecting API calls, strings with their consuming APIs, P/Invoke imports, static field
/// data and resources. Unreadable types and resources are skipped with a note.
/// </summary>
public sealed class ModuleScan
{
    /// <summary>A method reference: Api is "Ns.Type::Name", <see cref="Signature"/> adds parameter types; Index is its place in <see cref="Calls"/>.</summary>
    public sealed record ApiUse(MethodDef Caller, uint Offset, string Api, IMethod Target, int Index)
    {
        public string Signature => $"{Api}({string.Join(",", Target.MethodSig?.Params.Select(p => p.FullName) ?? [])})";
    }

    /// <summary>A string literal or constant; Consumers are the next APIs called after it.</summary>
    public sealed record CodeString(string Value, Location Location, MethodDef? Method, IReadOnlyList<string> Consumers);

    public sealed record NativeImport(MethodDef Method, string Module, string Entry);

    /// <summary>A static field with initial data (e.g. array initializers) and the methods using it.</summary>
    public sealed record FieldData(FieldDef Field, byte[] Data, IReadOnlyList<MethodDef> UsedIn);

    /// <summary>An embedded resource, or one byte[] / stream / string entry of a .resources container.</summary>
    public sealed record ResourceBlob(string Name, byte[]? Bytes, string? Text);

    /// <summary>Instructions after a string searched for consuming APIs.</summary>
    private const int ConsumerWindow = 12;

    public ModuleDef Module { get; }
    public List<ApiUse> Calls { get; } = [];
    public List<CodeString> Strings { get; } = [];
    public List<NativeImport> Imports { get; } = [];
    public List<FieldData> Data { get; } = [];
    public List<ResourceBlob> Resources { get; } = [];
    public List<string> Notes { get; } = [];
    public Dictionary<MethodDef, HashSet<string>> ApisByMethod { get; } = [];
    public int MethodsScanned { get; private set; }

    /// <summary>Calls grouped by API, in order of first use: rules match each API name once instead of every call.</summary>
    public IReadOnlyDictionary<string, List<ApiUse>> CallsByApi => _callsByApi ??= Calls.GroupBy(c => c.Api, StringComparer.Ordinal)
        .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.Ordinal);

    private Dictionary<string, List<ApiUse>>? _callsByApi;
    // A large assembly makes hundreds of thousands of calls to far fewer distinct targets (dnlib keeps one object per token).
    private readonly Dictionary<IMethod, string?> _apiNames = new(ReferenceEqualityComparer.Instance);

    private ModuleScan(ModuleDef module) => Module = module;

    /// <param name="instructions">Method body reader (fast reader or dnlib).</param>
    public static ModuleScan Run(ModuleDef module, Func<MethodDef, IList<Instruction>> instructions, AnalysisLimits limits, CancellationToken ct)
    {
        var scan = new ModuleScan(module);
        var fieldUses = new Dictionary<FieldDef, List<MethodDef>>();
        List<TypeDef> types;
        try { types = module.GetTypes().ToList(); }
        catch (Exception ex) { scan.Notes.Add($"Type table unreadable: {ex.Message}"); types = []; }

        foreach (var type in types)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var field in type.Fields)
                {
                    if (field.HasConstant && field.Constant?.Value is string constant && constant.Length > 0)
                        scan.Strings.Add(new CodeString(constant, new Location($"const {Format.MemberLabel(field)}"), null, []));
                }
                foreach (var method in type.Methods)
                {
                    if (method.ImplMap is { } map)
                        scan.Imports.Add(new NativeImport(method, map.Module?.Name.String ?? "", map.Name.String));
                    if (!method.HasBody && method.RVA == 0) continue;
                    scan.ScanBody(method, instructions(method), fieldUses);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                scan.Notes.Add($"{type.FullName}: skipped ({ex.GetType().Name}).");
            }
        }

        foreach (var (field, users) in fieldUses)
        {
            byte[]? data = MetadataUtil.Try(() => field.InitialValue);
            if (data is { Length: > 0 }) scan.Data.Add(new FieldData(field, data, users));
        }
        scan.ReadResources(limits);
        return scan;
    }

    private void ScanBody(MethodDef method, IList<Instruction> body, Dictionary<FieldDef, List<MethodDef>> fieldUses)
    {
        MethodsScanned++;
        var apis = new HashSet<string>(StringComparer.Ordinal);
        ApisByMethod[method] = apis;
        string? label = null;
        for (int i = 0; i < body.Count; i++)
        {
            var instr = body[i];
            switch (instr.OpCode.Code)
            {
                case Code.Call or Code.Callvirt or Code.Newobj or Code.Ldftn or Code.Ldvirtftn:
                    if (MetadataUtil.AsMethod(instr.Operand) is { } target && CachedApiName(target) is { } api)
                    {
                        Calls.Add(new ApiUse(method, instr.Offset, api, target, Calls.Count));
                        apis.Add(api);
                    }
                    break;
                case Code.Ldstr when instr.Operand is string s && s.Length > 0:
                    label ??= Format.MemberLabel(method);
                    Strings.Add(new CodeString(s, new Location($"{label} @IL_{instr.Offset:X4}"), method, Consumers(body, i)));
                    break;
                case Code.Ldtoken or Code.Ldsfld or Code.Ldsflda when MetadataUtil.AsField(instr.Operand) is { } f
                                                                      && MetadataUtil.Try(() => f.ResolveFieldDef()) is { HasFieldRVA: true } fd:
                    if (!fieldUses.TryGetValue(fd, out var users)) fieldUses[fd] = users = [];
                    if (!users.Contains(method)) users.Add(method);
                    break;
            }
        }
    }

    private string? CachedApiName(IMethod method)
    {
        if (!_apiNames.TryGetValue(method, out var name)) _apiNames[method] = name = ApiName(method);
        return name;
    }

    /// <summary>Up to three APIs called shortly after <paramref name="at"/>.</summary>
    private List<string> Consumers(IList<Instruction> body, int at)
    {
        var list = new List<string>();
        for (int j = at + 1; j < body.Count && j <= at + ConsumerWindow && list.Count < 3; j++)
        {
            var code = body[j].OpCode.Code;
            if (code is Code.Ret or Code.Throw) break;
            if (code is Code.Call or Code.Callvirt or Code.Newobj && MetadataUtil.AsMethod(body[j].Operand) is { } m && CachedApiName(m) is { } api)
                list.Add(api);
        }
        return list;
    }

    /// <summary>"Ns.Type::Name" with generic arguments dropped and nested types as Outer/Inner.</summary>
    public static string? ApiName(IMethod method)
    {
        var type = method.DeclaringType;
        if (type == null) return null;
        var scope = type.ScopeType ?? type; // generic instance -> its definition
        return $"{scope.FullName}::{method.Name}";
    }

    private void ReadResources(AnalysisLimits limits)
    {
        List<EmbeddedResource> embedded;
        try { embedded = Module.Resources.OfType<EmbeddedResource>().ToList(); }
        catch (Exception ex) { Notes.Add($"Resource table unreadable: {ex.Message}"); return; }
        foreach (var res in embedded)
        {
            byte[] bytes;
            try { bytes = res.CreateReader().ToArray(); }
            catch (Exception) { Notes.Add($"Resource '{res.Name}' unreadable."); continue; }
            if (bytes.Length > limits.MaxItemBytes) { Notes.Add($"Resource '{res.Name}' skipped: larger than the limit."); continue; }
            Resources.Add(new ResourceBlob(res.Name, bytes, null));
            if (!res.Name.String.EndsWith(".resources", StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                var set = ResourceReader.Read(Module, res.CreateReader());
                foreach (var element in set.ResourceElements)
                {
                    var name = $"{res.Name}:{element.Name}";
                    switch (element.ResourceData)
                    {
                        case BuiltInResourceData { Code: ResourceTypeCode.String, Data: string text }:
                            Resources.Add(new ResourceBlob(name, null, text));
                            break;
                        case BuiltInResourceData { Code: ResourceTypeCode.ByteArray or ResourceTypeCode.Stream, Data: byte[] data }:
                            Resources.Add(new ResourceBlob(name, data, null));
                            break;
                        case BinaryResourceData binary:
                            Resources.Add(new ResourceBlob(name, binary.Data, null));
                            break;
                    }
                }
            }
            catch (Exception)
            {
                Notes.Add($"Resource '{res.Name}' looks like a .resources container but could not be parsed.");
            }
        }
    }

    /// <summary>Scans a loaded assembly. Call under the workspace read lock.</summary>
    public static ModuleScan Of(LoadedAssembly asm, AnalysisLimits limits, CancellationToken ct) =>
        Run(asm.Module, m => FastIlReader.Instructions(asm, m), limits, ct);

    /// <summary>Scans a module that is not in the workspace.</summary>
    public static ModuleScan Of(ModuleDef module, AnalysisLimits limits, CancellationToken ct) =>
        Run(module, MetadataUtil.SafeInstructions, limits, ct);
}
