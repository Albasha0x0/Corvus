using System.Resources;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Corvus.Services.Simplify;

/// <summary>A ResourceManager over the module's own resources: its base name. Lookups never change it.</summary>
internal sealed class ResourceManagerObject(string baseName) : ReflectionObject
{
    public string BaseName { get; } = baseName;
    protected override string[] Types => ["System.Resources.ResourceManager"];
}

/// <summary>CultureInfo.InvariantCulture, also the current culture under the deterministic environment.</summary>
internal sealed class CultureObject : ReflectionObject
{
    public static readonly CultureObject Invariant = new();
    protected override string[] Types => ["System.Globalization.CultureInfo", "System.IFormatProvider"];
}

internal sealed partial class IlEvaluator
{
    private readonly Dictionary<FieldDef, ResourceManagerObject?> _lazyManagers = new();
    private readonly Dictionary<FieldDef, HashSet<MethodDef>> _lazyWriters = new();
    private readonly Dictionary<string, Dictionary<string, string?>?> _resourceTables = new(StringComparer.Ordinal);

    private static void AddResourceManager(Action<string, string, string, string, Func<IlEvaluator, object?[], object?>> add)
    {
        const string RM = "System.Resources.ResourceManager", S = "System.String", CI = "System.Globalization.CultureInfo";
        add("System.Void", RM, ".ctor", $"{S},System.Reflection.Assembly", (_, a) => a[1] is AssemblyObject
            ? new ResourceManagerObject(Str(a[0]))
            : throw Bail(FallbackReason.ExternalIo, "a ResourceManager over another assembly's resources"));
        add(S, RM, "GetString", S, (e, a) => e.ResourceString(a[0], a[1], null));
        add(S, RM, "GetString", $"{S},{CI}", (e, a) => e.ResourceString(a[0], a[1], a[2]));
        add(CI, CI, "get_InvariantCulture", "", (_, _) => CultureObject.Invariant);
    }

    /// <summary>ResourceManager.GetString from the module's neutral "baseName.resources" in the invariant culture; null when the key is absent.</summary>
    private string? ResourceString(object? manager, object? name, object? culture)
    {
        var rm = Of<ResourceManagerObject>(manager, "a ResourceManager");
        var key = Str(name);
        if (culture == null && !DeterministicEnvironment)
            throw Bail(FallbackReason.PlatformDependent, "a resource lookup in the current UI culture, which satellite assemblies may answer; the deterministicEnvironment option pins it to the invariant culture");
        if (culture != null && culture is not CultureObject) throw Bail(FallbackReason.UnsupportedValue, "a resource lookup in a culture the interpreter does not model");
        if (module.Assembly?.CustomAttributes.FirstOrDefault(a => a.TypeFullName == "System.Resources.NeutralResourcesLanguageAttribute") is { ConstructorArguments.Count: 2 } neutral &&
            neutral.ConstructorArguments[1].Value is int location && location != 0)
            throw Bail(FallbackReason.ExternalIo, "the neutral resources live in a satellite assembly (NeutralResourcesLanguage)");
        var table = ResourceTable(rm.BaseName) ?? throw Bail(FallbackReason.RuntimeError, $"no resources named {rm.BaseName}.resources (MissingManifestResourceException)");
        return table.TryGetValue(key, out var value) ? value : null;
    }

    /// <summary>The strings of an embedded .resources file of the module, by name; null when there is none.</summary>
    private Dictionary<string, string?>? ResourceTable(string baseName)
    {
        if (_resourceTables.TryGetValue(baseName, out var cached)) return cached;
        Dictionary<string, string?>? table = null;
        if (ResourceBytes(baseName + ".resources") is { } bytes)
        {
            table = new Dictionary<string, string?>(StringComparer.Ordinal);
            try
            {
                using var reader = new ResourceReader(new MemoryStream(bytes, writable: false));
                var names = new List<string>();
                var enumerator = reader.GetEnumerator();
                while (enumerator.MoveNext()) names.Add((string)enumerator.Key);
                foreach (var entry in names)
                {
                    reader.GetResourceData(entry, out var type, out var data);
                    // A string entry is a 7-bit length and UTF-8 text; GetString throws on other entries.
                    table[entry] = type == "ResourceTypeCode.String" ? new BinaryReader(new MemoryStream(data)).ReadString() : null;
                }
            }
            catch (Exception ex) when (ex is BadImageFormatException or InvalidOperationException or ArgumentException or IOException or FormatException)
            {
                throw Bail(FallbackReason.InvalidCode, $"the resources {baseName}.resources cannot be read ({ex.Message})");
            }
        }
        _resourceTables[baseName] = table;
        return table;
    }

    /// <summary>The manager a lazily filled ResourceManager field always holds (generated <c>Resources.ResourceManager</c>), or null.</summary>
    private ResourceManagerObject? LazyManager(FieldDef field)
    {
        if (field.FieldType.FullName != "System.Resources.ResourceManager") return null;
        // Inside the getter the field is null until it creates the manager.
        if (CurrentMethod != null && _lazyWriters.TryGetValue(field, out var writers) && writers.Contains(CurrentMethod)) return null;
        if (_lazyManagers.TryGetValue(field, out var known)) return known;
        _lazyManagers[field] = null;
        List<(MethodDef Method, int Index)>? stores;
        using (Meter?.Exclude()) stores = _facts.LazyStores(field);
        if (stores == null || stores.Count == 0) return null;
        _lazyWriters[field] = stores.Select(st => st.Method).ToHashSet();
        ResourceManagerObject? manager = null;
        foreach (var (method, index) in stores)
        {
            var code = method.Body.Instructions;
            int created = index - 1;
            if (created >= 0 && code[created].IsLdloc() && code[created].GetLocal(method.Body.Variables) is { } temp)
            {
                var writes = Enumerable.Range(0, code.Count).Where(i => code[i].IsStloc() && code[i].GetLocal(method.Body.Variables) == temp).ToList();
                created = writes.Count == 1 ? writes[0] - 1 : -1;
            }
            if (created < 0 || code[created] is not { OpCode.Code: Code.Newobj, Operand: IMethod ctor } ||
                ctor.FullName != "System.Void System.Resources.ResourceManager::.ctor(System.String,System.Reflection.Assembly)")
                return null;
            int start = created;
            for (int needed = 2; needed > 0;)
            {
                if (--start < 0) return null;
                var ins = code[start];
                if (ins.OpCode.FlowControl is not (FlowControl.Next or FlowControl.Call) || ins.IsLdloc() || ins.IsLdarg() || ins.OpCode.OpCodeType == OpCodeType.Prefix) return null;
                ins.CalculateStackUsage(false, out int pushes, out int pops);
                if (pops < 0) return null;
                needed -= pushes;
                if (needed < 0) return null;
                needed += pops;
            }
            var slice = code.Skip(start).Take(created - start + 1).Select(i => new Instruction(i.OpCode, i.Operand)).ToList();
            var frame = new Frame(null, slice, [], [], [], []);
            Interpret(frame, sliceMode: true);
            if (frame.Stack is not [ResourceManagerObject made] || manager != null && manager.BaseName != made.BaseName) return null;
            manager ??= made;
        }
        _lazyManagers[field] = manager;
        return CurrentMethod != null && _lazyWriters[field].Contains(CurrentMethod) ? null : manager;
    }
}
