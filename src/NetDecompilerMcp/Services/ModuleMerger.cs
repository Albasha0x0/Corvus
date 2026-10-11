using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;
using static NetDecompilerMcp.Core.MetadataUtil;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Copies code compiled by Roslyn into a target module. Compiled types and members are either mapped onto existing
/// definitions in the target (by name and signature), or declared as new ones (new types, compiler-generated lambda
/// closures, async/iterator state machines, local functions, &lt;PrivateImplementationDetails&gt;, user-added members).
///
/// Usage: declare new types/members (AddTypeTree / AddMethod / AddField), call <see cref="Fill"/>, then copy bodies with
/// <see cref="CopyBody"/> / <see cref="CopyNewBodies"/>. Anything that can be neither mapped nor declared ends up in
/// <see cref="Unmapped"/> and the caller must abort.
/// </summary>
internal sealed class ModuleMerger
{
    private static readonly SigComparer Comparer = new(SigComparerOptions.DontCompareTypeScope);
    private static readonly HashSet<string> EmbeddedAttributeNamespaces = ["System.Runtime.CompilerServices", "Microsoft.CodeAnalysis"];

    private readonly ModuleDef _target;
    private readonly ModuleDef _compiled;
    private readonly string _targetAssemblyName;
    private readonly Dictionary<TypeDef, TypeDef> _types = new();
    private readonly HashSet<TypeDef> _declaredTypes = new();
    private readonly Dictionary<IMemberDef, IMemberDef> _members = new();
    private readonly List<(TypeDef Compiled, TypeDef Target)> _newTypes = new();
    private readonly List<(MethodDef Compiled, MethodDef Target)> _newMethods = new();
    private readonly List<(FieldDef Compiled, FieldDef Target)> _newFields = new();
    private readonly List<(PropertyDef Compiled, TypeDef Target)> _newProperties = new();
    private readonly List<(EventDef Compiled, TypeDef Target)> _newEvents = new();
    private Dictionary<string, TypeRef>? _existingTypeRefs;

    public ModuleMerger(ModuleDef target, ModuleDef compiled, string targetAssemblyName)
    {
        _target = target;
        _compiled = compiled;
        _targetAssemblyName = targetAssemblyName;
    }

    public List<string> Unmapped { get; } = new();

    /// <summary>Labels of everything declared new (for reporting and diffs).</summary>
    public List<string> Added { get; } = new();

    public ModuleDef Target => _target;

    /// <summary>The target counterpart of a compiled type: declared new, or existing with the same full name.</summary>
    public TypeDef? MapType(TypeDef compiled) =>
        _types.TryGetValue(compiled, out var t) ? t : _target.Find(compiled.FullName, isReflectionName: false);

    public bool IsNew(TypeDef compiled) => _declaredTypes.Contains(compiled);

    /// <summary>Maps a compiled type onto an existing target type (e.g. the static helper class of a patch onto the patched type).</summary>
    public void Alias(TypeDef compiled, TypeDef target) => _types[compiled] = target;

    /// <summary>Only explicitly declared members (no lookup by name).</summary>
    public MethodDef? MapMethodIfDeclared(MethodDef compiled) => _members.TryGetValue(compiled, out var m) ? (MethodDef)m : null;

    public FieldDef? MapFieldIfDeclared(FieldDef compiled) => _members.TryGetValue(compiled, out var f) ? (FieldDef)f : null;

    /// <summary>The target methods declared new (their bodies are produced by <see cref="CopyNewBodies"/>).</summary>
    public IEnumerable<MethodDef> NewMethodTargets => _newMethods.Select(x => x.Target);

    public MethodDef? MapMethod(MethodDef compiled)
    {
        if (_members.TryGetValue(compiled, out var m)) return (MethodDef)m;
        var type = MapType(compiled.DeclaringType);
        return type?.Methods.FirstOrDefault(x => x.Name == compiled.Name && Comparer.Equals(x.MethodSig, compiled.MethodSig));
    }

    public FieldDef? MapField(FieldDef compiled)
    {
        if (_members.TryGetValue(compiled, out var f)) return (FieldDef)f;
        return MapType(compiled.DeclaringType)?.Fields.FirstOrDefault(x => x.Name == compiled.Name);
    }

    /// <summary>Declares a copy of a compiled type (with its nested types and members) under <paramref name="parent"/> or at top level.</summary>
    public TypeDef AddTypeTree(TypeDef compiled, TypeDef? parent, string name)
    {
        var type = new TypeDefUser(parent == null ? compiled.Namespace : UTF8String.Empty, name) { Attributes = compiled.Attributes };
        if (compiled.ClassLayout != null)
            type.ClassLayout = new ClassLayoutUser(compiled.PackingSize, compiled.ClassSize);
        foreach (var gp in compiled.GenericParameters)
            type.GenericParameters.Add(new GenericParamUser(gp.Number, gp.Flags, gp.Name));
        if (parent == null) _target.Types.Add(type);
        else parent.NestedTypes.Add(type);
        _types[compiled] = type;
        _declaredTypes.Add(compiled);
        _newTypes.Add((compiled, type));
        Added.Add(type.FullName);
        ResetTypeIndex();

        foreach (var nested in compiled.NestedTypes.ToList())
            AddTypeTree(nested, type, nested.Name);
        foreach (var field in compiled.Fields)
            DeclareField(field, type, field.Name);
        foreach (var method in compiled.Methods)
            DeclareMethod(method, type, method.Name);
        foreach (var property in compiled.Properties)
            _newProperties.Add((property, type));
        foreach (var ev in compiled.Events)
            _newEvents.Add((ev, type));
        return type;
    }

    public MethodDef AddMethod(MethodDef compiled, TypeDef target, string name)
    {
        var m = DeclareMethod(compiled, target, name);
        Added.Add(Format.MemberLabel(compiled).Replace(compiled.DeclaringType.FullName, target.FullName));
        return m;
    }

    public FieldDef AddField(FieldDef compiled, TypeDef target, string name)
    {
        var f = DeclareField(compiled, target, name);
        Added.Add($"{target.FullName}::{name}");
        return f;
    }

    public void AddProperty(PropertyDef compiled, TypeDef target)
    {
        _newProperties.Add((compiled, target));
        Added.Add($"{target.FullName}::{compiled.Name}");
    }

    public void AddEvent(EventDef compiled, TypeDef target)
    {
        _newEvents.Add((compiled, target));
        Added.Add($"{target.FullName}::{compiled.Name}");
    }

    /// <summary>dnlib's name -> TypeDef index enumerates lazily and breaks if types are added meanwhile: rebuild it.</summary>
    private void ResetTypeIndex()
    {
        _target.EnableTypeDefFindCache = false;
        _target.EnableTypeDefFindCache = true;
    }

    private MethodDef DeclareMethod(MethodDef compiled, TypeDef target, string name)
    {
        var m = new MethodDefUser(name, null, compiled.ImplAttributes, compiled.Attributes);
        foreach (var gp in compiled.GenericParameters)
            m.GenericParameters.Add(new GenericParamUser(gp.Number, gp.Flags, gp.Name));
        target.Methods.Add(m);
        _members[compiled] = m;
        _newMethods.Add((compiled, m));
        return m;
    }

    private FieldDef DeclareField(FieldDef compiled, TypeDef target, string name)
    {
        var f = new FieldDefUser(name, null, compiled.Attributes);
        target.Fields.Add(f);
        _members[compiled] = f;
        _newFields.Add((compiled, f));
        return f;
    }

    /// <summary>A name not yet used by <paramref name="existing"/>: "&lt;&gt;c" becomes "&lt;&gt;c$ndm1", "$ndm2", ...</summary>
    public static string UniqueName(string name, IEnumerable<string> existing)
    {
        var used = existing.ToHashSet(StringComparer.Ordinal);
        if (!used.Contains(name)) return name;
        for (int i = 1; ; i++)
            if (!used.Contains($"{name}$ndm{i}")) return $"{name}$ndm{i}";
    }

    /// <summary>Fills signatures, base types, interfaces, attributes, properties and events of everything declared.</summary>
    public void Fill()
    {
        ResetTypeIndex(); // name lookups must see the newly declared types

        foreach (var (c, t) in _newTypes)
        {
            var importer = ImporterFor(t, null);
            if (c.BaseType != null) t.BaseType = importer.Import(c.BaseType);
            foreach (var i in c.Interfaces)
                t.Interfaces.Add(new InterfaceImplUser(importer.Import(i.Interface)));
            CopyGenericConstraints(c.GenericParameters, t.GenericParameters, importer);
            CopyAttributes(c, t, importer);
        }

        foreach (var (c, f) in _newFields)
        {
            var importer = ImporterFor(f.DeclaringType, null);
            f.FieldSig = importer.Import(c.FieldSig);
            if (c.HasFieldRVA && c.InitialValue != null) f.InitialValue = c.InitialValue;
            if (c.Constant != null) f.Constant = new ConstantUser(c.Constant.Value, c.Constant.Type);
            if (c.FieldOffset != null) f.FieldOffset = c.FieldOffset;
            CopyAttributes(c, f, importer);
        }

        foreach (var (c, m) in _newMethods)
        {
            var importer = ImporterFor(m.DeclaringType, m);
            m.MethodSig = importer.Import(c.MethodSig);
            m.Parameters.UpdateParameterTypes();
            foreach (var pd in c.ParamDefs)
            {
                var copy = new ParamDefUser(pd.Name, pd.Sequence, pd.Attributes);
                if (pd.Constant != null) copy.Constant = new ConstantUser(pd.Constant.Value, pd.Constant.Type);
                m.ParamDefs.Add(copy);
                CopyAttributes(pd, copy, importer);
            }
            CopyGenericConstraints(c.GenericParameters, m.GenericParameters, importer);
            CopyAttributes(c, m, importer);
            foreach (var o in c.Overrides)
            {
                var body = ResolveOwn(o.MethodBody, importer) as IMethodDefOrRef ?? (IMethodDefOrRef)importer.Import(o.MethodBody);
                var declaration = ResolveOwn(o.MethodDeclaration, importer) as IMethodDefOrRef ?? (IMethodDefOrRef)importer.Import(o.MethodDeclaration);
                m.Overrides.Add(new MethodOverride(body, declaration));
            }
        }

        var declared = new List<(IHasCustomAttribute Member, TypeDef Type)>(); // properties and events
        foreach (var (c, t) in _newProperties)
        {
            var importer = ImporterFor(t, null);
            var p = new PropertyDefUser(c.Name, importer.Import(c.PropertySig), c.Attributes);
            foreach (var g in c.GetMethods) if (MapMethod(g) is { } mg) p.GetMethods.Add(mg);
            foreach (var s in c.SetMethods) if (MapMethod(s) is { } ms) p.SetMethods.Add(ms);
            CopyAttributes(c, p, importer);
            t.Properties.Add(p);
            declared.Add((p, t));
        }

        foreach (var (c, t) in _newEvents)
        {
            var importer = ImporterFor(t, null);
            var e = new EventDefUser(c.Name, importer.Import(c.EventType), c.Attributes)
            {
                AddMethod = c.AddMethod == null ? null : MapMethod(c.AddMethod),
                RemoveMethod = c.RemoveMethod == null ? null : MapMethod(c.RemoveMethod),
                InvokeMethod = c.InvokeMethod == null ? null : MapMethod(c.InvokeMethod),
            };
            CopyAttributes(c, e, importer);
            t.Events.Add(e);
            declared.Add((e, t));
        }
        MarkNullableOblivious(declared);
    }

    /// <summary>
    /// Patches compile without nullable annotations; a member added to a type with a nullable context would read as
    /// annotated by it (T as notnull, string as non-null), so it is marked oblivious with the target's own attributes.
    /// </summary>
    private void MarkNullableOblivious(List<(IHasCustomAttribute Member, TypeDef Type)> propertiesAndEvents)
    {
        var newTypes = _newTypes.Select(x => x.Target).ToHashSet();
        // The enclosing context attribute when it is not oblivious; its constructor (a definition or a reference) is reused.
        CustomAttribute? Context(TypeDef? t)
        {
            for (; t != null && !newTypes.Contains(t); t = t.DeclaringType)
                if (t.CustomAttributes.Find("System.Runtime.CompilerServices.NullableContextAttribute") is { } ca)
                    return ca.ConstructorArguments is [{ Value: byte b }] && b != 0 ? ca : null;
            return null;
        }
        CustomAttribute Oblivious(ICustomAttributeType ctor) => new(ctor, [new CAArgument(_target.CorLibTypes.Byte, (byte)0)]);

        foreach (var (_, m) in _newMethods)
            if (Context(m.DeclaringType) is { } ca) m.CustomAttributes.Add(Oblivious(ca.Constructor));
        var nullable = _target.GetTypes().SelectMany(t => t.CustomAttributes.Concat(t.Fields.SelectMany(f => f.CustomAttributes)))
            .FirstOrDefault(ca => ca.TypeFullName == "System.Runtime.CompilerServices.NullableAttribute" && ca.ConstructorArguments is [{ Value: byte }])?.Constructor;
        if (nullable == null) return;
        foreach (var (member, t) in _newFields.Select(x => ((IHasCustomAttribute)x.Target, x.Target.DeclaringType)).Concat(propertiesAndEvents))
            if (Context(t) != null) member.CustomAttributes.Add(Oblivious(nullable));
    }

    private void CopyGenericConstraints(IList<GenericParam> from, IList<GenericParam> to, Importer importer)
    {
        for (int i = 0; i < from.Count && i < to.Count; i++)
        {
            foreach (var c in from[i].GenericParamConstraints)
            {
                var copy = new GenericParamConstraintUser(importer.Import(c.Constraint));
                CopyAttributes(c, copy, importer);
                to[i].GenericParamConstraints.Add(copy);
            }
            CopyAttributes(from[i], to[i], importer);
        }
    }

    /// <summary>Copies custom attributes, skipping the attribute types Roslyn embeds into the compiled assembly (Nullable, IsReadOnly...).</summary>
    public void CopyAttributes(IHasCustomAttribute from, IHasCustomAttribute to, Importer importer, Func<CustomAttribute, bool>? filter = null)
    {
        foreach (var ca in from.CustomAttributes)
        {
            if (filter != null && !filter(ca)) continue;
            if (ca.AttributeType is TypeDef { Module: var m } at && m == _compiled && MapType(at) == null
                && EmbeddedAttributeNamespaces.Contains(at.Namespace))
                continue;
            var ctor = ca.Constructor is IMethod method
                ? (ResolveOwn(method, importer) ?? importer.Import(method)) as ICustomAttributeType
                : null;
            if (ctor == null) continue;
            var copy = new CustomAttribute(ctor);
            foreach (var arg in ca.ConstructorArguments) copy.ConstructorArguments.Add(ImportArgument(arg, importer));
            foreach (var na in ca.NamedArguments)
                copy.NamedArguments.Add(new CANamedArgument(na.IsField, importer.Import(na.Type), na.Name, ImportArgument(na.Argument, importer)));
            to.CustomAttributes.Add(copy);
        }
    }

    private static CAArgument ImportArgument(CAArgument arg, Importer importer) =>
        new(importer.Import(arg.Type), arg.Value switch
        {
            TypeSig sig => importer.Import(sig),
            IList<CAArgument> list => list.Select(a => ImportArgument(a, importer)).ToList(),
            CAArgument inner => ImportArgument(inner, importer),
            var v => v,
        });

    public void CopyNewBodies()
    {
        foreach (var (c, m) in _newMethods)
            if (c.HasBody && c.Body != null)
                m.Body = CopyBody(c, m);
    }

    /// <summary>Copies the compiled method's body for use by <paramref name="target"/>, remapping every operand.</summary>
    public CilBody CopyBody(MethodDef source, MethodDef target)
    {
        var importer = ImporterFor(target.DeclaringType, target);
        var src = source.Body ?? throw new ToolError("Internal: compiled method has no body.");

        var body = new CilBody { InitLocals = src.InitLocals, KeepOldMaxStack = false };
        var locals = new Dictionary<Local, Local>();
        foreach (var l in src.Variables)
            locals[l] = body.Variables.Add(new Local(importer.Import(l.Type), l.Name));

        var map = new Dictionary<Instruction, Instruction>();
        foreach (var i in src.Instructions)
        {
            var copy = new Instruction(i.OpCode);
            map[i] = copy;
            body.Instructions.Add(copy);
        }
        foreach (var i in src.Instructions)
        {
            map[i].Operand = i.Operand switch
            {
                Instruction t => map[t],
                Instruction[] ts => ts.Select(t => map[t]).ToArray(),
                Local l => locals[l],
                Parameter p => target.Parameters[p.Index],
                _ when AsField(i.Operand) is { } f => ResolveOwn(f) ?? Imported(importer.Import(f), f),
                _ when AsMethod(i.Operand) is { } m => ResolveOwn(m, importer) ?? Imported(importer.Import(m), m),
                ITypeDefOrRef t => importer.Import(t),
                MethodSig sig => importer.Import(sig),
                _ => i.Operand,
            };
        }
        foreach (var h in src.ExceptionHandlers)
        {
            body.ExceptionHandlers.Add(new ExceptionHandler(h.HandlerType)
            {
                TryStart = Map(h.TryStart), TryEnd = Map(h.TryEnd),
                HandlerStart = Map(h.HandlerStart), HandlerEnd = Map(h.HandlerEnd),
                FilterStart = Map(h.FilterStart),
                CatchType = h.CatchType == null ? null : importer.Import(h.CatchType),
            });
        }
        return body;

        Instruction? Map(Instruction? i) => i == null ? null : map[i];
    }

    private static T Imported<T>(T? imported, object original) where T : class =>
        imported ?? throw new ToolError($"Internal: could not import operand {original} into the target module.");

    private Importer ImporterFor(TypeDef type, MethodDef? method) =>
        new(_target, ImporterOptions.TryToUseDefs, new GenericParamContext(type, method), new Mapper(this));

    /// <summary>Compiled definitions and member references into the target assembly become target definitions.</summary>
    public IMethod? ResolveOwn(IMethod method, Importer importer) => method switch
    {
        MethodDef md when md.Module == _compiled => MapMethod(md) ?? NoteUnmapped(Format.MemberLabel(md)),
        MemberRef { DeclaringType: TypeRef tr } mr when IsTargetScope(tr) => FindMethod(tr.FullName, mr.Name, mr.MethodSig, Format.MemberLabel(mr)),
        MethodSpec spec when ResolveOwn(spec.Method, importer) is IMethodDefOrRef inner => new MethodSpecUser(inner, importer.Import(spec.GenericInstMethodSig)),
        _ => null,
    };

    public IField? ResolveOwn(IField field) => field switch
    {
        FieldDef fd when fd.Module == _compiled => MapField(fd) ?? NoteUnmapped<FieldDef>(Format.MemberLabel(fd)),
        MemberRef { DeclaringType: TypeRef tr } mr when IsTargetScope(tr) => FindField(tr.FullName, mr.Name, Format.MemberLabel(mr)),
        _ => null,
    };

    private T? NoteUnmapped<T>(string label) where T : class
    {
        Unmapped.Add(label);
        return null;
    }

    private IMethod? NoteUnmapped(string label) => NoteUnmapped<IMethod>(label);

    private bool IsTargetScope(TypeRef tr) => tr.DefinitionAssembly?.Name == _targetAssemblyName;

    private Dictionary<string, TypeRef> ExistingTypeRefs => _existingTypeRefs ??=
        ((_target as ModuleDefMD)?.GetTypeRefs() ?? []).GroupBy(t => t.FullName).ToDictionary(g => g.Key, g => g.First());

    private FieldDef? FindField(string typeName, string name, string label) =>
        FindType(typeName)?.Fields.FirstOrDefault(f => f.Name == name) ?? NoteUnmapped<FieldDef>(label);

    private MethodDef? FindMethod(string typeName, string name, MethodSig sig, string label) =>
        FindType(typeName)?.Methods.FirstOrDefault(m => m.Name == name && Comparer.Equals(m.MethodSig, sig)) ?? NoteUnmapped<MethodDef>(label);

    private TypeDef? FindType(string fullName) =>
        _target.Find(fullName, isReflectionName: false) ?? NoteUnmapped<TypeDef>(fullName);

    private sealed class Mapper(ModuleMerger merger) : ImportMapper
    {
        public override ITypeDefOrRef? Map(ITypeDefOrRef source) => source switch
        {
            TypeDef td when td.Module == merger._compiled => merger.MapType(td) ?? merger.NoteUnmapped<TypeDef>(td.FullName),
            TypeRef tr when merger.IsTargetScope(tr) => merger.FindType(tr.FullName),
            // Keep the module's own reference scopes (System.Runtime / mscorlib) instead of the implementation
            // assembly Roslyn bound to (System.Private.CoreLib).
            TypeRef tr => merger.ExistingTypeRefs.GetValueOrDefault(tr.FullName),
            _ => null,
        };

        public override IField? Map(FieldDef source) =>
            source.Module != merger._compiled ? null : merger.MapField(source) ?? merger.NoteUnmapped<FieldDef>(Format.MemberLabel(source));

        public override IMethod? Map(MethodDef source) =>
            source.Module != merger._compiled ? null : merger.MapMethod(source) ?? merger.NoteUnmapped(Format.MemberLabel(source));
    }
}
