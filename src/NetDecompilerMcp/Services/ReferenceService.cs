using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;
using static NetDecompilerMcp.Services.MetadataUtil;

namespace NetDecompilerMcp.Services;

/// <summary>Cross-references ("used by" / "uses"), overrides and type hierarchy across all loaded assemblies.</summary>
public sealed class ReferenceService(AssemblyWorkspace workspace)
{
    /// <summary>One usage site. Where = the member containing the usage.</summary>
    public sealed record Reference(LoadedAssembly Assembly, IMemberDef Where, uint? ILOffset, string Kind, string Detail);

    public sealed record Callee(uint ILOffset, string OpCode, string Kind, string Target, LoadedAssembly? TargetAssembly);

    public sealed record Hierarchy(List<string> BaseChain, List<string> Interfaces, List<ResolvedSymbol> Derived, int DerivedTotal);

    /// <param name="includeVirtualCalls">
    /// For methods: also report call sites that target a base or interface method this method overrides/implements
    /// (they dispatch here at runtime). Labelled "via Base::Method".
    /// </param>
    public SearchResult<Reference> FindReferences(ResolvedSymbol target, bool includeVirtualCalls, int limit, CancellationToken ct)
    {
        Action<LoadedAssembly, TypeDef, List<Reference>> visit = target.Member switch
        {
            MethodDef method => MethodVisitor(method, includeVirtualCalls, ct),
            FieldDef field => InstructionVisitor((asm, m, instr, found) =>
            {
                if (AsField(instr.Operand) is { } op && IsSameField(op, field))
                    found.Add(new Reference(asm, m, instr.Offset, FieldAccessKind(instr.OpCode.Code), instr.OpCode.Name));
            }),
            PropertyDef prop => AccessorVisitor(prop.GetMethods.Select(a => (a, "get")).Concat(prop.SetMethods.Select(a => (a, "set")))
                .Concat(prop.OtherMethods.Select(a => (a, "other"))).ToList()),
            EventDef ev => AccessorVisitor(new[] { (ev.AddMethod, "add"), (ev.RemoveMethod, "remove"), (ev.InvokeMethod, "raise") }
                .Where(x => x.Item1 != null).Select(x => (x.Item1!, x.Item2)).ToList()),
            TypeDef type => (asm, t, found) => VisitTypeForTypeReferences(asm, t, type, found),
            _ => throw new ToolError($"Cannot find references to a {target.Kind}."),
        };
        return SearchResult<Reference>.From(ParallelCollect(workspace.Assemblies, visit, ct), limit);
    }

    private static Action<LoadedAssembly, TypeDef, List<Reference>> MethodVisitor(MethodDef method, bool includeVirtualCalls, CancellationToken ct)
    {
        var targets = new List<(MethodDef Method, string? Via)> { (method, null) };
        if (includeVirtualCalls)
            targets.AddRange(BaseDeclarations(method).Select(b => (b, (string?)$"via {Format.MemberLabel(b)}")));
        var direct = InstructionVisitor((asm, m, instr, found) =>
        {
            if (AsMethod(instr.Operand) is not { } op) return;
            foreach (var (t, via) in targets)
                if (IsSameMethod(op, t))
                {
                    found.Add(new Reference(asm, m, instr.Offset, instr.OpCode.Name, via ?? ""));
                    break;
                }
        });
        // Calls through static delegate fields whose delegate calls the method (resolved once per assembly).
        return (asm, type, found) =>
        {
            direct(asm, type, found);
            foreach (var site in Simplify.DelegateCalls.ByType(asm, ct)[type])
                if (targets.Any(t => IsSameMethod(site.Target, t.Method)))
                    found.Add(new Reference(asm, site.Caller, site.Offset, "delegate", $"via {Format.MemberLabel(site.Field)}"));
        };
    }

    private static Action<LoadedAssembly, TypeDef, List<Reference>> AccessorVisitor(List<(MethodDef Accessor, string Kind)> accessors) =>
        InstructionVisitor((asm, m, instr, found) =>
        {
            if (AsMethod(instr.Operand) is not { } op) return;
            foreach (var (accessor, kind) in accessors)
                if (IsSameMethod(op, accessor))
                    found.Add(new Reference(asm, m, instr.Offset, kind, instr.OpCode.Name));
        });

    /// <summary>Adapts a per-instruction check into a per-type visitor for <see cref="MetadataUtil.ParallelCollect{T}"/>.</summary>
    private static Action<LoadedAssembly, TypeDef, List<Reference>> InstructionVisitor(Action<LoadedAssembly, MethodDef, Instruction, List<Reference>> visit) =>
        (asm, type, found) =>
        {
            foreach (var m in type.Methods)
                foreach (var instr in FastIlReader.Instructions(asm, m))
                    visit(asm, m, instr, found);
        };

    private static void VisitTypeForTypeReferences(LoadedAssembly asm, TypeDef type, TypeDef target, List<Reference> found)
    {
        if (type == target) return;
        if (IsSameType(type.BaseType, target)) found.Add(new Reference(asm, type, null, "base type", ""));
        foreach (var i in type.Interfaces)
            if (IsSameType(i.Interface, target)) found.Add(new Reference(asm, type, null, "implements", ""));
        foreach (var ca in type.CustomAttributes)
            if (IsSameType(ca.AttributeType, target)) found.Add(new Reference(asm, type, null, "attribute", ""));
        foreach (var gp in type.GenericParameters)
            if (gp.GenericParamConstraints.Any(c => IsSameType(c.Constraint, target))) found.Add(new Reference(asm, type, null, "generic constraint", gp.Name));

        foreach (var f in type.Fields)
        {
            if (Mentions(f.FieldType, target)) found.Add(new Reference(asm, f, null, "field type", ""));
            if (f.CustomAttributes.Any(ca => IsSameType(ca.AttributeType, target))) found.Add(new Reference(asm, f, null, "attribute", ""));
        }
        foreach (var p in type.Properties)
        {
            if (Mentions(p.PropertySig?.RetType, target)) found.Add(new Reference(asm, p, null, "property type", ""));
            if (p.CustomAttributes.Any(ca => IsSameType(ca.AttributeType, target))) found.Add(new Reference(asm, p, null, "attribute", ""));
        }
        foreach (var e in type.Events)
            if (IsSameType(e.EventType, target)) found.Add(new Reference(asm, e, null, "event type", ""));

        foreach (var m in type.Methods)
            ScanMethodForType(asm, m, target, found.Add);
    }

    private static void ScanMethodForType(LoadedAssembly asm, MethodDef m, TypeDef target, Action<Reference> add)
    {
        if (m.MethodSig != null)
        {
            if (Mentions(m.MethodSig.RetType, target)) add(new Reference(asm, m, null, "return type", ""));
            if (m.MethodSig.Params.Any(p => Mentions(p, target))) add(new Reference(asm, m, null, "parameter type", ""));
        }
        if (m.CustomAttributes.Any(ca => IsSameType(ca.AttributeType, target))) add(new Reference(asm, m, null, "attribute", ""));

        var body = FastIlReader.Read(asm, m);
        if (body == null) return;
        if (body.LocalTypes.Any(t => Mentions(t, target))) add(new Reference(asm, m, null, "local variable", ""));
        foreach (var (catchType, handlerOffset) in body.Catches)
            if (IsSameType(catchType, target)) add(new Reference(asm, m, handlerOffset, "catch", ""));
        foreach (var instr in body.Instructions)
        {
            if (instr.Operand is ITypeDefOrRef t && IsSameType(t, target))
                add(new Reference(asm, m, instr.Offset, instr.OpCode.Name, ""));
            else if (AsMethod(instr.Operand) is { DeclaringType: { } mt } im && IsSameType(mt, target))
                add(new Reference(asm, m, instr.Offset, instr.OpCode.Name, im.Name));
            else if (AsField(instr.Operand) is { DeclaringType: { } ft } fd && IsSameType(ft, target))
                add(new Reference(asm, m, instr.Offset, instr.OpCode.Name, fd.Name));
        }
    }

    /// <summary>Base-class virtual methods and interface methods that <paramref name="method"/> overrides or implements.</summary>
    public static List<MethodDef> BaseDeclarations(MethodDef method)
    {
        var result = new List<MethodDef>();
        foreach (var o in method.Overrides)
            if (Try(() => o.MethodDeclaration.ResolveMethodDef()) is { } explicitBase)
                result.Add(explicitBase);
        if (method.IsStatic || method.IsConstructor) return result;

        int count = ParamCount(method);
        if (method.IsVirtual && !method.IsNewSlot)
            for (var t = BaseTypeDef(method.DeclaringType); t != null; t = BaseTypeDef(t))
                foreach (var m in t.Methods)
                    if (m.IsVirtual && m.Name == method.Name && ParamCount(m) == count && !result.Contains(m))
                        result.Add(m);

        if (method.IsPublic || method.IsVirtual)
            foreach (var iface in AllInterfaces(method.DeclaringType))
                foreach (var m in iface.Methods)
                    if (m.Name == method.Name && ParamCount(m) == count && !result.Contains(m))
                        result.Add(m);
        return result;
    }

    public List<Callee> FindCallees(MethodDef method)
    {
        var body = SafeBody(method)
                   ?? throw new ToolError($"{Format.MemberLabel(method)} has no IL body (abstract, extern, runtime-implemented or an Il2Cpp stub).");
        var list = new List<Callee>();
        var owner = workspace.FindByModule(method.Module);
        var throughFields = owner == null ? [] : Simplify.DelegateCalls.Of(owner, default).Where(s => s.Caller == method).ToDictionary(s => s.Offset);
        foreach (var instr in body.Instructions)
        {
            if (throughFields.TryGetValue(instr.Offset, out var site))
            {
                var target = Try(() => site.Target.ResolveMethodDef());
                list.Add(new Callee(instr.Offset, $"{instr.OpCode.Name} via {Format.MemberLabel(site.Field)}", "method", Format.MemberLabel(site.Target),
                    workspace.FindByModule(target?.Module)));
                continue;
            }
            if (AsMethod(instr.Operand) is { } m)
            {
                var md = Try(() => m.ResolveMethodDef());
                list.Add(new Callee(instr.Offset, instr.OpCode.Name, m.Name == ".ctor" ? "constructor" : "method", Format.MemberLabel(m), workspace.FindByModule(md?.Module)));
                continue;
            }
            if (AsField(instr.Operand) is { } f)
            {
                var fd = Try(() => f.ResolveFieldDef());
                list.Add(new Callee(instr.Offset, instr.OpCode.Name, "field " + FieldAccessKind(instr.OpCode.Code), Format.MemberLabel(f), workspace.FindByModule(fd?.Module)));
                continue;
            }
            switch (instr.Operand)
            {
                case ITypeDefOrRef t:
                    list.Add(new Callee(instr.Offset, instr.OpCode.Name, "type", t.FullName, workspace.FindByModule(Try(() => t.ResolveTypeDef())?.Module)));
                    break;
                case string s:
                    list.Add(new Callee(instr.Offset, instr.OpCode.Name, "string", Format.Literal(s), null));
                    break;
            }
        }
        return list;
    }

    public Hierarchy GetHierarchy(TypeDef type, int limit, CancellationToken ct)
    {
        var chain = new List<string>();
        ITypeDefOrRef? current = type.BaseType;
        for (int guard = 0; current != null && guard < 64; guard++)
        {
            var resolved = Try(() => current.ResolveTypeDef());
            chain.Add(current.FullName + (resolved == null
                ? "  (unresolved — load its assembly to go further)"
                : $"  [{workspace.FindByModule(resolved.Module)?.Id ?? resolved.Module.Name}]"));
            if (resolved == null) break;
            current = resolved.BaseType;
        }

        var interfaces = AllInterfaces(type).Select(i => i.FullName)
            .Union(type.Interfaces.Select(i => i.Interface.FullName)) // keep unresolved direct interfaces too
            .OrderBy(n => n, StringComparer.Ordinal).ToList();

        var derived = new List<ResolvedSymbol>();
        int total = 0;
        foreach (var (asm, t) in AllTypes())
        {
            ct.ThrowIfCancellationRequested();
            if (t == type) continue;
            bool related = type.IsInterface ? t.Interfaces.Any(i => IsSameType(i.Interface, type)) : IsSameType(t.BaseType, type);
            if (!related) continue;
            total++;
            if (derived.Count < limit) derived.Add(new ResolvedSymbol(asm, t));
        }
        return new Hierarchy(chain, interfaces, derived, total);
    }

    /// <summary>Methods that override a virtual method or implement an interface method.</summary>
    public List<ResolvedSymbol> FindOverrides(MethodDef baseMethod, CancellationToken ct)
    {
        var declaring = baseMethod.DeclaringType;
        if (!declaring.IsInterface && !baseMethod.IsVirtual)
            throw new ToolError($"{Format.MemberLabel(baseMethod)} is not virtual, abstract or an interface method, so nothing can override it.");

        int count = ParamCount(baseMethod);
        var results = new List<ResolvedSymbol>();
        foreach (var (asm, t) in AllSubtypes(declaring, ct))
            foreach (var m in t.Methods)
            {
                bool explicitImpl = m.Overrides.Any(o => IsSameMethod(o.MethodDeclaration, baseMethod));
                bool implicitImpl = m.Name == baseMethod.Name && ParamCount(m) == count
                                    && (declaring.IsInterface ? m.IsVirtual || m.IsPublic : m.IsVirtual && !m.IsNewSlot);
                if (explicitImpl || implicitImpl)
                    results.Add(new ResolvedSymbol(asm, m));
            }
        return results;
    }

    /// <summary>All types deriving (transitively) from, or implementing, <paramref name="type"/>.</summary>
    private List<(LoadedAssembly Asm, TypeDef Type)> AllSubtypes(TypeDef type, CancellationToken ct)
    {
        var all = AllTypes().ToList();
        var result = new List<(LoadedAssembly, TypeDef)>();
        var seen = new HashSet<TypeDef> { type };
        var frontier = new Queue<TypeDef>([type]);
        while (frontier.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var current = frontier.Dequeue();
            foreach (var (asm, t) in all)
            {
                if (seen.Contains(t)) continue;
                bool related = IsSameType(t.BaseType, current) || (current.IsInterface && t.Interfaces.Any(i => IsSameType(i.Interface, current)));
                if (!related) continue;
                seen.Add(t);
                result.Add((asm, t));
                frontier.Enqueue(t);
            }
        }
        return result;
    }

    private IEnumerable<(LoadedAssembly, TypeDef)> AllTypes() =>
        workspace.Assemblies.SelectMany(a => a.Module.GetTypes().Select(t => (a, t)));
}
