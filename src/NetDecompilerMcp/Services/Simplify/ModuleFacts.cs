using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace NetDecompilerMcp.Services.Simplify;

/// <summary>
/// Whole-module facts the evaluator needs to read static state soundly, computed once per simplifier on first use:
/// <list type="bullet">
/// <item>which methods can run while a type's static constructor runs (the state is partial then);</item>
/// <item>whether the array or builder held in a readonly static field can be modified by code other than its type's
/// initialization (the evaluator only uses state that stays as the static constructor left it).</item>
/// </list>
/// The call graph covers the module's own code: call, callvirt (virtual calls reach every method of the same name),
/// newobj, ldftn and the static constructors that member accesses trigger. Code in other modules and reflection are
/// assumed not to call back into initialization or modify static arrays.
/// </summary>
internal sealed class ModuleFacts(ModuleDef module)
{
    private const int MaxParameterDepth = 6;
    private const int MaxConsumerScan = 64;

    // Nodes are methods, and virtual slots (a method name) through which virtual calls reach every override.
    private Dictionary<object, HashSet<object>>? _callees;
    private Dictionary<MethodDef, HashSet<MethodDef>>? _callers; // direct callers (virtual methods count as externally callable)
    private Dictionary<FieldDef, List<(MethodDef Method, int Index)>>? _fieldUses;
    private readonly Dictionary<TypeDef, HashSet<MethodDef>> _reach = new();
    private readonly Dictionary<TypeDef, HashSet<MethodDef>> _initOnly = new();
    private readonly Dictionary<FieldDef, bool> _frozen = new();
    private readonly Dictionary<MethodDef, HashSet<Instruction>> _targets = new();

    /// <summary>Whether <paramref name="method"/> can run while the static constructor of <paramref name="type"/> runs (the constructor included).</summary>
    public bool RunsDuringInitialization(TypeDef type, MethodDef method) => Reach(type).Contains(method);

    private HashSet<MethodDef> Reach(TypeDef type)
    {
        if (_reach.TryGetValue(type, out var reach)) return reach;
        Build();
        reach = new HashSet<MethodDef>();
        if (type.FindStaticConstructor() is { } cctor)
        {
            var seen = new HashSet<object> { cctor };
            var work = new Stack<object>();
            work.Push(cctor);
            while (work.Count > 0)
            {
                var node = work.Pop();
                if (node is MethodDef m) reach.Add(m);
                foreach (var next in _callees!.GetValueOrDefault(node) ?? [])
                    if (seen.Add(next)) work.Push(next);
            }
        }
        _reach[type] = reach;
        return reach;
    }

    /// <summary>
    /// Methods that only run as part of the type's initialization: its static constructor, and methods it reaches that
    /// nothing else calls and other assemblies cannot call.
    /// </summary>
    private HashSet<MethodDef> InitOnly(TypeDef type)
    {
        if (_initOnly.TryGetValue(type, out var set)) return set;
        set = new HashSet<MethodDef>(Reach(type));
        var cctor = type.FindStaticConstructor();
        bool changed = true;
        while (changed)
        {
            changed = false;
            foreach (var m in set.ToList())
            {
                if (m == cctor) continue;
                bool external = m.IsVirtual || m.Access is MethodAttributes.Public or MethodAttributes.Family or MethodAttributes.FamORAssem;
                if (external || (_callers!.GetValueOrDefault(m) ?? []).Any(c => !set.Contains(c)))
                {
                    set.Remove(m);
                    changed = true;
                }
            }
        }
        _initOnly[type] = set;
        return set;
    }

    /// <summary>
    /// Whether the object held in a static field stays as the type's initialization leaves it: every load of the field
    /// outside the initialization only reads it (element loads, length, comparisons, read-only intrinsics, or passing it
    /// to module methods that only read their parameter, transitively).
    /// </summary>
    public bool IsFrozen(FieldDef field)
    {
        if (_frozen.TryGetValue(field, out bool frozen)) return frozen;
        Build();
        var init = InitOnly(field.DeclaringType);
        bool immutableElements = field.FieldType.RemovePinnedAndModifiers() is SZArraySig { Next: var element } &&
                                 (element.IsPrimitive || element.ElementType == ElementType.String);
        var visited = new HashSet<(MethodDef, int, bool)>();
        frozen = true;
        foreach (var (method, index) in _fieldUses!.GetValueOrDefault(field) ?? [])
        {
            if (init.Contains(method)) continue;
            var body = MetadataUtil.SafeBody(method);
            if (body == null || body.Instructions[index].OpCode.Code != Code.Ldsfld ||
                !ValueOnlyRead(method, body, index, immutableElements, 0, visited))
            {
                frozen = false;
                break;
            }
        }
        _frozen[field] = frozen;
        return frozen;
    }

    /// <summary>Whether the reference pushed by code[k] is only read: follows it to the instruction that consumes it.</summary>
    private bool ValueOnlyRead(MethodDef m, CilBody body, int k, bool immutableElements, int depth, HashSet<(MethodDef, int, bool)> visited)
    {
        var code = body.Instructions;
        var targets = Targets(m, body);
        bool hasReturn = m.MethodSig?.RetType.RemovePinnedAndModifiers().ElementType != ElementType.Void;
        int position = 0; // stack slots above the value
        for (int j = k + 1; j < code.Count && j <= k + MaxConsumerScan; j++)
        {
            var ins = code[j];
            if (targets.Contains(ins)) return false; // a merge point: the stack may hold other values there
            ins.CalculateStackUsage(hasReturn, out int pushes, out int pops);
            if (pops < 0) return false;
            if (pops > position) return ConsumerOnlyReads(m, body, j, pops - 1 - position, immutableElements, depth, visited);
            position += pushes - pops;
            if (!BodyGraph.FallsThrough(ins)) return false;
        }
        return false;
    }

    private bool ConsumerOnlyReads(MethodDef m, CilBody body, int j, int operand, bool immutableElements, int depth, HashSet<(MethodDef, int, bool)> visited)
    {
        var ins = body.Instructions[j];
        switch (ins.OpCode.Code)
        {
            case Code.Ldlen: case Code.Pop: case Code.Ceq: case Code.Cgt_Un: case Code.Clt_Un:
            case Code.Brtrue: case Code.Brtrue_S: case Code.Brfalse: case Code.Brfalse_S:
            case Code.Beq: case Code.Beq_S: case Code.Bne_Un: case Code.Bne_Un_S:
                return true;
            case Code.Ldelem_I1: case Code.Ldelem_U1: case Code.Ldelem_I2: case Code.Ldelem_U2: case Code.Ldelem_I4: case Code.Ldelem_U4:
            case Code.Ldelem_I8: case Code.Ldelem_I: case Code.Ldelem_R4: case Code.Ldelem_R8:
            case Code.Ldind_I1: case Code.Ldind_U1: case Code.Ldind_I2: case Code.Ldind_U2: case Code.Ldind_I4: case Code.Ldind_U4:
            case Code.Ldind_I8: case Code.Ldind_I: case Code.Ldind_R4: case Code.Ldind_R8: case Code.Ldobj:
                return true;
            case Code.Ldelema:
                // readonly. ldelema: an element address used for reading; followed to its consumer.
                return j > 0 && body.Instructions[j - 1].OpCode.Code == Code.Readonly && ValueOnlyRead(m, body, j, immutableElements, depth, visited);
            case Code.Ldelem_Ref: case Code.Ldelem:
                // Elements that are themselves mutable objects are followed in turn.
                return immutableElements || ValueOnlyRead(m, body, j, false, depth, visited);
            case Code.Stloc: case Code.Stloc_S: case Code.Stloc_0: case Code.Stloc_1: case Code.Stloc_2: case Code.Stloc_3:
            {
                var local = ins.GetLocal(body.Variables);
                if (local == null) return false;
                if (!visited.Add((m, -1 - local.Index, immutableElements))) return true;
                var code = body.Instructions;
                for (int q = 0; q < code.Count; q++)
                {
                    var use = code[q];
                    if (use.OpCode.Code is Code.Ldloca or Code.Ldloca_S && use.GetLocal(body.Variables) == local) return false;
                    if (use.IsLdloc() && use.GetLocal(body.Variables) == local && !ValueOnlyRead(m, body, q, immutableElements, depth, visited)) return false;
                }
                return true;
            }
            case Code.Starg: case Code.Starg_S:
                return ParameterOnlyRead(m, ins.GetParameterIndex(), immutableElements, depth, visited);
            case Code.Call: case Code.Callvirt: case Code.Newobj:
            {
                if (MetadataUtil.AsMethod(ins.Operand) is not { } callee) return false;
                if (IlEvaluator.IntrinsicNames.Contains(callee.FullName))
                    return !IlEvaluator.MutatedArguments(callee.FullName).Contains(operand);
                if (callee is not MethodDef def || def.Module != module) return false;
                if (ins.OpCode.Code == Code.Callvirt && def.IsVirtual && !def.IsFinal) return false;
                return ParameterOnlyRead(def, ins.OpCode.Code == Code.Newobj ? operand + 1 : operand, immutableElements, depth + 1, visited);
            }
            default:
                return false;
        }
    }

    private bool ParameterOnlyRead(MethodDef m, int parameter, bool immutableElements, int depth, HashSet<(MethodDef, int, bool)> visited)
    {
        if (depth > MaxParameterDepth || parameter < 0) return false;
        if (!visited.Add((m, parameter, immutableElements))) return true;
        var body = MetadataUtil.SafeBody(m);
        if (body == null) return false;
        var code = body.Instructions;
        for (int q = 0; q < code.Count; q++)
        {
            var use = code[q];
            if (use.OpCode.Code is Code.Ldarga or Code.Ldarga_S && use.GetParameterIndex() == parameter) return false;
            if (use.IsLdarg() && use.GetParameterIndex() == parameter && !ValueOnlyRead(m, body, q, immutableElements, depth, visited)) return false;
        }
        return true;
    }

    private HashSet<Instruction> Targets(MethodDef m, CilBody body)
    {
        if (!_targets.TryGetValue(m, out var targets))
            _targets[m] = targets = new BodyGraph(body).Targets;
        return targets;
    }

    private void Build()
    {
        if (_callees != null) return;
        var callees = new Dictionary<object, HashSet<object>>();
        var callers = new Dictionary<MethodDef, HashSet<MethodDef>>();
        var fieldUses = new Dictionary<FieldDef, List<(MethodDef, int)>>();
        var methods = module.GetTypes().SelectMany(t => t.Methods).ToList();
        var cctors = new Dictionary<TypeDef, MethodDef?>();
        MethodDef? Cctor(TypeDef t) => cctors.TryGetValue(t, out var c) ? c : cctors[t] = t.FindStaticConstructor();

        void Edge(object from, object? to)
        {
            if (to == null) return;
            if (!callees.TryGetValue(from, out var set)) callees[from] = set = new HashSet<object>();
            if (!set.Add(to) || from is not MethodDef caller || to is not MethodDef callee) return;
            if (!callers.TryGetValue(callee, out var back)) callers[callee] = back = new HashSet<MethodDef>();
            back.Add(caller);
        }

        foreach (var m in methods.Where(m => m.IsVirtual))
            Edge(VirtualSlot(m.Name), m);
        foreach (var m in methods)
        {
            var body = MetadataUtil.SafeBody(m);
            if (body == null) continue;
            var code = body.Instructions;
            for (int i = 0; i < code.Count; i++)
            {
                var ins = code[i];
                switch (ins.OpCode.Code)
                {
                    case Code.Call: case Code.Callvirt: case Code.Newobj: case Code.Ldftn: case Code.Ldvirtftn: case Code.Jmp:
                    {
                        var target = MetadataUtil.AsMethod(ins.Operand);
                        if (target is MethodSpec spec) target = spec.Method;
                        var def = target as MethodDef ?? (target is MemberRef mr ? Local(mr) : null);
                        if (def != null && def.Module == module)
                        {
                            Edge(m, def);
                            Edge(m, Cctor(def.DeclaringType));
                        }
                        if (ins.OpCode.Code is Code.Callvirt or Code.Ldvirtftn && target != null)
                            Edge(m, VirtualSlot(target.Name));
                        break;
                    }
                    case Code.Ldsfld: case Code.Stsfld: case Code.Ldsflda:
                        if (ins.Operand is FieldDef fd && fd.Module == module)
                        {
                            Edge(m, Cctor(fd.DeclaringType));
                            if (ins.OpCode.Code != Code.Stsfld)
                            {
                                if (!fieldUses.TryGetValue(fd, out var uses)) fieldUses[fd] = uses = new List<(MethodDef, int)>();
                                uses.Add((m, i));
                            }
                        }
                        break;
                }
            }
        }
        (_callees, _callers, _fieldUses) = (callees, callers, fieldUses);
    }

    private static string VirtualSlot(UTF8String name) => "virtual " + name.String;

    /// <summary>The method a reference names when it is declared by a type of this module (generic instantiations included).</summary>
    private MethodDef? Local(MemberRef mr)
    {
        var owner = mr.Class switch
        {
            TypeDef td => td,
            TypeSpec { TypeSig: GenericInstSig { GenericType.TypeDefOrRef: TypeDef td } } => td,
            _ => null,
        };
        return owner?.Module == module ? SafeResolve(mr) : null;
    }

    private static MethodDef? SafeResolve(MemberRef mr)
    {
        try { return mr.ResolveMethod(); }
        catch { return null; }
    }
}
