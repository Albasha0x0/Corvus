using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;

namespace Corvus.Services.Simplify;

// Assumes code in other modules and reflection neither call back into initialization nor modify static objects.
/// <summary>Module call graph facts for sound static reads: what runs during a type initializer, and which statics stay as it left them.</summary>
internal sealed class ModuleFacts(ModuleDef module)
{
    private const int MaxParameterDepth = 6;
    private const int MaxConsumerScan = 64;

    // Nodes are methods, and virtual slots (a method name) through which virtual calls reach every override.
    private Dictionary<object, HashSet<object>>? _callees;
    // Direct callers; virtual methods count as externally callable.
    private Dictionary<MethodDef, HashSet<MethodDef>>? _callers;
    private Dictionary<FieldDef, List<(MethodDef Method, int Index)>>? _fieldUses;
    // Stsfld, and ldsflda since the address may be written through.
    private Dictionary<FieldDef, List<MethodDef>>? _fieldWrites;
    private HashSet<FieldDef>? _writtenInstanceFields;
    private readonly Dictionary<TypeDef, HashSet<MethodDef>> _reach = new();
    private readonly Dictionary<TypeDef, HashSet<MethodDef>> _initOnly = new();
    private readonly Dictionary<FieldDef, bool> _frozen = new();
    private readonly Dictionary<MethodDef, (HashSet<Instruction>, Dictionary<Instruction, int>, Dictionary<Instruction, int>)> _shapes = new();

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

    /// <summary>The static constructor and the methods it reaches that nothing else, in or out of the module, can call.</summary>
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

    /// <summary>Whether every load of the static field outside its initialization only reads the object, transitively.</summary>
    public bool IsFrozen(FieldDef field)
    {
        if (_frozen.TryGetValue(field, out bool frozen)) return frozen;
        Build();
        var init = InitOnly(field.DeclaringType);
        if (CrossInitializer(field) is { } writer) init = [.. init, .. InitOnly(writer)];
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

    /// <summary>Whether every stsfld or ldsflda of the static field, framework handle structs aside, is in its type's
    /// initialization; reflection writes are not seen.</summary>
    public bool WrittenOnlyByInitialization(FieldDef field)
    {
        if (!Hidden(field)) return false;
        Build();
        var init = InitOnly(field.DeclaringType);
        return (_fieldWrites!.GetValueOrDefault(field) ?? []).All(init.Contains);
    }

    // Reads must be in the owner's initializer, in A's, or in A's methods that cannot run during A's initializer.
    /// <summary>The one other precise-init type A whose initializer writes the field, when every read is ordered against it; else null.</summary>
    public TypeDef? CrossInitializer(FieldDef field)
    {
        if (_cross.TryGetValue(field, out var known)) return known;
        _cross[field] = null;
        if (!field.IsStatic || !Hidden(field) || field.DeclaringType.HasGenericParameters) return null;
        Build();
        var owner = field.DeclaringType;
        var ownInit = InitOnly(owner);
        // Writers outside the owner's initializer must all be in one type A's initializer.
        var writers = (_fieldWrites!.GetValueOrDefault(field) ?? []).Where(m => !ownInit.Contains(m)).Distinct().ToList();
        if (writers.Count == 0) return null;
        var a = writers.Select(m => m.DeclaringType).Distinct()
            .FirstOrDefault(t => t != owner && !t.HasGenericParameters && !t.IsBeforeFieldInit && t.FindStaticConstructor() != null && writers.All(InitOnly(t).Contains));
        if (a == null || RunsDuringInitialization(owner, a.FindStaticConstructor()!)) return null;
        var aInit = InitOnly(a);
        var aReach = Reach(a);
        foreach (var (reader, _) in _fieldUses!.GetValueOrDefault(field) ?? [])
        {
            if (ownInit.Contains(reader) || aInit.Contains(reader)) continue;
            if (reader.DeclaringType == a && !aReach.Contains(reader)) continue;
            return null;
        }
        _cross[field] = a;
        return a;
    }

    private readonly Dictionary<FieldDef, TypeDef?> _cross = new();

    /// <summary>Whether a class instance field other assemblies cannot access has no stfld or ldflda, so it always
    /// holds its default.</summary>
    public bool NeverWritten(FieldDef field)
    {
        if (field.IsStatic || field.DeclaringType.IsValueType || !Hidden(field)) return false;
        Build();
        return !_writtenInstanceFields!.Contains(field);
    }

    /// <summary>Whether a static field other assemblies cannot access holds its default because every writer is
    /// uncallable, such as an unused generated Culture setter.</summary>
    public bool AlwaysDefault(FieldDef field)
    {
        if (!field.IsStatic || !Hidden(field)) return false;
        Build();
        var writers = _fieldWrites!.GetValueOrDefault(field) ?? [];
        return writers.All(m => !m.IsStaticConstructor && !m.IsVirtual && m != module.EntryPoint && !Callable(m) &&
                                (_callers!.GetValueOrDefault(m)?.Count ?? 0) == 0);
    }

    /// <summary>Whether another assembly can call the method (internal methods too when the assembly grants friends).</summary>
    private bool Callable(MethodDef m) => m.Access switch
    {
        MethodAttributes.Public or MethodAttributes.Family or MethodAttributes.FamORAssem => true,
        MethodAttributes.Assembly or MethodAttributes.FamANDAssem => module.Assembly?.CustomAttributes.Any(a =>
            a.TypeFullName == "System.Runtime.CompilerServices.InternalsVisibleToAttribute") ?? false,
        _ => false,
    };

    /// <summary>The stsfld sites of a lazily filled field other assemblies cannot access, whose loads all sit in its
    /// writers; null otherwise.</summary>
    public List<(MethodDef Method, int Index)>? LazyStores(FieldDef field)
    {
        if (!field.IsStatic || !Hidden(field)) return null;
        Build();
        var writers = (_fieldWrites!.GetValueOrDefault(field) ?? []).Distinct().ToList();
        if (writers.Count == 0) return null;
        foreach (var (method, _) in _fieldUses!.GetValueOrDefault(field) ?? [])
            if (!writers.Contains(method)) return null;
        var stores = new List<(MethodDef, int)>();
        foreach (var m in writers)
        {
            var body = MetadataUtil.SafeBody(m);
            if (body == null) return null;
            for (int i = 0; i < body.Instructions.Count; i++)
            {
                var ins = body.Instructions[i];
                if (ins.Operand is not FieldDef f || f != field) continue;
                if (ins.OpCode.Code == Code.Ldsflda) return null;
                if (ins.OpCode.Code == Code.Stsfld) stores.Add((m, i));
            }
        }
        return stores;
    }

    /// <summary>The field a reference names when it is declared by a type of this module.</summary>
    private FieldDef? Local(IField field) => field switch
    {
        FieldDef fd => fd.Module == module ? fd : null,
        MemberRef mr when mr.Class is TypeDef or TypeSpec => SafeResolveField(mr) is { } fd && fd.Module == module ? fd : null,
        _ => null,
    };

    private static FieldDef? SafeResolveField(MemberRef mr)
    {
        try { return mr.ResolveField(); }
        catch { return null; }
    }

    /// <summary>Whether no other assembly can access the field: private, or internal to an assembly that grants no friends.</summary>
    private bool Hidden(FieldDef field) => field.Access switch
    {
        FieldAttributes.Private or FieldAttributes.PrivateScope => true,
        FieldAttributes.Assembly or FieldAttributes.FamANDAssem => !(module.Assembly?.CustomAttributes.Any(a =>
            a.TypeFullName == "System.Runtime.CompilerServices.InternalsVisibleToAttribute") ?? false),
        _ => false,
    };

    private static readonly HashSet<string> ImmutableStructs = new(StringComparer.Ordinal)
    {
        "System.RuntimeTypeHandle", "System.RuntimeMethodHandle", "System.RuntimeFieldHandle", "System.ModuleHandle",
    };

    /// <summary>Whether the reference pushed by code[k] is only read: follows it to the instruction that consumes it.</summary>
    private bool ValueOnlyRead(MethodDef m, CilBody body, int k, bool immutableElements, int depth, HashSet<(MethodDef, int, bool)> visited) =>
        Consumer(m, body, k) is var (j, operand) && ConsumerOnlyReads(m, body, j, operand, immutableElements, depth, visited);

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
                // A readonly. ldelema is followed to its consumer.
                return j > 0 && body.Instructions[j - 1].OpCode.Code == Code.Readonly && ValueOnlyRead(m, body, j, immutableElements, depth, visited);
            case Code.Ldelem_Ref: case Code.Ldelem:
                // Mutable elements are followed in turn.
                return immutableElements || ValueOnlyRead(m, body, j, false, depth, visited);
            case Code.Ldfld:
                // A number or string field is only read; an object field is followed in turn.
                return ins.Operand is IField { FieldSig.Type: var type } && (type.IsPrimitive || type.ElementType == ElementType.String || IsEnum(type))
                       || ValueOnlyRead(m, body, j, false, depth, visited);
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
                if (operand == 0 && IsCollection(callee.DeclaringType) && callee.Name.String is "get_Item" or "TryGetValue" or "ContainsKey" or "get_Count"
                        or "Contains" or "IndexOf" or "GetEnumerator")
                    return immutableElements || callee.Name.String is not ("get_Item" or "GetEnumerator") || ValueOnlyRead(m, body, j, false, depth, visited);
                if (IlEvaluator.IntrinsicNames.Contains(callee.FullName))
                    return !IlEvaluator.MutatedArguments(callee.FullName).Contains(operand);
                // A call through a forwarding static delegate field is followed into its target.
                if (ins.OpCode.Code is Code.Call or Code.Callvirt && callee.Name == "Invoke" && callee.MethodSig is { HasThis: true } sig && operand >= 1 &&
                    ProxyTarget(m, body, j, callee, sig) is var (target, call))
                {
                    int passed = operand - 1;
                    if (IlEvaluator.IntrinsicNames.Contains(target.FullName)) return !IlEvaluator.MutatedArguments(target.FullName).Contains(passed);
                    if (target is not MethodDef forwarded || forwarded.Module != module || (call == Code.Callvirt && forwarded.IsVirtual && !forwarded.IsFinal)) return false;
                    return ParameterOnlyRead(forwarded, call == Code.Newobj ? passed + 1 : passed, immutableElements, depth + 1, visited);
                }
                if (callee is not MethodDef def || def.Module != module) return false;
                if (ins.OpCode.Code == Code.Callvirt && def.IsVirtual && !def.IsFinal) return false;
                return ParameterOnlyRead(def, ins.OpCode.Code == Code.Newobj ? operand + 1 : operand, immutableElements, depth + 1, visited);
            }
            default:
                return false;
        }
    }

    /// <summary>Resolves a static delegate field's forwarding target and call opcode, or null; unset, delegate calls are not followed.</summary>
    public Func<FieldDef, int, (IMethod Target, Code Call)?>? DelegateTarget { get; set; }

    private readonly Dictionary<FieldDef, (IMethod, Code)?> _delegateTargets = new();

    /// <summary>The forwarding target of the Invoke at code[j] when a module static delegate field supplies the delegate, or null.</summary>
    private (IMethod Target, Code Call)? ProxyTarget(MethodDef m, CilBody body, int j, IMethod invoke, MethodSig sig)
    {
        if (DelegateTarget == null) return null;
        var (targets, _, _) = Shape(m, body);
        int producer = MethodSimplifier.Producer(body.Instructions, targets, j, sig.Params.Count);
        if (producer < 0 || body.Instructions[producer] is not { OpCode.Code: Code.Ldsfld, Operand: FieldDef { IsStatic: true } field } ||
            field.Module != module || field.FieldType.FullName != invoke.DeclaringType.FullName)
            return null;
        if (!_delegateTargets.TryGetValue(field, out var known)) _delegateTargets[field] = known = DelegateTarget(field, sig.Params.Count);
        return known;
    }

    private static bool IsCollection(ITypeDefOrRef? type) => type?.TryGetGenericInstSig()?.GenericType.FullName is
        "System.Collections.Generic.Dictionary`2" or "System.Collections.Generic.List`1";

    /// <summary>Why a static Dictionary or List is not a cache the evaluator may fill, or null when it is.</summary>
    public string? CacheUse(FieldDef field)
    {
        if (!IsCollection(field.FieldType.ToTypeDefOrRef())) return "is not a Dictionary or List";
        if (!Hidden(field)) return "is visible to other assemblies";
        if (!WrittenOnlyByInitialization(field)) return "is written outside its type's initialization";
        var init = InitOnly(field.DeclaringType);
        foreach (var (method, index) in _fieldUses!.GetValueOrDefault(field) ?? [])
        {
            if (init.Contains(method)) continue;
            var body = MetadataUtil.SafeBody(method);
            if (body == null || body.Instructions[index].OpCode.Code != Code.Ldsfld) return $"has its address taken in {method.FullName}";
            if (Consumer(method, body, index) is not var (j, operand) || operand != 0 || !CacheConsumer(method, body, j, field))
                return $"is used other than through its own methods in {method.FullName}";
        }
        return null;
    }

    private static bool IsMonitor(IMethod method) => method.FullName.StartsWith("System.Void System.Threading.Monitor::", StringComparison.Ordinal);

    /// <summary>Whether code[j] calls a cache method or Monitor, or stores the cache in a local only lock uses.</summary>
    private bool CacheConsumer(MethodDef method, CilBody body, int j, FieldDef field)
    {
        var ins = body.Instructions[j];
        if (MetadataUtil.AsMethod(ins.Operand) is { } callee)
            return callee.DeclaringType?.FullName == field.FieldType.FullName || IsMonitor(callee);
        if (!ins.IsStloc() || ins.GetLocal(body.Variables) is not { } local) return false;
        var code = body.Instructions;
        for (int q = 0; q < code.Count; q++)
        {
            if (code[q].OpCode.Code is Code.Ldloca or Code.Ldloca_S && code[q].GetLocal(body.Variables) == local) return false;
            if (!code[q].IsLdloc() || code[q].GetLocal(body.Variables) != local) continue;
            if (Consumer(method, body, q) is not var (use, operand) || operand != 0 ||
                MetadataUtil.AsMethod(code[use].Operand) is not { } monitor || !IsMonitor(monitor))
                return false;
        }
        return true;
    }

    /// <summary>The consumer of code[k]'s value and its operand position, through straight-line code and single-entry brs; null at merges.</summary>
    private (int Index, int Operand)? Consumer(MethodDef m, CilBody body, int k)
    {
        var code = body.Instructions;
        var (targets, entries, index) = Shape(m, body);
        bool hasReturn = m.MethodSig?.RetType.RemovePinnedAndModifiers().ElementType != ElementType.Void;
        // Stack slots above the value.
        int position = 0;
        bool viaBranch = false;
        for (int j = k + 1, steps = 0; j < code.Count && steps <= MaxConsumerScan; steps++)
        {
            var ins = code[j];
            if (targets.Contains(ins) && !(viaBranch && entries.GetValueOrDefault(ins) == 1)) return null;
            viaBranch = false;
            ins.CalculateStackUsage(hasReturn, out int pushes, out int pops);
            if (pops < 0) return null;
            if (pops > position) return (j, pops - 1 - position);
            position += pushes - pops;
            if (ins.OpCode.Code is Code.Br or Code.Br_S && ins.Operand is Instruction target && index.TryGetValue(target, out int t))
            {
                j = t;
                viaBranch = true;
                continue;
            }
            if (!BodyGraph.FallsThrough(ins)) return null;
            j++;
        }
        return null;
    }

    private static bool IsEnum(TypeSig type)
    {
        try { return type.ElementType == ElementType.ValueType && type.ToTypeDefOrRef()?.ResolveTypeDef() is { IsEnum: true }; }
        catch { return false; }
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

    /// <summary>The method's merge points, how many ways each is entered, and each instruction's index.</summary>
    private (HashSet<Instruction> Targets, Dictionary<Instruction, int> Entries, Dictionary<Instruction, int> Index) Shape(MethodDef m, CilBody body)
    {
        if (_shapes.TryGetValue(m, out var shape)) return shape;
        var code = body.Instructions;
        var targets = new BodyGraph(body).Targets;
        var entries = new Dictionary<Instruction, int>();
        var index = new Dictionary<Instruction, int>(code.Count);
        for (int i = 0; i < code.Count; i++)
        {
            index[code[i]] = i;
            foreach (var t in BodyGraph.BranchTargets(code[i])) entries[t] = entries.GetValueOrDefault(t) + 1;
            if (i + 1 < code.Count && BodyGraph.FallsThrough(code[i])) entries[code[i + 1]] = entries.GetValueOrDefault(code[i + 1]) + 1;
        }
        foreach (var eh in body.ExceptionHandlers)
            foreach (var start in new[] { eh.TryStart, eh.HandlerStart, eh.FilterStart })
                // Region starts never count as a single way in.
                if (start != null) entries[start] = entries.GetValueOrDefault(start) + 2;
        shape = (targets, entries, index);
        _shapes[m] = shape;
        return shape;
    }

    private void Build()
    {
        if (_callees != null) return;
        var callees = new Dictionary<object, HashSet<object>>();
        var callers = new Dictionary<MethodDef, HashSet<MethodDef>>();
        var fieldUses = new Dictionary<FieldDef, List<(MethodDef, int)>>();
        var fieldWrites = new Dictionary<FieldDef, List<MethodDef>>();
        var writtenInstanceFields = new HashSet<FieldDef>();
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

        var dispatch = new VirtualDispatch(module, methods);
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
                            foreach (var callee in dispatch.Targets(target))
                                Edge(m, callee);
                        break;
                    }
                    case Code.Ldsfld: case Code.Stsfld: case Code.Ldsflda:
                        if (ins.Operand is FieldDef fd && fd.Module == module)
                        {
                            Edge(m, Cctor(fd.DeclaringType));
                            if (ins.OpCode.Code == Code.Stsfld || (ins.OpCode.Code == Code.Ldsflda && !ImmutableStructs.Contains(fd.FieldType.FullName)))
                            {
                                if (!fieldWrites.TryGetValue(fd, out var writes)) fieldWrites[fd] = writes = new List<MethodDef>();
                                writes.Add(m);
                            }
                            if (ins.OpCode.Code != Code.Stsfld)
                            {
                                if (!fieldUses.TryGetValue(fd, out var uses)) fieldUses[fd] = uses = new List<(MethodDef, int)>();
                                uses.Add((m, i));
                            }
                        }
                        break;
                    case Code.Stfld: case Code.Ldflda:
                        if (MetadataUtil.AsField(ins.Operand) is { } written && Local(written) is { } instanceField)
                            writtenInstanceFields.Add(instanceField);
                        break;
                }
            }
        }
        (_callees, _callers, _fieldUses, _fieldWrites, _writtenInstanceFields) = (callees, callers, fieldUses, fieldWrites, writtenInstanceFields);
    }

    /// <summary>The module's virtual methods a callvirt can reach, by name and signature in derived types and by explicit override.</summary>
    private sealed class VirtualDispatch
    {
        private readonly Dictionary<string, List<MethodDef>> _byKey = new(StringComparer.Ordinal);
        private readonly Dictionary<string, List<MethodDef>> _explicit = new(StringComparer.Ordinal);
        private readonly Dictionary<TypeDef, HashSet<string>> _ancestors = new();
        private readonly Dictionary<string, List<MethodDef>> _cache = new(StringComparer.Ordinal);

        public VirtualDispatch(ModuleDef module, IEnumerable<MethodDef> methods)
        {
            foreach (var m in methods.Where(m => m.IsVirtual))
            {
                Add(_byKey, Key(m.Name, m.MethodSig), m);
                foreach (var o in m.Overrides)
                    if (o.MethodDeclaration is { } declaration) Add(_explicit, declaration.FullName, m);
            }
        }

        private static void Add(Dictionary<string, List<MethodDef>> map, string key, MethodDef m)
        {
            if (!map.TryGetValue(key, out var list)) map[key] = list = new List<MethodDef>();
            list.Add(m);
        }

        private static string Key(UTF8String name, MethodSig? sig) => name.String + " " + sig?.ToString();

        /// <summary>A type's name without generic arguments (Base`1, not Base`1&lt;int&gt;).</summary>
        private static string Definition(ITypeDefOrRef? type) => type switch
        {
            TypeSpec { TypeSig: GenericInstSig g } => g.GenericType.TypeDefOrRef.FullName,
            null => "",
            _ => type.FullName,
        };

        /// <summary>The type, its base types and the interfaces they implement, as names.</summary>
        private HashSet<string> Ancestors(TypeDef type)
        {
            if (_ancestors.TryGetValue(type, out var set)) return set;
            // Seeding the set guards against cycles.
            _ancestors[type] = set = new HashSet<string>(StringComparer.Ordinal) { type.FullName };
            void Include(ITypeDefOrRef? t)
            {
                if (t == null || !set.Add(Definition(t))) return;
                if (Resolve(t) is { } td)
                    set.UnionWith(Ancestors(td));
            }
            Include(type.BaseType);
            foreach (var i in type.Interfaces) Include(i.Interface);
            return set;
        }

        private static TypeDef? Resolve(ITypeDefOrRef t)
        {
            try { return (t is TypeSpec { TypeSig: GenericInstSig g } ? g.GenericType.TypeDefOrRef : t).ResolveTypeDef(); }
            catch { return null; }
        }

        public List<MethodDef> Targets(IMethod target)
        {
            if (_cache.TryGetValue(target.FullName, out var cached)) return cached;
            var declaring = Definition(target.DeclaringType);
            // A base class may implement an interface method without listing it, so interface calls reach every match.
            bool anyType = declaring == "System.Object" || target.DeclaringType == null || Resolve(target.DeclaringType) is not { IsInterface: false };
            var result = (_byKey.GetValueOrDefault(Key(target.Name, target.MethodSig)) ?? [])
                .Where(m => anyType || Ancestors(m.DeclaringType).Contains(declaring))
                .Concat(_explicit.GetValueOrDefault(target.FullName) ?? [])
                .Distinct().ToList();
            _cache[target.FullName] = result;
            return result;
        }
    }

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
