using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Core;

/// <summary>
/// A stand-in for a referenced assembly that is not on this machine, rebuilt from how the loaded assemblies use it:
/// every type they reference (with its kind: value types from value-type signatures, box / initobj; interfaces from
/// interface lists; delegates by their Invoke / ctor shape; exceptions from catch clauses; attributes from attribute
/// use; enums are value types with no members used), every member they reference with its exact signature (fields
/// static from ldsfld / stsfld, get_X / set_X pairs as properties, add_X / remove_X as events), and the virtual methods
/// the loaded code overrides. Bodies throw. The decompiler then reads the loaded code against real types (no "unknown
/// result type" guesses, properties instead of accessor calls, overrides it can prove), and an exported project can
/// reference it and build. It is never presented as the real assembly.
/// </summary>
internal static class ReferenceStubs
{
    /// <summary>Assemblies a stub must never stand in for: the core library and the framework.</summary>
    public static bool CanStub(string name) =>
        name is not ("mscorlib" or "netstandard" or "System.Runtime" or "System.Private.CoreLib")
        && Frameworks.SharedFrameworkOf(name) == null && !Frameworks.IsNetFrameworkAssembly(name)
        && !(name.StartsWith("Windows.", StringComparison.Ordinal) && name.EndsWith("Contract", StringComparison.Ordinal)) && name != "Windows";

    private sealed class Member
    {
        public required string Name;
        public required CallingConventionSig Sig;
        public bool Field, Virtual;
        /// <summary>Accessibility: public unless the loaded code overrides it as protected.</summary>
        public MethodAttributes Access = MethodAttributes.Public;
    }

    private sealed class StubType
    {
        public required string Namespace, Name;
        public StubType? Declaring;
        public int Arity;
        public bool Value, Interface, Exception, Attribute, BaseOfLoaded, MembersUsed, DefaultConstructor;
        /// <summary>Interfaces and a base class generic constraints require of it (types of other assemblies).</summary>
        public readonly List<ITypeDefOrRef> Implements = new();
        public ITypeDefOrRef? RequiredBase;
        public readonly Dictionary<string, Member> Members = new(StringComparer.Ordinal);
        public TypeDefUser? Def;
        public string FullName => Declaring != null ? Declaring.FullName + "/" + Name : (Namespace.Length > 0 ? Namespace + "." : "") + Name;
    }

    /// <summary>The stub image for <paramref name="assemblyName"/>, or null when nothing loaded references it (or it cannot be built).</summary>
    public static (byte[] Image, int Types, int Members)? Build(string assemblyName, Version? version, IReadOnlyList<LoadedAssembly> loaded, CancellationToken ct = default)
    {
        var types = new Dictionary<string, StubType>(StringComparer.Ordinal);
        var fieldStatic = new HashSet<string>(StringComparer.Ordinal); // "Type::field" accessed with ldsfld / stsfld
        ModuleDef? corlibSource = null;

        bool IsMissing(ITypeDefOrRef? t) => t is TypeRef tr && string.Equals(tr.DefinitionAssembly?.Name, assemblyName, StringComparison.OrdinalIgnoreCase);

        StubType Info(TypeRef tr)
        {
            if (types.TryGetValue(tr.FullName, out var known)) return known;
            var declaring = tr.ResolutionScope is TypeRef parent ? Info(parent) : null;
            string name = tr.Name;
            int tick = name.LastIndexOf('`');
            var info = new StubType
            {
                Namespace = declaring == null ? tr.Namespace.String : "",
                Name = name,
                Declaring = declaring,
                Arity = tick > 0 && int.TryParse(name[(tick + 1)..], out var n) ? n : 0,
            };
            types[tr.FullName] = info;
            return info;
        }

        StubType? Of(ITypeDefOrRef? t) => t switch
        {
            TypeRef tr when IsMissing(tr) => Info(tr),
            TypeSpec { TypeSig: GenericInstSig { GenericType.TypeDefOrRef: TypeRef gt } } when IsMissing(gt) => Info(gt),
            TypeSpec { TypeSig: ClassOrValueTypeSig c } when IsMissing(c.TypeDefOrRef) => Info((TypeRef)c.TypeDefOrRef),
            _ => null,
        };

        void Visit(TypeSig? sig, int depth = 0)
        {
            while (sig != null && depth++ < 64)
            {
                switch (sig)
                {
                    case ValueTypeSig v:
                        if (IsMissing(v.TypeDefOrRef)) Info((TypeRef)v.TypeDefOrRef).Value = true;
                        return;
                    case ClassSig:
                        return;
                    case GenericInstSig g:
                        if (g.GenericType is ValueTypeSig gv && IsMissing(gv.TypeDefOrRef)) Info((TypeRef)gv.TypeDefOrRef).Value = true;
                        else if (g.GenericType != null && IsMissing(g.GenericType.TypeDefOrRef))
                        {
                            var info = Info((TypeRef)g.GenericType.TypeDefOrRef);
                            info.Arity = Math.Max(info.Arity, g.GenericArguments.Count);
                        }
                        foreach (var a in g.GenericArguments) Visit(a, depth);
                        return;
                    case FnPtrSig f:
                        VisitMethod(f.MethodSig);
                        return;
                    case NonLeafSig n:
                        sig = n.Next;
                        continue;
                    default:
                        return;
                }
            }
        }

        void VisitMethod(MethodBaseSig? s)
        {
            if (s == null) return;
            Visit(s.RetType);
            foreach (var p in s.Params) Visit(p);
            if (s.ParamsAfterSentinel != null) foreach (var p in s.ParamsAfterSentinel) Visit(p);
        }

        // a missing type used as a generic argument must meet the parameter's constraints
        void Constrain(IList<GenericParam> parameters, IList<TypeSig> arguments)
        {
            for (int i = 0; i < parameters.Count && i < arguments.Count; i++)
            {
                if (arguments[i] is not ClassOrValueTypeSig { TypeDefOrRef: TypeRef tr } || !IsMissing(tr)) continue;
                var info = Info(tr);
                var gp = parameters[i];
                if (gp.HasNotNullableValueTypeConstraint) info.Value = true;
                if (gp.HasDefaultConstructorConstraint && !gp.HasNotNullableValueTypeConstraint) info.DefaultConstructor = true;
                foreach (var c in gp.GenericParamConstraints)
                {
                    if (c.Constraint is not { } constraint || constraint.FullName == "System.ValueType") continue;
                    var resolved = Services.MetadataUtil.Try(() => constraint.ResolveTypeDef());
                    if (resolved?.IsInterface == true || IsMissing(constraint) && types.TryGetValue(constraint.FullName, out var mi) && mi.Interface)
                    {
                        if (!info.Implements.Any(x => x.FullName == constraint.FullName)) info.Implements.Add(constraint);
                    }
                    else if (resolved != null && !resolved.IsInterface) info.RequiredBase ??= constraint;
                }
            }
        }

        void Attributes(IHasCustomAttribute? owner)
        {
            if (owner == null) return;
            foreach (var ca in owner.CustomAttributes)
                if (Of(ca.AttributeType) is { } a) a.Attribute = true;
        }

        void AddMember(StubType owner, string name, CallingConventionSig? sig, bool field)
        {
            if (sig == null) return;
            owner.MembersUsed = true;
            var key = (field ? "F:" : "M:") + name + ":" + sig;
            if (!owner.Members.ContainsKey(key)) owner.Members[key] = new Member { Name = name, Sig = sig, Field = field };
        }

        foreach (var asm in loaded)
        {
            ct.ThrowIfCancellationRequested();
            var m = asm.Module;
            bool references = m.GetAssemblyRefs().Any(r => string.Equals(r.Name, assemblyName, StringComparison.OrdinalIgnoreCase));
            if (!references) continue;
            corlibSource ??= m;

            foreach (var tr in m.GetTypeRefs())
                if (IsMissing(tr)) Info(tr);
            Attributes(m.Assembly);
            Attributes(m);

            for (uint rid = 1; rid <= m.TablesStream.TypeSpecTable.Rows; rid++)
                Visit(m.ResolveTypeSpec(rid)?.TypeSig);
            for (uint rid = 1; rid <= m.TablesStream.MethodSpecTable.Rows; rid++)
                if (m.ResolveMethodSpec(rid) is { GenericInstMethodSig: { } inst } spec)
                {
                    foreach (var a in inst.GenericArguments) Visit(a);
                    if (Services.MetadataUtil.Try(() => spec.Method.ResolveMethodDef()) is { } generic)
                        Constrain(generic.GenericParameters, inst.GenericArguments);
                }
            for (uint rid = 1; rid <= m.TablesStream.TypeSpecTable.Rows; rid++)
                if (m.ResolveTypeSpec(rid)?.TypeSig is GenericInstSig { GenericType.TypeDefOrRef: { } open } gi
                    && Services.MetadataUtil.Try(() => open.ResolveTypeDef()) is { } genericType)
                    Constrain(genericType.GenericParameters, gi.GenericArguments);
            for (uint rid = 1; rid <= m.TablesStream.MemberRefTable.Rows; rid++)
            {
                if (m.ResolveMemberRef(rid) is not { } mr) continue;
                var owner = mr.Class switch
                {
                    ITypeDefOrRef t => Of(t),
                    _ => null,
                };
                if (mr.IsFieldRef) Visit(mr.FieldSig?.Type);
                else VisitMethod(mr.MethodSig);
                if (owner != null) AddMember(owner, mr.Name, mr.IsFieldRef ? mr.FieldSig : mr.MethodSig, mr.IsFieldRef);
            }

            foreach (var t in m.GetTypes())
            {
                ct.ThrowIfCancellationRequested();
                Attributes(t);
                if (Of(t.BaseType) is { } baseInfo)
                {
                    baseInfo.BaseOfLoaded = true;
                    // the virtual methods this type overrides exist in its missing base
                    if (t.BaseType is TypeRef)
                        foreach (var md in t.Methods.Where(x => x.IsVirtual && !x.IsNewSlot && !x.IsStatic))
                            if (md.MethodSig != null)
                            {
                                AddMember(baseInfo, md.Name, md.MethodSig, field: false);
                                var overridden = baseInfo.Members[$"M:{md.Name}:{md.MethodSig}"];
                                overridden.Virtual = true;
                                // an override keeps the accessibility it overrides (protected internal is seen as protected)
                                if (md.Access is MethodAttributes.Family or MethodAttributes.FamORAssem) overridden.Access = MethodAttributes.Family;
                            }
                }
                foreach (var ii in t.Interfaces)
                    if (Of(ii.Interface) is { } iface) iface.Interface = true;
                foreach (var gp in t.GenericParameters)
                    foreach (var c in gp.GenericParamConstraints) Visit(c.Constraint?.ToTypeSig());
                foreach (var f in t.Fields) { Visit(f.FieldSig?.Type); Attributes(f); }
                foreach (var p in t.Properties) Attributes(p);
                foreach (var e in t.Events) Attributes(e);
                foreach (var md in t.Methods)
                {
                    VisitMethod(md.MethodSig);
                    Attributes(md);
                    foreach (var p in md.ParamDefs) Attributes(p);
                    foreach (var gp in md.GenericParameters)
                        foreach (var c in gp.GenericParamConstraints) Visit(c.Constraint?.ToTypeSig());
                    foreach (var o in md.Overrides)
                        if (o.MethodDeclaration is MemberRef { Class: ITypeDefOrRef decl } omr && Of(decl) is { } overridden
                            && overridden.Members.TryGetValue($"M:{omr.Name}:{omr.MethodSig}", out var om))
                            om.Virtual = true;
                    if (!md.HasBody) continue;
                    try
                    {
                        foreach (var local in md.Body.Variables) Visit(local.Type);
                        foreach (var eh in md.Body.ExceptionHandlers)
                            if (Of(eh.CatchType) is { } ex) ex.Exception = true;
                        var il = FastIlReader.Instructions(asm, md);
                        for (int k = 0; k < il.Count; k++)
                        {
                            var instr = il[k];
                            // new D(target, &method): the delegate's Invoke has the method's parameters and return
                            if (instr.OpCode.Code == Code.Newobj && instr.Operand is MemberRef { Name.String: ".ctor", Class: ITypeDefOrRef dt } ctor
                                && Of(dt) is { } delegateType && ctor.MethodSig is { Params.Count: 2 } cs && cs.Params[1].ElementType == ElementType.I
                                && k > 0 && il[k - 1].OpCode.Code is Code.Ldftn or Code.Ldvirtftn && il[k - 1].Operand is IMethod { MethodSig: { } target }
                                && !delegateType.Members.Values.Any(m => m.Name == "Invoke"))
                            {
                                var invoke = MethodSig.CreateInstance(target.RetType, target.Params.ToArray());
                                AddMember(delegateType, "Invoke", invoke, field: false);
                            }
                            switch (instr.Operand)
                            {
                                case TypeRef tr when IsMissing(tr) && instr.OpCode.Code is Code.Box or Code.Initobj or Code.Unbox or Code.Unbox_Any
                                    or Code.Sizeof or Code.Ldobj or Code.Stobj or Code.Cpobj or Code.Mkrefany or Code.Constrained:
                                    Info(tr).Value = true;
                                    break;
                                case TypeSpec ts:
                                    Visit(ts.TypeSig);
                                    break;
                                case MemberRef { IsFieldRef: true } fr when instr.OpCode.Code is Code.Ldsfld or Code.Stsfld or Code.Ldsflda
                                    && fr.Class is ITypeDefOrRef fc && Of(fc) is { } fo:
                                    fieldStatic.Add(fo.FullName + "::" + fr.Name);
                                    break;
                            }
                        }
                    }
                    catch (Exception) { /* an unreadable body adds nothing */ }
                }
            }
        }
        if (types.Count == 0 || corlibSource == null) return null;
        try
        {
            var image = Write(assemblyName, version, types, fieldStatic, corlibSource, out int memberCount);
            return (image, types.Count, memberCount);
        }
        catch (Exception) { return null; }
    }

    private static byte[] Write(string assemblyName, Version? version, Dictionary<string, StubType> types, HashSet<string> fieldStatic,
        ModuleDef corlibSource, out int memberCount)
    {
        // the core library a project compiles against: System.Runtime (.NET), netstandard, or mscorlib; never the
        // runtime's implementation (System.Private.CoreLib), which projects do not reference
        var corlib = corlibSource.GetAssemblyRefs().FirstOrDefault(a => a.Name == "System.Runtime")
                     ?? corlibSource.GetAssemblyRefs().FirstOrDefault(a => a.Name == "netstandard")
                     ?? corlibSource.GetAssemblyRefs().FirstOrDefault(a => a.Name == "mscorlib")
                     ?? corlibSource.CorLibTypes.AssemblyRef;
        AssemblyRef corlibRef = corlib.Name == "System.Private.CoreLib"
            ? new AssemblyRefUser("System.Runtime", corlib.Version, new PublicKeyToken("b03f5f7f11d50a3a"))
            : new AssemblyRefUser(corlib.Name, corlib.Version, corlib.PublicKeyOrToken, corlib.Culture);
        var module = new ModuleDefUser(assemblyName + ".dll", Guid.NewGuid(), corlibRef)
        {
            Kind = ModuleKind.Dll,
            RuntimeVersion = "v4.0.30319",
        };
        var assembly = new AssemblyDefUser(assemblyName, version is { } v && !Frameworks.IsWildcard(v) ? v : new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);
        var importer = new Importer(module, ImporterOptions.TryToUseDefs);
        ITypeDefOrRef CorLib(string ns, string name) => new TypeRefUser(module, ns, name, module.CorLibTypes.AssemblyRef);

        // kinds
        // a delegate: constructed from (object, native int), the shape only delegates have
        bool IsDelegate(StubType t) => !t.Value && !t.Interface
                                       && t.Members.Values.Any(m => m.Name == ".ctor" && m.Sig is MethodSig { Params.Count: 2 } s
                                                                    && s.Params[0].ElementType == ElementType.Object && s.Params[1].ElementType == ElementType.I);
        bool IsEnum(StubType t) => t.Value && !t.MembersUsed && t.Arity == 0;

        // the types, outer before nested
        foreach (var t in types.Values.OrderBy(t => Depth(t)))
        {
            ITypeDefOrRef? baseType = t.Interface ? null
                : IsEnum(t) ? CorLib("System", "Enum")
                : t.Value ? CorLib("System", "ValueType")
                : IsDelegate(t) ? CorLib("System", "MulticastDelegate")
                : t.Exception ? CorLib("System", "Exception")
                : t.Attribute ? CorLib("System", "Attribute")
                : t.RequiredBase != null ? importer.Import(t.RequiredBase)
                : module.CorLibTypes.Object.TypeDefOrRef;
            var visibility = t.Declaring == null ? TypeAttributes.Public : TypeAttributes.NestedPublic;
            var flags = visibility | (t.Interface ? TypeAttributes.Interface | TypeAttributes.Abstract
                : t.Value || IsDelegate(t) ? TypeAttributes.Sealed | TypeAttributes.SequentialLayout
                : TypeAttributes.BeforeFieldInit);
            var def = new TypeDefUser(t.Namespace, t.Name, baseType) { Attributes = flags };
            for (int i = 0; i < t.Arity; i++)
                def.GenericParameters.Add(new GenericParamUser((ushort)i, GenericParamAttributes.NonVariant, "T" + i));
            if (IsEnum(t))
                def.Fields.Add(new FieldDefUser("value__", new FieldSig(module.CorLibTypes.Int32),
                    FieldAttributes.Public | FieldAttributes.SpecialName | FieldAttributes.RTSpecialName));
            t.Def = def;
            if (t.Declaring?.Def is { } outer) outer.NestedTypes.Add(def);
            else module.Types.Add(def);
        }

        TypeSig Convert(TypeSig sig) => sig switch
        {
            ClassOrValueTypeSig c when c.TypeDefOrRef is TypeRef tr && types.TryGetValue(tr.FullName, out var st) && st.Def != null
                => st.Value ? new ValueTypeSig(st.Def) : new ClassSig(st.Def),
            GenericInstSig g => new GenericInstSig((ClassOrValueTypeSig)Convert(g.GenericType), g.GenericArguments.Select(Convert).ToList()),
            SZArraySig a => new SZArraySig(Convert(a.Next)),
            ArraySig a => new ArraySig(Convert(a.Next), a.Rank, a.Sizes, a.LowerBounds),
            PtrSig p => new PtrSig(Convert(p.Next)),
            ByRefSig b => new ByRefSig(Convert(b.Next)),
            PinnedSig p => new PinnedSig(Convert(p.Next)),
            CModReqdSig r => new CModReqdSig(importer.Import(r.Modifier), Convert(r.Next)),
            CModOptSig o => new CModOptSig(importer.Import(o.Modifier), Convert(o.Next)),
            _ => importer.Import(sig),
        };

        memberCount = 0;
        foreach (var t in types.Values)
        {
            var def = t.Def!;
            if (t.DefaultConstructor && !t.Interface && !t.Value && !t.Members.Values.Any(m => m.Name == ".ctor" && m.Sig is MethodSig { Params.Count: 0 }))
                t.Members["M:.ctor:default"] = new Member { Name = ".ctor", Sig = MethodSig.CreateInstance(module.CorLibTypes.Void) };
            foreach (var iface in t.Implements)
            {
                ITypeDefOrRef imported = iface is TypeRef itr && types.TryGetValue(itr.FullName, out var local) && local.Def != null ? local.Def : importer.Import(iface);
                def.Interfaces.Add(new InterfaceImplUser(imported));
                // what the interface declares, so the stub implements it (non-generic interfaces of other assemblies)
                if (Services.MetadataUtil.Try(() => iface.ResolveTypeDef()) is { HasGenericParameters: false } declared)
                    foreach (var im in declared.Methods.Where(x => !x.IsStatic && x.IsAbstract && x.MethodSig != null))
                        t.Members.TryAdd($"M:{im.Name}:{im.MethodSig}", new Member { Name = im.Name, Sig = im.MethodSig, Virtual = true });
            }
            var methods = new Dictionary<string, MethodDefUser>(StringComparer.Ordinal);
            foreach (var m in t.Members.Values)
            {
                if (m.Field)
                {
                    if (IsEnum(t) || m.Sig is not FieldSig fs) continue;
                    bool isStatic = fieldStatic.Contains(t.FullName + "::" + m.Name);
                    if (def.Fields.Any(f => f.Name == m.Name)) continue;
                    def.Fields.Add(new FieldDefUser(m.Name, new FieldSig(Convert(fs.Type)), FieldAttributes.Public | (isStatic ? FieldAttributes.Static : 0)));
                    memberCount++;
                    continue;
                }
                if (m.Sig is not MethodSig ms) continue;
                var sig = new MethodSig(ms.CallingConvention, ms.GenParamCount, Convert(ms.RetType), ms.Params.Select(Convert).ToList());
                bool isCtor = m.Name is ".ctor" or ".cctor";
                bool accessor = m.Name.StartsWith("get_", StringComparison.Ordinal) || m.Name.StartsWith("set_", StringComparison.Ordinal)
                                || m.Name.StartsWith("add_", StringComparison.Ordinal) || m.Name.StartsWith("remove_", StringComparison.Ordinal);
                var attrs = m.Access | MethodAttributes.HideBySig
                            | (!ms.HasThis ? MethodAttributes.Static : 0)
                            | (isCtor ? MethodAttributes.SpecialName | MethodAttributes.RTSpecialName : 0)
                            | (accessor ? MethodAttributes.SpecialName : 0)
                            | (t.Interface && ms.HasThis ? MethodAttributes.Virtual | MethodAttributes.NewSlot | MethodAttributes.Abstract : 0)
                            | (!t.Interface && (m.Virtual || IsDelegate(t) && m.Name is "Invoke") && ms.HasThis && !isCtor ? MethodAttributes.Virtual | MethodAttributes.NewSlot : 0)
                            | (!t.Interface && t.Value && m.Virtual ? MethodAttributes.Final : 0);
                var md = new MethodDefUser(m.Name, sig, attrs);
                if (IsDelegate(t) && !isCtor) md.ImplAttributes = MethodImplAttributes.Runtime;
                if (IsDelegate(t) && isCtor) md.ImplAttributes = MethodImplAttributes.Runtime;
                for (int i = 0; i < ms.GenParamCount; i++)
                    md.GenericParameters.Add(new GenericParamUser((ushort)i, GenericParamAttributes.NonVariant, "M" + i));
                for (int i = 0; i < sig.Params.Count; i++)
                    md.ParamDefs.Add(new ParamDefUser(m.Name.StartsWith("set_", StringComparison.Ordinal) && i == sig.Params.Count - 1 ? "value" : "p" + i, (ushort)(i + 1)));
                if (!md.IsAbstract && md.ImplAttributes != MethodImplAttributes.Runtime)
                {
                    var body = new CilBody();
                    body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
                    body.Instructions.Add(OpCodes.Throw.ToInstruction());
                    md.Body = body;
                }
                var key = m.Name + sig;
                if (methods.ContainsKey(key)) continue;
                methods[key] = md;
                def.Methods.Add(md);
                memberCount++;
            }

            // get_X / set_X pairs are properties, add_X / remove_X events (the decompiler then writes x.X, x.X += h)
            foreach (var group in def.Methods.Where(x => x.Name.StartsWith("get_", StringComparison.Ordinal) || x.Name.StartsWith("set_", StringComparison.Ordinal))
                         .GroupBy(x => x.Name.String[4..]).ToList())
            {
                var getter = group.FirstOrDefault(x => x.Name.StartsWith("get_", StringComparison.Ordinal));
                var setter = group.FirstOrDefault(x => x.Name.StartsWith("set_", StringComparison.Ordinal));
                TypeSig? propertyType = getter?.MethodSig.RetType ?? setter?.MethodSig.Params.LastOrDefault();
                if (propertyType == null) continue;
                var index = (getter?.MethodSig.Params ?? setter!.MethodSig.Params.Take(setter.MethodSig.Params.Count - 1).ToList()).ToArray();
                bool isStatic = (getter ?? setter)!.IsStatic;
                var property = new PropertyDefUser(group.Key, isStatic ? PropertySig.CreateStatic(propertyType, index) : PropertySig.CreateInstance(propertyType, index));
                if (getter != null) property.GetMethods.Add(getter);
                if (setter != null) property.SetMethods.Add(setter);
                def.Properties.Add(property);
            }
            foreach (var group in def.Methods.Where(x => (x.Name.StartsWith("add_", StringComparison.Ordinal) || x.Name.StartsWith("remove_", StringComparison.Ordinal))
                                                         && x.MethodSig.Params.Count == 1)
                         .GroupBy(x => x.Name.String[(x.Name.StartsWith("add_", StringComparison.Ordinal) ? 4 : 7)..]).ToList())
            {
                var add = group.FirstOrDefault(x => x.Name.StartsWith("add_", StringComparison.Ordinal));
                var remove = group.FirstOrDefault(x => x.Name.StartsWith("remove_", StringComparison.Ordinal));
                // code that only subscribes uses add_ alone; an event has both
                add ??= Counterpart(def, remove!, "add_" + group.Key);
                remove ??= Counterpart(def, add, "remove_" + group.Key);
                if (add.MethodSig.Params[0].ToTypeDefOrRef() is not { } handler) continue;
                def.Events.Add(new EventDefUser(group.Key, handler) { AddMethod = add, RemoveMethod = remove });
            }
        }

        using var stream = new MemoryStream();
        module.Write(stream, new ModuleWriterOptions(module) { Logger = DummyLogger.NoThrowInstance });
        return stream.ToArray();
    }

    /// <summary>A method like <paramref name="like"/> under another name (an event's missing accessor).</summary>
    private static MethodDefUser Counterpart(TypeDef type, MethodDef like, string name)
    {
        var method = new MethodDefUser(name, like.MethodSig.Clone(), like.ImplAttributes, like.Attributes);
        method.ParamDefs.Add(new ParamDefUser("value", 1));
        if (like.Body != null)
        {
            var body = new CilBody();
            body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            body.Instructions.Add(OpCodes.Throw.ToInstruction());
            method.Body = body;
        }
        type.Methods.Add(method);
        return method;
    }

    private static int Depth(StubType t)
    {
        int d = 0;
        for (var x = t.Declaring; x != null; x = x.Declaring) d++;
        return d;
    }
}
