using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
using dnlib.DotNet.Writer;
using LibCpp2IL;
using LibCpp2IL.BinaryStructures;
using LibCpp2IL.Metadata;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Builds Il2CppDumper-style dummy assemblies from the LibCpp2IL state: one module per metadata image with its types,
/// fields, methods, properties and events, the methods' native addresses as [Address(RVA, Offset, VA, Slot)], field
/// offsets as [FieldOffset(Offset)] and metadata tokens as [Token(Token)] (attributes of an Il2CppDummyDll assembly),
/// enum and constant values, and stub bodies that return a default value. What the existing Il2Cpp tools read from an
/// Il2CppDumper DummyDll folder is here in the same form. Not built: the original custom attributes.
/// </summary>
internal sealed class Il2CppDummyBuilder
{
    public const string AttributeAssembly = "Il2CppDummyDll";

    private readonly Il2CppMetadata _meta;
    private readonly Il2CppBinary _bin;
    private readonly Func<Il2CppMethodDefinition, int, (uint Rva, ulong Offset, ulong Va)?> _address;
    private readonly Action<string, string, string> _unreadable;
    private readonly ModuleDefUser[] _modules;
    private readonly int[] _typeImage;
    private readonly TypeDefUser?[] _types;
    private readonly Dictionary<(int Module, int Type), ITypeDefOrRef> _refs = new();
    private readonly Dictionary<(int Module, int Assembly), AssemblyRef> _asmRefs = new();
    private readonly Dictionary<Il2CppTypeEnum, int> _corlib = new();
    private readonly Dictionary<(int Module, Il2CppType Type), TypeSig> _sigs = new(new SigKeyComparer());
    private readonly Dictionary<int, (MemberRef Address, MemberRef FieldOffset, MemberRef Token, CorLibTypeSig String)> _attributeCtors = new();
    private ModuleDefUser? _attributeModule;
    private TypeDefUser? _addressType, _fieldOffsetType, _tokenType;

    public int Types { get; private set; }
    public int Methods { get; private set; }
    public int Fields { get; private set; }
    public int MethodsWithCode { get; private set; }

    public Il2CppDummyBuilder(Il2CppMetadata meta, Il2CppBinary bin,
        Func<Il2CppMethodDefinition, int, (uint Rva, ulong Offset, ulong Va)?> address, Action<string, string, string> unreadable)
    {
        _meta = meta;
        _bin = bin;
        _address = address;
        _unreadable = unreadable;
        _modules = new ModuleDefUser[meta.imageDefinitions.Length];
        _typeImage = new int[meta.typeDefs.Length];
        _types = new TypeDefUser?[meta.typeDefs.Length];
    }

    /// <summary>Builds every module (and the attribute module) in memory.</summary>
    public List<ModuleDefUser> Build(CancellationToken ct)
    {
        var images = _meta.imageDefinitions;
        int corlibImage = Array.FindIndex(images, i => string.Equals(i.Name, "mscorlib.dll", StringComparison.OrdinalIgnoreCase));
        var corlibName = corlibImage >= 0 ? AssemblyName(corlibImage) : null;
        var corlibRef = corlibName != null ? new AssemblyRefUser(corlibName) : AssemblyRefUser.CreateMscorlibReferenceCLR40();
        for (int i = 0; i < images.Length; i++)
        {
            var image = images[i];
            var name = image.Name ?? $"image{i}.dll";
            var module = new ModuleDefUser(name, Guid.NewGuid(), corlibRef) { Kind = ModuleKind.Dll, RuntimeVersion = MDHeaderRuntimeVersion.MS_CLR_40 };
            var asm = AssemblyName(i) ?? new AssemblyNameInfo(Path.GetFileNameWithoutExtension(name));
            new AssemblyDefUser(asm.Name, asm.Version, asm.PublicKeyOrToken as PublicKey, asm.Culture).Modules.Add(module);
            _modules[i] = module;
            for (int t = image.firstTypeIndex.Value; t < image.firstTypeIndex.Value + image.typeCount && t < _typeImage.Length; t++) _typeImage[t] = i;
        }
        if (corlibImage >= 0)
            for (int t = images[corlibImage].firstTypeIndex.Value; t < images[corlibImage].firstTypeIndex.Value + images[corlibImage].typeCount; t++)
                if (_meta.typeDefs[t] is { Namespace: "System" } d && Primitive(d.Name) is { } e) _corlib.TryAdd(e, t);

        // Type definitions first (references between them need every one), then their members.
        for (int t = 0; t < _types.Length; t++)
        {
            var d = _meta.typeDefs[t];
            _types[t] = new TypeDefUser(d.DeclaringTypeIndex.Value >= 0 ? "" : d.Namespace ?? "", d.Name ?? $"Type{t}") { Attributes = (dnlib.DotNet.TypeAttributes)d.Flags };
        }
        for (int t = 0; t < _types.Length; t++)
        {
            var d = _meta.typeDefs[t];
            int? outer = null;
            try { if (d.DeclaringTypeIndex.Value >= 0) outer = Definition(d.DeclaringTypeIndex.Value); }
            catch (Exception ex) when (ex is not OutOfMemoryException) { _unreadable($"type {SafeName(t)}", "unreadable_declaring_type", $"{ex.Message}; kept at the top level"); }
            if (outer is { } o && _types[o] is { } outerDef && o != t) outerDef.NestedTypes.Add(_types[t]!);
            else _modules[_typeImage[t]].Types.Add(_types[t]!);
        }
        BuildAttributeModule(corlibRef);
        for (int t = 0; t < _types.Length; t++)
        {
            if ((t & 0xFF) == 0) ct.ThrowIfCancellationRequested();
            try { Fill(t); }
            catch (Exception ex) when (ex is not OperationCanceledException and not OutOfMemoryException)
            {
                _unreadable($"type {SafeName(t)}", "unreadable_type", $"{ex.Message} ({ex.StackTrace?.Split('\n').FirstOrDefault()?.Trim()})");
            }
        }
        Types = _types.Length;
        var all = _modules.ToList();
        all.Add(_attributeModule!);
        return all;
    }

    /// <summary>Writes the modules into <paramref name="directory"/>; problems the writer reports become unreadable entries.</summary>
    public void Write(List<ModuleDefUser> modules, string directory, CancellationToken ct)
    {
        Directory.CreateDirectory(directory);
        foreach (var module in modules)
        {
            ct.ThrowIfCancellationRequested();
            var file = Path.Combine(directory, SafeFileName(module.Name));
            var options = new ModuleWriterOptions(module) { Logger = new WriterLog(module.Name, _unreadable) };
            try { module.Write(file, options); }
            catch (Exception ex) when (ex is ModuleWriterException or IOException or InvalidOperationException or ArgumentException)
            {
                _unreadable($"assembly {module.Name}", "write_failed", ex.Message);
            }
        }
    }

    private string SafeName(int type)
    {
        var d = _meta.typeDefs[type];
        try { return string.IsNullOrEmpty(d.Namespace) ? d.Name ?? $"#{type}" : $"{d.Namespace}.{d.Name}"; }
        catch (Exception ex) when (ex is not OutOfMemoryException) { return $"#{type}"; }
    }

    private static string SafeFileName(string name)
    {
        var clean = string.Concat(name.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));
        return clean.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? clean : clean + ".dll";
    }

    private sealed class WriterLog(string module, Action<string, string, string> unreadable) : ILogger
    {
        private int _count;
        public void Log(object sender, LoggerEvent loggerEvent, string format, params object[] args)
        {
            if (loggerEvent != LoggerEvent.Error || ++_count > 20) return;
            unreadable($"assembly {module}", "writer_error", args.Length > 0 ? string.Format(System.Globalization.CultureInfo.InvariantCulture, format, args) : format);
        }
        public bool IgnoresEvent(LoggerEvent loggerEvent) => loggerEvent != LoggerEvent.Error;
    }

    private AssemblyNameInfo? AssemblyName(int image)
    {
        var assemblyIndex = _meta.imageDefinitions[image].assemblyIndex;
        if (assemblyIndex < 0 || assemblyIndex >= _meta.AssemblyDefinitions.Length) return null;
        var n = _meta.AssemblyDefinitions[assemblyIndex].AssemblyName;
        var info = new AssemblyNameInfo(n.Name)
        {
            Version = new Version(Math.Max(0, n.major), Math.Max(0, n.minor), Math.Max(0, n.build), Math.Max(0, n.revision)),
            Culture = n.Culture ?? "",
        };
        if (n.PublicKeyToken is { } token) info.PublicKeyOrToken = new PublicKeyToken(token);
        return info;
    }

    private static Il2CppTypeEnum? Primitive(string? name) => name switch
    {
        "Void" => Il2CppTypeEnum.IL2CPP_TYPE_VOID, "Boolean" => Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN, "Char" => Il2CppTypeEnum.IL2CPP_TYPE_CHAR,
        "SByte" => Il2CppTypeEnum.IL2CPP_TYPE_I1, "Byte" => Il2CppTypeEnum.IL2CPP_TYPE_U1, "Int16" => Il2CppTypeEnum.IL2CPP_TYPE_I2,
        "UInt16" => Il2CppTypeEnum.IL2CPP_TYPE_U2, "Int32" => Il2CppTypeEnum.IL2CPP_TYPE_I4, "UInt32" => Il2CppTypeEnum.IL2CPP_TYPE_U4,
        "Int64" => Il2CppTypeEnum.IL2CPP_TYPE_I8, "UInt64" => Il2CppTypeEnum.IL2CPP_TYPE_U8, "Single" => Il2CppTypeEnum.IL2CPP_TYPE_R4,
        "Double" => Il2CppTypeEnum.IL2CPP_TYPE_R8, "String" => Il2CppTypeEnum.IL2CPP_TYPE_STRING, "TypedReference" => Il2CppTypeEnum.IL2CPP_TYPE_TYPEDBYREF,
        "IntPtr" => Il2CppTypeEnum.IL2CPP_TYPE_I, "UIntPtr" => Il2CppTypeEnum.IL2CPP_TYPE_U, "Object" => Il2CppTypeEnum.IL2CPP_TYPE_OBJECT,
        _ => null,
    };

    private static ElementType ElementOf(Il2CppTypeEnum e) => e switch
    {
        Il2CppTypeEnum.IL2CPP_TYPE_VOID => ElementType.Void, Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN => ElementType.Boolean, Il2CppTypeEnum.IL2CPP_TYPE_CHAR => ElementType.Char,
        Il2CppTypeEnum.IL2CPP_TYPE_I1 => ElementType.I1, Il2CppTypeEnum.IL2CPP_TYPE_U1 => ElementType.U1, Il2CppTypeEnum.IL2CPP_TYPE_I2 => ElementType.I2,
        Il2CppTypeEnum.IL2CPP_TYPE_U2 => ElementType.U2, Il2CppTypeEnum.IL2CPP_TYPE_I4 => ElementType.I4, Il2CppTypeEnum.IL2CPP_TYPE_U4 => ElementType.U4,
        Il2CppTypeEnum.IL2CPP_TYPE_I8 => ElementType.I8, Il2CppTypeEnum.IL2CPP_TYPE_U8 => ElementType.U8, Il2CppTypeEnum.IL2CPP_TYPE_R4 => ElementType.R4,
        Il2CppTypeEnum.IL2CPP_TYPE_R8 => ElementType.R8, Il2CppTypeEnum.IL2CPP_TYPE_STRING => ElementType.String, Il2CppTypeEnum.IL2CPP_TYPE_TYPEDBYREF => ElementType.TypedByRef,
        Il2CppTypeEnum.IL2CPP_TYPE_I => ElementType.I, Il2CppTypeEnum.IL2CPP_TYPE_U => ElementType.U, _ => ElementType.Object,
    };

    /// <summary>The type definition index of a CLASS / VALUETYPE type index; null for other kinds.</summary>
    private int? Definition(int typeIndex)
    {
        var t = _bin.GetType(Il2CppIndex.Of<Il2CppType>(typeIndex));
        return t.Type is Il2CppTypeEnum.IL2CPP_TYPE_CLASS or Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE ? IndexOf(t.AsClass()) : null;
    }

    private readonly Dictionary<Il2CppTypeDefinition, int> _indexes = new(ReferenceEqualityComparer.Instance);

    private int IndexOf(Il2CppTypeDefinition d)
    {
        if (_indexes.Count == 0)
            for (int i = 0; i < _meta.typeDefs.Length; i++) _indexes[_meta.typeDefs[i]] = i;
        return _indexes[d];
    }

    /// <summary>A type definition as seen from module <paramref name="module"/>: itself there, else a TypeRef to its assembly.</summary>
    private ITypeDefOrRef Ref(int type, int module)
    {
        if (_typeImage[type] == module) return _types[type]!;
        if (_refs.TryGetValue((module, type), out var r)) return r;
        var d = _meta.typeDefs[type];
        IResolutionScope scope;
        if (d.DeclaringTypeIndex.Value >= 0 && Definition(d.DeclaringTypeIndex.Value) is { } outer) scope = (IResolutionScope)Ref(outer, module);
        else
        {
            int target = _typeImage[type];
            if (!_asmRefs.TryGetValue((module, target), out var asmRef))
                _asmRefs[(module, target)] = asmRef = new AssemblyRefUser(_modules[target].Assembly);
            scope = asmRef;
        }
        var typeRef = new TypeRefUser(_modules[module], d.DeclaringTypeIndex.Value >= 0 ? "" : d.Namespace ?? "", d.Name ?? "", scope);
        _refs[(module, type)] = typeRef;
        return typeRef;
    }

    private TypeSig Corlib(Il2CppTypeEnum e, int module) =>
        _corlib.TryGetValue(e, out var t) ? new CorLibTypeSig(Ref(t, module), ElementOf(e))
            : _modules[module].CorLibTypes.Object;

    private TypeSig Sig(Il2CppType type, int module, int depth = 0)
    {
        if (depth > 32) return Corlib(Il2CppTypeEnum.IL2CPP_TYPE_OBJECT, module);
        if (_sigs.TryGetValue((module, type), out var known)) return known;
        TypeSig sig;
        switch (type.Type)
        {
            case Il2CppTypeEnum.IL2CPP_TYPE_CLASS or Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                int index = IndexOf(type.AsClass());
                var r = Ref(index, module);
                sig = _meta.typeDefs[index].IsValueType ? new ValueTypeSig(r) : new ClassSig(r);
                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                var generic = type.GetGenericClass();
                int definition = IndexOf(Il2CppDumperNames.Definition(generic, _meta, _bin));
                var inst = generic.Context.class_inst == 0 ? [] : _bin.ReadReadableAtVirtualAddress<Il2CppGenericInst>(generic.Context.class_inst).Types;
                var baseRef = Ref(definition, module);
                ClassOrValueTypeSig open = _meta.typeDefs[definition].IsValueType ? new ValueTypeSig(baseRef) : new ClassSig(baseRef);
                sig = new GenericInstSig(open, inst.Select(a => Sig(a, module, depth + 1)).ToList());
                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                sig = new SZArraySig(Sig(type.GetEncapsulatedType(), module, depth + 1));
                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_ARRAY:
                var array = type.GetArrayType();
                sig = new ArraySig(Sig(array.ElementType, module, depth + 1), Math.Max(1u, array.rank));
                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_PTR:
                sig = new PtrSig(Sig(type.GetEncapsulatedType(), module, depth + 1));
                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_VAR:
                sig = new GenericVar(type.GetGenericParameterDef().genericParameterIndexInOwner);
                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_MVAR:
                sig = new GenericMVar(type.GetGenericParameterDef().genericParameterIndexInOwner);
                break;
            default:
                // FNPTR and other kinds C# cannot name become object
                sig = type.Type is >= Il2CppTypeEnum.IL2CPP_TYPE_VOID and <= Il2CppTypeEnum.IL2CPP_TYPE_STRING
                      or Il2CppTypeEnum.IL2CPP_TYPE_TYPEDBYREF or Il2CppTypeEnum.IL2CPP_TYPE_I or Il2CppTypeEnum.IL2CPP_TYPE_U
                    ? Corlib(type.Type, module)
                    : Corlib(Il2CppTypeEnum.IL2CPP_TYPE_OBJECT, module);
                break;
        }
        sig = type.Byref == 1 ? new ByRefSig(sig) : sig;
        _sigs[(module, type)] = sig;
        return sig;
    }

    private ITypeDefOrRef TypeRefOf(Il2CppType type, int module) => Sig(type, module) switch
    {
        ClassOrValueTypeSig { TypeDefOrRef: { } r } => r,
        var s => new TypeSpecUser(s),
    };

    private void BuildAttributeModule(AssemblyRef corlibRef)
    {
        var module = new ModuleDefUser(AttributeAssembly + ".dll", Guid.NewGuid(), corlibRef) { Kind = ModuleKind.Dll, RuntimeVersion = MDHeaderRuntimeVersion.MS_CLR_40 };
        new AssemblyDefUser(AttributeAssembly, new Version(1, 0, 0, 0)).Modules.Add(module);
        _attributeModule = module;
        ITypeDefOrRef attributeBase = new TypeRefUser(module, "System", "Attribute", corlibRef);
        TypeDefUser Define(string name, params string[] fields)
        {
            var type = new TypeDefUser(AttributeAssembly, name, attributeBase) { Attributes = dnlib.DotNet.TypeAttributes.Public | dnlib.DotNet.TypeAttributes.BeforeFieldInit };
            foreach (var f in fields) type.Fields.Add(new FieldDefUser(f, new FieldSig(module.CorLibTypes.String), dnlib.DotNet.FieldAttributes.Public));
            var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void),
                dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.HideBySig | dnlib.DotNet.MethodAttributes.SpecialName | dnlib.DotNet.MethodAttributes.RTSpecialName);
            ctor.Body = new CilBody();
            ctor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            ctor.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), attributeBase)));
            ctor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            type.Methods.Add(ctor);
            module.Types.Add(type);
            return type;
        }
        _addressType = Define("AddressAttribute", "RVA", "Offset", "VA", "Slot");
        _fieldOffsetType = Define("FieldOffsetAttribute", "Offset");
        _tokenType = Define("TokenAttribute", "Token");
    }

    private (MemberRef Address, MemberRef FieldOffset, MemberRef Token, CorLibTypeSig String) Ctors(int module)
    {
        if (_attributeCtors.TryGetValue(module, out var c)) return c;
        var m = _modules[module];
        var scope = new AssemblyRefUser(_attributeModule!.Assembly);
        var voidSig = (CorLibTypeSig)Corlib(Il2CppTypeEnum.IL2CPP_TYPE_VOID, module);
        MemberRef Ctor(TypeDef t) => new MemberRefUser(m, ".ctor", MethodSig.CreateInstance(voidSig), new TypeRefUser(m, t.Namespace, t.Name, scope));
        c = (Ctor(_addressType!), Ctor(_fieldOffsetType!), Ctor(_tokenType!), (CorLibTypeSig)Corlib(Il2CppTypeEnum.IL2CPP_TYPE_STRING, module));
        _attributeCtors[module] = c;
        return c;
    }

    private static CustomAttribute Attribute(MemberRef ctor, CorLibTypeSig str, params (string Name, string Value)[] values) =>
        new(ctor, [], values.Select(v => new CANamedArgument(true, str, v.Name, new CAArgument(str, new UTF8String(v.Value)))));

    private static string Hex(ulong v) => $"0x{v:X}";

    private void Fill(int index)
    {
        var d = _meta.typeDefs[index];
        var type = _types[index]!;
        int module = _typeImage[index];
        var ctors = Ctors(module);
        type.CustomAttributes.Add(Attribute(ctors.Token, ctors.String, ("Token", Hex(d.Token))));
        if (d.ParentIndex.Value >= 0) type.BaseType = TypeRefOf(_bin.GetType(d.ParentIndex), module);
        if (d.GenericContainer is { } container) AddGenericParameters(type.GenericParameters, container, module);
        foreach (var i in d.RawInterfaces) type.Interfaces.Add(new InterfaceImplUser(TypeRefOf(i, module)));

        var fields = d.Fields ?? [];
        var typeIndex = d.TypeIndex;
        for (int i = 0; i < fields.Length; i++)
        {
            var f = fields[i];
            var raw = f.RawFieldType!;
            var attrs = (dnlib.DotNet.FieldAttributes)raw.Attrs;
            var field = new FieldDefUser(f.Name ?? $"field{i}", new FieldSig(Sig(raw, module)), attrs & ~dnlib.DotNet.FieldAttributes.HasFieldRVA);
            if ((attrs & dnlib.DotNet.FieldAttributes.HasDefault) != 0)
            {
                // Per field: the type-wide FieldDefaults of LibCpp2IL costs seconds on large games.
                object? value = null;
                bool known = false;
                try
                {
                    if (_meta.GetFieldDefaultValue(f) is { } dv) { value = dv.Value; known = true; }
                }
                catch (Exception ex) when (ex is not OutOfMemoryException) { _unreadable($"constant {SafeName(index)}.{f.Name}", "unreadable_constant", ex.Message); }
                if (known && (value != null || (attrs & dnlib.DotNet.FieldAttributes.Literal) != 0)) field.Constant = new ConstantUser(value);
                else field.Attributes &= ~dnlib.DotNet.FieldAttributes.HasDefault;
            }
            field.CustomAttributes.Add(Attribute(ctors.Token, ctors.String, ("Token", Hex(f.token))));
            if ((attrs & dnlib.DotNet.FieldAttributes.Literal) == 0)
            {
                int offset = _bin.GetFieldOffsetFromIndex(typeIndex, i, Il2CppIndex.Of<Il2CppFieldDefinition>(d.FirstFieldIdx.Value + i), d.IsValueType, (attrs & dnlib.DotNet.FieldAttributes.Static) != 0);
                if (offset >= 0) field.CustomAttributes.Add(Attribute(ctors.FieldOffset, ctors.String, ("Offset", Hex((ulong)offset))));
            }
            type.Fields.Add(field);
            Fields++;
        }

        var methods = d.Methods ?? [];
        var created = new MethodDefUser[methods.Length];
        bool isDelegate = d.ParentIndex.Value >= 0 && _bin.GetType(d.ParentIndex) is { Type: Il2CppTypeEnum.IL2CPP_TYPE_CLASS } p && p.AsClass() is { Namespace: "System", Name: "MulticastDelegate" };
        for (int i = 0; i < methods.Length; i++)
        {
            var m = methods[i];
            var method = new MethodDefUser(m.Name ?? $"method{i}", null, (dnlib.DotNet.MethodImplAttributes)(m.iflags & 0x0FFF), (dnlib.DotNet.MethodAttributes)m.flags);
            if (m.GenericContainer is { } mc) AddGenericParameters(method.GenericParameters, mc, module);
            var parameters = m.InternalParameterData ?? [];
            var ret = Sig(m.RawReturnType!, module);
            var paramSigs = parameters.Select(x => Sig(x.RawType!, module)).ToList();
            method.MethodSig = m.IsStatic
                ? MethodSig.CreateStaticGeneric((uint)method.GenericParameters.Count, ret, paramSigs.ToArray())
                : MethodSig.CreateInstanceGeneric((uint)method.GenericParameters.Count, ret, paramSigs.ToArray());
            if (method.GenericParameters.Count == 0)
                method.MethodSig = m.IsStatic ? MethodSig.CreateStatic(ret, paramSigs.ToArray()) : MethodSig.CreateInstance(ret, paramSigs.ToArray());
            for (int k = 0; k < parameters.Length; k++)
            {
                var pattrs = (dnlib.DotNet.ParamAttributes)(parameters[k].RawType!.Attrs & 0xFFFF) & ~dnlib.DotNet.ParamAttributes.HasDefault & ~dnlib.DotNet.ParamAttributes.HasFieldMarshal;
                method.ParamDefs.Add(new ParamDefUser(parameters[k].Name ?? $"p{k}", (ushort)(k + 1), pattrs));
            }
            method.CustomAttributes.Add(Attribute(ctors.Token, ctors.String, ("Token", Hex(m.token))));
            if (_address(m, module) is var (rva, offset, va))
            {
                var values = new List<(string, string)> { ("RVA", Hex(rva)), ("Offset", Hex(offset)), ("VA", Hex(va)) };
                if (m.slot != ushort.MaxValue) values.Add(("Slot", m.slot.ToString(System.Globalization.CultureInfo.InvariantCulture)));
                method.CustomAttributes.Add(Attribute(ctors.Address, ctors.String, values.ToArray()));
                MethodsWithCode++;
            }
            if (!isDelegate && (method.Attributes & dnlib.DotNet.MethodAttributes.Abstract) == 0 && (method.Attributes & dnlib.DotNet.MethodAttributes.PinvokeImpl) == 0
                && (method.ImplAttributes & (dnlib.DotNet.MethodImplAttributes.CodeTypeMask | dnlib.DotNet.MethodImplAttributes.InternalCall)) == 0)
                method.Body = StubBody(ret);
            else if (isDelegate) method.ImplAttributes = dnlib.DotNet.MethodImplAttributes.Runtime | dnlib.DotNet.MethodImplAttributes.Managed;
            type.Methods.Add(method);
            created[i] = method;
            Methods++;
        }

        foreach (var prop in d.Properties ?? [])
        {
            var getter = prop.get.Value >= 0 && prop.get.Value < created.Length ? created[prop.get.Value] : null;
            var setter = prop.set.Value >= 0 && prop.set.Value < created.Length ? created[prop.set.Value] : null;
            if (getter == null && setter == null) continue;
            TypeSig propertyType = getter != null ? getter.MethodSig.RetType : setter!.MethodSig.Params.LastOrDefault() ?? Corlib(Il2CppTypeEnum.IL2CPP_TYPE_OBJECT, module);
            var indexParams = getter != null ? getter.MethodSig.Params.ToArray() : setter!.MethodSig.Params.Take(Math.Max(0, setter.MethodSig.Params.Count - 1)).ToArray();
            bool isStatic = (getter ?? setter)!.IsStatic;
            var property = new PropertyDefUser(prop.Name ?? "", isStatic ? PropertySig.CreateStatic(propertyType, indexParams) : PropertySig.CreateInstance(propertyType, indexParams),
                (dnlib.DotNet.PropertyAttributes)(prop.attrs & 0xFFFF));
            if (getter != null) property.GetMethod = getter;
            if (setter != null) property.SetMethod = setter;
            property.CustomAttributes.Add(Attribute(ctors.Token, ctors.String, ("Token", Hex(prop.token))));
            type.Properties.Add(property);
        }
        foreach (var ev in d.Events ?? [])
        {
            var e = new EventDefUser(ev.Name ?? "", TypeRefOf(ev.RawType!, module), (dnlib.DotNet.EventAttributes)(ev.RawType!.Attrs & 0xFFFF));
            if (ev.add.Value >= 0 && ev.add.Value < created.Length) e.AddMethod = created[ev.add.Value];
            if (ev.remove.Value >= 0 && ev.remove.Value < created.Length) e.RemoveMethod = created[ev.remove.Value];
            if (ev.raise.Value >= 0 && ev.raise.Value < created.Length) e.InvokeMethod = created[ev.raise.Value];
            e.CustomAttributes.Add(Attribute(ctors.Token, ctors.String, ("Token", Hex(ev.token))));
            type.Events.Add(e);
        }
    }

    private void AddGenericParameters(IList<GenericParam> target, Il2CppGenericContainer container, int module)
    {
        foreach (var gp in container.GenericParameters)
        {
            var param = new GenericParamUser(gp.genericParameterIndexInOwner, (GenericParamAttributes)gp.flags, gp.Name ?? $"T{gp.genericParameterIndexInOwner}");
            target.Add(param);
            foreach (var constraint in gp.ConstraintTypes)
                param.GenericParamConstraints.Add(new GenericParamConstraintUser(TypeRefOf(constraint, module)));
        }
    }

    /// <summary>A body returning the default value of <paramref name="ret"/> (Il2CppDumper's stubs).</summary>
    private static CilBody StubBody(TypeSig ret)
    {
        var body = new CilBody { InitLocals = true };
        var r = ret.RemovePinnedAndModifiers();
        if (r.ElementType == ElementType.Void) { }
        else if (r.IsValueType || r.IsGenericParameter || r.ElementType == ElementType.TypedByRef)
        {
            var local = new Local(r);
            body.Variables.Add(local);
            body.Instructions.Add(OpCodes.Ldloca.ToInstruction(local));
            body.Instructions.Add(OpCodes.Initobj.ToInstruction(r.ToTypeDefOrRef()));
            body.Instructions.Add(OpCodes.Ldloc.ToInstruction(local));
        }
        else body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
        body.Instructions.Add(OpCodes.Ret.ToInstruction());
        return body;
    }
}

/// <summary>Signature cache key: module and the (shared) LibCpp2IL type object, by reference.</summary>
internal sealed class SigKeyComparer : IEqualityComparer<(int Module, Il2CppType Type)>
{
    public bool Equals((int Module, Il2CppType Type) a, (int Module, Il2CppType Type) b) => a.Module == b.Module && ReferenceEquals(a.Type, b.Type);
    public int GetHashCode((int Module, Il2CppType Type) k) => HashCode.Combine(k.Module, System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(k.Type));
}
