using System.Diagnostics;
using AssetRipper.Primitives;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
using dnlib.DotNet.Writer;
using LibCpp2IL;
using LibCpp2IL.Metadata;
using Corvus.Core;

namespace Corvus.Services;

/// <summary>
/// global-metadata.dat read without the game binary. The metadata holds the names and the shape of the code: images,
/// types (namespace, name, flags, nesting, value type or enum, generic parameters), methods (name, flags, parameter
/// names, generic parameters), fields, properties, events, metadata tokens and the string literals. Every type a
/// signature names (field, parameter, return and base types other than ValueType / Enum) is an index into the binary's
/// type table, so the dummy assemblies use one placeholder, <see cref="Placeholder"/>, there, and methods have no
/// addresses or bodies. Each Unity sub-version layout of the header version is tried and the first that reads as
/// consistent names and ranges is kept.
/// </summary>
public static class Il2CppMetadataOnly
{
    /// <summary>Each type's enclosing type from the metadata's nestedTypes section, -1 for top-level ones.</summary>
    internal static int[] OuterTypes(Il2CppMetadata meta, int count, Action<int, Exception> unreadable)
    {
        var outer = new int[count];
        Array.Fill(outer, -1);
        for (int t = 0; t < count; t++)
        {
            var d = meta.typeDefs[t];
            if (d.NestedTypeCount == 0) continue;
            try
            {
                foreach (int n in meta.GetNestedTypeIndicesFromIndexAndCount(d.NestedTypesStart, d.NestedTypeCount))
                    if (n >= 0 && n < count && n != t && outer[n] < 0) outer[n] = t;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException) { unreadable(t, ex); }
        }
        return outer;
    }

    /// <summary>Whether following the outer chain from <paramref name="t"/> comes back to it (a damaged nesting table).</summary>
    internal static bool Encloses(int[] outer, int t)
    {
        int steps = 0;
        for (int o = outer[t]; o >= 0; o = outer[o])
            if (o == t || ++steps > 64) return true;
        return false;
    }

    /// <summary>The type standing for every type whose definition is in the binary's type table.</summary>
    public const string Placeholder = "TypeInBinary";

    private const double MinNamedShare = 0.99;

    /// <summary>Reads the metadata and writes the dummy assemblies into <paramref name="dummyDirectory"/>.</summary>
    public static Il2CppMetadataReader.Output Read(Il2CppGameFiles files, string dummyDirectory, Action<string>? progress, CancellationToken ct)
    {
        var watch = Stopwatch.StartNew();
        byte[] bytes;
        try { bytes = File.ReadAllBytes(InputFiles.RequireRegularFile(files.Metadata, "metadata file")); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { throw new ToolError(ErrorCode.IoError, $"Cannot read {files.Metadata}: {ex.Message}"); }
        int header = Il2CppMetadataReader.CheckHeader(files.Metadata, bytes);
        var notes = new List<string>();
        var tried = new List<string>();
        lock (Il2CppMetadataReader.Gate)
        {
            try
            {
                foreach (var (version, source) in Il2CppMetadataReader.UnityVersions(files, header, notes))
                {
                    ct.ThrowIfCancellationRequested();
                    progress?.Invoke($"reading metadata v{header} as Unity {version} (no binary)");
                    Il2CppMetadata meta;
                    try { meta = Il2CppMetadata.ReadFrom(bytes, version); }
                    catch (Exception ex) when (ex is not (OutOfMemoryException or OperationCanceledException))
                    {
                        tried.Add($"Unity {version}: {ex.GetType().Name}: {Format.Clip(ex.Message, 160)}");
                        continue;
                    }
                    double named = NamedShare(meta);
                    if (named < MinNamedShare)
                    {
                        tried.Add($"Unity {version}: only {Format.Percent(named)} of the names and ranges read back consistent");
                        continue;
                    }
                    if (tried.Count > 0) notes.Add($"layout of Unity {version} ({source}) after {tried.Count} other(s) failed: {string.Join("; ", tried)}");
                    LibCpp2IlMain.TheMetadata = meta;
                    var unreadable = new List<Il2CppGameModel.Unreadable>();
                    var builder = new Builder(meta, (item, reason, detail) => unreadable.Add(new(item, reason, detail)));
                    var modules = builder.Build(ct);
                    progress?.Invoke($"writing {modules.Count} dummy assemblies");
                    builder.Write(modules, dummyDirectory, ct);
                    var literals = new string[meta.stringLiterals.Length];
                    for (uint i = 0; i < literals.Length; i++)
                    {
                        try { literals[i] = meta.GetStringLiteralFromIndex(i); }
                        catch (Exception ex) when (ex is not OutOfMemoryException) { literals[i] = ""; unreadable.Add(new($"string literal {i}", "unreadable_literal", ex.Message)); }
                    }
                    var model = new Il2CppGameModel
                    {
                        BinaryPath = "", MetadataPath = Path.GetFullPath(files.Metadata), MetadataVersion = meta.MetadataVersion, HeaderVersion = header,
                        UnityVersion = version.ToString(), UnityVersionSource = source, ImageBase = 0, MemoryImage = false,
                        LiteralValues = literals, LiteralSlots = new uint[literals.Length], Unreadables = unreadable,
                        Images = meta.imageDefinitions.Length, Types = meta.typeDefs.Length, MethodDefinitions = meta.methodDefs.Length,
                        Fields = builder.Fields, MethodsWithCode = 0, ReadTime = watch.Elapsed,
                    };
                    return new Il2CppMetadataReader.Output(model, notes, TimeSpan.Zero, Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes)));
                }
            }
            finally { LibCpp2IlMain.Reset(); }
        }
        throw new ToolError(ErrorCode.MalformedInput,
            $"{files.Metadata} (metadata v{header}) could not be read without the binary: reason unreadable_structures — no Unity sub-version's layout reads it. Tried: {string.Join("; ", tried)}",
            "put the game binary beside the metadata (its registration fixes the layout), or load Il2CppDumper / Cpp2IL output (the DummyDll folder)");
    }

    /// <summary>The share of type and method names that are present and printable, 0 when an index range is out of bounds.</summary>
    private static double NamedShare(Il2CppMetadata meta)
    {
        int types = meta.typeDefs.Length, methods = meta.methodDefs.Length;
        if (types == 0 || meta.imageDefinitions.Length == 0) return 0;
        long covered = 0;
        foreach (var image in meta.imageDefinitions)
        {
            if (image.firstTypeIndex.Value < 0 || image.firstTypeIndex.Value + image.typeCount > types) return 0;
            covered += image.typeCount;
        }
        if (covered != types) return 0;
        int good = 0, total = 0;
        foreach (var d in meta.typeDefs)
        {
            if (d.MethodCount > 0 && (d.FirstMethodIdx.Value < 0 || d.FirstMethodIdx.Value + d.MethodCount > methods)) return 0;
            total++;
            if (Printable(SafeString(meta, d.NameIndex))) good++;
        }
        foreach (var m in meta.methodDefs)
        {
            total++;
            if (Printable(SafeString(meta, m.nameIndex))) good++;
        }
        return (double)good / total;
    }

    private static bool Printable(string? s) => !string.IsNullOrEmpty(s) && s.Length < 1024 && !s.Any(c => char.IsControl(c) || c == '�');

    private static string? SafeString(Il2CppMetadata meta, int index)
    {
        try { return index >= 0 ? meta.GetStringFromIndex(index) : null; }
        catch (Exception ex) when (ex is not OutOfMemoryException) { return null; }
    }

    private sealed class Builder(Il2CppMetadata meta, Action<string, string, string> unreadable)
    {
        private const string AttributeAssembly = Il2CppDummyBuilder.AttributeAssembly;
        private readonly ModuleDefUser[] _modules = new ModuleDefUser[meta.imageDefinitions.Length];
        private readonly int[] _typeImage = new int[meta.typeDefs.Length];
        private readonly TypeDefUser[] _types = new TypeDefUser[meta.typeDefs.Length];
        private readonly Dictionary<int, (TypeSig Placeholder, MemberRef Token, CorLibTypeSig String, Dictionary<string, ITypeDefOrRef> System)> _perModule = [];
        private ModuleDefUser _attributes = null!;
        private AssemblyRef _corlib = null!;
        public int Fields { get; private set; }

        private string Name(int index, string fallback) => SafeString(meta, index) is { Length: > 0 } s ? s : fallback;

        public List<ModuleDefUser> Build(CancellationToken ct)
        {
            var images = meta.imageDefinitions;
            int corlibImage = Array.FindIndex(images, i => string.Equals(SafeString(meta, i.nameIndex), "mscorlib.dll", StringComparison.OrdinalIgnoreCase));
            _corlib = corlibImage >= 0 ? new AssemblyRefUser("mscorlib") : AssemblyRefUser.CreateMscorlibReferenceCLR40();
            for (int i = 0; i < images.Length; i++)
            {
                var name = Name(images[i].nameIndex, $"image{i}.dll");
                var module = new ModuleDefUser(name, Guid.Empty, _corlib) { Kind = ModuleKind.Dll, RuntimeVersion = MDHeaderRuntimeVersion.MS_CLR_40 };
                new AssemblyDefUser(AssemblyName(i, name), Version(i)).Modules.Add(module);
                _modules[i] = module;
                for (int t = images[i].firstTypeIndex.Value; t < images[i].firstTypeIndex.Value + images[i].typeCount; t++) _typeImage[t] = i;
            }
            BuildAttributeModule();
            for (int t = 0; t < _types.Length; t++)
            {
                var d = meta.typeDefs[t];
                _types[t] = new TypeDefUser(Name(d.NamespaceIndex, ""), Name(d.NameIndex, $"Type{t}")) { Attributes = (dnlib.DotNet.TypeAttributes)d.Flags };
            }
            // Nesting from the nestedTypes section: the declaring type index points into the binary's type table.
            var outer = OuterTypes(meta, _types.Length, (t, ex) => unreadable($"type {_types[t].FullName}", "unreadable_nested_types", ex.Message));
            for (int t = 0; t < _types.Length; t++)
            {
                if (outer[t] >= 0 && !Encloses(outer, t))
                {
                    _types[t].Namespace = "";
                    _types[outer[t]].NestedTypes.Add(_types[t]);
                }
                else _modules[_typeImage[t]].Types.Add(_types[t]);
            }
            for (int t = 0; t < _types.Length; t++)
            {
                if ((t & 0xFF) == 0) ct.ThrowIfCancellationRequested();
                try { Fill(t); }
                catch (Exception ex) when (ex is not (OperationCanceledException or OutOfMemoryException)) { unreadable($"type {_types[t].FullName}", "unreadable_type", ex.Message); }
            }
            var all = _modules.ToList();
            all.Add(_attributes);
            return all;
        }

        private string AssemblyName(int image, string fallback)
        {
            int a = meta.imageDefinitions[image].assemblyIndex;
            return a >= 0 && a < meta.AssemblyDefinitions.Length && meta.AssemblyDefinitions[a].AssemblyName.Name is { Length: > 0 } n ? n : Path.GetFileNameWithoutExtension(fallback);
        }

        private System.Version Version(int image)
        {
            int a = meta.imageDefinitions[image].assemblyIndex;
            if (a < 0 || a >= meta.AssemblyDefinitions.Length) return new System.Version(0, 0, 0, 0);
            var n = meta.AssemblyDefinitions[a].AssemblyName;
            return new System.Version(Math.Max(0, n.major), Math.Max(0, n.minor), Math.Max(0, n.build), Math.Max(0, n.revision));
        }

        private void BuildAttributeModule()
        {
            _attributes = new ModuleDefUser(AttributeAssembly + ".dll", Guid.Empty, _corlib) { Kind = ModuleKind.Dll, RuntimeVersion = MDHeaderRuntimeVersion.MS_CLR_40 };
            new AssemblyDefUser(AttributeAssembly, new System.Version(1, 0, 0, 0)).Modules.Add(_attributes);
            var attributeBase = new TypeRefUser(_attributes, "System", "Attribute", _corlib);
            var token = new TypeDefUser(AttributeAssembly, "TokenAttribute", attributeBase) { Attributes = dnlib.DotNet.TypeAttributes.Public };
            token.Fields.Add(new FieldDefUser("Token", new FieldSig(_attributes.CorLibTypes.String), dnlib.DotNet.FieldAttributes.Public));
            var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(_attributes.CorLibTypes.Void),
                dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.HideBySig | dnlib.DotNet.MethodAttributes.SpecialName | dnlib.DotNet.MethodAttributes.RTSpecialName)
            { Body = new CilBody() };
            ctor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            token.Methods.Add(ctor);
            _attributes.Types.Add(token);
            var placeholder = new TypeDefUser(AttributeAssembly, Placeholder, new TypeRefUser(_attributes, "System", "Object", _corlib))
            { Attributes = dnlib.DotNet.TypeAttributes.Public | dnlib.DotNet.TypeAttributes.Sealed | dnlib.DotNet.TypeAttributes.Abstract };
            _attributes.Types.Add(placeholder);
        }

        private (TypeSig Placeholder, MemberRef Token, CorLibTypeSig String, Dictionary<string, ITypeDefOrRef> System) Refs(int module)
        {
            if (_perModule.TryGetValue(module, out var r)) return r;
            var m = _modules[module];
            var scope = new AssemblyRefUser(_attributes.Assembly);
            var tokenCtor = new MemberRefUser(m, ".ctor", MethodSig.CreateInstance(m.CorLibTypes.Void), new TypeRefUser(m, AttributeAssembly, "TokenAttribute", scope));
            r = (new ClassSig(new TypeRefUser(m, AttributeAssembly, Placeholder, scope)), tokenCtor, m.CorLibTypes.String, []);
            _perModule[module] = r;
            return r;
        }

        private ITypeDefOrRef System(int module, string name)
        {
            var refs = Refs(module).System;
            if (!refs.TryGetValue(name, out var t)) refs[name] = t = new TypeRefUser(_modules[module], "System", name, _corlib);
            return t;
        }

        private CustomAttribute Token(int module, uint token)
        {
            var (_, ctor, str, _) = Refs(module);
            return new CustomAttribute(ctor, [], [new CANamedArgument(true, str, "Token", new CAArgument(str, new UTF8String($"0x{token:X}")))]);
        }

        private void Fill(int index)
        {
            var d = meta.typeDefs[index];
            var type = _types[index];
            int module = _typeImage[index];
            var placeholder = Refs(module).Placeholder;
            type.CustomAttributes.Add(Token(module, d.Token));
            if (!d.IsInterface && !(type.Namespace == "System" && type.Name == "Object"))
                type.BaseType = System(module, d.IsEnumType ? "Enum" : d.IsValueType ? "ValueType" : "Object");
            AddGenericParameters(type.GenericParameters, d.GenericContainerIndex);

            if (d.FieldCount > 0)
                foreach (var f in meta.GetFieldDefinitionsFromIndexAndCount(d.FirstFieldIdx, d.FieldCount))
                {
                    // Field attributes and constant types live in the field's type entry in the binary; an enum's members are its static fields.
                    var name = Name(f.nameIndex, $"field{Fields}");
                    var attrs = d.IsEnumType && name != "value__"
                        ? dnlib.DotNet.FieldAttributes.Public | dnlib.DotNet.FieldAttributes.Static
                        : dnlib.DotNet.FieldAttributes.PrivateScope; // shown as privatescope: the access is not known
                    var field = new FieldDefUser(name, new FieldSig(d.IsEnumType ? new ValueTypeSig(type) : placeholder), attrs);
                    if (d.IsEnumType && name == "value__") field.FieldSig = new FieldSig(_modules[module].CorLibTypes.Int32);
                    field.CustomAttributes.Add(Token(module, f.token));
                    type.Fields.Add(field);
                    Fields++;
                }

            var methods = d.MethodCount > 0 ? meta.GetMethodDefinitionsFromIndexAndCount(d.FirstMethodIdx, d.MethodCount) : [];
            var created = new MethodDefUser[methods.Length];
            for (int i = 0; i < methods.Length; i++)
            {
                var m = methods[i];
                var name = Name(m.nameIndex, $"method{i}");
                var method = new MethodDefUser(name, null, (dnlib.DotNet.MethodImplAttributes)(m.iflags & 0x0FFF), (dnlib.DotNet.MethodAttributes)m.flags);
                AddGenericParameters(method.GenericParameters, m.genericContainerIndex);
                var ret = name is ".ctor" or ".cctor" ? _modules[module].CorLibTypes.Void : placeholder;
                var parameters = new TypeSig[m.parameterCount];
                Array.Fill(parameters, placeholder);
                uint generic = (uint)method.GenericParameters.Count;
                method.MethodSig = (m.flags & 0x10) != 0 // static
                    ? generic > 0 ? MethodSig.CreateStaticGeneric(generic, ret, parameters) : MethodSig.CreateStatic(ret, parameters)
                    : generic > 0 ? MethodSig.CreateInstanceGeneric(generic, ret, parameters) : MethodSig.CreateInstance(ret, parameters);
                for (int k = 0; k < m.parameterCount; k++)
                {
                    var p = meta.GetParameterDefinitionFromIndex(Il2CppIndex.Of<Il2CppParameterDefinition>(m.parameterStart.Value + k));
                    method.ParamDefs.Add(new ParamDefUser(Name(p.nameIndex, $"arg{k}"), (ushort)(k + 1)));
                }
                method.CustomAttributes.Add(Token(module, m.token));
                type.Methods.Add(method);
                created[i] = method;
            }
            MethodDef? At(int i) => i >= 0 && i < created.Length ? created[i] : null;

            if (d.PropertyCount > 0)
                foreach (var p in meta.GetPropertyDefinitionsFromIndexAndCount(d.FirstPropertyId, d.PropertyCount))
                {
                    var get = At(p.get.Value);
                    var set = At(p.set.Value);
                    int args = get?.MethodSig.Params.Count ?? Math.Max(0, (set?.MethodSig.Params.Count ?? 1) - 1);
                    var sig = (get ?? set)?.IsStatic == true ? PropertySig.CreateStatic(placeholder, Enumerable.Repeat(placeholder, args).ToArray())
                        : PropertySig.CreateInstance(placeholder, Enumerable.Repeat(placeholder, args).ToArray());
                    var property = new PropertyDefUser(Name(p.nameIndex, "property"), sig, (dnlib.DotNet.PropertyAttributes)p.attrs);
                    if (get != null) property.GetMethods.Add(get);
                    if (set != null) property.SetMethods.Add(set);
                    property.CustomAttributes.Add(Token(module, p.token));
                    type.Properties.Add(property);
                }
            if (d.EventCount > 0)
                foreach (var e in meta.GetEventDefinitionsFromIndexAndCount(d.FirstEventId, d.EventCount))
                {
                    var ev = new EventDefUser(Name(e.nameIndex, "event"), ((ClassSig)placeholder).TypeDefOrRef)
                    {
                        AddMethod = At(e.add.Value), RemoveMethod = At(e.remove.Value), InvokeMethod = At(e.raise.Value),
                    };
                    ev.CustomAttributes.Add(Token(module, e.token));
                    type.Events.Add(ev);
                }
        }

        private void AddGenericParameters(IList<GenericParam> list, Il2CppVariableWidthIndex<Il2CppGenericContainer> index)
        {
            if (index.IsNull || index.Value < 0) return;
            var container = meta.GetGenericContainerFromIndex(index);
            for (int k = 0; k < container.genericParameterCount; k++)
            {
                var gp = meta.GetGenericParameterFromIndex(Il2CppIndex.Of<Il2CppGenericParameter>(container.genericParameterStart.Value + k));
                list.Add(new GenericParamUser((ushort)k, (GenericParamAttributes)gp.flags, Name(gp.nameIndex, $"T{k}")));
            }
        }

        public void Write(List<ModuleDefUser> modules, string directory, CancellationToken ct)
        {
            Directory.CreateDirectory(directory);
            foreach (var module in modules)
            {
                ct.ThrowIfCancellationRequested();
                var clean = string.Concat(module.Name.String.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));
                var file = Path.Combine(directory, clean.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? clean : clean + ".dll");
                try { File.WriteAllBytes(file, DeterministicModule.Write(module, DummyLogger.NoThrowInstance)); }
                catch (Exception ex) when (ex is ModuleWriterException or IOException or InvalidOperationException or ArgumentException)
                {
                    unreadable($"assembly {module.Name}", "write_failed", ex.Message);
                }
            }
        }
    }
}
