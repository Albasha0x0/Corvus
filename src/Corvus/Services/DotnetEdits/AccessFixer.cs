using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;
using static Corvus.Core.MetadataUtil;

namespace Corvus.Services;

/// <summary>Makes patched code pass runtime access checks: relaxes same-assembly members to internal and adds
/// <c>IgnoresAccessChecksTo</c>, honored by .NET and Mono, for other assemblies.</summary>
internal static class AccessFixer
{
    private const string IgnoresAccessChecksTo = "System.Runtime.CompilerServices.IgnoresAccessChecksToAttribute";

    /// <returns>A description of each change made.</returns>
    public static List<string> Fix(ModuleDef module, IEnumerable<MethodDef> methods)
    {
        var changes = new List<string>();
        var foreignAssemblies = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var method in methods)
        {
            var body = method.Body;
            if (body == null) continue;
            var accessor = method.DeclaringType;
            foreach (var instr in body.Instructions)
            {
                if (AsField(instr.Operand) is { } f && Try(() => f.ResolveFieldDef()) is { } fd)
                    Check(fd.DeclaringType, fd, IsFieldAccessible(fd, accessor), RelaxField);
                else if (AsMethod(instr.Operand) is { } m && Try(() => (m is MethodSpec spec ? spec.Method : m).ResolveMethodDef()) is { } md)
                    Check(md.DeclaringType, md, IsMethodAccessible(md, accessor), RelaxMethod);
                if (instr.Operand is ITypeDefOrRef t && Try(() => t.ResolveTypeDef()) is { } td)
                    CheckType(td);
            }
            foreach (var local in body.Variables)
                if (local.Type.ToTypeDefOrRef() is { } lt && Try(() => lt.ResolveTypeDef()) is { } ltd)
                    CheckType(ltd);

            void Check<T>(TypeDef owner, T member, bool accessible, Func<T, string?> relax) where T : IMemberDef
            {
                CheckType(owner);
                if (accessible) return;
                if (owner.Module == module)
                {
                    if (relax(member) is { } change) changes.Add(change);
                }
                else if (owner.Module?.Assembly?.Name is { } other)
                    foreignAssemblies.Add(other);
            }

            void CheckType(TypeDef type)
            {
                for (var t = type; t?.DeclaringType != null; t = t.DeclaringType)
                {
                    if (IsNestedTypeAccessible(t, accessor)) continue;
                    if (t.Module == module)
                    {
                        changes.Add($"type {t.FullName}: {Format.Access(t)} -> internal");
                        t.Visibility = TypeAttributes.NestedAssembly;
                    }
                    else if (t.Module?.Assembly?.Name is { } other)
                        foreignAssemblies.Add(other);
                }
                if (type.Module != module && !IsPublicTopLevel(type) && type.Module?.Assembly?.Name is { } asmName)
                    foreignAssemblies.Add(asmName);
            }
        }

        foreach (var other in foreignAssemblies)
            if (AddIgnoresAccessChecksTo(module, other))
                changes.Add($"[assembly: IgnoresAccessChecksTo(\"{other}\")] (access to non-public members of {other})");
        return changes;
    }

    private static string? RelaxField(FieldDef f)
    {
        var before = Format.Access(f);
        f.Access = f.Access == FieldAttributes.Family ? FieldAttributes.FamORAssem : FieldAttributes.Assembly;
        return $"field {Format.MemberLabel(f)}: {before} -> {Format.Access(f)}";
    }

    private static string? RelaxMethod(MethodDef m)
    {
        var before = Format.Access(m);
        m.Access = m.Access == MethodAttributes.Family ? MethodAttributes.FamORAssem : MethodAttributes.Assembly;
        return $"method {Format.MemberLabel(m)}: {before} -> {Format.Access(m)}";
    }

    private static bool IsPublicTopLevel(TypeDef t)
    {
        for (; t.DeclaringType != null; t = t.DeclaringType)
            if (!t.IsNestedPublic) return false;
        return t.IsPublic;
    }

    private static bool IsFieldAccessible(FieldDef f, TypeDef accessor) => f.Access switch
    {
        FieldAttributes.Public => true,
        FieldAttributes.Assembly or FieldAttributes.FamORAssem => SameModule(f.DeclaringType, accessor) || (f.Access == FieldAttributes.FamORAssem && DerivesFrom(accessor, f.DeclaringType)),
        FieldAttributes.Family => DerivesFrom(accessor, f.DeclaringType) || IsWithin(accessor, f.DeclaringType),
        FieldAttributes.FamANDAssem => SameModule(f.DeclaringType, accessor) && (DerivesFrom(accessor, f.DeclaringType) || IsWithin(accessor, f.DeclaringType)),
        _ => IsWithin(accessor, f.DeclaringType),
    };

    private static bool IsMethodAccessible(MethodDef m, TypeDef accessor) => m.Access switch
    {
        MethodAttributes.Public => true,
        MethodAttributes.Assembly or MethodAttributes.FamORAssem => SameModule(m.DeclaringType, accessor) || (m.Access == MethodAttributes.FamORAssem && DerivesFrom(accessor, m.DeclaringType)),
        MethodAttributes.Family => DerivesFrom(accessor, m.DeclaringType) || IsWithin(accessor, m.DeclaringType),
        MethodAttributes.FamANDAssem => SameModule(m.DeclaringType, accessor) && (DerivesFrom(accessor, m.DeclaringType) || IsWithin(accessor, m.DeclaringType)),
        _ => IsWithin(accessor, m.DeclaringType),
    };

    private static bool IsNestedTypeAccessible(TypeDef t, TypeDef accessor) => t.Visibility switch
    {
        TypeAttributes.NestedPublic => true,
        TypeAttributes.NestedAssembly or TypeAttributes.NestedFamORAssem => SameModule(t, accessor),
        TypeAttributes.NestedFamily => DerivesFrom(accessor, t.DeclaringType) || IsWithin(accessor, t.DeclaringType),
        TypeAttributes.NestedFamANDAssem => SameModule(t, accessor) && (DerivesFrom(accessor, t.DeclaringType) || IsWithin(accessor, t.DeclaringType)),
        _ => IsWithin(accessor, t.DeclaringType),
    };

    private static bool SameModule(TypeDef a, TypeDef b) => a.Module == b.Module;

    /// <summary>True if <paramref name="accessor"/> is <paramref name="owner"/> or nested within it at any depth.</summary>
    private static bool IsWithin(TypeDef accessor, TypeDef owner)
    {
        for (var t = accessor; t != null; t = t.DeclaringType)
            if (t == owner) return true;
        return false;
    }

    private static bool DerivesFrom(TypeDef accessor, TypeDef owner)
    {
        for (var outer = accessor; outer != null; outer = outer.DeclaringType)
            for (var t = BaseTypeDef(outer); t != null; t = BaseTypeDef(t))
                if (t == owner) return true;
        return false;
    }

    /// <summary>Adds the attribute, defining its type if missing. Returns false if already present.</summary>
    private static bool AddIgnoresAccessChecksTo(ModuleDef module, string assemblyName)
    {
        var assembly = module.Assembly ?? throw new ToolError(ErrorCode.Unsupported, "The target module has no assembly manifest.");
        var attrType = module.Find(IgnoresAccessChecksTo, isReflectionName: false) ?? DefineAttribute(module);
        var ctor = attrType.FindInstanceConstructors().First(c => c.MethodSig.Params.Count == 1);
        if (assembly.CustomAttributes.Any(ca => ca.AttributeType == attrType && ca.ConstructorArguments.FirstOrDefault().Value?.ToString() == assemblyName))
            return false;
        assembly.CustomAttributes.Add(new CustomAttribute(ctor, [new CAArgument(module.CorLibTypes.String, new UTF8String(assemblyName))]));
        return true;
    }

    private static TypeDef DefineAttribute(ModuleDef module)
    {
        var attributeRef = module.CorLibTypes.GetTypeRef("System", "Attribute");
        var type = new TypeDefUser("System.Runtime.CompilerServices", "IgnoresAccessChecksToAttribute", attributeRef)
        {
            Attributes = TypeAttributes.NotPublic | TypeAttributes.Class | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit,
        };
        var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName);
        ctor.ParamDefs.Add(new ParamDefUser("assemblyName", 1));
        var baseCtor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), attributeRef);
        ctor.Body = new CilBody();
        ctor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
        ctor.Body.Instructions.Add(OpCodes.Call.ToInstruction(baseCtor));
        ctor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        type.Methods.Add(ctor);
        module.Types.Add(type);
        module.EnableTypeDefFindCache = false;
        module.EnableTypeDefFindCache = true;
        return type;
    }
}
