using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using OpCode = dnlib.DotNet.Emit.OpCode;
using OpCodes = dnlib.DotNet.Emit.OpCodes;

namespace Corvus.Services.Simplify;

/// <summary>
/// A reflection object of the module being evaluated (or a framework type): immutable once created, one instance per
/// member, so reference comparison is member identity. <see cref="Is"/> answers type tests against framework types.
/// </summary>
internal abstract class ReflectionObject
{
    protected abstract string[] Types { get; }

    public virtual bool Is(string typeName) => typeName == "System.Object" || Types.Contains(typeName);
}

internal sealed class TypeObject(TypeSig sig) : ReflectionObject
{
    public TypeSig Sig { get; } = sig;
    protected override string[] Types => ["System.Type", "System.Reflection.TypeInfo", "System.Reflection.MemberInfo", "System.RuntimeType"];
}

internal sealed class FieldObject(FieldDef field) : ReflectionObject
{
    public FieldDef Field { get; } = field;
    protected override string[] Types => ["System.Reflection.FieldInfo", "System.Reflection.MemberInfo"];
}

internal sealed class MethodObject(IMethod method) : ReflectionObject
{
    public IMethod Method { get; } = method;
    public bool IsStatic => !(Method.MethodSig?.HasThis ?? false);
    protected override string[] Types => Method.Name == ".ctor" || Method.Name == ".cctor"
        ? ["System.Reflection.ConstructorInfo", "System.Reflection.MethodBase", "System.Reflection.MemberInfo"]
        : ["System.Reflection.MethodInfo", "System.Reflection.MethodBase", "System.Reflection.MemberInfo"];
}

internal sealed class ParameterObject(TypeObject type) : ReflectionObject
{
    public TypeObject Type { get; } = type;
    protected override string[] Types => ["System.Reflection.ParameterInfo"];
}

/// <summary>The module being evaluated, its assembly, and its ModuleHandle.</summary>
internal sealed class ModuleObject : ReflectionObject
{
    protected override string[] Types => ["System.Reflection.Module", "System.Reflection.RuntimeModule"];
}

internal sealed class AssemblyObject : ReflectionObject
{
    protected override string[] Types => ["System.Reflection.Assembly", "System.Reflection.RuntimeAssembly"];
}

internal sealed class OpCodeObject(OpCode code) : ReflectionObject
{
    public OpCode Code { get; } = code;
    protected override string[] Types => [];
}

/// <summary>A delegate: a static method (or one bound to <see cref="Target"/>), or a dynamic method's recorded IL.</summary>
internal sealed class DelegateObject(TypeSig type, IMethod? method, object? target, DynamicMethodObject? dynamic) : ReflectionObject
{
    public TypeSig Type { get; } = type;
    public IMethod? Method { get; } = method;
    public object? Target { get; } = target;
    public DynamicMethodObject? Dynamic { get; } = dynamic;
    protected override string[] Types => ["System.Delegate", "System.MulticastDelegate"];
    public override bool Is(string typeName) => base.Is(typeName) || typeName == Type.FullName;
}

/// <summary>
/// A DynamicMethod being built: its signature and its IL, emitted by its ILGenerator or, once a delegate is created,
/// decoded from the code its DynamicILInfo was given. Both ways accept the same instructions and operands
/// (<see cref="IlEvaluator.DynamicInstruction"/>).
/// </summary>
internal sealed class DynamicMethodObject(TypeObject? returnType, TypeObject[] parameters) : ReflectionObject
{
    public TypeObject? ReturnType { get; } = returnType;
    public TypeObject[] Parameters { get; } = parameters;
    public List<Instruction> Code { get; } = new();
    /// <summary>Set once a delegate is created: the IL can no longer change.</summary>
    public bool Sealed { get; set; }
    /// <summary>Whether GetILGenerator was called.</summary>
    public bool HasGenerator { get; set; }
    /// <summary>The DynamicILInfo, once GetDynamicILInfo was called.</summary>
    public DynamicILInfoObject? Info { get; set; }
    protected override string[] Types => ["System.Reflection.Emit.DynamicMethod", "System.Reflection.MethodInfo", "System.Reflection.MethodBase", "System.Reflection.MemberInfo"];
}

/// <summary>
/// A DynamicMethod's DynamicILInfo: its token scope and the code SetCode stored. Tokens are numbered as the runtime's
/// DynamicScope numbers them: the entry's index (0 is unused, 1 holds the method's signature) with the metadata table of
/// its kind in the high byte.
/// </summary>
internal sealed class DynamicILInfoObject(DynamicMethodObject method) : ReflectionObject
{
    public DynamicMethodObject Method { get; } = method;
    public List<object?> Tokens { get; } = [null, Signature.Instance];
    public byte[]? Code { get; set; }
    protected override string[] Types => ["System.Reflection.Emit.DynamicILInfo"];

    /// <summary>A signature blob in the scope (the method's own, or one GetTokenFor(byte[]) added).</summary>
    public sealed class Signature
    {
        public static readonly Signature Instance = new();
    }
}

internal sealed class ILGeneratorObject(DynamicMethodObject method) : ReflectionObject
{
    public DynamicMethodObject Method { get; } = method;
    protected override string[] Types => ["System.Reflection.Emit.ILGenerator"];
}

internal sealed partial class IlEvaluator
{
    private readonly Dictionary<string, TypeObject> _typeObjects = new(StringComparer.Ordinal);
    private readonly Dictionary<FieldDef, FieldObject> _fieldObjects = new();
    private readonly Dictionary<string, MethodObject> _methodObjects = new(StringComparer.Ordinal);
    private readonly ModuleObject _moduleObject = new();
    private readonly AssemblyObject _assemblyObject = new();

    private ModuleDef Module => module;

    private TypeObject TypeObjectOf(TypeSig sig)
    {
        var name = sig.FullName;
        if (!_typeObjects.TryGetValue(name, out var t)) _typeObjects[name] = t = new TypeObject(sig);
        return t;
    }

    private FieldObject FieldObjectOf(FieldDef field)
    {
        if (!_fieldObjects.TryGetValue(field, out var f)) _fieldObjects[field] = f = new FieldObject(field);
        return f;
    }

    private MethodObject MethodObjectOf(IMethod method)
    {
        var name = method.FullName;
        if (!_methodObjects.TryGetValue(name, out var m)) _methodObjects[name] = m = new MethodObject(method);
        return m;
    }

    private static readonly Dictionary<string, OpCode> EmitOpCodes = typeof(OpCodes)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(f => f.FieldType == typeof(OpCode))
        .ToDictionary(f => f.Name, f => (OpCode)f.GetValue(null)!, StringComparer.Ordinal);

    private static OpCodeObject OpCodeOf(string name) => EmitOpCodes.TryGetValue(name, out var op)
        ? new OpCodeObject(op)
        : throw Bail(FallbackReason.UnsupportedValue, $"OpCodes.{name}");

    private DelegateObject CreateDelegate(TypeSig type, IMethod method, object? target)
    {
        // Bound to an instance with no fields (a lambda class's singleton): the instance method sees nothing that can change.
        if (target != null && !(Fieldless(target) && (method.MethodSig?.HasThis ?? false)))
            throw Bail(FallbackReason.InstanceObject, $"creates a delegate bound to an object ({Describe(method)})");
        if (target == null && (method.MethodSig?.HasThis ?? false)) throw Bail(FallbackReason.InstanceObject, $"creates a delegate of instance method {Describe(method)}");
        return new DelegateObject(type, method, target, null);
    }

    /// <summary>Invokes a delegate: its static method, or the IL its dynamic method recorded.</summary>
    private object? InvokeDelegate(DelegateObject d, object?[] args)
    {
        if (d.Dynamic is { } dynamic)
        {
            if (args.Length != dynamic.Parameters.Length) throw Bail(FallbackReason.InvalidCode, "delegate invoked with the wrong number of arguments");
            if (_depth + 1 > limits.MaxDepth) throw Bail(FallbackReason.CallDepth, $"call depth exceeds the limit of {limits.MaxDepth}");
            var argSlots = dynamic.Parameters.Select(p => SlotOf(p.Sig)).ToArray();
            var actual = args.Select((a, i) => argSlots[i].Kind == Kind.Opaque ? Opaque.Instance : Store(argSlots[i], a)).ToArray();
            bool returns = dynamic.ReturnType is { } r && r.Sig.ElementType != ElementType.Void;
            var frame = new Frame(null, dynamic.Code, actual, argSlots, [], []) { ReturnsValue = returns };
            _depth++;
            try
            {
                var result = Interpret(frame, sliceMode: false);
                return result == Void ? Void : Store(SlotOf(dynamic.ReturnType!.Sig), result);
            }
            finally
            {
                _depth--;
            }
        }
        if (d.Method is { } method && d.Target == null)
            return Invoke(method, Code.Call, args);
        if (d.Method is { } bound && d.Target is InstanceObject instance && Fieldless(instance))
            return InvokeInstance(instance, bound, Code.Call, [instance, .. args]);
        throw Bail(FallbackReason.InstanceObject, "invokes a delegate bound to an object");
    }

    private static T Of<T>(object? v, string what) where T : class => (v is Pointer p ? p.Get() : v) switch
    {
        T t => t,
        null => throw Bail(FallbackReason.RuntimeError, "null reference"),
        _ => throw Bail(FallbackReason.UnsupportedValue, $"expected {what}"),
    };

    private TypeObject TypeOf(object? v) => Of<TypeObject>(v, "a Type");

    private MethodObject MethodOf(object? v) => Of<MethodObject>(v, "a MethodInfo");

    /// <summary>A metadata token of this module as a member: what Module.ResolveX and ModuleHandle.ResolveXHandle return.</summary>
    private object ResolveToken(object? token, string kind)
    {
        int value = I4(token);
        object? member;
        try
        {
            member = module.ResolveToken(value);
        }
        catch (Exception ex) when (ex is not EvaluationBailout)
        {
            member = null;
        }
        return (kind, member) switch
        {
            ("type", ITypeDefOrRef t) => TypeObjectOf(t.ToTypeSig()),
            ("method", IMethod m) when m is MethodDef or MemberRef { IsMethodRef: true } or MethodSpec => MethodObjectOf(m),
            ("field", FieldDef f) => FieldObjectOf(f),
            _ => throw Bail(FallbackReason.RuntimeError, $"token 0x{value:X8} is not a {kind} of the module"),
        };
    }

    /// <summary>The type of this module a type object stands for, or null.</summary>
    private TypeDef? OwnType(TypeObject t)
    {
        var sig = t.Sig.RemovePinnedAndModifiers();
        if (sig is not (ClassSig or ValueTypeSig)) return null;
        var td = sig.ToTypeDefOrRef() as TypeDef ?? Resolve(sig.ToTypeDefOrRef());
        return td?.Module == module ? td : null;

        static TypeDef? Resolve(ITypeDefOrRef? r)
        {
            try { return r?.ResolveTypeDef(); }
            catch { return null; }
        }
    }

    /// <summary>
    /// Module.ResolveSignature: the signature blob of a field, method, member reference, stand-alone signature or type
    /// specification of this module, as stored.
    /// </summary>
    private byte[] SignatureBlob(int token)
    {
        if (module is not ModuleDefMD md) throw Bail(FallbackReason.UnsupportedValue, "signatures of a module that was not read from an image");
        uint rid = (uint)token & 0x00FFFFFF;
        var tables = md.TablesStream;
        uint blob = (token >> 24) switch
        {
            0x04 when tables.TryReadFieldRow(rid, out var row) => row.Signature,
            0x06 when tables.TryReadMethodRow(rid, out var row) => row.Signature,
            0x0A when tables.TryReadMemberRefRow(rid, out var row) => row.Signature,
            0x11 when tables.TryReadStandAloneSigRow(rid, out var row) => row.Signature,
            0x1B when tables.TryReadTypeSpecRow(rid, out var row) => row.Signature,
            0x2B when tables.TryReadMethodSpecRow(rid, out var row) => row.Instantiation,
            _ => throw Bail(FallbackReason.RuntimeError, $"token 0x{token:X8} has no signature in the module (ArgumentException)"),
        };
        var bytes = md.BlobStream.Read(blob) ?? throw Bail(FallbackReason.InvalidCode, $"the signature of token 0x{token:X8} is outside the blob heap");
        Allocate(bytes.Length + 24);
        return bytes;
    }

    /// <summary>FieldInfo.GetOptionalCustomModifiers / GetRequiredCustomModifiers: one modifier at most (the runtime's order of several is not modelled).</summary>
    private ArrayObject CustomModifiers(FieldDef field, bool optional)
    {
        var found = new List<object?>();
        for (var sig = field.FieldSig?.Type; sig is ModifierSig modifier; sig = modifier.Next)
            if (sig is CModOptSig == optional) found.Add(TypeObjectOf(modifier.Modifier.ToTypeSig()));
        if (found.Count > 1) throw Bail(FallbackReason.UnsupportedValue, "the order of several custom modifiers");
        return NewArray(found.ToArray());
    }

    /// <summary>
    /// MemberInfo.GetCustomAttributes(bool) of a field of this module: a new instance of each attribute class (a class of
    /// this module deriving from System.Attribute), made by running its constructor with the stored arguments. One
    /// attribute at most (the runtime's order of several is not modelled), with constructor arguments of primitive types
    /// or strings and no named arguments; fields the runtime reports pseudo-attributes for (NonSerialized, MarshalAs,
    /// FieldOffset) are not modelled.
    /// </summary>
    private ArrayObject CustomAttributes(object? member)
    {
        if (member is not FieldObject { Field: var field }) throw Bail(FallbackReason.UnsupportedValue, "custom attributes of anything but a field");
        if (field.IsNotSerialized || field.HasFieldMarshal || field.FieldOffset != null)
            throw Bail(FallbackReason.UnsupportedValue, "custom attributes of a field with pseudo-attributes (NonSerialized, MarshalAs, FieldOffset)");
        if (field.CustomAttributes.Count > 1) throw Bail(FallbackReason.UnsupportedValue, "the order of several custom attributes");
        var instances = new List<object?>();
        foreach (var attribute in field.CustomAttributes)
        {
            if (attribute.Constructor is not MethodDef ctor || ctor.Module != module)
                throw Bail(FallbackReason.OtherModule, $"an attribute of another module ({attribute.TypeFullName})");
            if (attribute.NamedArguments.Count > 0) throw Bail(FallbackReason.UnsupportedValue, "an attribute with named arguments");
            var args = attribute.ConstructorArguments.Select(arg => arg.Value switch
            {
                bool b => b ? 1 : 0,
                char c => (int)c,
                sbyte or byte or short or ushort or int => (object?)Convert.ToInt32(arg.Value),
                uint u => unchecked((int)u),
                long l => l,
                ulong ul => unchecked((long)ul),
                float f => f,
                double d => d,
                UTF8String text => text.String,
                null => null,
                _ => throw Bail(FallbackReason.UnsupportedValue, $"an attribute argument of type {arg.Type.FullName}"),
            }).ToArray();
            instances.Add(NewInstance(ctor, args));
        }
        return NewArray(instances.ToArray());
    }

    /// <summary>Members of a type of this module that a BindingFlags value selects, in metadata order (the order the CLR returns them in).</summary>
    private object?[] Members<T>(TypeObject type, object? flagsValue, Func<TypeDef, IEnumerable<T>> members, Func<T, bool> isStatic, Func<T, bool> isPublic, Func<T, object> wrap)
    {
        var flags = (BindingFlags)I4(flagsValue);
        if ((flags & (BindingFlags.FlattenHierarchy | BindingFlags.IgnoreCase)) != 0)
            throw Bail(FallbackReason.UnsupportedValue, "reflection with FlattenHierarchy or IgnoreCase");
        var td = type.Sig.ToTypeDefOrRef()?.ResolveTypeDef();
        if (td == null || td.Module != module) throw Bail(FallbackReason.OtherModule, $"reflects over {type.Sig.FullName} of another module");
        if (td.BaseType != null && (flags & BindingFlags.Instance) != 0 && (flags & BindingFlags.DeclaredOnly) == 0 && td.BaseType.FullName != "System.Object")
            throw Bail(FallbackReason.UnsupportedValue, "reflection over inherited instance members");
        return members(td).Where(m => isStatic(m) ? (flags & BindingFlags.Static) != 0 : (flags & BindingFlags.Instance) != 0)
            .Where(m => isPublic(m) ? (flags & BindingFlags.Public) != 0 : (flags & BindingFlags.NonPublic) != 0)
            .Select(wrap).ToArray();
    }

    private ArrayObject ObjectArray(object?[] items) => NewArray(items);

    /// <summary>Type.GetMethod / GetField by name: the one member of that name, null when there is none (several overloads throw).</summary>
    private object? Single(object?[] members, string name)
    {
        var named = members.Where(m => m switch
        {
            MethodObject method => method.Method.Name == name,
            FieldObject field => field.Field.Name == name,
            _ => false,
        }).ToList();
        return named.Count switch
        {
            0 => null,
            1 => named[0],
            _ => throw Bail(FallbackReason.RuntimeError, $"several members named {name} (AmbiguousMatchException)"),
        };
    }

    /// <summary>The reflection and code-generation API the evaluator models (dnlib full names).</summary>
    private static void AddReflection(Action<string, string, string, string, Func<IlEvaluator, object?[], object?>> add)
    {
        const string I = "System.Int32", B = "System.Boolean", S = "System.String", T = "System.Type", O = "System.Object";
        const string MI = "System.Reflection.MethodInfo", MB = "System.Reflection.MethodBase", FI = "System.Reflection.FieldInfo", Mem = "System.Reflection.MemberInfo";
        const string Mod = "System.Reflection.Module", Asm = "System.Reflection.Assembly", MH = "System.ModuleHandle", BF = "System.Reflection.BindingFlags";
        const string DM = "System.Reflection.Emit.DynamicMethod", IL = "System.Reflection.Emit.ILGenerator", OC = "System.Reflection.Emit.OpCode", D = "System.Delegate";

        // Types and handles. A RuntimeXHandle is kept as the reflection object itself.
        add(T, T, "GetTypeFromHandle", "System.RuntimeTypeHandle", (e, a) => e.TypeOf(a[0]));
        add("System.RuntimeTypeHandle", T, "get_TypeHandle", "", (e, a) => e.TypeOf(a[0]));
        add(B, T, "op_Equality", $"{T},{T}", (_, a) => ReferenceEquals(a[0], a[1]) ? 1 : 0);
        add(B, T, "op_Inequality", $"{T},{T}", (_, a) => ReferenceEquals(a[0], a[1]) ? 0 : 1);
        add(T, T, "GetElementType", "", (e, a) => e.TypeOf(a[0]).Sig.RemovePinnedAndModifiers() is { ElementType: ElementType.SZArray or ElementType.Array or ElementType.ByRef or ElementType.Ptr } array
            ? e.TypeObjectOf(array.Next)
            : null);
        add(Mod, T, "get_Module", "", (e, a) => e.TypeOf(a[0]).Sig.ToTypeDefOrRef()?.ResolveTypeDef()?.Module == e.Module
            ? e._moduleObject
            : throw Bail(FallbackReason.OtherModule, "the module of another assembly's type"));
        add($"{FI}[]", T, "GetFields", BF, (e, a) => e.ObjectArray(e.Members<FieldDef>(e.TypeOf(a[0]), a[1], t => t.Fields, f => f.IsStatic, f => f.IsPublic, e.FieldObjectOf)));
        add($"{MI}[]", T, "GetMethods", BF, (e, a) => e.ObjectArray(e.Members<MethodDef>(e.TypeOf(a[0]), a[1], t => t.Methods.Where(m => !m.IsConstructor), m => m.IsStatic, m => m.IsPublic, m => e.MethodObjectOf(m))));
        const int DefaultLookup = (int)(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public);
        add(MI, T, "GetMethod", $"{S},{BF}", (e, a) => e.Single(e.Members<MethodDef>(e.TypeOf(a[0]), a[2], t => t.Methods.Where(m => !m.IsConstructor), m => m.IsStatic,
            m => m.IsPublic, m => e.MethodObjectOf(m)), Str(a[1])));
        add(MI, T, "GetMethod", S, (e, a) => e.Single(e.Members<MethodDef>(e.TypeOf(a[0]), DefaultLookup, t => t.Methods.Where(m => !m.IsConstructor), m => m.IsStatic,
            m => m.IsPublic, m => e.MethodObjectOf(m)), Str(a[1])));
        add(FI, T, "GetField", $"{S},{BF}", (e, a) => e.Single(e.Members<FieldDef>(e.TypeOf(a[0]), a[2], t => t.Fields, f => f.IsStatic, f => f.IsPublic, e.FieldObjectOf), Str(a[1])));
        add(FI, T, "GetField", S, (e, a) => e.Single(e.Members<FieldDef>(e.TypeOf(a[0]), DefaultLookup, t => t.Fields, f => f.IsStatic, f => f.IsPublic, e.FieldObjectOf), Str(a[1])));
        add(S, Mem, "get_Name", "", (e, a) => (a[0] is Pointer p ? p.Get() : a[0]) switch
        {
            FieldObject f => f.Field.Name.String,
            MethodObject m => m.Method.Name.String,
            TypeObject t => t.Sig.TypeName,
            null => throw Bail(FallbackReason.RuntimeError, "null reference"),
            _ => throw Bail(FallbackReason.UnsupportedValue, "the name of an object the interpreter does not model"),
        });
        add(I, Mem, "get_MetadataToken", "", (e, a) => (a[0] is Pointer p ? p.Get() : a[0]) switch
        {
            FieldObject f => (int)f.Field.MDToken.Raw,
            MethodObject { Method: IMDTokenProvider m } => (int)m.MDToken.Raw,
            // The runtime gives a type's token in the module defining it: known for this module's own types only.
            TypeObject t => e.OwnType(t) is { } td ? (int)td.MDToken.Raw : throw Bail(FallbackReason.OtherModule, $"the metadata token of {t.Sig.FullName}, defined in another module"),
            null => throw Bail(FallbackReason.RuntimeError, "null reference"),
            _ => throw Bail(FallbackReason.UnsupportedValue, "the token of an object the interpreter does not model"),
        });
        add(Mod, Mem, "get_Module", "", (e, a) => (a[0] is Pointer p ? p.Get() : a[0]) switch
        {
            FieldObject => e._moduleObject,
            MethodObject { Method: MethodDef m } when m.Module == e.Module => e._moduleObject,
            TypeObject t when e.OwnType(t) != null => e._moduleObject,
            null => throw Bail(FallbackReason.RuntimeError, "null reference"),
            _ => throw Bail(FallbackReason.OtherModule, "the module of a member of another module"),
        });
        add(T, Mem, "get_DeclaringType", "", (e, a) => (a[0] is Pointer p ? p.Get() : a[0]) switch
        {
            FieldObject f => e.TypeObjectOf(f.Field.DeclaringType.ToTypeSig()),
            MethodObject { Method: MethodDef m } => e.TypeObjectOf(m.DeclaringType.ToTypeSig()),
            null => throw Bail(FallbackReason.RuntimeError, "null reference"),
            _ => throw Bail(FallbackReason.UnsupportedValue, "the declaring type of an object the interpreter does not model"),
        });
        add("System.Object[]", Mem, "GetCustomAttributes", B, (e, a) => e.CustomAttributes(a[0] is Pointer p ? p.Get() : a[0]));

        // Fields
        add(T, FI, "get_FieldType", "", (e, a) => e.TypeObjectOf(Of<FieldObject>(a[0], "a FieldInfo").Field.FieldType));
        add($"{T}[]", FI, "GetOptionalCustomModifiers", "", (e, a) => e.CustomModifiers(Of<FieldObject>(a[0], "a FieldInfo").Field, optional: true));
        add($"{T}[]", FI, "GetRequiredCustomModifiers", "", (e, a) => e.CustomModifiers(Of<FieldObject>(a[0], "a FieldInfo").Field, optional: false));
        add(FI, FI, "GetFieldFromHandle", "System.RuntimeFieldHandle", (e, a) => a[0] switch
        {
            FieldHandle h => e.FieldObjectOf(h.Field),
            FieldObject f => f,
            _ => throw Bail(FallbackReason.UnsupportedValue, "expected a field handle"),
        });
        add("System.Void", FI, "SetValue", $"{O},{O}", (e, a) =>
        {
            var field = Of<FieldObject>(a[0], "a FieldInfo").Field;
            if (!field.IsStatic || a[1] != null) throw Bail(FallbackReason.InstanceObject, "sets an instance field by reflection");
            e.StoreStatic(field, a[2]);
            return null;
        });

        // Methods
        add(B, MB, "get_IsStatic", "", (e, a) => e.MethodOf(a[0]).IsStatic ? 1 : 0);
        add(T, MI, "get_ReturnType", "", (e, a) => e.TypeObjectOf(e.MethodOf(a[0]).Method.MethodSig.RetType));
        add("System.Reflection.ParameterInfo[]", MB, "GetParameters", "", (e, a) =>
            e.ObjectArray(e.MethodOf(a[0]).Method.MethodSig.Params.Select(p => (object?)new ParameterObject(e.TypeObjectOf(p))).ToArray()));
        add(T, "System.Reflection.ParameterInfo", "get_ParameterType", "", (_, a) => Of<ParameterObject>(a[0], "a ParameterInfo").Type);
        add(MB, MB, "GetMethodFromHandle", "System.RuntimeMethodHandle", (e, a) => e.MethodOf(a[0]));
        // Handles are kept as the reflection objects themselves.
        add("System.RuntimeMethodHandle", MB, "get_MethodHandle", "", (e, a) => e.MethodOf(a[0]));
        add("System.RuntimeFieldHandle", FI, "get_FieldHandle", "", (_, a) => Of<FieldObject>(a[0], "a FieldInfo"));

        // The module and its handle
        // (A ModuleHandle is kept as the module itself.)
        add(Asm, Asm, "GetExecutingAssembly", "", (e, _) => e._assemblyObject);
        add($"{Mod}[]", Asm, "GetModules", "", (e, a) =>
        {
            Of<AssemblyObject>(a[0], "an Assembly");
            return e.ObjectArray([e._moduleObject]);
        });
        add(Mod, Asm, "get_ManifestModule", "", (e, a) =>
        {
            Of<AssemblyObject>(a[0], "an Assembly");
            return e._moduleObject;
        });
        add(MH, Mod, "get_ModuleHandle", "", (_, a) => Of<ModuleObject>(a[0], "a Module"));
        add("System.Byte[]", Mod, "ResolveSignature", I, (e, a) =>
        {
            Of<ModuleObject>(a[0], "a Module");
            return e.NewArray(e.SignatureBlob(I4(a[1])));
        });
        foreach (var (ret, owner, name, kind) in new[]
                 {
                     ("System.RuntimeTypeHandle", MH, "ResolveTypeHandle", "type"), ("System.RuntimeMethodHandle", MH, "ResolveMethodHandle", "method"),
                     ("System.RuntimeFieldHandle", MH, "ResolveFieldHandle", "field"), (T, Mod, "ResolveType", "type"), (MB, Mod, "ResolveMethod", "method"),
                     (FI, Mod, "ResolveField", "field"), ("System.RuntimeTypeHandle", MH, "GetRuntimeTypeHandleFromMetadataToken", "type"),
                     ("System.RuntimeMethodHandle", MH, "GetRuntimeMethodHandleFromMetadataToken", "method"),
                     ("System.RuntimeFieldHandle", MH, "GetRuntimeFieldHandleFromMetadataToken", "field"),
                 })
        {
            add(ret, owner, name, I, (e, a) =>
            {
                Of<ModuleObject>(a[0], "a Module or ModuleHandle");
                return e.ResolveToken(a[1], kind);
            });
        }

        // Delegates
        add(D, D, "CreateDelegate", $"{T},{MI}", (e, a) => e.CreateDelegate(e.TypeOf(a[0]).Sig, e.MethodOf(a[1]).Method, null));

        // DynamicMethod and ILGenerator: the emitted IL is recorded.
        Func<IlEvaluator, object?[], object?> newDynamic = (e, a) =>
        {
            var parameters = a[2] == null ? [] : ArrayOf(a[2]).Data is object?[] items ? items.Select(e.TypeOf).ToArray() : throw Bail(FallbackReason.InvalidCode, "expected a Type array");
            return new DynamicMethodObject(a[1] == null ? null : e.TypeOf(a[1]), parameters);
        };
        add("System.Void", DM, ".ctor", $"{S},{T},{T}[]", newDynamic);
        add("System.Void", DM, ".ctor", $"{S},{T},{T}[],{B}", newDynamic);
        add("System.Void", DM, ".ctor", $"{S},{T},{T}[],{T}", newDynamic);
        add("System.Void", DM, ".ctor", $"{S},{T},{T}[],{T},{B}", newDynamic);
        add("System.Void", DM, ".ctor", $"{S},{T},{T}[],{Mod}", newDynamic);
        add("System.Void", DM, ".ctor", $"{S},{T},{T}[],{Mod},{B}", newDynamic);
        add(IL, DM, "GetILGenerator", "", (_, a) =>
        {
            var dynamic = Of<DynamicMethodObject>(a[0], "a DynamicMethod");
            if (dynamic.Info != null) throw Bail(FallbackReason.UnsupportedValue, "builds a dynamic method with both a DynamicILInfo and an ILGenerator");
            dynamic.HasGenerator = true;
            return new ILGeneratorObject(dynamic);
        });
        Func<IlEvaluator, object?[], object?> createDynamicDelegate = (e, a) =>
        {
            var dynamic = Of<DynamicMethodObject>(a[0], "a DynamicMethod");
            if (dynamic.Info is { } info && !dynamic.Sealed) e.DecodeDynamicCode(info);
            dynamic.Sealed = true;
            return new DelegateObject(e.TypeOf(a[1]).Sig, null, null, dynamic);
        };
        add(D, DM, "CreateDelegate", T, createDynamicDelegate);
        add(D, MI, "CreateDelegate", T, createDynamicDelegate);
        // DynamicILInfo: GetTokenFor fills the token scope; the code SetCode stores is decoded when the delegate is created.
        const string Info = "System.Reflection.Emit.DynamicILInfo";
        add(Info, DM, "GetDynamicILInfo", "", (_, a) =>
        {
            var dynamic = Of<DynamicMethodObject>(a[0], "a DynamicMethod");
            if (dynamic.HasGenerator) throw Bail(FallbackReason.UnsupportedValue, "builds a dynamic method with both an ILGenerator and a DynamicILInfo");
            return dynamic.Info ??= new DynamicILInfoObject(dynamic);
        });
        add(DM, Info, "get_DynamicMethod", "", (_, a) => Of<DynamicILInfoObject>(a[0], "a DynamicILInfo").Method);
        add(I, Info, "GetTokenFor", "System.RuntimeMethodHandle", (_, a) => Token(a[0], 0x06000000, Of<MethodObject>(a[1], "a method handle")));
        add(I, Info, "GetTokenFor", DM, (_, a) => Token(a[0], 0x06000000, Of<DynamicMethodObject>(a[1], "a DynamicMethod")));
        add(I, Info, "GetTokenFor", "System.RuntimeFieldHandle", (_, a) => Token(a[0], 0x04000000, (a[1] is Pointer p ? p.Get() : a[1]) switch
        {
            FieldHandle h => h.Field,
            FieldObject f => f.Field,
            null => throw Bail(FallbackReason.RuntimeError, "null reference"),
            _ => throw Bail(FallbackReason.UnsupportedValue, "expected a field handle"),
        }));
        add(I, Info, "GetTokenFor", "System.RuntimeTypeHandle", (e, a) => Token(a[0], 0x02000000, e.TypeOf(a[1])));
        add(I, Info, "GetTokenFor", S, (_, a) => Token(a[0], 0x70000000, Str(a[1])));
        add(I, Info, "GetTokenFor", "System.Byte[]", (_, a) => Token(a[0], 0x11000000, DynamicILInfoObject.Signature.Instance));
        add("System.Void", Info, "SetCode", "System.Byte[],System.Int32", (e, a) =>
        {
            var info = Of<DynamicILInfoObject>(a[0], "a DynamicILInfo");
            if (info.Method.Sealed) throw Bail(FallbackReason.UnsupportedValue, "sets the code of a dynamic method after creating its delegate");
            var code = a[1] == null ? [] : ArrayOf(a[1]).Data as byte[] ?? throw Bail(FallbackReason.InvalidCode, "expected a byte array");
            e.Allocate(24 + code.Length);
            info.Code = (byte[])code.Clone(); // the runtime copies the array
            return null;
        });
        add("System.Void", Info, "SetLocalSignature", "System.Byte[]", (_, a) =>
        {
            Of<DynamicILInfoObject>(a[0], "a DynamicILInfo");
            // LOCAL_SIG with a count of 0 is the only signature without locals.
            if (a[1] == null || ArrayOf(a[1]).Data is not byte[] { Length: 2 } sig || sig[0] != 0x07 || sig[1] != 0)
                throw Bail(FallbackReason.UnsupportedValue, "declares locals of a dynamic method (locals of dynamic methods are not modelled)");
            return null;
        });
        add("System.Void", Info, "SetExceptions", "System.Byte[]", (_, a) =>
        {
            Of<DynamicILInfoObject>(a[0], "a DynamicILInfo");
            if (a[1] != null && ArrayOf(a[1]).Data.Length > 0)
                throw Bail(FallbackReason.UnsupportedValue, "declares exception handlers of a dynamic method (they are not modelled)");
            return null;
        });

        add("System.Void", IL, "Emit", OC, (_, a) => Emit(a, null));
        add("System.Void", IL, "Emit", $"{OC},{I}", (_, a) => Emit(a, I4(a[2])));
        add("System.Void", IL, "Emit", $"{OC},System.Byte", (_, a) => Emit(a, I4(a[2])));
        add("System.Void", IL, "Emit", $"{OC},System.SByte", (_, a) => Emit(a, I4(a[2])));
        add("System.Void", IL, "Emit", $"{OC},System.Int16", (_, a) => Emit(a, I4(a[2])));
        add("System.Void", IL, "Emit", $"{OC},System.Int64", (_, a) => Emit(a, a[2] as long? ?? throw Bail(FallbackReason.InvalidCode, "expected an int64")));
        add("System.Void", IL, "Emit", $"{OC},{S}", (_, a) => Emit(a, Str(a[2])));
        add("System.Void", IL, "Emit", $"{OC},{MI}", (e, a) => Emit(a, e.MethodOf(a[2]).Method));
        add("System.Void", IL, "Emit", $"{OC},System.Reflection.ConstructorInfo", (e, a) => Emit(a, e.MethodOf(a[2]).Method));
        add("System.Void", IL, "Emit", $"{OC},{FI}", (_, a) => Emit(a, Of<FieldObject>(a[2], "a FieldInfo").Field));
        add("System.Void", IL, "Emit", $"{OC},{T}", (e, a) => Emit(a, e.TypeOf(a[2]).Sig.ToTypeDefOrRef() ?? throw Bail(FallbackReason.UnsupportedValue, "emits a type token of a constructed type")));
    }

    /// <summary>ILGenerator.Emit: appends the instruction to the dynamic method.</summary>
    private static object? Emit(object?[] a, object? operand)
    {
        var generator = Of<ILGeneratorObject>(a[0], "an ILGenerator");
        if (generator.Method.Sealed) throw Bail(FallbackReason.UnsupportedValue, "emits into a dynamic method after creating its delegate");
        generator.Method.Code.Add(DynamicInstruction(Of<OpCodeObject>(a[1], "an OpCode").Code, operand));
        return null;
    }

    /// <summary>
    /// An instruction of a dynamic method, built by ILGenerator.Emit or decoded from DynamicILInfo code: the one check of
    /// what the evaluator models there (numeric operands take the opcode's own operand type; arguments, but no locals,
    /// labels, switch tables, floating-point constants or signatures).
    /// </summary>
    internal static Instruction DynamicInstruction(OpCode op, object? operand)
    {
        object? actual = (op.OperandType, operand) switch
        {
            (OperandType.InlineNone, null) => null,
            (OperandType.ShortInlineI, int i) when op.Code == Code.Ldc_I4_S => (sbyte)i,
            (OperandType.ShortInlineI, int i) => (byte)i,
            (OperandType.InlineI, int i) => i,
            (OperandType.InlineI8, long l) => l,
            (OperandType.InlineString, string s) => s,
            (OperandType.InlineMethod, IMethod m) => m,
            (OperandType.InlineField, IField f) => f,
            (OperandType.InlineType or OperandType.InlineTok, ITypeDefOrRef t) => t,
            (OperandType.InlineVar or OperandType.ShortInlineVar, int i) when op.Code is Code.Ldarg or Code.Ldarg_S or Code.Ldarga or Code.Ldarga_S
                or Code.Starg or Code.Starg_S => new Parameter(i, i, null),
            (OperandType.InlineVar or OperandType.ShortInlineVar, _) => throw Bail(FallbackReason.UnsupportedValue, "emits a local variable access (locals of dynamic methods are not modelled)"),
            _ => throw Bail(FallbackReason.UnsupportedValue, $"emits {op.Name} with an operand the interpreter does not model"),
        };
        return new Instruction(op, actual);
    }

    /// <summary>DynamicILInfo.GetTokenFor: adds the entry to the scope and returns its token.</summary>
    private static int Token(object? info, int table, object entry)
    {
        var scope = Of<DynamicILInfoObject>(info, "a DynamicILInfo").Tokens;
        scope.Add(entry);
        return (scope.Count - 1) | table;
    }

    /// <summary>
    /// Decodes the code a DynamicILInfo was given into the dynamic method's instructions, resolving tokens in its scope.
    /// Every instruction goes through <see cref="DynamicInstruction"/>, as ILGenerator.Emit does.
    /// </summary>
    private void DecodeDynamicCode(DynamicILInfoObject info)
    {
        var code = info.Code ?? throw Bail(FallbackReason.RuntimeError, "creates the delegate of a dynamic method whose DynamicILInfo has no code (InvalidOperationException)");
        var instructions = info.Method.Code;
        instructions.Clear();
        int at = 0;
        int Take(int size) => at + size <= code.Length ? (at += size) - size : throw Bail(FallbackReason.InvalidCode, "the code of a dynamic method ends inside an instruction");
        int I4At(int k) => BitConverter.ToInt32(code, k);
        object Entry(int token, int table, string kind)
        {
            int index = token & 0x00FFFFFF;
            return (token & unchecked((int)0xFF000000)) == table && index > 0 && index < info.Tokens.Count && info.Tokens[index] is { } entry
                ? entry
                : throw Bail(FallbackReason.RuntimeError, $"the code of a dynamic method names token 0x{token:X8}, which its DynamicILInfo did not issue for a {kind}");
        }
        while (at < code.Length)
        {
            int b = code[Take(1)];
            var op = b == 0xFE ? OpCodes.TwoByteOpCodes[code[Take(1)]] : OpCodes.OneByteOpCodes[b];
            if (op.Code is Code.UNKNOWN1 or Code.UNKNOWN2) throw Bail(FallbackReason.InvalidCode, $"the code of a dynamic method holds the undefined opcode 0x{b:X2}");
            object? operand = op.OperandType switch
            {
                OperandType.InlineNone => null,
                OperandType.ShortInlineI => op.Code == Code.Ldc_I4_S ? (int)(sbyte)code[Take(1)] : (int)code[Take(1)],
                OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget => (int)code[Take(1)],
                OperandType.InlineVar => (int)BitConverter.ToUInt16(code, Take(2)),
                OperandType.InlineI8 => BitConverter.ToInt64(code, Take(8)),
                OperandType.ShortInlineR => BitConverter.ToSingle(code, Take(4)),
                OperandType.InlineR => BitConverter.ToDouble(code, Take(8)),
                OperandType.InlineString => Entry(I4At(Take(4)), 0x70000000, "string") as string ?? throw Bail(FallbackReason.InvalidCode, "ldstr of a token that is not a string"),
                OperandType.InlineMethod => Entry(I4At(Take(4)), 0x06000000, "method") is MethodObject m ? m.Method : throw Bail(FallbackReason.UnsupportedValue, "expected a MethodInfo"),
                OperandType.InlineField => (FieldDef)Entry(I4At(Take(4)), 0x04000000, "field"),
                OperandType.InlineType or OperandType.InlineTok => TypeOperand(I4At(Take(4))),
                OperandType.InlineSwitch => SwitchTable(),
                _ => I4At(Take(4)), // InlineI, InlineBrTarget, InlineSig: a number, as ILGenerator.Emit(OpCode, int) gives
            };
            instructions.Add(DynamicInstruction(op, operand));
        }

        object TypeOperand(int token) => (token & unchecked((int)0xFF000000)) == 0x02000000
            ? ((TypeObject)Entry(token, 0x02000000, "type")).Sig.ToTypeDefOrRef() ?? throw Bail(FallbackReason.UnsupportedValue, "emits a type token of a constructed type")
            : Entry(token, token & unchecked((int)0xFF000000), "member"); // a method or field token for ldtoken: not a type

        object SwitchTable()
        {
            int n = I4At(Take(4));
            if (n < 0 || n > (code.Length - at) / 4) throw Bail(FallbackReason.InvalidCode, "a switch table runs past the end of a dynamic method's code");
            Take(4 * n);
            return n;
        }
    }
}
