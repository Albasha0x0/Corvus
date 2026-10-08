using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace NetDecompilerMcp.Services.Simplify;

/// <summary>
/// Forwarder methods: bodies that pass their arguments, unchanged and in order, to one call (or newobj) and return its
/// result. A call site of a forwarder can call the target directly when that keeps the exact semantics:
/// <list type="bullet">
/// <item>the forwarder itself is not dispatched virtually (callvirt on an overridable or interface method is skipped);</item>
/// <item>the null check of callvirt on an instance forwarder is preserved (the target is called with callvirt, or the site is skipped);</item>
/// <item>a non-virtual call of a virtual target (base call) is never turned into a virtual one;</item>
/// <item>parameter and return types match, and the target is accessible from the calling type;</item>
/// <item>a static forwarder whose call runs its type's static constructor (no beforefieldinit) only calls a target of the same type.</item>
/// </list>
/// </summary>
internal sealed class Forwarders(ModuleDef module)
{
    private readonly Dictionary<MethodDef, (Code Op, IMethod Target)?> _cache = new();

    /// <summary>The instruction replacing a call of <paramref name="wrapper"/> with <paramref name="siteOp"/>, or null to keep it.</summary>
    public (OpCode OpCode, IMethod Target)? Rewrite(Code siteOp, MethodDef wrapper, TypeDef caller)
    {
        if (Detect(wrapper) is not var (op, target)) return null;
        if (wrapper.DeclaringType.IsInterface) return null;
        if (siteOp == Code.Callvirt && wrapper.IsVirtual && !wrapper.IsFinal && !wrapper.DeclaringType.IsSealed) return null;
        bool nullCheck = siteOp == Code.Callvirt && !wrapper.IsStatic;

        var resolved = target.ResolveMethodDef();
        if (resolved == null || !IsAccessible(resolved, caller)) return null;
        if (wrapper.IsStatic && !wrapper.DeclaringType.IsBeforeFieldInit && wrapper.DeclaringType.FindStaticConstructor() != null &&
            resolved.DeclaringType != wrapper.DeclaringType)
            return null; // the call would no longer run the wrapper type's static constructor

        OpCode result;
        switch (op)
        {
            case Code.Newobj:
                if (nullCheck) return null;
                result = OpCodes.Newobj;
                break;
            case Code.Call when resolved.IsStatic:
                if (nullCheck) return null;
                result = OpCodes.Call;
                break;
            case Code.Call:
                if (!nullCheck) result = OpCodes.Call;
                else if (resolved.IsVirtual && !resolved.IsFinal) return null; // a base call; callvirt would dispatch
                else result = OpCodes.Callvirt;
                break;
            default:
                result = OpCodes.Callvirt;
                break;
        }
        return (result, target);
    }

    private (Code Op, IMethod Target)? Detect(MethodDef w)
    {
        if (_cache.TryGetValue(w, out var cached)) return cached;
        var found = DetectUncached(w);
        _cache[w] = found;
        return found;
    }

    private (Code Op, IMethod Target)? DetectUncached(MethodDef w)
    {
        if (w.Module != module || w.IsConstructor || w.HasGenericParameters || w.DeclaringType.HasGenericParameters) return null;
        if (w.MethodSig is not { } wsig || wsig.CallingConvention == CallingConvention.VarArg) return null;
        var body = MetadataUtil.SafeBody(w);
        if (body == null || body.HasExceptionHandlers) return null;
        var code = body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToList();

        int n = w.Parameters.Count; // including 'this'
        if (code.Count < n + 2) return null;
        for (int i = 0; i < n; i++)
            if (!code[i].IsLdarg() || code[i].GetParameterIndex() != i) return null;
        int at = n;
        if (code[at].OpCode.Code == Code.Tailcall) at++;
        var call = code[at];
        if (call.OpCode.Code is not (Code.Call or Code.Callvirt or Code.Newobj) || call.Operand is not IMethod target) return null;
        if (!EndsWithReturn(code, at + 1, body.Variables)) return null;

        if (target is MethodSpec || target.DeclaringType is TypeSpec || target.MethodSig is not { } tsig) return null;
        if (tsig.CallingConvention == CallingConvention.VarArg || tsig.ExplicitThis) return null;
        if (ReferenceEquals(target, w)) return null;
        bool newobj = call.OpCode.Code == Code.Newobj;
        if (call.OpCode.Code == Code.Call && target.Name == ".ctor") return null; // base/this constructor call
        int targetCount = tsig.Params.Count + (tsig.HasThis && !newobj ? 1 : 0);
        if (targetCount != n) return null;

        var comparer = new SigComparer();
        int offset = 0;
        if (tsig.HasThis && !newobj)
        {
            // The receiver: what the wrapper passes must be the target's declaring type or derived from it.
            if (!IsReceiverCompatible(w.Parameters[0].Type, target.DeclaringType)) return null;
            offset = 1;
        }
        for (int i = 0; i < tsig.Params.Count; i++)
            if (!comparer.Equals(w.Parameters[i + offset].Type, tsig.Params[i])) return null;

        var wret = wsig.RetType;
        if (newobj)
        {
            if (!comparer.Equals(wret, target.DeclaringType.ToTypeSig())) return null;
        }
        else if (!comparer.Equals(wret, tsig.RetType)) return null;
        return (call.OpCode.Code, target);
    }

    /// <summary>ret, or the debug-build epilogue stloc.s; [br next;] ldloc.s; ret.</summary>
    private static bool EndsWithReturn(List<Instruction> code, int at, IList<Local> locals)
    {
        int rest = code.Count - at;
        if (rest == 1) return code[at].OpCode.Code == Code.Ret;
        if (rest is not (3 or 4) || !code[at].IsStloc() || !code[^2].IsLdloc() || code[^1].OpCode.Code != Code.Ret) return false;
        if (code[at].GetLocal(locals) != code[^2].GetLocal(locals)) return false;
        return rest == 3 || (code[at + 1].OpCode.Code is Code.Br or Code.Br_S && code[at + 1].Operand == code[^2]);
    }

    private static bool IsReceiverCompatible(TypeSig passed, ITypeDefOrRef targetType)
    {
        var comparer = new SigComparer();
        var expected = targetType.ToTypeSig();
        if (expected.IsValueType) // 'this' of a struct method is a managed pointer to the struct
            return passed is ByRefSig byRef && comparer.Equals(byRef.Next, expected);
        if (comparer.Equals(passed, expected)) return true;
        // A class receiver of a derived type.
        var type = passed.ToTypeDefOrRef()?.ResolveTypeDef();
        for (int depth = 0; type != null && depth < 64; depth++)
        {
            if (comparer.Equals(type, targetType)) return true;
            type = type.BaseType?.ResolveTypeDef();
        }
        return false;
    }

    /// <summary>Whether code in <paramref name="from"/> may call <paramref name="target"/> (conservative: protected access is refused).</summary>
    internal static bool IsAccessible(MethodDef target, TypeDef from)
    {
        var declaring = target.DeclaringType;
        if (!IsTypeAccessible(declaring, from)) return false;
        bool sameAssembly = SameAssembly(declaring, from);
        return target.Access switch
        {
            MethodAttributes.Public => true,
            MethodAttributes.Assembly or MethodAttributes.FamORAssem => sameAssembly || IsWithin(from, declaring),
            _ => IsWithin(from, declaring), // private, family, family-and-assembly, compiler-controlled
        };
    }

    private static bool IsTypeAccessible(TypeDef type, TypeDef from)
    {
        if (IsWithin(from, type)) return true;
        if (type.DeclaringType == null)
            return type.IsPublic || SameAssembly(type, from);
        if (!IsTypeAccessible(type.DeclaringType, from)) return false;
        return type.Visibility switch
        {
            TypeAttributes.NestedPublic => true,
            TypeAttributes.NestedAssembly or TypeAttributes.NestedFamORAssem => SameAssembly(type, from),
            _ => IsWithin(from, type.DeclaringType),
        };
    }

    /// <summary>Whether <paramref name="type"/> is <paramref name="container"/> or nested inside it.</summary>
    private static bool IsWithin(TypeDef? type, TypeDef container)
    {
        for (; type != null; type = type.DeclaringType)
            if (type == container) return true;
        return false;
    }

    private static bool SameAssembly(TypeDef a, TypeDef b) => a.Module == b.Module ||
        (a.Module?.Assembly is { } x && b.Module?.Assembly is { } y && x.FullName == y.FullName);
}
