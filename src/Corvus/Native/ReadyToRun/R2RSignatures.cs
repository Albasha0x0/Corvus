using System.Text;

namespace Corvus.Native.ReadyToRun;

/// <summary>
/// Names for metadata tokens met in ReadyToRun signatures. <c>module</c> is a module index of the image
/// (0 the image's own module, then its assembly references, then the manifest's) or -1 for the default context.
/// Implementations return a placeholder rather than throw when a token cannot be resolved.
/// </summary>
public interface IR2RNames
{
    /// <summary>A TypeDef, TypeRef or TypeSpec token.</summary>
    string Type(int module, uint token);
    /// <summary>A MethodDef or MemberRef token; <paramref name="owner"/> replaces the declaring type when set.</summary>
    string Method(int module, uint token, string? owner, IReadOnlyList<string>? methodArgs);
    /// <summary>A FieldDef or MemberRef token.</summary>
    string Field(int module, uint token, string? owner);
    /// <summary>A user string (#US heap offset).</summary>
    string UserString(int module, uint offset);
}

/// <summary>
/// A decoded method signature (READYTORUN_METHOD_SIG_*). <see cref="TokenModule"/> is the module the token belongs
/// to: the updated context, else the owner type's defining module (the runtime compares the token with the
/// method's own MethodDef), else the signature's context.
/// </summary>
public sealed record R2RMethodSig(uint Flags, int TokenModule, uint Token, string? Name)
{
    public const uint UnboxingStub = 0x01, InstantiatingStub = 0x02, MethodInstantiation = 0x04, SlotInsteadOfToken = 0x08,
        MemberRefToken = 0x10, Constrained = 0x20, OwnerType = 0x40, UpdateContext = 0x80, AsyncVariant = 0x100;

    public bool IsMethodDef => (Token >> 24) == 0x06;
}

/// <summary>
/// Walks ReadyToRun signatures (readytorun.h): ECMA-335 type signatures with the ZapSig extensions (module override,
/// __Canon, native value type), method and field signatures, and import cell (fixup) signatures. With no
/// <see cref="IR2RNames"/> only the length is decoded; names are null.
/// </summary>
public sealed class R2RSignatures(ImageView view, IR2RNames? names)
{
    private const int MaxDepth = 64;

    // ECMA-335 element types and the ReadyToRun extensions.
    private const byte EtVoid = 0x01, EtString = 0x0E, EtPtr = 0x0F, EtByRef = 0x10, EtValueType = 0x11, EtClass = 0x12, EtVar = 0x13,
        EtArray = 0x14, EtGenericInst = 0x15, EtTypedByRef = 0x16, EtI = 0x18, EtU = 0x19, EtFnPtr = 0x1B, EtObject = 0x1C,
        EtSzArray = 0x1D, EtMVar = 0x1E, EtCModReqd = 0x1F, EtCModOpt = 0x20, EtInternal = 0x21, EtSentinel = 0x41, EtPinned = 0x45,
        EtVarZapSig = 0x3B, EtNativeValueTypeZapSig = 0x3D, EtCanonZapSig = 0x3E, EtModuleZapSig = 0x3F;

    private static readonly string[] Primitives =
        ["?", "void", "bool", "char", "sbyte", "byte", "short", "ushort", "int", "uint", "long", "ulong", "float", "double", "string"];

    public ImageView View => view;

    /// <summary>Module of the first type token met since the last reset (the defining module of an owner type).</summary>
    private int? _firstTokenModule;

    /// <summary>A TypeDefOrRefOrSpec coded index as a token.</summary>
    private static uint TypeToken(uint coded) => (coded & 3) switch
    {
        0 => 0x02000000 | (coded >> 2),
        1 => 0x01000000 | (coded >> 2),
        2 => 0x1B000000 | (coded >> 2),
        _ => throw new R2RFormatException($"bad TypeDefOrRef coded index 0x{coded:X}"),
    };

    public string? Type(SigReader r, int module, int depth = 0)
    {
        if (depth > MaxDepth) throw new R2RFormatException($"type signature near RVA 0x{r.Position:X} nests too deeply");
        byte et = r.Byte();
        switch (et)
        {
            case >= EtVoid and <= EtString:
                return Primitives[et];
            case EtI: return "nint";
            case EtU: return "nuint";
            case EtObject: return "object";
            case EtTypedByRef: return "TypedReference";
            case EtCanonZapSig: return "__Canon";
            case EtValueType or EtClass:
            {
                uint token = TypeToken(r.Compressed());
                _firstTokenModule ??= module;
                return names?.Type(module, token);
            }
            case EtNativeValueTypeZapSig:
                return Type(r, module, depth + 1);
            case EtModuleZapSig:
            {
                int inner = (int)r.Compressed();
                return Type(r, inner, depth + 1);
            }
            case EtPtr:
                return Type(r, module, depth + 1) + "*";
            case EtByRef:
                return "ref " + Type(r, module, depth + 1);
            case EtSzArray:
                return Type(r, module, depth + 1) + "[]";
            case EtArray:
            {
                var element = Type(r, module, depth + 1);
                uint rank = r.Compressed();
                uint sizes = r.Compressed();
                for (uint i = 0; i < sizes; i++) r.Compressed();
                uint bounds = r.Compressed();
                for (uint i = 0; i < bounds; i++) r.Compressed();
                if (rank > 64) throw new R2RFormatException($"array rank {rank} near RVA 0x{r.Position:X}");
                return element + "[" + new string(',', (int)Math.Max(0, (int)rank - 1)) + "]";
            }
            case EtVar:
                return "!" + r.Compressed();
            case EtMVar:
                return "!!" + r.Compressed();
            case EtVarZapSig:
                // A type variable of a named generic type or method: the number, then the owner's token.
                return "!" + r.Compressed() + "@" + r.Compressed();
            case EtGenericInst:
            {
                var generic = Type(r, module, depth + 1);
                uint count = r.Compressed();
                if (count > 256) throw new R2RFormatException($"generic instantiation with {count} arguments near RVA 0x{r.Position:X}");
                var args = new List<string?>();
                for (uint i = 0; i < count; i++) args.Add(Type(r, module, depth + 1));
                return names == null ? null : $"{generic}<{string.Join(", ", args)}>";
            }
            case EtFnPtr:
                SkipMethodSignature(r, module, depth + 1);
                return "delegate*";
            case EtCModReqd or EtCModOpt:
                r.Compressed();
                return Type(r, module, depth + 1);
            case EtPinned or EtSentinel:
                return Type(r, module, depth + 1);
            case EtInternal:
                throw new R2RFormatException($"ELEMENT_TYPE_INTERNAL in a ReadyToRun signature near RVA 0x{r.Position:X}");
            default:
                throw new R2RFormatException($"unknown element type 0x{et:X2} at RVA 0x{r.Position - 1:X}");
        }
    }

    /// <summary>A standalone method signature (function pointer types): calling convention, counts, return and parameter types.</summary>
    private void SkipMethodSignature(SigReader r, int module, int depth)
    {
        byte conv = r.Byte();
        if ((conv & 0x10) != 0) r.Compressed(); // generic parameter count
        uint count = r.Compressed();
        if (count > 1024) throw new R2RFormatException($"function pointer with {count} parameters near RVA 0x{r.Position:X}");
        for (uint i = 0; i <= count; i++) Type(r, module, depth);
    }

    /// <summary>
    /// A method signature: flags, [module], [owner type], token (or slot), [method instantiation], [constrained type].
    /// </summary>
    public R2RMethodSig Method(SigReader r, int module)
    {
        uint flags = r.Compressed();
        if ((flags & ~0x1FFu) != 0) throw new R2RFormatException($"unknown method signature flags 0x{flags:X} near RVA 0x{r.Position:X}");
        if ((flags & R2RMethodSig.UpdateContext) != 0) module = (int)r.Compressed();
        var (owner, ownerModule) = Owner(r, module, (flags & R2RMethodSig.OwnerType) != 0);
        if ((flags & R2RMethodSig.SlotInsteadOfToken) != 0)
        {
            uint slot = r.Compressed();
            return new R2RMethodSig(flags, module, 0, names == null ? null : $"{owner}::slot {slot}");
        }
        uint rid = r.Compressed();
        bool memberRef = (flags & R2RMethodSig.MemberRefToken) != 0;
        uint token = (memberRef ? 0x0A000000u : 0x06000000u) | rid;
        int tokenModule = memberRef ? module : ownerModule;
        List<string>? args = null;
        if ((flags & R2RMethodSig.MethodInstantiation) != 0)
        {
            uint count = r.Compressed();
            if (count > 256) throw new R2RFormatException($"method instantiation with {count} arguments near RVA 0x{r.Position:X}");
            args = [];
            for (uint i = 0; i < count; i++) args.Add(Type(r, module) ?? "?");
        }
        string? constrained = (flags & R2RMethodSig.Constrained) != 0 ? Type(r, module) : null;
        if (names == null) return new R2RMethodSig(flags, tokenModule, token, null);
        var sb = new StringBuilder(names.Method(tokenModule, token, owner, args));
        if ((flags & R2RMethodSig.UnboxingStub) != 0) sb.Append(" [unboxing stub]");
        if ((flags & R2RMethodSig.InstantiatingStub) != 0) sb.Append(" [instantiating stub]");
        if ((flags & R2RMethodSig.AsyncVariant) != 0) sb.Append(" [async variant]");
        if (constrained != null) sb.Append(" [constrained to ").Append(constrained).Append(']');
        return new R2RMethodSig(flags, tokenModule, token, sb.ToString());
    }

    /// <summary>The owner type when present, and the module a definition token after it belongs to.</summary>
    private (string? Owner, int Module) Owner(SigReader r, int module, bool present)
    {
        if (!present) return (null, module);
        _firstTokenModule = null;
        var owner = Type(r, module);
        return (owner, _firstTokenModule ?? module);
    }

    /// <summary>A field signature: flags, [owner type], FieldDef or MemberRef rid.</summary>
    public string? Field(SigReader r, int module)
    {
        uint flags = r.Compressed();
        var (owner, ownerModule) = Owner(r, module, (flags & 0x40) != 0);
        uint rid = r.Compressed();
        bool memberRef = (flags & 0x10) != 0;
        uint token = (memberRef ? 0x0A000000u : 0x04000000u) | rid;
        return names?.Field(memberRef ? module : ownerModule, token, owner);
    }

    /// <summary>Describes the import cell signature at <paramref name="rva"/>: "kind target".</summary>
    public R2RFixup Fixup(uint rva, int module = -1)
    {
        var r = new SigReader(view, rva);
        byte raw = r.Byte();
        if ((raw & 0x80) != 0) module = (int)r.Compressed();
        var kind = (R2RFixupKind)(raw & 0x7F);
        string? target = null;
        R2RMethodSig? method = null;
        switch (kind)
        {
            case R2RFixupKind.TypeHandle or R2RFixupKind.DeclaringTypeHandle or R2RFixupKind.NewObject or R2RFixupKind.NewArray
                or R2RFixupKind.IsInstanceOf or R2RFixupKind.ChkCast or R2RFixupKind.CctorTrigger or R2RFixupKind.StaticBaseNonGC
                or R2RFixupKind.StaticBaseGC or R2RFixupKind.ThreadStaticBaseNonGC or R2RFixupKind.ThreadStaticBaseGC
                or R2RFixupKind.FieldBaseOffset or R2RFixupKind.TypeDictionary or R2RFixupKind.Check_TypeLayout
                or R2RFixupKind.Verify_TypeLayout or R2RFixupKind.VirtualEntry_Slot:
                target = Type(r, module);
                break;
            case R2RFixupKind.MethodHandle or R2RFixupKind.MethodEntry or R2RFixupKind.VirtualEntry or R2RFixupKind.MethodDictionary
                or R2RFixupKind.IndirectPInvokeTarget or R2RFixupKind.PInvokeTarget or R2RFixupKind.Check_IL_Body or R2RFixupKind.Verify_IL_Body:
                method = Method(r, module);
                target = method.Name;
                break;
            case R2RFixupKind.MethodEntry_DefToken or R2RFixupKind.VirtualEntry_DefToken:
                method = new R2RMethodSig(0, module, 0x06000000 | r.Compressed(), null);
                target = names?.Method(module, method.Token, null, null);
                break;
            case R2RFixupKind.MethodEntry_RefToken or R2RFixupKind.VirtualEntry_RefToken:
                method = new R2RMethodSig(0, module, 0x0A000000 | r.Compressed(), null);
                target = names?.Method(module, method.Token, null, null);
                break;
            case R2RFixupKind.FieldHandle or R2RFixupKind.FieldAddress or R2RFixupKind.FieldOffset or R2RFixupKind.Verify_FieldOffset:
                target = Field(r, module);
                break;
            case R2RFixupKind.Check_FieldOffset:
                r.Compressed(); // expected offset
                target = Field(r, module);
                break;
            case R2RFixupKind.Helper:
                target = R2RNamesTable.Helper(r.Compressed());
                break;
            case R2RFixupKind.StringHandle:
                target = names?.UserString(module, r.Compressed());
                break;
            case R2RFixupKind.DelegateCtor:
                method = Method(r, module);
                var delegateType = Type(r, module);
                target = names == null ? null : $"{delegateType} for {method.Name}";
                break;
        }
        return new R2RFixup(kind, target, method);
    }
}

/// <summary>An import cell's meaning: the fixup kind and, when decoded, what it refers to.</summary>
public sealed record R2RFixup(R2RFixupKind Kind, string? Target, R2RMethodSig? Method)
{
    public bool IsCallTarget => Kind is R2RFixupKind.MethodEntry or R2RFixupKind.MethodEntry_DefToken or R2RFixupKind.MethodEntry_RefToken
        or R2RFixupKind.VirtualEntry or R2RFixupKind.VirtualEntry_DefToken or R2RFixupKind.VirtualEntry_RefToken or R2RFixupKind.VirtualEntry_Slot
        or R2RFixupKind.IndirectPInvokeTarget or R2RFixupKind.PInvokeTarget;

    /// <summary>"Ns.Type::Method(int)" for calls, "helper WriteBarrier", "type handle Ns.Type", "string \"...\"".</summary>
    public string Describe()
    {
        if (Kind == R2RFixupKind.Helper) return "helper " + (Target ?? "?");
        if (Kind == R2RFixupKind.StringHandle) return "string " + (Target ?? "?");
        if (Kind is R2RFixupKind.MethodEntry or R2RFixupKind.MethodEntry_DefToken or R2RFixupKind.MethodEntry_RefToken) return Target ?? "method ?";
        return R2RNamesTable.Kind(Kind) + (Target != null ? " " + Target : "");
    }
}

/// <summary>READYTORUN_FIXUP_* values.</summary>
public enum R2RFixupKind : byte
{
    ThisObjDictionaryLookup = 0x07, TypeDictionaryLookup = 0x08, MethodDictionaryLookup = 0x09,
    TypeHandle = 0x10, MethodHandle = 0x11, FieldHandle = 0x12,
    MethodEntry = 0x13, MethodEntry_DefToken = 0x14, MethodEntry_RefToken = 0x15,
    VirtualEntry = 0x16, VirtualEntry_DefToken = 0x17, VirtualEntry_RefToken = 0x18, VirtualEntry_Slot = 0x19,
    Helper = 0x1A, StringHandle = 0x1B, NewObject = 0x1C, NewArray = 0x1D, IsInstanceOf = 0x1E, ChkCast = 0x1F,
    FieldAddress = 0x20, CctorTrigger = 0x21, StaticBaseNonGC = 0x22, StaticBaseGC = 0x23,
    ThreadStaticBaseNonGC = 0x24, ThreadStaticBaseGC = 0x25, FieldBaseOffset = 0x26, FieldOffset = 0x27,
    TypeDictionary = 0x28, MethodDictionary = 0x29, Check_TypeLayout = 0x2A, Check_FieldOffset = 0x2B,
    DelegateCtor = 0x2C, DeclaringTypeHandle = 0x2D, IndirectPInvokeTarget = 0x2E, PInvokeTarget = 0x2F,
    Check_InstructionSetSupport = 0x30, Verify_FieldOffset = 0x31, Verify_TypeLayout = 0x32,
    Check_VirtualFunctionOverride = 0x33, Verify_VirtualFunctionOverride = 0x34, Check_IL_Body = 0x35, Verify_IL_Body = 0x36,
}

/// <summary>Display names for fixup kinds and runtime helpers.</summary>
public static class R2RNamesTable
{
    public static string Kind(R2RFixupKind kind) => kind switch
    {
        R2RFixupKind.ThisObjDictionaryLookup => "dictionary lookup (this)",
        R2RFixupKind.TypeDictionaryLookup => "dictionary lookup (type)",
        R2RFixupKind.MethodDictionaryLookup => "dictionary lookup (method)",
        R2RFixupKind.TypeHandle => "type handle",
        R2RFixupKind.MethodHandle => "method handle",
        R2RFixupKind.FieldHandle => "field handle",
        R2RFixupKind.MethodEntry or R2RFixupKind.MethodEntry_DefToken or R2RFixupKind.MethodEntry_RefToken => "method entry",
        R2RFixupKind.VirtualEntry or R2RFixupKind.VirtualEntry_DefToken or R2RFixupKind.VirtualEntry_RefToken => "virtual call",
        R2RFixupKind.VirtualEntry_Slot => "virtual slot of",
        R2RFixupKind.Helper => "helper",
        R2RFixupKind.StringHandle => "string",
        R2RFixupKind.NewObject => "new object",
        R2RFixupKind.NewArray => "new array",
        R2RFixupKind.IsInstanceOf => "isinst",
        R2RFixupKind.ChkCast => "castclass",
        R2RFixupKind.FieldAddress => "field address",
        R2RFixupKind.CctorTrigger => "static constructor trigger",
        R2RFixupKind.StaticBaseNonGC => "static base (non-GC)",
        R2RFixupKind.StaticBaseGC => "static base (GC)",
        R2RFixupKind.ThreadStaticBaseNonGC => "thread static base (non-GC)",
        R2RFixupKind.ThreadStaticBaseGC => "thread static base (GC)",
        R2RFixupKind.FieldBaseOffset => "field base offset",
        R2RFixupKind.FieldOffset => "field offset",
        R2RFixupKind.TypeDictionary => "type dictionary",
        R2RFixupKind.MethodDictionary => "method dictionary",
        R2RFixupKind.Check_TypeLayout => "check type layout",
        R2RFixupKind.Check_FieldOffset => "check field offset",
        R2RFixupKind.DelegateCtor => "delegate constructor",
        R2RFixupKind.DeclaringTypeHandle => "declaring type handle",
        R2RFixupKind.IndirectPInvokeTarget => "p/invoke target (indirect)",
        R2RFixupKind.PInvokeTarget => "p/invoke target",
        R2RFixupKind.Check_InstructionSetSupport => "check instruction set support",
        R2RFixupKind.Verify_FieldOffset => "verify field offset",
        R2RFixupKind.Verify_TypeLayout => "verify type layout",
        R2RFixupKind.Check_VirtualFunctionOverride => "check virtual override",
        R2RFixupKind.Verify_VirtualFunctionOverride => "verify virtual override",
        R2RFixupKind.Check_IL_Body => "check IL body",
        R2RFixupKind.Verify_IL_Body => "verify IL body",
        _ => $"fixup 0x{(byte)kind:X2}",
    };

    /// <summary>READYTORUN_HELPER_* names.</summary>
    public static string Helper(uint id) => id switch
    {
        0x01 => "Module", 0x02 => "GSCookie", 0x03 => "IndirectTrapThreads",
        0x08 => "DelayLoad_MethodCall", 0x10 => "DelayLoad_Helper", 0x11 => "DelayLoad_Helper_Obj", 0x12 => "DelayLoad_Helper_ObjObj",
        0x20 => "Throw", 0x21 => "Rethrow", 0x22 => "Overflow", 0x23 => "RngChkFail", 0x24 => "FailFast", 0x25 => "ThrowNullRef",
        0x26 => "ThrowDivZero", 0x27 => "ThrowExact",
        0x30 => "WriteBarrier", 0x31 => "CheckedWriteBarrier", 0x32 => "ByRefWriteBarrier", 0x33 => "BulkWriteBarrier",
        0x38 => "Stelem_Ref", 0x39 => "Ldelema_Ref",
        0x3E => "MemZero", 0x3F => "MemSet", 0x40 => "NativeMemSet", 0x41 => "MemCpy",
        0x42 => "PInvokeBegin", 0x43 => "PInvokeEnd", 0x44 => "GCPoll", 0x45 => "ReversePInvokeEnter", 0x46 => "ReversePInvokeExit",
        0x50 => "GetString", 0x51 => "LogMethodEnter",
        0x54 => "GetRuntimeTypeHandle", 0x55 => "GetRuntimeMethodHandle", 0x56 => "GetRuntimeFieldHandle",
        0x58 => "Box", 0x59 => "Box_Nullable", 0x5A => "Unbox", 0x5B => "Unbox_Nullable", 0x5C => "NewMultiDimArr", 0x5D => "Unbox_TypeTest",
        0x60 => "NewObject", 0x61 => "NewArray", 0x62 => "CheckCastAny", 0x63 => "CheckInstanceAny",
        0x64 => "GenericGcStaticBase", 0x65 => "GenericNonGcStaticBase", 0x66 => "GenericGcTlsBase", 0x67 => "GenericNonGcTlsBase",
        0x68 => "VirtualFuncPtr", 0x69 => "IsInstanceOfException", 0x6A => "NewMaybeFrozenArray", 0x6B => "NewMaybeFrozenObject",
        0xC0 => "LMul", 0xC1 => "LMulOfv", 0xC2 => "ULMulOvf", 0xC3 => "LDiv", 0xC4 => "LMod", 0xC5 => "ULDiv", 0xC6 => "ULMod",
        0xC7 => "LLsh", 0xC8 => "LRsh", 0xC9 => "LRsz", 0xCA => "Lng2Dbl", 0xCB => "ULng2Dbl",
        0xCC => "Div", 0xCD => "Mod", 0xCE => "UDiv", 0xCF => "UMod",
        0xD0 => "Dbl2Int", 0xD1 => "Dbl2IntOvf", 0xD2 => "Dbl2Lng", 0xD3 => "Dbl2LngOvf", 0xD4 => "Dbl2UInt", 0xD5 => "Dbl2UIntOvf",
        0xD6 => "Dbl2ULng", 0xD7 => "Dbl2ULngOvf",
        0xE0 => "DblRem", 0xE1 => "FltRem", 0xE2 => "DblRound", 0xE3 => "FltRound",
        0xF0 => "PersonalityRoutine", 0xF1 => "PersonalityRoutineFilterFunclet",
        0xF8 => "MonitorEnter", 0xF9 => "MonitorExit",
        0x100 => "WriteBarrier_EAX", 0x101 => "WriteBarrier_EBX", 0x102 => "WriteBarrier_ECX", 0x103 => "WriteBarrier_ESI",
        0x104 => "WriteBarrier_EDI", 0x105 => "WriteBarrier_EBP",
        0x106 => "CheckedWriteBarrier_EAX", 0x107 => "CheckedWriteBarrier_EBX", 0x108 => "CheckedWriteBarrier_ECX",
        0x109 => "CheckedWriteBarrier_ESI", 0x10A => "CheckedWriteBarrier_EDI", 0x10B => "CheckedWriteBarrier_EBP",
        0x110 => "EndCatch", 0x111 => "StackProbe", 0x112 => "GetCurrentManagedThreadId",
        0x113 => "Stelem_Ref_I", 0x114 => "Ldelema_Ref_I",
        _ => $"0x{id:X}",
    };
}
