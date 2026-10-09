using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Normalized IL hash of a method body: SHA-256 over a canonical text form of the body that does not depend on metadata
/// tokens, byte offsets or short/long instruction forms, so a rebuild that does not change the code keeps the hash.
/// The encoding is documented in docs/il-hash.md; change <see cref="Version"/> with any change to it.
/// </summary>
public static class IlHash
{
    public const int Version = 1;

    private sealed record Entry(int AssemblyVersion, string? Hash);

    private static readonly ConditionalWeakTable<MethodDef, Entry> Cache = new();

    /// <summary>
    /// Hex SHA-256 of the method's canonical body, or null when it has no body or its body is not valid IL.
    /// Cached per method until the assembly is edited.
    /// </summary>
    public static string? Of(LoadedAssembly asm, MethodDef method, FastIlReader.Body? decoded = null)
    {
        int version = asm.Version;
        if (Cache.TryGetValue(method, out var entry) && entry.AssemblyVersion == version)
            return entry.Hash;
        var hash = Compute(asm, method, decoded ?? FastIlReader.Read(asm, method));
        Cache.AddOrUpdate(method, new Entry(version, hash));
        return hash;
    }

    /// <summary>Hash of an already decoded body (null: no body, or not valid IL).</summary>
    public static string? Compute(LoadedAssembly asm, MethodDef method, FastIlReader.Body? body)
    {
        if (body == null || body.Instructions.Count == 0) return null;
        if (!asm.IsDirty && asm.BodyHealth.IsInvalid(method)) return null;
        return Hex(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(body))));
    }

    /// <summary>First 16 hex digits: enough to tell bodies apart in listings.</summary>
    public static string Short(string hash) => hash[..16];

    /// <summary>The canonical text that is hashed (docs/il-hash.md).</summary>
    public static string Canonical(FastIlReader.Body body)
    {
        var instructions = body.Instructions;
        var index = new Dictionary<Instruction, int>(ReferenceEqualityComparer.Instance);
        for (int i = 0; i < instructions.Count; i++) index.TryAdd(instructions[i], i);
        string Target(Instruction? target) => target != null && index.TryGetValue(target, out int i) ? "@" + i.ToString(CultureInfo.InvariantCulture) : "@?";
        string End(Instruction? target) => target == null ? "@" + instructions.Count.ToString(CultureInfo.InvariantCulture) : Target(target);

        var sb = new StringBuilder();
        sb.Append("ilhash ").Append(Version).Append('\n');
        sb.Append("locals");
        foreach (var local in body.LocalTypes) sb.Append(' ').Append(TypeName(local));
        sb.Append('\n');
        // Without locals the flag has no effect (tiny headers cannot carry it).
        sb.Append("initlocals ").Append(body.InitLocals && body.LocalTypes.Count > 0 ? '1' : '0').Append('\n');
        foreach (var instr in instructions)
        {
            var (code, operand) = Normalize(instr);
            sb.Append(OpCodeName(code));
            if (operand != null) sb.Append(' ').Append(operand);
            sb.Append('\n');
        }
        foreach (var r in body.Regions)
        {
            sb.Append(r.Kind switch
            {
                ExceptionHandlerType.Filter => "filter",
                ExceptionHandlerType.Finally => "finally",
                ExceptionHandlerType.Fault => "fault",
                _ => "catch",
            });
            sb.Append(' ').Append(Target(r.TryStart)).Append(' ').Append(End(r.TryEnd))
              .Append(' ').Append(Target(r.HandlerStart)).Append(' ').Append(End(r.HandlerEnd));
            if (r.Kind == ExceptionHandlerType.Filter) sb.Append(' ').Append(Target(r.FilterStart));
            if (r.Kind == ExceptionHandlerType.Catch) sb.Append(" t:").Append(TypeName(r.CatchType));
            sb.Append('\n');
        }
        return sb.ToString();

        string? Branch(object? operand) => operand switch
        {
            Instruction target => Target(target),
            Instruction[] targets => string.Join(",", targets.Select(Target)),
            IList<Instruction> targets => string.Join(",", targets.Select(Target)),
            _ => "@?",
        };

        (Code Code, string? Operand) Normalize(Instruction instr)
        {
            var c = instr.OpCode.Code;
            var o = instr.Operand;
            static string I(long n) => "i:" + n.ToString(CultureInfo.InvariantCulture);
            switch (c)
            {
                case Code.Ldc_I4_M1: return (Code.Ldc_I4, I(-1));
                case >= Code.Ldc_I4_0 and <= Code.Ldc_I4_8: return (Code.Ldc_I4, I(c - Code.Ldc_I4_0));
                case Code.Ldc_I4_S or Code.Ldc_I4: return (Code.Ldc_I4, I(Convert.ToInt64(o ?? 0, CultureInfo.InvariantCulture)));
                case >= Code.Ldarg_0 and <= Code.Ldarg_3: return (Code.Ldarg, "a:" + (c - Code.Ldarg_0));
                case >= Code.Ldloc_0 and <= Code.Ldloc_3: return (Code.Ldloc, "v:" + (c - Code.Ldloc_0));
                case >= Code.Stloc_0 and <= Code.Stloc_3: return (Code.Stloc, "v:" + (c - Code.Stloc_0));
            }
            c = LongForm(c);
            var operandType = instr.OpCode.OperandType;
            string? text = operandType switch
            {
                OperandType.InlineNone or OperandType.InlinePhi => null,
                OperandType.ShortInlineBrTarget or OperandType.InlineBrTarget or OperandType.InlineSwitch => Branch(o),
                OperandType.ShortInlineVar or OperandType.InlineVar => c is Code.Ldarg or Code.Ldarga or Code.Starg
                    ? "a:" + VariableIndex(o) : "v:" + VariableIndex(o),
                OperandType.ShortInlineI or OperandType.InlineI => I(Convert.ToInt64(o ?? 0, CultureInfo.InvariantCulture)),
                OperandType.InlineI8 => "l:" + Convert.ToInt64(o ?? 0L, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture),
                OperandType.ShortInlineR => "r4:" + BitConverter.SingleToInt32Bits(o is float f ? f : 0f).ToString("x8", CultureInfo.InvariantCulture),
                OperandType.InlineR => "r8:" + BitConverter.DoubleToInt64Bits(o is double d ? d : 0d).ToString("x16", CultureInfo.InvariantCulture),
                OperandType.InlineString => o is string s ? "s:" + Quote(s) : "?",
                OperandType.InlineSig => o is MethodSig sig ? "sig:" + CallSiteName(sig) : "?",
                _ => Member(o),
            };
            return (c, text);
        }
    }

    private static string Member(object? operand) => operand switch
    {
        MemberRef { IsFieldRef: true } f => "f:" + FieldName(f),
        MemberRef m => "m:" + MethodName(m),
        IField f => "f:" + FieldName(f),
        IMethod m => "m:" + MethodName(m),
        ITypeDefOrRef t => "t:" + TypeName(t),
        _ => "?",
    };

    /// <summary>"ret Declaring::Name&lt;instantiation&gt;(params)".</summary>
    private static string MethodName(IMethod m)
    {
        var (method, instantiation) = m is MethodSpec spec ? (spec.Method ?? (IMethod)spec, spec.GenericInstMethodSig?.GenericArguments) : (m, null);
        var sig = method.MethodSig;
        var sb = new StringBuilder(TypeName(sig?.RetType)).Append(' ').Append(TypeName(method.DeclaringType)).Append("::").Append(method.Name);
        if (instantiation != null) sb.Append('<').Append(string.Join(",", instantiation.Select(x => TypeName(x)))).Append('>');
        return sb.Append('(').Append(string.Join(",", sig?.Params.Select(x => TypeName(x)) ?? [])).Append(')').ToString();
    }

    private static string FieldName(IField f) => $"{TypeName(f.FieldSig?.Type)} {TypeName(f.DeclaringType)}::{f.Name}";

    private static string CallSiteName(MethodSig sig) =>
        $"{(sig.HasThis ? "instance " : "")}{TypeName(sig.RetType)}({string.Join(",", sig.Params.Select(x => TypeName(x)))})";

    private static string TypeName(ITypeDefOrRef? t) => t is TypeSpec spec ? TypeName(spec.TypeSig) : t?.FullName ?? "?";

    /// <summary>
    /// A type in signature notation with generic parameters as !n / !!n: dnlib names them only when it knows the generic
    /// context, which depends on how the body was read.
    /// </summary>
    public static string TypeName(TypeSig? sig, Func<TypeDef, string>? name = null)
    {
        var sb = new StringBuilder();
        Write(sig);
        return sb.ToString();

        void Write(TypeSig? s)
        {
            switch (s)
            {
                case null: sb.Append('?'); break;
                case CorLibTypeSig c: sb.Append(c.FullName); break;
                case TypeDefOrRefSig t: sb.Append(name != null && t.TypeDefOrRef is TypeDef td ? name(td) : TypeName(t.TypeDefOrRef)); break;
                case GenericInstSig g:
                    Write(g.GenericType);
                    sb.Append('<');
                    for (int i = 0; i < g.GenericArguments.Count; i++)
                    {
                        if (i > 0) sb.Append(',');
                        Write(g.GenericArguments[i]);
                    }
                    sb.Append('>');
                    break;
                case GenericMVar mv: sb.Append("!!").Append(mv.Number); break;
                case GenericVar v: sb.Append('!').Append(v.Number); break;
                case PtrSig p: Write(p.Next); sb.Append('*'); break;
                case ByRefSig r: Write(r.Next); sb.Append('&'); break;
                case SZArraySig a: Write(a.Next); sb.Append("[]"); break;
                case ArraySig a: Write(a.Next); sb.Append('[').Append(a.Rank).Append(']'); break;
                case PinnedSig p: Write(p.Next); sb.Append(" pinned"); break;
                case ModifierSig m: Write(m.Next); sb.Append(m is CModReqdSig ? " modreq(" : " modopt(").Append(TypeName(m.Modifier)).Append(')'); break;
                case FnPtrSig f: sb.Append("method ").Append(f.MethodSig is { } ms ? CallSiteName(ms) : "?"); break;
                default: sb.Append(s.FullName); break;
            }
        }
    }

    private static int VariableIndex(object? operand) => operand switch
    {
        int i => i,
        Parameter p => p.Index,
        Local l => l.Index,
        byte b => b,
        ushort u => u,
        _ => -1,
    };

    private static Code LongForm(Code c) => c switch
    {
        Code.Br_S => Code.Br, Code.Brtrue_S => Code.Brtrue, Code.Brfalse_S => Code.Brfalse,
        Code.Beq_S => Code.Beq, Code.Bne_Un_S => Code.Bne_Un, Code.Bge_S => Code.Bge, Code.Bgt_S => Code.Bgt,
        Code.Ble_S => Code.Ble, Code.Blt_S => Code.Blt, Code.Bge_Un_S => Code.Bge_Un, Code.Bgt_Un_S => Code.Bgt_Un,
        Code.Ble_Un_S => Code.Ble_Un, Code.Blt_Un_S => Code.Blt_Un, Code.Leave_S => Code.Leave,
        Code.Ldarg_S => Code.Ldarg, Code.Ldarga_S => Code.Ldarga, Code.Starg_S => Code.Starg,
        Code.Ldloc_S => Code.Ldloc, Code.Ldloca_S => Code.Ldloca, Code.Stloc_S => Code.Stloc,
        _ => c,
    };

    private static string OpCodeName(Code c) => c.ToOpCode().Name;

    /// <summary>Double-quoted; backslash, quote, control characters, DEL and surrogates escaped (\uXXXX).</summary>
    private static string Quote(string s)
    {
        var sb = new StringBuilder(s.Length + 2).Append('"');
        foreach (var ch in s)
        {
            switch (ch)
            {
                case '\\': sb.Append("\\\\"); break;
                case '"': sb.Append("\\\""); break;
                default:
                    if (ch < 0x20 || ch == 0x7F || char.IsSurrogate(ch)) sb.Append("\\u").Append(((int)ch).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(ch);
                    break;
            }
        }
        return sb.Append('"').ToString();
    }

    private static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);
}
