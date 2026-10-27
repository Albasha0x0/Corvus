using System.Globalization;
using System.Text;

namespace Corvus.Core.Mobile;

/// <summary>Smali text in baksmali's layout; <see cref="Annotated"/> adds each instruction's offset and code units.</summary>
public sealed class DalvikDisassembler(DexFile dex)
{
    public bool Annotated { get; init; }

    /// <summary>A comment line to write after an instruction, by method and code offset; null writes none.</summary>
    public Func<DexEncodedMethod, IReadOnlyDictionary<int, string>?>? Notes { get; init; }

    public string Class(DexClass c)
    {
        var sb = new StringBuilder();
        sb.Append(".class ").Append(Flags(c.Access, 0)).Append(c.Descriptor).Append('\n');
        if (c.SuperClass != null) sb.Append(".super ").Append(c.SuperClass).Append('\n');
        if (c.SourceFile != null) sb.Append(".source \"").Append(DexFile.Escape(c.SourceFile)).Append("\"\n");
        if (c.Interfaces.Count > 0)
        {
            sb.Append("\n# interfaces\n");
            foreach (var i in c.Interfaces) sb.Append(".implements ").Append(i).Append('\n');
        }
        var annotations = dex.Annotations(c);
        if (annotations.Class.Count > 0)
        {
            sb.Append("\n\n# annotations\n");
            for (int i = 0; i < annotations.Class.Count; i++)
            {
                if (i > 0) sb.Append('\n');
                Annotation(sb, annotations.Class[i], "");
            }
        }
        var (fields, methods) = dex.ClassData(c);
        var statics = dex.StaticValues(c);
        var setInInitializer = StaticInitializerWrites(methods);
        int s = 0;
        void Fields(string title, IEnumerable<DexEncodedField> list)
        {
            var items = list.ToList();
            if (items.Count == 0) return;
            sb.Append("\n\n# ").Append(title).Append('\n');
            foreach (var f in items)
            {
                var r = dex.Field(f.FieldIndex);
                sb.Append(".field ").Append(Flags(f.Access, 1)).Append(r.Name).Append(':').Append(r.Type);
                // baksmali leaves out the default initial value of a final field the static initializer assigns.
                var v = f.IsStatic && s < statics.Count ? statics[s] : null;
                if (v != null && !((f.Access & 0x10) != 0 && IsDefault(v) && setInInitializer.Contains(f.FieldIndex))) sb.Append(" = ").Append(Value(v, ""));
                if (f.IsStatic) s++;
                sb.Append('\n');
                if (annotations.Fields.GetValueOrDefault(f.FieldIndex) is { Count: > 0 } fa)
                {
                    for (int k = 0; k < fa.Count; k++)
                    {
                        if (k > 0) sb.Append('\n');
                        Annotation(sb, fa[k], "    ");
                    }
                    sb.Append(".end field\n");
                }
                sb.Append('\n');
            }
            sb.Length--;
        }
        Fields("static fields", fields.Where(f => f.IsStatic));
        Fields("instance fields", fields.Where(f => !f.IsStatic));
        foreach (var (title, list) in new[] { ("direct methods", methods.Where(m => m.IsDirect)), ("virtual methods", methods.Where(m => !m.IsDirect)) })
        {
            var items = list.ToList();
            if (items.Count == 0) continue;
            sb.Append("\n\n# ").Append(title).Append('\n');
            for (int i = 0; i < items.Count; i++)
            {
                if (i > 0) sb.Append('\n');
                Method(sb, items[i], annotations);
            }
        }
        return sb.ToString();
    }

    private HashSet<int> StaticInitializerWrites(List<DexEncodedMethod> methods)
    {
        var result = new HashSet<int>();
        foreach (var m in methods.Where(m => m.IsDirect && dex.Method(m.MethodIndex).Name == "<clinit>"))
            if (dex.Code(m.CodeOffset) is { } code)
                foreach (var i in Dalvik.Decode(code.Instructions))
                    if (i.Opcode is >= 0x67 and <= 0x6d) result.Add(i.Index);
        return result;
    }

    private static bool IsDefault(DexValue v) => v.Kind switch
    {
        "null" => true, "boolean" => !(bool)v.Value!, "int" => (int)v.Value! == 0, "long" => (long)v.Value! == 0, "short" => (short)v.Value! == 0,
        "byte" => (sbyte)v.Value! == 0, "char" => (char)v.Value! == 0, "float" => BitConverter.SingleToInt32Bits((float)v.Value!) == 0,
        "double" => BitConverter.DoubleToInt64Bits((double)v.Value!) == 0, _ => false,
    };

    public string Method(DexEncodedMethod m, DexClassAnnotations annotations)
    {
        var sb = new StringBuilder();
        Method(sb, m, annotations);
        return sb.ToString();
    }

    private static string Flags(uint access, int kind) => DexFile.Access(access, kind) is { Length: > 0 } a ? a + " " : "";

    private void Method(StringBuilder sb, DexEncodedMethod m, DexClassAnnotations annotations)
    {
        var r = dex.Method(m.MethodIndex);
        sb.Append(".method ").Append(Flags(m.Access, 2)).Append(r.Name).Append(r.Proto.Descriptor).Append('\n');
        var code = m.CodeOffset != 0 ? dex.Code(m.CodeOffset) : null;
        int parameterBase = code == null ? 0 : code.Registers - code.Ins;
        if (code != null) sb.Append("    .registers ").Append(code.Registers.ToString(CultureInfo.InvariantCulture)).Append('\n');
        var (lines, names) = code != null ? dex.Debug(code.DebugInfoOffset) : ([], []);
        var parameterAnnotations = annotations.Parameters.GetValueOrDefault(m.MethodIndex) ?? [];
        int register = (m.Access & 0x8) != 0 ? 0 : 1;
        for (int i = 0; i < r.Proto.Parameters.Count; i++)
        {
            var name = i < names.Count ? names[i] : null;
            var pa = i < parameterAnnotations.Count ? parameterAnnotations[i] : [];
            if (name != null || pa.Count > 0)
            {
                sb.Append("    .param p").Append(register.ToString(CultureInfo.InvariantCulture));
                if (name != null) sb.Append(", \"").Append(DexFile.Escape(name)).Append('"');
                sb.Append("    # ").Append(r.Proto.Parameters[i]).Append('\n');
                if (pa.Count > 0)
                {
                    foreach (var a in pa) Annotation(sb, a, "        ");
                    sb.Append("    .end param\n");
                }
            }
            register += r.Proto.Parameters[i] is "J" or "D" ? 2 : 1;
        }
        foreach (var a in annotations.Methods.GetValueOrDefault(m.MethodIndex) ?? [])
        {
            Annotation(sb, a, "    ");
            sb.Append('\n');
        }
        if (code != null) Body(sb, code, parameterBase, lines, Notes?.Invoke(m));
        // Annotations end without a blank line when no code follows.
        else if (sb[^1] == '\n' && sb[^2] == '\n') sb.Length--;
        sb.Append(".end method\n");
    }

    private void Body(StringBuilder sb, DexCode code, int parameterBase, List<(int Offset, int Line)> lines, IReadOnlyDictionary<int, string>? notes)
    {
        var insns = Dalvik.Decode(code.Instructions);
        var at = insns.ToDictionary(i => i.Offset);
        var labels = new Dictionary<int, SortedSet<string>>();
        void Label(int offset, string kind) { if (!labels.TryGetValue(offset, out var set)) labels[offset] = set = new(StringComparer.Ordinal); set.Add($":{kind}_{offset:x}"); }
        var payloadOwner = new Dictionary<int, int>();
        foreach (var i in insns)
        {
            switch (i.Format)
            {
                case DalvikFormat.F10t or DalvikFormat.F20t or DalvikFormat.F30t: Label(i.Target, "goto"); break;
                case DalvikFormat.F21t or DalvikFormat.F22t: Label(i.Target, "cond"); break;
                case DalvikFormat.F31t:
                    payloadOwner[i.Target] = i.Offset;
                    Label(i.Target, i.Opcode switch { 0x2b => "pswitch_data", 0x2c => "sswitch_data", _ => "array" });
                    if (i.Opcode is 0x2b or 0x2c && at.TryGetValue(i.Target, out var payload) && payload.IsPayload)
                        foreach (var (_, target) in Dalvik.SwitchTargets(code.Instructions, payload, i.Offset)) Label(target, i.Opcode == 0x2b ? "pswitch" : "sswitch");
                    break;
            }
        }
        foreach (var t in code.Tries)
        {
            Label(t.Start, "try_start");
            foreach (var (type, handler) in t.Handlers) Label(handler, type == null ? "catchall" : "catch");
        }
        var lineAt = lines.GroupBy(l => l.Offset).ToDictionary(g => g.Key, g => g.Last().Line);
        if (!(sb[^1] == '\n' && sb[^2] == '\n')) sb.Append('\n');
        var pending = new Queue<int>(labels.Keys.Order());
        foreach (var i in insns)
        {
            if (lineAt.TryGetValue(i.Offset, out var line)) sb.Append("    .line ").Append(line.ToString(CultureInfo.InvariantCulture)).Append('\n');
            // A label inside an instruction (malformed or transformed code) is placed before the next instruction.
            while (pending.Count > 0 && pending.Peek() <= i.Offset)
                foreach (var n in labels[pending.Dequeue()].OrderBy(LabelOrder).ThenBy(n => n, StringComparer.Ordinal)) sb.Append("    ").Append(n).Append('\n');
            if (i.IsPayload) Payload(sb, code.Instructions, i, payloadOwner.GetValueOrDefault(i.Offset));
            else
            {
                sb.Append("    ").Append(Text(i, parameterBase, code.Instructions, payloadOwner));
                if (Annotated) sb.Append("    # ").Append($"{i.Offset:x4}: ").AppendJoin(' ', code.Instructions.AsSpan(i.Offset, i.Length).ToArray().Select(u => u.ToString("x4", CultureInfo.InvariantCulture)));
                sb.Append('\n');
                if (notes != null && notes.TryGetValue(i.Offset, out var note)) sb.Append("    # ").Append(note).Append('\n');
            }
            int end = i.Offset + i.Length;
            var ending = code.Tries.Where(t => t.Start + t.Count == end).ToList();
            if (ending.Count > 0)
            {
                sb.Append("    :try_end_").Append(end.ToString("x", CultureInfo.InvariantCulture)).Append('\n');
                foreach (var t in ending)
                    foreach (var (type, handler) in t.Handlers)
                        sb.Append(type == null ? "    .catchall" : "    .catch " + type).Append($" {{:try_start_{t.Start:x} .. :try_end_{end:x}}} ")
                          .Append(type == null ? ":catchall_" : ":catch_").Append(handler.ToString("x", CultureInfo.InvariantCulture)).Append('\n');
            }
            sb.Append('\n');
        }
        if (insns.Sum(i => i.Length) < code.Instructions.Length)
            sb.Append($"    # the code ends inside an instruction at 0x{insns.Sum(i => i.Length):x}\n\n");
        sb.Length--;
    }

    private static int LabelOrder(string label) => label.StartsWith(":try_start", StringComparison.Ordinal) ? 1 : 0;

    private void Payload(StringBuilder sb, ushort[] code, DalvikInstruction payload, int owner)
    {
        switch (payload.Format)
        {
            case DalvikFormat.PackedSwitchPayload:
            {
                var targets = Dalvik.SwitchTargets(code, payload, owner);
                sb.Append("    .packed-switch ").Append(Hex(targets.Count > 0 ? targets[0].Key : 0)).Append('\n');
                foreach (var (_, t) in targets) sb.Append($"        :pswitch_{t:x}\n");
                sb.Append("    .end packed-switch\n");
                break;
            }
            case DalvikFormat.SparseSwitchPayload:
                sb.Append("    .sparse-switch\n");
                foreach (var (key, t) in Dalvik.SwitchTargets(code, payload, owner)) sb.Append($"        {Hex(key)} -> :sswitch_{t:x}\n");
                sb.Append("    .end sparse-switch\n");
                break;
            default:
                var values = Dalvik.ArrayData(code, payload, out var width);
                sb.Append("    .array-data ").Append(width.ToString(CultureInfo.InvariantCulture)).Append('\n');
                // baksmali's writeSignedIntOrLongTo: an 8-byte element in int range carries no L suffix.
                foreach (var v in values)
                    sb.Append("        ").Append(width switch { 8 => Hex(v) + (v is < int.MinValue or > int.MaxValue ? "L" : "") + LikelyDouble(v), 1 => Hex(v) + "t", 2 => Hex(v) + "s", 4 => Hex(v) + LikelyFloat((int)v), _ => Hex(v) }).Append('\n');
                sb.Append("    .end array-data\n");
                break;
        }
    }

    private static string Hex(long v) => v < 0 ? "-0x" + ((ulong)-v).ToString("x", CultureInfo.InvariantCulture) : "0x" + v.ToString("x", CultureInfo.InvariantCulture);

    private static string Register(int r, int parameterBase) => r >= parameterBase ? $"p{r - parameterBase}" : $"v{r}";

    /// <summary>One instruction with its operands resolved; branch targets as labels.</summary>
    public string Text(DalvikInstruction i, int parameterBase, ushort[] code, IReadOnlyDictionary<int, int>? payloadOwner = null)
    {
        string R(int r) => Register(r, parameterBase);
        string Ref() => i.Ref switch
        {
            DalvikRef.String => "\"" + DexFile.Escape(dex.String(i.Index)) + "\"",
            DalvikRef.Type => dex.Type(i.Index),
            DalvikRef.Field => dex.Field(i.Index).Descriptor,
            DalvikRef.Method => dex.Method(i.Index).Descriptor,
            DalvikRef.Proto => dex.Proto(i.Index).Descriptor,
            DalvikRef.CallSite => $"call_site_{i.Index}",
            DalvikRef.MethodHandle => $"method_handle_{i.Index}",
            _ => "",
        };
        string Args() => i.IsRange
            ? i.Arguments.Count == 0 ? "{}" : $"{{{R(i.Arguments[0])} .. {R(i.Arguments[^1])}}}"
            : "{" + string.Join(", ", i.Arguments.Select(R)) + "}";
        // baksmali marks only const-wide and const-wide/high16 literals as long.
        bool wide = i.Opcode is 0x18 or 0x19;
        string Lit() => Hex(i.Literal) + (wide ? "L" : "");
        string Target(string kind) => $":{kind}_{i.Target:x}";
        var n = i.Name;
        return i.Format switch
        {
            DalvikFormat.F10x => n,
            DalvikFormat.F12x => $"{n} {R(i.A)}, {R(i.B)}",
            DalvikFormat.F11n => $"{n} {R(i.A)}, {Lit()}",
            DalvikFormat.F11x => $"{n} {R(i.A)}",
            DalvikFormat.F10t or DalvikFormat.F20t or DalvikFormat.F30t => $"{n} {Target("goto")}",
            DalvikFormat.F22x or DalvikFormat.F32x => $"{n} {R(i.A)}, {R(i.B)}",
            DalvikFormat.F21t => $"{n} {R(i.A)}, {Target("cond")}",
            DalvikFormat.F22t => $"{n} {R(i.A)}, {R(i.B)}, {Target("cond")}",
            DalvikFormat.F21s or DalvikFormat.F31i or DalvikFormat.F51l or DalvikFormat.F21h => $"{n} {R(i.A)}, {Lit()}{FloatComment(i)}",
            DalvikFormat.F21c or DalvikFormat.F31c => $"{n} {R(i.A)}, {Ref()}",
            DalvikFormat.F23x => $"{n} {R(i.A)}, {R(i.B)}, {R(i.C)}",
            DalvikFormat.F22b or DalvikFormat.F22s => $"{n} {R(i.A)}, {R(i.B)}, {Hex(i.Literal)}",
            DalvikFormat.F22c => $"{n} {R(i.A)}, {R(i.B)}, {Ref()}",
            DalvikFormat.F31t => $"{n} {R(i.A)}, {Target(i.Opcode switch { 0x2b => "pswitch_data", 0x2c => "sswitch_data", _ => "array" })}",
            DalvikFormat.F35c or DalvikFormat.F3rc => $"{n} {Args()}, {Ref()}",
            DalvikFormat.F45cc or DalvikFormat.F4rcc => $"{n} {Args()}, {Ref()}, {dex.Proto(i.Index2).Descriptor}",
            _ => $"# {n}",
        };
    }

    /// <summary>baksmali's comment on a constant that reads better as a float or double (NumberUtils.isLikelyFloat / isLikelyDouble).</summary>
    private static string FloatComment(DalvikInstruction i) =>
        i.Opcode is < 0x12 or > 0x19 ? "" : i.Opcode >= 0x16 ? LikelyDouble(i.Literal) : LikelyFloat((int)i.Literal);

    private static string LikelyDouble(long l)
    {
        {
            double d = BitConverter.Int64BitsToDouble(l);
            string? named = l switch
            {
                0x7ff8000000000000 => "Double.NaN", 0x7fefffffffffffff => "Double.MAX_VALUE", 0x400921fb54442d18 => "Math.PI", 0x4005bf0a8b145769 => "Math.E", _ => null,
            };
            if (named == null && (l is long.MaxValue or long.MinValue || double.IsNaN(d) || !(Shorter(d) < JavaScientific(l.ToString(CultureInfo.InvariantCulture)).Length))) return "";
            return "    # " + (named ?? (double.IsPositiveInfinity(d) ? "Double.POSITIVE_INFINITY" : double.IsNegativeInfinity(d) ? "Double.NEGATIVE_INFINITY" : DexFile.JavaNumber(d)));
        }
    }

    private static string LikelyFloat(int v)
    {
        float f = BitConverter.Int32BitsToSingle(v);
        string? name = v switch { 0x7fc00000 => "Float.NaN", 0x7f7fffff => "Float.MAX_VALUE", 0x40490fdb => "(float)Math.PI", 0x402df854 => "(float)Math.E", _ => null };
        if (name == null)
        {
            if (v is int.MaxValue or int.MinValue || float.IsNaN(f)) return "";
            int package = v >> 24, type = (v >> 16) & 0xff, id = v & 0xffff;
            // A resource id.
            if ((package == 0x7f || package == 1) && type < 0x1f && id < 0xfff) return "";
            if (!(Shorter(f) < JavaScientific(v.ToString(CultureInfo.InvariantCulture)).Length)) return "";
        }
        return "    # " + (name ?? (float.IsPositiveInfinity(f) ? "Float.POSITIVE_INFINITY" : float.IsNegativeInfinity(f) ? "Float.NEGATIVE_INFINITY" : DexFile.JavaNumber(f) + "f"));
    }

    /// <summary>Length of the float's scientific form with a run of 000 or 999 in the mantissa cut, as baksmali compares it.</summary>
    private static int Shorter(double value)
    {
        if (double.IsInfinity(value)) return 1;
        var s = JavaScientific(value.ToString("R", CultureInfo.InvariantCulture));
        int dot = s.IndexOf('.', StringComparison.Ordinal), e = s.IndexOf('E', StringComparison.Ordinal);
        foreach (var run in new[] { "000", "999" })
        {
            int at = s.IndexOf(run, StringComparison.Ordinal);
            if (dot >= 0 && at > dot && at < e) return at + (s.Length - e);
        }
        return s.Length;
    }

    /// <summary>A decimal number (as .NET writes it) in Java's DecimalFormat("0.####################E0") form.</summary>
    private static string JavaScientific(string number)
    {
        bool negative = number.StartsWith('-');
        if (negative) number = number[1..];
        int exp = 0;
        int ePos = number.IndexOfAny(['E', 'e']);
        if (ePos >= 0) { exp = int.Parse(number[(ePos + 1)..], CultureInfo.InvariantCulture); number = number[..ePos]; }
        int dot = number.IndexOf('.', StringComparison.Ordinal);
        var digits = dot >= 0 ? number.Remove(dot, 1) : number;
        int intDigits = dot >= 0 ? dot : number.Length;
        int lead = 0;
        while (lead < digits.Length - 1 && digits[lead] == '0') lead++;
        digits = digits[lead..].TrimEnd('0');
        if (digits.Length == 0) return (negative ? "-" : "") + "0E0";
        exp += intDigits - lead - 1;
        if (digits.Length > 21) digits = digits[..21];
        return (negative ? "-" : "") + digits[0] + (digits.Length > 1 ? "." + digits[1..] : "") + "E" + exp.ToString(CultureInfo.InvariantCulture);
    }

    private void Annotation(StringBuilder sb, DexAnnotation a, string indent)
    {
        sb.Append(indent).Append(".annotation ").Append(a.Visibility).Append(' ').Append(a.Type).Append('\n');
        foreach (var (name, value) in a.Elements) sb.Append(indent).Append("    ").Append(name).Append(" = ").Append(Value(value, indent + "    ")).Append('\n');
        sb.Append(indent).Append(".end annotation\n");
    }

    /// <summary>An encoded value as smali writes it; arrays and nested annotations span lines.</summary>
    private static string Value(DexValue v, string indent) => v.Kind switch
    {
        "array" when ((IReadOnlyList<DexValue>)v.Value!).Count == 0 => "{}",
        "array" => "{\n" + string.Join(",\n", ((IReadOnlyList<DexValue>)v.Value!).Select(x => indent + "    " + Value(x, indent + "    "))) + "\n" + indent + "}",
        "annotation" => ((DexAnnotation)v.Value!) is var a
            ? ".subannotation " + a.Type + "\n" + string.Concat(a.Elements.Select(e => $"{indent}    {e.Name} = {Value(e.Value, indent + "    ")}\n")) + indent + ".end subannotation"
            : "",
        "type" or "field" or "method" or "method_type" => v.Value?.ToString() ?? "",
        _ => v.ToString(),
    };
}
