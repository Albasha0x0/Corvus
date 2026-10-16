using System.Globalization;
using System.Text;

namespace Corvus.Core.Mobile;

/// <summary>
/// A class file as text in the layout of <c>javap -c -p</c>: declaration, every field and method with its modifiers and
/// generic types, and each method's bytecode with constant pool comments and the exception table.
/// </summary>
public sealed class JvmListing
{
    private readonly JvmClass _c;
    private readonly Lines _out = new();
    private bool IsInterface => (_c.Access & JvmClass.AccInterface) != 0;

    private JvmListing(JvmClass c) => _c = c;

    /// <summary>The whole class.</summary>
    public static string Class(JvmClass c) => Guarded(() =>
    {
        var w = new JvmListing(c);
        w.Write();
        return w._out.Text();
    });

    /// <summary>One method: its declaration and code, as they appear inside the class.</summary>
    public static string Method(JvmClass c, JvmMember m) => Guarded(() =>
    {
        var w = new JvmListing(c);
        w._out.Indent(1);
        w.WriteMethod(m);
        w._out.PendingNewline = false;
        w._out.Flush();
        return w._out.Text();
    });

    /// <summary>A read past an attribute or code end is one error kind: the input is malformed, not the reader.</summary>
    private static string Guarded(Func<string> write)
    {
        try { return write(); }
        catch (Exception e) when (e is IndexOutOfRangeException or ArgumentException or OverflowException)
        {
            throw new InvalidDataException("class file is truncated or malformed: " + e.Message, e);
        }
    }

    private void Write()
    {
        if (_c.SourceFile is { } source) _out.Println($"Compiled from \"{source}\"");
        WriteModifiers(Modifiers(IsInterface ? _c.Access & ~JvmClass.AccAbstract : _c.Access, ClassFlags));
        if ((_c.Access & JvmClass.AccModule) != 0 && _c.Find("Module") is { } module) WriteModuleName(module);
        else
        {
            _out.Print(IsInterface ? "interface " : "class ");
            _out.Print(_c.Name.Replace('/', '.'));
        }
        WriteSupertypes();
        _out.Print(" ");
        _out.Println("{");
        _out.Indent(1);
        if ((_c.Access & JvmClass.AccModule) != 0 && _c.Find("Module") is { } directives) WriteDirectives(directives);
        foreach (var f in _c.Fields) WriteField(f);
        foreach (var m in _c.Methods) WriteMethod(m);
        _out.PendingNewline = false;
        _out.Indent(-1);
        _out.Println("}");
    }

    private void WriteSupertypes()
    {
        if (_c.Find("Signature") is { } sig)
        {
            var s = JvmSignatures.Class(_c.Utf(_c.U2(sig.Offset)));
            var sb = new StringBuilder(JvmSignatures.Print(s.Parameters));
            if (IsInterface)
            {
                var sep = " extends ";
                foreach (var i in s.Interfaces) { sb.Append(sep); JvmSignatures.Print(sb, i); sep = ", "; }
            }
            else
            {
                if (s.Superclass != null && !JvmSignatures.IsObject(s.Superclass)) { sb.Append(" extends "); JvmSignatures.Print(sb, s.Superclass); }
                var sep = " implements ";
                foreach (var i in s.Interfaces) { sb.Append(sep); JvmSignatures.Print(sb, i); sep = ", "; }
            }
            _out.Print(sb.ToString());
            return;
        }
        if (!IsInterface && _c.SuperName is { } super && super != "java/lang/Object") _out.Print(" extends " + super.Replace('/', '.'));
        int n = 0;
        foreach (var i in _c.Interfaces)
        {
            _out.Print(n++ == 0 ? IsInterface ? " extends " : " implements " : ",");
            _out.Print(i.Replace('/', '.'));
        }
    }

    // Source modifiers in java.lang.reflect.AccessFlag order, by location.
    private static readonly (int Mask, string Name)[] ClassFlags = [(0x0001, "public"), (0x0010, "final"), (0x0400, "abstract")];
    private static readonly (int Mask, string Name)[] FieldFlags =
        [(0x0001, "public"), (0x0002, "private"), (0x0004, "protected"), (0x0008, "static"), (0x0010, "final"), (0x0040, "volatile"), (0x0080, "transient")];
    private static readonly (int Mask, string Name)[] MethodFlags =
        [(0x0001, "public"), (0x0002, "private"), (0x0004, "protected"), (0x0008, "static"), (0x0010, "final"), (0x0020, "synchronized"),
         (0x0100, "native"), (0x0400, "abstract"), (0x0800, "strictfp")];

    private static List<string> Modifiers(int access, (int Mask, string Name)[] table) => [.. table.Where(f => (access & f.Mask) != 0).Select(f => f.Name)];

    private void WriteModifiers(IEnumerable<string> items)
    {
        foreach (var item in items)
        {
            _out.Print(item);
            _out.Print(" ");
        }
    }

    private void WriteField(JvmMember f)
    {
        WriteModifiers(Modifiers(f.Access, FieldFlags));
        var type = f.Find("Signature") is { } sig ? JvmSignatures.Field(_c.Utf(_c.U2(sig.Offset))) : JvmSignatures.Field(f.Descriptor);
        _out.Print(JvmSignatures.Print(type));
        _out.Print(" ");
        _out.Print(f.Name);
        _out.Print(";");
        _out.Println();
        _out.Println();
    }

    private void WriteMethod(JvmMember m)
    {
        var modifiers = Modifiers(m.Access, MethodFlags);
        if (IsInterface && (m.Access & JvmClass.AccAbstract) == 0 && m.Name != "<clinit>" && _c.Major >= 52 && (m.Access & (JvmClass.AccStatic | JvmClass.AccPrivate)) == 0)
            modifiers.Add("default");
        WriteModifiers(modifiers);
        var d = m.Find("Signature") is { } sig ? JvmSignatures.Method(_c.Utf(_c.U2(sig.Offset))) : JvmSignatures.Method(m.Descriptor);
        if (d.Parameters.Count > 0) _out.Print(JvmSignatures.Print(d.Parameters) + " ");
        switch (m.Name)
        {
            case "<init>":
                _out.Print(_c.Name.Replace('/', '.'));
                _out.Print(Parameters(d, m.Access));
                break;
            case "<clinit>":
                _out.Print("{}");
                break;
            default:
                _out.Print(JvmSignatures.Print(d.Result).Replace('/', '.'));
                _out.Print(" ");
                _out.Print(m.Name);
                _out.Print(Parameters(d, m.Access));
                break;
        }
        if (m.Find("Exceptions") is { } ex)
        {
            _out.Print(" throws ");
            if (d.Throws.Count > 0) _out.Print(string.Join(", ", d.Throws.Select(JvmSignatures.Print)));
            else
                for (int i = 0, n = _c.U2(ex.Offset); i < n; i++)
                {
                    if (i > 0) _out.Print(", ");
                    _out.Print(_c.ClassName(_c.U2(ex.Offset + 2 + 2 * i)).Replace('/', '.'));
                }
        }
        _out.Println(";");
        _out.Indent(1);
        if (m.Find("Code") is { } code) WriteCode(code);
        _out.Indent(-1);
        _out.PendingNewline = true;
    }

    private static string Parameters(JvmMethodSignature d, int access)
    {
        var sb = new StringBuilder("(");
        for (int i = 0; i < d.Arguments.Count; i++)
        {
            if (i > 0) sb.Append(", ");
            JvmSignatures.Print(sb, d.Arguments[i]);
        }
        var text = sb.Append(')').ToString();
        if ((access & 0x0080) != 0 && text.LastIndexOf("[]", StringComparison.Ordinal) is var at and > 0) text = text[..at] + "..." + text[(at + 2)..];
        return text.Replace('/', '.');
    }

    private void WriteModuleName(JvmAttribute module)
    {
        int p = module.Offset;
        if ((_c.U2(p + 2) & 0x0020) != 0) _out.Print("open ");
        _out.Print("module ");
        _out.Print(_c.Utf(_c.Entry(_c.U2(p)).A));
        if (_c.U2(p + 4) is var version and > 0)
        {
            _out.Print("@");
            _out.Print(_c.Utf(version));
        }
    }

    private void WriteDirectives(JvmAttribute module)
    {
        int p = module.Offset + 6;
        string ModuleName(int index) => _c.Utf(_c.Entry(index).A);
        for (int i = 0, n = _c.U2(p); i < n; i++)
        {
            int at = p + 2 + 6 * i, flags = _c.U2(at + 2);
            _out.Print("requires");
            if ((flags & 0x0040) != 0) _out.Print(" static");
            if ((flags & 0x0020) != 0) _out.Print(" transitive");
            _out.Print(" ");
            _out.Print(ModuleName(_c.U2(at)));
            _out.Println(";");
        }
        p += 2 + 6 * _c.U2(p);
        foreach (var verb in new[] { "exports", "opens" })
        {
            int n = _c.U2(p);
            p += 2;
            for (int i = 0; i < n; i++)
            {
                _out.Print(verb);
                _out.Print(" ");
                _out.Print(_c.Utf(_c.Entry(_c.U2(p)).A).Replace('/', '.'));
                int to = _c.U2(p + 4);
                for (int k = 0; k < to; k++)
                {
                    if (k == 0) { _out.Println(" to"); _out.Indent(1); }
                    else _out.Println(",");
                    _out.Print(ModuleName(_c.U2(p + 6 + 2 * k)));
                }
                _out.Println(";");
                if (to > 0) _out.Indent(-1);
                p += 6 + 2 * to;
            }
        }
        for (int i = 0, n = _c.U2(p); i < n; i++)
        {
            _out.Print("uses ");
            _out.Print(_c.ClassName(_c.U2(p + 2 + 2 * i)).Replace('/', '.'));
            _out.Println(";");
        }
        p += 2 + 2 * _c.U2(p);
        for (int i = 0, n = _c.U2(p); i < n; i++)
        {
            p += 2;
            _out.Print("provides  ");
            _out.Print(_c.ClassName(_c.U2(p)).Replace('/', '.'));
            int with = _c.U2(p + 2);
            for (int k = 0; k < with; k++)
            {
                if (k == 0) { _out.Println(" with"); _out.Indent(1); }
                else _out.Println(",");
                _out.Print(_c.ClassName(_c.U2(p + 4 + 2 * k)).Replace('/', '.'));
            }
            _out.Println(";");
            if (with > 0) _out.Indent(-1);
            p += 2 + 2 * with - 2;
        }
    }

    private void WriteCode(JvmAttribute attr)
    {
        _out.Println("Code:");
        _out.Indent(1);
        int start = attr.Offset + 8, length = _c.S4(attr.Offset + 4);
        if (length < 0 || start + length > attr.Offset + attr.Length) throw new InvalidDataException("Code attribute is shorter than its code");
        var code = _c.Data.AsSpan(start, length).ToArray();
        for (int pc = 0; pc < length;) pc += WriteInstruction(code, pc);
        int table = start + length;
        int handlers = _c.U2(table);
        if (handlers > 0)
        {
            _out.Println("Exception table:");
            _out.Indent(1);
            _out.Println(" from    to  target type");
            for (int i = 0; i < handlers; i++)
            {
                int at = table + 2 + 8 * i;
                _out.Print(string.Format(CultureInfo.InvariantCulture, " {0,5} {1,5} {2,5}", _c.U2(at), _c.U2(at + 2), _c.U2(at + 4)));
                _out.Print("   ");
                if (_c.U2(at + 6) is var type and > 0)
                {
                    _out.Print("Class ");
                    _out.Println(StringValue(type));
                }
                else _out.Println("any");
            }
            _out.Indent(-1);
        }
        _out.Indent(-1);
    }

    private static readonly string[] Names = BuildNames();

    private static string[] BuildNames()
    {
        var n = new string[202];
        var plain = "nop aconst_null iconst_m1 iconst_0 iconst_1 iconst_2 iconst_3 iconst_4 iconst_5 lconst_0 lconst_1 fconst_0 fconst_1 fconst_2 dconst_0 dconst_1 bipush sipush ldc ldc_w ldc2_w iload lload fload dload aload";
        var all = plain.Split(' ').ToList();
        foreach (var t in "ilfda") for (int i = 0; i < 4; i++) all.Add($"{t}load_{i}");
        all.AddRange("iaload laload faload daload aaload baload caload saload istore lstore fstore dstore astore".Split(' '));
        foreach (var t in "ilfda") for (int i = 0; i < 4; i++) all.Add($"{t}store_{i}");
        all.AddRange(("iastore lastore fastore dastore aastore bastore castore sastore pop pop2 dup dup_x1 dup_x2 dup2 dup2_x1 dup2_x2 swap " +
                      "iadd ladd fadd dadd isub lsub fsub dsub imul lmul fmul dmul idiv ldiv fdiv ddiv irem lrem frem drem ineg lneg fneg dneg " +
                      "ishl lshl ishr lshr iushr lushr iand land ior lor ixor lxor iinc i2l i2f i2d l2i l2f l2d f2i f2l f2d d2i d2l d2f i2b i2c i2s " +
                      "lcmp fcmpl fcmpg dcmpl dcmpg ifeq ifne iflt ifge ifgt ifle if_icmpeq if_icmpne if_icmplt if_icmpge if_icmpgt if_icmple " +
                      "if_acmpeq if_acmpne goto jsr ret tableswitch lookupswitch ireturn lreturn freturn dreturn areturn return getstatic putstatic " +
                      "getfield putfield invokevirtual invokespecial invokestatic invokeinterface invokedynamic new newarray anewarray arraylength " +
                      "athrow checkcast instanceof monitorenter monitorexit wide multianewarray ifnull ifnonnull goto_w jsr_w").Split(' '));
        for (int i = 0; i < all.Count; i++) n[i] = all[i];
        return n;
    }

    private int WriteInstruction(byte[] code, int pc)
    {
        int op = code[pc];
        if (op >= Names.Length) throw new InvalidDataException($"unknown opcode 0x{op:x2} at {pc}");
        int U2(int at) => (code[at] << 8) | code[at + 1];
        short S2(int at) => (short)U2(at);
        int S4(int at) => (code[at] << 24) | (code[at + 1] << 16) | (code[at + 2] << 8) | code[at + 3];
        string name = Names[op];
        int size = 1;
        string operand = "";
        bool pool = false;
        int poolIndex = 0;
        string? poolSuffix = null;
        switch (op)
        {
            case 16: operand = ((sbyte)code[pc + 1]).ToString(CultureInfo.InvariantCulture); size = 2; break; // bipush
            case 17: operand = S2(pc + 1).ToString(CultureInfo.InvariantCulture); size = 3; break; // sipush
            case 18: pool = true; poolIndex = code[pc + 1]; size = 2; break; // ldc
            case 19 or 20: pool = true; poolIndex = U2(pc + 1); size = 3; break;
            case >= 21 and <= 25 or >= 54 and <= 58: operand = code[pc + 1].ToString(CultureInfo.InvariantCulture); size = 2; break;
            case 132: operand = $"{code[pc + 1]}, {(sbyte)code[pc + 2]}"; size = 3; break; // iinc
            case >= 153 and <= 166 or 198 or 199: operand = (pc + S2(pc + 1)).ToString(CultureInfo.InvariantCulture); size = 3; break;
            case 167: operand = (pc + S2(pc + 1)).ToString(CultureInfo.InvariantCulture); size = 3; break; // goto
            case 168: size = 3; break; // jsr: javap prints no operand
            case 169: size = 2; break; // ret
            case 200: operand = (pc + S4(pc + 1)).ToString(CultureInfo.InvariantCulture); size = 5; break; // goto_w
            case 201: size = 5; break; // jsr_w
            case >= 178 and <= 184 or 187 or 189 or 192 or 193: pool = true; poolIndex = U2(pc + 1); size = 3; break;
            case 185: pool = true; poolIndex = U2(pc + 1); poolSuffix = code[pc + 3].ToString(CultureInfo.InvariantCulture); size = 5; break;
            case 186: pool = true; poolIndex = U2(pc + 1); poolSuffix = "0"; size = 5; break;
            case 197: pool = true; poolIndex = U2(pc + 1); poolSuffix = code[pc + 3].ToString(CultureInfo.InvariantCulture); size = 4; break;
            case 188: // newarray
                operand = " " + (code[pc + 1] switch { 4 => "boolean", 5 => "char", 6 => "float", 7 => "double", 8 => "byte", 9 => "short", 10 => "int", 11 => "long",
                    var t => throw new InvalidDataException($"newarray type {t} at {pc}") });
                size = 2;
                break;
            case 196: // wide
            {
                int inner = code[pc + 1];
                name = Names[inner] + "_w";
                if (inner == 132) { operand = $"{U2(pc + 2)}, {S2(pc + 4)}"; size = 6; }
                else if (inner == 169) size = 4;
                else { operand = U2(pc + 2).ToString(CultureInfo.InvariantCulture); size = 4; }
                break;
            }
            case 170 or 171:
                return WriteSwitch(code, pc, op == 170);
        }
        _out.Print(string.Format(CultureInfo.InvariantCulture, "{0,4}: {1,-13} ", pc, name));
        if (pool)
        {
            _out.Print(poolSuffix == null ? $"#{poolIndex}" : $"#{poolIndex},  {poolSuffix}");
            _out.Tab();
            _out.Print("// ");
            _out.Print(Comment(poolIndex));
        }
        else _out.Print(operand);
        _out.Println();
        return size;
    }

    private int WriteSwitch(byte[] code, int pc, bool table)
    {
        int at = (pc + 4) & ~3;
        int S4(int i) => (code[i] << 24) | (code[i + 1] << 16) | (code[i + 2] << 8) | code[i + 3];
        int fallback = pc + S4(at);
        _out.Print(string.Format(CultureInfo.InvariantCulture, "{0,4}: {1,-13} ", pc, table ? "tableswitch" : "lookupswitch"));
        int size;
        _out.Indent(3);
        if (table)
        {
            int low = S4(at + 4), high = S4(at + 8);
            if (high < low || (long)high - low > code.Length) throw new InvalidDataException($"tableswitch at {pc} has {low} to {high}");
            _out.Print($"{{ // {low} to {high}");
            for (long v = low; v <= high; v++)
                _out.Print(string.Format(CultureInfo.InvariantCulture, "\n{0,12}: {1}", v, pc + S4(at + 12 + 4 * (int)(v - low))));
            size = at + 12 + 4 * (int)((long)high - low + 1) - pc;
        }
        else
        {
            int pairs = S4(at + 4);
            if (pairs < 0 || pairs > code.Length) throw new InvalidDataException($"lookupswitch at {pc} has {pairs} pairs");
            _out.Print($"{{ // {pairs}");
            for (int i = 0; i < pairs; i++)
                _out.Print(string.Format(CultureInfo.InvariantCulture, "\n{0,12}: {1}", S4(at + 8 + 8 * i), pc + S4(at + 12 + 8 * i)));
            size = at + 8 + 8 * pairs - pc;
        }
        _out.Print($"\n     default: {fallback}\n}}");
        _out.Indent(-3);
        _out.Println();
        return size;
    }

    /// <summary>The comment javap writes after a constant pool operand: a member of this class by name and type only.</summary>
    private string Comment(int index)
    {
        var e = _c.Entry(index);
        var shown = e.Tag is JvmClass.FieldRef or JvmClass.MethodRef or JvmClass.InterfaceMethodRef && e.A == _c.ThisIndex ? e.B : index;
        return TagName(e.Tag) + " " + StringValue(shown);
    }

    private static string TagName(int tag) => tag switch
    {
        JvmClass.Utf8 => "Utf8", JvmClass.Integer => "int", JvmClass.Float => "float", JvmClass.Long => "long", JvmClass.Double => "double",
        JvmClass.Class => "class", JvmClass.String => "String", JvmClass.FieldRef => "Field", JvmClass.MethodHandle => "MethodHandle",
        JvmClass.MethodType => "MethodType", JvmClass.MethodRef => "Method", JvmClass.InterfaceMethodRef => "InterfaceMethod",
        JvmClass.InvokeDynamic => "InvokeDynamic", JvmClass.Dynamic => "Dynamic", JvmClass.NameAndType => "NameAndType",
        _ => $"(unknown tag {tag})",
    };

    private string StringValue(int index)
    {
        var e = _c.Entry(index);
        return e.Tag switch
        {
            JvmClass.Class => CheckName(_c.Utf(e.A)),
            JvmClass.Double => JavaNumbers.Double(BitConverter.Int64BitsToDouble(e.Bits)) + "d",
            JvmClass.Float => JavaNumbers.Float(BitConverter.Int32BitsToSingle((int)e.Bits)) + "f",
            JvmClass.Integer => ((int)e.Bits).ToString(CultureInfo.InvariantCulture),
            JvmClass.Long => e.Bits.ToString(CultureInfo.InvariantCulture) + "l",
            JvmClass.FieldRef or JvmClass.MethodRef or JvmClass.InterfaceMethodRef => CheckName(_c.ClassName(e.A)) + "." + StringValue(e.B),
            JvmClass.Dynamic or JvmClass.InvokeDynamic => $"#{e.A}:" + StringValue(e.B),
            JvmClass.Module or JvmClass.Package => CheckName(_c.Utf(e.A)),
            JvmClass.NameAndType => CheckName(_c.Utf(e.A)) + ":" + _c.Utf(e.B),
            JvmClass.MethodHandle => (e.A switch
            {
                1 => "REF_getField", 2 => "REF_getStatic", 3 => "REF_putField", 4 => "REF_putStatic", 5 => "REF_invokeVirtual", 6 => "REF_invokeStatic",
                7 => "REF_invokeSpecial", 8 => "REF_newInvokeSpecial", 9 => "REF_invokeInterface", var k => throw new InvalidDataException($"method handle kind {k}"),
            }) + " " + StringValue(e.B),
            JvmClass.MethodType => _c.Utf(e.A),
            JvmClass.String => Escape(_c.Utf(e.A)),
            JvmClass.Utf8 => Escape(e.Text!),
            _ => throw new InvalidDataException($"constant #{index} has tag {e.Tag}"),
        };
    }

    private static string Escape(string s)
    {
        if (!s.Any(c => c is '"' or '\'' or '\\' || char.IsControl(c))) return s;
        var sb = new StringBuilder(s.Length + 8);
        foreach (var c in s)
            sb.Append(c switch
            {
                '\t' => "\\t", '\n' => "\\n", '\r' => "\\r", '\b' => "\\b", '\f' => "\\f", '"' => "\\\"", '\'' => "\\'", '\\' => "\\\\",
                _ => char.IsControl(c) ? $"\\u{(int)c:x4}" : c.ToString(),
            });
        return sb.ToString();
    }

    /// <summary>A binary name as is; anything else quoted with \ " newline and tab escaped.</summary>
    internal static string CheckName(string name)
    {
        if (name.Length == 0) return "\"\"";
        int previous = '/';
        for (int k = 0; k < name.Length;)
        {
            int cp = char.IsHighSurrogate(name[k]) && k + 1 < name.Length && char.IsLowSurrogate(name[k + 1]) ? char.ConvertToUtf32(name[k], name[k + 1]) : name[k];
            if ((previous == '/' && !JavaIdentifierStart(cp)) || (cp != '/' && !JavaIdentifierPart(cp)))
                return "\"" + name.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\t", "\\t") + "\"";
            previous = cp;
            k += cp > 0xFFFF ? 2 : 1;
        }
        return name;
    }

    private static UnicodeCategory Category(int cp) => cp <= 0xFFFF ? CharUnicodeInfo.GetUnicodeCategory((char)cp) : CharUnicodeInfo.GetUnicodeCategory(cp);

    private static bool JavaIdentifierStart(int cp) => Category(cp) is UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter
        or UnicodeCategory.TitlecaseLetter or UnicodeCategory.ModifierLetter or UnicodeCategory.OtherLetter or UnicodeCategory.LetterNumber
        or UnicodeCategory.CurrencySymbol or UnicodeCategory.ConnectorPunctuation;

    private static bool JavaIdentifierPart(int cp) => JavaIdentifierStart(cp)
        || Category(cp) is UnicodeCategory.DecimalDigitNumber or UnicodeCategory.SpacingCombiningMark or UnicodeCategory.NonSpacingMark or UnicodeCategory.Format
        || cp is >= 0 and <= 8 or >= 0x0E and <= 0x1B or >= 0x7F and <= 0x9F;

    /// <summary>javap's line writer: spaces are held until a visible character follows (so a line never ends in one), a newline in a value starts a new line.</summary>
    private sealed class Lines
    {
        private const int IndentWidth = 2, TabColumn = 40;
        private readonly StringBuilder _text = new(), _line = new();
        private int _spaces, _indent;
        public bool PendingNewline;

        public void Indent(int delta) => _indent += delta;

        public void Print(string s)
        {
            if (PendingNewline)
            {
                Println();
                PendingNewline = false;
            }
            foreach (var c in s)
            {
                if (c == ' ') _spaces++;
                else if (c == '\n') Println();
                else
                {
                    if (_line.Length == 0) _spaces += _indent * IndentWidth;
                    if (_spaces > 0)
                    {
                        _line.Append(' ', _spaces);
                        _spaces = 0;
                    }
                    _line.Append(c);
                }
            }
        }

        public void Println(string s)
        {
            Print(s);
            Println();
        }

        public void Println()
        {
            _spaces = 0;
            _text.Append(_line).Append('\n');
            _line.Clear();
        }

        public void Tab()
        {
            int column = _indent * IndentWidth + TabColumn;
            _spaces += column <= _line.Length ? 1 : column - _line.Length;
        }

        public void Flush()
        {
            if (_line.Length > 0) Println();
        }

        public string Text() => _text.ToString();
    }
}

/// <summary>Java's Double.toString and Float.toString: the shortest digits that read back, plain from 10^-3 to 10^7, else d.dddE±n.</summary>
public static class JavaNumbers
{
    public static string Double(double d) =>
        double.IsNaN(d) ? "NaN" : double.IsInfinity(d) ? d > 0 ? "Infinity" : "-Infinity"
        : Format(Shortest(d.ToString("R", CultureInfo.InvariantCulture), d.ToString("E1", CultureInfo.InvariantCulture)), Math.Abs(d) is >= 1e-3 and < 1e7 || d == 0);

    public static string Float(float f) =>
        float.IsNaN(f) ? "NaN" : float.IsInfinity(f) ? f > 0 ? "Infinity" : "-Infinity"
        : Format(Shortest(f.ToString("R", CultureInfo.InvariantCulture), f.ToString("E1", CultureInfo.InvariantCulture)), Math.Abs(f) is >= 1e-3f and < 1e7f || f == 0);

    /// <summary>Java takes two digits where one would do (4.9E-324, not 5.0E-324): the closest two-digit decimal then.</summary>
    private static string Shortest(string r, string twoDigits) =>
        r.TrimStart('-').Split('E', 'e')[0].Replace(".", "", StringComparison.Ordinal).Trim('0').Length == 1 ? twoDigits : r;

    /// <summary>Reformats .NET's shortest round-trip text ("1E-05", "123.45", "-0") in Java's layout.</summary>
    private static string Format(string r, bool plain)
    {
        bool negative = r.StartsWith('-');
        if (negative) r = r[1..];
        int e = 0;
        if (r.IndexOfAny(['E', 'e']) is var ei and >= 0)
        {
            e = int.Parse(r[(ei + 1)..], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
            r = r[..ei];
        }
        int dot = r.IndexOf('.');
        string digits = dot < 0 ? r : r[..dot] + r[(dot + 1)..];
        int point = (dot < 0 ? r.Length : dot) + e; // digits before the decimal point
        int lead = digits.Length - digits.TrimStart('0').Length;
        digits = digits.Trim('0');
        point -= lead;
        var sb = new StringBuilder(negative ? "-" : "");
        if (digits.Length == 0) return sb.Append("0.0").ToString();
        if (plain)
        {
            if (point <= 0) sb.Append("0.").Append('0', -point).Append(digits);
            else if (point >= digits.Length) sb.Append(digits).Append('0', point - digits.Length).Append(".0");
            else sb.Append(digits, 0, point).Append('.').Append(digits, point, digits.Length - point);
            return sb.ToString();
        }
        sb.Append(digits[0]).Append('.').Append(digits.Length > 1 ? digits[1..] : "0").Append('E').Append((point - 1).ToString(CultureInfo.InvariantCulture));
        return sb.ToString();
    }
}
