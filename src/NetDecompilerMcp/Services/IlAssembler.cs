using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Small IL assembler for patching method bodies from text. Accepts the output of get_il (edited) as well as
/// hand-written IL. One instruction per line:
///
///   [label:] opcode [operand]   // comment
///
/// Operands:
///   numbers (decimal or 0x hex), "C# escaped strings", labels (any 'name:' defined in the text, or IL_xxxx
///   offsets of the original body when prepending), switch (L1, L2, ...), arguments/locals by index or name,
///   and members/types either by a trailing metadata-token comment exactly as get_il prints it (/* 0A000025 */),
///   a token '0x06000012', or a symbol string ('Ns.Type::Method(int, string)', 'System.String::Concat(string, string)').
/// Directive: '.local &lt;type&gt;' declares a new local (index continues after existing locals).
/// Header lines from get_il (.method, .maxstack, braces, comments) are ignored.
/// </summary>
public sealed class IlAssembler(AssemblyWorkspace workspace)
{
    private static readonly Dictionary<string, OpCode> OpCodesByName = typeof(OpCodes)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(f => f.FieldType == typeof(OpCode))
        .Select(f => (OpCode)f.GetValue(null)!)
        .GroupBy(o => o.Name, StringComparer.OrdinalIgnoreCase)
        .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

    private static readonly Regex TokenComment = new(@"/\*\s*([0-9A-Fa-f]{8})\s*\*/", RegexOptions.Compiled);
    private static readonly Regex LabelPrefix = new(@"^([A-Za-z_][\w.$]*)\s*:(?!:)\s*", RegexOptions.Compiled);

    public sealed record Result(List<Instruction> Instructions, List<Local> NewLocals);

    private sealed record ParsedLine(int LineNumber, string? Label, string OpCode, string Operand, string? Token, string Raw);

    /// <summary>Parses <paramref name="source"/> into instructions for <paramref name="method"/>. Does not modify the method.</summary>
    public Result Assemble(LoadedAssembly asm, MethodDef method, string source, IList<Instruction>? originalForLabels)
    {
        var lines = Tokenize(source);
        if (lines.Count == 0)
            throw new ToolError("No IL instructions found in the patch text.");

        var module = method.Module;
        var importer = new Importer(module, ImporterOptions.TryToUseDefs);
        var newLocals = new List<Local>();
        var existingLocals = AnalysisService.SafeBody(method)?.Variables.ToList() ?? [];

        // Pass 1: create instructions, remember labels; branch operands are fixed up in pass 2.
        var labels = new Dictionary<string, Instruction>(StringComparer.Ordinal);
        var pending = new List<(Instruction Instr, ParsedLine Line)>();
        var instructions = new List<Instruction>();
        string? pendingLabel = null;

        foreach (var line in lines)
        {
            if (line.OpCode.Equals(".local", StringComparison.OrdinalIgnoreCase))
            {
                newLocals.Add(new Local(ParseTypeSig(asm, module, importer, line.Operand, line)));
                continue;
            }
            if (line.OpCode.Length == 0)
            {
                pendingLabel = line.Label ?? pendingLabel;
                continue;
            }
            if (!OpCodesByName.TryGetValue(line.OpCode, out var op))
                throw Error(line, $"unknown opcode '{line.OpCode}'");

            var instr = new Instruction(op);
            foreach (var label in new[] { pendingLabel, line.Label }.Where(l => l != null).Distinct())
            {
                if (!labels.TryAdd(label!, instr))
                    throw Error(line, $"label '{label}' defined twice");
            }
            pendingLabel = null;
            instructions.Add(instr);
            pending.Add((instr, line));
        }
        if (pendingLabel != null)
            throw new ToolError($"Label '{pendingLabel}' is not followed by an instruction.");

        var allLocals = existingLocals.Concat(newLocals).ToList();
        foreach (var (instr, line) in pending)
            instr.Operand = ParseOperand(asm, method, module, importer, instr.OpCode, line, labels, originalForLabels, allLocals);

        return new Result(instructions, newLocals);
    }

    private static List<ParsedLine> Tokenize(string source)
    {
        var result = new List<ParsedLine>();
        var raw = source.Replace("\r\n", "\n").Split('\n');
        bool sawMethodHeader = raw.Any(l => l.TrimStart().StartsWith(".method", StringComparison.Ordinal));
        bool inBody = !sawMethodHeader;

        for (int i = 0; i < raw.Length; i++)
        {
            var text = raw[i];
            var token = TokenComment.Match(text) is { Success: true } m ? m.Groups[1].Value : null;
            text = StripComments(text).Trim();
            if (text.Length == 0) continue;

            if (!inBody)
            {
                if (text.StartsWith('{')) inBody = true;
                continue;
            }
            if (text.StartsWith(".try", StringComparison.Ordinal) || text.StartsWith("catch", StringComparison.Ordinal)
                || text.StartsWith("finally", StringComparison.Ordinal) || text.StartsWith("fault", StringComparison.Ordinal)
                || text.StartsWith("filter", StringComparison.Ordinal))
                throw new ToolError($"Line {i + 1}: exception-handling blocks are not supported in patches. Use mode=prepend to keep the original body (and its try/catch), or patch a method without handlers.");
            if (text is "{" or "}" || (text.StartsWith('.') && !text.StartsWith(".local ", StringComparison.OrdinalIgnoreCase)))
                continue; // .maxstack, .locals init (...), braces

            string? label = null;
            var lm = LabelPrefix.Match(text);
            if (lm.Success && !OpCodesByName.ContainsKey(lm.Groups[1].Value))
            {
                label = lm.Groups[1].Value;
                text = text[lm.Length..].Trim();
            }
            if (text.Length == 0)
            {
                result.Add(new ParsedLine(i + 1, label, "", "", null, raw[i]));
                continue;
            }
            int space = text.IndexOfAny([' ', '\t']);
            var opcode = space < 0 ? text : text[..space];
            var operand = space < 0 ? "" : text[(space + 1)..].Trim();
            result.Add(new ParsedLine(i + 1, label, opcode, operand, token, raw[i]));
        }
        return result;
    }

    /// <summary>Removes // and /* */ comments that are outside string literals.</summary>
    private static string StripComments(string line)
    {
        var sb = new StringBuilder();
        bool inString = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (inString)
            {
                sb.Append(c);
                if (c == '\\' && i + 1 < line.Length) sb.Append(line[++i]);
                else if (c == '"') inString = false;
                continue;
            }
            if (c == '"') { inString = true; sb.Append(c); continue; }
            if (c == '/' && i + 1 < line.Length && line[i + 1] == '/') break;
            if (c == '/' && i + 1 < line.Length && line[i + 1] == '*')
            {
                int end = line.IndexOf("*/", i + 2, StringComparison.Ordinal);
                i = end < 0 ? line.Length : end + 1;
                continue;
            }
            sb.Append(c);
        }
        return sb.ToString();
    }

    private object? ParseOperand(LoadedAssembly asm, MethodDef method, ModuleDef module, Importer importer, OpCode op, ParsedLine line,
        Dictionary<string, Instruction> labels, IList<Instruction>? original, List<Local> locals)
    {
        var text = line.Operand;
        var inv = CultureInfo.InvariantCulture;
        switch (op.OperandType)
        {
            case OperandType.InlineNone:
                if (text.Length > 0) throw Error(line, $"{op.Name} takes no operand");
                return null;
            case OperandType.ShortInlineI:
                return op.Code == Code.Ldc_I4_S ? (object)(sbyte)ParseLong(line, text) : (byte)ParseLong(line, text);
            case OperandType.InlineI:
                return unchecked((int)ParseLong(line, text));
            case OperandType.InlineI8:
                return ParseLong(line, text);
            case OperandType.ShortInlineR:
                return float.Parse(text.TrimEnd('f', 'F'), NumberStyles.Float, inv);
            case OperandType.InlineR:
                return double.Parse(text.TrimEnd('d', 'D'), NumberStyles.Float, inv);
            case OperandType.InlineString:
                if (text.Length < 2 || text[0] != '"' || text[^1] != '"') throw Error(line, "expected a \"quoted string\"");
                return Regex.Unescape(text[1..^1]);
            case OperandType.InlineBrTarget:
            case OperandType.ShortInlineBrTarget:
                return Label(line, text, labels, original);
            case OperandType.InlineSwitch:
                return text.Trim('(', ')').Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(l => Label(line, l, labels, original)).ToArray();
            case OperandType.InlineVar:
            case OperandType.ShortInlineVar:
                return IsArgOpcode(op.Code) ? Argument(line, method, text) : LocalVar(line, locals, text);
            case OperandType.InlineMethod:
                return ResolveMember(asm, module, importer, line, SymbolKind.Method) as IMethod ?? throw Error(line, "operand is not a method");
            case OperandType.InlineField:
                return ResolveMember(asm, module, importer, line, SymbolKind.Field) as IField ?? throw Error(line, "operand is not a field");
            case OperandType.InlineType:
                return ParseTypeSig(asm, module, importer, text, line).ToTypeDefOrRef();
            case OperandType.InlineTok:
                return ResolveMember(asm, module, importer, line, SymbolKind.Any) as ITokenOperand ?? throw Error(line, "operand is not a type, method or field");
            default:
                throw Error(line, $"operand type {op.OperandType} ({op.Name}) is not supported");
        }
    }

    private static bool IsArgOpcode(Code c) => c is Code.Ldarg or Code.Ldarg_S or Code.Ldarga or Code.Ldarga_S or Code.Starg or Code.Starg_S;

    private static Parameter Argument(ParsedLine line, MethodDef method, string text)
    {
        if (int.TryParse(text, out int index))
            return index >= 0 && index < method.Parameters.Count ? method.Parameters[index] : throw Error(line, $"argument {index} out of range (0..{method.Parameters.Count - 1}, 0 = this for instance methods)");
        return method.Parameters.FirstOrDefault(p => p.Name == text) ?? throw Error(line, $"no parameter named '{text}'");
    }

    private static Local LocalVar(ParsedLine line, List<Local> locals, string text)
    {
        var t = text.StartsWith("V_", StringComparison.Ordinal) ? text[2..] : text;
        if (int.TryParse(t, out int index))
            return index >= 0 && index < locals.Count ? locals[index] : throw Error(line, $"local {index} does not exist ({locals.Count} locals; declare more with '.local <type>')");
        return locals.FirstOrDefault(l => l.Name == text) ?? throw Error(line, $"no local named '{text}'");
    }

    private static Instruction Label(ParsedLine line, string name, Dictionary<string, Instruction> labels, IList<Instruction>? original)
    {
        if (labels.TryGetValue(name, out var target))
            return target;
        if (original != null && name.StartsWith("IL_", StringComparison.OrdinalIgnoreCase)
            && uint.TryParse(name[3..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint offset))
        {
            var existing = original.FirstOrDefault(i => i.Offset == offset);
            if (existing != null) return existing;
        }
        throw Error(line, $"undefined label '{name}'");
    }

    private static long ParseLong(ParsedLine line, string text)
    {
        var t = text.Trim();
        bool neg = t.StartsWith('-');
        if (neg) t = t[1..];
        if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            && ulong.TryParse(t[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
            return neg ? -unchecked((long)hex) : unchecked((long)hex);
        if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var d))
            return d;
        if (ulong.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var u))
            return unchecked((long)u);
        throw Error(line, $"'{text}' is not an integer");
    }

    private object ResolveMember(LoadedAssembly asm, ModuleDef module, Importer importer, ParsedLine line, SymbolKind kind)
    {
        // 1. Token comment copied from get_il output (refers to this module).
        if (line.Token != null && module.ResolveToken(uint.Parse(line.Token, NumberStyles.HexNumber, CultureInfo.InvariantCulture)) is { } byComment)
            return byComment;

        var text = line.Operand.Trim();
        // 2. Explicit token.
        if (SymbolResolver.TryParseToken(text, out uint token) || TryParseRefToken(text, out token))
            return module.ResolveToken(token) ?? throw Error(line, $"token {text} not found in {asm.Id}");

        // 3. ILSpy-style operand text without token: strip the leading return type / 'instance' for symbol lookup.
        var symbol = SimplifyIlMemberSyntax(text);

        // 4. A member reference this module already has (framework calls etc.).
        var existing = FindExistingReference(module, symbol);
        if (existing != null) return existing;

        // 5. Any loaded assembly; import it into this module.
        IReadOnlyList<ResolvedSymbol> hits;
        try { hits = SymbolResolver.Resolve(workspace, null, symbol, kind); }
        catch (ToolError ex)
        {
            // 6. Framework / referenced-but-not-loaded assemblies, through the module's own type references.
            return ResolveThroughTypeRefs(module, symbol, kind, line)
                   ?? throw Error(line, $"cannot resolve '{symbol}': {ex.Message} Load the assembly that defines it, or use a token.");
        }
        if (hits.Count > 1)
            throw Error(line, $"'{symbol}' is ambiguous: {string.Join("; ", hits.Take(5))}. Add a parameter list or use a token.");
        return hits[0].Member switch
        {
            MethodDef md => ReferenceEquals(md.Module, module) ? md : importer.Import(md),
            FieldDef fd => ReferenceEquals(fd.Module, module) ? fd : importer.Import(fd),
            TypeDef td => ReferenceEquals(td.Module, module) ? td : importer.Import(td),
            _ => throw Error(line, $"'{symbol}' is a {hits[0].Kind}; use its accessor method (get_X / set_X / add_X)."),
        };
    }

    /// <summary>
    /// Builds a MemberRef for "Ns.Type::Member(params)" where Ns.Type lives in a referenced (not loaded) assembly.
    /// The declaring type is the module's existing TypeRef (or a corlib TypeRef), so the patched assembly keeps
    /// referencing the same facade (e.g. System.Runtime / mscorlib) it already uses.
    /// </summary>
    private static object? ResolveThroughTypeRefs(ModuleDef module, string symbol, SymbolKind kind, ParsedLine line)
    {
        int sep = symbol.IndexOf("::", StringComparison.Ordinal);
        if (sep <= 0) return null;
        var typeName = symbol[..sep].Trim();
        var rest = symbol[(sep + 2)..].Trim();
        int paren = rest.IndexOf('(');
        var name = (paren >= 0 ? rest[..paren] : rest).Trim();
        string? parameters = paren >= 0 ? rest[(paren + 1)..rest.LastIndexOf(')')] : null;

        ITypeDefOrRef? typeRef = (module as ModuleDefMD)?.GetTypeRefs().FirstOrDefault(t => t.FullName == typeName);
        if (typeRef == null)
        {
            int dot = typeName.LastIndexOf('.');
            typeRef = module.CorLibTypes.GetTypeRef(dot > 0 ? typeName[..dot] : "", dot > 0 ? typeName[(dot + 1)..] : typeName);
        }
        TypeDef? def;
        try { def = typeRef.ResolveTypeDef(); }
        catch { def = null; }
        if (def == null) return null;

        var importer = new Importer(module, ImporterOptions.TryToUseDefs);
        if (kind != SymbolKind.Method && def.FindField(name) is { } field)
            return new MemberRefUser(module, field.Name, importer.Import(field.FieldSig), typeRef);
        if (kind == SymbolKind.Field) return null;

        var candidates = def.Methods.Where(m => m.Name == name).ToList();
        if (parameters != null)
        {
            var wanted = Normalize(parameters);
            candidates = candidates.Where(m =>
                Normalize(string.Join(",", m.MethodSig.Params.Select(Format.Type))) == wanted
                || Normalize(string.Join(",", m.MethodSig.Params.Select(IlTypeName))) == wanted
                || Normalize(string.Join(",", m.MethodSig.Params.Select(p => p.FullName))) == wanted).ToList();
        }
        if (candidates.Count == 0) return null;
        if (candidates.Count > 1)
            throw Error(line, $"'{symbol}' has {candidates.Count} overloads: {string.Join("; ", candidates.Select(c => Format.Method(c, false)))}. Add the parameter list");
        var method = candidates[0];
        if (method.HasGenericParameters)
            throw Error(line, $"generic method '{symbol}' needs an instantiation; copy its token from get_il of a method that already calls it");
        return new MemberRefUser(module, method.Name, importer.Import(method.MethodSig), typeRef);
    }

    private static bool TryParseRefToken(string s, out uint token)
    {
        token = 0;
        if (!s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) return false;
        if (!uint.TryParse(s[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out token)) return false;
        return (token >> 24) is 0x01 or 0x0A or 0x1B or 0x2B;
    }

    /// <summary>"instance void [asm]Ns.Type::M(int32)" -> "Ns.Type::M(int32)".</summary>
    private static string SimplifyIlMemberSyntax(string text)
    {
        var s = Regex.Replace(text, @"\[[^\]]+\]", "");           // [System.Runtime]
        s = Regex.Replace(s, @"\b(instance|class|valuetype)\s+", "");
        int sep = s.IndexOf("::", StringComparison.Ordinal);
        if (sep > 0)
        {
            int start = s.LastIndexOf(' ', sep);
            if (start >= 0) s = s[(start + 1)..];                  // drop return type
        }
        return s.Replace("'", "").Trim();
    }

    private static object? FindExistingReference(ModuleDef module, string symbol)
    {
        var wanted = Normalize(symbol);
        if (module is ModuleDefMD md)
        {
            foreach (var mr in md.GetMemberRefs())
                if (Normalize(Format.MemberLabel(mr)) == wanted || Normalize(mr.FullName) == wanted || NameAndParamsMatch(mr, wanted))
                    return mr;
            foreach (var tr in md.GetTypeRefs())
                if (Normalize(tr.FullName) == wanted)
                    return tr;
        }
        return null;
    }

    private static bool NameAndParamsMatch(MemberRef mr, string wanted)
    {
        // wanted like "system.string::concat(string,string)" vs IL-style "system.string::concat(string,string)" — compare without param list types aliases.
        if (!mr.IsMethodRef) return Normalize($"{mr.DeclaringType?.FullName}::{mr.Name}") == wanted;
        var ilParams = string.Join(",", mr.MethodSig.Params.Select(p => p.TypeName));
        return Normalize($"{mr.DeclaringType?.FullName}::{mr.Name}({ilParams})") == wanted
               || Normalize($"{mr.DeclaringType?.FullName}::{mr.Name}({string.Join(",", mr.MethodSig.Params.Select(IlTypeName))})") == wanted;
    }

    private static string IlTypeName(TypeSig s) => s.ElementType switch
    {
        ElementType.I4 => "int32",
        ElementType.I8 => "int64",
        ElementType.I2 => "int16",
        ElementType.I1 => "int8",
        ElementType.U4 => "uint32",
        ElementType.U8 => "uint64",
        ElementType.U2 => "uint16",
        ElementType.U1 => "uint8",
        ElementType.R4 => "float32",
        ElementType.R8 => "float64",
        ElementType.I => "native int",
        _ => Format.Type(s),
    };

    private static string Normalize(string s) => new string(s.Where(c => !char.IsWhiteSpace(c)).ToArray()).ToLowerInvariant();

    private TypeSig ParseTypeSig(LoadedAssembly asm, ModuleDef module, Importer importer, string text, ParsedLine line)
    {
        var t = Regex.Replace(text.Trim(), @"\[[^\]]+\]", "").Replace("class ", "").Replace("valuetype ", "").Trim();
        if (line.Token != null && module.ResolveToken(uint.Parse(line.Token, NumberStyles.HexNumber, CultureInfo.InvariantCulture)) is ITypeDefOrRef byComment)
            return byComment.ToTypeSig();
        bool array = t.EndsWith("[]", StringComparison.Ordinal);
        if (array) t = t[..^2];
        var c = module.CorLibTypes;
        TypeSig? sig = t switch
        {
            "bool" or "System.Boolean" => c.Boolean,
            "char" or "System.Char" => c.Char,
            "sbyte" or "int8" or "System.SByte" => c.SByte,
            "byte" or "uint8" or "System.Byte" => c.Byte,
            "short" or "int16" or "System.Int16" => c.Int16,
            "ushort" or "uint16" or "System.UInt16" => c.UInt16,
            "int" or "int32" or "System.Int32" => c.Int32,
            "uint" or "uint32" or "System.UInt32" => c.UInt32,
            "long" or "int64" or "System.Int64" => c.Int64,
            "ulong" or "uint64" or "System.UInt64" => c.UInt64,
            "float" or "float32" or "System.Single" => c.Single,
            "double" or "float64" or "System.Double" => c.Double,
            "string" or "System.String" => c.String,
            "object" or "System.Object" => c.Object,
            "nint" or "native int" or "System.IntPtr" => c.IntPtr,
            _ => null,
        };
        if (sig == null)
        {
            if (SymbolResolver.TryParseToken(t, out uint tok) || TryParseRefToken(t, out tok))
                sig = (module.ResolveToken(tok) as ITypeDefOrRef)?.ToTypeSig() ?? throw Error(line, $"token {t} is not a type");
            else if (FindExistingReference(module, t) is TypeRef tr)
                sig = tr.ToTypeSig();
            else
            {
                IReadOnlyList<ResolvedSymbol> hits;
                try { hits = SymbolResolver.Resolve(workspace, null, t, SymbolKind.Type); }
                catch (ToolError ex) { throw Error(line, $"cannot resolve type '{t}': {ex.Message}"); }
                if (hits.Count > 1) throw Error(line, $"type '{t}' is ambiguous; use a token.");
                var td = (TypeDef)hits[0].Member;
                sig = (ReferenceEquals(td.Module, module) ? td : (ITypeDefOrRef)importer.Import(td)).ToTypeSig();
            }
        }
        return array ? new SZArraySig(sig) : sig;
    }

    private static ToolError Error(ParsedLine line, string message) =>
        new($"Line {line.LineNumber}: {message}.\n  > {line.Raw.Trim()}");
}
