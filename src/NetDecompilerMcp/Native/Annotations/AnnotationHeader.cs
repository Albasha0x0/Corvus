using System.Text;

namespace NetDecompilerMcp.Native.Annotations;

/// <summary>
/// A C header of an image's user annotations: the declared types, prototypes of functions (by their current name), the
/// named functions without one as comments, and globals with a type as extern declarations. Addresses are RVAs.
/// </summary>
public static class AnnotationHeader
{
    private static readonly HashSet<string> NotNames = new(StringComparer.Ordinal)
    {
        "__cdecl", "__stdcall", "__fastcall", "__thiscall", "__vectorcall", "__usercall", "__userpurge", "__pascal", "__clrcall",
        "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "bool", "_Bool", "const", "volatile",
        "__int8", "__int16", "__int32", "__int64", "__int128", "wchar_t", "struct", "union", "enum",
    };

    /// <param name="nameAt">The name in effect at an RVA (user, export, PDB...), or null.</param>
    /// <param name="isFunction">Whether a function starts at an RVA.</param>
    public static string Render(NativeAnnotations ann, Func<uint, string?> nameAt, Func<uint, bool> isFunction)
    {
        var types = ann.UserTypes;
        var sb = new StringBuilder();
        sb.AppendLine("// C declarations and prototypes exported from NetDecompilerMcp; addresses are RVAs.");
        sb.AppendLine($"// Source: {ann.FilePath}  sha256 {ann.Sha256}");
        sb.AppendLine("#pragma once");
        if (types.Declarations.Count > 0)
        {
            sb.AppendLine().AppendLine("/* types */");
            foreach (var d in types.Declarations) sb.AppendLine(d.Trim().TrimEnd(';') + ";");
        }

        var functions = new List<string>();
        var globals = new List<string>();
        foreach (var (rva, type) in types.Types.OrderBy(t => t.Key))
        {
            var name = Identifier(nameAt(rva) ?? (isFunction(rva) ? $"sub_{rva:X}" : $"g_{rva:X}"));
            if (isFunction(rva) && Prototype(type, name) is { } proto) functions.Add($"{proto}; // rva 0x{rva:X}");
            else globals.Add($"extern {Declarator(type, name)}; // rva 0x{rva:X}");
        }
        foreach (var (rva, name) in ann.Names().Where(n => isFunction(n.Rva) && !types.Types.ContainsKey(n.Rva)).OrderBy(n => n.Rva))
            functions.Add($"// {name}: rva 0x{rva:X}, no prototype set");
        if (functions.Count > 0) sb.AppendLine().AppendLine("/* functions */").AppendJoin(Environment.NewLine, functions).AppendLine();
        if (globals.Count > 0) sb.AppendLine().AppendLine("/* globals */").AppendJoin(Environment.NewLine, globals).AppendLine();
        return sb.ToString();
    }

    /// <summary>A prototype with <paramref name="name"/> as its declarator: "int __fastcall(int a)" or "int f(int a)" becomes "int __fastcall name(int a)".</summary>
    internal static string? Prototype(string type, string name)
    {
        var t = type.Trim().TrimEnd(';').Trim();
        if (!t.EndsWith(')')) return null;
        int depth = 0, open = -1;
        for (int i = t.Length - 1; i >= 0; i--)
        {
            if (t[i] == ')') depth++;
            else if (t[i] == '(' && --depth == 0) { open = i; break; }
        }
        if (open <= 0) return null;
        var prefix = t[..open].TrimEnd();
        int start = prefix.Length;
        while (start > 0 && (char.IsLetterOrDigit(prefix[start - 1]) || prefix[start - 1] is '_' or ':' or '$' or '@' or '?')) start--;
        var last = prefix[start..];
        // a declarator already there is replaced; a lone return type, a convention or a pointer star keeps everything
        bool named = last.Length > 0 && start > 0 && !NotNames.Contains(last) && prefix[..start].Trim().Length > 0;
        return (named ? prefix[..start].TrimEnd() : prefix) + " " + name + t[open..];
    }

    /// <summary>A variable declarator, as the IDA scripts parse a type text: "(*)" names the pointer, "[" follows the name.</summary>
    internal static string Declarator(string type, string name)
    {
        var t = type.Trim().TrimEnd(';').Trim();
        if (t.Contains("(*)", StringComparison.Ordinal)) return t.Replace("(*)", $"(*{name})");
        int bracket = t.IndexOf('[');
        return bracket > 0 ? $"{t[..bracket].TrimEnd()} {name}{t[bracket..]}" : $"{t} {name}";
    }

    /// <summary>A C identifier: other characters (::, @, ?) become '_'.</summary>
    private static string Identifier(string name)
    {
        var chars = name.Select(c => char.IsLetterOrDigit(c) || c == '_' ? c : '_').ToArray();
        var s = new string(chars);
        return s.Length > 0 && char.IsDigit(s[0]) ? "_" + s : s;
    }
}
