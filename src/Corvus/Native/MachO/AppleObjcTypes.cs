namespace Corvus.Native.MachO;

/// <summary>Objective-C type encodings ("i", "@\"NSString\"", "^{CGPoint=dd}", "[4c]") spelled as C types.</summary>
public static class ObjcTypeEncoding
{
    /// <summary>The C spelling of one encoded type, or the encoding itself when it is not understood.</summary>
    public static string ToC(string? encoding)
    {
        if (string.IsNullOrEmpty(encoding)) return "?";
        int at = 0;
        return Parse(encoding, ref at, 0) is { } c && at == encoding.Length ? c : encoding;
    }

    private static string? Parse(string s, ref int at, int depth)
    {
        if (depth > 16 || at >= s.Length) return null;
        // qualifiers: const, in, inout, out, bycopy, byref, oneway, atomic
        while (at < s.Length && s[at] is 'r' or 'n' or 'N' or 'o' or 'O' or 'R' or 'V' or 'A') at++;
        if (at >= s.Length) return null;
        char c = s[at++];
        switch (c)
        {
            case 'c': return "char";
            case 'i': return "int";
            case 's': return "short";
            case 'l': return "int32_t";
            case 'q': return "long long";
            case 'C': return "unsigned char";
            case 'I': return "unsigned int";
            case 'S': return "unsigned short";
            case 'L': return "uint32_t";
            case 'Q': return "unsigned long long";
            case 'f': return "float";
            case 'd': return "double";
            case 'D': return "long double";
            case 'B': return "bool";
            case 'v': return "void";
            case '*': return "char *";
            case '#': return "Class";
            case ':': return "SEL";
            case '?': return "void /* unknown */";
            case '@':
                if (at < s.Length && s[at] == '?')
                {
                    at++;
                    return "id /* block */";
                }
                if (at < s.Length && s[at] == '"')
                {
                    int end = s.IndexOf('"', at + 1);
                    if (end < 0) return null;
                    var name = s[(at + 1)..end];
                    at = end + 1;
                    return name.StartsWith('<') ? "id" + name : name + " *";
                }
                return "id";
            case '^':
                return Parse(s, ref at, depth + 1) is { } pointee ? pointee + " *" : null;
            case '[':
            {
                int start = at;
                while (at < s.Length && char.IsAsciiDigit(s[at])) at++;
                var count = s[start..at];
                var element = Parse(s, ref at, depth + 1);
                if (element == null || at >= s.Length || s[at] != ']') return null;
                at++;
                return $"{element}[{count}]";
            }
            case '{' or '(':
            {
                char close = c == '{' ? '}' : ')';
                int level = 1, start = at;
                while (at < s.Length && level > 0)
                {
                    if (s[at] == c) level++;
                    else if (s[at] == close) level--;
                    at++;
                }
                if (level != 0) return null;
                var body = s[start..(at - 1)];
                int eq = body.IndexOf('=', StringComparison.Ordinal);
                var tag = eq >= 0 ? body[..eq] : body;
                return (c == '{' ? "struct " : "union ") + (tag is "" or "?" ? "anonymous" : tag);
            }
            case 'b':
            {
                int start = at;
                while (at < s.Length && char.IsAsciiDigit(s[at])) at++;
                return at > start ? $"unsigned int : {s[start..at]}" : null;
            }
            default: return null;
        }
    }
}
