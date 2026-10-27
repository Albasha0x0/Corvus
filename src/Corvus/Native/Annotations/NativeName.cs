using System.Text;
using Corvus.Core;

namespace Corvus.Native.Annotations;

/// <summary>Validates user-supplied native names and makes C identifiers from managed names.</summary>
public static class NativeName
{
    public const int MaxLength = 255;
    private const int MaxIdentifierLength = 200;

    /// <summary>The trimmed name when it is an identifier (also '$', '@') of at most <see cref="MaxLength"/> characters; throws otherwise.</summary>
    public static string Validate(string name)
    {
        var n = (name ?? "").Trim();
        if (n.Length == 0)
            throw new ToolError(ErrorCode.InvalidArgument, "The name is empty.", "pass an identifier such as DecryptBlock");
        if (n.Length > MaxLength)
            throw new ToolError(ErrorCode.InvalidArgument, $"The name is {n.Length} characters; at most {MaxLength} are allowed.");
        if (!(char.IsLetter(n[0]) || n[0] is '_'))
            throw new ToolError(ErrorCode.InvalidArgument, $"'{n}' is not a valid name: it must start with a letter or underscore.");
        foreach (var c in n)
            if (!(char.IsLetterOrDigit(c) || c is '_' or '$' or '@'))
                throw new ToolError(ErrorCode.InvalidArgument, $"'{n}' is not a valid name: '{c}' is not allowed (use letters, digits, '_', '$' or '@').");
        return n;
    }

    /// <summary>The C identifier for a managed method name: "Ns.Type$$Method" -> "Ns_Type__Method".</summary>
    public static string Identifier(string text)
    {
        var sb = new StringBuilder(Math.Min(text.Length, MaxIdentifierLength) + 4);
        bool replaced = false;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (sb.Length >= MaxIdentifierLength) break;
            if (c == '$' && i + 1 < text.Length && text[i + 1] == '$')
            {
                // "List<int>$$Add" -> "List_int__Add".
                if (replaced) sb.Length--;
                sb.Append("__");
                replaced = false;
                i++;
            }
            else if (c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '_')
            {
                sb.Append(c);
                replaced = false;
            }
            else if (c > 0x7F && char.IsLetterOrDigit(c))
            {
                sb.Append($"u{(int)c:X4}");
                replaced = false;
            }
            else if (!replaced)
            {
                sb.Append('_');
                replaced = true;
            }
        }
        // Drop a trailing replacement: "List<int>" -> "List_int".
        if (replaced && sb.Length > 1) sb.Length--;
        if (sb.Length == 0 || char.IsDigit(sb[0])) sb.Insert(0, '_');
        return sb.ToString();
    }
}
