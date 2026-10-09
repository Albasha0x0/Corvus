using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native.Annotations;

/// <summary>Validation of user-supplied function names (rename_native).</summary>
public static class NativeName
{
    public const int MaxLength = 255;

    /// <summary>
    /// Returns the trimmed name when it is a C-identifier-ish symbol (letter/underscore start, then letters, digits,
    /// underscore, '$', '@'), at most <see cref="MaxLength"/> characters; throws <see cref="ToolError"/> otherwise.
    /// </summary>
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
}
