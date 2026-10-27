namespace Corvus.Native.Dump;

/// <summary>Evaluates a PDB FRAMEDATA postfix program; operators + - * / % @ (align down), ^ (read 32 bits), = (assign).</summary>
public static class X86FrameProgram
{
    /// <summary>Most tokens evaluated in one program.</summary>
    public const int MaxTokens = 512;

    /// <summary>The variables after running <paramref name="program"/> (updated in place); null on a bad token, missing operand, zero divisor or failed read.</summary>
    public static Dictionary<string, uint>? Run(string program, Dictionary<string, uint> variables, Func<uint, uint?> read)
    {
        var stack = new Stack<string>();
        var tokens = program.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length > MaxTokens) return null;
        bool Value(out uint v)
        {
            v = 0;
            if (stack.Count == 0) return false;
            string t = stack.Pop();
            if (t[0] is '$' or '.') return variables.TryGetValue(t, out v);
            if (uint.TryParse(t, out v)) return true;
            if (!int.TryParse(t, out int signed)) return false;
            v = unchecked((uint)signed);
            return true;
        }
        foreach (var t in tokens)
        {
            switch (t)
            {
                case "+" or "-" or "*" or "/" or "%" or "@":
                    if (!Value(out uint b) || !Value(out uint a)) return null;
                    if (b == 0 && t is "/" or "%" or "@") return null;
                    uint r = t switch
                    {
                        "+" => unchecked(a + b),
                        "-" => unchecked(a - b),
                        "*" => unchecked(a * b),
                        "/" => a / b,
                        "%" => a % b,
                        _ => a & ~(b - 1),
                    };
                    stack.Push(r.ToString());
                    break;
                case "^":
                    if (!Value(out uint at) || read(at) is not { } got) return null;
                    stack.Push(got.ToString());
                    break;
                case "=":
                    if (!Value(out uint value) || stack.Count == 0) return null;
                    string name = stack.Pop();
                    if (name[0] != '$') return null;
                    variables[name] = value;
                    break;
                default:
                    stack.Push(t);
                    break;
            }
        }
        return stack.Count == 0 ? variables : null;
    }
}
