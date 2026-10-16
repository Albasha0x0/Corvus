// Written in the shape transformed code takes (XOR-encoded strings, a flattened switch) for guide 2; the logic is small.
namespace Notes;

internal static class Strings
{
    internal static string D(string s, int k)
    {
        var c = s.ToCharArray();
        for (int i = 0; i < c.Length; i++) c[i] = (char)(c[i] ^ (k + i));
        return new string(c);
    }
}

public static class PreviewGate
{
    public static bool Verify(string code)
    {
        int state = 0;
        while (true)
        {
            switch (state)
            {
                case 0:
                    state = code.Length == 14 ? 1 : 3;
                    break;
                case 1:
                    state = code.StartsWith(Strings.D("\u0004\u0003\u0011\u0008\u001c\u006b", 65), StringComparison.Ordinal) ? 2 : 3;
                    break;
                case 2:
                    if (code.Substring(6) == Strings.D("\u0024\u0052\u0026\u0057\u002e\u0029\u005a\u0028", 19)) return true;
                    state = 3;
                    break;
                default:
                    Console.Error.WriteLine(Strings.D("\u0043\u0045\u005a\u004c\u0042\u0046\u0054\u0011\u0042\u0041\u0051\u0043\u005f\u0052\u004f\u0019\u0059\u0054\u0058\u0058", 42));
                    return false;
            }
        }
    }
}
