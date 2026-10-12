// Written in the shape obfuscators leave (XOR-encoded strings, a flattened switch) for guide 2; the logic is small.
namespace Notes;

public static class LicenseCheck
{
    public static bool Check(string key)
    {
        int state = 0;
        while (true)
        {
            switch (state)
            {
                case 0:
                    state = key.Length == 14 ? 1 : 3;
                    break;
                case 1:
                    state = key.StartsWith(D("\u000f\u000d\u0017\u0001\u0016\u006b", 65), StringComparison.Ordinal) ? 2 : 3;
                    break;
                case 2:
                    if (key.Substring(6) == D("\u0024\u0052\u0026\u0057\u002e\u0029\u005a\u0028", 19)) return true;
                    state = 3;
                    break;
                default:
                    Console.Error.WriteLine(D("\u0046\u0042\u004f\u0048\u0040\u005c\u0055\u0011\u0059\u0056\u004d\u0015\u0044\u0052\u0052\u005c\u0059\u004f\u0059\u0059", 42));
                    return false;
            }
        }
    }

    internal static string D(string s, int k)
    {
        var c = s.ToCharArray();
        for (int i = 0; i < c.Length; i++) c[i] = (char)(c[i] ^ (k + i));
        return new string(c);
    }
}
