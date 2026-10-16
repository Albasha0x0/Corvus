using System.Globalization;
using System.Text;

namespace Corvus.Services.Web.Scripts;

// Values of the PowerShell evaluator: .NET primitives, object[] arrays, byte[] and the few objects decoders build.

internal sealed class PsUnknown
{
    public static readonly PsUnknown Value = new();
    private PsUnknown() { }
}

/// <summary>No output (an assignment, Out-Null, a void method).</summary>
internal sealed class PsVoid
{
    public static readonly PsVoid Value = new();
    private PsVoid() { }
}

internal sealed record PsTypeValue(string Name);

internal sealed record PsEncodingValue(Encoding Encoding, string Name);

/// <summary>A stream over bytes (MemoryStream, a decompressed DeflateStream / GZipStream); CopyTo fills another.</summary>
internal sealed class PsStreamValue(byte[] data)
{
    public byte[] Data { get; set; } = data;
    public int Position { get; set; }
}

internal sealed class PsReaderValue(string text)
{
    public string Text { get; } = text;
    public int Position { get; set; }
}

internal sealed record PsMatchValue(string Value, int Index);

internal sealed record PsCommandInfo(string Name);

internal sealed record PsVariableInfo(string Name, object? Value);

internal sealed record PsSecureString(string Plain);

internal sealed record PsOpaque(string Type)
{
    /// <summary>A PSCredential's password; GetNetworkCredential().Password reads it.</summary>
    public string? Secret { get; init; }
}

internal sealed record PsMethodGroup(object? Target, string Name);

internal sealed class PsHashValue
{
    public Dictionary<string, object?> Items { get; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>A script block: its statements and the layer whose text they index.</summary>
internal sealed class PsBlockValue(List<PsStatement> body, List<PsParam>? parameters, PsLayerText layer, string text)
{
    public List<PsStatement> Body { get; } = body;
    public List<PsParam>? Parameters { get; } = parameters;
    public PsLayerText Layer { get; } = layer;
    public string Text { get; } = text;
}

internal static class PsConvert
{
    public static bool Known(object? v) => v is not PsUnknown;

    public static string? Str(object? v) => Str(v, " ");

    /// <summary>The value as text; arrays joined by <paramref name="ofs"/> (the shell's $OFS).</summary>
    public static string? Str(object? v, string ofs) => v switch
    {
        null => "",
        string s => s,
        char c => c.ToString(),
        long l => l.ToString(CultureInfo.InvariantCulture),
        int i => i.ToString(CultureInfo.InvariantCulture),
        byte b => b.ToString(CultureInfo.InvariantCulture),
        double d => d.ToString(CultureInfo.InvariantCulture),
        bool b => b ? "True" : "False",
        object[] a => Join(a, ofs),
        PsHashValue => "System.Collections.Hashtable",
        byte[] b => string.Join(" ", b),
        PsTypeValue t => t.Name,
        PsMatchValue m => m.Value,
        PsCommandInfo c => c.Name,
        PsBlockValue b => b.Text,
        PsVariableInfo info => info.Name,
        PsEncodingValue e => "System.Text." + e.Name,
        PsSecureString => "System.Security.SecureString",
        PsOpaque o => o.Type,
        PsMethodGroup g => MethodText(g),
        _ => null,
    };

    /// <summary>A method group as text, as the shell writes its overloads (used to spell commands from its letters).</summary>
    private static string? MethodText(PsMethodGroup g) => (g.Target, g.Name.ToLowerInvariant()) switch
    {
        (string, "normalize") => "string Normalize(), string Normalize(System.Text.NormalizationForm normalizationForm)",
        (string, "isnormalized") => "bool IsNormalized(), bool IsNormalized(System.Text.NormalizationForm normalizationForm)",
        (string, "insert") => "string Insert(int startIndex, string value)",
        (string, "replace") => "string Replace(char oldChar, char newChar), string Replace(string oldValue, string newValue)",
        (string, "trim") => "string Trim(Params char[] trimChars), string Trim()",
        (string, "tochararray") => "char[] ToCharArray(), char[] ToCharArray(int startIndex, int length)",
        _ => null,
    };

    public static string? Join(object?[] items, string sep)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < items.Length; i++)
        {
            if (i > 0) sb.Append(sep);
            if (Str(items[i]) is not { } s) return null;
            sb.Append(s);
        }
        return sb.ToString();
    }

    public static long? Long(object? v)
    {
        switch (v)
        {
            case null: return 0;
            case long l: return l;
            case int i: return i;
            case byte b: return b;
            case char c: return c;
            case bool b: return b ? 1 : 0;
            case double d when !double.IsNaN(d) && Math.Abs(d) < 9e18: return (long)Math.Round(d, MidpointRounding.ToEven);
            case string s:
            {
                s = s.Trim();
                if (s.Length == 0) return 0;
                bool neg = s.StartsWith('-');
                var body = neg || s.StartsWith('+') ? s[1..] : s;
                if (body.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && long.TryParse(body[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var h))
                    return neg ? -h : h;
                if (long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n)) return n;
                if (double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var f) && Math.Abs(f) < 9e18) return (long)Math.Round(f, MidpointRounding.ToEven);
                return null;
            }
            default: return null;
        }
    }

    public static double? Double(object? v) => v switch
    {
        double d => d,
        string s when double.TryParse(s.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var f) => f,
        _ => Long(v) is { } l ? l : null,
    };

    public static bool? Bool(object? v) => v switch
    {
        null => false,
        bool b => b,
        string s => s.Length > 0,
        long l => l != 0,
        int i => i != 0,
        double d => d != 0,
        char c => c != 0,
        object[] a => a.Length switch { 0 => false, 1 => Bool(a[0]), _ => true },
        PsUnknown => null,
        _ => true,
    };

    /// <summary>The items a pipeline or foreach enumerates: arrays and bytes item by item, anything else as one.</summary>
    public static IEnumerable<object?> Items(object? v)
    {
        switch (v)
        {
            case object[] a: foreach (var x in a) yield return x; break;
            case byte[] b: foreach (var x in b) yield return (long)x; break;
            case PsVoid: break;
            default: yield return v; break;
        }
    }

    public static object?[]? Array(object? v) => v switch
    {
        object[] a => a,
        byte[] b => b.Select(x => (object?)(long)x).ToArray(),
        PsUnknown => null,
        _ => [v],
    };

    public static byte[]? Bytes(object? v)
    {
        if (v is byte[] b) return b;
        if (v is not object[] a) return null;
        var r = new byte[a.Length];
        for (int i = 0; i < a.Length; i++)
        {
            if (Long(a[i]) is not { } n || a[i] is string) return null;
            r[i] = (byte)n;
        }
        return r;
    }

    public static char? Char(object? v) => v switch
    {
        char c => c,
        string { Length: 1 } s => s[0],
        string s when Long(s) is { } n && n is >= 0 and <= 0xFFFF => (char)n,
        long l when l is >= 0 and <= 0xFFFF => (char)l,
        int i when i is >= 0 and <= 0xFFFF => (char)i,
        double d when d is >= 0 and <= 0xFFFF => (char)Math.Round(d, MidpointRounding.ToEven),
        byte b => (char)b,
        _ => null,
    };

    /// <summary>Normalized type name: lowercase, without "system." and the brackets of generic arrays.</summary>
    public static string TypeKey(string name)
    {
        var n = name.Trim().ToLowerInvariant();
        if (n.StartsWith("system.", StringComparison.Ordinal)) n = n[7..];
        return n switch
        {
            "int32" or "int" => "int",
            "int64" or "long" => "long",
            "int16" or "short" => "short",
            "uint32" or "uint" => "uint",
            "uint16" or "ushort" => "ushort",
            "uint64" or "ulong" => "ulong",
            "boolean" or "bool" => "bool",
            "single" or "float" => "double",
            "decimal" => "double",
            "byte[]" => "byte[]",
            "char[]" => "char[]",
            "int32[]" or "int[]" => "int[]",
            "string[]" => "string[]",
            "object[]" or "array" => "object[]",
            "management.automation.scriptblock" => "scriptblock",
            "text.encoding" => "text.encoding",
            "type" => "type",
            _ => n,
        };
    }
}
