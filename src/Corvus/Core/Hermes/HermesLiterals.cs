using System.Buffers.Binary;
using System.Globalization;

namespace Corvus.Core.Hermes;

/// <summary>A literal of the array and object buffers: null, true, false, a number or a string id.</summary>
public readonly record struct HermesLiteral(HermesLiteralKind Kind, double Number, long StringId)
{
    /// <summary>The literal as JavaScript text; a key is written bare when it is an identifier.</summary>
    public string Text(HermesFile file, bool key = false) => Kind switch
    {
        HermesLiteralKind.Null => "null",
        HermesLiteralKind.True => "true",
        HermesLiteralKind.False => "false",
        HermesLiteralKind.Number => HermesCode.Number(Number),
        _ => file.String(StringId) is { } s ? key && HermesNames.IsIdentifier(s) ? s : HermesCode.Quote(s) : $"string#{StringId}",
    };
}

public enum HermesLiteralKind : byte { Null, True, False, Number, String }

/// <summary>The serialized literal format of the array, object key and object value buffers (tag byte, run length, values).</summary>
public static class HermesLiterals
{
    private const int MaxCount = 1 << 16;

    /// <summary><paramref name="count"/> literals from <paramref name="offset"/> in a buffer; stops early at a malformed entry.</summary>
    public static List<HermesLiteral> Read(HermesFile file, (int Start, int Length) buffer, long offset, long count)
    {
        var list = new List<HermesLiteral>((int)Math.Min(count, 256));
        var data = file.Bytes.Span;
        long at = buffer.Start + offset, end = (long)buffer.Start + buffer.Length;
        count = Math.Min(count, MaxCount);
        while (list.Count < count && at < end)
        {
            byte tag = data[(int)at];
            int run;
            if ((tag & 0x80) != 0)
            {
                if (at + 1 >= end) break;
                run = ((tag & 0x0F) << 8) | data[(int)at + 1];
                at += 2;
            }
            else { run = tag & 0x0F; at++; }
            if (run == 0) break;
            int kind = tag & 0x70;
            int size = kind switch { 0x30 => 8, 0x40 or 0x70 => 4, 0x50 => 2, 0x60 => 1, _ => 0 };
            for (int i = 0; i < run && list.Count < count; i++)
            {
                if (at + size > end) return list;
                var s = data[(int)at..];
                list.Add(kind switch
                {
                    0x00 => new(HermesLiteralKind.Null, 0, 0),
                    0x10 => new(HermesLiteralKind.True, 0, 0),
                    0x20 => new(HermesLiteralKind.False, 0, 0),
                    0x30 => new(HermesLiteralKind.Number, BinaryPrimitives.ReadDoubleLittleEndian(s), 0),
                    0x40 => new(HermesLiteralKind.String, 0, BinaryPrimitives.ReadUInt32LittleEndian(s)),
                    0x50 => new(HermesLiteralKind.String, 0, BinaryPrimitives.ReadUInt16LittleEndian(s)),
                    0x60 => new(HermesLiteralKind.String, 0, s[0]),
                    _ => new(HermesLiteralKind.Number, BinaryPrimitives.ReadInt32LittleEndian(s), 0),
                });
                at += size;
            }
        }
        return list;
    }

    /// <summary>An array literal: [a, b, c].</summary>
    public static string Array(HermesFile file, long offset, long count) =>
        "[" + string.Join(", ", Read(file, file.ArrayBuffer, offset, count).Select(l => l.Text(file))) + "]";

    /// <summary>An object literal: {k: v, ...}; a missing value reads as undefined.</summary>
    public static string Object(HermesFile file, long keyOffset, long valueOffset, long count)
    {
        var keys = Read(file, file.ObjectKeyBuffer, keyOffset, count);
        var values = Read(file, file.ObjectValueBuffer, valueOffset, count);
        return "{" + string.Join(", ", keys.Select((k, i) => k.Text(file, key: true) + ": " + (i < values.Count ? values[i].Text(file) : "undefined"))) + "}";
    }
}

/// <summary>JavaScript identifier checks for printing names bare or quoted.</summary>
public static class HermesNames
{
    private static readonly HashSet<string> Reserved = new(StringComparer.Ordinal)
    {
        "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do", "else", "export", "extends", "finally",
        "for", "function", "if", "import", "in", "instanceof", "new", "return", "super", "switch", "this", "throw", "try", "typeof", "var",
        "void", "while", "with", "yield", "let", "static", "enum", "await", "null", "true", "false",
    };

    public static bool IsIdentifier(string s)
    {
        if (s.Length == 0 || s.Length > 200) return false;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            bool ok = c == '_' || c == '$' || char.IsLetter(c) || (i > 0 && char.IsDigit(c));
            if (!ok) return false;
        }
        return true;
    }

    /// <summary>A property name usable after a dot (reserved words are allowed there).</summary>
    public static bool IsPropertyName(string s) => IsIdentifier(s);

    /// <summary>A name usable as a variable (not a reserved word).</summary>
    public static bool IsVariable(string s) => IsIdentifier(s) && !Reserved.Contains(s);

    public static string Index(long n) => n.ToString(CultureInfo.InvariantCulture);
}
