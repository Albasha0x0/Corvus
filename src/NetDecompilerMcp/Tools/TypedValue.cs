using System.Globalization;
using System.Numerics;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tools;

/// <summary>patch_bytes value + type: a number as an integer of a width and signedness, a float or a pointer; little-endian unless *be.</summary>
internal static class TypedValue
{
    public static readonly string[] Types = ["i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64", "ptr", "i16be", "u16be", "i32be", "u32be", "i64be", "u64be", "f32be", "f64be"];

    /// <summary>The pointer type, whose value may also be a name or an address to resolve.</summary>
    public static bool IsPointer(string? type) => string.Equals((type ?? "").Trim(), "ptr", StringComparison.OrdinalIgnoreCase);

    /// <summary>Decimal or 0x hex, optionally negative (what <see cref="Encode"/> reads as an integer).</summary>
    public static bool IsInteger(string value)
    {
        var v = value.Trim().Replace("_", "", StringComparison.Ordinal).TrimStart('-');
        return v.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? v.Length > 2 && v[2..].All(Uri.IsHexDigit) : v.Length > 0 && v.All(char.IsAsciiDigit);
    }

    /// <summary>The bytes of <paramref name="value"/> (decimal, 0x hex or negative; a float for f32/f64) as <paramref name="type"/>; out of range is refused.</summary>
    public static byte[] Encode(string type, string value, bool is64)
    {
        var t = (type ?? "").Trim().ToLowerInvariant();
        if (!Types.Contains(t)) throw new ToolError(ErrorCode.InvalidArgument, $"Unknown type '{type}'.", $"use {string.Join(", ", Types)}");
        bool bigEndian = t.EndsWith("be", StringComparison.Ordinal);
        var core = bigEndian ? t[..^2] : t;
        if (core == "ptr") core = is64 ? "u64" : "u32";
        var v = (value ?? "").Trim().Replace("_", "", StringComparison.Ordinal);
        byte[] bytes;
        if (core is "f32" or "f64")
        {
            if (!double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out var d))
                throw new ToolError(ErrorCode.InvalidArgument, $"'{value}' is not a number.", "e.g. 1.5 or -2e3");
            bytes = core == "f32" ? BitConverter.GetBytes((float)d) : BitConverter.GetBytes(d);
        }
        else
        {
            int bits = int.Parse(core[1..], CultureInfo.InvariantCulture);
            bool signed = core[0] == 'i';
            bool negative = v.StartsWith('-');
            var digits = negative ? v[1..] : v;
            BigInteger n = default;
            bool ok = digits.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                ? digits.Length > 2 && BigInteger.TryParse("0" + digits[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out n)
                : BigInteger.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out n);
            if (!ok) throw new ToolError(ErrorCode.InvalidArgument, $"'{value}' is not an integer.", "decimal, 0x hex, or negative");
            if (negative) n = -n;
            var min = signed ? -(BigInteger.One << (bits - 1)) : BigInteger.Zero;
            var max = (BigInteger.One << (signed ? bits - 1 : bits)) - 1;
            if (n < min || n > max) throw new ToolError(ErrorCode.InvalidArgument, $"{value} does not fit in {core} ({min}..{max}).");
            if (n < 0) n += BigInteger.One << bits;
            bytes = new byte[bits / 8];
            var raw = n.ToByteArray(isUnsigned: true, isBigEndian: false);
            Array.Copy(raw, bytes, Math.Min(raw.Length, bytes.Length));
        }
        if (bigEndian) Array.Reverse(bytes);
        return bytes;
    }
}
