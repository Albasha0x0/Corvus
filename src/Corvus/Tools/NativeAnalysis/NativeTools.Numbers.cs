using System.Buffers.Binary;
using System.ComponentModel;
using System.Globalization;
using System.Numerics;
using System.Text;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tools;

public sealed partial class NativeTools
{
    public sealed record ConvertedNumber(
        [property: Description("The text as given.")] string Input,
        [property: Description("Width in bytes the value was taken at; 0 on error.")] int Size,
        string? Unsigned,
        string? Signed,
        string? Hex,
        string? Binary,
        string? Octal,
        [property: Description("Bytes in memory order on a little-endian machine.")] string? BytesLe,
        string? BytesBe,
        [property: Description("The little-endian bytes as text when all are printable (trailing zeros dropped).")] string? AsciiLe,
        string? AsciiBe,
        [property: Description("The bits as an IEEE float (size 4) or double (size 8).")] string? Float,
        string? Error);

    public sealed record NumberConversions(IReadOnlyList<ConvertedNumber> Items);

    [McpServerTool(Name = "convert_number", Title = "Convert a number", UseStructuredContent = true, OutputSchemaType = typeof(NumberConversions))]
    [Description("Exact number conversions: signed and unsigned decimal, hex, binary, octal at a width, LE and BE bytes and their ASCII, the bits as " +
                 "float or double. Input: decimal, 0x or h-suffixed hex, 0b, 0o, negative, _ separators, C suffixes, 'ABCD' (C multi-character " +
                 "constant) or \"text\" (bytes in memory order).")]
    public Task<string> ConvertNumber(
        [Description("Numbers to convert.")] string[] numbers,
        [Description("Width in bytes: 1, 2, 4 or 8 (default: smallest that fits).")] int? size = null) => Task.Run(() =>
    {
        if (numbers is not { Length: > 0 }) throw new ToolError(ErrorCode.InvalidArgument, "No numbers given.", "numbers=[\"0x41424344\", \"-1\"]");
        if (numbers.Length > 256) throw new ToolError(ErrorCode.InvalidArgument, $"{numbers.Length} numbers; at most 256 per call.", "split the list");
        if (size is not (null or 1 or 2 or 4 or 8)) throw new ToolError(ErrorCode.InvalidArgument, $"size {size} is not 1, 2, 4 or 8.", "pass 1, 2, 4 or 8");
        var items = numbers.Select(n => Convert(n ?? "", size)).ToList();
        var sb = new StringBuilder();
        foreach (var i in items)
        {
            if (i.Error != null) { sb.AppendLine($"{i.Input}: error: {i.Error}"); continue; }
            sb.AppendLine($"{i.Input} ({i.Size} byte{(i.Size == 1 ? "" : "s")})");
            sb.AppendLine($"  unsigned  {i.Unsigned}").AppendLine($"  signed    {i.Signed}").AppendLine($"  hex       {i.Hex}")
              .AppendLine($"  binary    {i.Binary}").AppendLine($"  octal     {i.Octal}")
              .AppendLine($"  bytes LE  {i.BytesLe}").AppendLine($"  bytes BE  {i.BytesBe}");
            if (i.AsciiLe != null || i.AsciiBe != null) sb.AppendLine($"  ascii     LE {i.AsciiLe ?? "-"}, BE {i.AsciiBe ?? "-"}");
            if (i.Float != null) sb.AppendLine($"  {(i.Size == 4 ? "float " : "double")}    {i.Float}");
        }
        return ToolOutput.With(sb.ToString(), new NumberConversions(items));
    });

    /// <summary>One conversion; a bad input or a value outside the width is the item's error.</summary>
    internal static ConvertedNumber Convert(string input, int? size)
    {
        ConvertedNumber Error(string message) => new(input, 0, null, null, null, null, null, null, null, null, null, null, message);
        if (ParseNumber(input) is not { } value) return Error("not a number (decimal, 0x hex, h-suffixed hex, 0b, 0o, 'chars' or \"text\")");
        int width = size ?? new[] { 1, 2, 4, 8 }.FirstOrDefault(w => Fits(value, w));
        if (width == 0 || !Fits(value, width))
            return Error(size is { } s ? $"{value} does not fit in {s} byte(s) (signed or unsigned)" : $"{value} does not fit in 8 bytes");
        int bits = width * 8;
        var modulus = BigInteger.One << bits;
        var unsigned = value.Sign < 0 ? value + modulus : value;
        var signed = unsigned >= modulus >> 1 ? unsigned - modulus : unsigned;
        ulong raw = (ulong)unsigned;
        var le = new byte[width];
        for (int i = 0; i < width; i++) le[i] = (byte)(raw >> (8 * i));
        var be = le.Reverse().ToArray();
        string? floatText = width switch
        {
            4 => BinaryPrimitives.ReadSingleLittleEndian(le).ToString("R", CultureInfo.InvariantCulture),
            8 => BinaryPrimitives.ReadDoubleLittleEndian(le).ToString("R", CultureInfo.InvariantCulture),
            _ => null,
        };
        var binary = string.Join(' ', Enumerable.Range(0, bits / 4).Select(n => System.Convert.ToString((int)((raw >> (bits - 4 - n * 4)) & 0xF), 2).PadLeft(4, '0')));
        return new ConvertedNumber(input, width, unsigned.ToString(CultureInfo.InvariantCulture), signed.ToString(CultureInfo.InvariantCulture),
            "0x" + raw.ToString("X" + width * 2, CultureInfo.InvariantCulture), binary, "0o" + System.Convert.ToString((long)raw, 8),
            string.Join(' ', le.Select(b => b.ToString("X2", CultureInfo.InvariantCulture))), string.Join(' ', be.Select(b => b.ToString("X2", CultureInfo.InvariantCulture))),
            Printable(le), Printable(be), floatText, null);
    }

    private static bool Fits(BigInteger v, int width) => v >= -(BigInteger.One << (width * 8 - 1)) && v < BigInteger.One << (width * 8);

    /// <summary>The bytes as quoted text when every byte before trailing zeros is printable ASCII and there is at least one.</summary>
    private static string? Printable(byte[] bytes)
    {
        int n = bytes.Length;
        while (n > 0 && bytes[n - 1] == 0) n--;
        return n > 0 && bytes.Take(n).All(b => b is >= 0x20 and < 0x7F) ? "\"" + Encoding.ASCII.GetString(bytes, 0, n) + "\"" : null;
    }

    /// <summary>A number in the convert_number input forms, or null.</summary>
    internal static BigInteger? ParseNumber(string text)
    {
        var t = text.Trim();
        if (t.Length >= 2 && t[0] == '\'' && t[^1] == '\'')
        {
            var chars = t[1..^1];
            if (chars.Length is 0 or > 8 || chars.Any(c => c > 0xFF)) return null;
            return chars.Aggregate(BigInteger.Zero, (v, c) => v << 8 | c); // the first character is the most significant, as C compilers take it
        }
        if (t.Length >= 2 && t[0] == '"' && t[^1] == '"')
        {
            var chars = t[1..^1];
            if (chars.Length is 0 or > 8 || chars.Any(c => c > 0xFF)) return null;
            return chars.Reverse().Aggregate(BigInteger.Zero, (v, c) => v << 8 | c); // memory order: the first character is the lowest byte
        }
        t = t.Replace("_", "", StringComparison.Ordinal).Replace("'", "", StringComparison.Ordinal);
        bool negative = t.StartsWith('-');
        if (negative || t.StartsWith('+')) t = t[1..];
        int radix = 10;
        if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) (radix, t) = (16, t[2..]);
        else if (t.StartsWith("0b", StringComparison.OrdinalIgnoreCase)) (radix, t) = (2, t[2..]);
        else if (t.StartsWith("0o", StringComparison.OrdinalIgnoreCase)) (radix, t) = (8, t[2..]);
        else if (t.Length > 1 && t[^1] is 'h' or 'H' && t[0] is >= '0' and <= '9') (radix, t) = (16, t[..^1]);
        if (radix != 16) t = t.TrimEnd('u', 'U', 'l', 'L');
        else if (t.EndsWith("ul", StringComparison.OrdinalIgnoreCase) || t.EndsWith("ll", StringComparison.OrdinalIgnoreCase)) t = t[..^2];
        else if (t.Length > 0 && t[^1] is 'u' or 'U' or 'l' or 'L') t = t[..^1];
        if (t.Length is 0 or > 64) return null;
        BigInteger value = BigInteger.Zero;
        foreach (var c in t)
        {
            int d = c is >= '0' and <= '9' ? c - '0' : c is >= 'a' and <= 'f' ? c - 'a' + 10 : c is >= 'A' and <= 'F' ? c - 'A' + 10 : 99;
            if (d >= radix) return null;
            value = value * radix + d;
        }
        return negative ? -value : value;
    }
}
