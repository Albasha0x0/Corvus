using System.Globalization;
using System.Text;

namespace Corvus.Core.Mobile;

public sealed partial class DalvikEvaluator
{
    /// <summary>A java.nio.charset.Charset by its canonical name.</summary>
    private sealed record Charset(string Name);

    /// <summary>A java.util.Base64 encoder or decoder.</summary>
    private sealed record Base64Coder(bool Encoder, bool Url, bool Mime, bool Padding = true);

    private const string JavaString = "Ljava/lang/String;";

    /// <summary>A framework static field: the standard charsets; anything else is outside the subset.</summary>
    private static object? FrameworkStatic(string field) => field switch
    {
        "Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;" => new Charset("UTF-8"),
        "Ljava/nio/charset/StandardCharsets;->ISO_8859_1:Ljava/nio/charset/Charset;" => new Charset("ISO-8859-1"),
        "Ljava/nio/charset/StandardCharsets;->US_ASCII:Ljava/nio/charset/Charset;" => new Charset("US-ASCII"),
        "Ljava/nio/charset/StandardCharsets;->UTF_16:Ljava/nio/charset/Charset;" => new Charset("UTF-16"),
        "Ljava/nio/charset/StandardCharsets;->UTF_16BE:Ljava/nio/charset/Charset;" => new Charset("UTF-16BE"),
        "Ljava/nio/charset/StandardCharsets;->UTF_16LE:Ljava/nio/charset/Charset;" => new Charset("UTF-16LE"),
        _ => throw Unsupported("unsupported-call", "reads " + field),
    };

    private static string Str(object? v) => v switch
    {
        string s => s,
        null => throw Runtime("a string operation on null (NullPointerException)"),
        _ => throw Unsupported("invalid-code", Describe(v) + " used as a string"),
    };

    private static int Int(object? v) => v switch { int i => i, null => 0, _ => throw Unsupported("invalid-code", Describe(v) + " used as an int") };

    private static long Long(object? v) => v switch { long l => l, int i => i, null => 0, _ => throw Unsupported("invalid-code", Describe(v) + " used as a long") };

    /// <summary>String.valueOf(Object) and StringBuilder.append(Object) for the objects the interpreter models.</summary>
    private static string Text(object? v) => v switch
    {
        null => "null",
        string s => s,
        StringBuilder sb => sb.ToString(),
        Charset c => c.Name,
        _ => throw Unsupported("unsupported-call", "toString of " + Describe(v)),
    };

    private string Made(string s)
    {
        Allocate(s.Length);
        return s;
    }

    private DalvikArray Chars(string s)
    {
        var a = NewArray("[C", s.Length);
        for (int k = 0; k < s.Length; k++) a.Primitives![k] = s[k];
        return a;
    }

    private DalvikArray ByteArray(byte[] bytes)
    {
        var a = NewArray("[B", bytes.Length);
        for (int k = 0; k < bytes.Length; k++) a.Primitives![k] = (sbyte)bytes[k];
        return a;
    }

    private static byte[] Bytes(DalvikArray a, int offset, int count)
    {
        if (a.Type != "[B") throw Unsupported("invalid-code", $"{a.Type} passed as [B");
        Range(a.Length, offset, count);
        var bytes = new byte[count];
        for (int k = 0; k < count; k++) bytes[k] = (byte)a.Primitives![offset + k];
        return bytes;
    }

    private static string CharsText(DalvikArray a, int offset, int count)
    {
        if (a.Type != "[C") throw Unsupported("invalid-code", $"{a.Type} passed as [C");
        Range(a.Length, offset, count);
        var chars = new char[count];
        for (int k = 0; k < count; k++) chars[k] = (char)a.Primitives![offset + k];
        return new string(chars);
    }

    private static void Range(int length, int offset, int count)
    {
        if (offset < 0 || count < 0 || offset > length - count) throw Runtime($"offset {offset}, count {count} of {length} (IndexOutOfBoundsException)");
    }

    private object? Construct(Uninitialized pending, DexMethodRef m, List<object?> a)
    {
        if (m.Class != pending.Type) throw Unsupported("unsupported-call", $"{m.Descriptor} on a new {pending.Type}");
        var p = string.Concat(m.Proto.Parameters);
        if (pending.Type == "Ljava/lang/Object;") return p == "" ? new PlainObject() : throw Unsupported("unsupported-call", m.Descriptor);
        if (pending.Type == JavaString)
            return p switch
            {
                "" => "",
                "[C" => Made(CharsText(Array(a[0]), 0, Array(a[0]).Length)),
                "[CII" => Made(CharsText(Array(a[0]), Int(a[1]), Int(a[2]))),
                "[B" => Made(Decode(Bytes(Array(a[0]), 0, Array(a[0]).Length), "UTF-8")),
                "[BII" => Made(Decode(Bytes(Array(a[0]), Int(a[1]), Int(a[2])), "UTF-8")),
                "[BLjava/lang/String;" => Made(Decode(Bytes(Array(a[0]), 0, Array(a[0]).Length), CharsetName(Str(a[1])))),
                "[BIILjava/lang/String;" => Made(Decode(Bytes(Array(a[0]), Int(a[1]), Int(a[2])), CharsetName(Str(a[3])))),
                "[BLjava/nio/charset/Charset;" => Made(Decode(Bytes(Array(a[0]), 0, Array(a[0]).Length), CharsetOf(a[1]))),
                "[BIILjava/nio/charset/Charset;" => Made(Decode(Bytes(Array(a[0]), Int(a[1]), Int(a[2])), CharsetOf(a[3]))),
                "Ljava/lang/String;" => Str(a[0]),
                "Ljava/lang/StringBuilder;" or "Ljava/lang/StringBuffer;" => Made(Builder(a[0]).ToString()),
                _ => throw Unsupported("unsupported-call", m.Descriptor),
            };
        return p switch
        {
            "" => new StringBuilder(),
            "I" => Int(a[0]) < 0 ? throw Runtime("a negative capacity (NegativeArraySizeException)") : new StringBuilder(),
            "Ljava/lang/String;" => new StringBuilder(Made(Str(a[0]))),
            "Ljava/lang/CharSequence;" => new StringBuilder(Made(Text(a[0] ?? throw Runtime("a null CharSequence (NullPointerException)")))),
            _ => throw Unsupported("unsupported-call", m.Descriptor),
        };
    }

    private static StringBuilder Builder(object? v) => v switch
    {
        StringBuilder sb => sb,
        null => throw Runtime("a StringBuilder operation on null (NullPointerException)"),
        _ => throw Unsupported("invalid-code", Describe(v) + " used as a StringBuilder"),
    };

    private object? Intrinsic(DexMethodRef m, bool isStatic, object? receiver, object?[] a)
    {
        var signature = m.Name + "(" + string.Concat(m.Proto.Parameters) + ")";
        if (!isStatic)
            return receiver switch
            {
                null => throw Runtime($"{m.Descriptor} on null (NullPointerException)"),
                string s => StringMethod(s, signature, a, m),
                StringBuilder sb => BuilderMethod(sb, signature, a, m),
                DalvikArray arr when signature == "clone()" => Cloned(arr),
                Charset c when signature is "name()" or "displayName()" or "toString()" => c.Name,
                Base64Coder c => CoderMethod(c, signature, a, m),
                _ => throw Unsupported("unsupported-call", $"{m.Descriptor} on {Describe(receiver)}"),
            };
        return (m.Class + "->" + signature) switch
        {
            "Ljava/lang/String;->valueOf([C)" or "Ljava/lang/String;->copyValueOf([C)" => Made(CharsText(Array(a[0]), 0, Array(a[0]).Length)),
            "Ljava/lang/String;->valueOf([CII)" or "Ljava/lang/String;->copyValueOf([CII)" => Made(CharsText(Array(a[0]), Int(a[1]), Int(a[2]))),
            "Ljava/lang/String;->valueOf(C)" => ((char)Int(a[0])).ToString(),
            "Ljava/lang/String;->valueOf(I)" or "Ljava/lang/Integer;->toString(I)" => Int(a[0]).ToString(CultureInfo.InvariantCulture),
            "Ljava/lang/String;->valueOf(J)" or "Ljava/lang/Long;->toString(J)" => Long(a[0]).ToString(CultureInfo.InvariantCulture),
            "Ljava/lang/String;->valueOf(Z)" => Int(a[0]) != 0 ? "true" : "false",
            "Ljava/lang/String;->valueOf(Ljava/lang/Object;)" => Text(a[0]),
            "Ljava/lang/Character;->toString(C)" => ((char)Int(a[0])).ToString(),
            "Ljava/lang/Character;->toUpperCase(C)" => (int)char.ToUpperInvariant((char)Int(a[0])),
            "Ljava/lang/Character;->toLowerCase(C)" => (int)char.ToLowerInvariant((char)Int(a[0])),
            "Ljava/lang/Character;->isDigit(C)" => char.IsDigit((char)Int(a[0])) ? 1 : 0,
            "Ljava/lang/Character;->isLetter(C)" => char.IsLetter((char)Int(a[0])) ? 1 : 0,
            "Ljava/lang/Character;->isLetterOrDigit(C)" => char.IsLetterOrDigit((char)Int(a[0])) ? 1 : 0,
            "Ljava/lang/Character;->isUpperCase(C)" => char.IsUpper((char)Int(a[0])) ? 1 : 0,
            "Ljava/lang/Character;->isLowerCase(C)" => char.IsLower((char)Int(a[0])) ? 1 : 0,
            "Ljava/lang/Character;->digit(CI)" => Digit((char)Int(a[0]), Int(a[1])),
            "Ljava/lang/Character;->forDigit(II)" => Int(a[1]) is >= 2 and <= 36 && (uint)Int(a[0]) < (uint)Int(a[1]) ? (int)"0123456789abcdefghijklmnopqrstuvwxyz"[Int(a[0])] : 0,
            "Ljava/lang/Integer;->parseInt(Ljava/lang/String;)" => (int)Parse(Str(a[0]), 10, int.MinValue, int.MaxValue),
            "Ljava/lang/Integer;->parseInt(Ljava/lang/String;I)" => (int)Parse(Str(a[0]), Int(a[1]), int.MinValue, int.MaxValue),
            "Ljava/lang/Long;->parseLong(Ljava/lang/String;)" => Parse(Str(a[0]), 10, long.MinValue, long.MaxValue),
            "Ljava/lang/Long;->parseLong(Ljava/lang/String;I)" => Parse(Str(a[0]), Int(a[1]), long.MinValue, long.MaxValue),
            "Ljava/lang/Integer;->toString(II)" => Radix(Int(a[0]), Int(a[1])),
            "Ljava/lang/Long;->toString(JI)" => Radix(Long(a[0]), Int(a[1])),
            "Ljava/lang/Integer;->toHexString(I)" => ((uint)Int(a[0])).ToString("x", CultureInfo.InvariantCulture),
            "Ljava/lang/Long;->toHexString(J)" => ((ulong)Long(a[0])).ToString("x", CultureInfo.InvariantCulture),
            "Ljava/lang/Integer;->toOctalString(I)" => Convert.ToString(Int(a[0]), 8),
            "Ljava/lang/Long;->toOctalString(J)" => Convert.ToString(Long(a[0]), 8),
            "Ljava/lang/Integer;->toBinaryString(I)" => Convert.ToString(Int(a[0]), 2),
            "Ljava/lang/Long;->toBinaryString(J)" => Convert.ToString(Long(a[0]), 2),
            "Ljava/lang/Integer;->rotateLeft(II)" => (int)uint.RotateLeft((uint)Int(a[0]), Int(a[1]) & 31),
            "Ljava/lang/Integer;->rotateRight(II)" => (int)uint.RotateRight((uint)Int(a[0]), Int(a[1]) & 31),
            "Ljava/lang/Long;->rotateLeft(JI)" => (long)ulong.RotateLeft((ulong)Long(a[0]), Int(a[1]) & 63),
            "Ljava/lang/Long;->rotateRight(JI)" => (long)ulong.RotateRight((ulong)Long(a[0]), Int(a[1]) & 63),
            "Ljava/lang/Integer;->reverse(I)" => (int)ReverseBits((uint)Int(a[0])),
            "Ljava/lang/Integer;->reverseBytes(I)" => System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(Int(a[0])),
            "Ljava/lang/Long;->reverseBytes(J)" => System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(Long(a[0])),
            "Ljava/lang/Integer;->bitCount(I)" => System.Numerics.BitOperations.PopCount((uint)Int(a[0])),
            "Ljava/lang/Long;->bitCount(J)" => System.Numerics.BitOperations.PopCount((ulong)Long(a[0])),
            "Ljava/lang/Math;->abs(I)" => unchecked(Int(a[0]) < 0 ? -Int(a[0]) : Int(a[0])),
            "Ljava/lang/Math;->abs(J)" => unchecked(Long(a[0]) < 0 ? -Long(a[0]) : Long(a[0])),
            "Ljava/lang/Math;->min(II)" => Math.Min(Int(a[0]), Int(a[1])),
            "Ljava/lang/Math;->max(II)" => Math.Max(Int(a[0]), Int(a[1])),
            "Ljava/lang/Math;->min(JJ)" => Math.Min(Long(a[0]), Long(a[1])),
            "Ljava/lang/Math;->max(JJ)" => Math.Max(Long(a[0]), Long(a[1])),
            "Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)" => ArrayCopy(a),
            "Ljava/nio/charset/Charset;->forName(Ljava/lang/String;)" => new Charset(CharsetName(Str(a[0]))),
            "Ljava/nio/charset/Charset;->defaultCharset()" => new Charset("UTF-8"),
            "Landroid/util/Base64;->decode(Ljava/lang/String;I)" => ByteArray(Base64Decode(Str(a[0]), Int(a[1]), strict: false)),
            "Landroid/util/Base64;->decode([BI)" => ByteArray(Base64Decode(Encoding.Latin1.GetString(Bytes(Array(a[0]), 0, Array(a[0]).Length)), Int(a[1]), strict: false)),
            "Landroid/util/Base64;->decode([BIII)" => ByteArray(Base64Decode(Encoding.Latin1.GetString(Bytes(Array(a[0]), Int(a[1]), Int(a[2]))), Int(a[3]), strict: false)),
            "Landroid/util/Base64;->encodeToString([BI)" => Made(Base64Encode(Bytes(Array(a[0]), 0, Array(a[0]).Length), Int(a[1]))),
            "Landroid/util/Base64;->encodeToString([BIII)" => Made(Base64Encode(Bytes(Array(a[0]), Int(a[1]), Int(a[2])), Int(a[3]))),
            "Landroid/util/Base64;->encode([BI)" => ByteArray(Encoding.ASCII.GetBytes(Base64Encode(Bytes(Array(a[0]), 0, Array(a[0]).Length), Int(a[1])))),
            "Ljava/util/Base64;->getDecoder()" => new Base64Coder(false, false, false),
            "Ljava/util/Base64;->getUrlDecoder()" => new Base64Coder(false, true, false),
            "Ljava/util/Base64;->getMimeDecoder()" => new Base64Coder(false, false, true),
            "Ljava/util/Base64;->getEncoder()" => new Base64Coder(true, false, false),
            "Ljava/util/Base64;->getUrlEncoder()" => new Base64Coder(true, true, false),
            "Ljava/util/Base64;->getMimeEncoder()" => new Base64Coder(true, false, true),
            _ when m.Class == "Ljava/util/Arrays;" && m.Name is "copyOf" or "copyOfRange" => CopyOf(m, a),
            _ => throw Unsupported("unsupported-call", m.Descriptor),
        };
    }

    private DalvikArray Cloned(DalvikArray a)
    {
        Allocate(a.Length);
        return a.Copy();
    }

    private object? StringMethod(string s, string signature, object?[] a, DexMethodRef m)
    {
        int Bound(int index) => (uint)index < (uint)s.Length ? index : throw Runtime($"index {index} of a string of {s.Length} (StringIndexOutOfBoundsException)");
        return signature switch
        {
            "length()" => s.Length,
            "charAt(I)" => (int)s[Bound(Int(a[0]))],
            "codePointAt(I)" => char.IsHighSurrogate(s[Bound(Int(a[0]))]) && Int(a[0]) + 1 < s.Length && char.IsLowSurrogate(s[Int(a[0]) + 1])
                ? char.ConvertToUtf32(s[Int(a[0])], s[Int(a[0]) + 1]) : s[Int(a[0])],
            "isEmpty()" => s.Length == 0 ? 1 : 0,
            "toString()" or "intern()" => s,
            "toCharArray()" => Chars(s),
            "getBytes()" => ByteArray(Encode(s, "UTF-8")),
            "getBytes(Ljava/lang/String;)" => ByteArray(Encode(s, CharsetName(Str(a[0])))),
            "getBytes(Ljava/nio/charset/Charset;)" => ByteArray(Encode(s, CharsetOf(a[0]))),
            "substring(I)" => Substring(s, Int(a[0]), s.Length),
            "substring(II)" or "subSequence(II)" => Substring(s, Int(a[0]), Int(a[1])),
            "concat(Ljava/lang/String;)" => Made(s + Str(a[0])),
            "indexOf(I)" => IndexOf(s, Int(a[0]), 0),
            "indexOf(II)" => IndexOf(s, Int(a[0]), Int(a[1])),
            "indexOf(Ljava/lang/String;)" => s.IndexOf(Str(a[0]), StringComparison.Ordinal),
            "indexOf(Ljava/lang/String;I)" => s.IndexOf(Str(a[0]), Math.Clamp(Int(a[1]), 0, s.Length), StringComparison.Ordinal),
            "lastIndexOf(I)" => Int(a[0]) is >= 0 and < 0x10000 ? s.LastIndexOf((char)Int(a[0])) : s.LastIndexOf(char.ConvertFromUtf32(Int(a[0])), StringComparison.Ordinal),
            "lastIndexOf(Ljava/lang/String;)" => s.LastIndexOf(Str(a[0]), StringComparison.Ordinal),
            "equals(Ljava/lang/Object;)" => a[0] is string t && t == s ? 1 : 0,
            "contentEquals(Ljava/lang/CharSequence;)" => Text(a[0] ?? throw Runtime("a null CharSequence (NullPointerException)")) == s ? 1 : 0,
            "hashCode()" => JavaHash(s),
            "compareTo(Ljava/lang/String;)" => Compare(s, Str(a[0])),
            "startsWith(Ljava/lang/String;)" => s.StartsWith(Str(a[0]), StringComparison.Ordinal) ? 1 : 0,
            "endsWith(Ljava/lang/String;)" => s.EndsWith(Str(a[0]), StringComparison.Ordinal) ? 1 : 0,
            "contains(Ljava/lang/CharSequence;)" => s.Contains(Text(a[0] ?? throw Runtime("a null CharSequence (NullPointerException)")), StringComparison.Ordinal) ? 1 : 0,
            "trim()" => Trim(s),
            "replace(CC)" => Made(s.Replace((char)Int(a[0]), (char)Int(a[1]))),
            "replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)" => Made(Replace(s, Text(a[0] ?? throw Runtime("a null CharSequence (NullPointerException)")),
                Text(a[1] ?? throw Runtime("a null CharSequence (NullPointerException)")))),
            // The default locale changes non-ASCII case mappings (Turkish dotless i), so only ASCII text maps here.
            "toUpperCase()" when s.All(char.IsAscii) => s.ToUpperInvariant(),
            "toLowerCase()" when s.All(char.IsAscii) => s.ToLowerInvariant(),
            "toUpperCase()" or "toLowerCase()" => throw Unsupported("platform-dependent", $"{m.Name} of non-ASCII text depends on the default locale"),
            _ => throw Unsupported("unsupported-call", m.Descriptor),
        };
    }

    private object? BuilderMethod(StringBuilder sb, string signature, object?[] a, DexMethodRef m)
    {
        int Bound(int index, int length) => (uint)index < (uint)length ? index : throw Runtime($"index {index} of a StringBuilder of {sb.Length} (StringIndexOutOfBoundsException)");
        StringBuilder Grown(StringBuilder b)
        {
            if (b.Length > MaxElements) throw new Stop(DexFoldStatus.Partial, "memory-limit", $"a StringBuilder longer than {MaxElements:N0} characters");
            return b;
        }
        switch (signature)
        {
            case "append(Ljava/lang/String;)" or "append(Ljava/lang/Object;)" or "append(Ljava/lang/CharSequence;)" or "append(Ljava/lang/StringBuffer;)":
                return Grown(sb.Append(Text(a[0])));
            case "append(C)": return Grown(sb.Append((char)Int(a[0])));
            case "append(I)": return Grown(sb.Append(Int(a[0]).ToString(CultureInfo.InvariantCulture)));
            case "append(J)": return Grown(sb.Append(Long(a[0]).ToString(CultureInfo.InvariantCulture)));
            case "append(Z)": return Grown(sb.Append(Int(a[0]) != 0 ? "true" : "false"));
            case "append([C)": return Grown(sb.Append(CharsText(Array(a[0]), 0, Array(a[0]).Length)));
            case "append([CII)": return Grown(sb.Append(CharsText(Array(a[0]), Int(a[1]), Int(a[2]))));
            case "append(Ljava/lang/CharSequence;II)":
            {
                var text = Text(a[0]);
                int start = Int(a[1]), end = Int(a[2]);
                Range(text.Length, start, end - start);
                return Grown(sb.Append(text, start, end - start));
            }
            case "toString()": return Made(sb.ToString());
            case "length()": return sb.Length;
            case "charAt(I)": return (int)sb[Bound(Int(a[0]), sb.Length)];
            case "setCharAt(IC)": sb[Bound(Int(a[0]), sb.Length)] = (char)Int(a[1]); return null;
            case "deleteCharAt(I)": return sb.Remove(Bound(Int(a[0]), sb.Length), 1);
            case "insert(IC)": return Grown(sb.Insert(Bound(Int(a[0]), sb.Length + 1), (char)Int(a[1])));
            case "insert(ILjava/lang/String;)": return Grown(sb.Insert(Bound(Int(a[0]), sb.Length + 1), Text(a[1])));
            case "insert(II)": return Grown(sb.Insert(Bound(Int(a[0]), sb.Length + 1), Int(a[1]).ToString(CultureInfo.InvariantCulture)));
            case "delete(II)":
            {
                int start = Int(a[0]), end = Math.Min(Int(a[1]), sb.Length);
                if (start < 0 || start > end) throw Runtime($"delete({start}, {Int(a[1])}) of a StringBuilder of {sb.Length} (StringIndexOutOfBoundsException)");
                return sb.Remove(start, end - start);
            }
            case "replace(IILjava/lang/String;)":
            {
                int start = Int(a[0]), end = Math.Min(Int(a[1]), sb.Length);
                if (start < 0 || start > sb.Length || start > Int(a[1])) throw Runtime($"replace({start}, {Int(a[1])}) of a StringBuilder of {sb.Length} (StringIndexOutOfBoundsException)");
                return Grown(sb.Remove(start, end - start).Insert(start, Str(a[2])));
            }
            case "setLength(I)":
            {
                int length = Int(a[0]);
                if (length < 0) throw Runtime($"setLength({length}) (StringIndexOutOfBoundsException)");
                Allocate(Math.Max(0, length - sb.Length));
                sb.Length = length;
                return null;
            }
            case "reverse()":
            {
                var chars = sb.ToString().ToCharArray();
                System.Array.Reverse(chars);
                // Java keeps surrogate pairs in order when it reverses.
                for (int k = 0; k + 1 < chars.Length; k++)
                    if (char.IsLowSurrogate(chars[k]) && char.IsHighSurrogate(chars[k + 1])) (chars[k], chars[k + 1]) = (chars[k + 1], chars[k++]);
                sb.Clear().Append(chars);
                return sb;
            }
            case "indexOf(Ljava/lang/String;)": return sb.ToString().IndexOf(Str(a[0]), StringComparison.Ordinal);
            default: throw Unsupported("unsupported-call", m.Descriptor);
        }
    }

    private object? CoderMethod(Base64Coder c, string signature, object?[] a, DexMethodRef m) => (c.Encoder, signature) switch
    {
        (false, "decode(Ljava/lang/String;)") => ByteArray(Base64Decode(Str(a[0]), c.Url ? 8 : 0, strict: !c.Mime)),
        (false, "decode([B)") => ByteArray(Base64Decode(Encoding.Latin1.GetString(Bytes(Array(a[0]), 0, Array(a[0]).Length)), c.Url ? 8 : 0, strict: !c.Mime)),
        (true, "encodeToString([B)") => Made(JavaEncode(c, Bytes(Array(a[0]), 0, Array(a[0]).Length))),
        (true, "encode([B)") => ByteArray(Encoding.ASCII.GetBytes(JavaEncode(c, Bytes(Array(a[0]), 0, Array(a[0]).Length)))),
        (true, "withoutPadding()") => c with { Padding = false },
        _ => throw Unsupported("unsupported-call", m.Descriptor),
    };

    private static string JavaEncode(Base64Coder c, byte[] bytes)
    {
        var text = Convert.ToBase64String(bytes);
        if (c.Url) text = text.Replace('+', '-').Replace('/', '_');
        if (!c.Padding) text = text.TrimEnd('=');
        return c.Mime ? string.Join("\r\n", text.Chunk(76).Select(x => new string(x))) : text;
    }

    /// <summary>android.util.Base64.encodeToString: flags NO_PADDING 1, NO_WRAP 2, CRLF 4, URL_SAFE 8; a line break after every 76 characters.</summary>
    private static string Base64Encode(byte[] bytes, int flags)
    {
        var text = Convert.ToBase64String(bytes);
        if ((flags & 8) != 0) text = text.Replace('+', '-').Replace('/', '_');
        if ((flags & 1) != 0) text = text.TrimEnd('=');
        if ((flags & 2) != 0 || text.Length == 0) return text;
        var newline = (flags & 4) != 0 ? "\r\n" : "\n";
        return string.Concat(text.Chunk(76).Select(x => new string(x) + newline));
    }

    /// <summary>
    /// Base-64 as android.util.Base64.decode reads it (strict: false; characters outside the alphabet are skipped) or as
    /// java.util.Base64's basic and URL decoders do (strict: true). Padding is optional; data after it is an error.
    /// </summary>
    private static byte[] Base64Decode(string text, int flags, bool strict)
    {
        bool url = (flags & 8) != 0;
        var values = new List<int>(text.Length);
        int pad = 0;
        bool done = false;
        foreach (var ch in text)
        {
            int v = ch switch
            {
                >= 'A' and <= 'Z' => ch - 'A',
                >= 'a' and <= 'z' => ch - 'a' + 26,
                >= '0' and <= '9' => ch - '0' + 52,
                '+' when !url => 62,
                '/' when !url => 63,
                '-' when url => 62,
                '_' when url => 63,
                '=' => -2,
                _ => -1,
            };
            if (v == -1)
            {
                if (strict) throw Runtime($"'{ch}' is not base-64 (IllegalArgumentException)");
                continue;
            }
            if (done || (v >= 0 && pad > 0)) throw Runtime("data after the base-64 padding (IllegalArgumentException)");
            if (v >= 0) { values.Add(v); continue; }
            int r = values.Count % 4;
            if (r == 2 && ++pad == 2 || r == 3 && ++pad == 1) done = true;
            else if (r != 2) throw Runtime("misplaced base-64 padding (IllegalArgumentException)");
        }
        int rest = values.Count % 4;
        if (rest == 1 || pad == 1 && rest == 2) throw Runtime("bad base-64 length (IllegalArgumentException)");
        var bytes = new List<byte>(values.Count * 3 / 4);
        for (int k = 0; k + 1 < values.Count; k += 4)
        {
            int n = values.Count - k;
            int b = values[k] << 18 | values[k + 1] << 12 | (n > 2 ? values[k + 2] << 6 : 0) | (n > 3 ? values[k + 3] : 0);
            bytes.Add((byte)(b >> 16));
            if (n > 2) bytes.Add((byte)(b >> 8));
            if (n > 3) bytes.Add((byte)b);
        }
        return [.. bytes];
    }

    private static string CharsetOf(object? v) => v switch
    {
        Charset c => c.Name,
        null => throw Runtime("a null charset (NullPointerException)"),
        _ => throw Unsupported("invalid-code", Describe(v) + " used as a charset"),
    };

    /// <summary>The canonical name of a charset Java and .NET decode alike; others are outside the subset.</summary>
    private static string CharsetName(string name) => name.ToUpperInvariant() switch
    {
        "UTF-8" or "UTF8" => "UTF-8",
        "ISO-8859-1" or "ISO8859_1" or "ISO_8859_1" or "LATIN1" or "8859_1" => "ISO-8859-1",
        "US-ASCII" or "ASCII" => "US-ASCII",
        "UTF-16" or "UTF_16" => "UTF-16",
        "UTF-16BE" or "UNICODEBIGUNMARKED" => "UTF-16BE",
        "UTF-16LE" or "UNICODELITTLEUNMARKED" => "UTF-16LE",
        _ => throw Unsupported("unsupported-value", $"charset {name}"),
    };

    /// <summary>String.getBytes: an unmappable code point becomes '?', as Java's encoders replace it.</summary>
    private static byte[] Encode(string s, string charset)
    {
        switch (charset)
        {
            case "ISO-8859-1" or "US-ASCII":
            {
                int max = charset == "US-ASCII" ? 0x7F : 0xFF;
                var bytes = new List<byte>(s.Length);
                for (int k = 0; k < s.Length; k++)
                {
                    if (char.IsHighSurrogate(s[k]) && k + 1 < s.Length && char.IsLowSurrogate(s[k + 1])) k++;
                    bytes.Add(s[k] <= max && !char.IsSurrogate(s[k]) ? (byte)s[k] : (byte)'?');
                }
                return [.. bytes];
            }
            case "UTF-16": return [0xFE, 0xFF, .. Encoding.BigEndianUnicode.GetBytes(s)];
            case "UTF-16BE": return Encoding.BigEndianUnicode.GetBytes(s);
            case "UTF-16LE": return Encoding.Unicode.GetBytes(s);
            default:
            {
                var chars = s.ToCharArray();
                for (int k = 0; k < chars.Length; k++)
                {
                    if (char.IsHighSurrogate(chars[k]) && k + 1 < chars.Length && char.IsLowSurrogate(chars[k + 1])) { k++; continue; }
                    if (char.IsSurrogate(chars[k])) chars[k] = '?';
                }
                return Encoding.UTF8.GetBytes(chars);
            }
        }
    }

    /// <summary>new String(bytes, charset): malformed input becomes U+FFFD; UTF-16 reads a byte order mark and is big-endian without one.</summary>
    private static string Decode(byte[] b, string charset)
    {
        switch (charset)
        {
            case "ISO-8859-1": return Encoding.Latin1.GetString(b);
            case "US-ASCII": return new string([.. b.Select(x => x < 0x80 ? (char)x : '\uFFFD')]);
            case "UTF-16":
                if (b is [0xFF, 0xFE, ..]) return Utf16(b[2..], false);
                return Utf16(b is [0xFE, 0xFF, ..] ? b[2..] : b, true);
            case "UTF-16BE": return Utf16(b, true);
            case "UTF-16LE": return Utf16(b, false);
            default: return Encoding.UTF8.GetString(b);
        }
    }

    private static string Utf16(byte[] b, bool bigEndian)
    {
        var text = (bigEndian ? Encoding.BigEndianUnicode : Encoding.Unicode).GetString(b, 0, b.Length & ~1);
        return b.Length % 2 == 1 ? text + '\uFFFD' : text;
    }

    private string Substring(string s, int begin, int end)
    {
        if (begin < 0 || end > s.Length || begin > end) throw Runtime($"substring({begin}, {end}) of a string of {s.Length} (StringIndexOutOfBoundsException)");
        return Made(s[begin..end]);
    }

    private static int IndexOf(string s, int ch, int from)
    {
        from = Math.Max(0, from);
        if (from >= s.Length) return -1;
        return ch is >= 0 and < 0x10000 ? s.IndexOf((char)ch, from)
            : ch is >= 0x10000 and <= 0x10FFFF ? s.IndexOf(char.ConvertFromUtf32(ch), from, StringComparison.Ordinal) : -1;
    }

    private static int JavaHash(string s)
    {
        int h = 0;
        foreach (var c in s) h = unchecked(31 * h + c);
        return h;
    }

    private static int Compare(string a, string b)
    {
        int n = Math.Min(a.Length, b.Length);
        for (int k = 0; k < n; k++)
            if (a[k] != b[k]) return a[k] - b[k];
        return a.Length - b.Length;
    }

    private static string Trim(string s)
    {
        int start = 0, end = s.Length;
        while (start < end && s[start] <= ' ') start++;
        while (end > start && s[end - 1] <= ' ') end--;
        return s[start..end];
    }

    private static string Replace(string s, string target, string replacement)
    {
        if (target.Length > 0) return s.Replace(target, replacement, StringComparison.Ordinal);
        var sb = new StringBuilder(replacement);
        foreach (var c in s) sb.Append(c).Append(replacement);
        return sb.ToString();
    }

    private static int Digit(char c, int radix)
    {
        if (radix is < 2 or > 36) return -1;
        int v = c switch
        {
            >= '0' and <= '9' => c - '0',
            >= 'a' and <= 'z' => c - 'a' + 10,
            >= 'A' and <= 'Z' => c - 'A' + 10,
            _ when char.IsDigit(c) => (int)char.GetNumericValue(c),
            _ => -1,
        };
        return v < radix ? v : -1;
    }

    /// <summary>Integer.parseInt / Long.parseLong: an optional sign, then digits of the radix; anything else is a NumberFormatException.</summary>
    private static long Parse(string s, int radix, long min, long max)
    {
        if (radix is < 2 or > 36 || s.Length == 0) throw Runtime($"\"{s}\" is not a number (NumberFormatException)");
        bool negative = s[0] == '-';
        int start = s[0] is '-' or '+' ? 1 : 0;
        if (start == s.Length) throw Runtime($"\"{s}\" is not a number (NumberFormatException)");
        System.Numerics.BigInteger v = 0;
        for (int k = start; k < s.Length; k++)
        {
            int d = Digit(s[k], radix);
            if (d < 0) throw Runtime($"\"{s}\" is not a number (NumberFormatException)");
            v = v * radix + d;
            if (v > (System.Numerics.BigInteger)max + 1) throw Runtime($"\"{s}\" is out of range (NumberFormatException)");
        }
        if (negative) v = -v;
        if (v < min || v > max) throw Runtime($"\"{s}\" is out of range (NumberFormatException)");
        return (long)v;
    }

    private static string Radix(long v, int radix)
    {
        if (radix is < 2 or > 36) radix = 10;
        if (v == 0) return "0";
        var digits = new StringBuilder();
        var n = System.Numerics.BigInteger.Abs(v);
        while (n > 0)
        {
            digits.Insert(0, "0123456789abcdefghijklmnopqrstuvwxyz"[(int)(n % radix)]);
            n /= radix;
        }
        return (v < 0 ? "-" : "") + digits;
    }

    private static uint ReverseBits(uint v)
    {
        uint r = 0;
        for (int k = 0; k < 32; k++, v >>= 1) r = r << 1 | (v & 1);
        return r;
    }

    private object? ArrayCopy(object?[] a)
    {
        var source = Array(a[0]);
        var target = Array(a[2]);
        int from = Int(a[1]), to = Int(a[3]), count = Int(a[4]);
        if (source.References != null != (target.References != null) || source.References == null && source.Element != target.Element)
            throw Runtime($"arraycopy from {source.Type} to {target.Type} (ArrayStoreException)");
        Range(source.Length, from, count);
        Range(target.Length, to, count);
        Write(target);
        if (source.References != null) System.Array.Copy(source.References, from, target.References!, to, count);
        else System.Array.Copy(source.Primitives!, from, target.Primitives!, to, count);
        return null;
    }

    private DalvikArray CopyOf(DexMethodRef m, object?[] a)
    {
        var source = Array(a[0]);
        int from = 0, to;
        if (m.Name == "copyOf") to = Int(a[1]) >= 0 ? Int(a[1]) : throw Runtime($"copyOf with length {Int(a[1])} (NegativeArraySizeException)");
        else
        {
            from = Int(a[1]);
            to = Int(a[2]);
            if (from < 0 || from > source.Length) throw Runtime($"copyOfRange from {from} of {source.Length} (ArrayIndexOutOfBoundsException)");
            if (from > to) throw Runtime($"copyOfRange({from}, {to}) (IllegalArgumentException)");
        }
        var copy = NewArray(source.Type, to - from);
        int n = Math.Min(source.Length - from, to - from);
        if (source.References != null) System.Array.Copy(source.References, from, copy.References!, 0, n);
        else System.Array.Copy(source.Primitives!, from, copy.Primitives!, 0, n);
        return copy;
    }
}
