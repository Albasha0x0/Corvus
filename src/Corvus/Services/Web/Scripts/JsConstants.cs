using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Acornima;
using Acornima.Ast;
using Corvus.Core;

namespace Corvus.Services.Web.Scripts;

/// <summary>JavaScript's undefined and an unknown value of the constant evaluator.</summary>
internal sealed class JsUndefined
{
    public static readonly JsUndefined Value = new();
    private JsUndefined() { }
}

internal sealed class JsUnknown
{
    public static readonly JsUnknown Value = new();
    private JsUnknown() { }
}

/// <summary>A regular expression literal: its pattern and flags.</summary>
internal sealed record JsRegex(string Pattern, string Flags);

/// <summary>Evaluates constant JavaScript expressions with the language's conversions; names and calls resolve through callbacks; runs nothing.</summary>
internal sealed class JsConstants(ScriptBudget budget)
{
    private const int MaxDepth = 200;
    private int _depth;

    /// <summary>The value of an identifier, or <see cref="JsUnknown"/>.</summary>
    public Func<string, object?>? Names { get; set; }

    /// <summary>The value of a call the caller models (a decoder), or null to evaluate it here.</summary>
    public Func<CallExpression, object?>? Calls { get; set; }

    /// <summary>Decoding steps met while evaluating (base64, char codes, ...), for a layer's chain.</summary>
    public List<string> Steps { get; } = [];

    public static bool Known(object? v) => v is not JsUnknown;

    public object? Eval(Node? node)
    {
        if (node == null) return JsUnknown.Value;
        if (++_depth > MaxDepth || !budget.Step()) { _depth--; return JsUnknown.Value; }
        try { return EvalCore(node); }
        finally { _depth--; }
    }

    private void StepOf(string step)
    {
        if (Steps.Count < 12 && (Steps.Count == 0 || Steps[^1] != step)) Steps.Add(step);
    }

    private object? EvalCore(Node node)
    {
        switch (node)
        {
            case StringLiteral s: return s.Value;
            case NumericLiteral n: return n.Value;
            case BooleanLiteral b: return b.Value;
            case RegExpLiteral r: return new JsRegex(r.RegExp.Pattern, r.RegExp.Flags);
            case Literal { Value: null }: return null;
            case ParenthesizedExpression p: return Eval(p.Expression);
            case TemplateLiteral t:
            {
                var sb = new StringBuilder();
                for (int i = 0; i < t.Quasis.Count; i++)
                {
                    sb.Append(t.Quasis[i].Value.Cooked ?? t.Quasis[i].Value.Raw);
                    if (i < t.Expressions.Count)
                    {
                        var v = Eval(t.Expressions[i]);
                        if (!Known(v)) return JsUnknown.Value;
                        sb.Append(ToStr(v));
                    }
                }
                return sb.ToString();
            }
            case ArrayExpression a:
            {
                var items = new object?[a.Elements.Count];
                for (int i = 0; i < items.Length; i++)
                {
                    items[i] = a.Elements[i] is { } el ? Eval(el) : JsUndefined.Value;
                    if (!Known(items[i])) return JsUnknown.Value;
                }
                return items;
            }
            case Identifier id:
                return id.Name switch
                {
                    "undefined" => JsUndefined.Value,
                    "NaN" => double.NaN,
                    "Infinity" => double.PositiveInfinity,
                    _ => Names?.Invoke(id.Name) ?? JsUnknown.Value,
                };
            case UnaryExpression u when u is not UpdateExpression:
            {
                var v = Eval(u.Argument);
                if (!Known(v)) return JsUnknown.Value;
                return u.Operator switch
                {
                    Operator.LogicalNot => !Truthy(v),
                    Operator.UnaryNegation => -ToNumber(v),
                    Operator.UnaryPlus => ToNumber(v),
                    Operator.BitwiseNot => (double)~ToInt32(ToNumber(v)),
                    Operator.TypeOf => TypeOf(v),
                    Operator.Void => JsUndefined.Value,
                    _ => JsUnknown.Value,
                };
            }
            case LogicalExpression l:
            {
                var left = Eval(l.Left);
                if (!Known(left)) return JsUnknown.Value;
                return l.Operator switch
                {
                    Operator.LogicalAnd => Truthy(left) ? Eval(l.Right) : left,
                    Operator.LogicalOr => Truthy(left) ? left : Eval(l.Right),
                    Operator.NullishCoalescing => left is null or JsUndefined ? Eval(l.Right) : left,
                    _ => JsUnknown.Value,
                };
            }
            case BinaryExpression b:
            {
                var left = Eval(b.Left);
                if (!Known(left)) return JsUnknown.Value;
                var right = Eval(b.Right);
                return Known(right) ? Binary(b.Operator, left, right) : JsUnknown.Value;
            }
            case ConditionalExpression c:
            {
                var test = Eval(c.Test);
                return Known(test) ? Eval(Truthy(test) ? c.Consequent : c.Alternate) : JsUnknown.Value;
            }
            case SequenceExpression seq:
            {
                object? last = JsUndefined.Value;
                foreach (var e in seq.Expressions) last = Eval(e);
                return last;
            }
            case MemberExpression m:
            {
                var obj = Eval(m.Object);
                if (!Known(obj)) return JsUnknown.Value;
                var key = m.Computed ? Eval(m.Property) : m.Property is Identifier pid ? pid.Name : JsUnknown.Value;
                return Known(key) ? Member(obj, key) : JsUnknown.Value;
            }
            case CallExpression call:
            {
                if (Calls?.Invoke(call) is { } modelled && Known(modelled)) return modelled;
                return Call(call);
            }
        }
        return JsUnknown.Value;
    }

    // --- conversions ---

    public static bool Truthy(object? v) => v switch
    {
        null or JsUndefined => false,
        bool b => b,
        double d => d != 0 && !double.IsNaN(d),
        string s => s.Length > 0,
        _ => true,
    };

    private static string TypeOf(object? v) => v switch
    {
        JsUndefined => "undefined",
        bool => "boolean",
        double => "number",
        string => "string",
        _ => "object",
    };

    public static double ToNumber(object? v) => v switch
    {
        null => 0,
        JsUndefined => double.NaN,
        bool b => b ? 1 : 0,
        double d => d,
        string s => StringToNumber(s),
        object[] a => a.Length == 0 ? 0 : a.Length == 1 ? ToNumber(ToStr(a[0])) : double.NaN,
        _ => double.NaN,
    };

    private static double StringToNumber(string s)
    {
        s = s.Trim();
        if (s.Length == 0) return 0;
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return long.TryParse(s[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var h) ? h : double.NaN;
        if (s.StartsWith("0b", StringComparison.OrdinalIgnoreCase)) try { return Convert.ToInt64(s[2..], 2); } catch (Exception) { return double.NaN; }
        if (s.StartsWith("0o", StringComparison.OrdinalIgnoreCase)) try { return Convert.ToInt64(s[2..], 8); } catch (Exception) { return double.NaN; }
        if (s is "Infinity" or "+Infinity") return double.PositiveInfinity;
        if (s == "-Infinity") return double.NegativeInfinity;
        return double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && !s.Contains(',') ? d : double.NaN;
    }

    public static int ToInt32(double d)
    {
        if (double.IsNaN(d) || double.IsInfinity(d)) return 0;
        return unchecked((int)(long)Math.Truncate(d % 4294967296.0));
    }

    public static string ToStr(object? v) => v switch
    {
        null => "null",
        JsUndefined => "undefined",
        bool b => b ? "true" : "false",
        double d => NumberToString(d),
        string s => s,
        object[] a => string.Join(",", a.Select(x => x is null or JsUndefined ? "" : ToStr(x))),
        JsRegex r => $"/{r.Pattern}/{r.Flags}",
        _ => "[object Object]",
    };

    public static string NumberToString(double d)
    {
        if (double.IsNaN(d)) return "NaN";
        if (double.IsPositiveInfinity(d)) return "Infinity";
        if (double.IsNegativeInfinity(d)) return "-Infinity";
        if (d == Math.Floor(d) && Math.Abs(d) < 1e21) return ((decimal)d).ToString(CultureInfo.InvariantCulture);
        var r = d.ToString("R", CultureInfo.InvariantCulture);
        return r.Replace("E+", "e+").Replace("E-", "e-");
    }

    private object? Binary(Operator op, object? l, object? r)
    {
        switch (op)
        {
            case Operator.Addition:
            {
                var lp = Primitive(l);
                var rp = Primitive(r);
                if (lp is string || rp is string)
                {
                    var s = ToStr(lp) + ToStr(rp);
                    return s.Length > budget.MaxChars ? JsUnknown.Value : s;
                }
                return ToNumber(lp) + ToNumber(rp);
            }
            case Operator.Subtraction: return ToNumber(l) - ToNumber(r);
            case Operator.Multiplication: return ToNumber(l) * ToNumber(r);
            case Operator.Division: return ToNumber(l) / ToNumber(r);
            case Operator.Remainder: return CRemainder(ToNumber(l), ToNumber(r));
            case Operator.Exponentiation: return Math.Pow(ToNumber(l), ToNumber(r));
            case Operator.BitwiseAnd: return (double)(ToInt32(ToNumber(l)) & ToInt32(ToNumber(r)));
            case Operator.BitwiseOr: return (double)(ToInt32(ToNumber(l)) | ToInt32(ToNumber(r)));
            case Operator.BitwiseXor: StepOf("xor"); return (double)(ToInt32(ToNumber(l)) ^ ToInt32(ToNumber(r)));
            case Operator.LeftShift: return (double)(ToInt32(ToNumber(l)) << (ToInt32(ToNumber(r)) & 31));
            case Operator.RightShift: return (double)(ToInt32(ToNumber(l)) >> (ToInt32(ToNumber(r)) & 31));
            case Operator.UnsignedRightShift: return (double)((uint)ToInt32(ToNumber(l)) >> (ToInt32(ToNumber(r)) & 31));
            case Operator.StrictEquality: return StrictEquals(l, r);
            case Operator.StrictInequality: return !StrictEquals(l, r);
            case Operator.Equality: return LooseEquals(l, r);
            case Operator.Inequality: return !LooseEquals(l, r);
            case Operator.LessThan or Operator.LessThanOrEqual or Operator.GreaterThan or Operator.GreaterThanOrEqual:
            {
                var lp = Primitive(l);
                var rp = Primitive(r);
                int? c = lp is string ls && rp is string rs ? string.CompareOrdinal(ls, rs) : Compare(ToNumber(lp), ToNumber(rp));
                if (c == null) return false;
                return op switch { Operator.LessThan => c < 0, Operator.LessThanOrEqual => c <= 0, Operator.GreaterThan => c > 0, _ => c >= 0 };
            }
        }
        return JsUnknown.Value;
    }

    private static double CRemainder(double a, double b) => b == 0 ? double.NaN : a % b;

    private static int? Compare(double a, double b) => double.IsNaN(a) || double.IsNaN(b) ? null : a.CompareTo(b);

    private static object? Primitive(object? v) => v is object[] a ? ToStr(a) : v is JsRegex ? ToStr(v) : v;

    private static bool StrictEquals(object? a, object? b) => (a, b) switch
    {
        (double x, double y) => x == y,
        (string x, string y) => x == y,
        (bool x, bool y) => x == y,
        (null, null) => true,
        (JsUndefined, JsUndefined) => true,
        _ => ReferenceEquals(a, b),
    };

    private static bool LooseEquals(object? a, object? b)
    {
        if (a is null or JsUndefined) return b is null or JsUndefined;
        if (b is null or JsUndefined) return false;
        if (a.GetType() == b.GetType()) return StrictEquals(a, b);
        return ToNumber(Primitive(a)) == ToNumber(Primitive(b));
    }

    // --- members and calls ---

    private object? Member(object? obj, object? key)
    {
        var name = key is double d ? NumberToString(d) : ToStr(key);
        switch (obj)
        {
            case string s:
                if (name == "length") return (double)s.Length;
                if (key is double i && i >= 0 && i < s.Length && i == Math.Floor(i)) return s[(int)i].ToString();
                return new JsMethod(s, name);
            case object[] a:
                if (name == "length") return (double)a.Length;
                if (key is double j && j >= 0 && j < a.Length && j == Math.Floor(j)) return a[(int)j];
                return new JsMethod(a, name);
            case double:
                return new JsMethod(obj, name);
            case JsGlobal g:
                return new JsMethod(g, name);
            case Dictionary<string, object?> map:
                return map.TryGetValue(name, out var v) ? v : JsUndefined.Value;
        }
        return JsUnknown.Value;
    }

    /// <summary>A member read for a call: the receiver and the method name.</summary>
    private sealed record JsMethod(object? Receiver, string Name);

    /// <summary>A global namespace object (String, Math, JSON, window).</summary>
    private sealed record JsGlobal(string Name);

    private object? Call(CallExpression call)
    {
        object? callee;
        if (call.Callee is Identifier fn)
        {
            if (Names?.Invoke(fn.Name) is { } bound && Known(bound) && bound is not JsUnknown) callee = bound;
            else callee = new JsMethod(null, fn.Name);
        }
        else if (call.Callee is MemberExpression { Object: Identifier global } m && global.Name is "String" or "Math" or "window" or "self" or "globalThis" or "Number" or "JSON"
                 && Names?.Invoke(global.Name) is null or JsUnknown)
            callee = new JsMethod(new JsGlobal(global.Name), m.Computed ? ToStr(Eval(m.Property)) : ((Identifier)m.Property).Name);
        else callee = Eval(call.Callee);
        if (callee is not JsMethod method) return JsUnknown.Value;
        var args = new object?[call.Arguments.Count];
        for (int i = 0; i < args.Length; i++)
        {
            if (call.Arguments[i] is SpreadElement) return JsUnknown.Value;
            args[i] = Eval(call.Arguments[i]);
            if (!Known(args[i])) return JsUnknown.Value;
        }
        try { return Method(method.Receiver, method.Name, args); }
        catch (Exception ex) when (ex is ArgumentException or FormatException or OverflowException or RegexMatchTimeoutException or IndexOutOfRangeException) { return JsUnknown.Value; }
    }

    private object? A(object?[] args, int i) => i < args.Length ? args[i] : JsUndefined.Value;

    private object? Method(object? receiver, string name, object?[] args)
    {
        switch (receiver)
        {
            case null:
                return name switch
                {
                    "parseInt" => ParseInt(ToStr(A(args, 0)), args.Length > 1 ? ToInt32(ToNumber(args[1])) : 0),
                    "parseFloat" => ParseFloat(ToStr(A(args, 0))),
                    "Number" => args.Length == 0 ? 0.0 : ToNumber(args[0]),
                    "String" => args.Length == 0 ? "" : ToStr(args[0]),
                    "atob" => Atob(ToStr(A(args, 0))),
                    "unescape" => Step("url encoding", VbsInterpreter.UnescapeJs(ToStr(A(args, 0)))),
                    "decodeURIComponent" or "decodeURI" => Step("url encoding", Uri.UnescapeDataString(ToStr(A(args, 0)))),
                    "escape" => Uri.EscapeDataString(ToStr(A(args, 0))),
                    "encodeURIComponent" => Uri.EscapeDataString(ToStr(A(args, 0))),
                    "Boolean" => Truthy(A(args, 0)),
                    _ => JsUnknown.Value,
                };
            case JsGlobal { Name: "String" } when name is "fromCharCode" or "fromCodePoint":
            {
                var sb = new StringBuilder();
                foreach (var a in args)
                {
                    var code = ToNumber(a);
                    if (name == "fromCodePoint") { if (code is < 0 or > 0x10FFFF || double.IsNaN(code)) return JsUnknown.Value; sb.Append(char.ConvertFromUtf32((int)code)); }
                    else sb.Append((char)(ushort)ToInt32(code));
                }
                StepOf("char codes");
                return sb.ToString();
            }
            case JsGlobal { Name: "Math" }:
                return name switch
                {
                    "floor" => Math.Floor(ToNumber(A(args, 0))),
                    "ceil" => Math.Ceiling(ToNumber(A(args, 0))),
                    "round" => Math.Floor(ToNumber(A(args, 0)) + 0.5),
                    "abs" => Math.Abs(ToNumber(A(args, 0))),
                    "max" => args.Length == 0 ? double.NegativeInfinity : args.Max(ToNumber),
                    "min" => args.Length == 0 ? double.PositiveInfinity : args.Min(ToNumber),
                    "pow" => Math.Pow(ToNumber(A(args, 0)), ToNumber(A(args, 1))),
                    _ => JsUnknown.Value,
                };
            case JsGlobal { Name: "window" or "self" or "globalThis" }: return Method(null, name, args);
            case JsGlobal { Name: "Number" } when name == "parseInt": return Method(null, "parseInt", args);
            case string s: return StringMethod(s, name, args);
            case object[] a: return ArrayMethod(a, name, args);
            case double d when name == "toString":
            {
                int radix = args.Length > 0 ? ToInt32(ToNumber(args[0])) : 10;
                if (radix == 10 || d != Math.Floor(d) || Math.Abs(d) > long.MaxValue) return NumberToString(d);
                return ToRadix((long)d, radix);
            }
        }
        return JsUnknown.Value;
    }

    private object? Step(string step, object? v)
    {
        StepOf(step);
        return v;
    }

    private object? Atob(string s)
    {
        StepOf("base64");
        return ScriptText.FromBase64(s) is { } bytes ? Encoding.Latin1.GetString(bytes) : JsUnknown.Value;
    }

    public static string ToRadix(long v, int radix)
    {
        if (radix is < 2 or > 36) return v.ToString(CultureInfo.InvariantCulture);
        if (v == 0) return "0";
        bool neg = v < 0;
        ulong u = neg ? (ulong)(-v) : (ulong)v;
        var sb = new StringBuilder();
        while (u > 0) { sb.Insert(0, "0123456789abcdefghijklmnopqrstuvwxyz"[(int)(u % (ulong)radix)]); u /= (ulong)radix; }
        return neg ? "-" + sb : sb.ToString();
    }

    public static double ParseInt(string s, int radix)
    {
        s = s.TrimStart();
        int sign = 1;
        if (s.StartsWith('-')) { sign = -1; s = s[1..]; }
        else if (s.StartsWith('+')) s = s[1..];
        if ((radix == 0 || radix == 16) && s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) { s = s[2..]; radix = 16; }
        if (radix == 0) radix = 10;
        if (radix is < 2 or > 36) return double.NaN;
        double v = 0;
        int n = 0;
        foreach (var c in s)
        {
            int digit = c is >= '0' and <= '9' ? c - '0' : c is >= 'a' and <= 'z' ? c - 'a' + 10 : c is >= 'A' and <= 'Z' ? c - 'A' + 10 : 99;
            if (digit >= radix) break;
            v = v * radix + digit;
            n++;
        }
        return n == 0 ? double.NaN : sign * v;
    }

    private static double ParseFloat(string s)
    {
        var m = Regex.Match(s.TrimStart(), @"^[+-]?(\d+\.?\d*(e[+-]?\d+)?|\.\d+(e[+-]?\d+)?|Infinity)", RegexOptions.IgnoreCase);
        return m.Success && double.TryParse(m.Value.Replace("Infinity", "∞"), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d
            : m.Success && m.Value.EndsWith("Infinity", StringComparison.Ordinal) ? (m.Value.StartsWith('-') ? double.NegativeInfinity : double.PositiveInfinity) : double.NaN;
    }

    private object? StringMethod(string s, string name, object?[] args)
    {
        switch (name)
        {
            case "split":
            {
                var sep = A(args, 0);
                if (sep is JsUndefined) return new object?[] { s };
                if (sep is JsRegex rx)
                {
                    var parts = RegexTimeouts.Create(rx.Pattern, RegexOptions.None, TimeSpan.FromMilliseconds(200)).Split(s);
                    return parts.Cast<object?>().ToArray();
                }
                var str = ToStr(sep);
                if (str.Length == 0) return s.Select(c => (object?)c.ToString()).ToArray();
                return s.Split(str).Cast<object?>().ToArray();
            }
            case "charAt": { var i = ToNumber(A(args, 0)); i = double.IsNaN(i) ? 0 : Math.Truncate(i); return i >= 0 && i < s.Length ? s[(int)i].ToString() : ""; }
            case "charCodeAt": { var i = ToNumber(A(args, 0)); i = double.IsNaN(i) ? 0 : Math.Truncate(i); return i >= 0 && i < s.Length ? (double)s[(int)i] : double.NaN; }
            case "codePointAt": { var i = (int)ToNumber(A(args, 0)); return i >= 0 && i < s.Length ? (double)char.ConvertToUtf32(s, i) : JsUndefined.Value; }
            case "substr":
            {
                int len = s.Length, start = Clamp(ToNumber(A(args, 0)), len, true);
                int count = args.Length > 1 && A(args, 1) is not JsUndefined ? (int)Math.Max(0, Math.Min(Integer(ToNumber(args[1])), len - start)) : len - start;
                return s.Substring(start, Math.Max(0, count));
            }
            case "substring":
            {
                int len = s.Length;
                int a = (int)Math.Clamp(Integer(ToNumber(A(args, 0))), 0, len);
                int b = args.Length > 1 && A(args, 1) is not JsUndefined ? (int)Math.Clamp(Integer(ToNumber(args[1])), 0, len) : len;
                return s[Math.Min(a, b)..Math.Max(a, b)];
            }
            case "slice":
            {
                int len = s.Length, a = Clamp(ToNumber(A(args, 0)), len, true);
                int b = args.Length > 1 && A(args, 1) is not JsUndefined ? Clamp(ToNumber(args[1]), len, true) : len;
                return b > a ? s[a..b] : "";
            }
            case "toUpperCase" or "toLocaleUpperCase": return s.ToUpperInvariant();
            case "toLowerCase" or "toLocaleLowerCase": return s.ToLowerInvariant();
            case "trim": return s.Trim();
            case "trimStart" or "trimLeft": return s.TrimStart();
            case "trimEnd" or "trimRight": return s.TrimEnd();
            case "concat": return s + string.Concat(args.Select(ToStr));
            case "indexOf": return (double)s.IndexOf(ToStr(A(args, 0)), StringComparison.Ordinal);
            case "lastIndexOf": return (double)s.LastIndexOf(ToStr(A(args, 0)), StringComparison.Ordinal);
            case "includes": return s.Contains(ToStr(A(args, 0)), StringComparison.Ordinal);
            case "startsWith": return s.StartsWith(ToStr(A(args, 0)), StringComparison.Ordinal);
            case "endsWith": return s.EndsWith(ToStr(A(args, 0)), StringComparison.Ordinal);
            case "toString" or "valueOf": return s;
            case "repeat":
            {
                var n = ToNumber(A(args, 0));
                return n >= 0 && s.Length * n <= budget.MaxChars ? string.Concat(Enumerable.Repeat(s, (int)n)) : JsUnknown.Value;
            }
            case "replace" or "replaceAll":
            {
                var replacement = A(args, 1);
                if (replacement is not string rep) return JsUnknown.Value;
                StepOf("replace");
                if (A(args, 0) is JsRegex rx)
                {
                    var options = (rx.Flags.Contains('i') ? RegexOptions.IgnoreCase : 0) | (rx.Flags.Contains('m') ? RegexOptions.Multiline : 0) | (rx.Flags.Contains('s') ? RegexOptions.Singleline : 0);
                    var regex = RegexTimeouts.Create(rx.Pattern, options, TimeSpan.FromMilliseconds(200));
                    var net = rep.Replace("$&", "$0");
                    return rx.Flags.Contains('g') || name == "replaceAll" ? regex.Replace(s, net) : regex.Replace(s, net, 1);
                }
                var find = ToStr(A(args, 0));
                if (name == "replaceAll") return find.Length == 0 ? s : s.Replace(find, rep, StringComparison.Ordinal);
                int at = s.IndexOf(find, StringComparison.Ordinal);
                return at < 0 ? s : s[..at] + rep + s[(at + find.Length)..];
            }
            case "normalize": return s.Normalize();
        }
        return JsUnknown.Value;
    }

    private static double Integer(double d) => double.IsNaN(d) ? 0 : Math.Truncate(d);

    private static int Clamp(double d, int len, bool fromEnd)
    {
        d = Integer(d);
        if (d < 0 && fromEnd) d = Math.Max(0, len + d);
        return (int)Math.Clamp(d, 0, len);
    }

    private object? ArrayMethod(object?[] a, string name, object?[] args)
    {
        switch (name)
        {
            case "join":
            {
                var sep = A(args, 0) is JsUndefined ? "," : ToStr(args[0]);
                var s = string.Join(sep, a.Select(x => x is null or JsUndefined ? "" : ToStr(x)));
                return s.Length > budget.MaxChars ? JsUnknown.Value : s;
            }
            case "reverse":
            {
                StepOf("reverse");
                var copy = a.ToArray();
                Array.Reverse(copy);
                return copy;
            }
            case "concat": return a.Concat(args.SelectMany(x => x is object?[] inner ? inner : new[] { x })).ToArray();
            case "slice":
            {
                int len = a.Length, s = Clamp(ToNumber(A(args, 0)), len, true);
                int e = args.Length > 1 && A(args, 1) is not JsUndefined ? Clamp(ToNumber(args[1]), len, true) : len;
                return e > s ? a[s..e] : [];
            }
            case "toString": return ToStr(a);
            case "indexOf": return (double)Array.FindIndex(a, x => StrictEquals(x, A(args, 0)));
            case "includes": return a.Any(x => StrictEquals(x, A(args, 0)));
        }
        return JsUnknown.Value;
    }

    /// <summary>A JavaScript string literal for <paramref name="s"/>: single quotes, control characters escaped.</summary>
    public static string Literal(string s)
    {
        var sb = new StringBuilder(s.Length + 2).Append('\'');
        foreach (var c in s)
        {
            switch (c)
            {
                case '\'': sb.Append("\\'"); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\u2028': sb.Append("\\u2028"); break;
                case '\u2029': sb.Append("\\u2029"); break;
                default:
                    if (c < 0x20 || c == 0x7F) sb.Append("\\x").Append(((int)c).ToString("x2", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        }
        return sb.Append('\'').ToString();
    }

    /// <summary>A value as source text, or null when it has none (objects, functions, unknowns).</summary>
    public static string? Source(object? v) => v switch
    {
        string s => Literal(s),
        double d when double.IsNaN(d) => "NaN",
        double d when double.IsInfinity(d) => d > 0 ? "Infinity" : "-Infinity",
        double d => d < 0 ? "-" + NumberToString(-d) : NumberToString(d),
        bool b => b ? "true" : "false",
        null => "null",
        JsUndefined => "undefined",
        _ => null,
    };
}
