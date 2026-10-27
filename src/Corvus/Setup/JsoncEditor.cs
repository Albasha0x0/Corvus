using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Corvus.Setup;

/// <summary>Edits one server entry of a JSON-with-comments file in place, keeping the rest; null for anything it does not handle.</summary>
// Callers verify the result and otherwise rewrite the whole file.
internal static class JsoncEditor
{
    private abstract class Span
    {
        public int Start, End;
    }

    private sealed class Scalar : Span;

    private sealed class Obj : Span
    {
        public readonly List<Prop> Props = [];
    }

    private sealed class Prop
    {
        public required string Name;
        public int Start;
        public required Span Value;
        public int Comma = -1;
    }

    private static readonly JsonSerializerOptions Relaxed = new() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary><paramref name="text"/> with <paramref name="name"/> set to <paramref name="entry"/> (null removes it); null when it cannot edit in place.</summary>
    public static string? Edit(string text, IReadOnlyList<string> container, string name, JsonObject? entry)
    {
        try
        {
            var style = Style.Of(text);
            // One change per pass; each pass re-parses, so spans are never stale. Bounded: an entry has few keys.
            for (int pass = 0; pass < 64; pass++)
            {
                var next = Step(text, style, container, name, entry);
                if (next == null) return text;
                text = next;
            }
            return null;
        }
        catch (Exception ex) when (ex is FormatException or IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    /// <summary>The text after the next needed change, or null when nothing is left to change.</summary>
    private static string? Step(string text, Style style, IReadOnlyList<string> container, string name, JsonObject? entry)
    {
        var root = new Parser(text).Document() as Obj ?? throw new FormatException("not an object");
        var obj = root;
        for (int i = 0; i < container.Count; i++)
        {
            var found = Find(obj, container[i]);
            if (found == null)
            {
                if (entry == null) return null;
                // Create the missing containers, holding the entry, in the deepest existing object.
                JsonNode value = new JsonObject { [name] = entry.DeepClone() };
                for (int j = container.Count - 1; j > i; j--) value = new JsonObject { [container[j]] = value };
                return Insert(text, style, obj, container[i], value);
            }
            obj = found.Value as Obj ?? throw new FormatException($"{container[i]} is not an object");
        }

        var prop = Find(obj, name);
        if (entry == null) return prop == null ? null : Remove(text, obj, prop);
        if (prop == null) return Insert(text, style, obj, name, entry);
        if (prop.Value is not Obj current) return Replace(text, style, prop, entry);
        foreach (var (key, value) in entry)
        {
            var existing = Find(current, key);
            if (existing == null) return Insert(text, style, current, key, value);
            if (!JsonNode.DeepEquals(Node(text, existing.Value), value)) return Replace(text, style, existing, value);
        }
        foreach (var existing in current.Props)
            if (!entry.ContainsKey(existing.Name)) return Remove(text, current, existing);
        return null;
    }

    /// <summary>The last property with the name: the one a parser keeps.</summary>
    private static Prop? Find(Obj obj, string name) => obj.Props.LastOrDefault(p => p.Name == name);

    private static JsonNode? Node(string text, Span span) =>
        JsonNode.Parse(text[span.Start..span.End], documentOptions: new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });

    private static string Replace(string text, Style style, Prop prop, JsonNode? value)
    {
        bool inline = text.IndexOf('\n', prop.Value.Start, prop.Value.End - prop.Value.Start) < 0;
        var formatted = Format(value, LineIndent(text, prop.Start) ?? "", style, inline);
        return text[..prop.Value.Start] + formatted + text[prop.Value.End..];
    }

    private static string Insert(string text, Style style, Obj obj, string key, JsonNode? value)
    {
        var name = JsonSerializer.Serialize(key, Relaxed) + ": ";
        if (obj.Props.Count == 0)
        {
            var outer = LineIndent(text, obj.Start, anywhere: true) ?? "";
            var inner = outer + style.Unit;
            var property = name + Format(value, inner, style, inline: false);
            int open = obj.Start + 1, close = obj.End - 1;
            if (text[open..close].Trim().Length == 0)
                return text[..open] + style.NewLine + inner + property + style.NewLine + outer + text[close..];
            return text[..open] + style.NewLine + inner + property + text[open..];
        }

        var last = obj.Props[^1];
        var indent = LineIndent(text, last.Start);
        if (indent == null || text.IndexOf('\n', obj.Start, obj.End - obj.Start) < 0)
        {
            // An object on one line stays on one line.
            var inlineProperty = name + Format(value, "", style, inline: true);
            return last.Comma >= 0
                ? text[..(last.Comma + 1)] + " " + inlineProperty + text[(last.Comma + 1)..]
                : text[..last.Value.End] + ", " + inlineProperty + text[last.Value.End..];
        }
        var withComma = last.Comma >= 0 ? text : text[..last.Value.End] + "," + text[last.Value.End..];
        int anchor = last.Comma >= 0 ? last.Comma + 1 : last.Value.End + 1;
        // After a comment that ends the previous line.
        int at = SkipLineTrivia(withComma, anchor);
        return withComma[..at] + style.NewLine + indent + name + Format(value, indent, style, inline: false) + withComma[at..];
    }

    private static string Remove(string text, Obj obj, Prop prop)
    {
        int index = obj.Props.IndexOf(prop);
        bool last = index == obj.Props.Count - 1;
        var prev = index > 0 ? obj.Props[index - 1] : null;
        if (LineIndent(text, prop.Start) != null && text.IndexOf('\n', obj.Start, obj.End - obj.Start) >= 0)
        {
            int start = LineStart(text, prop.Start);
            int end = SkipLineTrivia(text, prop.Comma >= 0 ? prop.Comma + 1 : prop.Value.End);
            if (end < text.Length && text[end] == '\r') end++;
            if (end < text.Length && text[end] == '\n') end++;
            var removed = text[..start] + text[end..];
            // The previous property is now last: drop its comma unless this one had a trailing comma too.
            if (last && prop.Comma < 0 && prev is { Comma: >= 0 }) removed = removed[..prev.Comma] + removed[(prev.Comma + 1)..];
            return removed;
        }
        if (prop.Comma >= 0)
        {
            int end = prop.Comma + 1;
            while (end < text.Length && text[end] == ' ') end++;
            return text[..prop.Start] + text[end..];
        }
        return prev is { Comma: >= 0 } ? text[..prev.Comma] + text[prop.Value.End..] : text[..prop.Start] + text[prop.Value.End..];
    }

    /// <summary>JSON text for a value; continuation lines are indented under <paramref name="indent"/>.</summary>
    private static string Format(JsonNode? value, string indent, Style style, bool inline)
    {
        switch (value)
        {
            case JsonObject o when o.Count == 0: return "{}";
            case JsonObject o when inline:
                return "{ " + string.Join(", ", o.Select(p => JsonSerializer.Serialize(p.Key, Relaxed) + ": " + Format(p.Value, "", style, true))) + " }";
            case JsonObject o:
                var inner = indent + style.Unit;
                return "{" + string.Concat(o.Select((p, i) => (i == 0 ? "" : ",") + style.NewLine + inner + JsonSerializer.Serialize(p.Key, Relaxed) + ": "
                                                              + Format(p.Value, inner, style, false)))
                           + style.NewLine + indent + "}";
            case JsonArray a when inline || a.All(i => i is not JsonObject and not JsonArray):
                return "[" + string.Join(", ", a.Select(i => Format(i, "", style, true))) + "]";
            case JsonArray a:
                var item = indent + style.Unit;
                return "[" + string.Concat(a.Select((v, i) => (i == 0 ? "" : ",") + style.NewLine + item + Format(v, item, style, false))) + style.NewLine + indent + "]";
            case null: return "null";
            default: return value.ToJsonString(Relaxed);
        }
    }

    private static int LineStart(string text, int at)
    {
        while (at > 0 && text[at - 1] != '\n') at--;
        return at;
    }

    /// <summary>The whitespace before <paramref name="at"/> when only whitespace precedes it (anywhere: the line's indent); else null.</summary>
    private static string? LineIndent(string text, int at, bool anywhere = false)
    {
        int start = LineStart(text, at);
        int end = start;
        while (end < at && text[end] is ' ' or '\t') end++;
        return anywhere || end == at ? text[start..end] : null;
    }

    /// <summary>Past spaces and comments up to the end of the line (not past the line break).</summary>
    private static int SkipLineTrivia(string text, int at)
    {
        while (at < text.Length)
        {
            if (text[at] is ' ' or '\t') at++;
            else if (text.AsSpan(at).StartsWith("//")) { while (at < text.Length && text[at] is not ('\n' or '\r')) at++; }
            else if (text.AsSpan(at).StartsWith("/*") && text.IndexOf("*/", at + 2, StringComparison.Ordinal) is var close and >= 0
                     && text.IndexOf('\n', at, close - at) < 0) at = close + 2;
            else break;
        }
        return at;
    }

    /// <summary>The file's line break and indentation unit (the first indented line's leading whitespace).</summary>
    private sealed record Style(string NewLine, string Unit)
    {
        public static Style Of(string text)
        {
            var newLine = text.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
            foreach (var line in text.Split('\n'))
            {
                int n = 0;
                while (n < line.Length && line[n] is ' ' or '\t') n++;
                if (n > 0 && n < line.TrimEnd('\r').Length) return new Style(newLine, line[0] == '\t' ? "\t" : new string(' ', Math.Min(n, 8)));
            }
            return new Style(newLine, "  ");
        }
    }

    /// <summary>A lenient parser (comments, trailing commas) that records where each value and property is.</summary>
    private sealed class Parser(string text)
    {
        private int _at;

        public Span Document()
        {
            if (_at == 0 && text.Length > 0 && text[0] == '﻿') _at = 1;
            Trivia();
            var value = Value();
            Trivia();
            if (_at != text.Length) throw new FormatException("text after the document");
            return value;
        }

        private void Trivia()
        {
            while (_at < text.Length)
            {
                if (char.IsWhiteSpace(text[_at])) _at++;
                else if (text.AsSpan(_at).StartsWith("//")) { while (_at < text.Length && text[_at] != '\n') _at++; }
                else if (text.AsSpan(_at).StartsWith("/*"))
                {
                    var close = text.IndexOf("*/", _at + 2, StringComparison.Ordinal);
                    if (close < 0) throw new FormatException("unterminated comment");
                    _at = close + 2;
                }
                else break;
            }
        }

        private Span Value()
        {
            if (_at >= text.Length) throw new FormatException("unexpected end");
            switch (text[_at])
            {
                case '{': return Object();
                case '[':
                {
                    int start = _at++;
                    Trivia();
                    while (text[_at] != ']')
                    {
                        Value();
                        Trivia();
                        if (text[_at] == ',') { _at++; Trivia(); }
                        else if (text[_at] != ']') throw new FormatException("expected , or ]");
                    }
                    _at++;
                    return new Scalar { Start = start, End = _at };
                }
                case '"':
                {
                    int start = _at;
                    String();
                    return new Scalar { Start = start, End = _at };
                }
                default:
                {
                    int start = _at;
                    while (_at < text.Length && (char.IsLetterOrDigit(text[_at]) || text[_at] is '-' or '+' or '.')) _at++;
                    if (_at == start) throw new FormatException($"unexpected '{text[_at]}'");
                    return new Scalar { Start = start, End = _at };
                }
            }
        }

        private Obj Object()
        {
            var obj = new Obj { Start = _at++ };
            Trivia();
            while (text[_at] != '}')
            {
                if (text[_at] != '"') throw new FormatException("expected a property name");
                int start = _at;
                var name = String();
                Trivia();
                if (text[_at++] != ':') throw new FormatException("expected :");
                Trivia();
                var prop = new Prop { Name = name, Start = start, Value = Value() };
                obj.Props.Add(prop);
                Trivia();
                if (text[_at] == ',') { prop.Comma = _at++; Trivia(); }
                else if (text[_at] != '}') throw new FormatException("expected , or }");
            }
            obj.End = ++_at;
            return obj;
        }

        private string String()
        {
            int start = _at++;
            while (true)
            {
                if (_at >= text.Length) throw new FormatException("unterminated string");
                if (text[_at] == '\\') _at += 2;
                else if (text[_at++] == '"') break;
            }
            try { return JsonSerializer.Deserialize<string>(text.AsSpan(start, _at - start)) ?? ""; }
            catch (JsonException ex) { throw new FormatException(ex.Message); }
        }
    }
}
