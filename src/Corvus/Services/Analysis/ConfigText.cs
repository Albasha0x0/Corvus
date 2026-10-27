using System.Text;
using System.Text.Json;
using System.Xml;

namespace Corvus.Services.Analysis;

/// <summary>Reads the values of JSON, XML or INI config text; non-UTF-8, NUL-holding or unparsable text is not config.</summary>
internal static class ConfigText
{
    public const int MaxBytes = 4 << 20, MaxValues = 50_000;
    private const int MaxDepth = 64;
    private static readonly UTF8Encoding Strict = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>The format and values (<see cref="MaxValues"/> + 1 means more); null when not config text or over <see cref="MaxBytes"/>.</summary>
    public static (string Kind, List<string> Values)? Read(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length > MaxBytes) return null;
        if (bytes is [0xEF, 0xBB, 0xBF, ..]) bytes = bytes[3..];
        if (bytes.IndexOf((byte)0) >= 0) return null;
        string text;
        try { text = Strict.GetString(bytes); }
        catch (DecoderFallbackException) { return null; }
        var start = text.TrimStart();
        if (start.Length == 0) return null;
        return start[0] switch
        {
            '{' or '[' => Json(text),
            '<' => Xml(text),
            _ => Ini(text),
        };
    }

    private static (string, List<string>)? Json(string text)
    {
        try
        {
            using var doc = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = MaxDepth, AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            var values = new List<string>();
            var pending = new Stack<JsonElement>();
            pending.Push(doc.RootElement);
            while (pending.Count > 0 && values.Count <= MaxValues)
            {
                var e = pending.Pop();
                switch (e.ValueKind)
                {
                    case JsonValueKind.String:
                        values.Add(e.GetString()!);
                        break;
                    case JsonValueKind.Object:
                        foreach (var p in e.EnumerateObject().Reverse()) pending.Push(p.Value);
                        break;
                    case JsonValueKind.Array:
                        foreach (var item in e.EnumerateArray().Reverse()) pending.Push(item);
                        break;
                }
            }
            return ("json", values);
        }
        catch (JsonException) { return null; }
    }

    private static (string, List<string>)? Xml(string text)
    {
        var values = new List<string>();
        try
        {
            using var reader = XmlReader.Create(new StringReader(text), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, IgnoreComments = true });
            while (reader.Read() && values.Count <= MaxValues)
            {
                if (reader.NodeType == XmlNodeType.Element)
                {
                    while (reader.MoveToNextAttribute())
                        if (reader.Value.Length > 0) values.Add(reader.Value);
                    reader.MoveToElement();
                }
                else if (reader.NodeType is XmlNodeType.Text or XmlNodeType.CDATA && reader.Value.Trim() is { Length: > 0 } v) values.Add(v);
            }
            return ("xml", values);
        }
        catch (XmlException) { return null; }
    }

    /// <summary>INI: every line that is not blank or a comment is a [section] or key=value, with at least one value.</summary>
    private static (string, List<string>)? Ini(string text)
    {
        var values = new List<string>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] is ';' or '#') continue;
            if (line[0] == '[' && line[^1] == ']') continue;
            int eq = line.IndexOf('=');
            if (eq <= 0) return null;
            var value = line[(eq + 1)..].Trim();
            if (value.Length >= 2 && value[0] is '"' or '\'' && value[^1] == value[0]) value = value[1..^1];
            if (value.Length > 0 && values.Count <= MaxValues) values.Add(value);
        }
        return values.Count > 0 ? ("ini", values) : null;
    }
}
