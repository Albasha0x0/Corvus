using System.Text.Json;
using System.Text.RegularExpressions;

namespace Corvus.Mcp;

/// <summary>Masks secrets in recorded tool arguments: secret-named parameters, NAME=value pairs, credentials, URL passwords and known token shapes.</summary>
// Best effort: a secret in no recognizable form stays.
public static partial class Redaction
{
    public const string Mask = "[redacted]";

    public static bool IsSecretName(string name) => SecretName().IsMatch(name);

    public static string Text(string text)
    {
        if (text.Length == 0) return text;
        text = Assignment().Replace(text, m => m.Groups["name"].Value + m.Groups["sep"].Value + Mask);
        text = Credential().Replace(text, m => m.Groups["scheme"].Value + " " + Mask);
        text = UrlPassword().Replace(text, m => m.Groups["head"].Value + Mask + "@");
        return TokenShape().Replace(text, Mask);
    }

    /// <summary>Writes <paramref name="value"/> with every secret masked.</summary>
    public static void Write(Utf8JsonWriter w, JsonElement value, string? name = null)
    {
        if (name != null && IsSecretName(name) && value.ValueKind is not (JsonValueKind.Null or JsonValueKind.False or JsonValueKind.True))
        {
            w.WriteStringValue(Mask);
            return;
        }
        switch (value.ValueKind)
        {
            case JsonValueKind.String:
                w.WriteStringValue(Text(value.GetString()!));
                break;
            case JsonValueKind.Object:
                w.WriteStartObject();
                foreach (var p in value.EnumerateObject())
                {
                    w.WritePropertyName(p.Name);
                    Write(w, p.Value, p.Name);
                }
                w.WriteEndObject();
                break;
            case JsonValueKind.Array:
                w.WriteStartArray();
                foreach (var item in value.EnumerateArray()) Write(w, item);
                w.WriteEndArray();
                break;
            default:
                value.WriteTo(w);
                break;
        }
    }

    [GeneratedRegex(@"(?i)^(.*[_-])?(pass(word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth(orization)?|credentials?|cookie)$")]
    private static partial Regex SecretName();

    // "Ns.TokenReader::Read" is a symbol, not an assignment: a colon counts only with a space after it.
    [GeneratedRegex(@"(?i)(?<name>\b[A-Z0-9_.-]*(PASSWORD|PASSWD|PASSPHRASE|PWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?)[A-Z0-9_.-]*)(?<sep>\s*=\s*|:\s+)(""[^""\r\n]*""|'[^'\r\n]*'|[^\s""',;&]+)")]
    private static partial Regex Assignment();

    [GeneratedRegex(@"(?i)\b(?<scheme>bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")]
    private static partial Regex Credential();

    // The scheme is bounded: unbounded, every letter of a long run of them started a scan to the run's end.
    [GeneratedRegex(@"(?<head>[A-Za-z][A-Za-z0-9+.-]{0,31}://[^/\s:@]+:)[^/\s@]+@")]
    private static partial Regex UrlPassword();

    [GeneratedRegex(@"\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{20,})")]
    private static partial Regex TokenShape();
}
