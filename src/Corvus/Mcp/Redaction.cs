using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Corvus.Core;
using ModelContextProtocol.Protocol;

namespace Corvus.Mcp;

/// <summary>Masks secrets in recorded tool arguments: secret-named parameters, NAME=value pairs, credentials, URL passwords and known token shapes.</summary>
// Best effort: a secret in no recognizable form stays.
public static partial class Redaction
{
    public const string Mask = "[redacted]";

    public static bool IsSecretName(string name) => SecretName().IsMatch(name);

    /// <summary>Masks the secrets in <paramref name="text"/> with the plain mask; a value that is already a mask is masked again.</summary>
    public static string Text(string text) => Apply(text, _ => Mask, false);

    /// <summary>
    /// Masks secrets in analyzed-file text; each mask carries a short hash of the value, so equal values stay
    /// comparable. Masked text passes through unchanged.
    /// </summary>
    public static string Output(string text) => Apply(text, Hashed, true);

    /// <summary>A kept result's text and record with their secrets masked; a record that is not JSON is masked as text.</summary>
    public static (string Text, string? Record) Kept(string text, string? record)
    {
        if (record == null) return (Output(text), null);
        JsonNode? node;
        try { node = JsonNode.Parse(record); }
        catch (JsonException) { return (Output(text), Output(record)); }
        Output(node);
        return (Output(text), node?.ToJsonString() ?? record);
    }

    /// <summary>Masks the secrets in every string of <paramref name="node"/> in place, as <see cref="Output(string)"/> does.</summary>
    public static void Output(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var p in o.ToList())
                {
                    if (p.Value is JsonValue v && v.TryGetValue<string>(out var value))
                        o[p.Key] = IsSecretName(p.Key) && !IsMasked(value) ? Hashed(value) : Output(value);
                    else Output(p.Value);
                }
                break;
            case JsonArray a:
                for (int i = 0; i < a.Count; i++)
                {
                    if (a[i] is JsonValue item && item.TryGetValue<string>(out var text)) a[i] = Output(text);
                    else Output(a[i]);
                }
                break;
        }
    }

    /// <summary>
    /// A copy of a file-reading result, an error included, with the secrets of its text blocks, embedded text
    /// resources and record masked; any other result, or an off server, returns <paramref name="result"/> itself.
    /// </summary>
    internal static CallToolResult Result(ServerOptions options, string tool, CallToolResult result)
    {
        if (!options.RedactOutput || !ToolContract.Of(tool).UntrustedContent) return result;
        JsonElement? structured = result.StructuredContent;
        if (structured is { } s && JsonNode.Parse(s.GetRawText()) is { } node)
        {
            Output(node);
            structured = JsonSerializer.SerializeToElement(node);
        }
        return new CallToolResult
        {
            Content = [.. result.Content.Select(Block)],
            StructuredContent = structured,
            IsError = result.IsError,
            Meta = result.Meta,
        };
    }

    // A link block carries a uri and a name, no file text.
    private static ContentBlock Block(ContentBlock block) => block switch
    {
        TextContentBlock t => new TextContentBlock { Text = Output(t.Text), Annotations = t.Annotations, Meta = t.Meta },
        EmbeddedResourceBlock { Resource: TextResourceContents r } e => new EmbeddedResourceBlock
        {
            Resource = new TextResourceContents { Uri = r.Uri, MimeType = r.MimeType, Text = Output(r.Text), Meta = r.Meta },
            Annotations = e.Annotations,
            Meta = e.Meta,
        },
        _ => block,
    };

    // A mask is skipped only when hashing, so a second pass leaves masked text unchanged.
    private static string Apply(string text, Func<string, string> mask, bool keepMasked)
    {
        if (text.Length == 0) return text;
        bool Keep(string value) => keepMasked && IsMasked(value);
        text = AssignmentPattern.Replace(text, m =>
        {
            var value = Unquote(m.Groups["value"].Value);
            return Keep(value) ? m.Value : m.Groups["name"].Value + m.Groups["sep"].Value + mask(value);
        });
        text = CredentialPattern.Replace(text, m => Keep(m.Groups["secret"].Value) ? m.Value : m.Groups["scheme"].Value + " " + mask(m.Groups["secret"].Value));
        text = UrlPasswordPattern.Replace(text, m => Keep(m.Groups["secret"].Value) ? m.Value : m.Groups["head"].Value + mask(m.Groups["secret"].Value) + "@");
        return TokenShapePattern.Replace(text, m => mask(m.Value));
    }

    private static string Unquote(string value) =>
        value.Length >= 2 && value[0] is '"' or '\'' && value[^1] == value[0] ? value[1..^1] : value;

    private static bool IsMasked(string value) => MaskPattern.IsMatch(value);

    private static string Hashed(string value) =>
        Mask[..^1] + ":" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)), 0, 3).ToLowerInvariant() + "]";

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

    private static readonly Regex MaskPattern = new(@"^\[redacted(:[0-9a-f]{6})?\]$", RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

    // Non-backtracking, since these read file text.

    // "Ns.TokenReader::Read" is a symbol, not an assignment: a colon counts only with a space after it.
    private static readonly Regex AssignmentPattern = new(
        @"(?<name>\b[A-Z0-9_.-]*(PASSWORD|PASSWD|PASSPHRASE|PWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?)[A-Z0-9_.-]*)(?<sep>[""']?(?:\s*=\s*|:\s+))(?<value>""[^""\r\n]*""|'[^'\r\n]*'|[^\s""',;&]+)",
        RegexOptions.IgnoreCase | RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

    private static readonly Regex CredentialPattern = new(
        @"\b(?<scheme>bearer|basic)\s+(?<secret>[A-Za-z0-9._~+/=-]{8,})",
        RegexOptions.IgnoreCase | RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

    // The scheme is bounded: unbounded, every letter of a long run of them started a scan to the run's end.
    private static readonly Regex UrlPasswordPattern = new(
        @"(?<head>[A-Za-z][A-Za-z0-9+.-]{0,31}://[^/\s:@]+:)(?<secret>[^/\s@]+)@",
        RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

    private static readonly Regex TokenShapePattern = new(
        @"\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{20,})",
        RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);
}
