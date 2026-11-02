using System.Text;
using System.Text.Json;
using System.Text.Unicode;

namespace Corvus.Core;

/// <summary>
/// Reads JSON taken from an analyzed file. Bytes that are not UTF-8, not JSON,
/// nested past <see cref="MaxDepth"/> or larger than a stream limit fail with
/// <see cref="JsonException"/>, never with a later InvalidOperationException.
/// </summary>
internal static class InputJson
{
    /// <summary>The deepest nesting read, and the cap on a caller's own depth.</summary>
    public const int MaxDepth = 64;

    private const int DepthCap = 512;

    /// <summary>
    /// The parsed document; throws <see cref="JsonException"/> for bytes that
    /// are not UTF-8 JSON within the depth limit.
    /// </summary>
    public static JsonDocument ParseDocument(ReadOnlyMemory<byte> utf8, JsonDocumentOptions options = default)
    {
        RequireUtf8(utf8.Span);
        return JsonDocument.Parse(utf8, Bounded(options));
    }

    /// <summary>
    /// The parsed document whose root is an object; throws
    /// <see cref="JsonException"/> for any other root or for invalid input.
    /// </summary>
    public static JsonDocument ParseObject(ReadOnlyMemory<byte> utf8, JsonDocumentOptions options = default)
    {
        var doc = ParseDocument(utf8, options);
        if (doc.RootElement.ValueKind == JsonValueKind.Object) return doc;
        var kind = doc.RootElement.ValueKind;
        doc.Dispose();
        throw new JsonException($"the JSON root is {kind.ToString().ToLowerInvariant()}, not an object");
    }

    /// <summary>
    /// The parsed document of text already decoded from a file; throws
    /// <see cref="JsonException"/> for text that is not JSON within the depth
    /// limit. An unpaired surrogate reads as U+FFFD.
    /// </summary>
    public static JsonDocument ParseDocument(string text, JsonDocumentOptions options = default) =>
        ParseDocument(Encoding.UTF8.GetBytes(text), options);

    /// <summary>
    /// The value of a JSON string literal; throws <see cref="JsonException"/>
    /// when the text is not one string.
    /// </summary>
    public static string ParseString(string literal)
    {
        using var doc = ParseDocument(literal);
        if (doc.RootElement.ValueKind != JsonValueKind.String) throw new JsonException("the text is not a JSON string");
        return doc.RootElement.GetString()!;
    }

    /// <summary>
    /// The parsed document of a stream of at most <paramref name="maxBytes"/>
    /// (capped at 2 GB); throws <see cref="JsonException"/> past the limit or
    /// for bytes that are not UTF-8 JSON.
    /// </summary>
    public static JsonDocument ParseDocument(Stream stream, long maxBytes, JsonDocumentOptions options = default)
    {
        maxBytes = Math.Min(maxBytes, Array.MaxLength);
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int n;
        while ((n = stream.Read(chunk, 0, chunk.Length)) > 0)
        {
            if (buffer.Length + n > maxBytes) throw new JsonException($"the document is over {maxBytes:N0} bytes");
            buffer.Write(chunk, 0, n);
        }
        return ParseDocument(buffer.GetBuffer().AsMemory(0, (int)buffer.Length), options);
    }

    /// <summary>
    /// Throws <see cref="JsonException"/> when the bytes are not UTF-8; call
    /// before a <see cref="Utf8JsonReader"/> reads strings from them.
    /// </summary>
    public static void RequireUtf8(ReadOnlySpan<byte> bytes)
    {
        // JsonDocument and Utf8JsonReader check string bytes only when a string is read.
        if (!Utf8.IsValid(bytes)) throw new JsonException("the bytes are not UTF-8");
    }

    /// <summary>
    /// The string of the reader's current token; throws
    /// <see cref="JsonException"/> for bytes that are not UTF-8.
    /// </summary>
    public static string? GetString(ref Utf8JsonReader reader)
    {
        try { return reader.GetString(); }
        catch (InvalidOperationException ex) when (reader.TokenType is JsonTokenType.String or JsonTokenType.PropertyName)
        {
            throw new JsonException("a string is not UTF-8", ex);
        }
    }

    private static JsonDocumentOptions Bounded(JsonDocumentOptions options)
    {
        options.MaxDepth = options.MaxDepth is <= 0 ? MaxDepth : Math.Min(options.MaxDepth, DepthCap);
        return options;
    }
}
