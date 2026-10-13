using System.Text.Json;
using System.Text.Json.Serialization;

namespace Corvus.Core;

/// <summary>An edit's id: "&lt;assembly or image id&gt;#&lt;n&gt;", the same form for .NET and native edits (undo, list and export take it).</summary>
[JsonConverter(typeof(EditIdConverter))]
public readonly record struct EditId(string Target, int Number)
{
    public override string ToString() => $"{Target}#{Number}";

    public static bool TryParse(string? text, out EditId id)
    {
        id = default;
        int hash = text?.LastIndexOf('#') ?? -1;
        if (hash <= 0 || !int.TryParse(text.AsSpan(hash + 1), out var n) || n < 0) return false;
        id = new EditId(text![..hash], n);
        return true;
    }
}

internal sealed class EditIdConverter : JsonConverter<EditId>
{
    public override EditId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        EditId.TryParse(reader.GetString(), out var id) ? id : throw new JsonException("an edit id is <target>#<n>");

    public override void Write(Utf8JsonWriter writer, EditId value, JsonSerializerOptions options) => writer.WriteStringValue(value.ToString());
}

/// <summary>One change of an edit outcome.</summary>
/// <param name="Kind">rename, body, bytes, type, comment, member, ...</param>
/// <param name="Target">What changed: a symbol label or an address.</param>
public sealed record EditChange(string Kind, string Target, string? Before = null, string? After = null);

/// <summary>The outcome of a mutating tool (S4.2); batch item failures in <see cref="Failed"/>.</summary>
public sealed record EditOutcome(bool Applied, bool DryRun, IReadOnlyList<EditChange> Changes, IReadOnlyList<EditId> EditIds)
{
    public int? Failed { get; init; }
    public IReadOnlyList<object>? Items { get; init; }
    public string? ResultId { get; init; }
}
