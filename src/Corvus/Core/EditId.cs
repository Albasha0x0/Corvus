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

/// <summary>The outcome of a mutating tool; batch item failures in <see cref="Failed"/>.</summary>
public sealed record EditOutcome(bool Applied, bool DryRun, IReadOnlyList<EditChange> Changes, IReadOnlyList<EditId> EditIds)
{
    public int? Failed { get; init; }
    public IReadOnlyList<object>? Items { get; init; }
    public string? ResultId { get; init; }
    /// <summary>The engines the change was pushed to (ida, ghidra); empty: none open, they take it at their next use.</summary>
    public IReadOnlyList<string>? PushedTo { get; init; }
    /// <summary>The edit's content digest: the same for its dry run and the applied edit; save results list it with the edit id.</summary>
    public string? Digest { get; init; }
}

/// <summary>An edit a save wrote: its id and content digest (as its dry run and the applied edit reported).</summary>
public sealed record SavedEdit(EditId Id, string Digest);

/// <summary>Content digests of edits: the first 16 hex digits of a SHA-256 over the edit's kind and inputs, or its changes.</summary>
public static class EditDigest
{
    /// <summary>A .NET edit: the tool and its recorded arguments (symbols as label, token and signature).</summary>
    public static string Of(string kind, IReadOnlyDictionary<string, string?> args) =>
        Hash(kind + "\n" + string.Concat(args.OrderBy(a => a.Key, StringComparer.Ordinal).Select(a => $"{a.Key}={(a.Value == null ? "\0" : a.Value.Replace("\r\n", "\n"))}\n")));

    /// <summary>A native edit: its changes in order (kind, address, before, after).</summary>
    public static string Of(IEnumerable<EditChange> changes) =>
        Hash(string.Concat(changes.Select(c => $"{c.Kind}\0{c.Target}\0{c.Before}\0{c.After}\n")));

    private static string Hash(string text) =>
        Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text)))[..16];
}
