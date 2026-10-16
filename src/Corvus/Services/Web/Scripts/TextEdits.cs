using System.Text;

namespace Corvus.Services.Web.Scripts;

/// <summary>
/// Replacements over one text by span: a span seen with two different replacements is dropped (a value that changes, as
/// in a loop); rendering keeps the outermost of overlapping spans.
/// </summary>
internal class TextEdits(string text)
{
    private readonly Dictionary<(int Start, int End), string?> _edits = [];

    public string Text { get; } = text;
    public int Count => _edits.Count(e => e.Value != null);

    /// <param name="weak">A weak edit (a fold without variables) never overrides or conflicts with one made while running.</param>
    public void Set(int start, int end, string replacement, bool weak = false)
    {
        if (start < 0 || end > Text.Length || end <= start) return;
        if (_edits.TryGetValue((start, end), out var old))
        {
            if (weak || old == replacement) return;
            _edits[(start, end)] = null;
            return;
        }
        if (_edits.Count < 200_000) _edits[(start, end)] = replacement;
    }

    /// <summary>Replaces whatever edit the span has (a better spelling of the same value).</summary>
    public void Override(int start, int end, string replacement)
    {
        if (start >= 0 && end <= Text.Length && end > start && (_edits.TryGetValue((start, end), out var old) ? old != null : true)) _edits[(start, end)] = replacement;
    }

    public bool Has(int start, int end) => _edits.ContainsKey((start, end));

    public string Render()
    {
        if (_edits.Count == 0) return Text;
        var spans = _edits.Where(e => e.Value != null).Select(e => (e.Key.Start, e.Key.End, Text: e.Value!))
            .OrderBy(e => e.Start).ThenByDescending(e => e.End).ToList();
        var sb = new StringBuilder(Text.Length);
        int at = 0;
        foreach (var (start, end, replacement) in spans)
        {
            if (start < at) continue; // inside one already replaced
            sb.Append(Text, at, start - at).Append(replacement);
            at = end;
        }
        sb.Append(Text, at, Text.Length - at);
        return sb.ToString();
    }
}

/// <summary>A PowerShell layer's text and its edits.</summary>
internal sealed class PsLayerText(string text, int depth) : TextEdits(text)
{
    public int Depth { get; } = depth;
}
