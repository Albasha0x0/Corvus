namespace Corvus.Core;

/// <summary>
/// Keeps tool results that were too large to send, so read_result can page through them. Most recent first,
/// bounded by total characters; the oldest results are dropped first.
/// </summary>
public sealed class ResultStore
{
    public const int MaxTotalChars = 64 * 1024 * 1024;
    private readonly LinkedList<(string Id, string Tool, string Text)> _results = new();
    private long _chars;
    private int _next;

    public string Add(string tool, string text)
    {
        lock (_results)
        {
            var id = "r" + ++_next;
            _results.AddFirst((id, tool, text));
            _chars += text.Length;
            while (_chars > MaxTotalChars && _results.Count > 1)
            {
                _chars -= _results.Last!.Value.Text.Length;
                _results.RemoveLast();
            }
            return id;
        }
    }

    public (string Tool, string Text) Get(string id)
    {
        lock (_results)
        {
            foreach (var r in _results)
                if (string.Equals(r.Id, id?.Trim(), StringComparison.OrdinalIgnoreCase))
                    return (r.Tool, r.Text);
            var kept = _results.Count == 0 ? "none" : string.Join(", ", _results.Select(r => $"{r.Id} ({r.Tool})"));
            throw new ToolError(ErrorCode.NotFound, $"No kept result '{id}'. Kept: {kept}.",
                "repeat the original call with a narrower request; results are kept only while memory allows");
        }
    }
}
