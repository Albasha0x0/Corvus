using System.Text.Json;
using ModelContextProtocol.Protocol;

namespace Corvus.Core;

/// <summary>
/// This session's latest successful calls with their whole content (before the response budget cut it), so read_result
/// format=evidence id=last:N can bundle what was just seen; bounded by count and characters, oldest dropped first.
/// </summary>
public sealed class RecentCalls
{
    private const int MaxCalls = 100;
    private const long MaxChars = 32L << 20;

    private readonly LinkedList<KeptResult> _calls = new();
    private long _chars, _sequence;

    /// <summary>Remembers a successful call; <paramref name="origin"/> is its tool with masked arguments and inputs.</summary>
    public void Add(KeptOrigin origin, CallToolResult result)
    {
        if (result.IsError == true) return;
        var text = string.Concat(result.Content.OfType<TextContentBlock>().Select(b => b.Text));
        var record = result.StructuredContent?.GetRawText();
        long chars = text.Length + (record?.Length ?? 0);
        if (chars > MaxChars) return;
        lock (_calls)
        {
            var id = $"c-{++_sequence}";
            _calls.AddLast(new KeptResult(id, text, record, new KeptInfo(origin.Tool, origin.Arguments, origin.ArgumentsSha256, origin.Inputs ?? [],
                DateTimeOffset.UtcNow, chars, "", record != null)));
            _chars += chars;
            while (_calls.Count > MaxCalls || _chars > MaxChars)
            {
                _chars -= _calls.First!.Value.Info.Chars;
                _calls.RemoveFirst();
            }
        }
    }

    /// <summary>The latest <paramref name="count"/> calls, oldest first.</summary>
    public IReadOnlyList<KeptResult> Last(int count)
    {
        lock (_calls) return [.. _calls.Skip(Math.Max(0, _calls.Count - count))];
    }
}
