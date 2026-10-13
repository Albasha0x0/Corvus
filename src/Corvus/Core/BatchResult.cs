namespace Corvus.Core;

/// <summary>The error of one failed batch item (STANDARDS S6.5): code, message and next step, escaped as in error results.</summary>
public sealed record BatchError(string Code, string Message, string Next)
{
    /// <summary>Longest item message in characters: one item's error never crowds out the other items.</summary>
    public const int MaxMessageChars = 8_000;

    public static BatchError From(ToolError error, string? tool = null) =>
        new(ToolError.CodeName(error.Code), Cap(Format.EscapeMarkers(error.Message)), Format.EscapeMarkers(error.NextFor(tool)));

    /// <summary>An exception the item's work did not classify.</summary>
    public static BatchError Internal(Exception ex) =>
        new("internal", Cap(Format.EscapeMarkers($"{ex.GetType().Name}: {ex.Message}")), ToolError.InternalNext);

    private static string Cap(string message) =>
        message.Length <= MaxMessageChars ? message : message[..(MaxMessageChars - 40)] + $" ... ({message.Length:N0} chars, cut)";
}

/// <summary>One item of a batch call: the target as given, and its value or its error.</summary>
public sealed record BatchItem<T>(string Target, T? Value, BatchError? Error);

/// <summary>
/// A batch call's items in request order; <see cref="Failed"/> counts the items with an error. The call is a success while
/// any item succeeded (<see cref="BatchResult.ThrowIfAllFailed"/>).
/// </summary>
public sealed record BatchResult<T>(IReadOnlyList<BatchItem<T>> Items)
{
    public int Failed => Items.Count(i => i.Error != null);
}

public static class BatchResult
{
    /// <summary>
    /// Runs <paramref name="each"/> per target; a <see cref="ToolError"/> or unexpected exception becomes that item's error
    /// (cancellation ends the batch). With <paramref name="stopOnError"/>, the items after the first failure are not run.
    /// </summary>
    public static BatchResult<T> Run<T>(IEnumerable<string> targets, Func<string, T> each, string? tool = null, bool stopOnError = false)
    {
        var items = new List<BatchItem<T>>();
        foreach (var target in targets)
        {
            var item = One(target, each, tool);
            items.Add(item);
            if (stopOnError && item.Error != null) break;
        }
        return new BatchResult<T>(items);
    }

    public static async Task<BatchResult<T>> RunAsync<T>(IEnumerable<string> targets, Func<string, Task<T>> each, string? tool = null, bool stopOnError = false)
    {
        var items = new List<BatchItem<T>>();
        foreach (var target in targets)
        {
            BatchItem<T> item;
            try { item = new(target, await each(target), null); }
            catch (ToolError e) { item = new(target, default, BatchError.From(e, tool)); }
            catch (Exception e) when (e is not OperationCanceledException and not ModelContextProtocol.McpException) { item = new(target, default, BatchError.Internal(e)); }
            items.Add(item);
            if (stopOnError && item.Error != null) break;
        }
        return new BatchResult<T>(items);
    }

    private static BatchItem<T> One<T>(string target, Func<string, T> each, string? tool)
    {
        try { return new(target, each(target), null); }
        catch (ToolError e) { return new(target, default, BatchError.From(e, tool)); }
        catch (Exception e) when (e is not OperationCanceledException and not ModelContextProtocol.McpException) { return new(target, default, BatchError.Internal(e)); }
    }

    /// <summary>
    /// The batch, or a <see cref="ToolError"/> when every item failed: the items' code when they share one, else failed,
    /// with the first item's message and next step and every item's error in details.
    /// </summary>
    public static BatchResult<T> ThrowIfAllFailed<T>(this BatchResult<T> batch)
    {
        if (batch.Items.Count == 0 || batch.Items.Any(i => i.Error == null)) return batch;
        var first = batch.Items[0].Error!;
        var codes = batch.Items.Select(i => i.Error!.Code).Distinct().ToList();
        var code = codes.Count == 1 ? Enum.GetValues<ErrorCode>().FirstOrDefault(c => ToolError.CodeName(c) == codes[0]) : ErrorCode.Failed;
        var message = batch.Items.Count == 1 ? first.Message : $"all {batch.Items.Count} targets failed; the first, '{batch.Items[0].Target}': {first.Message}";
        throw new ToolError(code, message, first.Next)
        {
            Details = new { failed = batch.Items.Count, items = batch.Items.Select(i => new { target = i.Target, error = i.Error }).ToList() },
        };
    }
}
