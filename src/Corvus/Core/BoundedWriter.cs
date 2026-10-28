namespace Corvus.Core;

/// <summary>
/// A string writer for printed code (decompiled C#, IL) that throws
/// limit_exceeded once the text passes <paramref name="maxChars"/>, so one
/// call cannot print without bound.
/// </summary>
public sealed class BoundedWriter(int maxChars = BoundedWriter.MaxPrintedChars) : StringWriter
{
    /// <summary>The most characters one printer writes (64 Mi, 128 MiB as UTF-16).</summary>
    public const int MaxPrintedChars = 64 << 20;

    public override void Write(char value)
    {
        Room(1);
        base.Write(value);
    }

    public override void Write(char[] buffer, int index, int count)
    {
        Room(count);
        base.Write(buffer, index, count);
    }

    public override void Write(ReadOnlySpan<char> buffer)
    {
        Room(buffer.Length);
        base.Write(buffer);
    }

    public override void Write(string? value)
    {
        Room(value?.Length ?? 0);
        base.Write(value);
    }

    private void Room(int count)
    {
        if ((long)GetStringBuilder().Length + count <= maxChars) return;
        throw new ToolError(ErrorCode.LimitExceeded, $"The printed code passed {maxChars:N0} characters, the most one call prints.",
            "print one type or member at a time");
    }
}
