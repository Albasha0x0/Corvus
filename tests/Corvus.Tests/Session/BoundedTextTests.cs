using Corvus.Core;
using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary>The printer bound on decompiled text and the worker answer line bound.</summary>
public sealed class BoundedTextTests
{
    [Fact]
    public void A_printer_past_its_bound_is_refused_as_a_limit()
    {
        using var writer = new BoundedWriter(10);
        writer.Write("12345");
        writer.Write(['6', '7', '8', '9', '0']);
        var error = Assert.Throws<ToolError>(() => writer.Write('x'));
        Assert.Equal(ErrorCode.LimitExceeded, error.Code);
        Assert.Equal("1234567890", writer.ToString());
    }

    [Fact]
    public void Lines_are_read_across_buffer_ends_without_their_line_ends()
    {
        var text = "a\r\n" + new string('b', 20_000) + "\nc";
        var reader = new BoundedLineReader(new StringReader(text), 30_000);
        Assert.Equal("a", reader.ReadLine());
        Assert.Equal(20_000, reader.ReadLine()!.Length);
        Assert.Equal("c", reader.ReadLine());
        Assert.Null(reader.ReadLine());
    }

    [Fact]
    public void A_line_past_the_bound_is_refused_before_it_is_held()
    {
        var reader = new BoundedLineReader(new StringReader("ok\n" + new string('x', 20_000) + "\n"), 10_000);
        Assert.Equal("ok", reader.ReadLine());
        Assert.Throws<InvalidDataException>(() => reader.ReadLine());
    }
}
