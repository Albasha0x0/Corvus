namespace Corvus.Mcp;

/// <summary>The former record hand-over; same as <see cref="ToolOutput.With"/>.</summary>
public static class StructuredOutput
{
    public static string With(string text, object structured) => ToolOutput.With(text, structured);
}
