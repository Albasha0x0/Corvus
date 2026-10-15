namespace Corvus.Tests;

/// <summary>
/// Marks a quick test as the fuzz entry (FormatFuzz or PeFuzzer) of the readers named; an entry for a type covers the
/// types nested in it. FormatFuzzCoverageTests checks that every format reader has one.
/// </summary>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
internal sealed class FuzzEntryAttribute(params Type[] readers) : Attribute
{
    public Type[] Readers { get; } = readers;
}
