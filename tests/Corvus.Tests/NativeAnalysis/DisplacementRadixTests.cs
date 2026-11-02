using System.Text.RegularExpressions;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>Displacements in native tool text use the hex form of disassembly.</summary>
public class DisplacementRadixTests
{
    [Theory]
    [InlineData(0x48L, "+48h")]
    [InlineData(-8L, "-8h")]
    [InlineData(0L, "+0h")]
    [InlineData(-0x1000L, "-1000h")]
    public void A_displacement_is_signed_hex_with_the_h_suffix(long value, string expected) =>
        Assert.Equal(expected, Format.Displacement(value));

    [Fact]
    public void The_smallest_displacement_does_not_overflow() =>
        Assert.Equal("-8000000000000000h", Format.Displacement(long.MinValue));

    [Fact]
    public void An_indexed_memory_operand_prints_its_displacement_in_hex()
    {
        var text = InstructionInspectTests.InspectText("indexed");
        Assert.Contains("+10h", text);
        Assert.DoesNotMatch(new Regex(@"[+-]0x[0-9A-Fa-f]+\]"), text);
        Assert.DoesNotMatch(new Regex(@"\+16"), text);
    }

    [Fact]
    public void No_sample_output_shows_a_decimal_stack_displacement()
    {
        var decimalSlot = new Regex(@"\[(?:rsp|rbp|esp|ebp|sp|x29|fp)\s*[+-]\s*(?:\d+|0x[0-9A-Fa-f]+)\]", RegexOptions.IgnoreCase);
        var folder = Path.Combine(DocsTests.RepoRoot(), "tests", "Corvus.Tests", "ProtocolSamples");
        foreach (var file in Directory.EnumerateFiles(folder, "*.json"))
        {
            var hit = decimalSlot.Match(File.ReadAllText(file));
            Assert.False(hit.Success, $"{Path.GetFileName(file)}: {hit.Value}");
        }
    }
}
