using System.Globalization;
using Corvus.Services.Web;

namespace Corvus.Tests;

/// <summary>Numeric byte arrays in script text decode to their bytes without running the script.</summary>
public sealed class NumericArraysTests
{
    private static byte[] Sample(int count)
    {
        var data = new byte[count];
        for (int i = 0; i < count; i++) data[i] = (byte)(i * 7 + 3);
        return data;
    }

    private static string Join(byte[] data, Func<byte, string> format) => string.Join(",\n", data.Select(format));

    private static string Decimal(byte b) => b.ToString(CultureInfo.InvariantCulture);

    [Fact]
    public void A_decimal_list_decodes_to_its_bytes()
    {
        var data = Sample(5000);
        var found = NumericArrays.Find($"var b = new Uint8Array([{Join(data, Decimal)}]);", default);
        Assert.Equal(data, Assert.Single(found));
    }

    [Fact]
    public void A_hex_list_decodes_to_its_bytes()
    {
        var data = Sample(5000);
        var found = NumericArrays.Find($"x = [{Join(data, b => "0x" + b.ToString("x2"))}];", default);
        Assert.Equal(data, Assert.Single(found));
    }

    [Fact]
    public void A_fromCharCode_argument_list_decodes_to_its_bytes()
    {
        var data = Sample(5000);
        var found = NumericArrays.Find($"s = String.fromCharCode({Join(data, Decimal)});", default);
        Assert.Equal(data, Assert.Single(found));
    }

    [Fact]
    public void A_list_with_a_value_over_255_is_skipped()
    {
        var items = Sample(5000).Select(Decimal).ToList();
        items[2500] = "256";
        Assert.Empty(NumericArrays.Find($"[{string.Join(",", items)}]", default));
    }

    [Fact]
    public void A_list_of_4096_values_or_fewer_is_skipped()
    {
        Assert.Empty(NumericArrays.Find($"[{Join(Sample(4096), Decimal)}]", default));
    }

    [Fact]
    public void A_list_with_a_non_number_element_is_skipped()
    {
        var items = Sample(5000).Select(Decimal).ToList();
        items[2500] = "x";
        Assert.Empty(NumericArrays.Find($"[{string.Join(",", items)}]", default));
    }

    [Fact]
    public void At_most_eight_arrays_are_returned()
    {
        var list = $"[{Join(Sample(4100), Decimal)}];\n";
        Assert.Equal(8, NumericArrays.Find(string.Concat(Enumerable.Repeat(list, 10)), default).Count);
    }
}
