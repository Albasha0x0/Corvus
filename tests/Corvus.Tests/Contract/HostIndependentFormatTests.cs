using System.Globalization;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>Text that must read the same on every host: percents ignore the culture, foreign paths split on both separators.</summary>
public class HostIndependentFormatTests
{
    [Fact]
    public void Percent_ignores_the_culture()
    {
        var saved = CultureInfo.CurrentCulture;
        try
        {
            foreach (var culture in new[] { CultureInfo.InvariantCulture, new CultureInfo("fr-FR"), new CultureInfo("en-US") })
            {
                CultureInfo.CurrentCulture = culture;
                Assert.Equal("0%", Format.Percent(0));
                Assert.Equal("43%", Format.Percent(0.425));
                Assert.Equal("42.5%", Format.Percent(0.425, 1));
            }
        }
        finally { CultureInfo.CurrentCulture = saved; }
    }

    [Theory]
    [InlineData(@"C:\src\bar.obj", "bar.obj")]
    [InlineData("/build/obj/bar.o", "bar.o")]
    [InlineData("bar.obj", "bar.obj")]
    public void Foreign_file_name_splits_on_both_separators(string path, string name) => Assert.Equal(name, Format.ForeignFileName(path));
}
