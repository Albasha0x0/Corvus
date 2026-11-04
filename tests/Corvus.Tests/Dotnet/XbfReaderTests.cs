using Corvus.Core;

namespace Corvus.Tests;

/// <summary>Identification of compiled XAML (XBF) files.</summary>
public class XbfReaderTests
{
    [Fact]
    public void A_compiled_page_is_identified_as_xbf()
    {
        Assert.Equal("xbf (compiled XAML)", Blob.Identify(XbfTests.Page()));
    }

    [Fact]
    public void An_xbf_signature_with_an_unknown_version_is_not_identified_as_xbf()
    {
        var bytes = XbfTests.Page();
        bytes[12] = 9;
        Assert.NotEqual("xbf (compiled XAML)", Blob.Identify(bytes));
    }
}
