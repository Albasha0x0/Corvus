using System.Xml;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>XML read with a nesting bound.</summary>
public sealed class BoundedXmlTests
{
    private static string Nested(int depth) => string.Concat(Enumerable.Repeat("<a>", depth)) + string.Concat(Enumerable.Repeat("</a>", depth));

    [Fact]
    public void Xml_nested_past_the_depth_limit_is_refused_as_malformed()
    {
        Assert.Equal(BoundedXml.MaxDepth + 1, BoundedXml.Parse(Nested(BoundedXml.MaxDepth + 1)).Descendants().Count());
        var e = Assert.Throws<XmlException>(() => BoundedXml.Parse(Nested(BoundedXml.MaxDepth + 2)));
        Assert.Contains("deeper than 256 levels", e.Message);
        Assert.Throws<XmlException>(() => BoundedXml.Load(System.Text.Encoding.UTF8.GetBytes(Nested(BoundedXml.MaxDepth + 2))));
    }
}
