using System.Text;
using Corvus.Services.Web;

namespace Corvus.Tests;

/// <summary>Source map lookups on indexed maps (sections).</summary>
public sealed class SourceMapTests
{
    // Two sections, each with one source and one name; the second starts at line 2, column 10.
    private static readonly SourceMap Indexed = SourceMap.Parse(Encoding.UTF8.GetBytes("""
        {"version":3,"sections":[
          {"offset":{"line":0,"column":0},"map":{"version":3,"sources":["a.ts"],"names":["alpha"],"mappings":"AAAAA"}},
          {"offset":{"line":2,"column":10},"map":{"version":3,"sources":["b.ts"],"names":["beta"],"mappings":"EACEA"}}
        ]}
        """));

    [Fact]
    public void A_position_in_a_later_section_names_that_sections_source_and_name()
    {
        var seg = Indexed.Find(2, 12);
        Assert.NotNull(seg);
        Assert.Equal("b.ts", Indexed.Sources[seg.Value.Source]);
        Assert.Equal("beta", Indexed.Names[seg.Value.Name]);
        Assert.Equal((2, 12, 1, 2), (seg.Value.Line, seg.Value.Column, seg.Value.OriginalLine, seg.Value.OriginalColumn));
    }

    [Fact]
    public void An_original_line_in_a_later_section_maps_to_its_generated_position()
    {
        var hit = Indexed.Generated(1, 1);
        Assert.NotNull(hit);
        var seg = Assert.Single(hit.Value.Segments);
        Assert.Equal((2, 12, 1), (seg.Line, seg.Column, seg.Name));
    }
}
