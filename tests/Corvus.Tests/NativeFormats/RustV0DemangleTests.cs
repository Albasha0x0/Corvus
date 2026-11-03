using Corvus.Native.Itanium;

namespace Corvus.Tests.NativeFormats;

public sealed class RustV0DemangleTests
{
    [Fact]
    public void The_reference_example_demangles_to_its_path()
    {
        Assert.Equal("mycrate::example", RustV0Demangler.Demangle("_RNvCs15kBYyAo9fc_7mycrate7example"));
        Assert.Equal("mycrate::example", ItaniumDemangler.Demangle("_RNvCs15kBYyAo9fc_7mycrate7example"));
        Assert.True(ItaniumDemangler.IsMangled("_RNvCs15kBYyAo9fc_7mycrate7example"));
    }

    [Theory]
    [InlineData("_RINvC3foo3barjE", "foo::bar::<usize>")]
    [InlineData("_RNvXC3foojNtC3foo3Bar3baz", "<usize as foo::Bar>::baz")]
    [InlineData("_RNvMNtCs15kBYyAo9fc_7mycrate3fooNtB2_3Foo3bar", "<mycrate::foo::Foo>::bar")]
    [InlineData("_RINvC3foo3barRTlmEAhj4_SmE", "foo::bar::<&(i32, u32), [u8; 4], [u32]>")]
    [InlineData("_RINvC3foo3barFUKClEjPbOcE", "foo::bar::<unsafe extern \"C\" fn(i32) -> usize, *const bool, *mut char>")]
    [InlineData("_RNvNvC3foo3bar3baz", "foo::bar::baz")]
    [InlineData("_RNCNvC3foo3bar0", "foo::bar::{closure#0}")]
    public void Generic_arguments_and_impl_paths_are_written_in_angle_brackets(string name, string? expected) =>
        Assert.Equal(expected, RustV0Demangler.Demangle(name));

    [Fact]
    public void A_back_reference_repeats_an_earlier_path() =>
        Assert.Equal("foo::bar::<foo>", RustV0Demangler.Demangle("_RINvC3foo3barB2_E"));

    [Fact]
    public void A_punycode_identifier_is_decoded() =>
        Assert.Equal("foo::b\u00FCcher", RustV0Demangler.Demangle("_RNvC3foou9bcher_kva"));

    [Theory]
    [InlineData("_RINvC3foo3barBz_E")]
    [InlineData("_RINvC3foo3barBb_E")]
    public void A_back_reference_forward_is_refused(string name) =>
        Assert.Null(RustV0Demangler.Demangle(name));

    [Fact]
    public void A_deep_name_stops_at_the_depth_bound()
    {
        static string Nested(int n) => "_R" + string.Concat(Enumerable.Repeat("Nt", n)) + "C1a" + string.Concat(Enumerable.Repeat("1b", n));
        Assert.NotNull(RustV0Demangler.Demangle(Nested(100)));
        Assert.Null(RustV0Demangler.Demangle(Nested(200)));
    }

    [Fact]
    public void Itanium_names_still_demangle()
    {
        Assert.Equal("foo(int)", ItaniumDemangler.Demangle("_Z3fooi"));
        Assert.False(ItaniumDemangler.IsMangled("_Rust"));
        Assert.Null(ItaniumDemangler.Demangle("_Rust"));
    }
}
