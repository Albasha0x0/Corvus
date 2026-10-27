using Corvus.Core;
using Corvus.Services;

namespace Corvus.Tests;

public class AotMetadataTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    [Fact]
    public void Address_offset_and_token_attributes_are_read()
    {
        var addr = Assert.Single(AotMetadataService.GetAttributes(_env.One("NativeThing::Second").Member));
        Assert.Equal("0x1100", addr.Values["RVA"]);
        Assert.Equal("4", addr.Values["Slot"]);
        Assert.Equal("0x10", AotMetadataService.GetAttributes(_env.One("NativeThing::Counter").Member).Single().Values["Offset"]);
        Assert.Equal("0x2000010", AotMetadataService.GetAttributes(_env.One("NativeThing").Member).Single().Values["Token"]);
        Assert.Equal("RVA=0x1100 Offset=0x500 VA=0x180001100 Slot=4", AotMetadataService.CompactSummary(_env.One("NativeThing::Second").Member));
        Assert.Null(AotMetadataService.CompactSummary(_env.One("Account::CheckPreview").Member));
    }

    [Theory]
    [InlineData(0x1000UL, "rva", "First", "exact start")]
    [InlineData(0x1050UL, "rva", "First", "probably inside")]
    [InlineData(0x1200UL, "rva", "Second", "after the last known method")]
    [InlineData(0x180001100UL, "va", "Second", "exact start")]
    [InlineData(0x500UL, "offset", "Second", "exact start")]
    public void A_method_is_found_by_its_address(ulong address, string kind, string method, string relation)
    {
        var r = Assert.Single(_env.Locate(address, kind));
        Assert.Equal(method, Assert.Single(r.Methods).Method.Name);
        Assert.StartsWith(relation, r.Function!.Relation);
    }

    [Fact]
    public void Auto_mode_reads_one_kind_and_rejects_bad_input()
    {
        // 0x1000 is First's RVA and also inside Second by file offset: read as an RVA.
        var exact = Assert.Single(_env.Locate(0x1000));
        Assert.Equal(("First", "rva", "exact start"), (exact.Methods[0].Method.Name.String, exact.Kind, exact.Function!.Relation));
        Assert.Equal("rva", Assert.Single(_env.Locate(0x1050)).Kind);
        // At or above the image base: a VA. Nothing at the RVA: a file offset (0x450 is RVA 0x1050).
        var va = Assert.Single(_env.Locate(0x180001100));
        Assert.Equal(("va", 0x1100UL), (va.Kind, va.Rva));
        var offset = Assert.Single(_env.Locate(0x450));
        Assert.Equal(("offset", 0x1050UL, "First"), (offset.Kind, offset.Rva, offset.Methods[0].Method.Name.String));
        Assert.Empty(_env.Locate(0x1100 + AotMetadataService.MaxFunctionSpan, "rva"));
        Assert.Single(_env.Locate(0x1100 + AotMetadataService.MaxFunctionSpan - 1, "rva"));
        // Before the first method.
        Assert.Empty(_env.Locate(0x10, "rva"));
        Assert.Throws<ToolError>(() => _env.Locate(0x1000, "banana"));
    }

    [Fact]
    public void Invalid_attribute_addresses_mean_no_native_code()
    {
        var shared = _env.One("NativeThing::Shared").Member;
        var attr = Assert.Single(AotMetadataService.GetAttributes(shared));
        Assert.True(attr.InvalidAddress);
        Assert.Contains("not a real address", attr.ToString());
        Assert.Null(AotMetadataService.CompactSummary(shared));
        Assert.DoesNotContain(_env.AotMetadata.GetIndex(_env.Fixture), e => e.Method == shared);
        Assert.Empty(_env.Locate(0xA5399800A5350, "rva"));
        Assert.Empty(_env.Locate(0xA5399800A5360));

        Assert.True(AotMetadataService.IsInvalidAddress(0x1_0000_0000, 0x400, 0x1_8000_0000));
        Assert.True(AotMetadataService.IsInvalidAddress(0x1000, 0, 0x180001000));
        Assert.True(AotMetadataService.IsInvalidAddress(0x2000, 0x400, 0x1000));
        Assert.False(AotMetadataService.IsInvalidAddress(0x1000, 0x400, 0x180001000));
        Assert.False(AotMetadataService.IsInvalidAddress(null, null, null));
    }

    [Fact]
    public async Task Method_addresses_skip_same_named_types_without_metadata()
    {
        // A managed assembly without [Address] attributes defines the same type name.
        using var dir = new TempDir();
        var managed = dir.File("Managed.dll");
        File.WriteAllBytes(managed, ContainerFixtures.Module("Managed", m => m.Types.Add(new dnlib.DotNet.TypeDefUser("Fixture.Native", "NativeThing", m.CorLibTypes.Object.TypeDefOrRef))));
        _env.Workspace.Load(managed);
        var tools = _env.MethodAddressTools();
        var text = await tools.GetMethodAddresses("Fixture.Native.NativeThing");
        Assert.Contains("1 match(es) in assemblies without metadata skipped: Managed", text);
        Assert.Contains("RVA=0x1100", text);
        Assert.DoesNotContain("[Managed]", text);
        // Scoped to the managed assembly only: shown with a hint.
        Assert.Contains("No address attributes found. load_assembly the build folder or its global-metadata.dat", await tools.GetMethodAddresses("Fixture.Native.NativeThing", "Managed"));
    }

    [Fact]
    public void An_assembly_without_addresses_gives_a_clear_error()
    {
        using var env = new Env(Env.ConsumerPath);
        var ex = Assert.Throws<ToolError>(() => env.Locate(0x1000, "rva"));
        Assert.Contains("No [Address] attributes", ex.Message);
        Assert.Contains("dummy assembly folder", ex.Remediation);
        Assert.Contains("global-metadata.dat", ex.Remediation);
    }

    [Theory]
    [InlineData("0x1A2B", 0x1A2BUL)]
    [InlineData("1A2B", 0x1A2BUL)]
    [InlineData("1a2bh", 0x1A2BUL)]
    [InlineData("00000001`80001000", 0x180001000UL)]
    [InlineData("0x1_0000", 0x10000UL)]
    [InlineData("d:100", 100UL)]
    public void Address_forms_parse_to_their_value(string text, ulong expected) => Assert.Equal(expected, AotMetadataService.ParseAddress(text));

    [Theory]
    [InlineData("")]
    [InlineData("xyz")]
    [InlineData("d:abc")]
    public void Bad_addresses_parse_to_nothing(string text) => Assert.Null(AotMetadataService.ParseAddress(text));
}

public class ResourceTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    private string Name(string suffix) => _env.Resources.List(_env.Fixture).First(r => r.Name.EndsWith(suffix)).Name;

    [Fact]
    public void Embedded_files_and_resource_containers_are_listed()
    {
        var list = _env.Resources.List(_env.Fixture);
        Assert.Contains(list, r => r.Name.EndsWith("hello.txt") && r.Size > 0);
        Assert.Equal(2, Assert.Single(list, r => r.Name.EndsWith(".resources")).EntryCount);
    }

    [Fact]
    public void Text_container_entries_and_hex_are_read()
    {
        Assert.Contains("Hello from an embedded resource.", _env.Resources.Get(_env.Fixture, Name("hello.txt"), null, null));
        // Case-insensitive.
        Assert.Contains("hello.txt", _env.Resources.Get(_env.Fixture, Name("hello.txt").ToUpperInvariant(), null, null));
        var entries = _env.Resources.Get(_env.Fixture, Name(".resources"), null, null);
        Assert.Contains("Greeting", entries);
        Assert.Contains("Farewell", entries);
        Assert.Equal("Welcome, user!", _env.Resources.Get(_env.Fixture, Name(".resources"), "Greeting", null));
        Assert.Contains("00000000", ResourceService.Render([0, 1, 2, 255, 0, 0, 0, 0], 64));
    }

    [Fact]
    public void Resources_and_entries_are_saved_to_disk()
    {
        using var dir = new TempDir();
        _env.Resources.Get(_env.Fixture, Name("hello.txt"), null, dir.File("out/hello.txt"));
        Assert.StartsWith("Hello from", File.ReadAllText(dir.File("out/hello.txt")));
        _env.Resources.Get(_env.Fixture, Name(".resources"), "Greeting", dir.File("greeting.txt"));
        Assert.Equal("Welcome, user!", File.ReadAllText(dir.File("greeting.txt")));
    }

    [Fact]
    public void Missing_resources_and_entries_are_refused()
    {
        Assert.Throws<ToolError>(() => _env.Resources.Get(_env.Fixture, "missing.bin", null, null));
        Assert.Throws<ToolError>(() => _env.Resources.Get(_env.Fixture, Name(".resources"), "NoSuchEntry", null));
    }
}
