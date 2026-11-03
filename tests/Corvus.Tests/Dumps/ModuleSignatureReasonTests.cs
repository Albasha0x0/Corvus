using Corvus.Native.Dump;
using Corvus.Native.Pe;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>A module row whose signature state is unknown names why.</summary>
public sealed class ModuleSignatureReasonTests : IDisposable
{
    private const ulong Base = 0x1_8000_0000;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private (string Dump, byte[] File) ModuleDump()
    {
        var file = RebuildFixtures.Pe(new PeSpec(true, [new SectionSpec(".text", 0x60000020, new byte[0x300])], ImageBase: Base));
        var mapped = RebuildFixtures.Mapped(file);
        var b = new MinidumpBuilder { ProcessorArchitecture = 9 };
        b.Modules.Add(new MinidumpBuilder.Module(Base, (uint)mapped.Length, 0, "Z:/app/probe.dll"));
        b.Memory.Add((Base, mapped));
        var dump = _dir.File("probe.dmp");
        File.WriteAllBytes(dump, b.Build());
        return (dump, file);
    }

    private MinidumpService.CheckedModule Row(string dump, string? images)
    {
        using var service = new MinidumpService();
        return Assert.Single(service.Modules(dump, images, 0, 10).Rows);
    }

    [Fact]
    public void A_module_with_no_local_file_names_it_as_the_reason()
    {
        var (dump, _) = ModuleDump();

        var row = Row(dump, null);

        Assert.Equal("unknown", row.SignatureState);
        Assert.Equal("no local file", row.SignatureDetail);
    }

    [Fact]
    public void A_local_file_over_the_size_limit_names_the_limit()
    {
        var (dump, file) = ModuleDump();
        string folder = Directory.CreateDirectory(_dir.File("images")).FullName;
        using (var stream = File.Create(Path.Combine(folder, "probe.dll")))
        {
            stream.Write(file);
            stream.SetLength(ModuleChecks.MaxSignedFile + 1);
        }

        var row = Row(dump, folder);

        Assert.Equal("unknown", row.SignatureState);
        Assert.Equal("the local file is over the 256 MB limit", row.SignatureDetail);
    }

    [Fact]
    public void A_local_file_that_is_not_a_PE_image_says_it_could_not_be_read()
    {
        var (dump, _) = ModuleDump();
        string folder = Directory.CreateDirectory(_dir.File("images")).FullName;
        File.WriteAllBytes(Path.Combine(folder, "probe.dll"), new byte[0x400]);

        var row = Row(dump, folder);

        Assert.Equal("the local file could not be read as a PE image", row.SignatureDetail);
    }
}
