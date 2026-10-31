using Corvus.Core;
using Corvus.Native.Pe;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Exports a host program calls by name are reported as entry points in the native view.</summary>
public sealed class HostEntryTests
{
    private static byte[] DllExporting(params string[] names)
    {
        var sorted = names.OrderBy(n => n, StringComparer.Ordinal).ToArray();
        var b = new PeBuilder();
        b.Add(".text", new byte[0x40], 0x60000020);
        uint dir = 0, size = 0;
        b.Add(".edata", rva =>
        {
            var blob = new PeBlob(rva);
            dir = blob.Zero(40);
            uint dll = blob.Ascii("host.dll");
            blob.Align(4);
            uint eat = blob.Here;
            foreach (var _ in sorted) blob.U32(0x1000);
            var nameRvas = sorted.Select(n => blob.Ascii(n)).ToArray();
            blob.Align(4);
            uint names = blob.Here;
            foreach (var n in nameRvas) blob.U32(n);
            uint ordinals = blob.Here;
            for (int i = 0; i < sorted.Length; i++) blob.U16((ushort)i);
            blob.Patch32(dir + 12, dll);
            blob.Patch32(dir + 16, 1);
            blob.Patch32(dir + 20, (uint)sorted.Length);
            blob.Patch32(dir + 24, (uint)sorted.Length);
            blob.Patch32(dir + 28, eat);
            blob.Patch32(dir + 32, names);
            blob.Patch32(dir + 36, ordinals);
            size = blob.Here - dir;
            return blob.ToArray();
        });
        b.Directories[PeDirectory.Export] = (dir, size);
        return b.Build();
    }

    private static IReadOnlyList<Finding> Findings(byte[] file) =>
        new NativeFileView().Inspect(new FileInput("host.dll", file, Blob.Identify(file)) { Options = new FileViewOptions("native") }, default)?.Findings ?? [];

    [Theory]
    [InlineData("xlAutoOpen", "Excel")]
    [InlineData("CPlApplet", "Control Panel")]
    [InlineData("DllRegisterServer", "regsvr32")]
    public void An_export_a_host_calls_is_named_as_an_entry_point(string export, string host)
    {
        var found = Assert.Single(Findings(DllExporting(export, "Add")), f => f.Rule == "native/host-entry");
        Assert.Equal(FindingLevel.Review, found.Level);
        Assert.StartsWith(export + ":", found.Evidence);
        Assert.Contains(host, found.Evidence);
    }

    [Fact]
    public void Ordinary_export_names_report_no_entry_point()
    {
        Assert.DoesNotContain(Findings(DllExporting("Add", "Subtract")), f => f.Rule == "native/host-entry");
    }
}
