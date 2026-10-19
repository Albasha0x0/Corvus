using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Installers;

namespace Corvus.Tests;

/// <summary>Installers whose payload rides on a native stub: the payload found from the PE layout, listed and extracted.</summary>
public sealed class InstallerStubTests
{
    /// <summary>A PE32 stub with one resource: <paramref name="type"/> is a name, or #n for a numbered type.</summary>
    internal static byte[] Stub(string type, uint id, byte[] data, byte[]? overlay = null)
    {
        var pe = new PeBuilder { Is64 = false, Machine = 0x14C, ImageBase = 0x400000, Characteristics = 0x0102 };
        pe.Add(".text", [0xC3]);
        var rsrc = pe.Add(".rsrc", rva =>
        {
            var b = new PeBlob(rva);
            bool named = !type.StartsWith('#');
            uint Directory(bool name) { b.Zero(12); b.U16((ushort)(name ? 1 : 0)); b.U16((ushort)(name ? 0 : 1)); var entry = b.U32(0); b.U32(0); return entry; }
            var typeEntry = Directory(named);
            var nameDir = b.Here;
            var nameEntry = Directory(false);
            var languageDir = b.Here;
            var languageEntry = Directory(false);
            var leaf = b.Here;
            var dataRva = b.U32(0); b.U32((uint)data.Length); b.U32(0); b.U32(0);
            uint typeName = 0;
            if (named) { typeName = b.Here; b.U16((ushort)type.Length); b.Utf16(type); }
            b.Align(4);
            b.Patch32(dataRva, b.Bytes(data));
            b.Patch32(typeEntry, named ? 0x80000000 | (typeName - rva) : uint.Parse(type[1..]));
            b.Patch32(typeEntry + 4, 0x80000000 | (nameDir - rva));
            b.Patch32(nameEntry, id);
            b.Patch32(nameEntry + 4, 0x80000000 | (languageDir - rva));
            b.Patch32(languageEntry, 1033);
            b.Patch32(languageEntry + 4, leaf - rva);
            return b.ToArray();
        });
        pe.Directories[2] = (rsrc.Rva, (uint)rsrc.Data.Length);
        pe.Overlay = overlay ?? [];
        return pe.Build();
    }

    private static byte[] Zip(params (string Name, byte[] Data)[] files)
    {
        var o = new MemoryStream();
        using (var z = new ZipArchive(o, ZipArchiveMode.Create, leaveOpen: true))
            foreach (var (name, data) in files)
                using (var s = z.CreateEntry(name).Open()) s.Write(data);
        return o.ToArray();
    }

    [Fact]
    public void A_Squirrel_setup_lists_its_release_zip_and_names_the_releases()
    {
        var package = Zip(("App.nuspec", "<package/>"u8.ToArray()), ("lib/net45/App.exe", File.ReadAllBytes(Env.FixturePath)));
        var releases = Encoding.ASCII.GetBytes($"{new string('A', 40)} App-1.2.3-full.nupkg {package.Length}\n");
        var setup = Stub("DATA", 131, Zip(("RELEASES", releases), ("App-1.2.3-full.nupkg", package)));
        var reader = new SquirrelSetupReader();
        Assert.True(reader.Accepts(setup, "Setup.exe"));
        Assert.False(reader.Accepts(Stub("DATA", 132, [1]), "Other.exe"));

        var c = Containers.Open(setup, "Setup.exe", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("Squirrel installer", c.Kind);
        Assert.Contains($"Release App-1.2.3-full.nupkg: {package.Length:N0} bytes, SHA-1 {new string('a', 40)}.", c.Notes);
        Assert.Contains(c.Items, i => i.Name == "App-1.2.3-full.nupkg" && i.Bytes.SequenceEqual(package));
    }

    [Fact]
    [FuzzEntry(typeof(SquirrelSetupReader))]
    public void Fuzzed_installer_stubs_never_throw_past_a_tool_error()
    {
        var squirrel = Stub("DATA", 131, Zip(("RELEASES", Encoding.ASCII.GetBytes($"{new string('A', 40)} A-1-full.nupkg 3\n")), ("A-1-full.nupkg", [1, 2, 3])));
        var failures = FormatFuzz.Run(squirrel, b =>
        {
            try { Containers.Open(b, "Setup.exe", AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { }
        }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
