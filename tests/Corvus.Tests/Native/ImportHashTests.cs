using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Native.Pe;
using Corvus.Services;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>The import hash of a PE image built here, against the pefile algorithm written out as its terms.</summary>
public sealed class ImportHashTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    /// <summary>An x64 image importing each library's names (strings) and ordinals (ints) in order.</summary>
    private static byte[] Image(params (string Dll, object[] Entries)[] imports)
    {
        var rd = new PeBlob(0x2000);
        uint descriptors = rd.Zero(20 * (imports.Length + 1));
        for (int d = 0; d < imports.Length; d++)
        {
            var (dll, entries) = imports[d];
            uint lookup = rd.Zero(8 * (entries.Length + 1));
            for (int i = 0; i < entries.Length; i++)
            {
                if (entries[i] is int ordinal)
                {
                    rd.Patch32(lookup + 8 * (uint)i, (uint)ordinal);
                    rd.Patch32(lookup + 8 * (uint)i + 4, 0x80000000);
                    continue;
                }
                rd.Align(2);
                uint hint = rd.U16(0);
                rd.Ascii((string)entries[i]);
                rd.Patch32(lookup + 8 * (uint)i, hint);
            }
            uint name = rd.Ascii(dll);
            uint at = descriptors + 20 * (uint)d;
            rd.Patch32(at, lookup);
            rd.Patch32(at + 12, name);
            rd.Patch32(at + 16, lookup);
        }
        var pe = new PeBuilder { Is64 = true, Machine = 0x8664, Characteristics = 0x0022, DllCharacteristics = 0, EntryPoint = 0x1000 };
        pe.Add(".text", [0xC3], 0x60000020);
        pe.Add(".rdata", rd.ToArray(), 0xC0000040);
        pe.Directories[1] = (descriptors, 20 * (uint)(imports.Length + 1));
        return pe.Build();
    }

    private static string Md5(string terms) => Convert.ToHexStringLower(MD5.HashData(Encoding.UTF8.GetBytes(terms)));

    [Fact]
    public void Names_and_known_ordinals_hash_as_lower_case_library_dot_function_terms()
    {
        var pe = PeFile.FromBytes(Image(("KERNEL32.dll", ["CreateFileA", "ExitProcess"]), ("WS2_32.dll", [115, 2]), ("OLEAUT32.dll", [2])));
        Assert.Equal(Md5("kernel32.createfilea,kernel32.exitprocess,ws2_32.wsastartup,ws2_32.bind,oleaut32.sysallocstring"), ImportHash.Of(pe));
    }

    [Fact]
    public void An_ordinal_outside_the_tables_and_of_other_libraries_is_ord_and_its_number()
    {
        var pe = PeFile.FromBytes(Image(("ws2_32.dll", [9999]), ("custom.ocx", [7]), ("driver.sys", ["Entry"])));
        Assert.Equal(Md5("ws2_32.ord9999,custom.ord7,driver.entry"), ImportHash.Of(pe));
    }

    [Fact]
    public void An_image_without_imports_has_no_import_hash()
    {
        var pe = new PeBuilder { Is64 = true, EntryPoint = 0x1000 };
        pe.Add(".text", [0xC3], 0x60000020);
        Assert.Null(ImportHash.Of(PeFile.FromBytes(pe.Build())));
    }

    [Fact]
    public void The_file_summary_carries_the_import_hash_and_the_bundle_lists_it_with_the_file_hashes()
    {
        var path = _dir.File("a.exe");
        File.WriteAllBytes(path, Image(("kernel32.dll", ["ExitProcess"])));
        using var workspace = new AssemblyWorkspace();
        var summary = new InspectionService(workspace).Summarize(null, path, default, new FileViewOptions { Stix = true });
        Assert.Equal(Md5("kernel32.exitprocess"), summary.File.Imphash);
        var bundle = System.Text.Json.JsonDocument.Parse(StixBundle.Write(summary, "1.0.0", DateTimeOffset.UnixEpoch, Guid.NewGuid(), Guid.NewGuid()));
        var file = bundle.RootElement.GetProperty("objects").EnumerateArray().First(o => o.GetProperty("type").GetString() == "file");
        Assert.Equal(summary.File.Imphash, file.GetProperty("hashes").GetProperty("IMPHASH").GetString());
    }
}
