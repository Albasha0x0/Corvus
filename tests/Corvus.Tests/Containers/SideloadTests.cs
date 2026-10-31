using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Corvus.Core;
using Corvus.Native.Pe;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

public sealed class SideloadTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeBuilder Basic(bool dll)
    {
        var b = new PeBuilder();
        if (dll) b.Characteristics |= 0x2000;
        var text = b.Add(".text", [0xC3, 0xCC, 0xCC, 0xCC], 0x60000020);
        b.EntryPoint = text.Rva;
        return b;
    }

    /// <summary>An image importing each name, or delay-importing it.</summary>
    private static byte[] Importer(string name, bool delay)
    {
        var b = Basic(dll: false);
        uint descriptor = 0;
        b.Add(delay ? ".didat" : ".idata", rva =>
        {
            var blob = new PeBlob(rva);
            descriptor = blob.Zero(delay ? 64 : 40);
            uint dll = blob.Ascii(name);
            blob.Align(2);
            uint hint = blob.U16(1);
            blob.Ascii("Run");
            blob.Align(8);
            uint thunks = blob.Ptr(true, hint);
            blob.Ptr(true, 0);
            uint iat = blob.Ptr(true, hint);
            blob.Ptr(true, 0);
            if (delay)
            {
                uint hmod = blob.U32(0);
                blob.Patch32(descriptor, 1);
                blob.Patch32(descriptor + 4, dll);
                blob.Patch32(descriptor + 8, hmod);
                blob.Patch32(descriptor + 12, iat);
                blob.Patch32(descriptor + 16, thunks);
            }
            else
            {
                blob.Patch32(descriptor, thunks);
                blob.Patch32(descriptor + 12, dll);
                blob.Patch32(descriptor + 16, iat);
            }
            return blob.ToArray();
        });
        b.Directories[delay ? PeDirectory.DelayImport : PeDirectory.Import] = (descriptor, delay ? 64u : 40u);
        return b.Build();
    }

    /// <summary>A DLL exporting Run, and Fwd forwarded to <paramref name="forward"/> when given.</summary>
    private static byte[] Library(string name, string? forward = null)
    {
        var b = Basic(dll: true);
        uint code = b.Sections[0].Rva, dir = 0, size = 0;
        b.Add(".edata", rva =>
        {
            var blob = new PeBlob(rva);
            dir = blob.Zero(40);
            uint own = blob.Ascii(name);
            uint eat = blob.U32(code);
            uint slot = blob.U32(0);
            uint run = blob.Ascii("Run");
            uint fwd = blob.Ascii("Fwd");
            uint target = blob.Ascii(forward ?? "x.y");
            blob.Align(4);
            uint names = blob.U32(fwd);
            blob.U32(run);
            uint ordinals = blob.U16(1);
            blob.U16(0);
            size = blob.Here - dir;
            blob.Patch32(slot, target);
            blob.Patch32(dir + 12, own);
            blob.Patch32(dir + 16, 1);
            blob.Patch32(dir + 20, 2);
            blob.Patch32(dir + 24, 2);
            blob.Patch32(dir + 28, eat);
            blob.Patch32(dir + 32, names);
            blob.Patch32(dir + 36, ordinals);
            return blob.ToArray();
        });
        b.Directories[PeDirectory.Export] = (dir, size);
        return b.Build();
    }

    /// <summary>The image with a PKCS #7 signature from a throwaway certificate in its security directory.</summary>
    private static byte[] Signed(byte[] image)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=test signer", key, HashAlgorithmName.SHA256);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var cms = new SignedCms(new ContentInfo(image));
        cms.ComputeSignature(new CmsSigner(cert) { IncludeOption = X509IncludeOption.EndCertOnly });
        var blob = cms.Encode();
        int at = (image.Length + 7) & ~7;
        int length = (8 + blob.Length + 7) & ~7;
        var result = new byte[at + length];
        image.CopyTo(result, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(at), (uint)(8 + blob.Length));
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(at + 4), 0x0200);
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(at + 6), 2);
        blob.CopyTo(result, at + 8);
        int entry = PeImage.TryParse(image)!.DirectoryEntryOffset(PeImage.SecurityDirectory);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(entry), (uint)at);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(entry + 4), (uint)length);
        Assert.True(Certificates.Read(result).Present);
        return result;
    }

    private IReadOnlyList<SideloadHit> Scan(params (string Name, byte[] Bytes)[] files)
    {
        foreach (var (name, bytes) in files) File.WriteAllBytes(_dir.File(name), bytes);
        return SideloadReview.Scan(SideloadReview.OfFolder(_dir.Path), default).Hits;
    }

    [Fact]
    public void A_signed_image_beside_an_unsigned_DLL_it_imports_gives_one_record()
    {
        var hit = Assert.Single(Scan(("app.exe", Signed(Importer("plugin.dll", delay: false))), ("plugin.dll", Library("plugin.dll"))));
        Assert.Equal(("app.exe", "plugin.dll", "plugin.dll!Run", false), (hit.Image, hit.Dll, hit.Import, hit.Delay));
        var view = SideloadReview.View([hit], [])!;
        var finding = Assert.Single(view.Findings);
        Assert.Equal(("review", "sideload/unsigned-dll"), (finding.Level, finding.Rule));
        Assert.Contains("app.exe imports plugin.dll!Run; plugin.dll beside it is unsigned", finding.Evidence);
    }

    [Fact]
    public void A_signed_DLL_beside_a_signed_image_gives_no_record()
    {
        Assert.Empty(Scan(("app.exe", Signed(Importer("plugin.dll", delay: false))), ("plugin.dll", Signed(Library("plugin.dll")))));
    }

    [Fact]
    public void An_unsigned_image_gives_no_record()
    {
        Assert.Empty(Scan(("app.exe", Importer("plugin.dll", delay: false)), ("plugin.dll", Library("plugin.dll"))));
    }

    [Fact]
    public void A_KnownDLL_name_gives_no_record()
    {
        if (!OperatingSystem.IsWindows()) return;
        Assert.Empty(Scan(("app.exe", Signed(Importer("kernel32.dll", delay: false))), ("kernel32.dll", Library("kernel32.dll"))));
    }

    [Fact]
    public void A_delay_imported_name_is_found_the_same_way()
    {
        var hit = Assert.Single(Scan(("app.exe", Signed(Importer("plugin.dll", delay: true))), ("plugin.dll", Library("plugin.dll"))));
        Assert.True(hit.Delay);
        Assert.Contains("delay-imports plugin.dll!Run", SideloadReview.Describe(hit));
    }

    [Fact]
    public void Forwarded_exports_to_the_system_copy_of_the_same_name_are_noted()
    {
        var hit = Assert.Single(Scan(("app.exe", Signed(Importer("plugin.dll", delay: false))), ("plugin.dll", Library("plugin.dll", "plugin.Real"))));
        Assert.Equal(["plugin.dll, the system copy of the same name"], hit.Forwards);
    }

    [Fact]
    public void Forwarded_exports_to_a_renamed_copy_beside_the_DLL_are_noted()
    {
        var hit = Assert.Single(Scan(("app.exe", Signed(Importer("plugin.dll", delay: false))), ("plugin.dll", Library("plugin.dll", "plugin_orig.Run")),
            ("plugin_orig.dll", Library("plugin_orig.dll"))), h => h.Dll == "plugin.dll");
        Assert.Equal(["plugin_orig.dll, a renamed copy beside it"], hit.Forwards);
    }

    [Fact]
    public void A_folder_summary_and_an_archive_summary_carry_the_record()
    {
        File.WriteAllBytes(_dir.File("app.exe"), Signed(Importer("plugin.dll", delay: false)));
        File.WriteAllBytes(_dir.File("plugin.dll"), Library("plugin.dll"));
        var service = new InspectionService(new AssemblyWorkspace());
        var folder = service.Summarize(null, _dir.Path, default, FileViewOptions.None);
        Assert.Equal("sideload/unsigned-dll", Assert.Single(folder.Views["sideload"].Findings).Rule);

        var zip = _dir.File("bundle.zip");
        using (var stream = File.Create(zip))
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create))
            foreach (var name in new[] { "app.exe", "plugin.dll" })
            {
                using var entry = archive.CreateEntry("bin/" + name).Open();
                entry.Write(File.ReadAllBytes(_dir.File(name)));
            }
        var packed = service.Summarize(null, zip, default, FileViewOptions.None);
        Assert.Equal("bin/app.exe", Assert.Single(packed.Views["sideload"].Findings).Location);
    }

    [Fact]
    public void Names_in_one_folder_that_differ_only_in_case_do_not_throw()
    {
        var app = Signed(Importer("plugin.dll", delay: false));
        var dll = Library("plugin.dll");
        var (hits, _) = SideloadReview.Scan([new("a/app.exe", () => app, null), new("a/plugin.dll", () => dll, null), new("a/PLUGIN.DLL", () => dll, null)], default);
        Assert.Single(hits);
    }

    [Fact]
    [FuzzEntry(typeof(SideloadFileView))]
    public void Fuzzed_archives_never_throw_in_the_sideload_view()
    {
        var seed = ApkTestSigner.Zip([("bin/app.exe", Signed(Importer("plugin.dll", delay: false))), ("bin/plugin.dll", Library("plugin.dll", "plugin.Real"))]);
        var path = _dir.File("fuzz.zip");
        var failures = FormatFuzz.Run(seed, b =>
        {
            File.WriteAllBytes(path, b);
            try { new SideloadFileView().Inspect(FileInput.Open(path), default); }
            catch (ToolError) { }
        }, 100);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }
}
