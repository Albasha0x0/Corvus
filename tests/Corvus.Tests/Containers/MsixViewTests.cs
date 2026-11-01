using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>summarize_file view=msix on self-built packages.</summary>
public sealed class MsixViewTests(ITestOutputHelper output)
{
    private const string Publisher = "CN=Example Publisher, O=Example";

    private const string Manifest = """
        <Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10" xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
                 xmlns:desktop="http://schemas.microsoft.com/appx/manifest/desktop/windows10" xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
          <Identity Name="Example.Tool" Publisher="CN=Example Publisher, O=Example" Version="1.2.3.0" ProcessorArchitecture="x64" />
          <Properties><DisplayName>Example Tool</DisplayName><PublisherDisplayName>Example</PublisherDisplayName></Properties>
          <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0" /></Dependencies>
          <Applications>
            <Application Id="App" Executable="PSFLauncher64.exe" EntryPoint="Windows.FullTrustApplication">
              <Extensions>
                <desktop:Extension Category="windows.startupTask" Executable="Tool.exe" EntryPoint="Windows.FullTrustApplication"><desktop:StartupTask TaskId="ToolStart" Enabled="true" /></desktop:Extension>
                <uap:Extension Category="windows.protocol"><uap:Protocol Name="exampletool" /></uap:Extension>
              </Extensions>
            </Application>
          </Applications>
          <Capabilities><Capability Name="internetClient" /><rescap:Capability Name="runFullTrust" /></Capabilities>
        </Package>
        """;

    private const string PsfConfig = """
        { "applications": [ { "id": "App", "executable": "Tool.exe", "arguments": "-x",
            "startScript": { "scriptPath": "scripts\\prepare.ps1", "runInVirtualEnvironment": true, "waitForScriptToFinish": true },
            "endScript": { "scriptPath": "scripts/missing.ps1", "showWindow": false } } ],
          "processes": [ { "executable": "Tool", "fixups": [ { "dll": "FileRedirectionFixup.dll" } ] } ] }
        """;

    private static string BlockMap(params (string Name, byte[] Data)[] files) =>
        "<BlockMap xmlns=\"http://schemas.microsoft.com/appx/2010/blockmap\" HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\">" + string.Concat(files.Select(f =>
            $"<File Name=\"{f.Name}\" Size=\"{f.Data.Length}\" LfhSize=\"40\">" + string.Concat(f.Data.Chunk(64 << 10).Select(c => $"<Block Hash=\"{Convert.ToBase64String(SHA256.HashData(c))}\" />")) + "</File>")) + "</BlockMap>";

    private static (string, byte[])[] Named((string Path, byte[] Data)[] files) => [.. files.Select(f => (Uri.UnescapeDataString(f.Path).Replace('/', '\\'), f.Data))];

    private static byte[] Package(string manifest, byte[]? signature, (string Path, byte[] Data)[] files, Func<(string Name, byte[] Data)[], string>? map = null)
    {
        var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            void Put(string name, byte[] data)
            {
                using var s = zip.CreateEntry(name).Open();
                s.Write(data);
            }
            Put("AppxManifest.xml", Encoding.UTF8.GetBytes(manifest));
            foreach (var (path, data) in files) Put(path, data);
            if (map != null) Put("AppxBlockMap.xml", Encoding.UTF8.GetBytes(map(Named([("AppxManifest.xml", Encoding.UTF8.GetBytes(manifest)), .. files]))));
            if (signature != null) Put("AppxSignature.p7x", signature);
        }
        return ms.ToArray();
    }

    private static byte[] Signature(string subject)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var cms = new SignedCms(new ContentInfo(new Oid("1.2.840.113549.1.7.1"), "APPX digests"u8.ToArray()));
        cms.ComputeSignature(new CmsSigner(cert) { IncludeOption = X509IncludeOption.EndCertOnly });
        return [.. "PKCX"u8, .. cms.Encode()];
    }

    private MsixFileView.Facts View(byte[] bytes, string name = "tool.msix")
    {
        var view = new MsixFileView().Inspect(new FileInput(name, bytes, Blob.Identify(bytes)), default)!;
        foreach (var h in view.Highlights) output.WriteLine(h);
        return (MsixFileView.Facts)view.Detail;
    }

    private static (string, byte[])[] Files(byte[]? exe = null) =>
    [
        ("Tool.exe", exe ?? [1, 2, 3, 4]), ("PSFLauncher64.exe", [5, 6]), ("config.json", Encoding.UTF8.GetBytes(PsfConfig)),
        ("scripts/prepare.ps1", "Write-Output 1"u8.ToArray()), ("Assets/Logo%20Large.png", new byte[70_000]),
    ];

    [Fact]
    public void The_manifest_yields_identity_entry_points_extensions_and_restricted_capabilities()
    {
        var facts = View(Package(Manifest, null, Files()));
        Assert.Equal(("MSIX package", "Example.Tool", "1.2.3.0", "x64"), (facts.Kind, facts.Name, facts.Version, facts.Architecture));
        Assert.Equal(["Windows.Desktop 10.0.17763.0-10.0.22621.0"], facts.Families);
        var app = Assert.Single(facts.Applications);
        Assert.Equal(("PSFLauncher64.exe", "Windows.FullTrustApplication"), (app.Executable, app.EntryPoint));
        Assert.Equal(["windows.startupTask", "windows.protocol"], app.Extensions.Select(e => e.Category));
        Assert.Contains("ToolStart", app.Extensions[0].Targets);
        Assert.Contains("exampletool", app.Extensions[1].Targets);
        Assert.Equal(["internetClient:False", "runFullTrust:True"], facts.Capabilities.Select(c => $"{c.Name}:{c.Restricted}"));
    }

    [Fact]
    public void Package_Support_Framework_scripts_are_listed_with_their_presence_in_the_package()
    {
        var psf = View(Package(Manifest, null, Files())).Psf!;
        Assert.Equal(("PSFLauncher64.exe", "config.json"), (psf.Launcher, psf.Config));
        Assert.Equal(["FileRedirectionFixup.dll"], psf.Fixups);
        var scripts = Assert.Single(psf.Applications).Scripts;
        Assert.Equal(["start scripts\\prepare.ps1 True", "end scripts/missing.ps1 False"], scripts.Select(s => $"{s.Phase} {s.Path} {s.InPackage}"));
        Assert.Equal("runInVirtualEnvironment=true, waitForScriptToFinish=true", scripts[0].Options);
    }

    [Fact]
    public void A_signature_record_names_the_signer_and_compares_it_with_the_manifest_publisher()
    {
        var matching = View(Package(Manifest, Signature(Publisher), Files())).Signature;
        Assert.Equal(("signed", true), (matching.Status, matching.PublisherMatches));
        Assert.Contains("Example Publisher", matching.Subject);
        var other = View(Package(Manifest, Signature("CN=Someone Else"), Files())).Signature;
        Assert.Equal(false, other.PublisherMatches);
    }

    [Fact]
    public void A_missing_or_damaged_signature_is_unsigned_or_unreadable()
    {
        Assert.Equal("unsigned", View(Package(Manifest, null, Files())).Signature.Status);
        Assert.Equal("unreadable", View(Package(Manifest, "PKCXnot a signature"u8.ToArray(), Files())).Signature.Status);
    }

    [Fact]
    public void A_file_changed_after_the_block_map_was_written_is_named()
    {
        var original = Files();
        var bytes = Package(Manifest, null, Files([9, 9, 9, 9]), _ => BlockMap(Named([("AppxManifest.xml", Encoding.UTF8.GetBytes(Manifest)), .. original])));
        var check = View(bytes).BlockMap!;
        Assert.Equal(["Tool.exe"], check.Modified);
        Assert.Empty(check.NotInMap);
        Assert.Empty(check.NotInPackage);
        Assert.Equal(original.Length + 1, check.Files);
    }

    [Fact]
    public void An_unchanged_package_matches_its_block_map_including_escaped_names()
    {
        var check = View(Package(Manifest, null, Files(), files => BlockMap(files))).BlockMap!;
        Assert.True(check.Modified.Count + check.NotInMap.Count + check.NotInPackage.Count == 0, string.Join("|", check.Modified.Concat(check.NotInMap).Concat(check.NotInPackage)));
        Assert.Equal(check.Files, check.Hashed);
    }

    [Fact]
    public void A_bundle_lists_its_packages()
    {
        const string bundle = """
            <Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle"><Identity Name="Example.Tool" Publisher="CN=Example" Version="1.0.0.0" />
              <Packages><Package Type="application" Version="1.0.0.0" Architecture="x64" FileName="Tool_x64.msix" /><Package Type="resource" FileName="Tool_en.msix" /></Packages></Bundle>
            """;
        var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var s = zip.CreateEntry("AppxMetadata/AppxBundleManifest.xml").Open();
            s.Write(Encoding.UTF8.GetBytes(bundle));
        }
        var facts = View(ms.ToArray(), "tool.msixbundle");
        Assert.Equal("MSIX bundle", facts.Kind);
        Assert.Equal(["Tool_x64.msix", "Tool_en.msix"], facts.Packages.Select(p => p.FileName));
    }

    [Fact]
    public void A_zip_without_a_manifest_is_not_an_MSIX_package()
    {
        var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true)) zip.CreateEntry("a.txt");
        Assert.Null(new MsixFileView().Inspect(new FileInput("a.zip", ms.ToArray(), "zip"), default));
    }

    private static (string, byte[])[] Plain(params (string, byte[])[] extra) =>
        [("Tool.exe", [1, 2, 3, 4]), .. extra];

    private FileView Inspect(byte[] bytes, MsixFileView? view = null, string name = "tool.msix")
    {
        var result = (view ?? new MsixFileView()).Inspect(new FileInput(name, bytes, Blob.Identify(bytes)), default)!;
        foreach (var h in result.Highlights) output.WriteLine(h);
        return result;
    }

    [Fact]
    public void A_file_in_the_map_but_absent_and_a_file_absent_from_the_map_are_named()
    {
        var bytes = Package(Manifest, null, Plain(("Extra.bin", [1])),
            files => BlockMap([.. files.Where(f => f.Name != "Extra.bin"), ("Ghost.bin", [1])]));
        var check = View(bytes).BlockMap!;
        Assert.Equal(["Extra.bin"], check.NotInMap);
        Assert.Equal(["Ghost.bin"], check.NotInPackage);
    }

    [Fact]
    public void Lists_cut_at_twenty_report_the_full_count_and_the_cut()
    {
        var extra = Enumerable.Range(0, 25).Select(i => ($"extra{i}.bin", new byte[] { 1 })).ToArray();
        var bytes = Package(Manifest, null, Plain(extra),
            files => BlockMap([.. files.Where(f => !f.Name.StartsWith("extra"))]));
        var check = View(bytes).BlockMap!;
        Assert.Equal((20, 25), (check.NotInMap.Count, check.NotInMapCount));
        Assert.Contains("first 20 of 25 not in the map", check.Partial);
    }

    [Fact]
    public void Files_over_the_hash_budget_are_reported_as_not_hashed()
    {
        var bytes = Package(Manifest, null, Plain(("Big.bin", new byte[100])), files => BlockMap(files));
        var check = ((MsixFileView.Facts)Inspect(bytes, new MsixFileView(50)).Detail).BlockMap!;
        Assert.Equal(1, check.Hashed);
        Assert.Contains("(over the 50 byte budget)", check.Partial);
        Assert.Empty(check.Modified);
    }

    [Fact]
    public void A_block_map_with_another_hash_method_is_not_hashed()
    {
        var bytes = Package(Manifest, null, Plain(),
            files => BlockMap(files).Replace("xmlenc#sha256", "xmlenc#sha512"));
        var check = View(bytes).BlockMap!;
        Assert.Equal(0, check.Hashed);
        Assert.Contains("hash method is not SHA-256", check.Partial);
    }

    [Fact]
    public void A_malformed_block_map_is_unreadable_not_absent()
    {
        var view = Inspect(Package(Manifest, null, Plain(), _ => "<BlockMap"));
        Assert.Null(((MsixFileView.Facts)view.Detail).BlockMap);
        Assert.Contains(view.Highlights, h => h.StartsWith("AppxBlockMap.xml is unreadable"));
        Assert.Contains(view.Highlights, h => h.StartsWith("Next: unpack_container path=<package>"));
    }

    [Fact]
    public void A_package_without_a_block_map_says_no_map_is_readable()
    {
        var view = Inspect(Package(Manifest, null, Plain()));
        Assert.Null(((MsixFileView.Facts)view.Detail).BlockMap);
        Assert.Contains(view.Highlights, h => h.StartsWith("AppxBlockMap.xml is absent"));
    }

    [Fact]
    public void An_empty_file_with_no_blocks_matches_its_block_map()
    {
        var check = View(Package(Manifest, null, Plain(("Empty.bin", [])), files => BlockMap(files))).BlockMap!;
        Assert.Empty(check.Modified);
        Assert.Equal(check.Files, check.Hashed);
    }

    [Fact]
    public void A_signature_whose_signed_content_changed_is_invalid()
    {
        var signature = Signature(Publisher);
        var at = signature.AsSpan().IndexOf("APPX digests"u8);
        signature[at + 11] = (byte)'x';
        Assert.Equal("invalid", View(Package(Manifest, signature, Plain())).Signature.Status);
    }

    [Fact]
    public void A_cancelled_call_stops_the_block_map_scan()
    {
        var bytes = Package(Manifest, null, Plain(), files => BlockMap(files));
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() =>
            new MsixFileView().Inspect(new FileInput("t.msix", bytes, Blob.Identify(bytes)), cts.Token));
    }

    [Fact]
    public void Entries_past_the_scan_cap_are_not_reported_missing()
    {
        var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            void Put(string name, byte[] data)
            {
                using var s = zip.CreateEntry(name).Open();
                s.Write(data);
            }
            Put("AppxManifest.xml", Encoding.UTF8.GetBytes(Manifest));
            Put("AppxBlockMap.xml", Encoding.UTF8.GetBytes(BlockMap(("Tool.exe", [1, 2, 3, 4]), ("Late.bin", [1]))));
            Put("Tool.exe", [1, 2, 3, 4]);
            for (var i = 0; i < 50_000; i++) Put($"f{i}", []);
            Put("Late.bin", [1]);
        }
        var view = Inspect(ms.ToArray());
        var check = ((MsixFileView.Facts)view.Detail).BlockMap!;
        Assert.Empty(check.NotInPackage);
        Assert.Equal(-1, check.NotInPackageCount);
        Assert.Contains("scanned 50000 of", check.Partial);
        Assert.Contains(view.Highlights, h => h.Contains("missing from the package unknown"));
    }

    [Fact]
    public void An_oversized_or_malformed_manifest_keeps_the_notes_and_names_the_limit()
    {
        var oversized = Inspect(Package("<!--" + new string('a', (4 << 20) + 1) + "-->", null, Plain()));
        Assert.Contains(oversized.Highlights, h => h.Contains("AppxManifest.xml: unreadable"));
        Assert.Contains(oversized.Highlights, h => h.Contains("read limit"));
        var malformed = Inspect(Package("<Package", null, Plain()));
        Assert.Contains(malformed.Highlights, h => h.Contains("AppxManifest.xml: unreadable"));
        Assert.Single(((MsixFileView.Facts)malformed.Detail).Notes);
    }

    [Fact]
    public void A_script_stored_under_an_escaped_name_is_found()
    {
        const string config = """
            { "applications": [ { "id": "App", "startScript": { "scriptPath": "my script.ps1" } } ] }
            """;
        var files = Plain(("PSFLauncher64.exe", [5]), ("config.json", Encoding.UTF8.GetBytes(config)), ("my%20script.ps1", [1]));
        var script = Assert.Single(Assert.Single(View(Package(Manifest, null, files)).Psf!.Applications).Scripts);
        Assert.True(script.InPackage);
    }

    [Fact]
    public void The_config_next_to_the_launcher_wins_over_an_unrelated_config()
    {
        var files = Plain(("App/PSFLauncher64.exe", [5]), ("App/config.json", Encoding.UTF8.GetBytes(PsfConfig)),
            ("x/config.json", "{}"u8.ToArray()));
        Assert.Equal("App/config.json", View(Package(Manifest, null, files)).Psf!.Config);
        var unrelated = Plain(("PSFLauncher64.exe", [5]), ("x/config.json", "{}"u8.ToArray()));
        Assert.Null(View(Package(Manifest, null, unrelated)).Psf);
    }

    [Fact]
    public void A_bundle_names_unpack_container_as_the_next_call()
    {
        const string bundle = """
            <Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle"><Identity Name="Example.Tool" Publisher="CN=Example" Version="1.0.0.0" /><Packages /></Bundle>
            """;
        var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var s = zip.CreateEntry("AppxMetadata/AppxBundleManifest.xml").Open();
            s.Write(Encoding.UTF8.GetBytes(bundle));
        }
        Assert.Contains(Inspect(ms.ToArray(), name: "t.msixbundle").Highlights, h => h.Contains("unpack_container path=<bundle>"));
    }

    [Fact]
    [FuzzEntry(typeof(MsixFileView))]
    public void Fuzzed_MSIX_packages_never_throw_past_a_tool_error()
    {
        var seed = Package(Manifest, Signature(Publisher), Files(), files => BlockMap(files));
        var path = Path.Combine(Path.GetTempPath(), "corvus-msix-fuzz-" + Guid.NewGuid().ToString("N") + ".msix");
        try
        {
            var failures = FormatFuzz.Run(seed, b =>
            {
                try { new MsixFileView().Inspect(new FileInput(path, b, Blob.Identify(b)), default); }
                catch (ToolError) { }
            }, 300);
            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
        }
        finally { File.Delete(path); }
    }
}
