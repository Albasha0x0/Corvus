using System.Resources;
using System.Text;
using dnlib.DotNet;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Services.Analysis;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// The shapes of real apps that the second live pass ran into (a Costura-packed WPF app full of images, a single-file
/// bundle with translations, a NuGet package with one build per target, an APK without .NET), rebuilt as small fixtures.
/// </summary>
public class RealWorldShapeTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());
    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    private InspectionService Inspection => new(_workspace);

    private string Save(string name, byte[] bytes)
    {
        var path = _dir.File(name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static byte[] Random(int length, int seed)
    {
        var b = new byte[length];
        new Random(seed).NextBytes(b);
        return b;
    }

    private static byte[] Png(int seed) => [0x89, (byte)'P', (byte)'N', (byte)'G', 0x0D, 0x0A, 0x1A, 0x0A, .. Random(3000, seed)];

    /// <summary>A WPF-style ".g.resources" container: images and a large compressed asset.</summary>
    private static byte[] GResources()
    {
        using var ms = new MemoryStream();
        using (var writer = new ResourceWriter(ms))
        {
            for (int i = 0; i < 4; i++) writer.AddResource($"images/icon{i}.png", Png(i));
            writer.AddResource("assets/blob.bin", Random(8000, 99));
            writer.Generate();
        }
        return ms.ToArray();
    }

    // ------------------------------------------------------------------ text, PDBs, containers of resources, XOR

    [Fact]
    public void RandomBinary_IsNotText_ButUtf8AndAsciiAre()
    {
        var garbage = new byte[] { 0x4E, 0x17, 0xC3, 0xE8, 0xDE, 0x9E, 0xE9, 0x68, 0xA9, 0x47, 0xB5, 0xF2, 0xE8, 0xB5, 0xAB, 0xDA, 0x8A, 0x56, 0xBC, 0xD4, 0xF1, 0x71 };
        Assert.False(Blob.LooksLikeText(garbage)); // high bytes that do not form UTF-8 (base64 of junk decodes to this)
        Assert.True(Blob.LooksLikeText(Encoding.UTF8.GetBytes("工具SkinId：不存在！ - a translated message")));
        Assert.True(Blob.LooksLikeText(Encoding.Latin1.GetBytes("A plain sentence with one café in it, mostly ASCII.")));
        Assert.Equal("portable pdb", Blob.Identify("BSJB\x01\x00\x01\x00"u8));
        Assert.Equal("pdb", Blob.Identify(Encoding.ASCII.GetBytes("Microsoft C/C++ MSF 7.00\r\n\u001aDS\0\0\0")));
    }

    [Fact]
    public void Embedded_ResourcesContainerIsNotABlob_ImagesAreCounted_PdbsRecognized()
    {
        var pdb = File.ReadAllBytes(Path.ChangeExtension(Env.FixturePath, ".pdb"));
        var host = Save("App.exe", ContainerFixtures.Module("App",
            ("App.g.resources", GResources()),
            ("costura.app.pdb.compressed", ContainerFixtures.Deflate(pdb)),
            ("junk", Encoding.ASCII.GetBytes(Convert.ToBase64String(Random(48, 7))))));
        var report = Inspection.ExtractEmbedded(null, host, false, null, false, default);
        Assert.DoesNotContain(report.Contents, c => c.Source == "resource 'App.g.resources'"); // its entries are examined instead
        Assert.Contains(report.Contents, c => c.Source == "resource 'App.g.resources:assets/blob.bin'" && c.Kind.StartsWith("high-entropy"));
        Assert.DoesNotContain(report.Contents, c => c.Kind == "png");
        Assert.Contains(report.Notes, n => n == "Images not listed: 4 png (includeMedia=true lists and saves them).");
        var pdbItem = Assert.Single(report.Contents, c => c.Source == "resource 'costura.app.pdb.compressed'");
        Assert.Equal(("portable pdb", "deflate"), (pdbItem.Kind, string.Join(">", pdbItem.Encoding)));
        Assert.DoesNotContain(report.Contents, c => c.Kind == "text"); // base64 of random bytes is not text
        Assert.Equal(4, Inspection.ExtractEmbedded(null, host, false, null, false, default, includeMedia: true).Contents.Count(c => c.Kind == "png"));
    }

    [Fact]
    public void XorZip_NeedsARealArchive_NotJustTheMarkers()
    {
        // data that a 4-byte key turns into "PK\x03\x04" at the start and "PK\x05\x06" further on: not an archive
        var data = Random(4096, 3);
        var key = new byte[4];
        for (int i = 0; i < 4; i++) key[i] = (byte)(data[i] ^ "PK\x03\x04"u8[i]);
        for (int i = 0; i < 4; i++) data[2000 + i] = (byte)("PK\x05\x06"u8[i] ^ key[(2000 + i) % 4]);
        Assert.Null(Embedded.TryXor(data));

        // a real zip under the same kind of key is still recovered
        var zip = ContainerFixtures.Zip(("readme.txt", Encoding.ASCII.GetBytes("hello from inside")));
        var xored = zip.Select((b, i) => (byte)(b ^ new byte[] { 0x5A, 0x13, 0x77, 0xC1 }[i % 4])).ToArray();
        Assert.Equal(zip, Embedded.TryXor(xored)!.Value.Decoded);
    }

    // ------------------------------------------------------------------ extracted values

    [Fact]
    public void Values_VersionNumbersAreNotAddresses_PathsStopAtQuotes()
    {
        var path = Save("Values.dll", ContainerFixtures.Module("Values",
            ("costura.metadata", Encoding.ASCII.GetBytes(
                "costura.a.dll.compressed|4.0.3.0|A, Version=4.0.3.0, Culture=neutral|A.dll|ABC|1\r\nversion 5.0.0.1 and v2.1.0.4 and connect to 10.20.30.40\r\n" +
                "Start-Process -FilePath 'C:\\Program Files\\App\\App.exe' -ArgumentList $a -WindowStyle Hidden;Remove-Item -Path $sp\r\n"))));
        var values = Inspection.ExtractStrings(null, path, ["ipv4", "file_path"], null, null, false, default).Values;
        Assert.Equal(["10.20.30.40"], values.Where(v => v.Type == "ipv4").Select(v => v.Value));
        Assert.Equal(["C:\\Program Files\\App\\App.exe"], values.Where(v => v.Type == "file_path").Select(v => v.Value));
    }

    // ------------------------------------------------------------------ summarize_file

    [Fact]
    public void Summary_CosturaHostFirst_ImagesCounted_ResourcesDoNotMakeTextHighEntropy()
    {
        var fixture = File.ReadAllBytes(Env.FixturePath);
        var host = Save("Host.exe", ContainerFixtures.Module("Host",
            ("Host.g.resources", GResources()),
            ("big.bin", Random(300_000, 5)), // compressed assets in managed resources live in .text
            ("costura.testfixture.dll.compressed", ContainerFixtures.Deflate(fixture)),
            ("costura.testfixture.pdb.compressed", ContainerFixtures.Deflate(File.ReadAllBytes(Path.ChangeExtension(Env.FixturePath, ".pdb")))),
            ("costura.metadata", Encoding.ASCII.GetBytes("costura.testfixture.dll.compressed|1.0.0.0|TestFixture|TestFixture.dll|X|1"))));
        var s = Inspection.Summarize(null, host, default);
        Assert.Equal("Costura.Fody (embedded assemblies)", s.Container);
        Assert.Equal(["Host", "TestFixture"], s.Assemblies.Select(a => a.Identity.Name));
        var main = s.Assemblies[0];
        Assert.Equal(1, main.Packing.EmbeddedAssemblyTotal); // the PDB and the metadata file are not assemblies
        Assert.Empty(main.Packing.HighEntropySections);
        Assert.DoesNotContain(main.Packing.Contents, c => c.Kind == "png");
        Assert.Contains(main.Notes, n => n.Contains("images not listed: 4 png"));
        Assert.Contains("[Host.exe] 1 embedded assembly(ies) (Costura or similar).", s.Highlights);
        Assert.Empty(s.Assemblies[1].Highlights); // brief
        Assert.Empty(s.Assemblies[1].Values.Top);
    }

    [Fact]
    public void Summary_MainAssemblyFirst_SatellitesSkipped_FrameworkQuiet_CopiesOnce()
    {
        // real satellites and per-target builds differ in content (identical files are listed once by the container walker)
        static byte[] Variant(string name, string marker) => ContainerFixtures.Module(name, m => m.Types.Add(new TypeDefUser("", marker, m.CorLibTypes.Object.TypeDefOrRef)));
        var zip = Save("App.zip", ContainerFixtures.Zip(
            ("lib/Helper.dll", ContainerFixtures.Module("Helper", _ => { })),
            ("de/App.resources.dll", Variant("App.resources", "De")),
            ("fr/App.resources.dll", Variant("App.resources", "Fr")),
            ("System.Text.Json.dll", File.ReadAllBytes(typeof(System.Text.Json.JsonSerializer).Assembly.Location)),
            ("net48/App.dll", Variant("App", "Net48")),
            ("net8.0/App.dll", Variant("App", "Net80"))));
        var s = Inspection.Summarize(null, zip, default);
        Assert.Equal(["App", "Helper", "System.Text.Json"], s.Assemblies.Select(a => a.Identity.Name));
        Assert.Contains("2 satellite resource assembly(ies) (translations) not summarized.", s.Notes);
        Assert.Contains(s.Notes, n => n.StartsWith("App: 1 more build(s) of the same assembly not summarized (net8.0/App.dll)"));
        Assert.DoesNotContain(s.Highlights, h => h.StartsWith("[System.Text.Json.dll]")); // a framework library's capabilities are not findings
    }

    [Fact]
    public void Android_WithoutDotNet_IsLabelledSo()
    {
        var apk = Save("app.apk", ContainerFixtures.Zip(("AndroidManifest.xml", [1, 2, 3]), ("classes.dex", [4, 5, 6]), ("lib/arm64-v8a/libfoo.so", [7])));
        Assert.Equal("Android package (no .NET runtime or assemblies)", Inspection.Summarize(null, apk, default).Container);
        var xamarin = Save("x.apk", ContainerFixtures.Zip(("AndroidManifest.xml", [1]), ("assemblies/App.dll", ContainerFixtures.Module("App", _ => { }))));
        Assert.Equal("Android package (Xamarin / MAUI)", Inspection.Summarize(null, xamarin, default).Container);
    }

    [Fact]
    public void Certificates_TimestampedSignatureWithAnExpiredCertificate_IsTrusted()
    {
        if (!OperatingSystem.IsWindows()) return; // needs the Windows root store
        // any Authenticode-signed file on this machine whose signing certificate has expired since it was timestamped
        var candidates = new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) + @"\dotnet\shared", Environment.SystemDirectory }
            .Where(Directory.Exists)
            .SelectMany(d => Directory.EnumerateFiles(d, "*.dll", SearchOption.AllDirectories).Take(4000));
        foreach (var file in candidates)
        {
            byte[] bytes;
            try { bytes = File.ReadAllBytes(file); } catch (IOException) { continue; } catch (UnauthorizedAccessException) { continue; }
            var c = Certificates.Read(bytes);
            if (!c.Present || c.Timestamp == null || c.NotAfter > DateTime.UtcNow || c.DigestMatches != true) continue;
            Assert.StartsWith("trusted on this machine (timestamped ", c.Chain);
            return;
        }
    }

    // ------------------------------------------------------------------ workspace and editing messages

    [Fact]
    public async Task AddSearchDirectory_WithoutAssemblies_PointsToTheSubfolders()
    {
        var root = _dir.File("shared");
        Directory.CreateDirectory(Path.Combine(root, "8.0.1"));
        File.Copy(Env.FixturePath, Path.Combine(root, "8.0.1", "TestFixture.dll"));
        var tools = new NetDecompilerMcp.Tools.WorkspaceTools(_workspace, new Il2CppService(_workspace), new AssemblyReport(_workspace, new Il2CppService(_workspace)),
            new IndexingService(_workspace, new CallGraphService(_workspace), new ServerOptions()), new UnpackService(_workspace));
        var text = await tools.AddSearchDirectory(root);
        Assert.Contains("has no assemblies itself; subfolders are not searched. Add one of these instead:", text);
        Assert.Contains(Path.Combine(root, "8.0.1"), text);
    }

    [Fact]
    public void UndoConflict_NamesTheEditByItsListNumber()
    {
        using var env = new Env();
        env.Edit(() => env.Edits.StubMethod(env.One("Secret::Validate"), "true"));                                                     // #1
        env.Edit(() => env.Edits.AddMembersCSharp(env.One("Fixture.Model.Account", SymbolKind.Type), "public int Bonus() => 7;", false, default)); // #2
        env.Edit(() => env.Edits.PatchMethodCSharp(env.One("Account::Score"), "return Bonus();", false, default));                          // #3 uses #2
        var error = Assert.Throws<ToolError>(() => env.Edit(() => env.Edits.Undo(env.Fixture, 2, default))).Message;
        Assert.StartsWith("Edit #3 (patch C# Fixture.Model.Account::Score()) could not be re-applied:", error);
        Assert.EndsWith("\nNothing was changed.", error);
        Assert.Equal(1, error.Split("Nothing was changed.").Length - 1);
    }

    [Fact]
    public void IlPrepend_OntoAnEncryptedBody_SaysWhy()
    {
        var bytes = File.ReadAllBytes(Env.FixturePath);
        // overwrite one method's code with bytes that are not IL
        using (var pe = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(bytes)))
        {
            var md = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
            foreach (var h in md.MethodDefinitions)
            {
                var def = md.GetMethodDefinition(h);
                if (md.GetString(def.Name) != "CheckLicense") continue;
                var body = System.Reflection.Metadata.PEReaderExtensions.GetMethodBody(pe, def.RelativeVirtualAddress);
                var section = pe.PEHeaders.SectionHeaders.First(s => def.RelativeVirtualAddress >= s.VirtualAddress && def.RelativeVirtualAddress < s.VirtualAddress + s.VirtualSize);
                int offset = def.RelativeVirtualAddress - section.VirtualAddress + section.PointerToRawData;
                int start = offset + ((bytes[offset] & 3) == 2 ? 1 : 12);
                for (int i = 0; i < body.Size; i++) bytes[start + i] = 0xA6;
            }
        }
        using var env = new Env(Save("enc/TestFixture.dll", bytes));
        var error = Assert.Throws<ToolError>(() => env.Edit(() => env.Edits.PatchMethodIL(env.One("Account::CheckLicense"), "nop", "prepend", false))).Message;
        Assert.Contains("is not valid IL (encrypted, or dumped from memory before decryption): there is no code to prepend to", error);
        env.Edit(() => env.Edits.PatchMethodIL(env.One("Account::CheckLicense"), "ldc.i4.1\nret", "replace", false)); // replace still works
    }

    [Fact]
    public void Binding_InheritedGenericProperty_CommentShowsTheTypeArgument()
    {
        using var env = new Env();
        var code = new CppBindingGenerator().Generate(env.Fixture, env.Def<TypeDef>("Fixture.Model.Bank", SymbolKind.Type), ["Instance"], false, "mono");
        Assert.Contains("// public static T Instance { get; }  [T = Bank, declared on Fixture.Model.Singleton`1]", code);
    }
}
