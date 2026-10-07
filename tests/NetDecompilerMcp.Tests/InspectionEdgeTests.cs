using System.Text;
using dnlib.DotNet;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Services.Analysis;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Inspection on the shapes the third live pass met: damaged files, IL2CPP games, apphost launchers, big bundles and
/// workspaces, string-helper look-alikes, evidence choice.
/// </summary>
public class InspectionEdgeTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());
    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    private InspectionService Inspection => new(_workspace);

    private string Save(string relative, byte[] bytes)
    {
        var path = _dir.File(relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    [Fact]
    public void DamagedFiles_StillGetTheirFileFacts()
    {
        var fixture = File.ReadAllBytes(Env.FixturePath);
        var truncated = Inspection.Summarize(null, Save("truncated.dll", fixture[..(fixture.Length / 3)]), default);
        Assert.Equal(".NET assembly", truncated.File.Type);
        Assert.Empty(truncated.Assemblies);
        Assert.Contains(truncated.Highlights, h => h.StartsWith("The .NET metadata is damaged:", StringComparison.Ordinal));
        Assert.Equal(64, truncated.File.Sha256.Length);

        var zip = ContainerFixtures.Zip(("lib/A.dll", ContainerFixtures.Module("A", _ => { })), ("lib/B.dll", ContainerFixtures.Module("B", _ => { })));
        var cut = Inspection.Summarize(null, Save("cut.nupkg", zip[..20]), default);
        Assert.Equal("unreadable container", cut.Container);
        Assert.Contains(cut.Highlights, h => h.StartsWith("The file is damaged:", StringComparison.Ordinal));
    }

    [Fact]
    public void Il2CppGames_AreRecognized()
    {
        // layout: GameAssembly.dll + Game_Data/il2cpp_data/Metadata/global-metadata.dat
        var root = _dir.File("il2cppgame");
        Save("il2cppgame/GameAssembly.dll", [0x4D, 0x5A, 0, 0]);
        var metadata = Save("il2cppgame/Game_Data/il2cpp_data/Metadata/global-metadata.dat", [0xAF, 0x1B, 0xB1, 0xFA, 29, 0, 0, 0, 1, 2, 3, 4]);
        Assert.Contains(GameLayout.FolderHints(root), h => h.StartsWith("Unity IL2CPP game") && h.Contains(Path.GetFullPath(metadata)));
        Assert.StartsWith("Unity IL2CPP metadata", GameLayout.FileHint(metadata, File.ReadAllBytes(metadata)));
        Assert.Contains(Inspection.Summarize(null, metadata, default).Highlights, h => h.StartsWith("Unity IL2CPP metadata"));

        // a Mono game loaded from its root: the assemblies are in *_Data/Managed
        var mono = _dir.File("monogame");
        Save("monogame/Game_Data/Managed/Assembly-CSharp.dll", ContainerFixtures.Module("Assembly-CSharp", _ => { }));
        Assert.Contains(GameLayout.FolderHints(mono), h => h.StartsWith("Unity (Mono) game") && h.Contains(Path.Combine(mono, "Game_Data", "Managed")));

        // a real IL2CPP binary on this machine, when there is one
        var real = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Programs\WildWorks\Animal Jam\Data\build\GameAssembly.dll");
        if (File.Exists(real))
            Assert.StartsWith("Unity IL2CPP game code", GameLayout.FileHint(real, File.ReadAllBytes(real)));
    }

    [Fact]
    public void FolderLoad_GroupsNativeFiles_AndHintsGameLayouts()
    {
        var root = _dir.File("mixed");
        File.Copy(Env.FixturePath, Save("mixed/TestFixture.dll", []), overwrite: true);
        File.Copy(Path.Combine(Environment.SystemDirectory, "kernel32.dll"), Save("mixed/native1.dll", []), overwrite: true);
        Save("mixed/native2.dll", Encoding.ASCII.GetBytes("not a PE at all"));
        Save("mixed/GameAssembly.dll", [0x4D, 0x5A]);
        var text = WorkspaceTools.FormatLoad(_workspace, root, _workspace.LoadDirectory(root, false));
        Assert.True(text.Contains("skipped 2 native or non-PE files: native1.dll, native2.dll"), text); // the 2-byte GameAssembly.dll is a damaged PE: listed on its own
        Assert.DoesNotContain("data directory RVA", text);
        Assert.Contains("Note: Unity IL2CPP game", text);
    }

    [Fact]
    public void ApphostLauncher_SummarizesTheAppNextToIt()
    {
        var host = Directory.EnumerateFiles(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "packs"), "apphost.exe", SearchOption.AllDirectories)
            .FirstOrDefault();
        if (host == null) return; // needs a .NET SDK's apphost
        var exe = Save("app/TestFixture.exe", File.ReadAllBytes(host));
        File.Copy(Env.FixturePath, Path.Combine(Path.GetDirectoryName(exe)!, "TestFixture.dll"));
        var s = Inspection.Summarize(null, exe, default);
        Assert.StartsWith(".NET apphost", s.Container);
        Assert.Equal("TestFixture", Assert.Single(s.Assemblies).Identity.Name);
        Assert.Contains("Using the application next to the launcher: TestFixture.dll.", s.Notes);
        Assert.Equal(UnpackService.ApphostAppOrigin, new UnpackService(_workspace).Unpack(exe, _dir.File("app-out"), false, AnalysisLimits.Default, default).Files[0].Origin);
    }

    [Fact]
    public void BigContainers_AreListedInPages()
    {
        var entries = Enumerable.Range(0, 130).Select(i => ($"lib/A{i:D3}.dll", ContainerFixtures.Module($"A{i:D3}", _ => { })))
            .Concat(Enumerable.Range(0, 10).Select(i => ($"de/App{i}.resources.dll", ContainerFixtures.Module($"App{i}.resources", _ => { })))).ToArray();
        var zip = Save("big.zip", ContainerFixtures.Zip(entries));
        var listing = new UnpackService(_workspace).List(zip, AnalysisLimits.Default, default);
        Assert.Equal(UnpackService.MaxListed, listing.Assemblies.Count);
        Assert.DoesNotContain(listing.Assemblies, a => a.Path.Contains(".resources")); // translations last, past the cut
        Assert.Contains(listing.Notes, n => n.StartsWith("140 assemblies; 100 listed"));
        var unpacked = new UnpackService(_workspace).Unpack(zip, _dir.File("big-out"), false, AnalysisLimits.Default, default);
        Assert.Equal(UnpackService.MaxListed, unpacked.Files.Count);
        Assert.Contains(unpacked.Notes, n => n.StartsWith("140 files written to"));
        Assert.Equal(140, Directory.EnumerateFiles(_dir.File("big-out"), "*.dll", SearchOption.AllDirectories).Count());
    }

    [Fact]
    public async Task ListAssemblies_FiltersAndPages()
    {
        _workspace.LoadDirectory(Path.GetDirectoryName(Env.FixturePath)!, false);
        var tools = new WorkspaceTools(_workspace, new Il2CppService(_workspace), new AssemblyReport(_workspace, new Il2CppService(_workspace)),
            new IndexingService(_workspace, new CallGraphService(_workspace), new ServerOptions()), new UnpackService(_workspace));
        var all = await tools.ListAssemblies();
        Assert.True(all.Total > 3);
        var page = await tools.ListAssemblies(offset: 1, limit: 2);
        Assert.Equal(2, page.Assemblies.Count);
        Assert.Equal(all.Total, page.Total);
        Assert.Equal(all.Assemblies[1].Id, page.Assemblies[0].Id);
        var fixtures = await tools.ListAssemblies(filter: "testfixture");
        Assert.All(fixtures.Assemblies, a => Assert.Contains("TestFixture", a.Id, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(fixtures.Assemblies.Count, fixtures.Total);
    }

    [Fact]
    public void StringDecryptor_NeedsDecoding_NotJustAnIntToStringHelper()
    {
        var calls = string.Join(" ", Enumerable.Range(0, 12).Select(i => $"public static string C{i}() => Pad({i}) + D({i});"));
        var path = Save("Strings.dll", ReferenceResolutionTests.Compile("Strings", $$"""
            public static class S
            {
                private static readonly byte[] Data = { 0x41, 0x42, 0x43, 0x44 };
                public static string Pad(int n) => new string(' ', n);                          // formatting helper
                public static string D(int i) => ((char)(Data[i % 4] ^ 0x20)).ToString();        // decodes static data
                {{calls}}
            }
            """));
        var markers = Inspection.Summarize(null, path, default).Assemblies.Single().Markers;
        Assert.Contains(markers.Indicators, i => i.StartsWith("Possible string decryptor S::D(int)"));
        Assert.DoesNotContain(markers.Indicators, i => i.Contains("S::Pad"));
    }

    [Fact]
    public void SummaryEvidence_PrefersTheDecidingString()
    {
        var path = Save("Runner.dll", ReferenceResolutionTests.Compile("Runner",
            "public static class R { public static void Go() { System.Diagnostics.Process.Start(\"powershell.exe\", \"-NoProfile\"); } }"));
        var feature = Inspection.Summarize(null, path, default).Assemblies.Single().Features.Single(f => f.Name == "run PowerShell");
        Assert.StartsWith("str:", Assert.Single(feature.Evidence).Feature);
    }

    [Fact]
    public void CosturaEmbeddedAssemblies_AreCountedNotHighlightedOneByOne()
    {
        var host = Save("Host.exe", ContainerFixtures.Module("Host",
            ("costura.testfixture.dll.compressed", ContainerFixtures.Deflate(File.ReadAllBytes(Env.FixturePath)))));
        var s = Inspection.Summarize(null, host, default);
        Assert.Contains("[Host.exe] 1 embedded assembly(ies) (Costura or similar).", s.Highlights);
        Assert.DoesNotContain(s.Highlights, h => h.Contains("Embedded .NET assembly"));
    }
    [Fact]
    public void TruncatedZip_RecoversTheCompleteEntries()
    {
        var ms = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var n in new[] { "A", "B" })
                using (var s = zip.CreateEntry($"lib/{n}.dll").Open())
                    s.Write(ReferenceResolutionTests.Compile(n, $"public class {n}Type {{ }}"));
        }
        var full = ms.ToArray();
        // cut inside the second entry: no central directory, the first entry still whole
        var secondHeader = full.AsSpan(4).IndexOf("PK\u0003\u0004"u8) + 4;
        var cut = full[..(secondHeader + 40)];
        var contents = Containers.Open(cut, "cut.zip", AnalysisLimits.Default, default);
        Assert.Equal("lib/A.dll", Assert.Single(contents.Items).Name);
        Assert.Contains(contents.Notes, n => n.StartsWith("Damaged zip") && n.Contains("1 entr(ies) recovered"));
        Assert.Throws<ToolError>(() => Containers.Open(full[..20], "tiny.zip", AnalysisLimits.Default, default));
    }

    /// <summary>A stream that cannot seek: ZipArchive then writes each entry's sizes in a data descriptor after it.</summary>
    private sealed class ForwardOnly(Stream inner) : Stream
    {
        public override bool CanRead => false; public override bool CanSeek => false; public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => inner.Position; set => throw new NotSupportedException(); }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
    }

    [Fact]
    public void StreamedZip_WithoutCentralDirectory_RecoversEveryEntry_AndStepsOverBadOnes()
    {
        var ms = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(new ForwardOnly(ms), System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var n in new[] { "A", "B", "C", "D" })
                using (var s = zip.CreateEntry($"lib/{n}.dll").Open())
                    s.Write(ReferenceResolutionTests.Compile(n, $"public class {n}Type {{ }}"));
        }
        var full = ms.ToArray();
        var headers = new List<int>();
        for (int i = full.AsSpan().IndexOf("PK\u0003\u0004"u8); i >= 0;)
        {
            headers.Add(i);
            int nextAt = full.AsSpan(i + 4).IndexOf("PK\u0003\u0004"u8);
            i = nextAt < 0 ? -1 : i + 4 + nextAt;
        }
        Assert.Equal(4, headers.Count);
        Assert.All(headers, h => Assert.True((full[h + 6] & 0x08) != 0)); // sizes in descriptors

        // central directory gone
        var central = full.AsSpan().IndexOf("PK\u0001\u0002"u8);
        var cut = full[..central];
        cut[headers[1] + 6] |= 0x01;                    // B: marked encrypted
        cut[headers[2] + 30 + 9 + 20] ^= 0xFF;          // C: data damaged (inside its compressed bytes)

        var contents = Containers.Open(cut, "streamed.zip", AnalysisLimits.Default, default);
        Assert.Equal(["lib/A.dll", "lib/D.dll"], contents.Items.Select(i => i.Name).ToArray());
        Assert.Contains("Skipped lib/B.dll: encrypted.", contents.Notes);
        Assert.Contains(contents.Notes, n => n.StartsWith("Skipped lib/C.dll:"));
        Assert.Contains(contents.Notes, n => n.StartsWith("Damaged zip") && n.Contains("2 entr(ies) recovered") && !n.Contains("lost"));
        Assert.All(contents.Items, i => Assert.Equal(".NET assembly", Blob.Identify(i.Bytes)));
    }
}
