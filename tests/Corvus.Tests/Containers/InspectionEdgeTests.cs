using System.Text;
using dnlib.DotNet;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Inspection edge cases: damaged files, AOT builds, apphost launchers, large containers, heuristics.</summary>
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
    public void Damaged_files_still_get_their_file_facts()
    {
        var fixture = File.ReadAllBytes(Env.FixturePath);
        var truncated = Inspection.Summarize(null, Save("truncated.dll", fixture[..(fixture.Length / 3)]), default);
        Assert.Equal(".NET assembly", truncated.File.Type);
        Assert.Empty(truncated.Assemblies);
        Assert.Contains(truncated.Highlights, h => h.StartsWith("The .NET metadata is damaged:", StringComparison.Ordinal));
        Assert.Equal(64, truncated.File.Sha256.Length);

        var zip = ContainerFixtures.Zip(("lib/A.dll", ContainerFixtures.Module("A", _ => { })), ("lib/B.dll", ContainerFixtures.Module("B", _ => { })));
        var cutPath = Save("cut.nupkg", zip[..20]);
        var cut = Inspection.Summarize(null, cutPath, default);
        Assert.Equal("unreadable container", cut.Container);
        Assert.Contains(cut.Highlights, h => h.StartsWith("The file is damaged:", StringComparison.Ordinal));
        // No handle left open (Windows refuses the delete otherwise).
        File.Delete(cutPath);
        Assert.False(File.Exists(cutPath));
    }

    [Fact]
    public void AOT_builds_are_recognized()
    {
        // AOT build layout: GameAssembly.dll + *_Data/il2cpp_data/Metadata/global-metadata.dat.
        var root = _dir.File("aotbuild");
        Save("aotbuild/GameAssembly.dll", [0x4D, 0x5A, 0, 0]);
        var metadata = Save("aotbuild/App_Data/il2cpp_data/Metadata/global-metadata.dat", [0xAF, 0x1B, 0xB1, 0xFA, 29, 0, 0, 0, 1, 2, 3, 4]);
        Assert.Contains(PlayerLayout.FolderHints(root), h => h.StartsWith("AOT build: the code is native in GameAssembly.dll") && h.Contains(Path.GetFullPath(metadata)));
        Assert.StartsWith("AOT metadata (global-metadata.dat)", PlayerLayout.FileHint(metadata, File.ReadAllBytes(metadata)));
        Assert.Contains(Inspection.Summarize(null, metadata, default).Highlights, h => h.StartsWith("AOT metadata (global-metadata.dat)"));

        // Mono build layout: assemblies in *_Data/Managed.
        var mono = _dir.File("monobuild");
        Save("monobuild/App_Data/Managed/Assembly-CSharp.dll", ContainerFixtures.Module("Assembly-CSharp", _ => { }));
        Assert.Contains(PlayerLayout.FolderHints(mono), h => h.StartsWith("Mono build") && h.Contains(Path.Combine(mono, "App_Data", "Managed")));
    }

    [Fact]
    public void Folder_load_groups_native_files_and_hints_build_layouts()
    {
        var root = _dir.File("mixed");
        File.Copy(Env.FixturePath, Save("mixed/TestFixture.dll", []), overwrite: true);
        Save("mixed/native1.dll", ContainerFixtures.NativeLibrary());
        Save("mixed/native2.dll", Encoding.ASCII.GetBytes("not a PE at all"));
        Save("mixed/GameAssembly.dll", [0x4D, 0x5A]);
        var text = WorkspaceTools.FormatLoad(_workspace, root, _workspace.LoadDirectory(root, false));
        // The 2-byte GameAssembly.dll counts as a damaged PE.
        Assert.True(text.Contains("skipped 2 native or non-PE files: native1.dll, native2.dll"), text);
        Assert.DoesNotContain("data directory RVA", text);
        Assert.Contains("Note: AOT build", text);
    }

    [Fact]
    public void An_apphost_launcher_summarizes_the_app_next_to_it()
    {
        var root = new DirectoryInfo(System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory());
        while (root != null && !Directory.Exists(Path.Combine(root.FullName, "packs"))) root = root.Parent;
        Assert.NotNull(root);
        var host = Directory.EnumerateFiles(Path.Combine(root.FullName, "packs"), "apphost*", SearchOption.AllDirectories)
            .First(f => Path.GetFileName(f) is "apphost" or "apphost.exe");
        var exe = Save("app/TestFixture.exe", File.ReadAllBytes(host));
        File.Copy(Env.FixturePath, Path.Combine(Path.GetDirectoryName(exe)!, "TestFixture.dll"));
        var s = Inspection.Summarize(null, exe, default);
        Assert.StartsWith(".NET apphost", s.Container);
        Assert.Equal("TestFixture", Assert.Single(s.Assemblies).Identity.Name);
        Assert.Contains("Using the application next to the launcher: TestFixture.dll.", s.Notes);
        var unpacked = new UnpackService(_workspace).Unpack(exe, _dir.File("app-out"), false, AnalysisLimits.Default, default);
        var app = Assert.Single(unpacked.Files);
        Assert.Equal((UnpackService.ApphostAppOrigin, false), (app.Origin, app.Extracted));
        Assert.Equal(new Dictionary<string, string> { ["path"] = app.Path }, unpacked.Next!.Arguments);
        Assert.Equal("load_assembly", unpacked.Next.Tool);
    }

    [Fact]
    public void Big_containers_are_listed_in_pages()
    {
        var entries = Enumerable.Range(0, 130).Select(i => ($"lib/A{i:D3}.dll", ContainerFixtures.Module($"A{i:D3}", _ => { })))
            .Concat(Enumerable.Range(0, 10).Select(i => ($"de/App{i}.resources.dll", ContainerFixtures.Module($"App{i}.resources", _ => { })))).ToArray();
        var zip = Save("big.zip", ContainerFixtures.Zip(entries));
        var listing = new UnpackService(_workspace).List(zip, AnalysisLimits.Default, default);
        Assert.Equal(UnpackService.MaxListed, listing.Assemblies.Count);
        // Translations last, past the cut.
        Assert.DoesNotContain(listing.Assemblies, a => a.Path.Contains(".resources"));
        Assert.Contains(listing.Notes, n => n.StartsWith("140 assemblies; 100 listed"));
        Assert.Equal(140, listing.Total);
        // list_assemblies path= ignored offset, limit and filter, so entries past the first 100 could not be listed.
        var rest = new UnpackService(_workspace).List(zip, AnalysisLimits.Default, default, offset: 100, limit: 50);
        Assert.Equal(40, rest.Assemblies.Count);
        Assert.Equal(10, rest.Assemblies.Count(a => a.Path.Contains(".resources")));
        var few = new UnpackService(_workspace).List(zip, AnalysisLimits.Default, default, filter: "A12", limit: 3);
        Assert.Equal(["lib/A120.dll", "lib/A121.dll", "lib/A122.dll"], few.Assemblies.Select(a => a.Path));
        Assert.Equal(10, few.Total);
        var unpacked = new UnpackService(_workspace).Unpack(zip, _dir.File("big-out"), false, AnalysisLimits.Default, default);
        Assert.Equal(140, unpacked.Files.Count); // the tool pages them
        Assert.True(unpacked.Files.Select(f => f.Path.Contains(".resources")).SkipWhile(r => !r).All(r => r)); // translations last
        Assert.Equal(140, Directory.EnumerateFiles(_dir.File("big-out"), "*.dll", SearchOption.AllDirectories).Count());
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public async Task List_assemblies_filters_and_pages()
    {
        _workspace.LoadDirectory(Path.GetDirectoryName(Env.FixturePath)!, false);
        var tools = new WorkspaceTools(_workspace, new AotMetadataService(_workspace), new IndexingService(_workspace, new CallGraphService(_workspace), new ServerOptions()), new UnpackService(_workspace));
        async Task<(string Text, WorkspaceTools.WorkspaceList List)> List(int offset = 0, int limit = 100, string? filter = null)
        {
            var collector = Corvus.Mcp.ToolOutput.Collect();
            var text = await tools.ListAssemblies(filter: filter, offset: offset, limit: limit);
            return (text, Assert.IsType<WorkspaceTools.WorkspaceList>(collector.Value));
        }
        var (_, all) = await List();
        Assert.True(all.Total > 3);
        var (text, page) = await List(offset: 1, limit: 2);
        Assert.Equal(2, page.Items.Count);
        Assert.Equal(all.Total, page.Total);
        Assert.Equal(all.Items[1].Id, page.Items[0].Id);
        // Rows of loaded assemblies are counted as assemblies, not files.
        Assert.Contains($"{all.Total} assemblies (showing 2-3):\n  {page.Items[0].Id}  ", text);
        Assert.Contains("[More: offset=3]", text);
        var (_, fixtures) = await List(filter: "testfixture");
        Assert.All(fixtures.Items, a => Assert.Contains("TestFixture", a.Id, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(fixtures.Items.Count, fixtures.Total);
    }

    /// <summary>
    /// load, reload and unload_assembly and add_search_directory return a record of what they changed (S4): the ids, the
    /// loaded images (kind, path, name and version or machine and SHA-256), the search directories; never a copy of the text.
    /// </summary>
    [Fact]
    public async Task Workspace_changes_return_their_records()
    {
        var tools = new WorkspaceTools(_workspace, new AotMetadataService(_workspace), new IndexingService(_workspace, new CallGraphService(_workspace), new ServerOptions()), new UnpackService(_workspace));
        async Task<T> Change<T>(Func<Task<string>> call)
        {
            var collector = Corvus.Mcp.ToolOutput.Collect();
            await call();
            return Assert.IsType<T>(collector.Value);
        }
        var load = await Change<WorkspaceTools.ImageChange>(() => tools.LoadAssembly(Env.FixturePath));
        var id = Assert.Single(load.Ids);
        var row = Assert.Single(load.Entries);
        Assert.Equal(("assembly", id, Env.FixturePath), (row.Kind, row.Id, row.Path));
        Assert.StartsWith("TestFixture", row.Name);
        var native = await Change<WorkspaceTools.ImageChange>(() => tools.LoadAssembly(McpProtocolTests.NativeSample(_dir)));
        Assert.Equal(("native", "AMD64"), (native.Entries[0].Kind, native.Entries[0].Machine));
        Assert.Equal(64, native.Entries[0].Sha256!.Length);
        Assert.Equal(id, Assert.Single((await Change<WorkspaceTools.ImageChange>(() => tools.ReloadAssembly(id))).Entries).Id);
        var search = await Change<WorkspaceTools.SearchDirectoryChange>(() => tools.AddSearchDirectory(_dir.Path));
        Assert.Contains(Path.GetFullPath(_dir.Path), search.SearchDirectories);
        Assert.Equal(id, Assert.Single((await Change<WorkspaceTools.UnloadChange>(() => tools.UnloadAssembly(id))).Ids));
    }

    [Fact]
    public void String_decoder_needs_decoding_not_just_an_int_to_string_helper()
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
        Assert.Contains(markers.Indicators, i => i.StartsWith("Possible string decoder S::D(int)"));
        Assert.DoesNotContain(markers.Indicators, i => i.Contains("S::Pad"));
    }

    [Fact]
    public void Summary_evidence_prefers_the_deciding_string()
    {
        var path = Save("Runner.dll", ReferenceResolutionTests.Compile("Runner",
            "public static class R { public static void Go() { System.Diagnostics.Process.Start(\"powershell.exe\", \"-NoProfile\"); } }"));
        var feature = Inspection.Summarize(null, path, default).Assemblies.Single().Features.Single(f => f.Name == "run PowerShell");
        Assert.StartsWith("str:", Assert.Single(feature.Evidence).Feature);
    }

    [Fact]
    public void Costura_embedded_assemblies_are_counted_not_highlighted_one_by_one()
    {
        var host = Save("Host.exe", ContainerFixtures.Module("Host",
            ("costura.testfixture.dll.compressed", ContainerFixtures.Deflate(File.ReadAllBytes(Env.FixturePath)))));
        var s = Inspection.Summarize(null, host, default);
        Assert.Contains("[Host.exe] 1 embedded assembly(ies) (Costura or similar).", s.Highlights);
        Assert.DoesNotContain(s.Highlights, h => h.Contains("Embedded .NET assembly"));
    }
    [Fact]
    public void Jmod_opens_as_the_zip_after_its_header()
    {
        var ms = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
        {
            using (var s = zip.CreateEntry("classes/module-info.class").Open()) s.Write([0xCA, 0xFE, 0xBA, 0xBE]);
            using (var s = zip.CreateEntry("lib/A.dll").Open()) s.Write(ReferenceResolutionTests.Compile("A", "public class AType { }"));
        }
        // The zip's offsets count from after the header, as jmod writes them.
        byte[] bytes = [(byte)'J', (byte)'M', 1, 0, .. ms.ToArray()];
        Assert.Equal("jmod", Blob.Identify(bytes));
        var contents = Containers.Open(bytes, "a.jmod", AnalysisLimits.Default, default);
        Assert.Equal("JMOD (Java module)", contents.Kind);
        Assert.Equal("lib/A.dll", Assert.Single(contents.Items).Name);
    }

    [Fact]
    public void Truncated_zip_recovers_the_complete_entries()
    {
        var ms = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var n in new[] { "A", "B" })
                using (var s = zip.CreateEntry($"lib/{n}.dll").Open())
                    s.Write(ReferenceResolutionTests.Compile(n, $"public class {n}Type {{ }}"));
        }
        var full = ms.ToArray();
        // Cut inside the second entry: no central directory, first entry intact.
        var secondHeader = full.AsSpan(4).IndexOf("PK\u0003\u0004"u8) + 4;
        var cut = full[..(secondHeader + 40)];
        var contents = Containers.Open(cut, "cut.zip", AnalysisLimits.Default, default);
        Assert.Equal("lib/A.dll", Assert.Single(contents.Items).Name);
        Assert.Contains(contents.Notes, n => n.StartsWith("Damaged zip") && n.Contains("1 entr(ies) recovered"));
        Assert.Throws<ToolError>(() => Containers.Open(full[..20], "tiny.zip", AnalysisLimits.Default, default));
    }

    /// <summary>Non-seekable stream: ZipArchive writes entry sizes in trailing data descriptors.</summary>
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
    public void Streamed_zip_without_central_directory_recovers_every_entry_and_steps_over_bad_ones()
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
        // Sizes in descriptors.
        Assert.All(headers, h => Assert.True((full[h + 6] & 0x08) != 0));

        // Drop the central directory.
        var central = full.AsSpan().IndexOf("PK\u0001\u0002"u8);
        var cut = full[..central];
        cut[headers[1] + 6] |= 0x01;                    // B: marked encrypted
        cut[headers[2] + 30 + 9 + 20] ^= 0xFF;          // C: data damaged (inside its compressed bytes)

        var contents = Containers.Open(cut, "streamed.zip", AnalysisLimits.Default, default);
        Assert.Equal(["lib/A.dll", "lib/D.dll"], contents.Items.Select(i => i.Name).ToArray());
        Assert.Contains("Skipped lib/B.dll: encrypted.", contents.Notes);
        Assert.Contains(contents.Notes, n => n.StartsWith("lib/C.dll: damaged (", StringComparison.Ordinal));
        Assert.Contains(contents.Notes, n => n.StartsWith("Damaged zip") && n.Contains("2 entr(ies) recovered") && !n.Contains("lost"));
        Assert.All(contents.Items, i => Assert.Equal(".NET assembly", Blob.Identify(i.Bytes)));
    }
}
