using System.Text;
using dnlib.DotNet;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>The containers family's provider interfaces: type-scan discovery and their use by the readers, the survey and search_container.</summary>
public sealed class ContainerProviderTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new();

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    /// <summary>"FAKEPACK" + name length + name + payload: one file per container.</summary>
    internal sealed class FakePackReader : IContainerReader
    {
        public static readonly byte[] Magic = "FAKEPACK"u8.ToArray();
        public string Kind => "fakepack";
        public bool Accepts(ReadOnlySpan<byte> data, string name) => data.StartsWith(Magic);

        public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
        {
            int n = data[Magic.Length];
            var inner = Encoding.ASCII.GetString(data, Magic.Length + 1, n);
            return new ContainerContents(Kind, [new ExtractedItem(inner, data[(Magic.Length + 1 + n)..], "fakepack entry")], []);
        }

        public static byte[] Pack(string inner, byte[] payload) => [.. Magic, (byte)inner.Length, .. Encoding.ASCII.GetBytes(inner), .. payload];
    }

    internal sealed class MarkerRules : ISurveyRuleProvider
    {
        public IEnumerable<Features.Rule> Rules => [new("carry the test marker", "test", [["marker:Account"]])];
        public IReadOnlyCollection<string> Kinds => ["marker"];

        public Evidence? Evaluate(SurveySubject subject, string feature, CancellationToken ct)
        {
            var type = feature["marker:".Length..];
            return subject.Managed?.Module.GetTypes().Any(t => t.Name == type) == true ? new Evidence(feature, 1, [type]) : null;
        }
    }

    internal abstract class AbstractReader : IContainerReader
    {
        public string Kind => "abstract";
        public bool Accepts(ReadOnlySpan<byte> data, string name) => true;
        public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) => throw new InvalidOperationException();
    }

    internal sealed class NoDefaultConstructorReader(string kind) : IContainerReader
    {
        public string Kind => kind;
        public bool Accepts(ReadOnlySpan<byte> data, string name) => true;
        public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) => throw new InvalidOperationException();
    }

    [Fact]
    public void Scan_finds_concrete_providers_with_a_default_constructor_in_name_order()
    {
        var readers = Providers.Scan<IContainerReader>(typeof(ContainerProviderTests).Assembly);
        Assert.Contains(readers, r => r is FakePackReader);
        Assert.DoesNotContain(readers, r => r is AbstractReader or NoDefaultConstructorReader);
        Assert.Equal(readers.Select(r => r.GetType().FullName).Order(StringComparer.Ordinal), readers.Select(r => r.GetType().FullName));
        // The server's own scan sees only its assembly; tests add theirs for one async flow.
        Assert.DoesNotContain(Providers.Of<IContainerReader>(), r => r is FakePackReader);
        using (Providers.With(new FakePackReader())) Assert.Contains(Providers.Of<IContainerReader>(), r => r is FakePackReader);
        Assert.DoesNotContain(Providers.Of<IContainerReader>(), r => r is FakePackReader);
    }

    [Fact]
    public void A_reader_opens_data_no_built_in_reader_takes()
    {
        var file = _dir.File("app.fake");
        File.WriteAllBytes(file, FakePackReader.Pack("Fixture.dll", File.ReadAllBytes(Env.FixturePath)));
        Assert.Equal("data with embedded .NET images", Containers.Open(File.ReadAllBytes(file), "app.fake", AnalysisLimits.Default, default).Kind);

        using var _ = Providers.With(new FakePackReader());
        var report = new UnpackService(_workspace).Unpack(file, _dir.File("out"), load: false, AnalysisLimits.Default, default);
        Assert.Equal("fakepack", report.Container);
        var dll = Assert.Single(report.Files);
        Assert.Equal(".NET assembly", dll.Kind);
        Assert.EndsWith("Fixture.dll", dll.Path);
        // Nested: an item in the reader's format (plain data to the built-in kinds) is opened too.
        var outer = _dir.File("outer.fake");
        File.WriteAllBytes(outer, FakePackReader.Pack("inner.fake", File.ReadAllBytes(file)));
        var listing = new UnpackService(_workspace).List(outer, AnalysisLimits.Default, default);
        Assert.Equal("inner.fake_unpacked/Fixture.dll", Assert.Single(listing.Assemblies).Path);
    }

    /// <summary>A kind that matches the Blob kind of inner files ("zip", ".NET assembly").</summary>
    internal sealed class BlobKindSearch : IContainerSearchKind
    {
        public IReadOnlyList<string> Kinds => ["blobkind"];

        public IEnumerable<ContainerMatch> Search(ContainerScope scope, string kind, Func<string, bool> matches, CancellationToken ct) =>
            scope.Items.Where(i => matches(i.Kind)).Select(i => new ContainerMatch(i.Path, i.Kind, kind));
    }

    // Regression: kind=file listed run.ps1.bin and run.ps1 for one entry.
    [Fact]
    public void A_file_written_under_a_safe_name_is_listed_once_with_its_recorded_name()
    {
        var zip = _dir.File("scripts.zip");
        File.WriteAllBytes(zip, ContainerFixtures.Zip(("tools/run.ps1", "Write-Output 1"u8.ToArray()), ("readme.txt", "hello"u8.ToArray())));
        var unpacker = new UnpackService(_workspace);
        var all = unpacker.Search(zip, "*", "file", 10, AnalysisLimits.Default, default);
        Assert.Equal(["readme.txt", "tools/run.ps1.bin"], all.Items.Select(m => m.Path).Order(StringComparer.Ordinal));
        Assert.EndsWith(", recorded as tools/run.ps1", all.Items.Single(m => m.Path == "tools/run.ps1.bin").Detail);
        Assert.Equal("tools/run.ps1.bin", Assert.Single(unpacker.Search(zip, "run.ps1", "file", 10, AnalysisLimits.Default, default).Items).Path);
    }

    [Fact]
    public void Search_kinds_from_providers_and_the_built_in_file_kind()
    {
        var zip = _dir.File("app.zip");
        File.WriteAllBytes(zip, ContainerFixtures.Zip(("lib/net8.0/Fixture.dll", File.ReadAllBytes(Env.FixturePath)), ("assets/readme.txt", "hello"u8.ToArray()),
            ("assets/fixture-notes.txt", "notes"u8.ToArray())));
        var unpacker = new UnpackService(_workspace);
        var files = unpacker.Search(zip, "fixture", "file", 10, AnalysisLimits.Default, default);
        // Prefix before substring.
        Assert.Equal(["lib/net8.0/Fixture.dll", "assets/fixture-notes.txt"], files.Items.Select(m => m.Path));
        Assert.All(files.Items, m => Assert.Equal("file", m.Kind));
        Assert.StartsWith(".NET assembly, ", files.Items[0].Detail);
        Assert.Single(unpacker.Search(zip, "fixture", "file", 1, AnalysisLimits.Default, default, offset: 1).Items);
        Assert.Contains("file", UnpackService.SearchKinds);

        Assert.Contains("Unknown kind", Assert.Throws<ToolError>(() => unpacker.Search(zip, "net", "blobkind", 10, AnalysisLimits.Default, default)).Message);
        using var _ = Providers.With(new BlobKindSearch());
        var byKind = unpacker.Search(zip, ".net", "blobkind", 10, AnalysisLimits.Default, default);
        Assert.Equal("lib/net8.0/Fixture.dll", Assert.Single(byKind.Items).Path);
    }

    /// <summary>A view for files that start with "FAKEPACK".</summary>
    internal sealed class FakePackView : IFileSummaryView
    {
        public string Name => "fakepack";

        public FileView? Inspect(FileInput file, CancellationToken ct) =>
            file.Bytes.AsSpan().StartsWith(FakePackReader.Magic) ? new FileView(new { entries = 1, magic = "FAKEPACK" }, ["A fakepack archive."]) : null;
    }

    [Fact]
    public async Task Summary_views_from_providers_and_the_overview()
    {
        var file = _dir.File("app.fake");
        File.WriteAllBytes(file, FakePackReader.Pack("Fixture.dll", File.ReadAllBytes(Env.FixturePath)));
        var tools = new Corvus.Tools.InspectionTools(new InspectionService(_workspace), _workspace);
        var collector = Corvus.Mcp.ToolOutput.Collect();
        var text = await tools.SummarizeFile(path: Env.FixturePath);
        var overview = Assert.IsType<Corvus.Tools.FileSummaryRecord>(collector.Value);
        Assert.Equal(["overview", "managed", "all"], overview.Views);
        Assert.Equal("TestFixture", Assert.Single(overview.Assemblies!).Name);
        Assert.Null(overview.Detail);
        Assert.DoesNotContain("{\"", text);
        Assert.Contains("Views: overview, managed, all", text);

        collector = Corvus.Mcp.ToolOutput.Collect();
        await tools.SummarizeFile(path: Env.FixturePath, view: "managed");
        var managed = Assert.IsType<Corvus.Tools.FileSummaryRecord>(collector.Value);
        Assert.Equal("TestFixture", (string?)managed.Detail!["assemblies"]![0]!["identity"]!["name"]);
        var bad = await Assert.ThrowsAsync<ToolError>(() => tools.SummarizeFile(path: Env.FixturePath, view: "android"));
        Assert.Equal("pass view as one of overview, managed, all", bad.Remediation);

        using var _ = Providers.With(new FakePackView());
        collector = Corvus.Mcp.ToolOutput.Collect();
        await tools.SummarizeFile(path: file);
        var fake = Assert.IsType<Corvus.Tools.FileSummaryRecord>(collector.Value);
        Assert.Contains("fakepack", fake.Views);
        Assert.Contains("A fakepack archive.", fake.Highlights!);
        collector = Corvus.Mcp.ToolOutput.Collect();
        text = await tools.SummarizeFile(path: file, view: "fakepack");
        Assert.Equal("FAKEPACK", (string?)Assert.IsType<Corvus.Tools.FileSummaryRecord>(collector.Value).Detail!["magic"]);
        Assert.Contains("magic: FAKEPACK", text);
    }

    [Fact]
    public void Survey_rule_providers_add_rules_and_feature_kinds()
    {
        using var module = ModuleDefMD.Load(Env.FixturePath);
        var scan = ModuleScan.Of(module, AnalysisLimits.Default, default);
        Assert.DoesNotContain(Features.Detect(scan, default), f => f.Category == "test");
        using var _ = Providers.With(new MarkerRules());
        var found = Assert.Single(Features.Detect(scan, default), f => f.Category == "test");
        Assert.Equal("marker:Account", Assert.Single(found.Evidence).Feature);
    }
}
