using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Electron facts from synthetic apps: fuses and versions from the binary, archive integrity, package.json entry, webPreferences values.</summary>
public sealed class ElectronTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    private const string MainJs = """
        const { app, BrowserWindow } = require('electron');
        function create() {
          const win = new BrowserWindow({ width: 800, webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
            "sandbox": false,
            preload: path.join(__dirname, 'preload.js'),
          } });
        }
        """;

    private static readonly AsarWriter.File[] App =
    [
        AsarWriter.Text("package.json", """{"name":"demo","productName":"Demo","version":"1.2.3","main":"dist/main.js","dependencies":{"a":"1","b":"2"}}"""),
        AsarWriter.Text("dist/main.js", MainJs),
        AsarWriter.Text("dist/renderer.js", "x.create({webPreferences:{nodeIntegration:!1,contextIsolation:!0,sandbox:!0,...extra,[k]:1,webSecurity:!1}});new W({webPreferences:prefs});"),
        AsarWriter.Text("node_modules/lib/index.js", "webPreferences: { nodeIntegration: true }"),
    ];

    private InspectionService.FileSummary Summarize(string path) => new InspectionService(_workspace).Summarize(null, path, default);

    [Fact]
    public void BinaryScanReadsFusesAndVersions()
    {
        var facts = Electron.Scan(new MemoryStream(ElectronFixtures.Executable(null, fuses: "01r0")), "app.exe");
        Assert.Equal(("44.2.0", "152.0.7977.76", "24.20.0"), (facts.ElectronVersion, facts.ChromiumVersion, facts.NodeVersion));
        Assert.Contains("Chrome/152.0.7977.76 Electron/44.2.0", facts.Evidence);
        Assert.Equal((1, 1), (facts.FuseWireVersion, facts.Sentinels));
        Assert.Equal(["RunAsNode disabled", "EnableCookieEncryption enabled", "EnableNodeOptionsEnvironmentVariable removed", "EnableNodeCliInspectArguments disabled"],
            facts.Fuses.Select(f => $"{f.Name} {f.State}"));
        var nine = Electron.Scan(new MemoryStream(ElectronFixtures.Executable(null, fuses: "0100110110")), "app.exe");
        Assert.Equal(["WasmTrapHandlers", "fuse_9"], nine.Fuses.Skip(8).Select(f => f.Name));
        Assert.False(Electron.Scan(new MemoryStream(Encoding.ASCII.GetBytes("Chrome/1.2.3.4 only")), "x").IsElectron);
    }

    [Fact]
    public void ScanFindsSentinelsAcrossWindowBoundaries()
    {
        var exe = ElectronFixtures.Executable(null, fuses: "1");
        int at = Encoding.Latin1.GetString(exe).IndexOf(ElectronFixtures.Sentinel, StringComparison.Ordinal);
        // place the sentinel so it straddles the first 4 MiB window
        var shifted = new byte[4 * 1024 * 1024 + 512 - 10 - at + exe.Length];
        exe.CopyTo(shifted, shifted.Length - exe.Length);
        var facts = Electron.Scan(new MemoryStream(shifted), "big.exe");
        Assert.Equal(1, facts.Sentinels);
        Assert.Equal("enabled", facts.Fuses.Single().State);
    }

    [Fact]
    public void ArchiveSummaryNamesVersionsFusesIntegrityEntryAndSettings()
    {
        var (bytes, header) = AsarWriter.Build(App);
        var asar = ElectronFixtures.App(_dir.File("app"), bytes, Convert.ToHexStringLower(SHA256.HashData(header)));
        var summary = Summarize(asar);
        Assert.Equal(AsarContainer.Kind, summary.Container);
        var e = summary.Electron!;
        Assert.Equal(Path.Combine(_dir.Path, "app", "App.exe"), e.Executable);
        Assert.Equal("44.2.0", e.ElectronVersion);
        Assert.Equal(9, e.Fuses.Count);
        Assert.Equal(("good", 4), (e.Archive!.HeaderIntegrity, e.Archive.Files));
        Assert.Equal(4, e.Archive.FileIntegrity["ok"]);
        Assert.Equal(("dist/main.js", true, 2, "Demo"), (e.Package!.Main, e.Package.MainFound, e.Package.Dependencies, e.Package.ProductName));
        Assert.Equal(
        [
            "nodeIntegration=true@dist/main.js:4:5", "contextIsolation=false@dist/main.js:5:5", "sandbox=false@dist/main.js:6:5",
            "preload=path.join(__dirname, 'preload.js')@dist/main.js:7:5",
            "nodeIntegration=false@dist/renderer.js:1:27", "contextIsolation=true@dist/renderer.js:1:46", "sandbox=true@dist/renderer.js:1:66",
            "webSecurity=false@dist/renderer.js:1:92", "webPreferences=prefs@dist/renderer.js:1:117",
        ], e.WebPreferences.Select(s => $"{s.Setting}={s.Value}@{s.Site}"));
        Assert.Contains("Electron 44.2.0 (Chromium 152.0.7977.76, Node 24.20.0).", summary.Highlights);
        Assert.Contains(summary.Highlights, h => h.StartsWith("ASAR header integrity good (App.exe resource INTEGRITY/ELECTRONASAR)", StringComparison.Ordinal));
        Assert.Contains("webPreferences nodeIntegration: true at dist/main.js:4:5.", summary.Highlights);
        Assert.Contains(summary.Highlights, h => h.StartsWith("Electron fuses: enabled EnableCookieEncryption, EnableEmbeddedAsarIntegrityValidation", StringComparison.Ordinal));
    }

    [Fact]
    public void ExecutableSummaryReadsTheArchiveBesideIt()
    {
        var (bytes, header) = AsarWriter.Build(App);
        var damaged = (byte[])bytes.Clone();
        damaged[^1] ^= 0x20; // last byte of the last packed file
        ElectronFixtures.App(_dir.File("app"), damaged, new string('0', 64));
        var e = Summarize(Path.Combine(_dir.Path, "app", "App.exe")).Electron!;
        Assert.Equal("bad", e.Archive!.HeaderIntegrity);
        Assert.Equal(1, e.Archive.FileIntegrity["hash_mismatch"]);
        Assert.Equal("dist/main.js", e.Package!.Main);
    }

    [Fact]
    public void AppFolderWithoutArchive()
    {
        var root = _dir.File("folderapp");
        Directory.CreateDirectory(Path.Combine(root, "resources", "app"));
        File.WriteAllBytes(Path.Combine(root, "App.exe"), ElectronFixtures.Executable(null));
        File.WriteAllText(Path.Combine(root, "resources", "app", "package.json"), """{"main":"main.js"}""");
        File.WriteAllText(Path.Combine(root, "resources", "app", "main.js"), "new BrowserWindow({webPreferences:{sandbox:false}})");
        var e = Summarize(Path.Combine(root, "App.exe")).Electron!;
        Assert.Null(e.Archive);
        Assert.Equal(("main.js", true), (e.Package!.Main, e.Package.MainFound));
        Assert.Equal("sandbox=false@main.js:1:36", e.WebPreferences.Select(s => $"{s.Setting}={s.Value}@{s.Site}").Single());
    }

    [Fact]
    public void OtherFilesHaveNoElectronFacts()
    {
        var path = _dir.File("plain.exe");
        File.WriteAllBytes(path, ElectronFixtures.Executable(null, fuses: null, electron: "x"));
        Assert.Null(Summarize(path).Electron);
        Assert.Null(Summarize(Env.FixturePath).Electron);
    }

    [RequiresRealDataFact(RealData.ElectronApps)]
    [Trait("Speed", "Slow")]
    public void RealAppsListAndSummarize()
    {
        var root = RealData.Path(RealData.ElectronApps);
        var archives = Directory.EnumerateFiles(root, "*.asar", new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 6, IgnoreInaccessible = true }).ToList();
        Assert.NotEmpty(archives);
        var report = new List<string>();
        foreach (var asar in archives)
        {
            long allocated = GC.GetAllocatedBytesForCurrentThread();
            var cpu = ThreadCpuClock.Now();
            var listing = new UnpackService(_workspace).List(asar, AnalysisLimits.Default, default);
            var took = ThreadCpuClock.Now() - cpu;
            allocated = GC.GetAllocatedBytesForCurrentThread() - allocated;
            var e = Summarize(asar).Electron!;
            report.Add($"{asar}: {new FileInfo(asar).Length / 1048576.0:0.0} MiB, {listing.FileTotal} entries, list {took.TotalMilliseconds:0} ms CPU, {allocated / 1048576.0:0} MiB allocated; " +
                       $"Electron {e.ElectronVersion}, {e.Fuses.Count} fuses, header {e.Archive?.HeaderIntegrity}, files {string.Join(" ", e.Archive?.FileIntegrity.Select(s => $"{s.Value} {s.Key}") ?? [])}, " +
                       $"main {e.Package?.Main}, {e.WebPreferences.Count} webPreferences values");
            Assert.NotEqual("bad", e.Archive?.HeaderIntegrity);
            Assert.True(allocated < new FileInfo(asar).Length + 100L * 1024 * 1024, report[^1]);
        }
        Console.WriteLine(string.Join(Environment.NewLine, report));
    }
}
