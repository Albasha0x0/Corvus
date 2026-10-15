using System.Text;
using Corvus.Core;
using Corvus.Native.Elf;
using Corvus.Services.Analysis;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>
/// summarize_file views on damaged files, each asked for by name: a view answers, returns null or throws a tool error.
/// The views with a fuzz entry of their own (pcap, SQLite, firmware, Flutter, nib, Rust) are left to it.
/// </summary>
public sealed class FileViewFuzzTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private void Fuzz(IFileSummaryView view, string name, int iterations, params byte[][] seeds)
    {
        // a folder of its own: views that look beside the file (Wasm glue, bundle folders) find nothing there
        var path = Path.Combine(Directory.CreateDirectory(_dir.File(view.Name)).FullName, name);
        var failures = new List<string>();
        foreach (var seed in seeds)
            failures.AddRange(FormatFuzz.Run(seed, b =>
            {
                File.WriteAllBytes(path, b); // some views read the file again from its path
                try { view.Inspect(new FileInput(path, b, Blob.Identify(b)) { Options = new FileViewOptions(view.Name) }, default); }
                catch (ToolError) { }
            }, iterations));
        Assert.True(failures.Count == 0, $"view={view.Name}: " + string.Join("\n", failures.Take(10)));
    }

    [Fact]
    [FuzzEntry(typeof(AndroidFileView))]
    public void Android() => Fuzz(new AndroidFileView(), "app.apk", 300, AndroidSamples.Apk());

    [Fact]
    [FuzzEntry(typeof(AppleFileView))]
    public void Apple()
    {
        var plist = Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.example.zoo</string>" +
            "<key>CFBundleExecutable</key><string>Zoo</string><key>CFBundleShortVersionString</key><string>1.2</string></dict></plist>");
        var ipa = ContainerFixtures.Zip(("Payload/Zoo.app/Info.plist", plist), ("Payload/Zoo.app/Zoo", FormatWriterTests.SampleMachO().Build()));
        Fuzz(new AppleFileView(), "Zoo.ipa", 300, ipa);
    }

    [Fact]
    [FuzzEntry(typeof(ElectronFileView))]
    public void Electron()
    {
        var (asar, _) = AsarWriter.Build([AsarWriter.Text("package.json", """{"name":"demo","main":"main.js"}"""), AsarWriter.Text("main.js", "new BrowserWindow({ webPreferences: { nodeIntegration: true } })")]);
        Fuzz(new ElectronFileView(), "app.asar", 300, asar);
        Fuzz(new ElectronFileView(), "app.exe", 300, ElectronFixtures.Executable(ElectronFixtures.IntegrityJson(new string('0', 64))));
    }

    [Fact]
    [FuzzEntry(typeof(GoFileView))]
    public void Go()
    {
        var elf = new ElfWriter
        {
            Machine = ElfWriter.EmX64, Type = 2, Base = 0x400000, Entry = ElfWriter.TextRva, Text = [0xC3], Hash = ElfWriter.HashKind.None,
            DataSectionName = ".go.buildinfo", Data = GoBuildInfoTests.Inline(),
        }.Build();
        Fuzz(new GoFileView(), "gobin", 300, elf);
    }

    [Fact]
    [FuzzEntry(typeof(NativeFileView))]
    public void Native() => Fuzz(new NativeFileView(), "lib.bin", 300, NativePeTests.KitchenSink(true), FormatWriterTests.SampleElf().Build(), FormatWriterTests.SampleMachO().Build());

    [Fact]
    [FuzzEntry(typeof(PlistFileView))]
    public void Plist() => Fuzz(new PlistFileView(), "Info.plist", 500,
        Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><plist><dict><key>a</key><array><integer>1</integer><data>AAEC</data></array></dict></plist>"));

    [Fact]
    [FuzzEntry(typeof(ProtobufFileView))]
    public void Protobuf() => Fuzz(new ProtobufFileView(), "demo.pb", 500, ProtoWriter.Demo());

    [Fact]
    [FuzzEntry(typeof(SqliteRecoverFileView))]
    public void SqliteRecover() => Fuzz(new SqliteRecoverFileView(), "msg.db", 300,
        NativeSqlite.Build("CREATE TABLE msg(id INTEGER PRIMARY KEY, body TEXT);", "INSERT INTO msg(body) VALUES ('one'), ('two'), ('three');", "DELETE FROM msg WHERE id = 2;"));

    [Fact]
    [FuzzEntry(typeof(WasmFileView))]
    public void Wasm() => Fuzz(new WasmFileView(), "app.wasm", 500, WasmTests.Sample());
}
