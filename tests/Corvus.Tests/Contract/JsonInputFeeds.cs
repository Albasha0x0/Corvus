using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.ExceptionServices;
using System.Text;
using Corvus.Core;
using Corvus.Core.Ark;
using Corvus.Core.Mobile;
using Corvus.Core.Models;
using Corvus.Core.Node;
using Corvus.Core.Pcap;
using Corvus.Core.Python;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Go;
using Corvus.Native.Linking;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Dependencies;
using Corvus.Services.Mobile;
using Corvus.Services.Web;
using Corvus.Services.Web.Packages;

namespace Corvus.Tests;

public sealed partial class JsonInputTests
{
    private const string PsfManifest = """<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Example.Tool" Publisher="CN=Example" Version="1.0.0.0" ProcessorArchitecture="x64" /><Applications><Application Id="App" Executable="PSFLauncher64.exe" EntryPoint="Windows.FullTrustApplication" /></Applications></Package>""";

    private static string Decoded(byte[] bytes) => Encoding.UTF8.GetString(bytes);

    private static byte[] Joined(params byte[][] parts) => [.. parts.SelectMany(p => p)];

    private static byte[] ZipOf(params (string Name, byte[] Data)[] entries) => ContainerFixtures.Zip(entries);

    private static byte[] AsarOf(byte[] json)
    {
        var archive = new byte[16 + json.Length];
        BitConverter.GetBytes(4u).CopyTo(archive, 0);
        BitConverter.GetBytes((uint)json.Length + 8).CopyTo(archive, 4);
        BitConverter.GetBytes((uint)json.Length + 4).CopyTo(archive, 8);
        BitConverter.GetBytes((uint)json.Length).CopyTo(archive, 12);
        json.CopyTo(archive, 16);
        return archive;
    }

    private static void InFolder(string name, byte[] content, Action<string> read)
    {
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File(name), content);
        read(dir.Path);
    }

    private static void ReadSourceLink(byte[] json)
    {
        var metadata = new MetadataBuilder();
        metadata.AddCustomDebugInformation(EntityHandle.ModuleDefinition, metadata.GetOrAddGuid(new Guid("CC110556-A091-4D38-9FEC-25AB9A351A6A")), metadata.GetOrAddBlob(json));
        var image = new BlobBuilder();
        new PortablePdbBuilder(metadata, ImmutableArray.CreateRange(new int[MetadataTokens.TableCount]), default).Serialize(image);
        var provider = MetadataReaderProvider.FromPortablePdbImage(image.ToImmutableArray());
        try
        {
            var constructor = typeof(PortablePdb).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic, [typeof(MetadataReaderProvider), typeof(string)])!;
            try { ((IDisposable)constructor.Invoke([provider, "x.pdb"])).Dispose(); }
            catch (TargetInvocationException ex) { ExceptionDispatchInfo.Capture(ex.InnerException!).Throw(); }
        }
        catch
        {
            provider.Dispose();
            throw;
        }
    }

    /// <summary>Each reader of JSON from an input file, by its source file, with a valid seed and the call that reads a document.</summary>
    private static readonly Dictionary<string, (string Seed, Action<byte[]> Read)> Feeds = new(StringComparer.Ordinal)
    {
        ["Core/Archives/ContainerImage.cs"] = (
            """{"architecture":"amd64","os":"linux","config":{"Cmd":["--serve"],"Env":["MODE=prod"]},"rootfs":{"type":"layers","diff_ids":[]},"history":[{"created_by":"RUN x"}]}""",
            b => Containers.Open(ImageArchive(b), "x.tar", AnalysisLimits.Default, default)),
        ["Services/Analysis/Hunts/HuntRules.cs"] = (
            """{"hunts":[{"id":"a","title":"t","table":"DeviceRegistryEvents","kql":"x","facts":["registry_key:k"],"proof":{"verdict":"keep"}}],"detectionRules":[{"id":"a"}],"notes":["n"]}""",
            b => Corvus.Services.Analysis.Hunts.HuntRules.Read(b)),
        ["Services/Analysis/Hunts/TenantResult.cs"] = (
            """{"schema":[],"results":[{"Source":"DeviceFileEvents","Queried":"0123456789abcdef0123456789abcdef01234567","Devices":1,"FirstSeen":"2026-11-05T01:00:00Z"}]}""",
            b => Corvus.Services.Analysis.Hunts.TenantResult.Read(b, "0123456789abcdef0123456789abcdef01234567", DateTimeOffset.UnixEpoch)),
        ["Core/Electron.cs"] = ("""[{"file":"a.js","alg":"SHA256","value":"abc"}]""", b => Electron.ParseResource(b, "x")),
        ["Core/Models/Safetensors.cs"] = (
            """{"__metadata__":{"k":"v"},"t":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}""",
            b => Safetensors.Read(new MemoryStream(Safe(b)), b.Length + 12)),
        ["Core/Pcap/Qlog.cs"] = (
            """{"qlog_version":"0.3","title":"t","traces":[{"vantage_point":{"name":"n","type":"client"},"events":[[0,"transport","packet_sent",{}]]}]}""",
            b => Qlog.Read(new MemoryStream(b), _ => { }, default)),
        ["Core/ConfigFile.cs"] = ("""{"$schema":"s","CORVUS_X":"1","CORVUS_Y":2}""", b => WithFile(b, p => ConfigFile.Apply(p, "test", _ => null, (_, _) => { }))),
        ["Native/Dump/SessionHookSidecar.cs"] = ("""{"hooks":[{"address":"0x1000","length":5,"kind":"coverage"}]}""", b =>
        {
            var dump = Path.Combine(Path.GetTempPath(), "corvus-hooks-" + Guid.NewGuid().ToString("N") + ".dmp");
            var sidecar = SessionHookSidecar.PathFor(dump);
            File.WriteAllBytes(sidecar, b);
            try { SessionHookSidecar.Read(dump); }
            finally { File.Delete(sidecar); }
        }),
        ["Native/Dump/RegionSetFile.cs"] = ("""{"format":1,"regions":[{"base":"0x1000","size":16,"file":"a.bin"}]}""", b => WithFile(b, p => RegionSetFile.Open(p))),
        ["Native/RustAudit.cs"] = (
            """{"packages":[{"name":"a","version":"1.0.0","source":"registry","kind":"build","root":true,"dependencies":[]}]}""",
            b => RustAudit.Parse(Zlib(b))),
        ["Services/Analysis/Dependencies/DepsJson.cs"] = (
            """{"runtimeTarget":{"name":".NETCoreApp,Version=v8.0"},"targets":{".NETCoreApp,Version=v8.0":{"a/1.0":{"dependencies":{"b":"1.0"}}}},"libraries":{"a/1.0":{"type":"package","sha512":"sha512-AAAA"}}}""",
            b => DepsJson.Parse("deps.json", b)),
        ["Services/Web/SourceMap.cs"] = (
            """{"version":3,"file":"o.js","sources":["a.js"],"sourcesContent":["x"],"names":["n"],"mappings":"AAAA"}""",
            b => SourceMap.Parse(b)),
        ["Services/Analysis/BuildSummary.cs"] = (
            """{"names":["A.dll","B.dll"]}""",
            b => WithFile(b, p =>
            {
                Static(typeof(BuildSummary), "ScriptingAssemblyCount", p);
                _ = ((IEnumerable<string>)Static(typeof(BuildSummary), "ScriptingAssemblyNames", p)!).ToList();
            })),
        ["Core/Ark/HarmonyPackage.cs"] = (
            """{"app":{"bundleName":"a.b","versionName":"1.0","versionCode":1},"module":{"name":"m","type":"entry","deviceTypes":["phone"],"abilities":[{"name":"A","exported":true}],"requestPermissions":[{"name":"p"}]}}""",
            b => _ = new HarmonyPackage(new MemoryStream(ZipOf(("module.json", b))), 1 << 20).Modules),
        ["Core/Models/ModelRisk.cs"] = (
            """{"class_name":"Sequential","config":{"layers":[{"module":"keras.layers","class_name":"Dense"}]}}""",
            b => ModelRisk.Scan("m.keras", ZipOf(("config.json", b)))),
        ["Core/Node/NodeBundle.cs"] = (
            """{"/a.js":{"1":[0,3]},"resources":{"./a.txt":[0,3]}}""",
            b =>
            {
                var limits = AnalysisLimits.Default;
                NodeBundle.Open(NodeBundleTests.PkgImage("abc"u8.ToArray(), Joined("boot\n})(require, "u8.ToArray(), b, ", \"/snapshot/app/index.js\", {}, {})"u8.ToArray())), limits, default);
                var code = Joined("process.__nexe = "u8.ToArray(), b, ";\nrun();"u8.ToArray());
                NodeBundle.Open(NodeBundleTests.Image(new byte[32], code, "abc"u8.ToArray(), NodeBundleTests.NexeTrailer(code.Length, 3)), limits, default);
            }),
        ["Core/Python/FrozenPython.cs"] = (
            """{"entry_point":"app:main","distributions":{"a-1.0":"h"}}""",
            b => FrozenPython.ReadZipApp(ZipOf(("__main__.py", "pass\n"u8.ToArray()), ("PEX-INFO", b)), AnalysisLimits.Default, default)),
        ["Native/Dump/CoreFile.MachO.cs"] = (
            """{"threads":[{"thread_id":7937},{"thread_id":7938}]}""",
            b =>
            {
                using var dir = new TempDir();
                var path = dir.File("process.core");
                File.WriteAllBytes(path, SyntheticMachOCore.Core(notes: true, process: b));
                using var core = CoreFile.Open(path);
            }),
        ["Native/Linking/UnixProbing.cs"] = (
            """{"runtimeTarget":{"name":".NETCoreApp,Version=v8.0/linux-x64"},"targets":{"t":{"a/1":{"runtimeTargets":{"runtimes/linux-x64/native/liba.so":{"rid":"linux-x64","assetType":"native"}}}}}}""",
            b => InFolder("app.deps.json", b, dir =>
            {
                Static(typeof(UnixProbing), "DepsRuntimeTarget", dir);
                Static(typeof(UnixProbing), "DepsRids", dir);
            })),
        ["Services/Analysis/ElectronFacts.cs"] = (
            """{"name":"app","productName":"App","version":"1.0.0","main":"main.js","dependencies":{"a":"1"}}""",
            b =>
            {
                var files = typeof(ElectronInspector).GetNestedType("AppFiles", BindingFlags.NonPublic)!;
                var app = Activator.CreateInstance(files, "app", new List<(string, long)> { ("package.json", b.Length) }, (Func<string, byte[]?>)(_ => b));
                Static(typeof(ElectronInspector), "Package", app, new List<string>());
            }),
        ["Services/Analysis/MsixFileView.cs"] = (
            """{"applications":[{"id":"App","executable":"Tool.exe","startScript":{"scriptPath":"a.ps1"}}],"processes":[{"executable":"Tool","fixups":[{"dll":"F.dll"}]}]}""",
            b =>
            {
                var package = ZipOf(("AppxManifest.xml", Encoding.UTF8.GetBytes(PsfManifest)), ("PSFLauncher64.exe", [5, 6]), ("config.json", b));
                new MsixFileView().Inspect(new FileInput("t.msix", package, Corvus.Core.Blob.Identify(package)), default);
            }),
        ["Services/AotMetadata/AotDumpFiles.cs"] = (
            """{"ScriptMethod":[{"Address":4096,"Name":"A$$b","Signature":"void b()","TypeSignature":"v"}],"ScriptString":[{"Address":1,"Value":"hi"}],"ScriptMetadata":[{"Address":2,"Name":"n","Signature":"s"}],"ScriptMetadataMethod":[{"Address":3,"Name":"m","MethodAddress":4}],"Addresses":[1,2]}""",
            b => WithFile(b, path =>
            {
                var offsets = new List<long>();
                new ScriptJsonReader { Method = (_, at) => offsets.Add(at), String = _ => { }, Metadata = (_, _) => { }, MetadataMethod = (_, _) => { }, Address = _ => { } }.Read(path);
                using var handle = File.OpenHandle(path);
                foreach (var at in offsets) ScriptJsonReader.ReadMethodAt(handle, at);
            })),
        ["Services/Dotnet/PortablePdb.cs"] = ("""{"documents":{"/_/*":"https://example.com/raw/*"}}""", ReadSourceLink),
        ["Services/Mobile/WebBridges.cs"] = (
            """[{"pkg":"@capacitor/camera","classpath":"com.example.CameraPlugin"}]""",
            b =>
            {
                using var dir = new TempDir();
                var apk = AndroidSamples.Save(dir, "app.apk", AndroidSamples.Apk(30, ("classes.dex", JniBindingsTests.Dex()),
                    ("assets/www/app.js", "registerPlugin('Camera');"u8.ToArray()), ("assets/capacitor.plugins.json", b)));
                using var workspace = new AssemblyWorkspace(new ServerOptions());
                var dex = new DexService();
                new AppGraph(dex, new JniBindings(dex), new JavaDotNetMap(workspace, dex), null).Build(apk, 0, 100, default);
            }),
        ["Services/Web/Packages/PackageProvenance.cs"] = (
            """{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3","verificationMaterial":{},"dsseEnvelope":{"payload":"e30=","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"AA==","keyid":"k"}]}}""",
            b =>
            {
                using var dir = new TempDir();
                var package = dir.File("p.tgz");
                File.WriteAllBytes(package, [1, 2, 3]);
                File.WriteAllBytes(package + ".sigstore.json", b);
                PackageProvenance.Read(package, default);
            }),
        ["Core/Asar.cs"] = (
            """{"files":{"a.txt":{"size":3,"offset":"0","integrity":{"algorithm":"SHA256","hash":"ab","blockSize":4,"blocks":["cd"]}},"l":{"link":"a.txt"}}}""",
            b => AsarArchive.Read(new MemoryStream(AsarOf(b)))),
        ["Core/Har.cs"] = (
            """{"log":{"entries":[{"request":{"method":"GET","url":"http://a/"},"response":{"status":200,"headers":[{"name":"content-encoding","value":"gzip"}],"content":{"mimeType":"text/plain","text":"hi"}}}]}}""",
            b => Captures.ReadHar(b)),
        ["Core/Webcil.cs"] = (
            """{"resources":{"assembly":{"a.dll":"sha256-x"},"wasmNative":{"dotnet.native.wasm":"sha256-y"}}}""",
            b => InFolder("blazor.boot.json", b, dir => Webcil.BootManifestEntries(dir))),
        ["Native/Go/GoBuildInfo.cs"] = (
            "\"-s -w\"",
            b => GoBuildInfo.Parse("go1.22", "path\tx\nbuild\t-ldflags=" + Decoded(b) + "\nbuild\t-tags=\"" + Decoded(b) + "\"\n")),
        ["Services/Analysis/ConfigText.cs"] = ("""{"a":"bcd","e":["f","g"]}""", b => ConfigText.Read(b)),
        ["Services/Analysis/Embedded.cs"] = (
            """{"name":"alpha","items":["beta","gamma"],"mode":"delta"}""",
            b =>
            {
                Static(typeof(Embedded), "StructuredText", b, false);
                Static(typeof(Embedded), "StructuredText", Encoding.Unicode.GetBytes(Decoded(b)), true);
            }),
        ["Services/Analysis/ScriptSources.cs"] = (
            """{"cells":[{"cell_type":"code","source":["import os\n","os.system('ls')"]}]}""",
            b => NotebookCells.Read(Decoded(b))),
        ["Services/Web/FlightData.cs"] = (
            """{"a":"b","c":["d"]}""",
            b =>
            {
                var text = Decoded(b);
                FlightData.Read("0:" + text + "\n1:I" + text + "\n2:E" + text + "\n3:HL" + text + "\n", default);
                FlightData.Read("<script>self.__next_f.push([1," + text + "])</script>", default);
                FlightData.Read("<script>self.__next_f.push([1,\"" + text + "\"])</script>", default);
            }),
        ["Services/Web/Packages/AgentConfigReview.cs"] = (
            """{"version":"2.0.0","tasks":[{"label":"x","command":"echo","runOptions":{"runOn":"folderOpen"}}]}""",
            b => PackageReview.JsonTree.Parse(Decoded(b))),
        ["Services/Web/Packages/WorkflowAuditor.cs"] = (
            """[{"ident":"template-injection","determinations":{"severity":"High"},"desc":"d","locations":[{"concrete":{"location":{"start_point":{"row":3}}}}]}]""",
            b => Static(typeof(WorkflowAuditor), "Read", b, "w.yml")),
        ["Services/Web/Packages/Lockfiles.cs"] = (
            """{"lockfileVersion":3,"packages":{"":{"name":"a"},"node_modules/b":{"version":"1.0.0","resolved":"https://r.example/b/-/b-1.0.0.tgz","integrity":"sha512-x"}}}""",
            b => Lockfiles.Read("package-lock.json", Decoded(b))),
        ["Services/Web/Packages/NpmReview.cs"] = (
            """{"name":"a","version":"1.0.0","main":"i.js","scripts":{"postinstall":"node i.js"}}""",
            b => InFolder("package.json", b, dir =>
            {
                var files = Corvus.Services.Web.Packages.PackageFiles.Open(dir, default)!;
                PackageReview.Json(files, "package.json");
            })),
        ["Services/Web/SavedPage.cs"] = (
            """{"imports":{"a":"https://e.example/a.js"},"scopes":{"/x/":{"b":"./b.js"}},"integrity":{"https://e.example/a.js":"sha256-x"}}""",
            b => SavedPage.Read("<html><head><script type=\"importmap\">" + Decoded(b) + "</script></head></html>", "page.html", default)),
    };
}
