using System.IO.Compression;
using System.Resources;
using System.Text;
using System.Text.Json;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>summarize_file, survey_features, extract_strings and extract_embedded over fixtures built at test time.</summary>
public class InspectionTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());
    private InspectionService Inspection => new(_workspace);

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    private string Save(string name, byte[] bytes)
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    /// <summary>Compiles C# against the running framework's assemblies.</summary>
    internal static byte[] Compile(string name, string source)
    {
        return Roslyn.Compile(name, source,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Enable));
    }

    /// <summary>Everyday framework APIs: files, HTTP, the registry, processes.</summary>
    private static byte[] EverydayApis() => Compile("EverydayApis", """
        using System;
        using System.Diagnostics;
        using System.IO;
        using System.Net.Http;
        using System.Threading.Tasks;
        using Microsoft.Win32;

        public static class Everyday
        {
            public static string ReadSettings() => File.ReadAllText(@"C:\ProgramData\Everyday\settings.ini");
            public static void Backdate(string path) => File.SetCreationTime(path, new DateTime(2001, 1, 1));

            public static async Task<string> Fetch()
            {
                using var client = new HttpClient();
                return await client.GetStringAsync("https://example.com/path");
            }

            public static async Task<byte[]> Download()
            {
                using var client = new HttpClient();
                return await client.GetByteArrayAsync("https://example.com/files/update.bin");
            }

            public static object? ReadMode()
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Everyday");
                return key?.GetValue("Mode");
            }

            public static void WriteMode()
            {
                using var key = Registry.CurrentUser.CreateSubKey(@"Software\Everyday");
                key.SetValue("Mode", 1);
            }

            public static void OpenEditor() => Process.Start("notepad.exe", "readme.txt");
        }
        """);

    private const string SecretText = "Quarterly notes, not for sharing.\nStaging server: https://files.example.net/build2\nEnd of file.\n";

    private static byte[] Gzip(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var z = new GZipStream(ms, CompressionLevel.Optimal)) z.Write(data);
        return ms.ToArray();
    }

    private static byte[] Xor(byte[] data, byte[] key) => [.. data.Select((b, i) => (byte)(b ^ key[i % key.Length]))];

    private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

    /// <summary>A .resources container with a byte[] entry and a string entry.</summary>
    private static byte[] ResourcesFile(byte[] blob, string text)
    {
        using var ms = new MemoryStream();
        using (var writer = new ResourceWriter(ms))
        {
            writer.AddResource("blob", blob);
            writer.AddResource("note", text);
            writer.Generate();
        }
        return ms.ToArray();
    }

    /// <summary>One text file embedded with every encoding chain the finder decodes, plus a raw XOR it cannot.</summary>
    private static byte[] EncodedFixture()
    {
        var text = Encoding.UTF8.GetBytes(SecretText);
        var gz = Gzip(text);
        var xor1 = Xor(gz, [0x5A]);
        var xor3 = Xor(gz, [0xC0, 0xFF, 0xEE]);
        return ContainerFixtures.Module("Encoded", m =>
        {
            m.Resources.Add(new EmbeddedResource("notes.b64", Ascii(Convert.ToBase64String(text))));
            m.Resources.Add(new EmbeddedResource("notes.hex", Ascii(Convert.ToHexString(text))));
            m.Resources.Add(new EmbeddedResource("notes.gz.b64", Gzip(Ascii(Convert.ToBase64String(text)))));
            m.Resources.Add(new EmbeddedResource("notes.xor1", xor1));
            m.Resources.Add(new EmbeddedResource("notes.xor3", xor3));
            m.Resources.Add(new EmbeddedResource("notes.b64xor", Ascii(Convert.ToBase64String(xor1))));
            m.Resources.Add(new EmbeddedResource("notes.plainxor", Xor(text, [0x5A])));
            m.Resources.Add(new EmbeddedResource("Encoded.Strings.resources", ResourcesFile(xor1, Convert.ToHexString(text))));

            // Static array initializer: <PrivateImplementationDetails>::data, a FieldRVA of a fixed-size struct.
            var details = new TypeDefUser("", "<PrivateImplementationDetails>", m.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed };
            var valueType = new TypeRefUser(m, "System", "ValueType", m.CorLibTypes.AssemblyRef);
            var size = new TypeDefUser("", $"__StaticArrayInitTypeSize={xor1.Length}", valueType)
            {
                Attributes = TypeAttributes.NestedPrivate | TypeAttributes.ExplicitLayout | TypeAttributes.Sealed,
                ClassLayout = new ClassLayoutUser(1, (uint)xor1.Length),
            };
            details.NestedTypes.Add(size);
            var field = new FieldDefUser("data", new FieldSig(new ValueTypeSig(size)),
                FieldAttributes.Assembly | FieldAttributes.Static | FieldAttributes.InitOnly | FieldAttributes.HasFieldRVA) { InitialValue = xor1 };
            details.Fields.Add(field);
            m.Types.Add(details);

            // String literals and a method referencing the array.
            var holder = new TypeDefUser("Encoded", "Holder", m.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed };
            var method = new MethodDefUser("Strings", MethodSig.CreateStatic(m.CorLibTypes.Void), MethodAttributes.Public | MethodAttributes.Static);
            method.Body = new CilBody();
            foreach (var literal in new[] { Convert.ToBase64String(text), Convert.ToHexString(text) })
            {
                method.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction(literal));
                method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            method.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(field));
            method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            holder.Methods.Add(method);
            m.Types.Add(holder);
        });
    }

    /// <summary>Strings that are typed values, and lookalikes that are not.</summary>
    private static byte[] StringsFixture() => Compile("Strings", """
        public static class Strings
        {
            public static string[] Indicators() => new[]
            {
                "192.0.2.1",
                "https://example.com/path",
                @"C:\Users\Public\Documents\report.txt",
            };

            public static string[] Lookalikes() => new[]
            {
                "http://www.w3.org/2001/XMLSchema",
                "http://schemas.microsoft.com/winfx/2006/xaml/presentation",
                "readme.txt",
                "settings.json",
                "app.config",
                "4.0.0.0",
            };
        }
        """);

    /// <summary>Marker types and attributes that toolchains inject (as de4dot knows them).</summary>
    private static byte[] MarkedFixture() => ContainerFixtures.Module("Marked", m =>
    {
        foreach (var (ns, name) in new[]
                 {
                     ("", "ConfusedByAttribute"),
                     ("SmartAssembly.Attributes", "PoweredByAttribute"),
                     ("Xenocode.Client.Attributes.AssemblyAttributes", "ProcessedByXenocode"),
                     ("Vendor", "ObfuscatedByGoliath"),
                 })
            m.Types.Add(new TypeDefUser(ns, name, m.CorLibTypes.Object.TypeDefOrRef));
        var suppress = new TypeRefUser(m, "System.Runtime.CompilerServices", "SuppressIldasmAttribute", m.CorLibTypes.AssemblyRef);
        m.Assembly.CustomAttributes.Add(new CustomAttribute(new MemberRefUser(m, ".ctor", MethodSig.CreateInstance(m.CorLibTypes.Void), suppress)));
    });

    /// <summary>A DLL from the newest version of a package in the NuGet cache (the newest target framework folder).</summary>
    private static string CachedDll(string package, string dll)
    {
        var folder = Path.GetDirectoryName(ContainerFixtures.NuGetPackage(package))!;
        var found = Directory.EnumerateFiles(Path.Combine(folder, "lib"), dll, SearchOption.AllDirectories).OrderByDescending(p => p, StringComparer.Ordinal).FirstOrDefault();
        Assert.True(found != null, $"{dll} not found in {folder}");
        return found!;
    }

    /// <summary>
    /// API rules match each distinct API once (every call was tested per rule: seconds on a large assembly); the count is
    /// every call, the locations the first in scan order, and a parameter list still tells overloads apart.
    /// </summary>
    [Fact]
    public void Features_count_every_call_and_list_the_first_in_scan_order()
    {
        var source = "using System.Diagnostics; using System.Net.Sockets; public static class Calls {\n" +
                     string.Concat(Enumerable.Range(0, 7).Select(i => $"public static void M{i}() {{ Process.Start(\"a{i}\"); }}\n")) +
                     "public static object Tcp() => new TcpClient(\"h\", 1); public static object Plain() => new TcpClient(); }";
        var report = Inspection.SurveyFeatures(null, Save("Calls.dll", Compile("Calls", source)), null, default);
        var start = report.Features.Single(f => f.Name == "create processes").Evidence.Single(e => e.Feature == "api:System.Diagnostics.Process::Start");
        Assert.Equal(7, start.Count);
        Assert.Equal(Enumerable.Range(0, 7).Select(i => $"Calls::M{i}()"), start.Locations.Select(l => l[..l.IndexOf(" @", StringComparison.Ordinal)]));
        var tcp = report.Features.Single(f => f.Name == "use raw TCP / UDP sockets").Evidence.Single();
        Assert.Equal(("api:System.Net.Sockets.TcpClient::.ctor(System.String,System.Int32)", 1), (tcp.Feature, tcp.Count));
        Assert.StartsWith("Calls::Tcp()", Assert.Single(tcp.Locations));
    }

    private string EightCallsPath() =>
        Save("EightCalls.dll", Compile("EightCalls", "using System.Diagnostics; public static class Calls {\n" +
            string.Concat(Enumerable.Range(0, 8).Select(i => $"public static void M{i}() {{ Process.Start(\"a{i}\"); }}\n")) + "}"));

    private static int ListedCalls(string text) => text.Split('\n').Count(l => l.Contains("Calls::M") && l.Contains(" @IL_"));

    [Fact]
    public void A_capped_list_prints_first_5_of_8_with_the_next_call()
    {
        var report = Inspection.SurveyFeatures(null, EightCallsPath(), "execution", default);
        var shown = Corvus.Tools.ContainerText.Survey(Corvus.Tools.ContainerText.Survey(report, "execution"));
        Assert.Contains("first 5 of 8; rerun with locations=8", shown);
        Assert.Equal(5, ListedCalls(shown));
    }

    [Fact]
    public void Locations_8_lists_all_eight()
    {
        var report = Inspection.SurveyFeatures(null, EightCallsPath(), "execution", default);
        var all = Corvus.Tools.ContainerText.Survey(Corvus.Tools.ContainerText.Survey(report, "execution", 8));
        Assert.DoesNotContain("first 5 of 8", all);
        Assert.DoesNotContain("rerun with locations", all);
        Assert.Equal(8, ListedCalls(all));
    }

    [Fact]
    public void The_path_only_worker_carries_locations_through_its_arguments()
    {
        var args = new Corvus.Tools.FileWork.SurveyArgs(EightCallsPath(), "execution", 8);
        var text = Corvus.Tools.ContainerText.Survey(Corvus.Tools.FileWork.SurveyWith(Inspection, args, default));
        Assert.Equal(8, ListedCalls(text));
    }

    [Fact]
    public void Locations_is_ignored_without_a_category()
    {
        var report = Inspection.SurveyFeatures(null, EightCallsPath(), null, default);
        var text = Corvus.Tools.ContainerText.Survey(Corvus.Tools.ContainerText.Survey(report, null, 8));
        Assert.Equal(0, ListedCalls(text));
        Assert.DoesNotContain("rerun with locations", text);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(101)]
    [InlineData(-1)]
    public async Task A_locations_value_outside_1_to_100_is_refused(int locations)
    {
        var tools = new Corvus.Tools.InspectionTools(new InspectionService(_workspace), _workspace);
        var error = await Assert.ThrowsAsync<ToolError>(() => tools.SurveyFeatures(path: EightCallsPath(), category: "execution", locations: locations));
        Assert.Equal(ErrorCode.InvalidArgument, error.Code);
    }

    [Fact]
    public void Matches_beyond_the_stored_locations_print_the_distinct_count_without_a_rerun()
    {
        var evidence = new Evidence("api:X", 9, ["a", "b"]);
        var feature = new Feature("f", "c", [evidence]);
        var report = new InspectionService.FeatureReport("m", 0, [feature], []);
        var text = Corvus.Tools.ContainerText.Survey(Corvus.Tools.ContainerText.Survey(report, "c"));
        Assert.Contains("9 matches, 2 distinct locations", text);
        Assert.DoesNotContain("rerun with locations", text);
    }

    [Theory]
    [InlineData("RegionInfo.CurrentRegion.Name", true)]
    [InlineData("\"\"", false)]
    public void A_region_read_is_reported_only_with_a_managed_file_delete(string read, bool expected)
    {
        var source = "using System.Globalization; using System.IO; public static class Wipe {\n" +
                     $"public static string Where() => {read};\n" +
                     "public static void Go() { File.Delete(\"a\"); } }";
        var report = Inspection.SurveyFeatures(null, Save("Wipe.dll", Compile("Wipe", source)), null, default);

        Assert.Equal(expected, report.Features.Any(f => f.Name == "delete files and read the locale or region"));
    }

    [Fact]
    public void Everyday_framework_APIs_match_their_features_and_not_stronger_ones()
    {
        var report = Inspection.SurveyFeatures(null, Save("EverydayApis.dll", EverydayApis()), null, default);
        var byName = report.Features.ToDictionary(c => c.Name);

        Assert.Contains(byName["send HTTP requests"].Evidence, e => e.Feature == "api:System.Net.Http.HttpClient::*Async");
        Assert.Equal("network", byName["download files"].Category);
        Assert.Equal("registry", byName["query the registry"].Category);
        Assert.Equal("registry", byName["modify the registry"].Category);
        Assert.Contains(byName["create processes"].Evidence, e => e.Feature == "api:System.Diagnostics.Process::Start" && e.Locations.Any(l => l.Contains("Everyday::OpenEditor")));
        // File.SetCreationTime.
        Assert.Equal("system changes", byName["change file timestamps"].Category);

        // Benign file, process and registry use must not match the stronger features.
        Assert.DoesNotContain("run the Windows command shell", byName.Keys);
        Assert.DoesNotContain("auto-start through a Run registry key", byName.Keys);
        Assert.True(report.MethodsScanned > 5);

        var registry = Inspection.SurveyFeatures(null, _dir.File("EverydayApis.dll"), "registry", default);
        Assert.Equal(["modify the registry", "query the registry"], registry.Features.Select(c => c.Name).Order());
    }

    /// <summary>extract_strings pages its rows and keeps every value: read_result text is the CSV, json the records.</summary>
    [Fact]
    public async Task Values_page_and_keep_every_value_for_read_result()
    {
        var path = Save("EverydayApis.dll", EverydayApis());
        var all = Inspection.ExtractStrings(null, path, null, default);
        Assert.True(all.Total >= 3);
        var store = new ResultStore(ResultCacheOptions.MemoryOnly);
        var tools = new Corvus.Tools.InspectionTools(Inspection, _workspace, null, store);
        var collector = Corvus.Mcp.ToolOutput.Collect();
        var text = await tools.ExtractStrings(path: path, limit: 2);
        var page = Assert.IsType<Corvus.Tools.ValuePage>(collector.Value);
        Assert.Equal(all.Values.Take(2).Select(v => (v.Type, v.Value)), page.Items.Select(v => (v.Type, v.Value)));
        Assert.Equal((0, all.Total), (page.Offset, page.Total));
        Assert.Contains($"(showing 1-2)", text);
        Assert.Contains("[More: offset=2]", text);
        Assert.Contains($"read_result id={page.ValuesResultId}", text);
        var kept = store.Read(page.ValuesResultId!);
        Assert.StartsWith("type,value,count,", kept.Text);
        Assert.Equal(all.Total + 1, kept.Text.TrimEnd('\n').Split('\n').Length);
        Assert.Equal(all.Total, JsonDocument.Parse(kept.Record!).RootElement.GetProperty("items").GetArrayLength());

        collector = Corvus.Mcp.ToolOutput.Collect();
        await tools.ExtractStrings(path: path, types: ["url"], offset: 0);
        Assert.All(Assert.IsType<Corvus.Tools.ValuePage>(collector.Value).Items, v => Assert.Equal("url", v.Type));
        Assert.Contains("Unknown value type", (await Assert.ThrowsAsync<ToolError>(() => tools.ExtractStrings(path: path, types: ["phone"]))).Message);
    }

    /// <summary>The default page counts matches per feature; category= (or all) adds the evidence, a string's marked derived.</summary>
    [Fact]
    public async Task Features_default_page_counts_and_category_adds_evidence_with_basis()
    {
        var path = Save("Bot.dll", Compile("Bot", "public static class Bot { public static string Url = \"https://api.telegram.org/bot1/send\"; " +
                                                  "public static void Run() { System.Diagnostics.Process.Start(\"x\"); System.Diagnostics.Process.Start(\"y\"); } }"));
        var tools = new Corvus.Tools.InspectionTools(new InspectionService(_workspace), _workspace);
        var collector = Corvus.Mcp.ToolOutput.Collect();
        var text = await tools.SurveyFeatures(path: path);
        var page = Assert.IsType<Corvus.Tools.SurveyRecord>(collector.Value);
        var start = page.Features.Single(f => f.Name == "create processes");
        Assert.Equal((2, null, null), (start.Matches, start.Basis, start.Evidence));
        Assert.Equal("derived", page.Features.Single(f => f.Name.StartsWith("communicate through a web service", StringComparison.Ordinal)).Basis);
        Assert.Contains("create processes, 2 matches", text);
        Assert.Contains("Evidence: category=", text);
        Assert.DoesNotContain("Bot::Run", text);

        collector = Corvus.Mcp.ToolOutput.Collect();
        text = await tools.SurveyFeatures(path: path, category: "all");
        var all = Assert.IsType<Corvus.Tools.SurveyRecord>(collector.Value);
        Assert.Equal(page.Features.Select(f => f.Name), all.Features.Select(f => f.Name));
        var url = Assert.Single(all.Features.Single(f => f.Name.StartsWith("communicate through a web service", StringComparison.Ordinal)).Evidence!);
        Assert.Equal("derived", url.Basis);
        Assert.Null(Assert.Single(all.Features.Single(f => f.Name == "create processes").Evidence!).Basis);
        Assert.Contains("api:System.Diagnostics.Process::Start x2", text);
        Assert.Contains("Bot::Run()", text);
    }

    [Fact]
    public async Task Features_take_a_native_image_as_image()
    {
        var path = McpProtocolTests.NativeSample(_dir);
        var native = _workspace.LoadAny(path).Native!;
        var options = new ServerOptions { BackgroundIndexing = false };
        var code = new NativeCodeService(_workspace, options, null, new Corvus.Native.Annotations.AnnotationStore(_dir.File("ann")));
        var tools = new Corvus.Tools.InspectionTools(new InspectionService(_workspace, code), _workspace, code);
        var byImage = await tools.SurveyFeatures(image: native.Id);
        var byAssembly = await tools.SurveyFeatures(assembly: native.Id);
        Assert.Equal(byAssembly, byImage);
        // An image path that is not loaded is read as a file.
        var copy = _dir.File("unloaded-copy.bin");
        File.Copy(path, copy);
        static string Rows(string text) => text[text.IndexOf('\n')..];
        Assert.Equal(Rows(byImage), Rows(await tools.SurveyFeatures(image: copy)));
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.SurveyFeatures(assembly: native.Id, image: native.Id))).Code);
    }

    [Fact]
    public void Features_of_a_loaded_assembly_match_the_file()
    {
        var path = Save("EverydayApis.dll", EverydayApis());
        var loaded = _workspace.Load(path);
        var fromFile = Inspection.SurveyFeatures(null, path, null, default).Features.Select(c => c.Name);
        var fromWorkspace = Inspection.SurveyFeatures(loaded.Id, null, null, default).Features.Select(c => c.Name);
        Assert.Equal(fromFile.Order(), fromWorkspace.Order());
    }

    [Fact]
    public void Embedded_encoded_copies_of_a_text_file_are_decoded_with_their_chain()
    {
        var report = Inspection.ExtractEmbedded(null, Save("Encoded.dll", EncodedFixture()), false, null, false, default);
        var original = Encoding.UTF8.GetBytes(SecretText);
        var texts = report.Contents.Where(p => p.Kind == "text").ToList();
        Assert.All(texts, p => Assert.Equal(original, p.Bytes));

        var found = string.Join("\n", report.Contents.Select(p => $"{p.Source} [{p.Kind}] {string.Join(" > ", p.Encoding)}"));
        string Chain(string source)
        {
            var matches = texts.Where(p => p.Source.StartsWith(source, StringComparison.Ordinal)).ToList();
            Assert.True(matches.Count == 1, $"{matches.Count} text item(s) from {source}; found:\n{found}");
            return string.Join(" > ", matches[0].Encoding);
        }
        Assert.Equal("base64", Chain("resource 'notes.b64'"));
        Assert.Equal("hex", Chain("resource 'notes.hex'"));
        Assert.Equal("gzip > base64", Chain("resource 'notes.gz.b64'"));
        Assert.Equal("xor key 5a > gzip", Chain("resource 'notes.xor1'"));
        Assert.Equal("xor key c0ffee > gzip", Chain("resource 'notes.xor3'"));
        Assert.Equal("base64 > xor key 5a > gzip", Chain("resource 'notes.b64xor'"));
        Assert.Equal("xor key 5a > gzip", Chain("resource 'Encoded.Strings.resources:blob'"));
        Assert.Equal("hex", Chain("resource 'Encoded.Strings.resources:note'"));
        Assert.Equal("xor key 5a > gzip", Chain("static data <PrivateImplementationDetails>::data (used in Encoded.Holder::Strings()"));
        Assert.Equal("base64", Chain("string Encoded.Holder::Strings() @IL_0000"));
        Assert.Equal("hex", Chain("string Encoded.Holder::Strings() @IL_0006"));
        Assert.Equal(11, texts.Count);

        // Raw XOR over text has no known header to recover the key from.
        Assert.DoesNotContain(report.Contents, p => p.Source.StartsWith("resource 'notes.plainxor'", StringComparison.Ordinal));
    }

    /// <summary>A container path searches every assembly inside; rows page with the list envelope and save writes them all.</summary>
    [Fact]
    public async Task Extract_embedded_on_a_container_searches_its_assemblies_and_pages()
    {
        var single = Inspection.ExtractEmbedded(null, Save("Encoded.dll", EncodedFixture()), false, null, false, default);
        var zip = Save("app.zip", ContainerFixtures.Zip(("lib/Encoded.dll", File.ReadAllBytes(_dir.File("Encoded.dll"))), ("readme.txt", "x"u8.ToArray())));
        var inZip = Inspection.ExtractEmbedded(null, zip, false, null, false, default);
        Assert.Equal(single.Contents.Select(c => "lib/Encoded.dll: " + c.Source), inZip.Contents.Select(c => c.Source));
        Assert.Equal("app.zip", inZip.Assembly);

        var tools = new Corvus.Tools.InspectionTools(Inspection, _workspace);
        var collector = Corvus.Mcp.ToolOutput.Collect();
        var text = await tools.ExtractEmbedded(path: zip, offset: 2, limit: 3, save: true, outputDirectory: _dir.File("zip-out"));
        var page = Assert.IsType<Corvus.Tools.EmbeddedPage>(collector.Value);
        Assert.Equal((2, inZip.Contents.Count, 3), (page.Offset, page.Total, page.Items.Count));
        Assert.Equal(inZip.Contents.Skip(2).Take(3).Select(c => c.Source), page.Items.Select(c => c.Source));
        Assert.Equal(inZip.Contents.Count, Directory.GetFiles(_dir.File("zip-out"), "embedded_*").Length);
        Assert.Contains("(showing 3-5)", text);
        Assert.Contains("[More: offset=5]", text);
    }

    [Fact]
    public void Embedded_native_images_in_a_native_file_report_their_offset_and_save_identical_bytes()
    {
        var inner = NativePeTests.KitchenSink(is64: false);
        var outer = NativePeTests.KitchenSink(is64: true);
        var padded = outer.Length + (16 - outer.Length % 16) % 16;
        var file = new byte[padded + inner.Length];
        outer.CopyTo(file, 0);
        inner.CopyTo(file, padded);
        var path = Save("Outer.exe", file);

        var report = Inspection.ExtractEmbedded(null, path, true, _dir.File("native-out"), false, default);
        var item = Assert.Single(report.Contents, c => c.FileOffset == padded);
        Assert.Equal("native PE", item.Kind);
        Assert.Equal(inner, File.ReadAllBytes(item.SavedTo!));
    }

    [Fact]
    public void Embedded_a_native_image_inside_a_section_is_listed_with_its_offset()
    {
        var inner = NativePeTests.KitchenSink(is64: false);
        var builder = new PeBuilder { EntryPoint = 0x1000 };
        builder.Add(".text", [0xC3], 0x60000020);
        builder.Add(".rsrc", inner);
        var file = builder.Build();
        var at = file.AsSpan().IndexOf(inner);
        Assert.True(at > 0);
        var path = Save("Resource.exe", file);

        var report = Inspection.ExtractEmbedded(null, path, true, _dir.File("section-out"), false, default);
        var item = Assert.Single(report.Contents, c => c.FileOffset == at);
        Assert.Equal(inner, File.ReadAllBytes(item.SavedTo!));
        Assert.Contains($"at file offset {at} (0x{at:X})", Corvus.Tools.ContainerText.Embedded(report, 0, 10));
    }

    [Fact]
    public void Embedded_a_managed_image_inside_a_native_file_keeps_the_container_path()
    {
        var inner = Compile("Inner", "public static class Inner { public static int V = 1; }");
        var outer = NativePeTests.KitchenSink(is64: true);
        var padded = outer.Length + (16 - outer.Length % 16) % 16;
        var file = new byte[padded + inner.Length];
        outer.CopyTo(file, 0);
        inner.CopyTo(file, padded);

        var report = Inspection.ExtractEmbedded(null, Save("Holder.exe", file), false, null, false, default);
        Assert.DoesNotContain(report.Contents, c => c.FileOffset != null);
        Assert.DoesNotContain(report.Notes, n => n.Contains("found past the header"));
    }

    [Fact]
    public void Strings_of_a_native_image_are_typed_with_section_and_address()
    {
        var builder = new PeBuilder { EntryPoint = 0x1000 };
        builder.Add(".text", [0xC3], 0x60000020);
        var strings = new[] { "https://updates.example.net/v1/check", @"C:\ProgramData\Vendor\cache.bin", @"HKEY_LOCAL_MACHINE\SOFTWARE\Vendor\Setup", "192.0.2.44:8443" };
        builder.Add(".rdata", System.Text.Encoding.ASCII.GetBytes("\0" + string.Join("\0", strings) + "\0"));
        var path = Save("Typed.exe", builder.Build());

        var report = Inspection.ExtractStrings(null, path, null, default);
        var url = Assert.Single(report.Values, v => v.Type == "url");
        Assert.Equal("https://updates.example.net/v1/check", url.Value);
        Assert.Matches(@"^\.rdata 0x14[0-9A-F]+$", Assert.Single(url.Locations));
        Assert.Contains(report.Values, v => v.Type == "file_path");
        Assert.Contains(report.Values, v => v.Type == "registry_key");
        Assert.Contains(report.Values, v => v.Type == "ipv4" && v.Value.StartsWith("192.0.2.44", StringComparison.Ordinal));
        Assert.All(Inspection.ExtractStrings(null, path, ["url"], default).Values, v => Assert.Equal("url", v.Type));
    }

    [Fact]
    public void Embedded_a_native_file_without_inner_images_takes_the_existing_path()
    {
        var path = Save("Plain.exe", NativePeTests.KitchenSink(is64: true));
        var error = Assert.Throws<ToolError>(() => Inspection.ExtractEmbedded(null, path, false, null, false, default));
        Assert.Contains("not a .NET assembly", error.Message);
    }

    [Fact]
    public void Embedded_save_writes_defanged_files_and_values_come_from_decoded_text()
    {
        var path = Save("Encoded.dll", EncodedFixture());
        var saved = Inspection.ExtractEmbedded(null, path, true, _dir.File("embedded"), false, default);
        Assert.NotNull(saved.OutputDirectory);
        Assert.All(saved.Contents, p => Assert.StartsWith(saved.OutputDirectory!, p.SavedTo));
        Assert.All(saved.Contents.Where(p => p.Kind == "text"), p => Assert.Equal(SecretText, File.ReadAllText(p.SavedTo!)));
        Assert.All(saved.Contents, p => Assert.Matches(@"^embedded_\d\d\.\w+$", Path.GetFileName(p.SavedTo!)));

        // The default folder (under %TEMP%) is named after the file and its hash: a name of this run's own, so concurrent runs do not share it.
        var unique = Save($"Encoded-{Guid.NewGuid():N}.dll", File.ReadAllBytes(path));
        var byDefault = Inspection.ExtractEmbedded(null, unique, true, null, false, default);
        try
        {
            Assert.Equal("corvus-embedded", Path.GetFileName(Path.GetDirectoryName(byDefault.OutputDirectory!)));
            Assert.StartsWith(Path.GetFileNameWithoutExtension(unique), Path.GetFileName(byDefault.OutputDirectory!), StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(byDefault.OutputDirectory!, recursive: true);
            try { Directory.Delete(Path.GetDirectoryName(byDefault.OutputDirectory!)!); }
            catch (IOException) { /* another test's output is still there */ }
        }

        var url = Assert.Single(Inspection.ExtractStrings(null, path, ["url"], default).Values);
        Assert.Equal("https://files.example.net/build2", url.Value);
        Assert.Contains(url.Locations, l => l.Contains("(decoded: "));
    }

    [Fact]
    public void Embedded_XOR_text_recovers_single_byte_keys_when_asked_to()
    {
        var path = Save("Encoded.dll", EncodedFixture());
        Assert.DoesNotContain(Inspection.ExtractEmbedded(null, path, false, null, false, default).Contents,
            // Off by default.
            p => p.Source.StartsWith("resource 'notes.plainxor'", StringComparison.Ordinal));

        var on = Inspection.ExtractEmbedded(null, path, false, null, false, default, xorText: true);
        var recovered = Assert.Single(on.Contents, p => p.Source.StartsWith("resource 'notes.plainxor'", StringComparison.Ordinal));
        Assert.Equal("text", recovered.Kind);
        Assert.Equal(["xor key 5a (brute-forced)"], recovered.Encoding);
        Assert.Equal(Encoding.UTF8.GetBytes(SecretText), recovered.Bytes);
        Assert.Equal("inferred", recovered.Basis);
        Assert.All(on.Contents.Where(p => p != recovered && !p.Kind.StartsWith("high-entropy", StringComparison.Ordinal)), p => Assert.Null(p.Basis));
        // Default results are unchanged.
        var off = Inspection.ExtractEmbedded(null, path, false, null, false, default);
        Assert.Equal(off.Contents.Select(p => (p.Source, string.Join(">", p.Encoding))).Order(),
            on.Contents.Where(p => p != recovered).Select(p => (p.Source, string.Join(">", p.Encoding))).Order());
    }

    [Fact]
    public void Sibling_high_entropy_resources_report_a_shared_block_offset()
    {
        // Two random 2 KB resources that carry the same 8-byte block at 0x10.
        var a = new byte[2048];
        var b = new byte[2048];
        new Random(11).NextBytes(a);
        new Random(12).NextBytes(b);
        a.AsSpan(0x10, 8).CopyTo(b.AsSpan(0x10, 8));
        var fixture = ContainerFixtures.Module("Siblings", m =>
        {
            m.Resources.Add(new EmbeddedResource("a.bin", a));
            m.Resources.Add(new EmbeddedResource("b.bin", b));
        });
        var report = Inspection.ExtractEmbedded(null, Save("Siblings.dll", fixture), false, null, false, default);
        var first = Assert.Single(report.Contents, p => p.Source == "resource 'a.bin'");
        Assert.Contains("8-byte block shared at 0x10", first.Detail);
        Assert.Contains("structural signal only", first.Detail);
        Assert.Contains("resource 'b.bin'", first.Detail);
        var second = Assert.Single(report.Contents, p => p.Source == "resource 'b.bin'");
        Assert.Contains("resource 'a.bin'", second.Detail);
        Assert.Contains("8-byte block shared at 0x10", second.Detail);
    }

    [Fact]
    public void A_high_entropy_resource_without_siblings_carries_no_shared_note()
    {
        var fixture = ContainerFixtures.Module("Alone", m => m.Resources.Add(new EmbeddedResource("a.bin", Random2K(21))));
        var report = Inspection.ExtractEmbedded(null, Save("Alone.dll", fixture), false, null, false, default);
        Assert.Null(Assert.Single(report.Contents, p => p.Source == "resource 'a.bin'").Detail);
    }

    [Fact]
    public void A_16_byte_block_shared_between_siblings_is_not_repeated_as_8_byte_blocks()
    {
        var a = Random2K(31);
        var b = Random2K(32);
        a.AsSpan(0x30, 16).CopyTo(b.AsSpan(0x30, 16));
        Assert.Equal("16-byte block shared at 0x30 (structural signal only)", BlockRepeats.Shared(a, b));
    }

    [Fact]
    public void Sibling_buffers_of_unequal_length_compare_the_common_prefix()
    {
        var a = Random2K(41);
        var b = Random2K(42)[..1024];
        a.AsSpan(0x200, 8).CopyTo(b.AsSpan(0x200, 8));
        a.AsSpan(0x600, 8).CopyTo(b.AsSpan(0x100, 8));
        Assert.Equal("8-byte block shared at 0x200 (structural signal only)", BlockRepeats.Shared(a, b));
    }

    [Fact]
    public void Sibling_buffers_report_a_shared_header_and_where_they_differ()
    {
        byte[] a = [0x4D, 0x5A, 0x90, 0x00, 1, 2, 3, 4, 5, 6];
        byte[] b = [0x4D, 0x5A, 0x90, 0x00, 9, 9, 9, 9, 9, 9];
        Assert.Equal("4-byte header shared (4D5A9000); differs at 0x4", BlockRepeats.Header(a, b));
        Assert.Equal("10-byte header shared (4D5A900001020304...)", BlockRepeats.Header(a, a));
    }

    [Fact]
    public void Sibling_buffers_under_four_shared_bytes_report_no_header()
    {
        Assert.Null(BlockRepeats.Header([1, 2, 3], [2, 2, 3]));
        Assert.Null(BlockRepeats.Header([1, 2, 3, 4], [1, 2, 3, 5]));
        Assert.Null(BlockRepeats.Header([], [1]));
    }

    [Fact]
    public void Sibling_resources_with_one_header_name_its_length_and_difference()
    {
        var a = Random2K(81);
        var b = Random2K(82);
        var c = Random2K(83);
        a.AsSpan(0, 6).CopyTo(b.AsSpan(0, 6));
        Assert.Equal(6, a.AsSpan().CommonPrefixLength(b));
        Assert.True(a.AsSpan().CommonPrefixLength(c) < 4);
        Assert.True(b.AsSpan().CommonPrefixLength(c) < 4);
        var fixture = ContainerFixtures.Module("Headers", m =>
        {
            m.Resources.Add(new EmbeddedResource("a.bin", a));
            m.Resources.Add(new EmbeddedResource("b.bin", b));
            m.Resources.Add(new EmbeddedResource("c.bin", c));
        });
        var report = Inspection.ExtractEmbedded(null, Save("Headers.dll", fixture), false, null, false, default);
        string expected = $"6-byte header shared ({Convert.ToHexString(a.AsSpan(0, 6))}); differs at 0x6 (structural signal only)";
        var da = Assert.Single(report.Contents, p => p.Source == "resource 'a.bin'").Detail;
        var db = Assert.Single(report.Contents, p => p.Source == "resource 'b.bin'").Detail;
        Assert.Contains($"resource 'b.bin': {expected}", da);
        Assert.Contains($"resource 'a.bin': {expected}", db);
        Assert.Null(Assert.Single(report.Contents, p => p.Source == "resource 'c.bin'").Detail);
    }

    [Fact]
    public void Sibling_resources_sharing_one_byte_stay_unannotated()
    {
        var a = Random2K(84);
        var b = Random2K(85);
        b[0] = a[0];
        Assert.Equal(1, a.AsSpan().CommonPrefixLength(b));
        var fixture = ContainerFixtures.Module("OneByte", m =>
        {
            m.Resources.Add(new EmbeddedResource("a.bin", a));
            m.Resources.Add(new EmbeddedResource("b.bin", b));
        });
        var report = Inspection.ExtractEmbedded(null, Save("OneByte.dll", fixture), false, null, false, default);
        Assert.All(report.Contents.Where(p => p.Source.StartsWith("resource '")), p => Assert.Null(p.Detail));
    }

    [Fact]
    public void Sibling_resources_with_a_header_and_a_block_name_both_notes()
    {
        var a = Random2K(86);
        var b = Random2K(87);
        a.AsSpan(0, 6).CopyTo(b.AsSpan(0, 6));
        a.AsSpan(0x200, 8).CopyTo(b.AsSpan(0x200, 8));
        var fixture = ContainerFixtures.Module("HeaderBlock", m =>
        {
            m.Resources.Add(new EmbeddedResource("a.bin", a));
            m.Resources.Add(new EmbeddedResource("b.bin", b));
        });
        var report = Inspection.ExtractEmbedded(null, Save("HeaderBlock.dll", fixture), false, null, false, default);
        var da = Assert.Single(report.Contents, p => p.Source == "resource 'a.bin'").Detail;
        Assert.Contains($"8-byte block shared at 0x200; 6-byte header shared ({Convert.ToHexString(a.AsSpan(0, 6))}); differs at 0x6 (structural signal only)", da);
    }

    [Fact]
    public void A_shorter_buffer_that_is_a_prefix_names_where_it_ends()
    {
        var a = Random2K(88);
        Assert.Equal($"1024-byte header shared ({Convert.ToHexString(a.AsSpan(0, 8))}...); shorter buffer ends at 0x400",
            BlockRepeats.Header(a, a[..1024]));
    }

    [Fact]
    public void Sibling_notes_name_three_siblings_then_count_the_rest()
    {
        var common = Random2K(51).AsSpan(0, 8).ToArray();
        var fixture = ContainerFixtures.Module("Many", m =>
        {
            for (int i = 0; i < 6; i++)
            {
                var data = Random2K(60 + i);
                common.CopyTo(data, 0x10);
                m.Resources.Add(new EmbeddedResource($"r{i}.bin", data));
            }
        });
        var report = Inspection.ExtractEmbedded(null, Save("Many.dll", fixture), false, null, false, default);
        var first = Assert.Single(report.Contents, p => p.Source == "resource 'r0.bin'");
        Assert.Contains("and 2 more siblings", first.Detail);
        Assert.Equal(3, first.Detail!.Split("resource 'r").Length - 1);
    }

    [Fact]
    public void A_high_entropy_resource_with_an_internal_repeat_carries_the_detail()
    {
        var data = Random2K(71);
        data.AsSpan(0x40, 16).CopyTo(data.AsSpan(0x400, 16));
        var fixture = ContainerFixtures.Module("Inner", m => m.Resources.Add(new EmbeddedResource("a.bin", data)));
        var report = Inspection.ExtractEmbedded(null, Save("Inner.dll", fixture), false, null, false, default);
        Assert.Contains("0x40, 0x400", Assert.Single(report.Contents, p => p.Source == "resource 'a.bin'").Detail);
    }

    [Fact]
    public void Short_and_uniform_buffers_have_no_repeated_blocks()
    {
        Assert.Null(BlockRepeats.Within([1, 2, 3]));
        Assert.Null(BlockRepeats.Within([]));
        Assert.Null(BlockRepeats.Within(new byte[64]));
        Assert.Null(BlockRepeats.Shared(new byte[64], new byte[64]));
        Assert.Null(BlockRepeats.Shared([1, 2, 3], [1, 2, 3]));
    }

    [Fact]
    public void Repeated_block_groups_beyond_three_are_counted()
    {
        var data = new byte[8 * 10];
        for (int g = 0; g < 5; g++)
        {
            data[g * 16] = (byte)(g + 1);
            data[g * 16 + 8] = (byte)(g + 1);
        }
        var note = BlockRepeats.Within(data);
        Assert.Contains("and 2 more 8-byte groups", note);
        Assert.DoesNotContain("16-byte", note);
    }

    private static byte[] Random2K(int seed)
    {
        var data = new byte[2048];
        new Random(seed).NextBytes(data);
        return data;
    }

    [Fact]
    public void A_block_repeated_inside_one_buffer_is_named_with_its_offsets()
    {
        var data = new byte[256];
        new Random(5).NextBytes(data);
        data.AsSpan(0x20, 16).CopyTo(data.AsSpan(0x80, 16));
        var note = BlockRepeats.Within(data);
        Assert.Contains("16-byte block", note);
        Assert.Contains("0x20, 0x80", note);
        Assert.Null(BlockRepeats.Within(Unrepeated()));
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public void Embedded_XOR_text_rejects_readable_and_random_data()
    {
        var random = new byte[2048];
        new Random(7).NextBytes(random);
        var fixture = ContainerFixtures.Module("NotXor", m =>
        {
            m.Resources.Add(new EmbeddedResource("utf16.txt", Encoding.Unicode.GetBytes(SecretText)));                 // UTF-16, not XORed
            m.Resources.Add(new EmbeddedResource("readme.txt", Encoding.UTF8.GetBytes(SecretText + SecretText)));       // readable already
            m.Resources.Add(new EmbeddedResource("random.bin", random));
            m.Resources.Add(new EmbeddedResource("table.bin", [.. Enumerable.Range(0, 512).SelectMany(i => BitConverter.GetBytes(i * 7))]));
        });
        var report = Inspection.ExtractEmbedded(null, Save("NotXor.dll", fixture), false, null, false, default, xorText: true);
        Assert.DoesNotContain(report.Contents, p => p.Encoding.Any(e => e.Contains("brute-forced")));
        Assert.Contains(report.Contents, p => p.Source == "resource 'random.bin'" && p.Kind.StartsWith("high-entropy"));

        // Real resources and tables (codec, opcode) must not yield false decodes.
        foreach (var real in new[]
                 {
                     Env.FixturePath, CachedDll("Microsoft.CodeAnalysis.Common", "Microsoft.CodeAnalysis.dll"),
                     RealPackages.Lib("OggVorbisEncoder", "1.2.2", "net6.0", "OggVorbisEncoder.dll"),
                     RealPackages.Lib("Iced", "1.21.0", "netstandard2.1", "Iced.dll"),
                 })
            Assert.DoesNotContain(Inspection.ExtractEmbedded(null, real, false, null, false, default, xorText: true).Contents,
                p => p.Encoding.Any(e => e.Contains("brute-forced")));
    }

    [Fact]
    public void Embedded_XOR_text_recovers_structured_configuration()
    {
        const string Json = "{\"servers\":[\"https://update.example-cdn.net/api/v2/status\",\"https://backup.example.org/sync.php\"],\"interval\":300,\"jitter\":0.2,\"channel\":\"q3-rollout\",\"install\":{\"path\":\"%APPDATA%\\\\svc\",\"autorun\":true}}";
        const string Urls = "https://a.example.net/x.bin\nhttps://b.example.org/files/build2.dat\nhttp://10.20.30.40:8080/up\n";
        const string Ini = "[server]\nhost=relay.example.com\nport=4433\nkey=6f1e2d3c4b5a\nretry=5\n";
        var fixture = ContainerFixtures.Module("Configs", m =>
        {
            m.Resources.Add(new EmbeddedResource("config.bin", Xor(Encoding.UTF8.GetBytes(Json), [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77])));
            m.Resources.Add(new EmbeddedResource("urls.bin", Xor(Encoding.UTF8.GetBytes(Urls), [0xA5, 0x5A, 0x3C])));
            m.Resources.Add(new EmbeddedResource("ini.bin", Xor(Encoding.UTF8.GetBytes(Ini), [0x7E])));
        });
        var report = Inspection.ExtractEmbedded(null, Save("Configs.dll", fixture), false, null, false, default, xorText: true);
        EmbeddedContent Found(string resource)
        {
            var hit = report.Contents.FirstOrDefault(p => p.Source == $"resource '{resource}'");
            Assert.True(hit != null, string.Join(" | ", report.Contents.Select(c => $"{c.Source} [{string.Join(">", c.Encoding)}] {c.Kind}")));
            return hit!;
        }
        Assert.Equal(Json, Encoding.UTF8.GetString(Found("config.bin").Bytes));
        Assert.Equal(["xor key 11223344556677 (brute-forced)"], Found("config.bin").Encoding);
        Assert.Equal(Urls, Encoding.UTF8.GetString(Found("urls.bin").Bytes));
        Assert.Equal(Ini, Encoding.UTF8.GetString(Found("ini.bin").Bytes));
    }

    [Fact]
    public void Embedded_XOR_text_recovers_multi_byte_keys_UTF16_and_other_scripts()
    {
        const string Arabic = "ملاحظات ربع سنوية، ليست للمشاركة. خادم التجهيز جاهز الآن والنهاية قريبة.\n";
        var text = SecretText + SecretText;
        var fixture = ContainerFixtures.Module("MultiXor", m =>
        {
            m.Resources.Add(new EmbeddedResource("key4.bin", Xor(Encoding.UTF8.GetBytes(text), [0x13, 0x37, 0xC0, 0xDE])));
            m.Resources.Add(new EmbeddedResource("utf16.bin", Xor(Encoding.Unicode.GetBytes(text), [0x5A, 0xA5, 0x3C])));
            m.Resources.Add(new EmbeddedResource("arabic.bin", Xor(Encoding.UTF8.GetBytes(Arabic + Arabic + Arabic), [0x21, 0x42, 0x63, 0x84, 0xA5])));
        });
        var report = Inspection.ExtractEmbedded(null, Save("MultiXor.dll", fixture), false, null, false, default, xorText: true);
        EmbeddedContent Found(string resource)
        {
            var hit = report.Contents.FirstOrDefault(p => p.Source == $"resource '{resource}'");
            Assert.True(hit != null, string.Join(" | ", report.Contents.Select(c => $"{c.Source} [{string.Join(">", c.Encoding)}] {c.Kind}")));
            return hit!;
        }

        var key4 = Found("key4.bin");
        Assert.Equal(["xor key 1337c0de (brute-forced)"], key4.Encoding);
        Assert.Equal(text, Encoding.UTF8.GetString(key4.Bytes));

        var utf16 = Found("utf16.bin");
        Assert.Equal(["xor key 5aa53c (brute-forced, UTF-16 text)"], utf16.Encoding);
        // Returned as UTF-8.
        Assert.Equal(text, Encoding.UTF8.GetString(utf16.Bytes));

        var arabic = Found("arabic.bin");
        Assert.Equal(["xor key 21426384a5 (brute-forced)"], arabic.Encoding);
        Assert.Equal(Arabic + Arabic + Arabic, Encoding.UTF8.GetString(arabic.Bytes));
    }

    [Fact]
    public void Values_classified_by_type_and_lookalikes_left_out()
    {
        var report = Inspection.ExtractStrings(null, Save("Strings.dll", StringsFixture()), null, default);
        var found = report.Values.Select(i => (i.Type, i.Value)).ToList();

        Assert.Contains(("ipv4", "192.0.2.1"), found);
        Assert.Contains(("url", "https://example.com/path"), found);
        Assert.Contains(("domain", "example.com"), found);
        Assert.Contains(("file_path", @"C:\Users\Public\Documents\report.txt"), found);
        Assert.Equal(4, found.Count);

        Assert.DoesNotContain(found, f => f.Value.Contains("w3.org") || f.Value.Contains("schemas.microsoft.com"));
        Assert.DoesNotContain(found, f => f.Value is "readme.txt" or "settings.json" or "app.config" or "4.0.0.0");
    }

    [Fact]
    public void A_container_path_reads_its_own_assemblies_and_skips_the_framework_ones()
    {
        var zip = _dir.File("app.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        {
            archive.CreateEntryFromFile(Save("App.dll", Roslyn.Release("App", """public static class C { public static string U() => "https://example.com/api/items"; }""")), "lib/App.dll");
            archive.CreateEntryFromFile(Path.Combine(System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory(), "System.Runtime.dll"), "lib/System.Runtime.dll");
        }
        var report = Inspection.ExtractStrings(null, zip, null, default);
        var url = Assert.Single(report.Values, v => v.Type == "url");
        Assert.Equal("https://example.com/api/items", url.Value);
        Assert.All(url.Locations, l => Assert.StartsWith("lib/App.dll: ", l));
        Assert.Equal("1 of the container's 1 own assemblies read; 1 framework assemblies skipped.", report.Notes[0]);
        Assert.Null(report.Partial);
    }

    [Fact]
    public void A_container_with_more_own_assemblies_than_are_read_names_the_rest_as_partial()
    {
        var zip = _dir.File("many.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
            for (int i = 0; i < 9; i++)
                archive.CreateEntryFromFile(Save($"Lib{i}.dll", Roslyn.Release($"Lib{i}", $"public static class C{i} {{ }}")), $"Lib{i}.dll");
        var report = Inspection.ExtractStrings(null, zip, null, default);
        Assert.Equal("the first 8 of 9 assemblies are read, host and main first", report.Partial);
    }

    [Fact]
    public void A_whole_base64_literal_is_an_encoded_value_with_the_api_it_is_passed_to()
    {
        var key = Convert.ToBase64String([.. Enumerable.Range(1, 32).Select(i => (byte)i)]);
        var path = Save("Keys.dll", Roslyn.Release("Keys", $$"""
            public static class K
            {
                public static byte[] Key() => System.Convert.FromBase64String("{{key}}");
                public static string Name() => "PlayerController2DSpawner";
            }
            """));
        var row = Assert.Single(Inspection.ExtractStrings(null, path, ["encoded"], default).Values);
        Assert.Equal((key, "base64, 32 bytes"), (row.Value, row.Detail));
        Assert.Contains("System.Convert::FromBase64String", row.PassedTo);
    }

    [Fact]
    public void Encoded_literals_past_the_cap_of_an_assembly_are_counted_not_listed()
    {
        var keys = Enumerable.Range(0, Values.MaxEncoded + 5).Select(i => Convert.ToBase64String([.. Enumerable.Range(i, 32).Select(b => (byte)b)]));
        var literals = string.Join(", ", keys.Select(k => "\"" + k + "\""));
        var path = Save("ManyKeys.dll", Roslyn.Release("ManyKeys", "public static class K { public static string[] All() => new[] { " + literals + " }; }"));
        var report = Inspection.ExtractStrings(null, path, ["encoded"], default);
        Assert.Equal(Values.MaxEncoded, report.Values.Count);
        Assert.Equal("5 encoded values past 100 per assembly are not listed", report.Partial);
    }

    [Fact]
    public void Values_beside_a_long_run_of_colons_keep_their_addresses()
    {
        // The run backtracked an IPv6 pattern of three overlapping classes past its 1 s timeout, and the text lost its addresses.
        var text = "fe80::1 and 2001:db8::7\n" + new string(':', 20_000) + "g";
        var fixture = ContainerFixtures.Module("Colons", m => m.Resources.Add(new EmbeddedResource("notes.txt", Encoding.UTF8.GetBytes(text))));
        var found = Inspection.ExtractStrings(null, Save("Colons.dll", fixture), null, default).Values.Select(i => (i.Type, i.Value)).ToList();
        Assert.Contains(("ipv6", "fe80::1"), found);
        Assert.Contains(("ipv6", "2001:db8::7"), found);
    }

    [Fact]
    public void Values_of_everyday_APIs_know_where_they_go_and_export()
    {
        var path = Save("EverydayApis.dll", EverydayApis());
        var report = Inspection.ExtractStrings(null, path, null, default);
        var url = Assert.Single(report.Values, i => i.Type == "url" && i.Value == "https://example.com/path");
        Assert.Contains("System.Net.Http.HttpClient::GetStringAsync", url.PassedTo);
        Assert.Contains(report.Values, i => i.Type == "file_path" && i.Value == @"C:\ProgramData\Everyday\settings.ini");
        Assert.Contains(report.Values, i => i.Type == "registry_key" && i.Value == @"Software\Everyday");

        var filtered = Inspection.ExtractStrings(null, path, ["url", "domain"], default);
        Assert.All(filtered.Values, i => Assert.Contains(i.Type, new[] { "url", "domain" }));

        Assert.Contains("Unknown value type", Assert.Throws<ToolError>(() => Inspection.ExtractStrings(null, path, ["phone"], default)).Message);
    }

    [Fact]
    public void Microsoft_signed_assemblies_verify_and_an_unsigned_one_has_no_certificate()
    {
        foreach (var (package, dll) in new[] { ("Microsoft.CodeAnalysis.CSharp", "Microsoft.CodeAnalysis.CSharp.dll"), ("Microsoft.CodeAnalysis.Common", "Microsoft.CodeAnalysis.dll") })
        {
            var sig = Certificates.Read(File.ReadAllBytes(CachedDll(package, dll)));
            Assert.True(sig.Present, dll);
            Assert.Null(sig.Problem);
            Assert.Contains("O=Microsoft Corporation", sig.Signer);
            Assert.True(sig.DigestMatches, dll);
            Assert.True(sig.SignatureValid, dll);
            Assert.Equal("SHA256", sig.DigestAlgorithm);
            // Trusted or not depends on the machine's root store.
            Assert.NotNull(sig.Chain);
        }

        var dnlib = Certificates.Read(File.ReadAllBytes(CachedDll("dnlib", "dnlib.dll")));
        Assert.False(dnlib.Present);
        Assert.Null(dnlib.Signer);
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public void Summary_shows_strong_names_and_signatures_and_a_changed_byte_breaks_the_digest()
    {
        var roslyn = File.ReadAllBytes(CachedDll("Microsoft.CodeAnalysis.Common", "Microsoft.CodeAnalysis.dll"));
        var signed = Inspection.Summarize(null, Save("Microsoft.CodeAnalysis.dll", roslyn), default);
        var one = Assert.Single(signed.Assemblies);
        Assert.True(one.Signature.StrongNamed);
        Assert.Equal("31bf3856ad364e35", one.Signature.PublicKeyToken);
        Assert.True(one.Signature.Certificate.DigestMatches);
        Assert.Contains(signed.Highlights, h => h.Contains("Authenticode-signed by") && h.Contains("Microsoft Corporation"));

        var unsigned = Assert.Single(Inspection.Summarize(null, CachedDll("dnlib", "dnlib.dll"), default).Assemblies);
        Assert.False(unsigned.Signature.Certificate.Present);
        Assert.DoesNotContain(unsigned.Highlights, h => h.Contains("Authenticode"));

        // One changed byte: the signature verifies but the digest no longer matches.
        var modified = roslyn.ToArray();
        modified[modified.Length / 2] ^= 0xFF;
        var t = Certificates.Read(modified);
        Assert.False(t.DigestMatches);
        Assert.True(t.SignatureValid);
        Assert.Contains(Inspection.Summarize(null, Save("modified.dll", modified), default).Highlights, h => h.Contains("modified after signing"));

        // Truncated inside the certificate table.
        var cut = Certificates.Read(roslyn[..(roslyn.Length - 100)]);
        Assert.True(cut.Present);
        Assert.Contains("outside the file", cut.Problem);
    }

    [Fact]
    public void Protector_markers_are_named_and_plain_assemblies_have_none()
    {
        var marked = Assert.Single(Inspection.Summarize(null, Save("Marked.dll", MarkedFixture()), default).Assemblies).Markers;
        Assert.Equal(["Confuser / ConfuserEx", "SmartAssembly", "Goliath.NET", "Xenocode"], marked.Tools);
        Assert.Contains(marked.Indicators, i => i.StartsWith("SuppressIldasmAttribute"));

        foreach (var plain in new[] { Save("Plain.dll", ContainerFixtures.Module("Plain")), Env.FixturePath })
        {
            var facts = Assert.Single(Inspection.Summarize(null, plain, default).Assemblies).Markers;
            Assert.Empty(facts.Tools);
            Assert.Empty(facts.Indicators);
        }
    }

    [Fact]
    public void Summary_reads_an_assembly_and_a_container()
    {
        var path = Save("EverydayApis.dll", EverydayApis());
        var report = Inspection.Summarize(null, path, default);
        Assert.Equal(".NET assembly", report.File.Type);
        Assert.Equal(Blob.Sha256(File.ReadAllBytes(path)), report.File.Sha256);
        var one = Assert.Single(report.Assemblies);
        Assert.Equal("EverydayApis", one.Identity.Name);
        Assert.Equal("library", one.Identity.Kind);
        Assert.Contains(one.Features, c => c.Name == "download files");
        Assert.True(one.Values.ByType["url"] >= 2);
        Assert.Contains(report.Highlights, h => h.StartsWith("Can download files (network"));

        var zip = Save("bundle.zip", ContainerFixtures.Zip(("app/EverydayApis.dll", File.ReadAllBytes(path)), ("lib/Encoded.dll", EncodedFixture())));
        var container = Inspection.Summarize(null, zip, default);
        Assert.Equal("zip archive", container.Container);
        Assert.Equal(["app/EverydayApis.dll", "lib/Encoded.dll"], container.Assemblies.Select(a => a.Path).Order());
        Assert.Contains(container.Highlights, h => h.StartsWith("[lib/Encoded.dll] Embedded text"));
    }

    [Fact]
    public void Summarizing_a_native_image_shows_sections_mitigations_pdb_tls_and_import_capabilities()
    {
        var bytes = NativePeTests.KitchenSink(is64: true);
        var pe = Corvus.Native.Pe.PeFile.FromBytes(bytes);
        var (on, off) = Corvus.Tools.NativeTools.Mitigations(pe);
        var summary = Inspection.Summarize(null, Save("Native.dll", bytes), default);
        Assert.Contains(summary.Highlights, h => h.StartsWith("Sections (") && h.Contains(".rdata"));
        Assert.Contains($"Mitigations on: {(on.Count > 0 ? string.Join(", ", on) : "none")}; off: {(off.Count > 0 ? string.Join(", ", off) : "none")}.", summary.Highlights);
        Assert.Contains("PDB path: seed.pdb.", summary.Highlights);
        Assert.Contains(summary.Highlights, h => h.StartsWith("TLS callbacks run before the entry point: 0x"));
        Assert.Contains(summary.Highlights, h => h.StartsWith("Import capabilities:"));
        Assert.DoesNotContain(summary.Notes, n => n.Contains("nothing to summarize"));
    }

    [Fact]
    public void Summarizing_a_native_image_without_pdb_tls_or_imports_omits_those_lines()
    {
        var summary = Inspection.Summarize(null, Save("Bare.dll", NativePeTests.BasicImage()), default);
        Assert.Contains(summary.Highlights, h => h.StartsWith("Sections ("));
        Assert.Contains(summary.Highlights, h => h.StartsWith("Mitigations on:") && h.Contains("off:"));
        Assert.DoesNotContain(summary.Highlights, h => h.StartsWith("PDB path") || h.StartsWith("TLS callbacks") || h.StartsWith("Import capabilities"));
    }

    [Fact]
    public void Summarizing_a_truncated_native_image_reports_the_highlights_as_unavailable()
    {
        var bytes = NativePeTests.KitchenSink(is64: true);
        var summary = Inspection.Summarize(null, Save("Cut.dll", bytes[..0x90]), default);
        Assert.Contains(summary.Highlights, h => h.StartsWith("PE highlights unavailable:"));
    }

    [Fact]
    public void Summary_notes_name_the_cap_an_empty_input_and_embedded_counts()
    {
        var many = Save("many.zip", ContainerFixtures.Zip([.. Enumerable.Range(0, 26).Select(i => ($"lib/A{i}.dll", ContainerFixtures.Module($"A{i}")))]));
        var capped = Inspection.Summarize(null, many, default);
        Assert.Equal(8, capped.Assemblies.Count);
        Assert.Contains(capped.Notes, n => n.StartsWith("Summarized 8 of 26 assemblies (own first, framework last; the first in full, the others in brief)"));
        // Brief entries: highlights only at file level.
        Assert.All(capped.Assemblies.Skip(1), a => Assert.Empty(a.Highlights));

        var empty = Inspection.Summarize(null, Save("notes.txt", "just some text"u8.ToArray()), default);
        Assert.Contains("No managed assemblies inside: nothing to summarize beyond the file facts.", empty.Notes);

        var encoded = Inspection.Summarize(null, Save("Encoded.dll", EncodedFixture()), default);
        Assert.Contains("Embedded content: 11 item(s), 5 listed. extract_embedded lists everything.", Assert.Single(encoded.Assemblies).Notes);
        Assert.Equal(5, encoded.Highlights.Count(h => h.StartsWith("Embedded text", StringComparison.Ordinal)));

        var everyday = Inspection.Summarize(null, Save("EverydayApis.dll", EverydayApis()), default);
        Assert.Contains(everyday.Highlights, h => h.StartsWith("Network values: ", StringComparison.Ordinal) && h.Contains(" url"));
    }

    [Fact]
    public void Summarize_and_survey_refuse_missing_and_non_assembly_inputs()
    {
        var path = Save("EverydayApis.dll", EverydayApis());
        Assert.Contains("Pass either", Assert.Throws<ToolError>(() => Inspection.Summarize(null, null, default)).Message);
        Assert.Contains("Pass either", Assert.Throws<ToolError>(() => Inspection.SurveyFeatures("x", path, null, default)).Message);
        Assert.Contains("not a .NET assembly (zip)",
            Assert.Throws<ToolError>(() => Inspection.SurveyFeatures(null, Save("a.zip", ContainerFixtures.Zip(("a.dll", [1, 2]))), null, default)).Message);
    }

    private static readonly int FuzzCases = int.TryParse(Environment.GetEnvironmentVariable("CORVUS_FUZZ_CASES"), out var n) ? n : 30;

    /// <summary>Fixtures cut short and with random bytes changed: every analysis either works or throws ToolError.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void Truncated_and_fuzzed_assemblies_fail_cleanly()
    {
        var inputs = new Dictionary<string, byte[]>
        {
            ["everyday"] = EverydayApis(),
            ["encoded"] = EncodedFixture(),
            ["marked"] = MarkedFixture(),
            ["test fixture"] = File.ReadAllBytes(Env.FixturePath),
        };
        var random = new Random(4321);
        var failures = new List<string>();
        foreach (var (name, bytes) in inputs)
        {
            var cases = new List<(string, byte[])>();
            foreach (var cut in new[] { 2, 64, 0x200, bytes.Length / 4, bytes.Length / 2, bytes.Length - 1 })
                cases.Add(($"{name} cut at {cut}", bytes[..cut]));
            for (int i = 0; i < FuzzCases; i++)
            {
                var mutated = bytes.ToArray();
                for (int k = 0; k < 1 + i % 8; k++)
                {
                    // Half the mutations target headers and metadata tables.
                    int at = random.Next(2) == 0 ? random.Next(Math.Min(8192, mutated.Length)) : random.Next(mutated.Length);
                    mutated[at] = (byte)random.Next(256);
                }
                cases.Add(($"{name} fuzz #{i}", mutated));
            }
            foreach (var (label, data) in cases)
            {
                var path = Save("fuzz.dll", data);
                foreach (var (tool, run) in new (string, Action)[]
                         {
                             ("summarize_file", () => Inspection.Summarize(null, path, default)),
                             ("survey_features", () => Inspection.SurveyFeatures(null, path, null, default)),
                             ("extract_strings", () => Inspection.ExtractStrings(null, path, null, default)),
                             ("extract_embedded", () => Inspection.ExtractEmbedded(null, path, false, null, false, default)),
                         })
                {
                    try { run(); }
                    catch (ToolError) { /* a clear error for corrupt input */ }
                    catch (Exception ex) { failures.Add($"{tool} on {label}: {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}"); }
                }
            }
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }

    /// <summary>Fuzzes the security directory, WIN_CERTIFICATE header and PKCS#7 blob of a signed file.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void Damaged_signatures_are_reported_not_thrown()
    {
        var signed = File.ReadAllBytes(CachedDll("Microsoft.CodeAnalysis.Common", "Microsoft.CodeAnalysis.dll"));
        var pe = PeImage.TryParse(signed)!;
        var (offset, size) = pe.Directory(signed, 4);
        int entry = pe.DirectoryEntryOffset(4);
        var random = new Random(99);
        var failures = new List<string>();
        for (int i = 0; i < FuzzCases * 10; i++)
        {
            var damaged = signed.ToArray();
            for (int k = 0; k < 1 + i % 6; k++)
            {
                int at = (i % 5) switch
                {
                    0 => entry + random.Next(8),                         // the security directory entry (offset / size)
                    1 => (int)offset + random.Next(8),                   // WIN_CERTIFICATE length / revision / type
                    _ => (int)offset + 8 + random.Next((int)size - 8),   // the PKCS#7 SignedData
                };
                damaged[at] = (byte)random.Next(256);
            }
            try { Certificates.Read(damaged); }
            catch (Exception ex) { failures.Add($"case {i}: {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}"); }
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }

    /// <summary>Corrupt inputs give tool errors and the server keeps serving.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public async Task Corrupt_inputs_give_clear_errors_over_MCP()
    {
        await using var client = await McpProtocolTests.StartServerAsync("--no-index");
        var good = File.ReadAllBytes(Env.FixturePath);
        var corruptMetadata = good.ToArray();
        int bsjb = corruptMetadata.AsSpan().IndexOf("BSJB"u8);
        // The metadata root signature.
        corruptMetadata.AsSpan(bsjb, 4).Clear();
        var inputs = new Dictionary<string, (string Path, string Error)>
        {
            ["missing"] = (_dir.File("missing.dll"), "File not found"),
            ["truncated"] = (Save("truncated.dll", good[..(good.Length / 3)]), "unreadable .NET metadata"),
            ["corrupt metadata"] = (Save("corrupt.dll", corruptMetadata), "unreadable .NET metadata"),
        };

        foreach (var tool in new[] { "summarize_file", "survey_features", "extract_strings", "extract_embedded" })
            foreach (var (label, (path, error)) in inputs)
            {
                var r = await client.CallToolAsync(tool, new Dictionary<string, object?> { ["path"] = path });
                if (tool == "summarize_file" && label != "missing")
                {
                    // summarize_file reports file facts with the damage as a highlight.
                    Assert.NotEqual(true, r.IsError);
                    Assert.Contains("The .NET metadata is damaged: ", string.Join("\n", r.Content.OfType<TextContentBlock>().Select(c => c.Text)));
                    continue;
                }
                var text = string.Join("\n", r.Content.OfType<TextContentBlock>().Select(c => c.Text));
                Assert.True(r.IsError == true, $"{tool} / {label}: {text}");
                Assert.Contains(error, text);
            }

        // Not .NET at all.
        var notes = Save("notes.txt", "just some text"u8.ToArray());
        foreach (var tool in new[] { "survey_features", "extract_strings", "extract_embedded" })
        {
            var r = await client.CallToolAsync(tool, new Dictionary<string, object?> { ["path"] = notes });
            Assert.True(r.IsError == true, tool);
            Assert.Contains("is not a .NET assembly (text)", string.Join("\n", r.Content.OfType<TextContentBlock>().Select(c => c.Text)));
        }

        var ok = await client.CallToolAsync("survey_features", new Dictionary<string, object?> { ["path"] = Save("EverydayApis.dll", EverydayApis()) });
        Assert.NotEqual(true, ok.IsError);
        Assert.Contains("download files", ok.StructuredContent!.ToString());

        // Results whose nullable fields are absent must still validate against the advertised output schema.
        var everyday = _dir.File("EverydayApis.dll");
        foreach (var tool in new[] { "summarize_file", "survey_features", "extract_strings", "extract_embedded" })
        {
            var r = await client.CallToolAsync(tool, new Dictionary<string, object?> { ["path"] = everyday });
            Assert.NotEqual(true, r.IsError);
            await McpProtocolTests.AssertMatchesOutputSchema(client, tool, r);
        }
        var nulls = await client.CallToolAsync("summarize_file", new Dictionary<string, object?> { ["path"] = everyday });
        Assert.DoesNotContain(":null", nulls.StructuredContent!.ToString());
    }

    private static byte[] Unrepeated() => [.. Enumerable.Range(0, 256).Select(i => (byte)i)];
}
