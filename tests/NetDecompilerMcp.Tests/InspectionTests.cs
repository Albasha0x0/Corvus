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
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services.Analysis;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// summarize_file / survey_features / extract_strings / extract_embedded, with every fixture built at test time: C# compiled
/// with Roslyn against the running framework, and assemblies written with dnlib.
/// </summary>
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

    // ------------------------------------------------------------------ fixture builders

    /// <summary>Compiles C# against the running framework's assemblies.</summary>
    internal static byte[] Compile(string name, string source)
    {
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Where(p => p.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)).Select(p => MetadataReference.CreateFromFile(p));
        var compilation = CSharpCompilation.Create(name, [CSharpSyntaxTree.ParseText(source)], references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Enable));
        using var ms = new MemoryStream();
        var result = compilation.Emit(ms);
        Assert.True(result.Success, string.Join("\n", result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error)));
        return ms.ToArray();
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

    private const string SecretText = "Quarterly notes, not for sharing.\nStaging server: https://drop.example.net/stage2\nEnd of file.\n";

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

    /// <summary>
    /// The same small text file, hidden in an assembly in every way the embedded-content finder decodes: base64 and hex string
    /// literals, resources (base64, hex, gzip > base64, XOR over gzip with 1- and 3-byte keys, base64 > XOR > gzip),
    /// a .resources byte[] and string entry, and a static byte array (array initializer data). Plus the text XORed
    /// directly, which has no known header to recover a key from.
    /// </summary>
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

            // a static array initializer: <PrivateImplementationDetails>::data, a FieldRVA of a fixed-size struct type
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

            // string literals, and a method that uses the array
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

    /// <summary>Marker types and attributes that protectors inject (as de4dot knows them).</summary>
    private static byte[] ProtectedFixture() => ContainerFixtures.Module("Protected", m =>
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

    // ------------------------------------------------------------------ features

    [Fact]
    public void Features_OfEverydayFrameworkApis()
    {
        var report = Inspection.SurveyFeatures(null, Save("EverydayApis.dll", EverydayApis()), null, default);
        var byName = report.Features.ToDictionary(c => c.Name);

        Assert.Equal("T1071.001", byName["send HTTP requests"].Attack);
        Assert.Contains(byName["send HTTP requests"].Evidence, e => e.Feature == "api:System.Net.Http.HttpClient::*Async");
        Assert.Equal("T1105", byName["download files"].Attack);
        Assert.Equal("T1012", byName["query the registry"].Attack);
        Assert.Equal("T1112", byName["modify the registry"].Attack);
        Assert.Contains(byName["create processes"].Evidence, e => e.Feature == "api:System.Diagnostics.Process::Start" && e.Locations.Any(l => l.Contains("Everyday::OpenEditor")));
        Assert.Equal("T1070.006", byName["change file timestamps"].Attack); // File.SetCreationTime

        // reading a file, starting notepad and writing an app's own key are not command shells, Run keys or downloads to disk
        Assert.DoesNotContain("run the Windows command shell", byName.Keys);
        Assert.DoesNotContain("persist through a Run registry key", byName.Keys);
        Assert.True(report.MethodsScanned > 5);

        var registry = Inspection.SurveyFeatures(null, _dir.File("EverydayApis.dll"), "registry", default);
        Assert.Equal(["modify the registry", "query the registry"], registry.Features.Select(c => c.Name).Order());
        Assert.Equal(["download files"], Inspection.SurveyFeatures(null, _dir.File("EverydayApis.dll"), "T1105", default).Features.Select(c => c.Name));
    }

    [Fact]
    public void Features_OfALoadedAssemblyMatchTheFile()
    {
        var path = Save("EverydayApis.dll", EverydayApis());
        var loaded = _workspace.Load(path);
        var fromFile = Inspection.SurveyFeatures(null, path, null, default).Features.Select(c => c.Name);
        var fromWorkspace = Inspection.SurveyFeatures(loaded.Id, null, null, default).Features.Select(c => c.Name);
        Assert.Equal(fromFile.Order(), fromWorkspace.Order());
    }

    // ------------------------------------------------------------------ embedded content: encoding round-trips

    [Fact]
    public void Embedded_EncodedCopiesOfATextFile_AreDecodedWithTheirChain()
    {
        var report = Inspection.ExtractEmbedded(null, Save("Encoded.dll", EncodedFixture()), false, null, false, default);
        var original = Encoding.UTF8.GetBytes(SecretText);
        var texts = report.Contents.Where(p => p.Kind == "text").ToList();
        Assert.All(texts, p => Assert.Equal(original, p.Bytes)); // every decoded copy is byte-for-byte the original

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

        // XOR straight over text has no known header to recover the key from: not decoded, and not misreported
        Assert.DoesNotContain(report.Contents, p => p.Source.StartsWith("resource 'notes.plainxor'", StringComparison.Ordinal));
    }

    [Fact]
    public void Embedded_SaveWritesDefangedFiles_AndValuesComeFromDecodedText()
    {
        var path = Save("Encoded.dll", EncodedFixture());
        var saved = Inspection.ExtractEmbedded(null, path, true, _dir.File("payloads"), false, default);
        Assert.NotNull(saved.OutputDirectory);
        Assert.All(saved.Contents, p => Assert.StartsWith(saved.OutputDirectory!, p.SavedTo));
        Assert.All(saved.Contents.Where(p => p.Kind == "text"), p => Assert.Equal(SecretText, File.ReadAllText(p.SavedTo!)));
        Assert.All(saved.Contents, p => Assert.Matches(@"^embedded_\d\d\.\w+$", Path.GetFileName(p.SavedTo!)));

        var byDefault = Inspection.ExtractEmbedded(null, path, true, null, false, default);
        try { Assert.Equal("netdecomp-embedded", Path.GetFileName(Path.GetDirectoryName(byDefault.OutputDirectory!))); }
        finally { Directory.Delete(byDefault.OutputDirectory!, recursive: true); }

        var url = Assert.Single(Inspection.ExtractStrings(null, path, ["url"], null, null, false, default).Values);
        Assert.Equal("https://drop.example.net/stage2", url.Value);
        Assert.Contains(url.Locations, l => l.Contains("(decoded: "));
    }

    // ------------------------------------------------------------------ values: string classification

    [Fact]
    public void Values_ClassifiedByType_AndLookalikesLeftOut()
    {
        var report = Inspection.ExtractStrings(null, Save("Strings.dll", StringsFixture()), null, null, null, false, default);
        var found = report.Values.Select(i => (i.Type, i.Value)).ToList();

        Assert.Contains(("ipv4", "192.0.2.1"), found);
        Assert.Contains(("url", "https://example.com/path"), found);
        Assert.Contains(("domain", "example.com"), found);
        Assert.Contains(("file_path", @"C:\Users\Public\Documents\report.txt"), found);
        Assert.Equal(4, found.Count); // and nothing from the lookalikes

        Assert.DoesNotContain(found, f => f.Value.Contains("w3.org") || f.Value.Contains("schemas.microsoft.com"));
        Assert.DoesNotContain(found, f => f.Value is "readme.txt" or "settings.json" or "app.config" or "4.0.0.0");
    }

    [Fact]
    public void Values_OfEverydayApis_KnowWhereTheyGo_AndExport()
    {
        var path = Save("EverydayApis.dll", EverydayApis());
        var report = Inspection.ExtractStrings(null, path, null, null, null, false, default);
        var url = Assert.Single(report.Values, i => i.Type == "url" && i.Value == "https://example.com/path");
        Assert.Contains("System.Net.Http.HttpClient::GetStringAsync", url.PassedTo);
        Assert.Contains(report.Values, i => i.Type == "file_path" && i.Value == @"C:\ProgramData\Everyday\settings.ini");
        Assert.Contains(report.Values, i => i.Type == "registry_key" && i.Value == @"Software\Everyday");

        var filtered = Inspection.ExtractStrings(null, path, ["url", "domain"], null, null, false, default);
        Assert.All(filtered.Values, i => Assert.Contains(i.Type, new[] { "url", "domain" }));

        var csv = Inspection.ExtractStrings(null, path, null, _dir.File("iocs.csv"), null, false, default);
        Assert.StartsWith("type,value,count,", File.ReadAllText(csv.SavedTo!));
        var json = Inspection.ExtractStrings(null, path, null, _dir.File("iocs.json"), null, false, default);
        Assert.Equal(json.Total, JsonDocument.Parse(File.ReadAllText(json.SavedTo!)).RootElement.GetArrayLength());
        Assert.Contains("exists", Assert.Throws<ToolError>(() => Inspection.ExtractStrings(null, path, null, _dir.File("iocs.json"), null, false, default)).Message);
        Assert.Contains("Unknown value type", Assert.Throws<ToolError>(() => Inspection.ExtractStrings(null, path, ["phone"], null, null, false, default)).Message);
    }

    // ------------------------------------------------------------------ signatures

    [Fact]
    public void Certificates_MicrosoftSignedRoslyn_AndUnsignedDnlib()
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
            Assert.NotNull(sig.Chain); // trusted or not depends on the machine's root store
        }

        var dnlib = Certificates.Read(File.ReadAllBytes(CachedDll("dnlib", "dnlib.dll")));
        Assert.False(dnlib.Present);
        Assert.Null(dnlib.Signer);
    }

    [Fact]
    public void Certificates_InSummary_WithStrongNames_AndTamperedCopies()
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

        // one byte changed in the middle of the file: the signature still verifies, but over a digest the file no longer has
        var tampered = roslyn.ToArray();
        tampered[tampered.Length / 2] ^= 0xFF;
        var t = Certificates.Read(tampered);
        Assert.False(t.DigestMatches);
        Assert.True(t.SignatureValid);
        Assert.Contains(Inspection.Summarize(null, Save("tampered.dll", tampered), default).Highlights, h => h.Contains("modified after signing"));

        // cut inside the certificate table
        var cut = Certificates.Read(roslyn[..(roslyn.Length - 100)]);
        Assert.True(cut.Present);
        Assert.Contains("outside the file", cut.Problem);
    }

    // ------------------------------------------------------------------ markers

    [Fact]
    public void Markers_AreNamed_PlainAssembliesGiveNothing()
    {
        var marked = Assert.Single(Inspection.Summarize(null, Save("Protected.dll", ProtectedFixture()), default).Assemblies).Markers;
        Assert.Equal(["Confuser / ConfuserEx", "SmartAssembly", "Goliath.NET", "Xenocode"], marked.Tools);
        Assert.Contains(marked.Indicators, i => i.StartsWith("SuppressIldasmAttribute"));

        foreach (var plain in new[] { Save("Plain.dll", ContainerFixtures.Module("Plain")), Env.FixturePath })
        {
            var facts = Assert.Single(Inspection.Summarize(null, plain, default).Assemblies).Markers;
            Assert.Empty(facts.Tools);
            Assert.Empty(facts.Indicators);
        }
    }

    // ------------------------------------------------------------------ summary

    [Fact]
    public void Summary_OfAnAssemblyAndOfAContainer()
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
        Assert.Contains(report.Highlights, h => h.StartsWith("Can download files (T1105"));

        var zip = Save("bundle.zip", ContainerFixtures.Zip(("app/EverydayApis.dll", File.ReadAllBytes(path)), ("lib/Encoded.dll", EncodedFixture())));
        var container = Inspection.Summarize(null, zip, default);
        Assert.Equal("zip archive", container.Container);
        Assert.Equal(["app/EverydayApis.dll", "lib/Encoded.dll"], container.Assemblies.Select(a => a.Path).Order());
        Assert.Contains(container.Highlights, h => h.StartsWith("[lib/Encoded.dll] Embedded text"));
    }

    [Fact]
    public void Summary_Messages()
    {
        var many = Save("many.zip", ContainerFixtures.Zip([.. Enumerable.Range(0, 26).Select(i => ($"lib/A{i}.dll", ContainerFixtures.Module($"A{i}")))]));
        var capped = Inspection.Summarize(null, many, default);
        Assert.Equal(25, capped.Assemblies.Count);
        Assert.Contains("Summarized the first 25 of 26 assemblies; list_assemblies with path lists them all.", capped.Notes);

        var empty = Inspection.Summarize(null, Save("notes.txt", "just some text"u8.ToArray()), default);
        Assert.Contains("No managed assemblies inside: nothing to summarize beyond the file facts.", empty.Notes);

        var encoded = Inspection.Summarize(null, Save("Encoded.dll", EncodedFixture()), default);
        Assert.Contains("6 more embedded item(s).", encoded.Highlights); // 11 decoded copies: 5 listed, 6 counted

        var everyday = Inspection.Summarize(null, Save("EverydayApis.dll", EverydayApis()), default);
        Assert.Contains(everyday.Highlights, h => h.StartsWith("Network values: ", StringComparison.Ordinal) && h.Contains(" url"));
    }

    [Fact]
    public void BadArguments()
    {
        var path = Save("EverydayApis.dll", EverydayApis());
        Assert.Contains("Pass either", Assert.Throws<ToolError>(() => Inspection.Summarize(null, null, default)).Message);
        Assert.Contains("Pass either", Assert.Throws<ToolError>(() => Inspection.SurveyFeatures("x", path, null, default)).Message);
        Assert.Contains("not a .NET assembly (zip)",
            Assert.Throws<ToolError>(() => Inspection.SurveyFeatures(null, Save("a.zip", ContainerFixtures.Zip(("a.dll", [1, 2]))), null, default)).Message);
        Assert.Contains("Unknown format", Assert.Throws<ToolError>(() => Inspection.ExtractStrings(null, path, null, null, "xml", false, default)).Message);
    }

    // ------------------------------------------------------------------ robustness

    private static readonly int FuzzCases = int.TryParse(Environment.GetEnvironmentVariable("NDM_FUZZ_CASES"), out var n) ? n : 30;

    /// <summary>Fixtures cut short and with random bytes changed: every analysis either works or throws ToolError.</summary>
    [Fact]
    public void TruncatedAndFuzzedAssemblies_FailCleanly()
    {
        var inputs = new Dictionary<string, byte[]>
        {
            ["everyday"] = EverydayApis(),
            ["encoded"] = EncodedFixture(),
            ["protected"] = ProtectedFixture(),
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
                    // half the changes land in the headers and metadata tables, the rest anywhere
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
                             ("extract_strings", () => Inspection.ExtractStrings(null, path, null, null, null, false, default)),
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

    /// <summary>
    /// A signed file with its certificate table damaged (the PKCS#7 blob, the WIN_CERTIFICATE header, the directory entry):
    /// the signature is reported with a problem or a failed check, never an exception.
    /// </summary>
    [Fact]
    public void DamagedSignatures_AreReportedNotThrown()
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

    // ------------------------------------------------------------------ robustness over MCP

    /// <summary>Truncated and corrupt inputs to each of the four tools: a tool error with the reason, and the server keeps serving.</summary>
    [Fact]
    public async Task CorruptInputs_GiveClearErrorsOverMcp()
    {
        await using var client = await McpProtocolTests.StartServerAsync("--no-index");
        var good = File.ReadAllBytes(Env.FixturePath);
        var corruptMetadata = good.ToArray();
        int bsjb = corruptMetadata.AsSpan().IndexOf("BSJB"u8);
        corruptMetadata.AsSpan(bsjb, 4).Clear(); // the metadata root signature
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
                var text = string.Join("\n", r.Content.OfType<TextContentBlock>().Select(c => c.Text));
                Assert.True(r.IsError == true, $"{tool} / {label}: {text}");
                Assert.Contains(error, text);
            }

        // not .NET at all: the three single-assembly tools say so; summarize_file reports the file facts
        var notes = Save("notes.txt", "just some text"u8.ToArray());
        foreach (var tool in new[] { "survey_features", "extract_strings", "extract_embedded" })
        {
            var r = await client.CallToolAsync(tool, new Dictionary<string, object?> { ["path"] = notes });
            Assert.True(r.IsError == true, tool);
            Assert.Contains("is not a .NET assembly (text)", string.Join("\n", r.Content.OfType<TextContentBlock>().Select(c => c.Text)));
        }

        // still serving
        var ok = await client.CallToolAsync("survey_features", new Dictionary<string, object?> { ["path"] = Save("EverydayApis.dll", EverydayApis()) });
        Assert.NotEqual(true, ok.IsError);
        Assert.Contains("download files", ok.StructuredContent!.ToString());
    }
}
