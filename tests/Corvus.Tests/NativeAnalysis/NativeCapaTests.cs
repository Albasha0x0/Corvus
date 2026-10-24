using System.Reflection;
using System.Text;
using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Worker;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>A small x64 program for capa, built here: its entry calls a function that starts a process and one that writes a registry value.</summary>
internal static class CapaFixture
{
    public const ulong Base = 0x140000000;
    public const uint Entry = 0x1000, Spawn = 0x1040, Store = 0x1080;

    public static byte[] Build()
    {
        const uint CodeRva = 0x1000, DataRva = 0x2000;
        (string Dll, string[] Names)[] imports = [("KERNEL32.dll", ["CreateProcessA", "ExitProcess"]), ("ADVAPI32.dll", ["RegSetValueExA"])];
        // Import descriptors (one per DLL and a terminator), then each DLL's lookup and address tables, hint/name entries and name.
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
        uint command = rd.Ascii("notepad.exe");

        var code = new byte[0x100];
        Array.Fill(code, (byte)0xCC);
        int p = 0;
        void At(uint rva) => p = (int)(rva - CodeRva);
        void Emit(params byte[] bytes) { bytes.CopyTo(code, p); p += bytes.Length; }
        // An instruction ending in a 32-bit displacement from its own end to target.
        void Relative(byte[] opcode, uint target)
        {
            Emit(opcode);
            Emit(BitConverter.GetBytes((int)(target - (CodeRva + (uint)p + 4))));
        }
        At(Entry);
        Emit(0x48, 0x83, 0xEC, 0x28);
        Relative([0xE8], Spawn);
        Relative([0xE8], Store);
        Emit(0x31, 0xC9);
        Relative([0xFF, 0x15], slots["ExitProcess"]);
        // CreateProcessA(NULL, "notepad.exe", NULL, NULL, ...) with the stack arguments left as they are.
        At(Spawn);
        Emit(0x48, 0x83, 0xEC, 0x68, 0x31, 0xC9);
        Relative([0x48, 0x8D, 0x15], command);
        Emit(0x45, 0x31, 0xC0, 0x45, 0x31, 0xC9);
        Relative([0xFF, 0x15], slots["CreateProcessA"]);
        Emit(0x48, 0x83, 0xC4, 0x68, 0xC3);
        At(Store);
        Emit(0x48, 0x83, 0xEC, 0x38);
        Relative([0xFF, 0x15], slots["RegSetValueExA"]);
        Emit(0x48, 0x83, 0xC4, 0x38, 0xC3);

        var pe = new PeBuilder { Is64 = true, Machine = 0x8664, Characteristics = 0x0022, DllCharacteristics = 0, ImageBase = Base, EntryPoint = Entry };
        pe.Add(".text", code, 0x60000020);
        pe.Add(".rdata", rd.ToArray(), 0xC0000040);
        pe.Directories[1] = (descriptors, 20 * (uint)(imports.Length + 1));
        return pe.Build();
    }
}

/// <summary>capa's behaviour labels of whole PE and .NET files, in survey_features category=capa and the function dossier.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class NativeCapaTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var o in _owned) o.Dispose();
        _dir.Dispose();
    }

    private static string Va(uint rva) => (CapaFixture.Base + rva).ToString(System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>
    /// A result document as capa 10.0.0 writes it for <see cref="CapaFixture"/>: an instruction rule inside Spawn (its block
    /// in the layout), function rules at Entry and Store; then rules capa's own report leaves out (library, subscope,
    /// classification) or shows as a limitation, a file rule, and a rule with an ATT&amp;CK entry capa does not give this program.
    /// </summary>
    private static string Result() => $$"""
        {"meta":{"version":"10.0.0","analysis":{"format":"pe","arch":"amd64","os":"windows",
          "base_address":{"type":"absolute","value": {{CapaFixture.Base}} },
          "layout":{"functions":[
            {"address":{"type":"absolute","value": {{Va(CapaFixture.Spawn)}} },"matched_basic_blocks":[{"address":{"type":"absolute","value": {{Va(CapaFixture.Spawn)}} } }]},
            {"address":{"type":"absolute","value": {{Va(CapaFixture.Store)}} },"matched_basic_blocks":[{"address":{"type":"absolute","value": {{Va(CapaFixture.Store)}} } }]}]} } },
         "rules":{
          "create process on Windows":{"meta":{"name":"create process on Windows","namespace":"host-interaction/process/create",
            "scopes":{"static":"instruction","dynamic":"call"},"lib":false,"is_subscope_rule":false,"attack":[],
            "mbc":[{"parts":["Process","Create Process"],"objective":"Process","behavior":"Create Process","method":"","id":"C0017"}],"maec":{ } },
            "matches":[[{"type":"absolute","value": {{Va(CapaFixture.Spawn + 0x13)}} },{ }]]},
          "terminate process":{"meta":{"name":"terminate process","namespace":"host-interaction/process/terminate",
            "scopes":{"static":"function","dynamic":"span of calls"},"lib":false,"is_subscope_rule":false,"attack":[],
            "mbc":[{"parts":["Process","Terminate Process"],"objective":"Process","behavior":"Terminate Process","method":"","id":"C0018"}],"maec":{ } },
            "matches":[[{"type":"absolute","value": {{Va(CapaFixture.Entry)}} },{ }]]},
          "set registry value":{"meta":{"name":"set registry value","namespace":"host-interaction/registry/create",
            "scopes":{"static":"function","dynamic":"call"},"lib":false,"is_subscope_rule":false,"attack":[],
            "mbc":[{"parts":["Operating System","Registry","Set Registry Key"],"objective":"Operating System","behavior":"Registry","method":"Set Registry Key","id":"C0036.001"}],
            "maec":{ } },
            "matches":[[{"type":"absolute","value": {{Va(CapaFixture.Store)}} },{ }]]},
          "persist via Run registry key":{"meta":{"name":"persist via Run registry key","namespace":"persistence/registry/run",
            "scopes":{"static":"function"},"lib":false,"is_subscope_rule":false,
            "attack":[{"parts":["Persistence","Boot or Logon Autostart Execution","Registry Run Keys / Startup Folder"],"tactic":"Persistence",
              "technique":"Boot or Logon Autostart Execution","subtechnique":"Registry Run Keys / Startup Folder","id":"T1547.001"}],"mbc":[],"maec":{ } },
            "matches":[[{"type":"absolute","value": {{Va(CapaFixture.Store)}} },{ }]]},
          "contain a thread local storage (.tls) section":{"meta":{"name":"contain a thread local storage (.tls) section","namespace":"executable/pe/section/tls",
            "scopes":{"static":"file","dynamic":"file"},"lib":false,"is_subscope_rule":false,"attack":[],"mbc":[],"maec":{ } },
            "matches":[[{"type":"no address"},{ }]]},
          "calculate modulo 256 via x86 assembly":{"meta":{"name":"calculate modulo 256 via x86 assembly","namespace":"internal/math",
            "scopes":{"static":"instruction"},"lib":true,"is_subscope_rule":false,"maec":{ } },
            "matches":[[{"type":"absolute","value": {{Va(CapaFixture.Spawn + 4)}} },{ }]]},
          "create process on Windows/basic block":{"meta":{"name":"create process on Windows/basic block","namespace":"host-interaction/process/create",
            "scopes":{"static":"basic block"},"lib":false,"is_subscope_rule":true,"maec":{ } },
            "matches":[[{"type":"absolute","value": {{Va(CapaFixture.Spawn)}} },{ }]]},
          "a classified sample":{"meta":{"name":"a classified sample","namespace":"anti-analysis",
            "scopes":{"static":"file"},"lib":false,"is_subscope_rule":false,"maec":{"analysis_conclusion":"benign"} },
            "matches":[[{"type":"no address"},{ }]]},
          "(internal) packer file limitation":{"meta":{"name":"(internal) packer file limitation","namespace":"internal/limitation/file",
            "scopes":{"static":"file"},"lib":false,"is_subscope_rule":false,"maec":{ } },
            "matches":[[{"type":"no address"},{ }]]} } }
        """;

    private static ExternalTools.RunResult Ran(string stdout, int exit = 0, string stderr = "") => new(exit, Encoding.UTF8.GetBytes(stdout), stderr, false, false, null);

    private string FixtureFile()
    {
        var path = _dir.File("fixture.exe");
        File.WriteAllBytes(path, CapaFixture.Build());
        return path;
    }

    /// <summary>A fake capa 10.0.0 answering <paramref name="result"/>, named by CORVUS_CAPA and run in this process.</summary>
    private IDisposable FakeCapa(string result)
    {
        var fake = new FakeTool();
        _owned.Add(fake);
        fake.On("^--version$", stdout: "capa.exe 10.0.0\n");
        fake.On(@"^-j .+$", stdout: result);
        return new EnvironmentScope().Set("CORVUS_CAPA", fake.CopyAs("capa")).Set(FakeTool.ScriptVariable, fake.ScriptPath).Set("CORVUS_WORKER_HOST", "0");
    }

    [Fact]
    public void Labels_are_named_at_their_function_and_rules_capas_report_leaves_out_are_dropped()
    {
        var read = NativeCapa.Read(Ran(Result()), "capa 10.0.0", tested: true);
        Assert.Equal(("matched", (string?)"pe", (ulong?)CapaFixture.Base), (read.State, read.Format, read.BaseAddress));
        Assert.Equal(["contain a thread local storage (.tls) section", "create process on Windows", "terminate process", "set registry value",
            "persist via Run registry key"], read.Labels.Select(l => l.Name));
        var spawn = read.Labels[1];
        Assert.Equal(("instruction", CapaFixture.Base + CapaFixture.Spawn), (spawn.Scope, Assert.Single(spawn.Addresses)));
        Assert.Equal(["Process::Create Process [C0017]"], spawn.Mbc);
        Assert.Equal(["Operating System::Registry::Set Registry Key [C0036.001]"], read.Labels[3].Mbc);
        Assert.Equal(["Persistence::Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder [T1547.001]"], read.Labels[4].Attack);
        Assert.Empty(read.Labels[0].Addresses);
        Assert.Equal(["capa file limitation: (internal) packer file limitation"], read.Notes);
    }

    [Fact]
    public void A_format_capa_does_not_read_is_not_checked_with_capas_message()
    {
        // The head of what capa 10.0.0 logs for a text file, wrapped at 80 columns.
        const string stderr = """
            ERROR    capa:                                                   helpers.py:271
                     -------------------------------------------------------
                     -------------------------
            ERROR    capa:  Input file does not appear to be a supported     helpers.py:272
                     file.
            ERROR    capa:                                                   helpers.py:273
            ERROR    capa:  See all supported file formats via capa's help   helpers.py:274
                     output (-h).
            """;
        var read = NativeCapa.Read(Ran("", 16, stderr), "capa 10.0.0", tested: true);
        Assert.Equal(NativeCapa.NotChecked, read.State);
        Assert.Equal("capa does not read this file (exit 16: Input file does not appear to be a supported file.)", Assert.Single(read.Notes));
    }

    [Fact]
    public void Capa_not_set_up_is_not_checked_naming_the_variable_to_set()
    {
        using var env = new EnvironmentScope().Set("CORVUS_CAPA", Path.Combine(Path.GetTempPath(), "no-capa", "capa.exe"));
        var report = NativeCapa.Analyze(FixtureFile(), default);
        Assert.Equal(NativeCapa.NotChecked, report.State);
        Assert.Contains("CORVUS_CAPA", Assert.Single(report.Notes));
    }

    [Fact]
    public void Survey_features_category_capa_lists_each_label_at_its_functions_with_capas_attack_and_mbc_entries()
    {
        using var capa = FakeCapa(Result());
        using var workspace = new AssemblyWorkspace(new ServerOptions { BackgroundIndexing = false });
        var report = new InspectionService(workspace).SurveyFeatures(null, FixtureFile(), "capa", default);
        var spawn = Assert.Single(report.Features, f => f.Name == "create process on Windows");
        Assert.Equal(("capa", "host-interaction/process/create", 1), (spawn.Category, spawn.Evidence[0].Feature, spawn.Evidence[0].Count));
        Assert.StartsWith($"0x{CapaFixture.Base + CapaFixture.Spawn:X}", Assert.Single(spawn.Evidence[0].Locations));
        Assert.Equal(["MBC Process::Create Process [C0017]"], spawn.Evidence.Skip(1).Select(e => e.Feature));
        Assert.Equal(["ATT&CK Persistence::Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder [T1547.001]"],
            Assert.Single(report.Features, f => f.Name == "persist via Run registry key").Evidence.Skip(1).Select(e => e.Feature));
        Assert.Equal(["(file)"], Assert.Single(report.Features, f => f.Name == "contain a thread local storage (.tls) section").Evidence[0].Locations);
        Assert.Contains("category capa: labels of capa 10.0.0 over the whole file, matched", report.Notes);
        Assert.Contains("capa: capa file limitation: (internal) packer file limitation", report.Notes);
    }

    [Fact]
    public void Survey_features_names_dotnet_labels_at_the_method_token()
    {
        var method = typeof(Fixture.Model.Account).GetMethods(BindingFlags.DeclaredOnly | BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)[0];
        var result = $$"""
            {"meta":{"analysis":{"format":"dotnet","arch":"any","os":"any","base_address":{"type":"no address"},
              "layout":{"functions":[{"address":{"type":"dn_token","value": {{method.MetadataToken}} },"matched_basic_blocks":[]}]} } },
             "rules":{"write file in .NET":{"meta":{"name":"write file in .NET","namespace":"host-interaction/file-system/write",
               "scopes":{"static":"instruction"},"lib":false,"is_subscope_rule":false,"attack":[],"mbc":[],"maec":{ } },
               "matches":[[{"type":"dn_token_offset","value":[ {{method.MetadataToken}} ,12]},{ }]]} } }
            """;
        using var capa = FakeCapa(result);
        using var workspace = new AssemblyWorkspace(new ServerOptions { BackgroundIndexing = false });
        var path = _dir.File("Fixture.dll");
        File.Copy(Env.FixturePath, path);
        var report = new InspectionService(workspace).SurveyFeatures(null, path, "capa", default);
        var write = Assert.Single(report.Features);
        Assert.Equal($"0x{method.MetadataToken:X8} Fixture.Model.Account::{method.Name}", Assert.Single(write.Evidence[0].Locations));
    }

    [Fact]
    public async Task The_dossier_of_a_function_shows_the_labels_capa_matched_in_it()
    {
        using var capa = FakeCapa(Result());
        var path = FixtureFile();
        Assert.Equal("matched", NativeCapa.Analyze(path, default).State);
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        _owned.Add(workspace);
        var code = new NativeCodeService(workspace, options, null, new AnnotationStore(_dir.File("ann")));
        var tools = new NativeFunctionTools(workspace, code, new OutputPager(options));
        var text = await tools.AnalyzeNativeFunction(path, $"0x{CapaFixture.Base + CapaFixture.Spawn:X}", sections: "annotations");
        output.WriteLine(text);
        Assert.Contains("capa create process on Windows (host-interaction/process/create); MBC Process::Create Process [C0017]", text);
        Assert.DoesNotContain("set registry value", text);
    }

    /// <summary>A real capa 10.0.0 named by CORVUS_CAPA labels the fixture's process, registry and exit functions, run in the worker host.</summary>
    [CapaFact]
    [Trait("Speed", "Slow")]
    public void Capa_labels_the_functions_that_start_a_process_write_a_registry_value_and_exit()
    {
        // A pool of the test's own, so its capa worker ends with the test.
        using var pool = new WorkerPool(new WorkerPoolOptions { Enabled = true, MemoryLimitBytes = 0 });
        using var shared = WorkerPool.UseShared(pool);
        var report = NativeCapa.Analyze(FixtureFile(), default);
        output.WriteLine(string.Join("\n", report.Labels.Select(l => $"{l.Name} [{l.Scope}] at {string.Join(",", l.Addresses.Select(a => $"0x{a:X}"))}: " +
                                                                     string.Join("; ", l.Attack.Concat(l.Mbc)))));
        Assert.True(report.State == "matched", string.Join("; ", report.Notes));
        Assert.True(report.Tested, $"{report.Checker} is not the tested capa {NativeCapa.TestedVersion}");
        var at = report.Labels.ToDictionary(l => l.Name, l => l.Addresses);
        Assert.Equal([CapaFixture.Base + CapaFixture.Entry], at["terminate process"]);
        Assert.Equal([CapaFixture.Base + CapaFixture.Spawn], at["create process on Windows"]);
        Assert.Equal([CapaFixture.Base + CapaFixture.Store], at["set registry value"]);
    }
}

/// <summary>Runs when CORVUS_CAPA names a capa; skipped with the variable named otherwise, checked when a test runs.</summary>
[Xunit.Sdk.XunitTestCaseDiscoverer(RunTimeSkips.FactDiscoverer, RunTimeSkips.Assembly)]
public sealed class CapaFactAttribute : FactAttribute, IRunTimeSkip
{
    public string? RunTimeSkip() => Environment.GetEnvironmentVariable(ExternalTools.Capa.Variable) is { Length: > 0 }
        ? null : $"{ExternalTools.Capa.Variable} is not set: it names the standalone capa {NativeCapa.TestedVersion} these tests compare with.";
}
