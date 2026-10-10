using System.Diagnostics;
using System.Text;
using Iced.Intel;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Services.Analysis;
using Xunit.Abstractions;
using static Iced.Intel.AssemblerRegisters;

namespace NetDecompilerMcp.Tests;

/// <summary>survey_features on native images: synthetic code, and a sample of System32 / Program Files binaries (Slow).</summary>
public class NativeSurveyTests(ITestOutputHelper output)
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const ulong Base64 = 0x140000000UL;

    private static Instruction Rip(Iced.Intel.Code code, Register reg, uint rva) =>
        Instruction.Create(code, reg, new MemoryOperand(Register.RIP, (long)(Base64 + rva), 8));

    private static Instruction CallSlot(uint rva) => Instruction.Create(Iced.Intel.Code.Call_rm64, new MemoryOperand(Register.RIP, (long)(Base64 + rva), 8));

    [Fact]
    public void Native_rules_match_imports_arguments_and_strings()
    {
        const uint VirtualProtect = Data, CreateProcessW = Data + 8, IsDebuggerPresent = Data + 16;
        var a = new Assembler(64);
        a.sub(rsp, 0x68);
        a.mov(rcx, rbx);
        a.mov(edx, 0x1000);
        a.mov(r8d, 0x40);                                   // PAGE_EXECUTE_READWRITE
        a.lea(r9, __[rsp + 0x60]);
        a.AddInstruction(CallSlot(VirtualProtect));
        a.xor(ecx, ecx);
        a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RDX, Data + 0x100));
        a.xor(r8d, r8d);
        a.xor(r9d, r9d);
        a.and(__dword_ptr[rsp + 0x20], 0);
        a.mov(__dword_ptr[rsp + 0x28], 0x8000004);          // CREATE_SUSPENDED | CREATE_NO_WINDOW
        a.and(__qword_ptr[rsp + 0x30], 0);
        a.and(__qword_ptr[rsp + 0x38], 0);
        a.mov(__qword_ptr[rsp + 0x40], rsi);
        a.mov(__qword_ptr[rsp + 0x48], rdi);
        a.AddInstruction(CallSlot(CreateProcessW));
        a.AddInstruction(CallSlot(IsDebuggerPresent));
        a.add(rsp, 0x68);
        a.ret();
        var stream = new MemoryStream();
        a.Assemble(new StreamCodeWriter(stream), Base64 + Code);
        var data = new byte[0x200];
        Encoding.Unicode.GetBytes("cmd.exe /c whoami\0").CopyTo(data, 0x100);
        NativeImport Import(string name, uint slot) => new("KERNEL32.dll", name, null, 0, slot, false);
        var image = CodeTestImage.Synthetic(NativeArch.X64, stream.ToArray(), data,
            [Import("VirtualProtect", VirtualProtect), Import("CreateProcessW", CreateProcessW), Import("IsDebuggerPresent", IsDebuggerPresent)], entry: Code);
        var index = NativeCodeIndex.Build(image);
        var found = Features.Detect(new NativeFeatureScan(index, default), default);

        var rwx = Assert.Single(found, f => f.Name == "allocate or make memory writable and executable");
        Assert.Contains("PAGE_EXECUTE_READWRITE", rwx.Evidence[0].Locations[0]);
        Assert.Contains(found, f => f.Name == "create a suspended process");
        Assert.Contains(found, f => f.Name == "run the Windows command shell" && f.Attack == "T1059.003");
        Assert.Contains(found, f => f.Name == "check for a debugger");
        Assert.DoesNotContain(found, f => f.Name == "have a writable and executable section");
    }

    [Fact]
    public void Survey_takes_a_loaded_native_image_or_a_native_path()
    {
        using var env = new Env();
        using var dir = new TempDir();
        var path = McpProtocolTests.NativeSample(dir);
        var id = env.Workspace.LoadAny(path).Native!.Id;
        var inspection = new InspectionService(env.Workspace, new NetDecompilerMcp.Services.NativeCodeService(env.Workspace, env.Options));
        var loaded = inspection.SurveyFeatures(id, null, null, default);
        Assert.Equal(id, loaded.Assembly);
        Assert.Contains(loaded.Notes, n => n.StartsWith("native image", StringComparison.Ordinal));
        var file = new InspectionService(env.Workspace).SurveyFeatures(null, path, "anti-analysis", default);
        Assert.Equal("native.dll", file.Assembly);
        Assert.All(file.Features, f => Assert.Equal("anti-analysis", f.Category));
    }

    /// <summary>Native PE files: every System32 / SysWOW64 file in a fixed sample and the first Program Files binaries.</summary>
    private static IEnumerable<string> Sample()
    {
        var names = new[] { "kernel32.dll", "advapi32.dll", "user32.dll", "shell32.dll", "wininet.dll", "urlmon.dll", "ws2_32.dll", "crypt32.dll",
            "taskmgr.exe", "cmd.exe", "notepad.exe", "explorer.exe", "regedit.exe", "mstsc.exe", "certutil.exe", "bitsadmin.exe" };
        foreach (var dir in MsvcCorpus.SystemDirectories())
            foreach (var n in names)
                if (File.Exists(Path.Combine(dir, n))) yield return Path.Combine(dir, n);
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (pf.Length == 0 || !Directory.Exists(pf)) yield break;
        int taken = 0;
        foreach (var f in MsvcCorpus.SafeFiles(pf, "*.exe", recursive: true).Concat(MsvcCorpus.SafeFiles(pf, "*.dll", recursive: true)).Order(StringComparer.OrdinalIgnoreCase))
        {
            if (taken >= 24) yield break;
            long size;
            try { size = new FileInfo(f).Length; }
            catch (IOException) { continue; }
            if (size is < 4096 or > 40 << 20) continue;
            byte[] head;
            try { head = File.ReadAllBytes(f); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
            if (Blob.Identify(head) != "native PE") continue;
            taken++;
            yield return f;
        }
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void System32_and_program_files_survey()
    {
        using var env = new Env();
        var inspection = new InspectionService(env.Workspace);
        var hits = new Dictionary<string, int>();
        int files = 0;
        var total = Stopwatch.StartNew();
        double slowest = 0;
        string slowestFile = "";
        foreach (var path in Sample())
        {
            var sw = Stopwatch.StartNew();
            var report = inspection.SurveyFeatures(null, path, null, default);
            sw.Stop();
            files++;
            if (sw.Elapsed.TotalSeconds > slowest) { slowest = sw.Elapsed.TotalSeconds; slowestFile = path; }
            foreach (var f in report.Features) hits[f.Name] = hits.GetValueOrDefault(f.Name) + 1;
            output.WriteLine($"{path}: {report.Features.Count} features, {report.MethodsScanned} functions, {sw.Elapsed.TotalSeconds:0.00} s" +
                             (report.Features.Count > 0 ? ": " + string.Join(", ", report.Features.Select(f => f.Name).Take(8)) : ""));
            Assert.True(sw.Elapsed < TimeSpan.FromMinutes(2), $"{path} took {sw.Elapsed}");
        }
        output.WriteLine($"{files} files in {total.Elapsed.TotalSeconds:0.0} s (slowest {slowest:0.0} s: {slowestFile})");
        foreach (var (name, n) in hits.OrderByDescending(kv => kv.Value)) output.WriteLine($"  {n,4}  {name}");
    }
}
