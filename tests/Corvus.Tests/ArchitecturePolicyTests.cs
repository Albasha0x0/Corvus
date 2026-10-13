using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>
/// Images whose instructions the built-in analysis does not decode (MIPS, s390x): code tools refuse with unsupported, the
/// file's machine name and a Next; composite reports mark their code facts as not decoded. No success claims zero code facts.
/// </summary>
public sealed class ArchitecturePolicyTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private string Image(ushort machine, string name)
    {
        var w = new NativeFormats.ElfWriter { Is64 = false, Machine = machine, Text = [0, 0, 0, 0, 0x08, 0x00, 0xE0, 0x03, 0, 0, 0, 0] };
        w.Symbols.Add(new NativeFormats.ElfWriter.Symbol("f", NativeFormats.ElfWriter.TextRva, 12));
        var path = _dir.File(name);
        File.WriteAllBytes(path, w.Build());
        return path;
    }

    [Theory]
    [InlineData(NativeFormats.ElfWriter.EmMips, "Mips (EM_MIPS)", "EM_MIPS")]
    [InlineData(22, "EM_S390", "EM_S390")]
    public async Task Code_tools_refuse_with_the_machine_name_and_reports_mark_code_as_not_decoded(ushort machine, string archName, string machineName)
    {
        var path = Image(machine, $"m{machine}.so");
        var options = new ServerOptions { BackgroundIndexing = false };
        using var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var pager = new OutputPager(options);
        var tools = new NativeCodeTools(workspace, code, pager);
        var native = new NativeTools(workspace, pager, code);
        var f = "rva:0x" + NativeFormats.ElfWriter.TextRva.ToString("X");

        var refusals = new Func<Task>[]
        {
            () => tools.Disassemble(path, f), () => tools.GetCfg(path, f), () => tools.FindXrefs(path, f), () => tools.NativeCallTree(path, f),
            () => tools.InspectInstruction(path, f), () => tools.SearchInstructions(path, mnemonic: "nop"),
            () => new NativeCallTools(workspace, code).GetCallArguments(path, f), () => new NativeTraceTools(workspace, code).TraceNativeValues(path, f),
            () => new NativeVirtualCallTools(workspace, code).FindVirtualCalls(path), () => new NativeSimilarityTools(workspace, code).FindSimilarFunctions(path, f),
        };
        foreach (var call in refusals)
        {
            var e = await Assert.ThrowsAsync<ToolError>(call);
            Assert.Equal(ErrorCode.Unsupported, e.Code);
            Assert.Contains(archName, e.Message);
            Assert.DoesNotContain("Other", e.Message);
            Assert.False(string.IsNullOrWhiteSpace(e.Remediation));
            Assert.Contains($"\"arch\":\"{machineName}\"", System.Text.Json.JsonSerializer.Serialize(e.Details));
            Assert.Contains("instructions-not-decoded", System.Text.Json.JsonSerializer.Serialize(e.Details));
        }

        // composite reports: a success, with code facts marked not decoded
        var collector = ToolOutput.Collect();
        var dossier = await new NativeFunctionTools(workspace, code, pager).AnalyzeNativeFunction(path, f);
        Assert.DoesNotContain("0 blocks", dossier);
        Assert.Contains($"not decoded ({archName})", dossier);
        Assert.Equal("partial", collector.Coverage?.Status);
        var repeat = await FunctionDossierTests.Answer(() => new NativeFunctionTools(workspace, code, pager).AnalyzeNativeFunction(path, f));
        Assert.Contains("coverage: (partial,", repeat); // a cached answer keeps the coverage (G2-B1)
        var resolved = await native.ResolveAddress(path, f);
        Assert.Contains($"instructions and references: not decoded ({archName})", resolved);
        Assert.Contains("1 function", await tools.ListFunctions(path));
        Assert.Contains($"Code: not decoded by the built-in analysis ({archName})", await native.GetPeInfo(path));
    }
}
