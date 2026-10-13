using Corvus.Core;
using Corvus.Tools;
using Corvus.Native.Providers;

namespace Corvus.Tests;

public class NativeToolsTests
{
    private static readonly string Kernel32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll");

    private static (Env Env, NativeTools Tools) Setup()
    {
        var env = new Env();
        return (env, new NativeTools(env.Workspace, env.Pager));
    }

    [WindowsFact]
    public async Task Kernel32OverviewImportsExportsAndAddresses()
    {
        var (env, tools) = Setup();
        using var _ = env;
        var info = await tools.GetPeInfo(Kernel32);
        Assert.Contains("kernel32.dll: AMD64 DLL (PE32+)", info);
        Assert.Contains("kernel32.pdb", info);
        Assert.Contains("Mitigations: on: ASLR", info);
        Assert.Contains("Signature:", info);

        Assert.Contains("CreateFileW", await tools.ListExports("kernel32.dll", filter: "CreateFileW"));
        var forwarded = await tools.ListExports("kernel32.dll", filter: "HeapAlloc");
        Assert.Contains("-> NTDLL.RtlAllocateHeap", forwarded);

        var imports = await tools.ListImports("kernel32.dll", filter: "NtClose");
        Assert.Contains("ntdll.dll!NtClose", imports);
        var apiSet = await tools.ListImports("kernel32.dll", library: "api-ms-win-core-synch-l1-1-0");
        Assert.Matches(@"api-ms-win-core-synch-l1-1-0\.dll \((?i:kernelbase)\.dll\)!", apiSet);

        var resolved = await tools.ResolveAddress("kernel32.dll", "CreateFileW");
        Assert.Contains("export CreateFileW", resolved);
        Assert.Contains("section .text (r-x)", resolved);
        Assert.Contains("unwind range", await tools.ResolveAddress("kernel32.dll", "BaseThreadInitThunk"));

        Assert.Contains("ntdll.dll!NtClose", await tools.ResolveAddress("kernel32.dll", "ntdll!NtClose") is var slot ? slot.Replace("IAT slot of ", "") : "");

        var mz = await tools.SearchBytes("kernel32.dll", "4D 5A ?? 00");
        Assert.Contains("hit", mz);
        Assert.Contains("1 hit", await tools.SearchBytes("kernel32.dll", "KERNEL32.dll", text: true, section: ".rdata", limit: 1) is var t && t.Contains("hit") ? "1 hit" : t);

        var dump = await tools.ReadBytes("kernel32.dll", "rva:0", 16);
        Assert.Contains("4D 5A", dump);
    }

    [WindowsFact]
    public async Task Kernel32FunctionsDisassemblyGraphsAndReferences()
    {
        using var env = new Env();
        var code = new Corvus.Services.NativeCodeService(env.Workspace, env.Options);
        var tools = new NativeCodeTools(env.Workspace, code, env.Pager);
        var list = await tools.ListFunctions(Kernel32, filter: "BaseThreadInitThunk");
        Assert.Contains("BaseThreadInitThunk", list);
        Assert.Matches(@"kernel32\.dll: [\d,]+ functions", list);

        var disasm = await tools.Disassemble("kernel32.dll", "BaseThreadInitThunk");
        Assert.Contains("; BaseThreadInitThunk at 0x18", disasm);
        Assert.Contains("call", disasm);

        var cfg = await tools.GetCfg("kernel32.dll", "BaseThreadInitThunk");
        Assert.Matches(@"BaseThreadInitThunk at 0x[0-9A-F]+: \d+ blocks", cfg);
        Assert.Contains("Return", cfg);

        var xrefs = await tools.FindXrefs("kernel32.dll", "ntdll!NtClose");
        Assert.Contains("References to", xrefs);
        Assert.Contains("ImportCall", xrefs);

        var tree = await tools.NativeCallTree("kernel32.dll", "BaseThreadInitThunk", depth: 2);
        Assert.StartsWith("Engine: ours (", tree);
        Assert.StartsWith("  BaseThreadInitThunk", tree.Split('\n')[2]);

        var strings = await tools.SearchNativeStrings("kernel32.dll", ".dll", limit: 5);
        Assert.Contains("refs", strings);
        Assert.StartsWith("Error (not_found)", (await Assert.ThrowsAsync<ToolError>(() => tools.GetCfg("kernel32.dll", "rva:0"))).Render(null));
        Assert.StartsWith("Error (invalid_argument)", (await Assert.ThrowsAsync<ToolError>(() => tools.NativeCallTree("kernel32.dll", "BaseThreadInitThunk", direction: "up"))).Render(null));
    }

    [WindowsFact]
    public async Task Win32ResourcesThroughTheResourceTools()
    {
        var (env, tools) = Setup();
        using var _ = env;
        await tools.GetPeInfo(Kernel32);
        var resources = new ResourceTools(env.Workspace, env.Resources, env.Decompiler, env.Pager);
        var list = await resources.ListResources("kernel32.dll");
        Assert.Contains("VERSION/#1/", list);
        // Rows page by offset and limit, the record holding the rows the text shows (G1).
        var collected = Corvus.Mcp.ToolOutput.Collect();
        var page = await resources.ListResources("kernel32.dll", offset: 1, limit: 1);
        var record = (ResourceList)collected.Record!;
        var row = Assert.Single(record.Items);
        Assert.Contains("(showing 2-2)", page);
        Assert.Contains($"  {row.Name}  {row.Size:N0} bytes at rva {row.Rva}", page);
        var version = await resources.GetResource("kernel32.dll", "VERSION/1");
        Assert.Contains("OriginalFilename: kernel32", version, StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith("Error (not_found)", (await Assert.ThrowsAsync<ToolError>(() => resources.GetResource("kernel32.dll", "NOPE/1"))).Render(null));
    }

    [WindowsFact]
    public async Task ErrorsAreTyped()
    {
        var (env, tools) = Setup();
        using var _ = env;
        Assert.StartsWith("Error (not_loaded)", (await Assert.ThrowsAsync<ToolError>(() => tools.GetPeInfo("nothing.dll"))).Render(null));
        await tools.GetPeInfo(Kernel32);
        Assert.StartsWith("Error (not_found)", (await Assert.ThrowsAsync<ToolError>(() => tools.ResolveAddress("kernel32.dll", "0xFFFFFFFFFFFF"))).Render(null));
        Assert.StartsWith("Error (not_found)", (await Assert.ThrowsAsync<ToolError>(() => tools.ResolveAddress("kernel32.dll", "NoSuchExportName"))).Render(null));
        Assert.StartsWith("Error (invalid_argument)", (await Assert.ThrowsAsync<ToolError>(() => tools.SearchBytes("kernel32.dll", "4D ZZ"))).Render(null));
        Assert.StartsWith("Error (invalid_argument)", (await Assert.ThrowsAsync<ToolError>(() => tools.SearchBytes("kernel32.dll", "?? ??"))).Render(null));
        Assert.StartsWith("Error (unsupported)", (await Assert.ThrowsAsync<ToolError>(() => tools.GetPeInfo(Env.FixturePath))).Render(null));
        // A .NET tool given a native image says which tools apply.
        var wrongKind = Assert.Throws<ToolError>(() => env.Workspace.Read(() => env.Workspace.Get("kernel32.dll")));
        Assert.Equal(ErrorCode.Unsupported, wrongKind.Code);
        Assert.Contains("get_pe_info", wrongKind.Remediation);
    }

    [Trait("Speed", "Slow")]
    [WindowsFact]
    public async Task DecompilesThroughIdaAndRecoversCppClasses()
    {
        using var env = new Env();
        using var engines = new Corvus.Services.NativeEngineService();
        if (!engines.Providers[0].CheckAvailability().IsAvailable) return; // IDA not installed here
        var tools = new NativeAnalysisTools(env.Workspace, engines, env.Pager);
        var imagehlp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "imagehlp.dll");
        var text = await tools.DecompileNative(imagehlp, "CheckSumMappedFile", addresses: true);
        Assert.Contains("CheckSumMappedFile", text);
        Assert.Contains("return", text);
        Assert.Matches(@"/\* 18[0-9A-F]+ \*/", text);
        // The second call reuses the open session.
        var again = await tools.DecompileNative("imagehlp.dll", "CheckSumMappedFile");
        Assert.Contains("CheckSumMappedFile", again);

        var classes = await tools.ListCppClasses(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "msvcp_win.dll"), filter: "exception");
        Assert.Contains("class std::exception", classes);
        Assert.Contains("vftable", classes);
    }

    [Fact]
    public async Task CallTreeOfAnImportSlotListsTheFunctionsCallingThroughIt()
    {
        using var env = new Env();
        using var dir = new TempDir();
        var tools = new NativeCodeTools(env.Workspace, new Corvus.Services.NativeCodeService(env.Workspace, env.Options), env.Pager);
        var path = McpProtocolTests.NativeSample(dir);
        var tree = await tools.NativeCallTree(path, "KERNEL32.dll!ExitProcess", direction: "callers", depth: 2);
        Assert.Contains("KERNEL32!ExitProcess  (import slot at 0x", tree);
        Assert.Contains("nothing calls through it", tree); // the sample only imports it
        // callees of a slot: still no function there
        var error = await Assert.ThrowsAsync<ToolError>(() => tools.NativeCallTree("native.dll", "KERNEL32.dll!ExitProcess"));
        Assert.Contains("is the import slot of KERNEL32!ExitProcess, not a function", error.Message);
        Assert.Contains("native_call_tree direction=callers function=KERNEL32!ExitProcess", error.Remediation);
    }

    [Fact]
    public async Task FunctionRangeEndingPastTheImageListsToItsEnd()
    {
        using var env = new Env();
        using var dir = new TempDir();
        var tools = new NativeCodeTools(env.Workspace, new Corvus.Services.NativeCodeService(env.Workspace, env.Options), env.Pager);
        var all = await tools.ListFunctions(McpProtocolTests.NativeSample(dir));
        var count = System.Text.RegularExpressions.Regex.Match(all, @"\n(\d+) functions? \(").Groups[1].Value;
        Assert.NotEqual("", count);
        foreach (var end in new[] { "0x7FFFFFFFFFFF", "0x10000000" })
            Assert.Contains($"\n{count} function", await tools.ListFunctions("native.dll", from: "rva:0", to: end));
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => tools.ListFunctions("native.dll", from: "0x7FFFFFFFFFFF"))).Code);
    }

    /// <summary>ReadyToRun images clear the IL-only flag too; they are not mixed-mode and get no native view.</summary>
    [Fact]
    public void ReadyToRunAssembliesGetNoNativeView()
    {
        var linq = Path.Combine(Path.GetDirectoryName(typeof(object).Assembly.Location)!, "System.Linq.dll");
        using var env = new Env();
        var asm = env.Workspace.Load(linq);
        Assert.False(asm.Module.IsILOnly); // the flag a plain IL-only check would have taken for mixed-mode
        Assert.False(Corvus.Native.Linking.MixedModeMap.IsMixedMode(asm.Module));
        Assert.Null(env.Workspace.Read(() => env.Workspace.NativeViewOf(asm)));
        Assert.Empty(env.Workspace.Read(() => env.Workspace.Natives));
    }

    [WindowsFact]
    public void LoadAnyLoadsNativeImagesAndKeepsIdsUnique()
    {
        using var env = new Env();
        var (assembly, native) = env.Workspace.LoadAny(Kernel32);
        Assert.Null(assembly);
        Assert.Equal("kernel32.dll", native!.Id);
        Assert.Same(native, env.Workspace.LoadAny(Kernel32).Native);
        var wow = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86), "kernel32.dll");
        if (File.Exists(wow) && Environment.Is64BitOperatingSystem)
            Assert.Equal("kernel32.dll#2", env.Workspace.LoadAny(wow).Native!.Id);
        var reloaded = env.Workspace.ReloadNative(native);
        Assert.Equal("kernel32.dll", reloaded.Id);
        env.Workspace.UnloadNative(reloaded);
        Assert.Null(env.Workspace.Read(() => env.Workspace.FindNative(Kernel32)));
    }
}
