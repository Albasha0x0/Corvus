using NetDecompilerMcp.Core;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

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
        var apiSet = await tools.ListImports("kernel32.dll", module: "api-ms-win-core-synch-l1-1-0");
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
    public async Task ErrorsAreTyped()
    {
        var (env, tools) = Setup();
        using var _ = env;
        Assert.StartsWith("Error (not_loaded)", (await Assert.ThrowsAsync<ToolError>(() => tools.GetPeInfo("nothing.dll"))).Render(null));
        await tools.GetPeInfo(Kernel32);
        Assert.StartsWith("Error (not_found)", (await Assert.ThrowsAsync<ToolError>(() => tools.ResolveAddress("kernel32.dll", "0xFFFFFFFFFFFF"))).Render(null));
        Assert.StartsWith("Error (not_found)", (await Assert.ThrowsAsync<ToolError>(() => tools.ResolveAddress("kernel32.dll", "NoSuchExportName"))).Render(null));
        Assert.StartsWith("Error (invalid_argument)", (await Assert.ThrowsAsync<ToolError>(() => tools.SearchBytes("kernel32.dll", "4D ZZ"))).Render(null));
        Assert.StartsWith("Error (invalid_argument)", (await Assert.ThrowsAsync<ToolError>(() => tools.SearchBytes("kernel32.dll", "?? 5A"))).Render(null));
        Assert.StartsWith("Error (unsupported)", (await Assert.ThrowsAsync<ToolError>(() => tools.GetPeInfo(Env.FixturePath))).Render(null));
        // A .NET tool given a native image says which tools apply.
        var wrongKind = Assert.Throws<ToolError>(() => env.Workspace.Read(() => env.Workspace.Get("kernel32.dll")));
        Assert.Equal(ErrorCode.Unsupported, wrongKind.Code);
        Assert.Contains("get_pe_info", wrongKind.Remediation);
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
