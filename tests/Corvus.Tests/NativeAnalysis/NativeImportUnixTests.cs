using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Linking;
using Corvus.Services;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>
/// P/Invoke declarations checked against Linux, macOS and Android libraries on any host: target platform detection,
/// .NET probing names and folders, ELF and Mach-O export matching, C++ mangled exports and __Internal in an Il2Cpp game.
/// </summary>
public sealed class NativeImportUnixTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const string Source = """
        using System;
        using System.Runtime.InteropServices;
        public static class U
        {
            [DllImport("dbgshim")] public static extern int RegisterForRuntimeStartup(uint pid, IntPtr cb, IntPtr p, out IntPtr token);
            [DllImport("libdbgshim.so", EntryPoint = "CloseCLREnumeration")] public static extern int Close(IntPtr a, IntPtr b, uint n);
            [DllImport("dbgshim")] public static extern void NoSuchExport8f3a();
            [DllImport("nosuch8f3a")] public static extern void MissingLibrary();
            [DllImport("libc")] public static extern int getpid();
            [DllImport("winonly")] public static extern void WindowsOnly();
            [DllImport("armlib")] public static extern void WrongArch();
            [DllImport("cpp")] public static extern int foo(int x);
            [DllImport("cpp")] public static extern int plain();
            [DllImport("__Internal")] public static extern void il2cpp_internal_fn();
        }
        """;

    private string Put(string relative, byte[] bytes)
    {
        var path = _dir.File(relative.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static byte[] Library(params string[] functions) =>
        new ElfWriter { Symbols = [.. functions.Select((f, i) => new ElfWriter.Symbol(f, ElfWriter.TextRva + (uint)i * 4, 4))] }.Build();

    private Dictionary<string, NativeImportVerifier.Check> Verify(Env env, string assembly, string? platform, out TargetPlatform target)
    {
        var asm = env.Workspace.Load(assembly);
        var result = env.Workspace.Read(() => new NativeImportVerifier(p => NativeImageLoader.Open(p), hostHasSystemDlls: false).Verify(asm, default, platform));
        target = result.Platform;
        return result.Checks.ToDictionary(c => c.Method.Split("::")[1].Split('(')[0]);
    }

    [Fact]
    public void UnixLibrariesAreProbedAndTheirExportsMatched()
    {
        var app = Put("app/App.dll", Roslyn.Compile("App", Source, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary)));
        Put("app/runtimes/linux-arm64/native/libdbgshim.so", File.ReadAllBytes(NativeFixtures.LinuxArm64DbgShim));
        Put("app/runtimes/osx-arm64/native/libdbgshim.dylib", File.ReadAllBytes(NativeFixtures.OsxArm64DbgShim));
        Put("app/runtimes/win-x64/native/winonly.dll", [0x4D, 0x5A]);
        Put("app/runtimes/linux-arm64/native/libarmlib.so", File.ReadAllBytes(NativeFixtures.LinuxArmDbgShim));
        Put("app/libcpp.so", Library("_Z3fooi", "plain"));
        using var env = new Env();

        var linux = Verify(env, app, "linux", out var target);
        Assert.Equal(("linux", "linux-arm64"), (target.Os, target.Rid));
        string Verdict(Dictionary<string, NativeImportVerifier.Check> checks, string method) => $"{checks[method].Status}/{checks[method].Reason}";
        Assert.Equal("verified/versioned", Verdict(linux, "RegisterForRuntimeStartup")); // libdbgshim versions its exports
        Assert.Contains("version", linux["RegisterForRuntimeStartup"].Detail);
        Assert.EndsWith(Path.Combine("linux-arm64", "native", "libdbgshim.so"), linux["RegisterForRuntimeStartup"].ResolvedFile);
        Assert.StartsWith("verified/", Verdict(linux, "Close"));
        Assert.Equal("contradicted/missing_export", Verdict(linux, "NoSuchExport8f3a"));
        Assert.Equal("unresolved/dll_not_found", Verdict(linux, "MissingLibrary"));
        Assert.Contains("libnosuch8f3a.so", linux["MissingLibrary"].Detail);
        Assert.Equal("unresolved/system_dll_not_on_host", Verdict(linux, "getpid"));
        Assert.Equal("unresolved/wrong_platform", Verdict(linux, "WindowsOnly"));
        Assert.Contains("runtimes/win-x64/native/winonly.dll", linux["WindowsOnly"].Detail);
        Assert.Equal("contradicted/arch_mismatch", Verdict(linux, "WrongArch"));
        Assert.Equal("contradicted/mangled_only", Verdict(linux, "foo"));
        Assert.Equal("_Z3fooi", linux["foo"].Export);
        Assert.Contains("foo(int)", linux["foo"].Detail);
        Assert.Equal("verified/exact", Verdict(linux, "plain"));
        Assert.Equal("not_checked/runtime_internal", Verdict(linux, "il2cpp_internal_fn"));

        var mac = Verify(env, app, "osx", out target);
        Assert.Equal("osx-arm64", target.Rid);
        Assert.Equal("verified/exact", Verdict(mac, "RegisterForRuntimeStartup"));
        Assert.Equal("_RegisterForRuntimeStartup", mac["RegisterForRuntimeStartup"].Export);
        Assert.EndsWith("libdbgshim.dylib", mac["RegisterForRuntimeStartup"].ResolvedFile);

        // Without a platform: runtimes for several systems, so the library beside the app decides; with none, Windows rules as before.
        Verify(env, app, null, out target);
        Assert.Equal("linux", target.Os);
        Assert.Contains("beside", target.Source);
        File.Delete(_dir.File("app/libcpp.so"));
        Assert.Equal("windows", UnixProbing.Detect(_dir.File("app"), null).Os);
    }

    [Fact]
    public void InternalBindsToTheIl2CppGameBinary()
    {
        // Dummy assemblies of an Android game with libil2cpp.so beside the dump.
        var dummy = Put("game/DummyDll/Assembly-CSharp.dll", Roslyn.Compile("Assembly-CSharp", Source, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary)));
        Put("game/script.json", "{}"u8.ToArray());
        Put("game/libil2cpp.so", Library("il2cpp_internal_fn", "il2cpp_init"));
        Put("game/libcpp.so", Library("plain"));
        using var env = new Env();
        var checks = Verify(env, dummy, null, out var target);
        Assert.Equal(("android", "android-arm64"), (target.Os, target.Rid));
        Assert.Contains("libil2cpp.so", target.Source);
        Assert.Equal("verified", checks["il2cpp_internal_fn"].Status);
        Assert.Equal("internal", checks["il2cpp_internal_fn"].Reason);
        Assert.Equal("verified", checks["plain"].Status); // the game binary's folder is probed too
    }

    [Fact]
    public void PlatformAndProbingFollowTheRuntime()
    {
        var linux = new TargetPlatform("linux", "linux-x64", "test");
        Assert.Equal(["libfoo.so", "foo.so", "libfoo", "foo"], UnixProbing.ProbeNames("foo", linux));
        Assert.Equal(["libfoo.so.1"], UnixProbing.ProbeNames("libfoo.so.1", linux));
        Assert.Equal(["libfoo.dylib", "foo.dylib", "libfoo", "foo"], UnixProbing.ProbeNames("foo", new TargetPlatform("osx", null, "test")));
        Assert.Equal(["android-arm64", "android", "linux-arm64", "linux", "unix"], new TargetPlatform("android", "android-arm64", "test").RidChain);
        Assert.True(UnixProbing.IsSystemLibrary("libc") && UnixProbing.IsSystemLibrary("/usr/lib/libSystem.dylib") && UnixProbing.IsSystemLibrary("liblog.so") && !UnixProbing.IsSystemLibrary("dbgshim"));

        var dir = _dir.File("deps");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "App.deps.json"), """{"runtimeTarget":{"name":".NETCoreApp,Version=v8.0/linux-musl-x64"},"targets":{}}""");
        var detected = UnixProbing.Detect(dir, null);
        Assert.Equal(("linux", "linux-musl-x64", NativeArch.X64), (detected.Os, detected.Rid, detected.Arch));
        Assert.Equal("osx", UnixProbing.Detect(dir, "macos").Os);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => UnixProbing.Detect(dir, "beos")).Code);
        File.WriteAllText(Path.Combine(dir, "App.deps.json"), """{"targets":{".NETCoreApp,Version=v8.0":{"Lib/1.0":{"runtimeTargets":{"runtimes/osx-arm64/native/libx.dylib":{"rid":"osx-arm64","assetType":"native"}}}}}}""");
        Assert.Equal(("osx", "osx-arm64"), UnixProbing.Detect(dir, null) is var d ? (d.Os, d.Rid) : default);
    }
}
