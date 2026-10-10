using System.Diagnostics;

namespace NetDecompilerMcp.Tests.NativeFormats;

/// <summary>Real ELF, Mach-O and ARM64 PE images from restored runtime packages (see the test project's PackageDownload items).</summary>
public static class NativeFixtures
{
    private const string DbgShim = "9.0.621003";

    public static string LinuxArm64DbgShim => RealPackages.File("Microsoft.Diagnostics.DbgShim.linux-arm64", DbgShim, "runtimes/linux-arm64/native/libdbgshim.so");
    public static string LinuxArmDbgShim => RealPackages.File("Microsoft.Diagnostics.DbgShim.linux-arm", DbgShim, "runtimes/linux-arm/native/libdbgshim.so");
    public static string OsxArm64DbgShim => RealPackages.File("Microsoft.Diagnostics.DbgShim.osx-arm64", DbgShim, "runtimes/osx-arm64/native/libdbgshim.dylib");
    public static string WinArm64DbgShim => RealPackages.File("Microsoft.Diagnostics.DbgShim.win-arm64", DbgShim, "runtimes/win-arm64/native/dbgshim.dll");
    public static string OsxArm64AppHost => RealPackages.File("Microsoft.NETCore.App.Host.osx-arm64", "10.0.11", "runtimes/osx-arm64/native/apphost");
    /// <summary>Universal x86_64 + arm64 dylib with classic dyld info opcodes.</summary>
    public static string OsxFatSkia => RealPackages.File("SkiaSharp.NativeAssets.macOS", "2.88.9", "runtimes/osx/native/libSkiaSharp.dylib");
}

/// <summary>
/// Optional LLVM tools as oracles: NDM_LLVM_BIN names a folder with llvm-readobj, llvm-objdump and llvm-cxxfilt.
/// Their option strings live only in <see cref="Options"/>.
/// </summary>
public static class LlvmOracle
{
    public const string Variable = "NDM_LLVM_BIN";

    /// <summary>Native option strings per use.</summary>
    public static class Options
    {
        public const string ElfGnuStyle = "--elf-output-style=GNU";
        public const string Headers = "--file-headers --program-headers --section-headers";
        public const string DynamicSymbols = "--dyn-syms";
        public const string Relocations = "--relocations";
        public const string DynamicTable = "--dynamic-table";
        public const string Notes = "--notes";
        public const string UnwindInfo = "--unwind";
        public const string MachOChainedFixups = "--macho --chained-fixups";
        public const string MachOExportsTrie = "--macho --exports-trie";
        public const string MachODyldInfo = "--macho --dyld-info";
        public const string MachOFunctionStarts = "--macho --function-starts";
        public const string MachORebase = "--macho --rebase";
        public const string MachOBind = "--macho --bind";
        public const string MachOWeakBind = "--macho --weak-bind";
        public const string MachOLazyBind = "--macho --lazy-bind";
        public const string MachODataInCode = "--macho --data-in-code";
        public const string MachOPrivateHeaders = "--macho --private-headers";
        public const string MachOUniversalHeaders = "--macho --universal-headers";
        public const string MachOArch = "--arch=";
        public const string Disassemble = "-d --no-show-raw-insn";
        /// <summary>A position-independent shared object without a C library, linked by lld.</summary>
        public const string ClangSharedObject = "-O1 -fPIC -shared -nostdlib -fuse-ld=lld -Wno-incompatible-library-redeclaration";
        public const string LinkAndroidPacked = "-Wl,--pack-dyn-relocs=android";
        public const string LinkAndroidPackedRelr = "-Wl,--pack-dyn-relocs=android+relr";
        public const string LinkRelr = "-Wl,-z,pack-relative-relocs";
        public const string LinkLazy = "-Wl,-z,lazy";
        public const string LinkBothHashes = "-Wl,--hash-style=both";
        public const string LinkBuildId = "-Wl,--build-id";
        public const string Target = "--target=";
        public const string LinkChainedFixups = "-Wl,-fixup_chains";
        public const string LinkNoChainedFixups = "-Wl,-no_fixup_chains";
        /// <summary>Mach-O without an SDK: undefined symbols are looked up at load time.</summary>
        public const string LinkMachODynamicLookup = "-Wl,-undefined,dynamic_lookup -Wl,-platform_version,macos,11.0,11.0";
    }

    /// <summary>Compiles <paramref name="source"/> (C) with clang into <paramref name="output"/>; null on success, else clang's output.</summary>
    public static string? Compile(string source, string output, string options)
    {
        if (Bin is not { } bin) return "NDM_LLVM_BIN is not set";
        var exe = System.IO.Path.Combine(bin, OperatingSystem.IsWindows() ? "clang.exe" : "clang");
        if (!System.IO.File.Exists(exe)) return $"{exe} not found";
        var c = System.IO.Path.ChangeExtension(output, ".c");
        System.IO.File.WriteAllText(c, source);
        var psi = new ProcessStartInfo(exe);
        foreach (var o in options.Split(' ', StringSplitOptions.RemoveEmptyEntries)) psi.ArgumentList.Add(o);
        psi.ArgumentList.Add(c);
        psi.ArgumentList.Add("-o");
        psi.ArgumentList.Add(output);
        var (code, log) = Tools.Run(psi, 120_000);
        return code == 0 && System.IO.File.Exists(output) ? null : log;
    }

    public static string? Bin => RealData.Get(Variable) is { } dir && Directory.Exists(dir) ? dir : null;

    /// <summary>Output of <paramref name="tool"/> (e.g. "llvm-readobj") or null when NDM_LLVM_BIN is unset or the tool failed.</summary>
    public static string? Run(string tool, string options, string path)
    {
        if (Bin is not { } bin) return null;
        var exe = System.IO.Path.Combine(bin, OperatingSystem.IsWindows() ? tool + ".exe" : tool);
        if (!System.IO.File.Exists(exe)) return null;
        var psi = new ProcessStartInfo(exe);
        foreach (var o in options.Split(' ', StringSplitOptions.RemoveEmptyEntries)) psi.ArgumentList.Add(o);
        psi.ArgumentList.Add(path);
        var (code, output) = Tools.Run(psi, 120_000);
        return code == 0 ? output : null;
    }

    /// <summary>llvm-cxxfilt on many names at once (one per line); null when the tool is not available.</summary>
    public static string[]? Demangle(IReadOnlyList<string> names)
    {
        if (Bin is not { } bin) return null;
        var exe = System.IO.Path.Combine(bin, OperatingSystem.IsWindows() ? "llvm-cxxfilt.exe" : "llvm-cxxfilt");
        if (!System.IO.File.Exists(exe)) return null;
        var psi = new ProcessStartInfo(exe) { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false };
        using var p = Process.Start(psi)!;
        var reader = Task.Run(() => p.StandardOutput.ReadToEnd());
        foreach (var n in names) p.StandardInput.WriteLine(n);
        p.StandardInput.Close();
        var text = reader.Result;
        p.WaitForExit();
        return text.Split('\n').Select(l => l.TrimEnd('\r')).Take(names.Count).ToArray();
    }
}
