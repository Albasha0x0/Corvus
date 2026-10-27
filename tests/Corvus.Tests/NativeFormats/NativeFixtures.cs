using System.Diagnostics;

namespace Corvus.Tests.NativeFormats;

/// <summary>Real ELF, Mach-O and ARM64 PE images from restored runtime packages (see the test project's PackageDownload items).</summary>
public static class NativeFixtures
{
    private const string DbgShim = "9.0.621003";

    public static string LinuxArm64DbgShim => RealPackages.File("Microsoft.Diagnostics.DbgShim.linux-arm64", DbgShim, "runtimes/linux-arm64/native/libdbgshim.so");
    /// <summary>The same sources as <see cref="LinuxArm64DbgShim"/> built against musl: a second build to match functions against.</summary>
    public static string LinuxMuslArm64DbgShim => RealPackages.File("Microsoft.Diagnostics.DbgShim.linux-musl-arm64", DbgShim, "runtimes/linux-musl-arm64/native/libdbgshim.so");
    public static string LinuxArmDbgShim => RealPackages.File("Microsoft.Diagnostics.DbgShim.linux-arm", DbgShim, "runtimes/linux-arm/native/libdbgshim.so");
    public static string OsxArm64DbgShim => RealPackages.File("Microsoft.Diagnostics.DbgShim.osx-arm64", DbgShim, "runtimes/osx-arm64/native/libdbgshim.dylib");
    public static string LinuxX64DbgShim => RealPackages.File("Microsoft.Diagnostics.DbgShim.linux-x64", DbgShim, "runtimes/linux-x64/native/libdbgshim.so");
    public static string OsxX64DbgShim => RealPackages.File("Microsoft.Diagnostics.DbgShim.osx-x64", DbgShim, "runtimes/osx-x64/native/libdbgshim.dylib");
    /// <summary>Itanium RTTI with vtables (x64 ELF and Mach-O), from the test SDK's code coverage package.</summary>
    public static string LinuxX64Coverage => RealPackages.File("Microsoft.CodeCoverage", "17.14.1", "build", "netstandard2.0", "ubuntu", "x64", "libCoverageInstrumentationMethod.so");
    public static string OsxX64Coverage => RealPackages.File("Microsoft.CodeCoverage", "17.14.1", "build", "netstandard2.0", "macos", "x64", "libCoverageInstrumentationMethod.dylib");
    public static string LinuxX64InstrumentationEngine => RealPackages.File("Microsoft.CodeCoverage", "17.14.1", "build", "netstandard2.0", "ubuntu", "x64", "libInstrumentationEngine.so");
    public static string OsxX64InstrumentationEngine => RealPackages.File("Microsoft.CodeCoverage", "17.14.1", "build", "netstandard2.0", "macos", "x64", "libInstrumentationEngine.dylib");
    /// <summary>Itanium RTTI on ARM64 and ARM32 Android (slow set: the runtime packs download with CORVUS_ALL_TESTS=1).</summary>
    public static string AndroidArm64Tracing => RealPackages.File("Microsoft.Android.Runtime.35.android-arm64", "35.0.105", "runtimes", "android-arm64", "native", "libxamarin-native-tracing.so");
    public static string AndroidArmTracing => RealPackages.File("Microsoft.Android.Runtime.35.android-arm", "35.0.105", "runtimes", "android-arm", "native", "libxamarin-native-tracing.so");
    public static string WinArm64DbgShim => RealPackages.File("Microsoft.Diagnostics.DbgShim.win-arm64", DbgShim, "runtimes/win-arm64/native/dbgshim.dll");
    public static string OsxArm64AppHost => RealPackages.File("Microsoft.NETCore.App.Host.osx-arm64", "10.0.11", "runtimes/osx-arm64/native/apphost");
    /// <summary>
    /// A stripped library of a NativeAOT runtime pack (linux-x64, osx-arm64; four more Linux targets in the slow set) and,
    /// beside it, its separate DWARF: &lt;file&gt;.dbg (ELF, linked by .gnu_debuglink and build-id) or &lt;file&gt;.dwarf (Mach-O, by UUID).
    /// </summary>
    public static string NativeAotLib(string rid, string file) => RealPackages.File("Microsoft.NETCore.App.Runtime.NativeAOT." + rid, "10.0.11", "runtimes", rid, "native", file);

    /// <summary>Universal x86_64 + arm64 dylib with classic dyld info opcodes.</summary>
    public static string OsxFatSkia => RealPackages.File("SkiaSharp.NativeAssets.macOS", "2.88.9", "runtimes/osx/native/libSkiaSharp.dylib");
}

/// <summary>Optional LLVM reference tools: CORVUS_LLVM_BIN names their folder; their option strings live only in <see cref="Options"/>.</summary>
public static class LlvmOracle
{
    public const string Variable = "CORVUS_LLVM_BIN";

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
        /// <summary>llvm-dwarfdump: every entry of .debug_info (and .debug_types).</summary>
        public const string DwarfDebugInfo = "--debug-info";
        /// <summary>llvm-symbolizer: each address's inlined frames, short function names and file base names (then --obj=FILE).</summary>
        public const string Symbolize = "--inlines --functions=short --basenames";
        public const string SymbolizeObject = "--obj=";
        /// <summary>DWARF variants of the same source.</summary>
        public const string DebugInfo = "-g";
        public const string DwarfVersion = "-gdwarf-";
        public const string TypeUnits = "-fdebug-types-section";
        public const string CompressDebug = "-gz=";
        public const string CPlusPlus = "-x c++";
        /// <summary>Split DWARF: skeleton units in the output, split units in .dwo files beside it.</summary>
        public const string SplitDwarf = "-gsplit-dwarf";
        public const string CompileOnly = "-c";
        /// <summary>llvm-dwp: package the .dwo files an executable's skeletons name (then -o FILE).</summary>
        public const string DwpFromExecutable = "-e";
        public const string Output = "-o";
    }

    /// <summary>Runs <paramref name="tool"/> (clang, llvm-dwp, ...) from CORVUS_LLVM_BIN in <paramref name="workingDirectory"/>; null on success, else its output.</summary>
    public static string? Tool(string tool, string workingDirectory, params string[] args)
    {
        if (Bin is not { } bin) return $"{Variable} is not set";
        var exe = System.IO.Path.Combine(bin, OperatingSystem.IsWindows() ? tool + ".exe" : tool);
        if (!System.IO.File.Exists(exe)) return $"{exe} not found";
        var psi = new ProcessStartInfo(exe) { WorkingDirectory = workingDirectory };
        foreach (var a in args) foreach (var o in a.Split(' ', StringSplitOptions.RemoveEmptyEntries)) psi.ArgumentList.Add(o);
        var (code, log) = Tools.Run(psi, 120_000);
        return code == 0 ? null : log;
    }

    /// <summary>
    /// llvm-symbolizer on <paramref name="obj"/>: per address, its frames innermost first as (function, file base name, line);
    /// null when the tool is not available.
    /// </summary>
    public static List<List<(string Function, string File, int Line)>>? Symbolize(string obj, IReadOnlyList<ulong> addresses)
    {
        if (Bin is not { } bin) return null;
        var exe = System.IO.Path.Combine(bin, OperatingSystem.IsWindows() ? "llvm-symbolizer.exe" : "llvm-symbolizer");
        if (!System.IO.File.Exists(exe)) return null;
        var psi = new ProcessStartInfo(exe) { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false };
        foreach (var o in Options.Symbolize.Split(' ')) psi.ArgumentList.Add(o);
        psi.ArgumentList.Add(Options.SymbolizeObject + obj);
        using var p = Process.Start(psi)!;
        var reader = Task.Run(() => p.StandardOutput.ReadToEnd());
        foreach (var a in addresses) p.StandardInput.WriteLine($"0x{a:X}");
        p.StandardInput.Close();
        var blocks = reader.Result.Replace("\r", "").Split("\n\n", StringSplitOptions.RemoveEmptyEntries);
        p.WaitForExit();
        var result = new List<List<(string, string, int)>>();
        foreach (var block in blocks.Take(addresses.Count))
        {
            var lines = block.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            var frames = new List<(string, string, int)>();
            for (int k = 0; k + 1 < lines.Length; k += 2)
            {
                var parts = lines[k + 1].Split(':');
                frames.Add((lines[k], parts[0], parts.Length > 1 && int.TryParse(parts[1], out var n) ? n : 0));
            }
            result.Add(frames);
        }
        return result;
    }

    /// <summary>Compiles <paramref name="source"/> (C) with clang into <paramref name="output"/>; null on success, else clang's output.</summary>
    public static string? Compile(string source, string output, string options)
    {
        if (Bin is not { } bin) return "CORVUS_LLVM_BIN is not set";
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

    /// <summary>Output of <paramref name="tool"/> (e.g. "llvm-readobj") or null when CORVUS_LLVM_BIN is unset or the tool failed.</summary>
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
