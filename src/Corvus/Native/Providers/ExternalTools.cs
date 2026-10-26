using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;

namespace Corvus.Native.Providers;

/// <summary>How an external tool is started: an executable, or a jar run by the configured Java.</summary>
public enum ExternalToolKind { Executable, Jar }

/// <summary>
/// One external program: the environment variable that names it (a file or its folder), the file names looked for there
/// and on PATH, extra folders probed, the version arguments, and its option strings by operation (placeholders in braces).
/// </summary>
public sealed record ExternalTool(string Id, string Name, string Variable, ExternalToolKind Kind, string[] Files, string[] VersionArguments,
    int MinimumMajorVersion, string Purpose, bool TestOracle, IReadOnlyDictionary<string, string[]> Options)
{
    /// <summary>Folders searched after the variable: before PATH when <see cref="KnownDirectoriesFirst"/>, else after it.</summary>
    public Func<IEnumerable<(string Directory, string Source)>> KnownDirectories { get; init; } = () => [];
    public bool KnownDirectoriesFirst { get; init; }
}

/// <summary>Where a tool was found and how it ran its version probe.</summary>
public sealed record ExternalToolProbe(string Id, string Name, string Purpose, bool Found, string? Path, string? Source, string? Version,
    string? Problem, string Remediation)
{
    public bool Usable => Found && Problem == null;

    /// <summary>Why Version is unknown for a usable tool (its version check timed out); null when it was read or not asked.</summary>
    public string? VersionUnknown { get; init; }
}

/// <summary>
/// The one table of external programs (engines, device bridge, test oracles), how each is found and run. Children get a
/// minimal environment (<see cref="MinimalEnvironment"/>), never the whole server environment.
/// </summary>
public static partial class ExternalTools
{
    private static Dictionary<string, string[]> Ops(params (string Op, string[] Args)[] ops) => ops.ToDictionary(o => o.Op, o => o.Args, StringComparer.Ordinal);

    private static readonly string Exe = OperatingSystem.IsWindows() ? ".exe" : "";

    /// <summary>
    /// Reads a variable that locates a tool (its own, PATH, JAVA_HOME, the Android SDK's) or sets whether and where it
    /// downloads (CORVUS_OFFLINE, CORVUS_SYMBOL_CACHE, _NT_SYMBOL_PATH); null when unset. The process
    /// environment unless the host replaces it, as the tests do to keep one test's settings from another's lookups.
    /// </summary>
    internal static Func<string, string?> ReadVariable { get; set; } = Environment.GetEnvironmentVariable;

    /// <summary>
    /// Values a host adds to the environment of the children it starts; empty in the server. The tests give their flow's
    /// settings, so a tool one test starts sees them and a worker another test starts does not.
    /// </summary>
    internal static Func<IReadOnlyDictionary<string, string?>> ChildVariables { get; set; } = () => new Dictionary<string, string?>();

    /// <summary>The <see cref="ChildVariables"/> a child keeps: <see cref="KeptVariables"/> and ADB_*.</summary>
    internal static Dictionary<string, string?> KeptChildVariables() =>
        ChildVariables().Where(v => Kept(v.Key)).ToDictionary(v => v.Key, v => v.Value);

    private static bool Kept(string name) =>
        KeptVariables.Contains(name, StringComparer.OrdinalIgnoreCase) || name.StartsWith("ADB_", StringComparison.OrdinalIgnoreCase);

    public static readonly ExternalTool Java = new("java", "Java (JDK 17+)", "CORVUS_JAVA", ExternalToolKind.Executable, ["java" + Exe], ["-version"], 17,
        "decompile_java", false,
        Ops(("jar", ["-Xss16m", "-jar", "{jar}"])))
    {
        KnownDirectories = () => ReadVariable("JAVA_HOME") is { Length: > 0 } home ? [(System.IO.Path.Combine(home, "bin"), "JAVA_HOME")] : [],
        KnownDirectoriesFirst = true,
    };

    public static readonly ExternalTool JavaDecompiler = new("jadx", "JADX headless server (jadx-headless-mcp fat jar)", "CORVUS_JAVA_DECOMPILER", ExternalToolKind.Jar,
        ["jadx-headless-mcp*.jar"], [], 0, "decompile_java (Java and Kotlin source)", false,
        Ops(("server", ["--threads", "{threads}", "--decompile-timeout-ms", "{timeoutMs}", "--max-source-bytes", "{maxBytes}", "--resources", "none"])));

    public static readonly ExternalTool JavaDecompiler2 = new("vineflower", "Vineflower (jar)", "CORVUS_JAVA_DECOMPILER2", ExternalToolKind.Jar,
        ["vineflower*.jar"], [], 0, "decompile_java engine=vineflower", false,
        Ops(("decompile", ["-log=WARN", "{input}", "{output}"]), ("library", ["-e={jar}"])));

    public static readonly ExternalTool PythonDecompiler = new("python-decompiler", "Python decompiler (pycdc or a compatible program)",
        "CORVUS_PY_DECOMPILER", ExternalToolKind.Executable, ["pycdc" + Exe], [], 0, "summarize_file view=python (Python source)", false,
        Ops(("decompile", ["{input}"])));

    public static readonly ExternalTool Adb = new("adb", "Android Debug Bridge (adb)", "CORVUS_ADB", ExternalToolKind.Executable, ["adb" + Exe], ["version"], 0,
        "the Android device tools", false,
        Ops(("devices", ["devices", "-l"]),
            ("getprop", ["-s", "{serial}", "shell", "getprop"]),
            ("boot", ["-s", "{serial}", "shell", "getprop", "sys.boot_completed"]),
            ("packages", ["-s", "{serial}", "shell", "pm", "list", "packages", "-f", "-U", "-i"]),
            ("ps", ["-s", "{serial}", "shell", "ps", "-A", "-o", "PID,PPID,USER,NAME"]),
            ("ps-legacy", ["-s", "{serial}", "shell", "ps"]),
            ("features", ["-s", "{serial}", "shell", "pm", "list", "features"]),
            ("services", ["-s", "{serial}", "shell", "service", "list"]),
            ("settings", ["-s", "{serial}", "shell", "settings", "list", "{namespace}"]),
            ("ls", ["-s", "{serial}", "shell", "ls", "-la", "{remote}"]),
            ("user", ["--user", "{user}"]),
            ("dumpsys", ["-s", "{serial}", "shell", "dumpsys", "package", "{package}"]),
            ("path", ["-s", "{serial}", "shell", "pm", "path", "{package}"]),
            ("stat", ["-s", "{serial}", "shell", "stat", "-c", "%F", "{remote}"]),
            ("pull", ["-s", "{serial}", "pull", "{remote}", "{local}"]),
            ("push", ["-s", "{serial}", "push", "{local}", "{remote}"]),
            ("remove", ["-s", "{serial}", "shell", "rm", "-f", "{remote}"]),
            ("logcat", ["-s", "{serial}", "logcat", "-d", "-v", "threadtime"]),
            ("listing", ["-s", "{serial}", "shell", "ls", "-l", "{remote}"]),
            ("cat", ["-s", "{serial}", "shell", "cat", "{remote}"]),
            ("screencap", ["-s", "{serial}", "exec-out", "screencap", "-p"]),
            ("window", ["-s", "{serial}", "shell", "dumpsys", "window", "windows"]),
            ("activities", ["-s", "{serial}", "shell", "dumpsys", "activity", "activities"]),
            ("wm", ["-s", "{serial}", "shell", "wm", "{what}"]),
            ("display", ["-s", "{serial}", "shell", "dumpsys", "display"]),
            ("bugreport-stream", ["-s", "{serial}", "exec-out", "bugreportz", "-s"]),
            ("bugreport-zip", ["-s", "{serial}", "shell", "bugreportz"]),
            ("bugreport-text", ["-s", "{serial}", "shell", "bugreport"]),
            ("size", ["-s", "{serial}", "shell", "stat", "-c", "%s", "{remote}"]),
            ("install", ["-s", "{serial}", "install-multiple"]),
            ("uninstall", ["-s", "{serial}", "uninstall"])))
    {
        KnownDirectories = AndroidSdkDirectories,
    };

    public static readonly ExternalTool Aapt2 = new("aapt2", "aapt2 (test oracle)", "CORVUS_AAPT2", ExternalToolKind.Executable, ["aapt2" + Exe], ["version"], 0,
        "oracle for the manifest and resource readers in tests", true,
        Ops(("xmltree", ["dump", "xmltree", "--file", "{file}", "{apk}"]), ("resources", ["dump", "resources", "{apk}"])));

    public static readonly ExternalTool ApkSigner = new("apksigner", "apksigner (test oracle)", "CORVUS_APKSIGNER", ExternalToolKind.Jar, ["apksigner*.jar"], ["--version"], 0,
        "oracle for APK signature verification in tests", true,
        Ops(("verify", ["verify", "--print-certs", "-v", "{apk}"])));

    public static readonly ExternalTool DexDisassembler = new("baksmali", "baksmali (test oracle)", "CORVUS_DEX_DISASSEMBLER", ExternalToolKind.Jar, ["baksmali*.jar"], ["--version"], 0,
        "oracle for the Dalvik disassembler in tests", true,
        Ops(("disassemble", ["disassemble", "-o", "{out}", "{dex}"])));

    public static readonly ExternalTool ProtoCompiler = new("protoc", "protoc (test oracle)", "CORVUS_PROTO_COMPILER", ExternalToolKind.Executable, ["protoc" + Exe], ["--version"], 0,
        "oracle for the .proto text rebuilt from descriptors in tests", true,
        Ops(("descriptor-set", ["--proto_path", "{root}", "--descriptor_set_out", "{out}", "{file}"])));

    public static readonly ExternalTool TShark = new("tshark", "TShark (Wireshark)", "CORVUS_TSHARK", ExternalToolKind.Executable, ["tshark" + Exe], ["--version"], 3,
        "search_container kind=packet (fields not decoded in-process)", false,
        Ops(("fields", ["-r", "{file}", "-n", "-2", "-Y", "{filter}", "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,", "-E", "quote=n",
                "-e", "frame.number", "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ipv6.src", "-e", "ip.dst", "-e", "ipv6.dst",
                "-e", "tcp.srcport", "-e", "udp.srcport", "-e", "tcp.dstport", "-e", "udp.dstport", "-e", "_ws.col.protocol"]),
            ("field", ["-e", "{field}"]),
            // test oracle for unpack_container's HTTP objects; TShark leaves out-of-order segments unassembled by default
            ("export-objects", ["-r", "{file}", "-n", "-q", "-o", "tcp.reassemble_out_of_order:TRUE", "--export-objects", "http,{out}"]),
            ("http-messages", ["-r", "{file}", "-n", "-Y", "http.request or http.response", "-T", "fields", "-e", "frame.number"]),
            ("key-log", ["-o", "tls.keylog_file:{keys}"])))
    {
        KnownDirectories = WiresharkDirectories,
    };

    // WABT; threads are enabled to match the in-process feature set (WABT leaves them off by default)
    public static readonly ExternalTool WasmText = new("wasm2wat", "wasm2wat, WABT (test oracle)", "CORVUS_WASM_TO_TEXT", ExternalToolKind.Executable, ["wasm2wat" + Exe],
        ["--version"], 0, "oracle for the WebAssembly text writer in tests", true,
        Ops(("text", ["--enable-threads", "{module}"])));

    public static readonly ExternalTool WasmValidator = new("wasm-validate", "wasm-validate, WABT (test oracle)", "CORVUS_WASM_VALIDATOR", ExternalToolKind.Executable,
        ["wasm-validate" + Exe], ["--version"], 0, "oracle for the WebAssembly validator in tests", true,
        Ops(("validate", ["--enable-threads", "{module}"])));

    // Hermes's own dump tool; one build reads one bytecode version, so the variable may name a folder of builds (tests try each)
    public static readonly ExternalTool HbcDisassembler = new("hbcdump", "hbcdump, Hermes (test oracle)", "CORVUS_HBC_DISASSEMBLER", ExternalToolKind.Executable,
        ["hbcdump" + Exe], ["-version"], 0, "oracle for the Hermes bytecode disassembler in tests", true,
        Ops(("objdump", ["-objdump-disassemble", "-c", "disassemble;quit", "{file}"])));

    // Offline only: it matches against databases the user downloaded and never fetches them.
    public static readonly ExternalTool OsvScanner = new("osv-scanner", "osv-scanner 2+ (OSV advisories, offline)", "CORVUS_OSV_SCANNER", ExternalToolKind.Executable,
        ["osv-scanner" + Exe], ["--version"], 2, "summarize_file view=dependencies advisories", false,
        Ops(("scan", ["scan", "source", "--offline", "--format", "json", "-L", "{file}"])));

    // The freeze file and result formats are capa's own and change between releases: 10.0.0 is the version tested.
    public static readonly ExternalTool Capa = new("capa", "capa (standalone, rules built in)", "CORVUS_CAPA", ExternalToolKind.Executable,
        ["capa" + Exe], ["--version"], 0, "survey_features category=capa and analyze_native_function labels", false,
        Ops(("freeze", ["-j", "{file}"]), ("analyze", ["-j", "{file}"])));

    // Tested with speakeasy 2.0.0b9 (report format 5); it prints no version, so the report's format is checked instead.
    // Unknown functions stop the run rather than return a guessed 1, and region contents are saved for the region set.
    public static readonly ExternalTool Emulator = new("emulator", "speakeasy 2.0.0b9 (Windows API emulator)", "CORVUS_EMULATOR", ExternalToolKind.Executable,
        ["speakeasy" + Exe], [], 0, "emulate_native engine=speakeasy (a whole program or raw code)", false,
        Ops(("run", ["-t", "{input}", "--no-mp", "--snapshot-memory-regions", "--no-modules-functions-always-exist", "--timeout", "{seconds}",
                "--max-api-count", "{apis}", "--max-instructions", "{instructions}"]),
            ("raw", ["--raw", "--raw-offset", "{offset}", "--arch", "{arch}"]),
            ("entry", ["--entry-point", "{rva}"]),
            ("report", ["-o", "{report}"])));

    // Tested with GuardDog 3.2.0 on Linux; its rule engine and sandbox do not build on Windows.
    public static readonly ExternalTool GuardDog = new("guarddog", "GuardDog", "CORVUS_GUARDDOG", ExternalToolKind.Executable,
        ["guarddog" + Exe], ["--version"], 3, "summarize_file view=package rules", false,
        Ops(("scan", ["{ecosystem}", "scan", "{file}", "--output-format=json"])));

    // Dart 3.13.7 and 3.0.7 to 3.12.2 tested; --save-debugging-info alone also turns on DWARF stack traces, which drop most Function
    // objects.
    public static readonly ExternalTool DartSdk = new("dart", "Dart SDK (test oracle)", "CORVUS_DART", ExternalToolKind.Executable, ["dart" + Exe],
        ["--version"], 3, "oracle for the Dart AOT snapshot reader in tests", true,
        Ops(("aot", ["compile", "aot-snapshot", "-o", "{output}", "--extra-gen-snapshot-options=--save-debugging-info={debug}", "{source}"]),
            ("aot-split", ["compile", "aot-snapshot", "-o", "{output}", "--save-debugging-info={debug}", "{source}"])));

    // Flutter 3.47.8 (Dart 3.13.7) and 3.10.6 to 3.44.9 (CORVUS_FLUTTER_RELEASES) tested. CORVUS_FLUTTER names the SDK
    // folder; "kernel" runs in its dartaotruntime ("kernel-jit" in dart, before 3.16), "aot-elf" in the engine's
    // gen_snapshot for an Android release (x64, arm64), which compresses pointers.
    public static readonly ExternalTool FlutterSdk = new("flutter", "Flutter SDK (test oracle)", "CORVUS_FLUTTER", ExternalToolKind.Executable,
        ["bin/cache/dart-sdk/bin/dartaotruntime" + Exe], ["--version"], 3, "oracle for compressed-pointer Dart AOT snapshots in tests", true,
        Ops(("kernel", ["{root}/bin/cache/dart-sdk/bin/snapshots/frontend_server_aot.dart.snapshot", "--sdk-root",
                "{root}/bin/cache/artifacts/engine/common/flutter_patched_sdk_product/", "--target=flutter", "--aot", "--tfa", "-Ddart.vm.product=true",
                "--no-print-incremental-dependencies", "--output-dill", "{output}", "{source}"]),
            ("kernel-jit", ["{root}/bin/cache/dart-sdk/bin/snapshots/frontend_server.dart.snapshot", "--sdk-root",
                "{root}/bin/cache/artifacts/engine/common/flutter_patched_sdk_product/", "--target=flutter", "--aot", "--tfa", "-Ddart.vm.product=true",
                "--no-print-incremental-dependencies", "--output-dill", "{output}", "{source}"]),
            ("aot-elf", ["--deterministic", "--snapshot_kind=app-aot-elf", "--elf={output}", "--save-debugging-info={debug}", "{kernel}"])));

    // apple-codesign 0.29.0 tested; it prints each code requirement fully parenthesized, with every string quoted.
    public static readonly ExternalTool RCodesign = new("rcodesign", "rcodesign, apple-codesign (test oracle)", "CORVUS_RCODESIGN", ExternalToolKind.Executable,
        ["rcodesign" + Exe], ["--version"], 0, "oracle for Mach-O code requirements in tests", true, Ops(("signature", ["print-signature-info", "{file}"])));

    // 7-Zip 26.04 tested; -snl keeps symbolic links as links.
    public static readonly ExternalTool ArchiveLister = new("7z", "7-Zip (test oracle)", "CORVUS_ARCHIVE_LISTER", ExternalToolKind.Executable,
        ["7z" + Exe], ["i"], 0, "oracle for disk image and archive readers in tests", true, Ops(("extract", ["x", "-y", "-snl", "-sccUTF-8", "-o{output}", "{file}"])));

    // lzfse 1.0 (Apple's reference encoder, built from source) tested; it has no version option, so -h prints its usage.
    public static readonly ExternalTool LzfseTool = new("lzfse", "lzfse (test oracle)", "CORVUS_LZFSE", ExternalToolKind.Executable,
        ["lzfse" + Exe], ["-h"], 0, "oracle for the LZFSE decoder in tests", true, Ops(("encode", ["-encode", "-i", "{file}", "-o", "{output}"])));

    // carfile-go 0.8.0 tested (a CGO_ENABLED=0 build). json writes catalog.json, the renditions in tree order; png
    // (each bitmap) and resources (cropped images, originals) write a manifest.json naming each file's rendition index.
    public static readonly ExternalTool AssetCatalogReader = new("carfile", "carfile-go (test oracle)", "CORVUS_ASSET_CATALOG_READER", ExternalToolKind.Executable,
        ["carfile" + Exe], ["-v"], 0, "oracle for the asset catalog reader in tests", true,
        Ops(("json", ["-q", "-f", "json", "-o", "{output}", "{file}"]), ("png", ["-q", "-f", "png", "-o", "{output}", "{file}"]),
            ("resources", ["-q", "-f", "resources", "-o", "{output}", "{file}"])));

    // ark_disasm from the OpenHarmony 5.1.0 public SDK (toolchains package) tested. list writes the listing to {output}.
    public static readonly ExternalTool ArkDisassembler = new("ark_disasm", "ark_disasm, OpenHarmony SDK (test oracle)", "CORVUS_ARK_DISASSEMBLER", ExternalToolKind.Executable,
        ["ark_disasm" + Exe], ["--version"], 0, "oracle for the Ark bytecode disassembler in tests", true,
        Ops(("list", ["{file}", "{output}"])));

    // repak 0.2.3 tested. list and hashes print each path after the mount point (an empty -s strips nothing); hashes
    // prints the SHA-256 of each file's contents and fails on a pak with encrypted files.
    public static readonly ExternalTool PakTool = new("repak", "repak (test oracle)", "CORVUS_PAK_TOOL", ExternalToolKind.Executable,
        ["repak" + Exe], ["--version"], 0, "oracle for the Unreal pak reader in tests", true,
        Ops(("list", ["list", "-s", "", "{file}"]), ("hashes", ["hash-list", "-s", "", "{file}"])));

    // UndertaleModCli 0.9.2.0 tested. dump writes strings.txt, CodeEntries/<name>.gml and EmbeddedTextures/*.png under
    // {output}.
    public static readonly ExternalTool GameMakerTool = new("UndertaleModCli", "UndertaleModCli (test oracle)", "CORVUS_GAMEMAKER_TOOL", ExternalToolKind.Executable,
        ["UndertaleModCli" + Exe], ["--version"], 0, "oracle for the GameMaker data file reader in tests", true,
        Ops(("dump", ["dump", "{file}", "-o", "{output}", "-s", "-t", "-c", "UMT_DUMP_ALL"])));

    /// <summary>Every external program, in display order.</summary>
    public static readonly IReadOnlyList<ExternalTool> Table = [Java, JavaDecompiler, JavaDecompiler2, PythonDecompiler, Adb, TShark, OsvScanner, GuardDog, Emulator, Capa, Aapt2, ApkSigner, DexDisassembler, ProtoCompiler, WasmText, WasmValidator, HbcDisassembler, DartSdk, FlutterSdk, RCodesign, ArchiveLister, LzfseTool, AssetCatalogReader, ArkDisassembler, PakTool, GameMakerTool];

    private static IEnumerable<(string, string)> WiresharkDirectories()
    {
        if (OperatingSystem.IsWindows())
            foreach (var root in new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) })
                if (root.Length > 0) yield return (System.IO.Path.Combine(root, "Wireshark"), "default Wireshark location");
        if (OperatingSystem.IsMacOS()) yield return ("/Applications/Wireshark.app/Contents/MacOS", "default Wireshark location");
    }

    public static ExternalTool Get(string id) => Table.Single(t => t.Id == id);

    /// <summary>The option strings of <paramref name="op"/> with placeholders filled (also inside an option, -e={jar}); an unknown placeholder stays as written.</summary>
    public static List<string> Arguments(ExternalTool tool, string op, params (string Name, string Value)[] values)
    {
        var map = values.ToDictionary(v => "{" + v.Name + "}", v => v.Value, StringComparer.Ordinal);
        return [.. tool.Options[op].Select(a => map.TryGetValue(a, out var whole) ? whole
            : map.Aggregate(a, (text, p) => text.Replace(p.Key, p.Value, StringComparison.Ordinal)))];
    }

    private static IEnumerable<(string, string)> AndroidSdkDirectories()
    {
        foreach (var variable in new[] { "ANDROID_HOME", "ANDROID_SDK_ROOT" })
            if (ReadVariable(variable) is { Length: > 0 } sdk) yield return (System.IO.Path.Combine(sdk, "platform-tools"), variable);
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (OperatingSystem.IsWindows() && local.Length > 0) yield return (System.IO.Path.Combine(local, "Android", "Sdk", "platform-tools"), "default SDK location");
        else if (OperatingSystem.IsMacOS() && home.Length > 0) yield return (System.IO.Path.Combine(home, "Library", "Android", "sdk", "platform-tools"), "default SDK location");
        else if (home.Length > 0) yield return (System.IO.Path.Combine(home, "Android", "Sdk", "platform-tools"), "default SDK location");
    }

    /// <summary>The tool's file: the variable (a file, or a folder holding one of <see cref="ExternalTool.Files"/>), known folders, then PATH.</summary>
    public static (string Path, string Source)? Locate(ExternalTool tool)
    {
        if (ReadVariable(tool.Variable) is { Length: > 0 } configured)
        {
            configured = configured.Trim().Trim('"');
            if (File.Exists(configured)) return (System.IO.Path.GetFullPath(configured), tool.Variable);
            if (Directory.Exists(configured) && InDirectory(tool, configured) is { } inside) return (inside, tool.Variable);
            return null; // a variable that names nothing usable is not silently replaced by another copy
        }
        var path = tool.Kind == ExternalToolKind.Executable
            ? (ReadVariable("PATH") ?? "").Split(System.IO.Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries).Select(d => (d.Trim('"'), "PATH"))
            : [];
        var known = tool.KnownDirectories();
        foreach (var (dir, source) in tool.KnownDirectoriesFirst ? known.Concat(path) : path.Concat(known))
            if (InDirectory(tool, dir) is { } found) return (found, source);
        return null;
    }

    private static string? InDirectory(ExternalTool tool, string dir)
    {
        try
        {
            if (!Directory.Exists(dir)) return null;
            foreach (var pattern in tool.Files)
                if (pattern.Contains('*', StringComparison.Ordinal))
                {
                    if (Directory.EnumerateFiles(dir, pattern).Order(StringComparer.Ordinal).LastOrDefault() is { } match) return System.IO.Path.GetFullPath(match);
                }
                else if (File.Exists(System.IO.Path.Combine(dir, pattern))) return System.IO.Path.GetFullPath(System.IO.Path.Combine(dir, pattern));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { }
        return null;
    }

    public static string Remediation(ExternalTool tool) => tool.Kind == ExternalToolKind.Jar
        ? $"set {tool.Variable} to the jar or its folder (run by {Java.Variable}, JAVA_HOME or PATH java)"
        : $"set {tool.Variable} (the program or its folder) or PATH";

    /// <summary>How long a version check may take; tests shorten it.</summary>
    internal static TimeSpan VersionTimeout { get; set; } = TimeSpan.FromSeconds(15);

    // Lazy, so callers that race for one file share a single version check
    // rather than each running the program.
    private static readonly ConcurrentDictionary<string, Lazy<ExternalToolProbe>> Probes = new(StringComparer.Ordinal);

    /// <summary>The problem of a probe that found the tool neither through its variable nor on PATH.</summary>
    public const string NotFound = "not found";

    /// <summary>Where the tool is and its version, probed once per file per server process.</summary>
    public static ExternalToolProbe Probe(ExternalTool tool)
    {
        var located = Locate(tool);
        if (located is not { } at)
        {
            var configured = ReadVariable(tool.Variable);
            var why = configured is { Length: > 0 }
                ? $"{tool.Variable} is set to '{configured.Trim()}', which is not {(tool.Kind == ExternalToolKind.Jar ? "a jar or a folder with one" : "the program or a folder with it")}"
                : NotFound;
            return new(tool.Id, tool.Name, tool.Purpose, false, null, null, null, why, Remediation(tool));
        }
        var key = tool.Id + "|" + at.Path + "|" + Stamp(at.Path);
        var probe = Probes.GetOrAdd(key, _ => new(() => VersionProbe(tool, at.Path, at.Source))).Value;
        // A timed-out check is not kept, so the next call reads the version again.
        if (probe.VersionUnknown != null) Probes.TryRemove(key, out _);
        return probe;
    }

    /// <summary>
    /// <see cref="Probe(ExternalTool)"/> bounded by <paramref name="wait"/>: a version check still running then is reported
    /// usable with its version unknown, and finishes for the next call.
    /// </summary>
    public static ExternalToolProbe Probe(ExternalTool tool, TimeSpan wait)
    {
        // Without version arguments nothing runs, so there is no check to report as running.
        if (tool.VersionArguments.Length == 0) return Probe(tool);
        // A thread of its own for the same reason as SessionTools.OwnThread.
        var probe = Task.Factory.StartNew(() => Probe(tool), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        if (((IAsyncResult)probe).AsyncWaitHandle.WaitOne(wait) || Locate(tool) is not { } at) return probe.GetAwaiter().GetResult();
        return new(tool.Id, tool.Name, tool.Purpose, true, at.Path, at.Source, null, null, Remediation(tool)) { VersionUnknown = StillRunning };
    }

    /// <summary>How long server_status waits for a check (engines and external programs); tests shorten it.</summary>
    internal static TimeSpan StatusWait { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>The unknown-version note of a check still running when a bounded probe stopped waiting.</summary>
    public const string StillRunning = "check running; call server_status again";

    private static string Stamp(string path)
    {
        try { return File.GetLastWriteTimeUtc(path).Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return "?"; }
    }

    private static ExternalToolProbe VersionProbe(ExternalTool tool, string path, string source)
    {
        if (tool.VersionArguments.Length == 0) return new(tool.Id, tool.Name, tool.Purpose, true, path, source, VersionFromName(path), null, Remediation(tool));
        var (exe, args) = tool.Kind == ExternalToolKind.Jar
            ? Probe(Java) is { Usable: true, Path: { } java } ? (java, Arguments(Java, "jar", ("jar", path)).Concat(tool.VersionArguments).ToList()) : ((string?)null, (List<string>)[])
            : (path, tool.VersionArguments.ToList());
        if (exe == null) return new(tool.Id, tool.Name, tool.Purpose, true, path, source, null, "no usable Java to run it", $"set {Java.Variable} or JAVA_HOME to a JDK 17+");
        var run = Run(exe, args, VersionTimeout, 64 * 1024, CancellationToken.None);
        if (run.StartError != null) return new(tool.Id, tool.Name, tool.Purpose, true, path, source, null, $"cannot be started: {run.StartError}", Remediation(tool));
        // A slow version check on a busy machine says nothing against the tool: it stays usable, its version unknown.
        if (run.TimedOut)
            return new(tool.Id, tool.Name, tool.Purpose, true, path, source, null, null, Remediation(tool)) { VersionUnknown = $"check timed out after {(VersionTimeout < TimeSpan.FromSeconds(1) ? $"{VersionTimeout.TotalMilliseconds:0} ms" : $"{VersionTimeout.TotalSeconds:0} s")}" };
        var version = VersionPattern().Match(run.Text + "\n" + run.Stderr) is { Success: true } m ? m.Value : null;
        string? problem = null;
        if (tool.MinimumMajorVersion > 0)
        {
            var major = version == null ? 0 : int.Parse(version.Split('.')[0], System.Globalization.CultureInfo.InvariantCulture);
            if (major == 1 && version!.Split('.') is [_, var legacy, ..]) major = int.Parse(legacy, System.Globalization.CultureInfo.InvariantCulture); // 1.8 means 8
            if (major < tool.MinimumMajorVersion) problem = $"version {version ?? "unknown"}; {tool.MinimumMajorVersion} or newer is required";
        }
        return new(tool.Id, tool.Name, tool.Purpose, true, path, source, version, problem, Remediation(tool));
    }

    private static string? VersionFromName(string path) => VersionPattern().Match(System.IO.Path.GetFileNameWithoutExtension(path)) is { Success: true } m ? m.Value : null;

    [GeneratedRegex(@"\d+(\.\d+)+")]
    private static partial Regex VersionPattern();

    /// <summary>Variables a child keeps; everything else is removed (credentials and tokens in the server's environment stay out).</summary>
    private static readonly string[] KeptVariables =
    [
        "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "SYSTEMDRIVE", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "LOCALAPPDATA",
        "APPDATA", "LANG", "LC_ALL", "JAVA_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT", "ANDROID_SERIAL", "ANDROID_ADB_SERVER_PORT",
        "ANDROID_ADB_SERVER_ADDRESS",
    ];

    /// <summary>
    /// The overrides that reduce the server's environment to <see cref="KeptVariables"/> and ADB_* (null removes), then
    /// the kept <see cref="ChildVariables"/>, then <paramref name="extra"/>.
    /// </summary>
    public static Dictionary<string, string?> MinimalEnvironment(IReadOnlyDictionary<string, string?>? extra = null)
    {
        var result = new Dictionary<string, string?>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables())
        {
            var name = (string)e.Key;
            if (!Kept(name)) result[name] = null;
        }
        foreach (var (k, v) in KeptChildVariables()) result[k] = v;
        foreach (var (k, v) in extra ?? new Dictionary<string, string?>()) result[k] = v;
        return result;
    }

    public sealed record RunResult(int? ExitCode, byte[] Output, string Stderr, bool TimedOut, bool Truncated, string? StartError)
    {
        public string Text => Encoding.UTF8.GetString(Output);
    }

    /// <summary>
    /// Runs a program to completion in its own job with a minimal environment. Stdout is kept up to <paramref name="maxOutputBytes"/>;
    /// past that the tree is stopped and <see cref="RunResult.Truncated"/> set. Cancellation and the timeout stop the tree too.
    /// With <paramref name="sink"/>, stdout streams there instead (same budget) and <see cref="RunResult.Output"/> is empty.
    /// </summary>
    public static RunResult Run(string exe, IReadOnlyList<string> args, TimeSpan timeout, long maxOutputBytes, CancellationToken ct,
        IReadOnlyDictionary<string, string?>? environment = null, string? workingDirectory = null, Stream? sink = null)
    {
        ChildProcess child;
        try
        {
            child = ChildProcess.Start(new ChildProcessStart(exe, args) { Environment = MinimalEnvironment(environment), WorkingDirectory = workingDirectory });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return new RunResult(null, [], "", false, false, ex.Message);
        }
        using (child)
        {
            child.StandardInput.Dispose();
            bool truncated = false;
            var watch = System.Diagnostics.Stopwatch.StartNew();
            byte[] stdout = [];
            string stderr = "";
            Thread[] readers = [ChildProcess.StartReader(() =>
            {
                var buffer = new MemoryStream();
                var target = sink ?? buffer;
                var chunk = new byte[64 * 1024];
                long written = 0;
                try
                {
                    int n;
                    while ((n = child.StandardOutput.Read(chunk, 0, chunk.Length)) > 0)
                    {
                        int keep = (int)Math.Min(n, Math.Max(0, maxOutputBytes - written));
                        target.Write(chunk, 0, keep);
                        written += keep;
                        if (keep < n) { truncated = true; child.Kill(); break; }
                    }
                }
                catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
                stdout = buffer.ToArray();
            }), ChildProcess.StartReader(() =>
            {
                try
                {
                    using var r = new StreamReader(child.StandardError, new UTF8Encoding(false), false, 4096, leaveOpen: true);
                    var text = new StringBuilder();
                    var block = new char[4096];
                    int n;
                    while ((n = r.Read(block, 0, block.Length)) > 0)
                        if (text.Length < 256 * 1024) text.Append(block, 0, n);
                    stderr = text.ToString();
                }
                catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
            })];
            bool exited, timedOut;
            try
            {
                exited = child.Exited.Wait(timeout, ct);
                timedOut = !exited;
            }
            catch (OperationCanceledException) { exited = timedOut = false; }
            // A tree still holding the output at the deadline is stopped, which ends it.
            if (!exited || !ChildProcess.JoinReaders(readers, watch, timeout)) child.Kill();
            ChildProcess.JoinReaders(readers, System.Diagnostics.Stopwatch.StartNew(), TimeSpan.FromSeconds(5));
            ct.ThrowIfCancellationRequested();
            return new RunResult(child.ExitCode, stdout, stderr, timedOut, truncated, null);
        }
    }

    /// <summary>The program and arguments that start <paramref name="path"/>: a jar through Java, else the program itself; null without a usable Java.</summary>
    public static (string Exe, List<string> Args)? Command(ExternalTool tool, string path, IEnumerable<string> args) =>
        tool.Kind == ExternalToolKind.Jar || path.EndsWith(".jar", StringComparison.OrdinalIgnoreCase)
            ? Probe(Java) is { Usable: true, Path: { } java } ? (java, [.. Arguments(Java, "jar", ("jar", path)), .. args]) : null
            : (path, [.. args]);
}
