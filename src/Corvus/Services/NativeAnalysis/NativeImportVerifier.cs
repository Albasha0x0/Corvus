using System.ComponentModel;
using dnlib.DotNet;
using dnlib.DotNet.MD;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Itanium;
using Corvus.Native.Linking;

namespace Corvus.Services;

/// <summary>
/// Checks P/Invoke declarations ([DllImport] / ImplMap rows) against the exports of the native DLLs they bind to,
/// with the Windows runtime's lookup rules: DLL search order, API set redirection, A/W suffixes, x86 stdcall
/// decoration (_Name@N with N computed from the signature), ordinals and export forwarders. DLL location and
/// forwarders follow <see cref="NativeLinker"/>, which the cross-image navigation uses as well. Each declaration gets
/// a verdict (verified / contradicted / unresolved / dynamic_only / not_checked) with a reason code; run-time loading
/// found in the IL (<see cref="DynamicNativeLoads"/>) turns unresolved declarations into dynamic_only, and malformed
/// ImplMap / ModuleRef rows are reported with their location instead of being read as empty names. Off Windows targets
/// (the platform the app ships for, see <see cref="UnixProbing"/>) .so / .dylib libraries are probed as .NET does and
/// matched against ELF dynamic symbols and Mach-O exports; __Internal binds to an Il2Cpp game's own binary.
/// </summary>
public sealed class NativeImportVerifier
{
    public sealed record Check(
        string Method,
        [property: Description("Metadata token of the method.")] string Token,
        string Module, string EntryPoint, string CharSet, bool ExactSpelling, string CallingConvention,
        [property: Description("verified, contradicted, unresolved, dynamic_only or not_checked.")] string Status,
        [property: Description("Why: verified -> exact, suffixed (A/W), decorated (stdcall _Name@N), forwarded, ordinal, versioned, internal; contradicted -> missing_export, " +
                               "missing_ordinal, bad_ordinal, exact_spelling, ordinal_points_elsewhere, forwarder_broken, arch_mismatch, mangled_only; unresolved -> dll_not_found, " +
                               "api_set_unmapped, not_an_image, system_dll_not_on_host, forwarder_dll_not_found, forwarded_unverified, wrong_platform, malformed_metadata; dynamic_only -> " +
                               "library_loaded_at_run_time, dll_import_resolver; not_checked -> runtime_internal, runtime_library; Mach-O: resolved, version_too_old, system_library, weak_library_absent.")] string Reason,
        string? ResolvedFile, string? Export, string Detail,
        [property: Description("Where malformed metadata was found (stream, table, row, token, file offset), else null.")] string? Location);

    public sealed record Result(List<Check> Checks, List<DynamicNativeLoad> DynamicLoads, bool DynamicTruncated, List<MetadataIssue> MetadataIssues)
    {
        public TargetPlatform Platform { get; init; } = new("windows", null, "default");
    }

    public const string Verified = "verified", Contradicted = "contradicted", Unresolved = "unresolved", DynamicOnly = "dynamic_only", NotChecked = "not_checked";

    public static readonly string[] Statuses = [Verified, Contradicted, Unresolved, DynamicOnly, NotChecked];

    private readonly NativeLinker _linker;
    private readonly bool _systemDlls;
    private readonly Func<string, INativeImage?> _open;

    public NativeImportVerifier(Func<string, INativeImage> open) : this(open, OperatingSystem.IsWindows()) { }

    /// <param name="open">Opens a native image.</param>
    /// <param name="hostHasSystemDlls">
    /// False off Windows: only DLLs next to the assembly (and loaded images) are checked, and declarations bound to Windows
    /// system DLLs are unresolved with reason system_dll_not_on_host.
    /// </param>
    public NativeImportVerifier(Func<string, INativeImage> open, bool hostHasSystemDlls)
    {
        _open = Cached(open);
        _linker = new NativeLinker(_open);
        _systemDlls = hostHasSystemDlls;
    }

    /// <summary>DLLs that ship with Windows; API set contracts (api-ms-*, ext-ms-*) count as well.</summary>
    private static readonly HashSet<string> SystemDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "kernel32", "kernelbase", "ntdll", "user32", "gdi32", "gdiplus", "advapi32", "shell32", "shlwapi", "shcore", "ole32", "oleaut32",
        "oleacc", "combase", "comctl32", "comdlg32", "ws2_32", "wsock32", "winmm", "version", "crypt32", "bcrypt", "ncrypt", "secur32",
        "sspicli", "wintrust", "credui", "dbghelp", "psapi", "iphlpapi", "setupapi", "cfgmgr32", "wininet", "winhttp", "urlmon", "rpcrt4",
        "userenv", "wtsapi32", "netapi32", "mpr", "imm32", "uxtheme", "dwmapi", "propsys", "powrprof", "hid", "winusb", "winspool",
        "d3d9", "d3d11", "d3d12", "dxgi", "d2d1", "dwrite", "opengl32", "glu32", "msvcrt", "ucrtbase", "mscoree", "msi", "avrt", "mf",
        "mfplat", "mfreadwrite", "dnsapi", "fwpuclnt", "authz", "wevtapi", "pdh", "tdh", "winscard", "xinput1_4", "xinput9_1_0",
    };

    internal static bool IsSystemDll(string module)
    {
        var name = Path.GetFileName(module.Trim());
        if (ApiSetSchema.IsApiSetName(name)) return true;
        foreach (var extension in new[] { ".dll", ".drv" })
            if (name.EndsWith(extension, StringComparison.OrdinalIgnoreCase)) name = name[..^extension.Length];
        return SystemDlls.Contains(name);
    }

    /// <summary>Each file opened once per verifier; unreadable files are remembered as null.</summary>
    private static Func<string, INativeImage?> Cached(Func<string, INativeImage> open)
    {
        var images = new Dictionary<string, INativeImage?>(StringComparer.OrdinalIgnoreCase);
        return file =>
        {
            if (images.TryGetValue(file, out var image)) return image;
            try { image = open(file); }
            catch (Exception ex) when (ex is ToolError or IOException or UnauthorizedAccessException) { image = null; }
            return images[file] = image;
        };
    }

    /// <param name="platform">auto, windows, linux, osx, android or ios (see <see cref="UnixProbing.Detect"/>).</param>
    public Result Verify(LoadedAssembly asm, CancellationToken ct, string? platform = null) => Verify(asm, ct, platform, null, null);

    /// <param name="workspace">When given, the assembly is read in short shared-lock sections (call without holding the lock).</param>
    /// <param name="progress">(done, total, message): per library checked.</param>
    public Result Verify(LoadedAssembly asm, CancellationToken ct, string? platform, AssemblyWorkspace? workspace, Action<int, int, string>? progress)
    {
        void Each<T>(IReadOnlyList<T> items, Func<T, bool> visit)
        {
            if (workspace != null) workspace.ReadEach(asm, items, visit, ct);
            else
                foreach (var item in items)
                {
                    ct.ThrowIfCancellationRequested();
                    if (!visit(item)) break;
                }
        }
        T Locked<T>(Func<T> read) => workspace != null ? workspace.Read(read, ct) : read();

        var appDirectory = Path.GetDirectoryName(Path.GetFullPath(asm.FilePath))!;
        var game = Il2CppGame(appDirectory);
        var target = UnixProbing.Detect(appDirectory, platform, game?.Platform);
        var issues = MetadataSurvey.Survey(asm.OriginalBytes).ToList();
        var (rowIssues, types, x86) = Locked(() => (MetadataSurvey.ImplMapRows(asm.Module), asm.Module.GetTypes().ToList(), IsX86(asm.Module)));
        issues.AddRange(rowIssues.Values);
        progress?.Invoke(0, 1, "scanning IL for run-time native loading");
        var (dynamic, truncated) = DynamicNativeLoads.Find(types, Each);
        var resolvers = dynamic.Where(d => d.Kind == "dll_import_resolver").Select(d => d.Method).Distinct().ToList();
        var loadedLibraries = dynamic.Where(d => d.Library != null && d.Kind is "native_library_load" or "load_library")
            .GroupBy(d => DynamicNativeLoads.NormalizeLibrary(d.Library!)).ToDictionary(g => g.Key, g => g.First());

        var declarations = new List<MethodDef>();
        Each(types, type =>
        {
            foreach (var method in type.Methods)
                if (method.ImplMap != null) declarations.Add(method);
            return true;
        });
        // One library at a time, in declaration order within it.
        var libraries = declarations.GroupBy(m => m.ImplMap.Module?.Name?.String ?? "", StringComparer.OrdinalIgnoreCase).ToList();
        var checks = new List<Check>();
        for (int i = 0; i < libraries.Count; i++)
        {
            progress?.Invoke(i, libraries.Count, $"checking {(libraries[i].Key.Length > 0 ? libraries[i].Key : "(no module)")} ({libraries[i].Count()} declarations)");
            Each(libraries[i].ToList(), method =>
            {
                if (method.ImplMap is not { } map) return true; // removed by an edit meanwhile
                var check = rowIssues.TryGetValue(map.Rid, out var issue) ? Malformed(method, map, issue)
                    : target.IsWindows ? CheckOne(asm, method, map, x86)
                    : CheckUnix(method, map, appDirectory, target, game);
                checks.Add(Dynamic(check, resolvers, loadedLibraries));
                return true;
            });
        }
        progress?.Invoke(libraries.Count, libraries.Count, $"{checks.Count} declarations checked");
        return new Result(checks, dynamic, truncated, issues) { Platform = target };
    }

    /// <summary>An Il2Cpp game whose dummy assemblies are in <paramref name="directory"/>: its binary (for __Internal), platform and library folders.</summary>
    private sealed record GameBinary(string File, TargetPlatform Platform, List<string> Folders);

    private GameBinary? Il2CppGame(string directory)
    {
        if (Il2CppDumpFiles.Locate(directory)?.GameAssembly is not { } binary || _open(binary) is not { } image) return null;
        var folder = Path.GetDirectoryName(binary)!;
        string arch = image.Arch switch { NativeArch.Arm64 => "arm64", NativeArch.Arm => "arm", NativeArch.X64 => "x64", NativeArch.X86 => "x86", _ => "" };
        string os = image.Format switch
        {
            ImageFormat.Elf => Path.GetFileName(binary) == "libil2cpp.so" ? "android" : "linux",
            ImageFormat.MachO => Path.GetFileName(binary) == "UnityFramework" ? "ios" : "osx",
            _ => "windows",
        };
        var folders = new List<string> { folder };
        // iOS: UnityFramework.framework sits in the app's Frameworks folder beside the other frameworks.
        if (os == "ios" && Path.GetDirectoryName(folder) is { } frameworks) folders.Add(frameworks);
        return new GameBinary(binary, new TargetPlatform(os, arch.Length > 0 ? $"{os}-{arch}" : null, $"Il2Cpp game binary {Path.GetFileName(binary)}"), folders);
    }

    /// <summary>A declaration checked against .so / .dylib libraries with the .NET probing rules of a Unix target.</summary>
    private Check CheckUnix(MethodDef method, ImplMap map, string appDirectory, TargetPlatform target, GameBinary? game)
    {
        string label = Format.MemberLabel(method);
        var (module, entry, charSet, callConv) = Describe(method, map);
        Check Result(string status, string reason, string? file, string? export, string detail) =>
            new(label, $"0x{method.MDToken.Raw:X8}", module, entry, charSet, map.IsNoMangle, callConv, status, reason, file, export, detail, null);

        if (module == "__Internal" && game != null && _open(game.File) is { } own)
        {
            var name = own.Format == ImageFormat.MachO ? "_" + entry : entry;
            return own.Exports.Any(e => e.Name == name) || own.Symbols.Any(s => s.Name == name && s.Kind == ImageSymbolKind.Function)
                ? Result(Verified, "internal", game.File, name, $"__Internal: defined in {Path.GetFileName(game.File)}, the game binary it is linked into")
                : Result(Contradicted, "missing_export", game.File, null, $"__Internal: {Path.GetFileName(game.File)} does not define it; {NativeLinker.NearMisses(own, name)}");
        }
        if (RuntimeResolved(module) is { } why) return Result(NotChecked, "runtime_internal", null, null, why);
        if (IsRuntimeLibrary(module))
            return Result(NotChecked, "runtime_library", null, null, "a .NET runtime native library that ships with the runtime on this platform");

        var (file, searched, other) = UnixProbing.Locate(module, appDirectory, target, game?.Folders);
        var tried = string.Join(", ", UnixProbing.ProbeNames(module, target));
        if (file == null)
            return other.Count > 0
                ? Result(Unresolved, "wrong_platform", null, null, $"shipped only for other platforms ({string.Join("; ", other.Take(6))}), not for {target.Rid ?? target.Os}")
                : UnixProbing.IsSystemLibrary(module)
                    ? Result(Unresolved, "system_dll_not_on_host", null, null, $"a {target.Os} system library, not shipped with the app; probed {tried}")
                : Result(Unresolved, "dll_not_found", null, null, $"probed {tried} in {string.Join("; ", searched)}");
        if (_open(file) is not { } image || image.Format == ImageFormat.Pe)
            return Result(Unresolved, "not_an_image", file, null, $"{file} is not a readable ELF or Mach-O library");
        if (target.Arch is { } arch && image.Arch != arch)
            return Result(Contradicted, "arch_mismatch", file, null, $"the library is {image.MachineName}, the app targets {target.Rid}");

        bool apple = image.Format == ImageFormat.MachO;
        var symbol = apple ? "_" + entry : entry;
        if (_linker.ExportNamed(image, symbol) is { } export)
        {
            if (export.ForwardedTo is { } forwarded)
            {
                int bang = forwarded.IndexOf('!');
                var library = Path.GetFileName(forwarded[..Math.Max(0, bang)]);
                var target2 = forwarded[(bang + 1)..];
                var (reexporter, _, _) = UnixProbing.Locate(library, Path.GetDirectoryName(file)!, target, [appDirectory]);
                if (reexporter != null && _open(reexporter) is { } next && _linker.ExportNamed(next, target2) is { ForwardedTo: null })
                    return Result(Verified, "forwarded", file, symbol, $"re-exported from {forwarded}");
                return Result(Unresolved, "forwarded_unverified", file, symbol, $"re-exported from {forwarded}, which " + (reexporter == null ? "the app does not ship" : "does not export it"));
            }
            var version = apple ? null : image.Symbols.FirstOrDefault(s => s.Name == entry && s.Version != null)?.Version;
            return version != null
                ? Result(Verified, "versioned", file, symbol, $"exported with version {version}")
                : Result(Verified, "exact", file, symbol, "exported");
        }
        // A C++ function exported under its mangled name only: the declaration must name the mangled form.
        foreach (var e in image.Exports)
            if (e.Name != null && ItaniumDemangler.IsMangled(e.Name, apple) && ItaniumDemangler.Demangle(e.Name, apple) is { } demangled
                && FunctionName(demangled) is var function && (function == entry || function.EndsWith("::" + entry, StringComparison.Ordinal)))
                return Result(Contradicted, "mangled_only", file, e.Name, $"exported only as the C++ name {e.Name} ({demangled}); EntryPoint must spell the mangled name");
        var detail = NativeLinker.NearMisses(image, symbol);
        if (ItaniumDemangler.Demangle(entry) is { } readable) detail += $"; the entry point is the C++ name {readable}";
        return Result(Contradicted, "missing_export", file, null, detail);
    }

    /// <summary>The qualified function name of a demangled signature: "ns::f(int)" -> "ns::f".</summary>
    private static string FunctionName(string demangled)
    {
        int paren = demangled.IndexOf('(');
        var head = paren > 0 ? demangled[..paren] : demangled;
        int space = head.LastIndexOf(' ');
        return space >= 0 && !head.Contains('<') ? head[(space + 1)..] : head;
    }

    /// <summary>An unresolved or contradicted verdict reconsidered in the light of run-time loading.</summary>
    private static Check Dynamic(Check check, List<string> resolvers, Dictionary<string, DynamicNativeLoad> loaded)
    {
        if (check.Status == Unresolved && check.Reason != "malformed_metadata")
        {
            if (check.Module.Length > 0 && loaded.TryGetValue(DynamicNativeLoads.NormalizeLibrary(check.Module), out var load))
                return check with { Status = DynamicOnly, Reason = "library_loaded_at_run_time",
                    Detail = $"not found statically ({check.Detail}); the assembly loads '{load.Library}' itself at run time ({load.Kind} in {load.Method})" };
            if (resolvers.Count > 0)
                return check with { Status = DynamicOnly, Reason = "dll_import_resolver",
                    Detail = $"not found statically ({check.Detail}); a DllImportResolver set in {resolvers[0]} decides at run time which library this binds to" };
        }
        if (check.Status == Contradicted && resolvers.Count > 0)
            return check with { Detail = check.Detail + $"; note: a DllImportResolver set in {resolvers[0]} may bind this declaration to another library at run time" };
        return check;
    }

    private static Check Malformed(MethodDef method, ImplMap map, MetadataIssue issue)
    {
        var (module, entry, charSet, callConv) = Describe(method, map);
        return new(Format.MemberLabel(method), $"0x{method.MDToken.Raw:X8}", module, entry, charSet, map.IsNoMangle, callConv, Unresolved, "malformed_metadata",
            null, null, $"{issue.Code}: {issue.Detail}; the runtime cannot bind this declaration as stored", $"{issue.Location}, file offset {issue.FileOffset}");
    }

    /// <summary>32-bit when the module requires it (x86, or AnyCPU with "prefer 32-bit").</summary>
    internal static bool IsX86(ModuleDef module) =>
        module.Machine == dnlib.PE.Machine.I386 && (module.Is32BitRequired || module.Is32BitPreferred);

    /// <summary>The declaration's module, entry point, character set and calling convention as the runtime reads them.</summary>
    internal static (string Module, string Entry, string CharSet, string CallConv) Describe(MethodDef method, ImplMap map) =>
        (map.Module?.Name?.String ?? "",
         map.Name?.String is { Length: > 0 } n ? n : method.Name.String,
         map.IsCharSetUnicode || map.IsCharSetAuto ? "Unicode" : map.IsCharSetAnsi ? "Ansi" : "None",
         map.IsCallConvCdecl ? "Cdecl" : map.IsCallConvStdcall ? "StdCall" : map.IsCallConvThiscall ? "ThisCall" : map.IsCallConvFastcall ? "FastCall" : "Winapi");

    /// <summary>Why a module is not looked up as a DLL (resolved by the runtime itself), or null.</summary>
    internal static string? RuntimeResolved(string module) =>
        module.Length == 0 ? "the ImplMap row names no module"
        : module is "QCall" or "__Internal" || module.StartsWith("libSystem.", StringComparison.Ordinal)
            ? "resolved by the runtime itself (QCall, __Internal or a runtime native library)"
        : null;

    private Check CheckOne(LoadedAssembly asm, MethodDef method, ImplMap map, bool x86)
    {
        string label = Format.MemberLabel(method);
        var (module, entry, charSet, callConv) = Describe(method, map);
        Check Result(string status, string reason, string? file, string? export, string detail) =>
            new(label, $"0x{method.MDToken.Raw:X8}", module, entry, charSet, map.IsNoMangle, callConv, status, reason, file, export, detail, null);

        if (RuntimeResolved(module) is { } why) return Result(NotChecked, "runtime_internal", null, null, why);

        var (file, searched) = _linker.Locate(module, asm.FilePath, x86, runtimeFolder: true);
        if (!_systemDlls)
            file = file != null && IsAppLocal(file, asm.FilePath, searched) ? file : AppLocalIgnoringCase(module, asm.FilePath);
        if (file == null)
            return IsRuntimeLibrary(module)
                ? Result(NotChecked, "runtime_library", null, null, "a .NET runtime native library that the runtime links in on this platform (no separate DLL)")
                : !_systemDlls && IsSystemDll(module)
                    ? Result(Unresolved, "system_dll_not_on_host", null, null, $"a Windows system DLL, and this host has none to check against; searched {string.Join("; ", searched)}")
                : Result(Unresolved, searched.Any(s => s.EndsWith("(not in this system's map)", StringComparison.Ordinal)) ? "api_set_unmapped" : "dll_not_found",
                    null, null, "searched " + string.Join("; ", searched));
        var image = _linker.Open(file);
        if (image == null) return Result(Unresolved, "not_an_image", file, null, $"{file} is not a readable PE image");

        int? stack = x86 && callConv is "StdCall" or "Winapi" ? StackBytes(method) : null;
        if (entry.StartsWith('#'))
        {
            if (!uint.TryParse(entry.AsSpan(1), out var ordinal)) return Result(Contradicted, "bad_ordinal", file, null, $"'{entry}' is not an ordinal");
            var byOrdinal = _linker.ExportByOrdinal(image, ordinal);
            if (byOrdinal == null) return Result(Contradicted, "missing_ordinal", file, null, $"no export with ordinal {ordinal}");
            // The method's own name exported under another ordinal: the ordinal binds to a different function.
            if (byOrdinal.Name is { } atOrdinal && !Candidates(method.Name.String, charSet, false, stack).Any(c => c.Name == atOrdinal)
                && Candidates(method.Name.String, charSet, false, stack).Select(c => _linker.ExportNamed(image, c.Name)).FirstOrDefault(e => e != null) is { } named
                && named.Ordinal != ordinal)
                return Result(Contradicted, "ordinal_points_elsewhere", file, atOrdinal,
                    $"ordinal {ordinal} is {atOrdinal}, but {named.Name} (the method's name) is ordinal {named.Ordinal}");
            return Result(Verified, "ordinal", file, byOrdinal.Name ?? entry, $"ordinal {ordinal}" + (byOrdinal.Name != null ? $" ({byOrdinal.Name})" : ""));
        }

        foreach (var (candidate, exact) in Candidates(entry, charSet, map.IsNoMangle, stack))
        {
            if (_linker.ExportNamed(image, candidate) is not { } export) continue;
            if (export.ForwardedTo != null)
            {
                int dot = export.ForwardedTo.LastIndexOf('.');
                if (!_systemDlls && dot > 0 && IsSystemDll(export.ForwardedTo[..dot]))
                    return Result(Unresolved, "system_dll_not_on_host", file, candidate,
                        $"{candidate} is forwarded to {export.ForwardedTo}, a Windows system DLL this host does not have");
                // From the file found above: locating the module again misses an app-local DLL matched ignoring case.
                var link = _linker.BindIn(module, file, x86, candidate, "pinvoke");
                if (link.IsResolved) return Result(Verified, "forwarded", file, candidate, $"forwarded: {link.Chain}");
                return link.Detail.Contains(": module not found", StringComparison.Ordinal)
                    ? Result(Unresolved, "forwarder_dll_not_found", file, candidate, $"forwarder target not found: {link.Chain}: {link.Detail}")
                    : Result(Contradicted, "forwarder_broken", file, candidate, $"forwarder does not resolve: {link.Chain}: {link.Detail}");
            }
            if (exact) return Result(Verified, "exact", file, candidate, "exported");
            return Result(Verified, candidate.StartsWith('_') && candidate.Contains('@') ? "decorated" : "suffixed", file, candidate, $"exported as {candidate}");
        }
        // ExactSpelling turns off the A/W and decorated forms; the DLL may only have those.
        if (map.IsNoMangle && Candidates(entry, charSet, false, stack).Select(c => c.Name).FirstOrDefault(c => c != entry && _linker.ExportNamed(image, c) != null) is { } other)
            return Result(Contradicted, "exact_spelling", file, null,
                $"ExactSpelling=true, so only '{entry}' is looked up, but the DLL exports it as {other}; {NativeLinker.NearMisses(image, entry)}");
        return Result(Contradicted, "missing_export", file, null, NativeLinker.NearMisses(image, entry));
    }

    /// <summary>Found next to the assembly or among the loaded images, not in a host folder.</summary>
    private static bool IsAppLocal(string file, string requester, List<string> searched) =>
        searched.LastOrDefault() == "loaded images"
        || string.Equals(Path.GetDirectoryName(Path.GetFullPath(file)), Path.GetDirectoryName(Path.GetFullPath(requester)), StringComparison.OrdinalIgnoreCase);

    /// <summary>The DLL next to the assembly matched without case, as the Windows loader matches it (for case-sensitive file systems).</summary>
    private static string? AppLocalIgnoringCase(string module, string requester)
    {
        var name = Path.GetFileName(module.Trim());
        if (name.Length == 0 || ApiSetSchema.IsApiSetName(name)) return null;
        if (!Path.HasExtension(name)) name += ".dll";
        try
        {
            return Path.GetDirectoryName(requester) is { Length: > 0 } dir
                ? Directory.EnumerateFiles(dir).FirstOrDefault(f => string.Equals(Path.GetFileName(f), name, StringComparison.OrdinalIgnoreCase))
                : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>System.*.Native libraries: shipped as separate files on some platforms, linked into the runtime on others.</summary>
    internal static bool IsRuntimeLibrary(string module) =>
        module.StartsWith("System.", StringComparison.Ordinal) && module.EndsWith(".Native", StringComparison.Ordinal);

    /// <summary>Export names the runtime tries, in order; Exact is false for suffixed or decorated forms.</summary>
    internal static IEnumerable<(string Name, bool Exact)> Candidates(string entry, string charSet, bool exactSpelling, int? stdcallBytes)
    {
        var names = new List<(string, bool)>();
        if (exactSpelling) names.Add((entry, true));
        else if (charSet == "Unicode") { names.Add((entry + "W", false)); names.Add((entry, true)); }
        else { names.Add((entry, true)); names.Add((entry + "A", false)); }
        if (stdcallBytes is { } bytes)
            foreach (var (name, _) in names.ToArray())
                names.Add(($"_{name}@{bytes}", false));
        return names;
    }

    /// <summary>Bytes of x86 stack arguments for stdcall decoration, or null when a parameter's size is unknown.</summary>
    internal static int? StackBytes(MethodDef method)
    {
        try
        {
            int total = 0;
            foreach (var p in method.Parameters)
            {
                if (p.IsHiddenThisParameter) continue;
                if (p.ParamDef?.MarshalType is { } marshal && marshal.NativeType is NativeType.Struct or NativeType.FixedArray or NativeType.SafeArray)
                    return null;
                var size = ArgumentSize(p.Type);
                if (size == null) return null;
                total += size.Value;
            }
            return total;
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { return null; } // unreadable signature
    }

    private static int? ArgumentSize(TypeSig type)
    {
        type = type.RemovePinnedAndModifiers();
        switch (type.ElementType)
        {
            case ElementType.I8: case ElementType.U8: case ElementType.R8:
                return 8;
            case ElementType.Boolean: case ElementType.Char: case ElementType.I1: case ElementType.U1: case ElementType.I2: case ElementType.U2:
            case ElementType.I4: case ElementType.U4: case ElementType.R4: case ElementType.I: case ElementType.U:
            case ElementType.Ptr: case ElementType.FnPtr: case ElementType.ByRef: case ElementType.String: case ElementType.Object:
            case ElementType.Class: case ElementType.SZArray: case ElementType.Array:
                return 4;
            case ElementType.ValueType:
                var def = type.ToTypeDefOrRef().ResolveTypeDef();
                if (def == null) return null;
                if (def.IsEnum) return def.GetEnumUnderlyingType() is { } underlying ? ArgumentSize(underlying) : null;
                // Structs by value need the marshaled layout; only explicit sizes are trusted.
                return def.ClassLayout is { ClassSize: > 0 } layout ? (int)((layout.ClassSize + 3) & ~3u) : null;
            default:
                return null;
        }
    }
}
