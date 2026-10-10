using System.ComponentModel;
using dnlib.DotNet;
using dnlib.DotNet.MD;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Linking;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Checks P/Invoke declarations ([DllImport] / ImplMap rows) against the exports of the native DLLs they bind to,
/// with the Windows runtime's lookup rules: DLL search order, API set redirection, A/W suffixes, x86 stdcall
/// decoration (_Name@N with N computed from the signature), ordinals and export forwarders. DLL location and
/// forwarders follow <see cref="NativeLinker"/>, which the cross-image navigation uses as well. Each declaration gets
/// a verdict (verified / contradicted / unresolved / dynamic_only / not_checked) with a reason code; run-time loading
/// found in the IL (<see cref="DynamicNativeLoads"/>) turns unresolved declarations into dynamic_only, and malformed
/// ImplMap / ModuleRef rows are reported with their location instead of being read as empty names.
/// </summary>
public sealed class NativeImportVerifier
{
    public sealed record Check(
        string Method,
        [property: Description("Metadata token of the method.")] string Token,
        string Module, string EntryPoint, string CharSet, bool ExactSpelling, string CallingConvention,
        [property: Description("verified, contradicted, unresolved, dynamic_only or not_checked.")] string Status,
        [property: Description("Why: verified -> exact, suffixed (A/W), decorated (stdcall _Name@N), forwarded, ordinal; contradicted -> missing_export, " +
                               "missing_ordinal, bad_ordinal, exact_spelling, ordinal_points_elsewhere, forwarder_broken; unresolved -> dll_not_found, " +
                               "api_set_unmapped, not_an_image, not_windows, forwarder_dll_not_found, malformed_metadata; dynamic_only -> " +
                               "library_loaded_at_run_time, dll_import_resolver; not_checked -> runtime_internal, runtime_library.")] string Reason,
        string? ResolvedFile, string? Export, string Detail,
        [property: Description("Where malformed metadata was found (stream, table, row, token, file offset), else null.")] string? Location);

    public sealed record Result(List<Check> Checks, List<DynamicNativeLoad> DynamicLoads, bool DynamicTruncated, List<MetadataIssue> MetadataIssues);

    public const string Verified = "verified", Contradicted = "contradicted", Unresolved = "unresolved", DynamicOnly = "dynamic_only", NotChecked = "not_checked";

    public static readonly string[] Statuses = [Verified, Contradicted, Unresolved, DynamicOnly, NotChecked];

    private readonly NativeLinker _linker;

    public NativeImportVerifier(Func<string, INativeImage> open) => _linker = new NativeLinker(Cached(open));

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

    public Result Verify(LoadedAssembly asm, CancellationToken ct)
    {
        var issues = MetadataSurvey.Survey(asm.OriginalBytes).ToList();
        var rowIssues = MetadataSurvey.ImplMapRows(asm.Module);
        issues.AddRange(rowIssues.Values);
        var (dynamic, truncated) = DynamicNativeLoads.Find(asm.Module, ct);
        var resolvers = dynamic.Where(d => d.Kind == "dll_import_resolver").Select(d => d.Method).Distinct().ToList();
        var loadedLibraries = dynamic.Where(d => d.Library != null && d.Kind is "native_library_load" or "load_library")
            .GroupBy(d => DynamicNativeLoads.NormalizeLibrary(d.Library!)).ToDictionary(g => g.Key, g => g.First());

        var checks = new List<Check>();
        bool x86 = IsX86(asm.Module);
        foreach (var type in asm.Module.GetTypes())
            foreach (var method in type.Methods)
            {
                ct.ThrowIfCancellationRequested();
                if (method.ImplMap is not { } map) continue;
                var check = rowIssues.TryGetValue(map.Rid, out var issue)
                    ? Malformed(method, map, issue)
                    : CheckOne(asm, method, map, x86);
                checks.Add(Dynamic(check, resolvers, loadedLibraries));
            }
        return new Result(checks, dynamic, truncated, issues);
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
        if (!OperatingSystem.IsWindows()) return Result(Unresolved, "not_windows", null, null, "DLL lookup is checked on Windows hosts only");

        var (file, searched) = _linker.Locate(module, asm.FilePath, x86, runtimeFolder: true);
        if (file == null)
            return IsRuntimeLibrary(module)
                ? Result(NotChecked, "runtime_library", null, null, "a .NET runtime native library that the runtime links in on this platform (no separate DLL)")
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
                var link = _linker.Bind(module, asm.FilePath, x86, candidate, null, "pinvoke", runtimeFolder: true);
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
