using System.ComponentModel;
using System.Globalization;
using System.Text;
using dnlib.DotNet;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Dump;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Crash text without a dump: Unity Player.log / error.log backtraces, Mono and Il2Cpp managed lines, .NET exception
/// text, WER Report.wer, Event Log 1000/1026 text and debugger stacks. Each frame is resolved against the loaded build
/// (native images through their code index and Il2Cpp names, managed frames by MVID or name) and checked for being
/// that build: time stamps, MVIDs, and the names the text gives against ours.
/// </summary>
public sealed class StackTextService(AssemblyWorkspace workspace, NativeCodeService? code = null, Il2CppNavigator? navigator = null, DecompilerService? decompiler = null)
{
    /// <summary>Managed frames per call whose IL offset is mapped to a C# statement (each decompiles its method once).</summary>
    public const int MaxStatements = 30;

    public const int MaxTextChars = 1 << 20;
    public const int MaxFileBytes = 8 << 20;
    public const int DefaultLimit = 200;
    private static readonly TimeSpan IndexWait = TimeSpan.FromSeconds(30);

    public sealed record InnerExceptionText(string Type, string? Message);

    public sealed record SymbolizedException(
        [property: Description("Native exception code (WER, Event Log), e.g. 0xC0000005.")] string? Code,
        [property: Description("Symbolic name of the code.")] string? Name,
        string? Type, string? Message,
        [property: Description("Inner exceptions, outermost first.")] IReadOnlyList<InnerExceptionText> Inner);

    public sealed record SymbolizedFrame(
        int Index,
        [property: Description("Line of the text (0 for a frame built from WER or Event Log fields).")] int Line,
        string Raw,
        [property: Description("native, managed or il2cpp.")] string Kind,
        string? Module, string? Offset, string? Address,
        [property: Description("Our name for the frame: function+0xoffset, or the managed method.")] string? Resolved,
        [property: Description("user, pdb, il2cpp, export, discovered, nearest_export, metadata, or none.")] string? Source,
        [property: Description("Id of the loaded native image the frame resolved in.")] string? Image,
        [property: Description("Id of the loaded assembly the method resolved in.")] string? Assembly,
        string? Token, int? IlOffset,
        [property: Description("The C# statement at the IL offset (decompiled with sequence points), when the frame's build matches.")] string? Statement,
        [property: Description("Which exception of the chain the frame belongs to: 0 the outermost.")] int? Exception,
        [property: Description("match (the same build: time stamp, MVID or the text's own name agree), mismatch (another build: do not trust the name), or unknown.")] string BuildCheck,
        string? BuildDetail,
        [property: Description("The call that continues from this frame.")] string? NextStep);

    public sealed record MissingModule(string Module, string? Version, string? TimeDateStamp,
        [property: Description("Frames in that module.")] int Frames);

    public sealed record SymbolizedStack(
        [property: Description("The format recognized (unity, dotnet, wer, eventlog, windbg, android), or the one requested.")] string Format,
        SymbolizedException? Exception,
        int Total, int Offset, bool Truncated, IReadOnlyList<SymbolizedFrame> Frames,
        [property: Description("Lines no format recognized (blank lines aside).")] int UnrecognizedLines,
        IReadOnlyList<string> UnrecognizedSample,
        [property: Description("Modules or assemblies the frames name that are not loaded, with what identifies the build needed.")] IReadOnlyList<MissingModule> ModulesMissing,
        IReadOnlyList<string> Notes);

    public async Task<SymbolizedStack> Symbolize(string? text, string? path, string? format, string? images, string? moduleBases, int offset, int limit, CancellationToken ct)
    {
        var fmt = (format ?? "auto").Trim().ToLowerInvariant() switch
        {
            "" or "auto" => "auto",
            var f when StackTextFormats.Families.Contains(f) => f,
            var f => throw new ToolError(ErrorCode.InvalidArgument, $"format '{f}' is not one of auto, {string.Join(", ", StackTextFormats.Families)}."),
        };
        var notes = new List<string>();
        var input = Input(text, path, notes);
        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, 1000);
        var parsed = await Task.Run(() => StackTextFormats.Parse(input, fmt), ct);
        var bases = Bases(moduleBases, parsed);
        var natives = Images(images);

        var page = new List<SymbolizedFrame>();
        var missing = new Dictionary<string, (string? Version, uint? Stamp, int Frames)>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < parsed.Frames.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var f = parsed.Frames[i];
            bool inPage = i >= offset && page.Count < limit;
            if (f.Kind == "native")
            {
                var module = ModuleOf(f, bases, parsed);
                var native = module == null ? null : FindImage(natives, module, f.BuildId);
                if (module != null && native == null)
                {
                    var known = parsed.Modules.FirstOrDefault(m => SameModule(m.Name, module));
                    var e = missing.GetValueOrDefault(module);
                    missing[module] = (known?.Version ?? e.Version, known?.TimeDateStamp ?? e.Stamp, e.Frames + 1);
                }
                if (inPage) page.Add(await Native(i, f, module, native, bases, parsed, ct));
            }
            else if (inPage) page.Add(Managed(i, f, missing, page.Count(p => p.Statement != null) < MaxStatements, ct));
            else if (f.Mvid is { } mvid && workspace.Read(() => !workspace.Assemblies.Any(a => a.Module.Mvid == mvid)))
                Count(missing, f.Type, mvid);
        }
        if (parsed.Frames.Count == 0)
            notes.Add(parsed.Unrecognized > 0 ? "No stack frame was recognized: see unrecognizedSample, or pass format to pick one." : "The text is empty.");
        if (natives.Count == 0 && parsed.Frames.Any(f => f.Kind == "native"))
            notes.Add("No native image is loaded: load the crashed program's binaries (load_assembly) to name the native frames.");

        string recognized = fmt != "auto" ? fmt : parsed.Formats.Count == 0 ? "none" : parsed.Formats.MaxBy(kv => kv.Value).Key;
        SymbolizedException? exception = parsed.Exception is { } x
            ? new SymbolizedException(x.Code is { } c ? $"0x{c:X8}" : null, x.Code is { } c2 ? ExceptionCodes.Name(c2) : null, x.Type, x.Message,
                x.Inner.Select(i => new InnerExceptionText(i.Type, i.Message)).ToList())
            : null;
        return new SymbolizedStack(recognized, exception, parsed.Frames.Count, offset, offset + page.Count < parsed.Frames.Count, page,
            parsed.Unrecognized, parsed.UnrecognizedSample,
            missing.OrderByDescending(m => m.Value.Frames).Select(m => new MissingModule(m.Key, m.Value.Version, m.Value.Stamp is { } s ? $"0x{s:X8}" : null, m.Value.Frames)).ToList(),
            notes);
    }

    private static void Count(Dictionary<string, (string? Version, uint? Stamp, int Frames)> missing, string? type, Guid mvid)
    {
        string key = $"assembly with MVID {mvid:D}" + (type != null ? $" (defines {type})" : "");
        var e = missing.GetValueOrDefault(key);
        missing[key] = (e.Version, e.Stamp, e.Frames + 1);
    }

    /// <summary>The text, or a log file read tail-first (crash records are at its end).</summary>
    private static string Input(string? text, string? path, List<string> notes)
    {
        bool hasText = !string.IsNullOrEmpty(text), hasPath = !string.IsNullOrWhiteSpace(path);
        if (hasText == hasPath)
            throw new ToolError(ErrorCode.InvalidArgument, hasText ? "pass text or path, not both." : "pass the crash text (text) or a log file (path).");
        if (hasText)
        {
            if (text!.Length > MaxTextChars)
                throw new ToolError(ErrorCode.LimitExceeded, $"text is {text.Length} characters; the limit is {MaxTextChars}.", "save it to a file and pass path (its last 8 MiB are read)");
            return text;
        }
        var full = InputFiles.RequireRegularFile(path!, "crash text file");
        try
        {
            var info = new FileInfo(full);
            if (info.Length <= MaxFileBytes) return File.ReadAllText(full);
            using var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            stream.Seek(-MaxFileBytes, SeekOrigin.End);
            var buffer = new byte[MaxFileBytes];
            stream.ReadExactly(buffer);
            var tail = Encoding.UTF8.GetString(buffer);
            int firstLine = tail.IndexOf('\n');
            notes.Add($"The file is {info.Length} bytes: only its last {MaxFileBytes >> 20} MiB were read.");
            return firstLine >= 0 ? tail[(firstLine + 1)..] : tail;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.IoError, $"cannot read {path}: {ex.Message}");
        }
    }

    /// <summary>Module load addresses: the caller's (name=0xBASE;...), then the text's module list.</summary>
    private static Dictionary<string, ulong> Bases(string? list, ParsedStackText parsed)
    {
        var bases = new Dictionary<string, ulong>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in parsed.Modules)
            if (m.Base is { } b) bases.TryAdd(m.Name, b);
        foreach (var item in (list ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int eq = item.IndexOf('=');
            var value = eq > 0 ? item[(eq + 1)..].Trim() : "";
            if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) value = value[2..];
            if (eq <= 0 || !ulong.TryParse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b))
                throw new ToolError(ErrorCode.InvalidArgument, $"moduleBases: '{item}' is not name=0xBASE.", "for example GameAssembly.dll=0x7FFB0C3F0000;UnityPlayer.dll=0x7FFB0A000000");
            bases[item[..eq].Trim()] = b;
        }
        return bases;
    }

    private List<LoadedNative> Images(string? list)
    {
        var result = new List<LoadedNative>();
        if (string.IsNullOrWhiteSpace(list)) return workspace.Read(() => workspace.Natives.ToList());
        foreach (var item in list.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var id = workspace.Read(() => workspace.FindNative(item)?.Id);
            if (id == null && Path.IsPathFullyQualified(item) && File.Exists(item))
                id = workspace.LoadAny(item).Native?.Id ?? throw new ToolError(ErrorCode.Unsupported, $"images: {item} is a .NET assembly, not a native image.");
            result.Add(workspace.Read(() => workspace.GetNative(id ?? item)));
        }
        return result;
    }

    private static bool SameModule(string a, string b) =>
        a.Equals(b, StringComparison.OrdinalIgnoreCase) || Path.GetFileNameWithoutExtension(a).Equals(Path.GetFileNameWithoutExtension(b), StringComparison.OrdinalIgnoreCase)
        && (!Path.HasExtension(a) || !Path.HasExtension(b));

    /// <summary>A text's build id may be cut short (tombstones print a prefix on some versions).</summary>
    private static bool SameBuildId(string? ours, string theirs) => ours != null && (ours.StartsWith(theirs, StringComparison.OrdinalIgnoreCase) || theirs.StartsWith(ours, StringComparison.OrdinalIgnoreCase));

    private static LoadedNative? FindImage(List<LoadedNative> natives, string module, string? buildId = null) =>
        (buildId != null ? natives.FirstOrDefault(n => SameBuildId(n.Image.BuildId, buildId)) : null)
        ?? natives.FirstOrDefault(n => Path.GetFileName(n.FilePath).Equals(module, StringComparison.OrdinalIgnoreCase))
        ?? natives.FirstOrDefault(n => SameModule(Path.GetFileName(n.FilePath), module));

    /// <summary>The module a native frame is in: named by the text, else the module whose range (or nearest base below) holds its address.</summary>
    private static string? ModuleOf(TextFrame f, Dictionary<string, ulong> bases, ParsedStackText parsed)
    {
        if (f.Module != null) return f.Module;
        if (f.Address is not { } a) return null;
        var sized = parsed.Modules.FirstOrDefault(m => m.Base is { } b && m.Size is { } s && a >= b && a - b < s);
        if (sized != null) return sized.Name;
        return bases.Where(kv => kv.Value <= a).OrderByDescending(kv => kv.Value).Select(kv => kv.Key).FirstOrDefault();
    }

    private async Task<SymbolizedFrame> Native(int index, TextFrame f, string? module, LoadedNative? native, Dictionary<string, ulong> bases, ParsedStackText parsed, CancellationToken ct)
    {
        ulong? rva = f.Offset;
        if (rva == null && f.Address is { } a && module != null && bases.FirstOrDefault(kv => SameModule(kv.Key, module)) is { Key: not null } kb && a >= kb.Value)
            rva = a - kb.Value;
        string? address = f.Address is { } addr ? $"0x{addr:X}" : null;
        SymbolizedFrame Row(string? resolved, string? source, string check, string? detail, string? next, ulong? shownRva = null) =>
            new(index, f.Line, f.Raw, "native", module, (shownRva ?? rva) is { } r ? $"0x{r:X}" : null, address, resolved, source, native?.Id, null, null, null, null, f.Segment, check, detail, next);

        var textModule = module == null ? null : parsed.Modules.FirstOrDefault(m => SameModule(m.Name, module));
        if (module == null)
            return Row(null, null, "unknown", "no module for this address", "pass moduleBases (name=0xBASE) or the crash's module list");
        if (native == null)
            return Row(null, null, "unknown", "the module is not loaded",
                $"load_assembly {module}" + (textModule?.Version is { } v ? $" (version {v})" : "") + (textModule?.TimeDateStamp is { } ts ? $" (time stamp 0x{ts:X8})" : "")
                + (f.BuildId is { } id ? $" (BuildId {id})" : ""));

        var index0 = await Index(native, ct);
        uint size = native.Image.SizeOfImage;
        // module!function+0x.. : the function by name, then the offset inside it
        if (rva == null && f.Symbol != null)
        {
            var start = index0?.AddressesOfName(f.Symbol) is [var one] ? one.Rva
                : native.Image.Exports.FirstOrDefault(e => e.Name == f.Symbol && e.ForwardedTo == null)?.Rva;
            if (start == null)
                return Row(null, null, "unknown", $"no function named {f.Symbol} in {native.Id}", $"search_pdb_symbols image={native.Id} or load_pdb");
            rva = start + (f.SymbolOffset ?? 0);
            var (named, source) = Name(native, index0, (uint)rva.Value);
            if (index0?.FunctionAt(start.Value) is not { } function)
                return Row(named, source, "unknown", "the function's extent is not known here", $"decompile_native image={native.Id} address=0x{rva:X}");
            bool inside = rva < function.End && index0.FunctionAt((uint)rva.Value)?.Start == start;
            return Row(named, source, inside ? "match" : "mismatch",
                inside ? null : $"{f.Symbol}+0x{f.SymbolOffset:X} is past the end of {f.Symbol} here (size 0x{function.End - function.Start:X}): the text is from another build",
                $"decompile_native image={native.Id} address=0x{rva:X}");
        }
        if (rva == null)
            return Row(null, null, "unknown", $"no load address for {module}", $"pass moduleBases={module}=0x<base>");
        if (rva >= size)
            return Row(null, null, "mismatch", $"offset 0x{rva:X} is past the end of {native.Id} (size 0x{size:X}): another build", null);

        var (name, src) = Name(native, index0, (uint)rva.Value);
        string check = "unknown";
        string? detail = null;
        uint? stamp = native.Pe?.Coff.TimeDateStamp;
        if (f.BuildId is { } wantId)
        {
            bool same = SameBuildId(native.Image.BuildId, wantId);
            check = native.Image.BuildId == null ? "unknown" : same ? "match" : "mismatch";
            detail = native.Image.BuildId == null ? $"{native.Id} has no build id to compare with {wantId}"
                : same ? null : $"the text's {module} has BuildId {wantId}, the loaded image {native.Image.BuildId}";
        }
        else if (textModule?.TimeDateStamp is { } want && stamp is { } have)
        {
            check = want == have ? "match" : "mismatch";
            detail = want == have ? null : $"the text's {module} has time stamp 0x{want:X8}, the loaded image 0x{have:X8}";
        }
        else if (textModule?.Version is { } version && FileVersion(native) is { } fileVersion)
        {
            bool same = Normalize(fileVersion) == Normalize(version);
            check = same ? "unknown" : "mismatch";
            detail = same ? "same file version (no time stamp to compare)" : $"the text's {module} is version {version}, the loaded image {fileVersion}";
        }
        else if (f.Symbol != null && name != null)
        {
            bool agree = Bare(name).Contains(Bare(f.Symbol), StringComparison.Ordinal) || Bare(f.Symbol).Contains(Bare(name), StringComparison.Ordinal);
            check = agree ? "match" : "unknown";
            detail = agree ? null : $"the text names it {f.Symbol}; here it is {name} (another naming source, or another build)";
        }
        else if (native.Image.Sections.FirstOrDefault(s => s.Contains((uint)rva.Value)) is { IsExecutable: false } section)
        {
            check = "mismatch";
            detail = $"0x{rva:X} is in {section.Name}, not code: another build";
        }
        return Row(name, src, check, detail, $"decompile_native image={native.Id} address=0x{rva:X}");
    }

    private static string? FileVersion(LoadedNative native) => native.Pe?.VersionInfo is not { } info ? null
        : info.Fixed is { FileVersion: var v and not 0 } ? $"{v >> 48}.{(v >> 32) & 0xFFFF}.{(v >> 16) & 0xFFFF}.{v & 0xFFFF}" : info.Get("FileVersion");

    private static string Normalize(string version) => string.Join('.', version.Split([',', '.', ' '], StringSplitOptions.RemoveEmptyEntries).Select(p => p.TrimStart('0') is { Length: > 0 } t ? t : "0"));

    private static string Bare(string name)
    {
        int paren = name.IndexOf('(');
        var s = paren > 0 ? name[..paren] : name;
        int plus = s.LastIndexOf("+0x", StringComparison.Ordinal);
        return (plus > 0 ? s[..plus] : s).Replace("::", ".", StringComparison.Ordinal).Trim();
    }

    private async Task<NativeCodeIndex?> Index(LoadedNative native, CancellationToken ct)
    {
        if (code == null) return null;
        try { return await code.Index(native, null, ct).WaitAsync(IndexWait, ct); }
        catch (TimeoutException) { return null; }
        catch (ToolError) { return null; }
    }

    /// <summary>Our name at an RVA: user, PDB, Il2Cpp and discovered names, then the nearest export below.</summary>
    private (string? Name, string? Source) Name(LoadedNative native, NativeCodeIndex? index, uint rva)
    {
        (string Name, string Source, uint Start)? found = null;
        if (index?.FunctionAt(rva) is { } f)
        {
            var sourced = index.Sourced.NameAt(f.Start);
            found = (index.NameAt(f.Start) ?? f.Name, sourced is { } sn ? sn.Source.ToString().ToLowerInvariant() : f.KnownName != null ? "export" : "discovered", f.Start);
        }
        if (found is not { Source: "user" } && Path.GetFileName(native.FilePath).StartsWith("GameAssembly", StringComparison.OrdinalIgnoreCase)
            && navigator?.FrameName(rva) is { } il2cpp)
            found = il2cpp;
        if (found == null && native.Image.Exports.Where(e => e.ForwardedTo == null && e.Rva <= rva && e.Name != null).MaxBy(e => e.Rva) is { } export)
            found = (export.Name!, "nearest_export", export.Rva);
        if (found is not { } n) return (null, "none");
        return (rva == n.Start ? n.Name : $"{n.Name}+0x{rva - n.Start:X}", n.Source);
    }

    private sealed record ManagedMatch(string Kind, string? Resolved, string? Assembly, string? Token, string Check, string? Detail, string? Next)
    {
        public (LoadedAssembly Assembly, MethodDef Method)? Target { get; init; }
    }

    private SymbolizedFrame Managed(int index, TextFrame f, Dictionary<string, (string? Version, uint? Stamp, int Frames)> missing, bool statement, CancellationToken ct)
    {
        var (m, text) = workspace.Read(() =>
        {
            var match = Resolve(f, missing);
            string? s = null;
            // a statement only where the IL is the one that ran (the same build) or no build check is possible
            if (statement && decompiler != null && f.IlOffset is { } il && match is { Target: { } t, Kind: "managed", Check: not "mismatch" })
            {
                try { s = decompiler.StatementAt(t.Assembly, t.Method, il, ct)?.Text; }
                catch (ToolError) { }
            }
            return (match, s);
        });
        return new SymbolizedFrame(index, f.Line, f.Raw, m.Kind, null, f.SymbolOffset is { } so ? $"0x{so:X}" : null, f.Address is { } a ? $"0x{a:X}" : null,
            m.Resolved, m.Resolved != null ? "metadata" : "none", null, m.Assembly, m.Token, f.IlOffset, text, f.Segment, m.Check, m.Detail, m.Next);
    }

    /// <summary>A managed frame's method in the loaded assemblies: by MVID when the text has one (the build check), else by name.</summary>
    private ManagedMatch Resolve(TextFrame f, Dictionary<string, (string? Version, uint? Stamp, int Frames)> missing)
    {
        if (f.Type == null || f.Method == null) return new("managed", null, null, null, "unknown", "a runtime or wrapper frame: no method to resolve", null);
        var typeName = StripGeneric(f.Type);
        var defining = workspace.Assemblies.Select(a => (Asm: a, Type: Find(a, typeName))).Where(x => x.Type != null).ToList();
        var candidates = defining;
        string check = "unknown";
        string? detail = null;
        if (f.Mvid is { } mvid)
        {
            var same = workspace.Assemblies.FirstOrDefault(a => a.Module.Mvid == mvid);
            if (same != null)
            {
                check = "match";
                candidates = [(same, Find(same, typeName))];
            }
            else if (defining.Count > 0)
            {
                check = "mismatch";
                detail = $"the frame's module has MVID {mvid:D}; the loaded {defining[0].Asm.Id} has {defining[0].Asm.Module.Mvid:D}: another build, its code may not match";
            }
            else
            {
                Count(missing, f.Type, mvid);
                return new("managed", null, null, null, "unknown", $"no loaded assembly has MVID {mvid:D}", "load the application's managed assemblies with load_assembly");
            }
        }
        else if (defining.Count > 0) detail = "matched by name: the text carries no MVID to check the build";
        var (asm, type) = candidates.FirstOrDefault(c => c.Type != null);
        if (asm == null || type == null)
            return new("managed", null, null, null, check, detail ?? $"no loaded assembly defines {typeName}", "load the application's assemblies with load_assembly");
        var methods = type.Methods.Where(m => m.Name == f.Method).ToList();
        if (methods.Count == 0)
            return new("managed", null, asm.Id, null, check == "match" ? "mismatch" : check, $"{typeName} in {asm.Id} has no method {f.Method}", null);
        int arity = Arity(f.Args);
        var pick = methods.Where(m => m.MethodSig?.Params.Count == arity).ToList() is { Count: > 0 } byArity ? byArity : methods;
        if (pick.Count > 1) detail = (detail == null ? "" : detail + "; ") + $"{pick.Count} overloads with {arity} parameters: the first is shown";
        var method = pick[0];
        var token = $"0x{method.MDToken.Raw:X8}";
        bool il2cpp = navigator?.ImageOf(asm) != null;
        return new(il2cpp ? "il2cpp" : "managed", Format.MemberLabel(method), asm.Id, token, check, detail,
            il2cpp ? $"get_il2cpp_info assembly={asm.Id} symbol={token}" : $"decompile_member assembly={asm.Id} member={token}") { Target = (asm, method) };
    }

    private static TypeDef? Find(LoadedAssembly asm, string typeName) =>
        asm.Module.Find(typeName, isReflectionName: true) ?? asm.Module.Find(typeName.Replace('+', '/'), isReflectionName: false);

    /// <summary>List`1[T] / List`1&lt;T&gt; to List`1.</summary>
    private static string StripGeneric(string type)
    {
        int at = type.IndexOfAny(['[', '<']);
        return at > 0 ? type[..at] : type;
    }

    private static int Arity(string? args)
    {
        if (string.IsNullOrWhiteSpace(args)) return 0;
        int depth = 0, count = 1;
        foreach (var c in args)
        {
            if (c is '<' or '[' or '(') depth++;
            else if (c is '>' or ']' or ')') depth--;
            else if (c == ',' && depth == 0) count++;
        }
        return count;
    }
}
