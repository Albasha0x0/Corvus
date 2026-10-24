using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Code;

namespace Corvus.Services;

/// <summary>
/// Names a native Il2Cpp binary (GameAssembly.dll) from the dump that describes it: the dummy-DLL methods'
/// [Address] RVAs and, with script.json, every function start, generic instantiation, ScriptMetadata and MethodInfo
/// slot; with stringliteral.json (or script.json's strings), the string literal slots. The names form the image's
/// <see cref="NativeNameSource.Il2Cpp"/> layer, below user and PDB names, replaced or cleared as a whole.
/// <para>
/// Naming scheme: C identifiers (letters, digits, '_'), the name characters IDA accepts for x86/x64, so the names
/// in IDA equal ours. Functions "Ns_Type__Method": the script.json name "Ns.Type$$Method" with "$$" as "__" and
/// every other character outside the set replaced by '_' (runs collapsed, a trailing one dropped; non-ASCII letters
/// as uXXXX; a leading digit gets '_'); a name already used at another address gets "_&lt;RVA hex&gt;". Comments keep
/// the readable form: "Ns.Type::Method(int, string)" for dummy methods, "Ns.Type&lt;args&gt;::Method" for
/// instantiations, and the other methods sharing the code. Data: StringLiteral_&lt;n&gt; (n in slot address order)
/// commented with the text, ScriptMetadata slots ("Ns_Type_TypeInfo", "Ns_Type_var") and MethodInfo slots
/// ("Method_Ns_Type_Method"), commented with the script.json name.
/// </para>
/// </summary>
public sealed class Il2CppNativeNames(Il2CppService il2cpp, Il2CppNavigator navigator, NativeCodeService code)
{
    /// <summary>Most other methods listed in a shared function's comment.</summary>
    public const int SharedListed = 8;
    private const int MaxCommentText = 200;

    private static readonly ConditionalWeakTable<LoadedNative, Applied> AppliedTable = new();

    /// <summary>What the last apply used for an image: the dump image and its literal slots (sorted by RVA).</summary>
    public sealed record Applied(Il2CppNavigator.Image Image, string Assemblies, uint[] LiteralSlots, string[] LiteralTexts);

    public sealed record Report(
        string Assemblies, string? DumpDirectory, bool HasScript,
        int Functions, int FunctionsNotDiscovered, int SharedFunctions, int SharedExtraMethods, int UnnamedStarts,
        int OutsideImage, int Suffixed, int UserNamesKept, int Strings, int MetadataSlots, int MethodInfoSlots, TimeSpan Elapsed,
        IReadOnlyList<string> Notes);

    /// <summary>Builds the il2cpp layer for <paramref name="native"/> from the dummy assemblies in <paramref name="scope"/> and applies it.</summary>
    public Report Apply(LoadedNative native, NativeCodeIndex? index, IReadOnlyList<LoadedAssembly> scope, CancellationToken ct)
    {
        var watch = Stopwatch.StartNew();
        var image = PickImage(native, scope);
        var pe = native.Image;
        var notes = new List<string>();
        if (image.Problem != null) notes.Add(image.Problem);
        var names = new Dictionary<uint, string>();
        var comments = new Dictionary<uint, string>();
        var used = new Dictionary<string, uint>(StringComparer.Ordinal);
        int suffixed = 0;
        var user = code.Annotations(native);

        string Unique(string name, uint rva)
        {
            if (used.TryAdd(name, rva)) return name;
            suffixed++;
            var unique = $"{name}_{rva:X}";
            used.TryAdd(unique, rva);
            return unique;
        }

        bool Executable(uint rva) => rva < pe.SizeOfImage && pe.SectionAt(rva) is { IsExecutable: true };
        bool Mapped(uint rva) => rva < pe.SizeOfImage && pe.SectionAt(rva) != null;

        int functions = 0, notDiscovered = 0, shared = 0, sharedExtra = 0, unnamed = 0, outside = 0, userKept = 0;
        var script = image.Script;
        foreach (var start in image.Starts)
        {
            ct.ThrowIfCancellationRequested();
            var (methods, scriptMethods) = Il2CppNavigator.MethodsSharing(image, start);
            int total = methods.Count + scriptMethods.Count;
            if (total == 0) { unnamed++; continue; }
            if (!Executable(start)) { outside++; continue; }
            var labels = methods.Select(m => (Key: Il2CppNames.MethodKey(m.Method), Readable: Format.MemberLabel(m.Method)))
                .Concat(scriptMethods.Select(e => (Key: script!.MethodName(e), Readable: script.MethodName(e).Replace("$$", "::"))))
                .ToList();
            names[start] = Unique(NativeName.Identifier(labels[0].Key), start);
            var comment = new StringBuilder(labels[0].Readable);
            if (total > 1)
            {
                shared++;
                sharedExtra += total - 1;
                comment.Append($"\nshared code, also: {string.Join("; ", labels.Skip(1).Take(SharedListed).Select(l => l.Readable))}");
                if (total - 1 > SharedListed) comment.Append($" (+{total - 1 - SharedListed} more; find_method_by_address 0x{start:X} lists them)");
            }
            comments[start] = comment.ToString();
            functions++;
            if (index != null && index.FunctionByStart(start) == null) notDiscovered++;
            if (user.NameAt(start) != null) userKept++;
        }
        if (outside > 0) notes.Add($"{outside} function start(s) are not in an executable section of {native.Id}");

        uint[] literalSlots = [];
        string[] literalTexts = [];
        if (image.Dump is { } dump && dump.Files.HasLiterals)
        {
            try
            {
                var values = dump.Values;
                var addresses = dump.Addresses;
                var slots = new List<uint>(values.Length);
                var texts = new List<string>(values.Length);
                for (int i = 0; i < values.Length; i++)
                {
                    if (addresses[i] > uint.MaxValue || !Mapped((uint)addresses[i])) { outside++; continue; }
                    uint rva = (uint)addresses[i];
                    if (names.ContainsKey(rva)) continue;
                    names[rva] = Unique($"StringLiteral_{i}", rva);
                    comments[rva] = Quote(values[i]);
                    slots.Add(rva);
                    texts.Add(values[i]);
                }
                literalSlots = slots.ToArray();
                literalTexts = texts.ToArray();
            }
            catch (ToolError e) { notes.Add(e.Message); }
        }

        // ScriptMetadata and MethodInfo slots
        int metadata = 0, methodInfos = 0;
        if (script != null)
        {
            for (int e = 0; e < script.MetadataCount; e++)
            {
                uint rva = script.MetadataAddress(e);
                if (!Mapped(rva)) { outside++; continue; }
                if (names.ContainsKey(rva)) continue;
                var name = script.MetadataName(e);
                names[rva] = Unique(NativeName.Identifier(name), rva);
                comments[rva] = name;
                metadata++;
            }
            if (script.MethodInfoCount > 0)
            {
                try
                {
                    script.ForEachMethodInfo(m =>
                    {
                        if (m.Address is 0 or > uint.MaxValue || !Mapped((uint)m.Address)) return;
                        uint rva = (uint)m.Address;
                        if (names.ContainsKey(rva)) return;
                        var name = m.Name.EndsWith("()", StringComparison.Ordinal) ? m.Name[..^2] : m.Name;
                        names[rva] = Unique(NativeName.Identifier(name), rva);
                        comments[rva] = m.MethodAddress is > 0 and <= uint.MaxValue ? $"{m.Name}: code at rva 0x{m.MethodAddress:X}" : $"{m.Name}: no code of its own";
                        methodInfos++;
                    }, ct);
                }
                catch (Exception ex) when (ex is System.Text.Json.JsonException or IOException or UnauthorizedAccessException)
                {
                    notes.Add($"MethodInfo slots not named: cannot read {script.Path}: {ex.Message}");
                }
            }
        }

        var assemblies = string.Join(", ", image.Assemblies.Select(a => a.Id));
        var (sourcePath, identity) = Provenance(image);
        NativeNameLayers.Of(native).Set(new NativeNameLayers.Layer(NativeNameSource.Il2Cpp, names, comments, $"Il2Cpp metadata ({assemblies})",
            new ImportInfo(sourcePath, identity, DateTime.UtcNow)), index);
        AppliedTable.AddOrUpdate(native, new Applied(image, assemblies, literalSlots, literalTexts));
        if (code.SaveImported(native, NativeNameSource.Il2Cpp) is { } problem) notes.Add($"names not saved for the next load: {problem}");
        return new Report(assemblies, image.Dump?.Files.Directory, script != null, functions, notDiscovered, shared, sharedExtra, unnamed, outside,
            suffixed, userKept, literalSlots.Length, metadata, methodInfos, watch.Elapsed, notes);
    }

    /// <summary>
    /// The file the names were read from (global-metadata.dat for the built-in reader, else script.json, stringliteral.json
    /// or the first dummy assembly) and its SHA-256, saved with the names.
    /// </summary>
    private static (string? Path, string? Sha256) Provenance(Il2CppNavigator.Image image)
    {
        string? path = null;
        if (image.Dump?.Files is { } files)
        {
            if (files.Model != null)
            {
                try { path = Il2CppRawLoader.Model(files.Model).MetadataPath; }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or EndOfStreamException or ToolError) { }
                path ??= files.Model;
            }
            path ??= files.ScriptJson ?? files.StringLiteralJson;
        }
        path ??= image.Assemblies.FirstOrDefault()?.FilePath;
        if (path == null) return (null, null);
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 20);
            return (path, Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(stream)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return (path, null); }
    }

    /// <summary>Removes the il2cpp layer and its saved copy; returns how many names it had, or null when none was applied.</summary>
    public int? Clear(LoadedNative native, NativeCodeIndex? index)
    {
        AppliedTable.Remove(native);
        code.RestoreImported(native);
        var removed = NativeNameLayers.OfOrNull(native)?.Remove(NativeNameSource.Il2Cpp, index)?.Names.Count;
        bool deleted = code.ForgetImported(native, NativeNameSource.Il2Cpp);
        return removed ?? (deleted ? 0 : null);
    }

    /// <summary>The il2cpp data applied to an image, or null.</summary>
    public static Applied? Of(LoadedNative native) =>
        AppliedTable.TryGetValue(native, out var applied) && NativeNameLayers.OfOrNull(native)?.Get(NativeNameSource.Il2Cpp) != null ? applied : null;

    /// <summary>
    /// The dump image describing <paramref name="native"/>: the one made from this file (by path, build id or SHA-256), else the only
    /// one in scope. Refuses when no dummy assembly is loaded, when several dumps are and none names this file, and
    /// when none of the dump's function starts falls in an executable section of the image.
    /// </summary>
    private Il2CppNavigator.Image PickImage(LoadedNative native, IReadOnlyList<LoadedAssembly> scope)
    {
        var withMetadata = scope.Where(a => il2cpp.GetIndex(a).Count > 0).ToList();
        if (withMetadata.Count == 0)
            throw new ToolError(ErrorCode.NotLoaded, "No Il2Cpp dummy assembly (one with [Address] attributes) is loaded" +
                                                     (scope.Count > 0 ? " in the selected assemblies." : "."),
                "load_assembly the application folder or its global-metadata.dat (built-in reader; apply_il2cpp_names does it when the metadata is beside the image), or a dummy assembly folder (script.json and stringliteral.json beside it add generic instantiations, metadata slots and strings)");
        var images = navigator.ImagesFor(withMetadata);
        var image = images.FirstOrDefault(i => i.Dump?.Files.Describes(native) == true)
                    ?? (images.Count == 1 ? images[0] : null)
                    ?? throw new ToolError(ErrorCode.Ambiguous, $"{images.Count} Il2Cpp dumps are loaded and none was made from {native.FilePath}: " +
                                                                string.Join("; ", images.Select(i => i.Dump?.Files.Directory ?? string.Join(", ", i.Assemblies.Select(a => a.Id)))),
                        "pass assembly to pick the dummy assemblies of this build");
        var pe = native.Image;
        if (!image.Starts.Any(s => s < pe.SizeOfImage && pe.SectionAt(s) is { IsExecutable: true }))
            throw new ToolError(ErrorCode.InvalidArgument,
                $"None of the {image.Starts.Length} function addresses of the dump ({string.Join(", ", image.Assemblies.Select(a => a.Id))}) is in an executable section of {native.Id}: " +
                "the dump was not made from this binary.", "load the matching GameAssembly.dll, or the dummy assemblies dumped from this binary");
        return image;
    }

    /// <summary>The text as a quoted, escaped comment, clipped to 200 characters.</summary>
    public static string Quote(string text)
    {
        var clipped = text.Length > MaxCommentText ? text[..MaxCommentText] : text;
        var sb = new StringBuilder("\"");
        foreach (var c in clipped)
            sb.Append(c switch
            {
                '\\' => "\\\\",
                '"' => "\\\"",
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                < ' ' => $"\\x{(int)c:X2}",
                _ => c.ToString(),
            });
        return sb.Append('"').Append(text.Length > MaxCommentText ? "..." : "").ToString();
    }

    /// <summary>The assembly of the method(s) whose body starts at <paramref name="rva"/>, from script.json; null when unknown.</summary>
    internal static string? MethodAssembly(Il2CppNavigator.Image image, uint rva)
    {
        if (image.Script is not { } script || script.MethodRange(rva) is not (var first, > 0)) return null;
        return script.Definition(first) is { } definition ? Path.GetFileNameWithoutExtension(definition.Image) : null;
    }

    /// <summary>
    /// Lines describing <paramref name="rva"/> through the applied il2cpp names: the slot or function name, its comment,
    /// and the reverse navigation to the managed method (find_method_by_address). Empty when nothing was applied.
    /// </summary>
    public static List<string> Describe(LoadedNative native, NativeCodeIndex? index, uint rva)
    {
        var lines = new List<string>();
        if (NativeNameLayers.OfOrNull(native)?.Get(NativeNameSource.Il2Cpp) is not { } layer) return lines;
        if (Of(native) is not { } applied)
        {
            // restored from the saved names: no dump loaded to navigate with
            if (layer.Names.TryGetValue(rva, out var saved))
                lines.Add($"il2cpp name {saved}" + (layer.Comments.TryGetValue(rva, out var c) ? $": {c.Replace("\n", "; ")}" : "") +
                          " (saved names; apply_il2cpp_names again for the managed side)");
            return lines;
        }
        if (layer.Names.TryGetValue(rva, out var name))
        {
            lines.Add($"il2cpp name {name}" + (layer.Comments.TryGetValue(rva, out var c) ? $": {c.Replace("\n", "; ")}" : ""));
        }
        else if (Il2CppNavigator.Function(applied.Image, rva) is { } f && layer.Names.TryGetValue(f.Start, out var owner))
        {
            lines.Add($"in il2cpp function {owner} (rva 0x{f.Start:X}, {f.Relation})" +
                      (layer.Comments.TryGetValue(f.Start, out var c) ? $": {c.Replace("\n", "; ")}" : ""));
            rva = f.Start;
        }
        else return lines;
        lines.Add($"managed side: find_method_by_address 0x{rva:X}{(MethodAssembly(applied.Image, rva) is { } assembly ? $" (assembly {assembly})" : "")} shows the method(s), get_il2cpp_info their metadata");
        if (index?.Sourced.NameAt(rva) is { } over && over.Source.Rank() > NativeNameSource.Il2Cpp.Rank())
            lines.Add($"(the {over.Source.Id()} name {over.Name} is in effect there)");
        return lines;
    }
}
