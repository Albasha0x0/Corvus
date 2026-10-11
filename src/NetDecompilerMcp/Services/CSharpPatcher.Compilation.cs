using System.Reflection;
using System.Text;
using dnlib.DotNet;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>Roslyn compilation: options (accessibility checks off), references, error formatting.</summary>
public sealed partial class CSharpPatcher
{
    private static CSharpCompilationOptions CreateOptions()
    {
        var options = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary,
            optimizationLevel: OptimizationLevel.Release,
            allowUnsafe: true,
            nullableContextOptions: NullableContextOptions.Disable,
            metadataImportOptions: MetadataImportOptions.All,
            checkOverflow: false);
        // Roslyn's internal IgnoreAccessibility binder flag (used by scripting/IDE tooling): patched code may access
        // private and internal members of the original assembly.
        var flags = typeof(CSharpCompilationOptions).GetProperty("TopLevelBinderFlags", BindingFlags.Instance | BindingFlags.NonPublic);
        flags?.SetValue(options, Enum.ToObject(flags.PropertyType, 1u << 22));
        return options;
    }

    /// <summary>The assembly's own (current) image plus the transitive closure of its references.</summary>
    /// <param name="clashing">Simple names of types a compilation found in two references (CS0433); see <see cref="HideClashingTypes"/>.</param>
    private List<MetadataReference> BuildReferences(LoadedAssembly asm, byte[]? targetImage, out List<string> missing, IReadOnlySet<string>? clashing = null)
    {
        var targetBytes = targetImage ?? asm.GetImageBytes();
        var closure = Closure(asm, targetBytes);
        missing = [.. closure.Missing];
        var images = closure.Images.ToList();
        var friend = FriendImage(targetBytes, asm.AssemblyName + PatchSuffix, closure.StandIns);
        images[0] = (images[0].Name, friend, images[0].Path);
        var references = images.Select(i => Reference(i.Image)).ToList();
        if (clashing is { Count: > 0 }) HideClashingTypes(asm, images, references, clashing);
        // A stand-in has no public key, so a reference naming one by its token does not bind to it (CS0012).
        for (int i = 1; i < images.Count && closure.StandIns.Count > 0; i++)
            if (WithoutTokens(images[i].Image, closure.StandIns) is { } image)
                references[i] = Reference(image);
        return SingleCoreLibrary(references, images);
    }

    /// <summary>The images of a target and its reference closure (the target's own first), the names not found, and those resolved to stand-ins.</summary>
    private sealed record ReferenceClosure(int Generation, IReadOnlyList<(string Name, byte[] Image, string Path)> Images, IReadOnlyList<string> Missing,
        HashSet<string> StandIns);

    // Per target image: one patch compiles several times, and the same reference bytes let Roslyn reuse what it read.
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<byte[], ReferenceClosure> Closures = new();

    private ReferenceClosure Closure(LoadedAssembly asm, byte[] targetBytes)
    {
        if (Closures.TryGetValue(targetBytes, out var cached) && cached.Generation == workspace.Generation) return cached;
        var missing = new List<string>();
        var images = new List<(string Name, byte[] Image, string Path)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var stubbed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // References of each module resolve from its own folder first.
        var queue = new Queue<(ModuleDef Module, bool Owned, string Path)>();

        void Enqueue(string name, byte[] image, ModuleDef module, bool owned, string path)
        {
            if (!seen.Add(name)) { if (owned) module.Dispose(); return; }
            images.Add((name, image, path));
            queue.Enqueue((module, owned, path));
        }

        Enqueue(asm.AssemblyName, targetBytes, asm.Module, owned: false, asm.FilePath);
        bool netFramework = Frameworks.ResolvesAsNetFramework(asm.Module); // applies to the whole reference closure
        var targetFramework = Frameworks.RequesterFramework(asm.Module);
        while (queue.Count > 0)
        {
            var (module, owned, from) = queue.Dequeue();
            foreach (var r in module.GetAssemblyRefs())
            {
                string name = r.Name;
                if (seen.Contains(name)) continue;
                var target = workspace.LocateReference(name, r.Version, r.PublicKeyOrToken?.Token?.Data, from, netFramework, targetFramework);
                if (target?.Loaded is { } loaded)
                {
                    Enqueue(name, loaded.GetImageBytes(), loaded.Module, owned: false, loaded.FilePath);
                    continue;
                }
                if (target == null) { seen.Add(name); missing.Add(name); continue; }
                if (target.Stub != null) stubbed.Add(name);
                try
                {
                    // Embedded (Costura) assemblies resolve their references from the host's folder.
                    var bytes = target.Bytes ?? File.ReadAllBytes(target.File!);
                    Enqueue(name, bytes, ModuleDefMD.Load(bytes), owned: true, target.File ?? from);
                }
                catch
                {
                    seen.Add(name);
                    missing.Add(name);
                }
            }
            if (owned) module.Dispose();
        }
        var closure = new ReferenceClosure(workspace.Generation, images, missing, stubbed);
        Closures.AddOrUpdate(targetBytes, closure);
        return closure;
    }

    /// <summary>
    /// Writes the target's reference copy (<see cref="FriendImage"/>) on another thread while the caller decompiles the
    /// shadow: for a large assembly both take seconds. The compile that needs it waits for it on the cache lock.
    /// </summary>
    private void PrefetchFriendImage(LoadedAssembly asm)
    {
        var bytes = asm.GetImageBytes();
        var standIns = Closure(asm, bytes).StandIns;
        var friend = asm.AssemblyName + PatchSuffix;
        _ = Task.Run(() => FriendImage(bytes, friend, standIns));
    }

    /// <summary>
    /// References are imported with their internals, so a non-public top-level type defined under the same full name in two
    /// of them (System.SR is in most runtime libraries) is ambiguous (CS0433). The copy that counts is the target's own,
    /// else the one of the assembly the target references by that name, else the only public one; the other non-public
    /// copies (all of them when none is public and none is used) are renamed out of reach in their reference copies.
    /// </summary>
    private static void HideClashingTypes(LoadedAssembly asm, List<(string Name, byte[] Image, string Path)> images, List<MetadataReference> references,
        IReadOnlySet<string> clashing)
    {
        var defined = images.Select(i => TopLevelTypes(i.Image).Where(t => clashing.Contains(Format.StripArity(t.Name))).ToList()).ToList();
        var usedFrom = asm.Module.GetTypeRefs().Where(t => t.ResolutionScope is AssemblyRef)
            .GroupBy(t => t.FullName).ToDictionary(g => g.Key, g => ((AssemblyRef)g.First().ResolutionScope).Name.String);
        var hide = new Dictionary<int, HashSet<string>>();
        foreach (var name in defined.SelectMany(d => d.Select(t => t.FullName)).Distinct())
        {
            var owners = Enumerable.Range(0, images.Count).Where(i => defined[i].Any(t => t.FullName == name)).ToList();
            if (owners.Count < 2) continue;
            bool Public(int i) => defined[i].First(t => t.FullName == name).IsPublic;
            int? winner = owners[0] == 0 ? 0
                : usedFrom.TryGetValue(name, out var from) && owners.FirstOrDefault(i => string.Equals(images[i].Name, from, StringComparison.OrdinalIgnoreCase), -1) is var used and >= 0 ? used
                : owners.Where(Public).ToList() is [var onlyPublic] ? onlyPublic : null;
            if (winner == null && owners.Any(Public)) continue;
            // The target's own type wins over referenced ones, public or not, as when it was compiled (CS0436).
            foreach (int i in owners.Where(i => i != winner && (winner == 0 || !Public(i))))
                (hide.TryGetValue(i, out var set) ? set : hide[i] = new HashSet<string>(StringComparer.Ordinal)).Add(name);
        }
        foreach (var (i, names) in hide)
            if (WithTypesRenamed(images[i].Image, names) is { } renamed)
            {
                images[i] = (images[i].Name, renamed, images[i].Path);
                references[i] = Reference(renamed);
            }
    }

    private static List<(string FullName, string Name, bool IsPublic)> TopLevelTypes(byte[] image)
    {
        try
        {
            using var pe = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(image, writable: false));
            var md = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
            var result = new List<(string, string, bool)>();
            foreach (var h in md.TypeDefinitions)
            {
                var t = md.GetTypeDefinition(h);
                if (!t.GetDeclaringType().IsNil) continue;
                string ns = md.GetString(t.Namespace), name = md.GetString(t.Name);
                result.Add((ns.Length == 0 ? name : ns + "." + name, name, (t.Attributes & System.Reflection.TypeAttributes.VisibilityMask) == System.Reflection.TypeAttributes.Public));
            }
            return result;
        }
        catch (Exception ex) when (ex is BadImageFormatException or InvalidOperationException) { return []; }
    }

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<byte[], TokenFreeImage> RenamedImages = new();

    /// <summary>The image with the top-level types <paramref name="fullNames"/> given unspeakable names; null when it cannot be rewritten. Cached per image.</summary>
    private static byte[]? WithTypesRenamed(byte[] image, HashSet<string> fullNames)
    {
        var key = string.Join(",", fullNames.Order(StringComparer.Ordinal));
        lock (RenamedImages)
        {
            if (RenamedImages.TryGetValue(image, out var cached) && cached.Names == key) return cached.Image;
            byte[]? result;
            try
            {
                using var module = ModuleDefMD.Load(image);
                foreach (var t in module.Types.Where(t => fullNames.Contains(t.FullName)))
                    t.Name = "<hidden>" + t.Name;
                using var ms = new MemoryStream();
                FaithfulWriter.WritePlain(module, ms);
                result = ms.ToArray();
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { result = null; }
            RenamedImages.AddOrUpdate(image, new TokenFreeImage(key, result));
            return result;
        }
    }

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<byte[], MetadataReference> References = new();

    /// <summary>One reference object per image: Roslyn reuses the symbols it read from it in later compilations.</summary>
    private static MetadataReference Reference(byte[] image) => References.GetValue(image, i => MetadataReference.CreateFromImage(i));

    /// <summary>The image with the public key tokens of its references to <paramref name="names"/> removed; null when it has none.</summary>
    private static byte[]? WithoutTokens(byte[] image, HashSet<string> names)
    {
        var key = string.Join(",", names.Order(StringComparer.OrdinalIgnoreCase));
        lock (TokenFreeImages)
        {
            if (TokenFreeImages.TryGetValue(image, out var cached) && cached.Names == key) return cached.Image;
            var result = RewriteWithoutTokens(image, names);
            TokenFreeImages.AddOrUpdate(image, new TokenFreeImage(key, result));
            return result;
        }
    }

    private sealed record TokenFreeImage(string Names, byte[]? Image);

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<byte[], TokenFreeImage> TokenFreeImages = new();

    private static byte[]? RewriteWithoutTokens(byte[] image, HashSet<string> names)
    {
        try
        {
            using (var pe = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(image, writable: false)))
            {
                var md = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
                if (!md.AssemblyReferences.Select(md.GetAssemblyReference).Any(r => !r.PublicKeyOrToken.IsNil && names.Contains(md.GetString(r.Name))))
                    return null;
            }
            using var module = ModuleDefMD.Load(image);
            foreach (var r in module.GetAssemblyRefs().Where(r => names.Contains(r.Name)))
                r.PublicKeyOrToken = new PublicKeyToken(Array.Empty<byte>());
            using var ms = new MemoryStream();
            FaithfulWriter.WritePlain(module, ms);
            return ms.ToArray();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null; // compile against it as it is
        }
    }

    /// <summary>Name suffix of the assembly a patch is compiled into (it references the target).</summary>
    internal const string PatchSuffix = ".__patch";

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<byte[], TokenFreeImage> FriendImages = new();

    /// <summary>
    /// The target image as a compile reference that grants the patch assembly access to its internals
    /// ([InternalsVisibleTo]). The decompiled declaration compiled with the patch is a separate assembly: its internal
    /// members using internal types of the target failed the accessibility consistency checks (CS0050-CS0061), which
    /// ignoring access checks does not cover. References to <paramref name="standIns"/> lose their public key token
    /// (see <see cref="WithoutTokens"/>). Only metadata is written: Roslyn reads no method body or resource of a
    /// reference, and rewriting them made the first patch of a large assembly take seconds. Cached per image.
    /// </summary>
    internal static byte[] FriendImage(byte[] image, string friend, HashSet<string> standIns)
    {
        var key = friend + "|" + string.Join(",", standIns.Order(StringComparer.OrdinalIgnoreCase));
        lock (FriendImages)
        {
            if (FriendImages.TryGetValue(image, out var cached) && cached.Names == key) return cached.Image!;
            // Metadata only, as a plain IL image (also for ReadyToRun and mixed-mode targets); else written as it is.
            var result = Friend(image, friend, standIns, metadataOnly: true) ?? Friend(image, friend, standIns, metadataOnly: false) ?? image;
            FriendImages.AddOrUpdate(image, new TokenFreeImage(key, result));
            return result;
        }
    }

    private static byte[]? Friend(byte[] image, string friend, HashSet<string> standIns, bool metadataOnly)
    {
        try
        {
            using var module = ModuleDefMD.Load(image);
            if (module.Assembly is not { } assembly) return image;
            foreach (var r in module.GetAssemblyRefs().Where(r => standIns.Contains(r.Name)))
                r.PublicKeyOrToken = new PublicKeyToken(Array.Empty<byte>());
            // The core library defines the attribute: a reference to it would give the core library an assembly reference, and Roslyn none.
            ICustomAttributeType ctor = module.Find("System.Runtime.CompilerServices.InternalsVisibleToAttribute", isReflectionName: false)?
                                            .FindMethod(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String)) is { } own
                ? own
                : new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
                    new TypeRefUser(module, "System.Runtime.CompilerServices", "InternalsVisibleToAttribute", module.CorLibTypes.AssemblyRef));
            assembly.CustomAttributes.Add(new CustomAttribute(ctor, [new CAArgument(module.CorLibTypes.String, friend)]));
            using var ms = new MemoryStream();
            if (metadataOnly)
            {
                foreach (var m in module.GetTypes().SelectMany(t => t.Methods))
                    m.Body = null;
                module.Resources.Clear();
                // Compiled code names the target's members by name, so its tokens need not be kept.
                module.Write(ms, new dnlib.DotNet.Writer.ModuleWriterOptions(module));
            }
            else FaithfulWriter.WritePlain(module, ms);
            return ms.ToArray();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null;
        }
    }

    /// <summary>
    /// Roslyn takes the core library to be the one assembly without references that defines System.Object, and finds
    /// none when there are two. A .NET target's closure has System.Private.CoreLib, while netstandard (and mscorlib)
    /// resolve to reference assemblies that define every type themselves, for the decompiler's sake. For compiling,
    /// such duplicates are replaced by the facade of the same name next to the core library, or dropped. Out-of-band
    /// packages in a System.Private.CoreLib closure (System.Memory for a netstandard library) define types the core
    /// library defines too (CS0433), so they are replaced by the runtime's own assemblies of the same name.
    /// </summary>
    private static List<MetadataReference> SingleCoreLibrary(List<MetadataReference> references, List<(string Name, byte[] Image, string Path)> images)
    {
        var cores = Enumerable.Range(0, images.Count).Where(i => IsCoreLibrary(images[i].Image)).ToList();
        if (cores.Count == 0) return references;
        string[] preference = ["System.Private.CoreLib", "mscorlib", "System.Runtime", "netstandard"];
        int Rank(int i) => Array.FindIndex(preference, n => string.Equals(n, images[i].Name, StringComparison.OrdinalIgnoreCase)) is var r and >= 0 ? r : preference.Length;
        int keep = cores.OrderBy(Rank).First();
        var dir = Path.GetDirectoryName(images[keep].Path);
        if (dir == null) return references;

        byte[]? Sibling(string name) => RuntimeFile(Path.Combine(dir, name + ".dll"));

        var replaced = new Dictionary<int, byte[]?>();
        foreach (int i in cores.Where(i => i != keep))
            replaced[i] = Sibling(images[i].Name) is { } facade && !IsCoreLibrary(facade) ? facade : null;
        if (string.Equals(images[keep].Name, "System.Private.CoreLib", StringComparison.OrdinalIgnoreCase))
            for (int i = 1; i < images.Count; i++) // 0 is the target
                if (i != keep && !replaced.ContainsKey(i) && !string.Equals(Path.GetDirectoryName(images[i].Path), dir, StringComparison.OrdinalIgnoreCase)
                    && Sibling(images[i].Name) is { } runtime)
                    replaced[i] = runtime;
        if (replaced.Count == 0) return references;
        var result = new List<MetadataReference>(references);
        foreach (var (i, bytes) in replaced.OrderByDescending(r => r.Key))
        {
            if (bytes != null) result[i] = MetadataReference.CreateFromImage(bytes);
            else result.RemoveAt(i);
        }
        return result;
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (DateTime Written, byte[]? Bytes)> RuntimeFiles = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>A file of the runtime folder, read once while unchanged: the same bytes keep their Roslyn reference (see <see cref="Reference"/>).</summary>
    private static byte[]? RuntimeFile(string file)
    {
        try
        {
            if (!File.Exists(file)) return null;
            var written = File.GetLastWriteTimeUtc(file);
            if (RuntimeFiles.TryGetValue(file, out var cached) && cached.Written == written) return cached.Bytes;
            var bytes = File.ReadAllBytes(file);
            RuntimeFiles[file] = (written, bytes);
            return bytes;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>Whether an image references no other assembly and defines System.Object.</summary>
    private static bool IsCoreLibrary(byte[] image)
    {
        try
        {
            using var pe = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(image, writable: false));
            var md = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
            if (md.AssemblyReferences.Count != 0) return false;
            foreach (var h in md.TypeDefinitions)
            {
                var t = md.GetTypeDefinition(h);
                if (md.StringComparer.Equals(t.Name, "Object") && md.StringComparer.Equals(t.Namespace, "System")) return true;
            }
            return false;
        }
        catch (BadImageFormatException) { return false; }
        catch (InvalidOperationException) { return false; }
    }

    private static string MemberName(SyntaxNode node) => node switch
    {
        MethodDeclarationSyntax m => m.Identifier.Text,
        PropertyDeclarationSyntax p => p.Identifier.Text,
        BaseTypeDeclarationSyntax t => t.Identifier.Text,
        ConstructorDeclarationSyntax => "constructor",
        _ => node.Kind().ToString(),
    };

    private static string FormatErrors(IEnumerable<Diagnostic> diagnostics, SyntaxTree tree, List<string> missing)
    {
        var userNodes = tree.GetRoot().GetAnnotatedNodes(UserCode).ToList();
        var lines = tree.GetText().Lines;
        var errors = diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error).ToList();

        SyntaxNode? UserNodeAt(Diagnostic d) =>
            d.Location.SourceTree == tree ? userNodes.FirstOrDefault(n => n.Span.Contains(d.Location.SourceSpan.Start)) : null;

        var sb = new StringBuilder($"C# compilation failed ({errors.Count} error(s)). Nothing was changed.\n");
        foreach (var d in errors.Take(20))
        {
            int line = d.Location.GetLineSpan().StartLinePosition.Line;
            var user = UserNodeAt(d);
            int start = user?.GetLocation().GetLineSpan().StartLinePosition.Line ?? 0;
            var where = user switch
            {
                null => $"decompiled context line {line + 1}",
                CompilationUnitSyntax => $"your code line {line + 1}",
                BlockSyntax => $"your code line {line - start}", // body is wrapped in a "{" line
                _ => $"line {line - start + 1} of your member {MemberName(user)}",
            };
            var text = d.Location.IsInSource ? lines[line].ToString().Trim() : "";
            sb.AppendLine($"  {d.Id} at {where}: {d.GetMessage()}{(text.Length > 0 ? $"\n      > {Format.Clip(text, 160)}" : "")}");
        }
        if (errors.Count > 20) sb.AppendLine($"  … {errors.Count - 20} more");
        if (errors.Any(e => UserNodeAt(e) == null))
            sb.AppendLine("Errors outside your code come from the decompiled declaration of the surrounding type (e.g. signatures the decompiler cannot express). If they persist, use patch_method_il.");
        if (missing.Count > 0)
            sb.AppendLine($"Unresolved references (load them or add_search_directory): {string.Join(", ", missing)}");
        return sb.ToString();
    }
}
