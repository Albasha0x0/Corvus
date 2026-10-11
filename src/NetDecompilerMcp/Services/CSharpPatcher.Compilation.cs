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
    private List<MetadataReference> BuildReferences(LoadedAssembly asm, byte[]? targetImage, out List<string> missing)
    {
        missing = new List<string>();
        var references = new List<MetadataReference>();
        var images = new List<(string Name, byte[] Image, string Path)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var stubbed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // References of each module resolve from its own folder first.
        var queue = new Queue<(ModuleDef Module, bool Owned, string Path)>();

        void Enqueue(string name, byte[] image, ModuleDef module, bool owned, string path)
        {
            if (!seen.Add(name)) { if (owned) module.Dispose(); return; }
            references.Add(MetadataReference.CreateFromImage(image));
            images.Add((name, image, path));
            queue.Enqueue((module, owned, path));
        }

        Enqueue(asm.AssemblyName, FriendImage(targetImage ?? asm.GetImageBytes(), asm.AssemblyName + PatchSuffix), asm.Module, owned: false, asm.FilePath);
        bool netFramework = Frameworks.TargetsNetFramework(asm.Module); // applies to the whole reference closure
        var targetFramework = Frameworks.TargetFrameworkOf(asm.Module);
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
        // A stand-in has no public key, so a reference naming one by its token does not bind to it (CS0012).
        for (int i = 0; i < images.Count && stubbed.Count > 0; i++)
            if (WithoutTokens(images[i].Image, stubbed) is { } image)
                references[i] = MetadataReference.CreateFromImage(image);
        return SingleCoreLibrary(references, images);
    }

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

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<byte[], byte[]> FriendImages = new();

    /// <summary>
    /// The target image as a compile reference that grants the patch assembly access to its internals
    /// ([InternalsVisibleTo]). The decompiled declaration compiled with the patch is a separate assembly: its internal
    /// members using internal types of the target failed the accessibility consistency checks (CS0050-CS0061), which
    /// ignoring access checks does not cover. Only the reference copy changes; cached per image.
    /// </summary>
    private static byte[] FriendImage(byte[] image, string friend)
    {
        lock (FriendImages)
        {
            if (FriendImages.TryGetValue(image, out var cached)) return cached;
            byte[] result;
            try
            {
                using var module = ModuleDefMD.Load(image);
                if (module.Assembly is not { } assembly) return image;
                // The core library defines the attribute: a reference to it would give the core library an assembly reference, and Roslyn none.
                ICustomAttributeType ctor = module.Find("System.Runtime.CompilerServices.InternalsVisibleToAttribute", isReflectionName: false)?
                                                .FindMethod(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String)) is { } own
                    ? own
                    : new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
                        new TypeRefUser(module, "System.Runtime.CompilerServices", "InternalsVisibleToAttribute", module.CorLibTypes.AssemblyRef));
                assembly.CustomAttributes.Add(new CustomAttribute(ctor, [new CAArgument(module.CorLibTypes.String, friend)]));
                using var ms = new MemoryStream();
                FaithfulWriter.WritePlain(module, ms);
                result = ms.ToArray();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                result = image; // unwritable image: compile against it as it is
            }
            FriendImages.AddOrUpdate(image, result);
            return result;
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

        byte[]? Sibling(string name)
        {
            var file = Path.Combine(dir, name + ".dll");
            try { return File.Exists(file) ? File.ReadAllBytes(file) : null; }
            catch (IOException) { return null; }
        }

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
