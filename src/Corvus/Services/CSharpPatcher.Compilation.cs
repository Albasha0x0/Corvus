using System.Reflection;
using System.Text;
using dnlib.DotNet;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Corvus.Core;

namespace Corvus.Services;

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
    private List<MetadataReference> BuildReferences(LoadedAssembly asm, byte[]? targetImage, out List<string> missing, CancellationToken ct, IReadOnlySet<string>? clashing = null)
    {
        var targetBytes = targetImage ?? asm.GetImageBytes();
        var closure = Closure(asm);
        missing = [.. closure.Missing];
        var images = closure.Images.ToList();
        var friend = FriendImage(targetBytes, asm.AssemblyName + PatchSuffix, closure.StandIns, ct);
        images[0] = (images[0].Name, friend, images[0].Path);
        var references = images.Select(i => Reference(i.Image)).ToList();
        if (clashing is { Count: > 0 }) HideClashingTypes(asm, images, references, clashing, ct);
        // The first compile of an assembly writes every reference copy it needs: seconds each for large ones.
        var copies = new byte[]?[images.Count];
        Parallel.For(1, images.Count, new ParallelOptions { CancellationToken = ct }, i => copies[i] = ReferenceCopy(images[i].Image, closure.StandIns, ct));
        for (int i = 1; i < images.Count; i++)
            if (copies[i] is { } image)
                references[i] = Reference(image);
        return SingleCoreLibrary(references, images);
    }

    /// <summary>
    /// The images of a target's reference closure (the target's own first, replaced by the caller), the names not found,
    /// and those resolved to stand-ins.
    /// </summary>
    private sealed record ReferenceClosure(int Generation, int Version, IReadOnlyList<(string Name, byte[] Image, string Path)> Images, IReadOnlyList<string> Missing,
        HashSet<string> StandIns);

    // Per assembly state: every compile of an edit and of the edits after it reads the same reference bytes, so Roslyn and
    // the reference copies below reuse what they made from them.
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedAssembly, ReferenceClosure> Closures = new();

    private ReferenceClosure Closure(LoadedAssembly asm)
    {
        if (Closures.TryGetValue(asm, out var cached) && cached.Generation == workspace.Generation && cached.Version == asm.Version) return cached;
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

        Enqueue(asm.AssemblyName, [], asm.Module, owned: false, asm.FilePath);
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
                    var bytes = target.Bytes ?? RuntimeFile(target.File!) ?? throw new IOException(target.File);
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
        var closure = new ReferenceClosure(workspace.Generation, asm.Version, images, missing, stubbed);
        Closures.AddOrUpdate(asm, closure);
        return closure;
    }

    /// <summary>
    /// Writes the target's reference copy (<see cref="FriendImage"/>) on another thread while the caller decompiles the
    /// shadow: for a large assembly both take seconds. The compile that needs it waits for it on the cache lock.
    /// </summary>
    private void PrefetchFriendImage(LoadedAssembly asm, CancellationToken ct)
    {
        var bytes = asm.GetImageBytes();
        var standIns = Closure(asm).StandIns;
        var friend = asm.AssemblyName + PatchSuffix;
        _ = Task.Run(() => FriendImage(bytes, friend, standIns, CancellationToken.None), ct);
    }

    /// <summary>
    /// References are imported with their internals, so a non-public top-level type defined under the same full name in two
    /// of them (System.SR is in most runtime libraries) is ambiguous (CS0433). The copy that counts is the target's own,
    /// else the one of the assembly the target references by that name, else the only public one; the other non-public
    /// copies (all of them when none is public and none is used) are renamed out of reach in their reference copies.
    /// </summary>
    private static void HideClashingTypes(LoadedAssembly asm, List<(string Name, byte[] Image, string Path)> images, List<MetadataReference> references,
        IReadOnlySet<string> clashing, CancellationToken ct)
    {
        var all = images.Select(i => TopLevelTypes(i.Image)).ToList();
        var defined = all.Select(types => types.Where(t => clashing.Contains(Format.StripArity(t.Name))).ToList()).ToList();
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
                Hide(i, name);
        }
        // CS0104 between a type of the target and one of a reference (System.Func, Lazy, Tuple in a library that predates them
        // and defines its own, compiled now against a newer framework): the target's type is the one its code meant.
        var own = all[0].Select(t => t.FullName).ToHashSet(StringComparer.Ordinal);
        foreach (var pair in clashing.Where(c => c.StartsWith(AmbiguousPrefix, StringComparison.Ordinal)))
        {
            var names = pair[AmbiguousPrefix.Length..].Split('|');
            if (names.Length != 2 || own.Contains(names[0]) == own.Contains(names[1])) continue;
            var other = own.Contains(names[0]) ? names[1] : names[0];
            for (int i = 1; i < images.Count; i++)
                if (all[i].Any(t => t.FullName == other)) Hide(i, other);
        }
        foreach (var (i, names) in hide)
            if (WithTypesRenamed(images[i].Image, names, ct) is { } renamed)
            {
                images[i] = (images[i].Name, renamed, images[i].Path);
                references[i] = Reference(renamed);
            }

        void Hide(int image, string name) => (hide.TryGetValue(image, out var set) ? set : hide[image] = new HashSet<string>(StringComparer.Ordinal)).Add(name);
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

    private static readonly DerivedImages RenamedImages = new();

    /// <summary>The image with the top-level types <paramref name="fullNames"/> given unspeakable names; null when it cannot be rewritten. Cached per image.</summary>
    private static byte[]? WithTypesRenamed(byte[] image, HashSet<string> fullNames, CancellationToken ct) =>
        RenamedImages.Get(image, string.Join(",", fullNames.Order(StringComparer.Ordinal)), () =>
        {
            try
            {
                return Rewritten(image, module =>
                {
                    foreach (var t in module.Types.Where(t => fullNames.Contains(t.FullName)))
                        t.Name = "<hidden>" + t.Name;
                });
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { return null; }
        }, ct);

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<byte[], MetadataReference> References = new();

    /// <summary>One reference object per image: Roslyn reuses the symbols it read from it in later compilations.</summary>
    private static MetadataReference Reference(byte[] image) => References.GetValue(image, i => MetadataReference.CreateFromImage(i));

    /// <summary>
    /// The image with the public key tokens of its references to <paramref name="names"/> removed (a stand-in has no public
    /// key, so a reference naming one by its token does not bind to it, CS0012) and any-version references reset (see
    /// <see cref="IsAnyVersion"/>); null when it needs neither.
    /// </summary>
    private static byte[]? ReferenceCopy(byte[] image, HashSet<string> names, CancellationToken ct) =>
        TokenFreeImages.Get(image, string.Join(",", names.Order(StringComparer.OrdinalIgnoreCase)), () => RewriteReferences(image, names), ct);

    private static readonly DerivedImages TokenFreeImages = new();

    private static byte[]? RewriteReferences(byte[] image, HashSet<string> names)
    {
        try
        {
            using (var pe = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(image, writable: false)))
            {
                var md = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
                if (!md.AssemblyReferences.Select(md.GetAssemblyReference).Any(r => (!r.PublicKeyOrToken.IsNil && names.Contains(md.GetString(r.Name))) || IsAnyVersion(r.Version)))
                    return null;
            }
            return Rewritten(image, module => FixReferences(module, names));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null; // compile against it as it is
        }
    }

    /// <summary>
    /// A compile reference changed by <paramref name="change"/>, written as metadata only: Roslyn reads no method body or
    /// resource of a reference, and writing them took seconds per large reference. Written as it is when that fails.
    /// </summary>
    private static byte[] Rewritten(byte[] image, Action<ModuleDefMD> change)
    {
        try
        {
            using var module = ModuleDefMD.Load(image);
            change(module);
            foreach (var m in module.GetTypes().SelectMany(t => t.Methods))
                m.Body = null;
            module.Resources.Clear();
            using var ms = new MemoryStream();
            // Compiled code names members by name, so tokens need not be kept.
            module.Write(ms, new dnlib.DotNet.Writer.ModuleWriterOptions(module));
            return ms.ToArray();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            using var module = ModuleDefMD.Load(image);
            change(module);
            using var ms = new MemoryStream();
            FaithfulWriter.WritePlain(module, ms);
            return ms.ToArray();
        }
    }

    private static void FixReferences(ModuleDef module, HashSet<string> standIns)
    {
        foreach (var r in module.GetAssemblyRefs())
        {
            if (standIns.Contains(r.Name)) r.PublicKeyOrToken = new PublicKeyToken(Array.Empty<byte>());
            if (IsAnyVersion(r.Version)) r.Version = new Version(0, 0, 0, 0);
        }
    }

    /// <summary>
    /// 65535.65535.65535.65535, written by some tools for "any version": taken literally, it needs a newer assembly than any
    /// that exists (CS1705), while version 0.0.0.0 binds to whichever is referenced.
    /// </summary>
    private static bool IsAnyVersion(Version? v) => v is { Major: 65535 };

    /// <summary>Name suffix of the assembly a patch is compiled into (it references the target).</summary>
    internal const string PatchSuffix = ".__patch";

    private static readonly DerivedImages FriendImages = new();

    /// <summary>
    /// The target image as a compile reference that grants the patch assembly access to its internals
    /// ([InternalsVisibleTo]). The decompiled declaration compiled with the patch is a separate assembly: its internal
    /// members using internal types of the target failed the accessibility consistency checks (CS0050-CS0061), which
    /// ignoring access checks does not cover. References to <paramref name="standIns"/> lose their public key token
    /// and any-version references are reset (see <see cref="ReferenceCopy"/>). Only metadata is written: Roslyn reads no method body or resource of a
    /// reference, and rewriting them made the first patch of a large assembly take seconds. Cached per image.
    /// </summary>
    internal static byte[] FriendImage(byte[] image, string friend, HashSet<string> standIns, CancellationToken ct) =>
        FriendImages.Get(image, friend + "|" + string.Join(",", standIns.Order(StringComparer.OrdinalIgnoreCase)),
            // Metadata only, as a plain IL image (also for ReadyToRun and mixed-mode targets); else written as it is.
            () => Friend(image, friend, standIns, metadataOnly: true) ?? Friend(image, friend, standIns, metadataOnly: false) ?? image, ct)!;

    private static byte[]? Friend(byte[] image, string friend, HashSet<string> standIns, bool metadataOnly)
    {
        try
        {
            using var module = ModuleDefMD.Load(image);
            if (module.Assembly is not { } assembly) return image;
            FixReferences(module, standIns);
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

    /// <summary>
    /// Images made from an image and a key, once per pair while the image lives. Each is made outside any lock: a caller
    /// waiting for another thread's result (seconds for a large assembly) stops when its call is cancelled.
    /// </summary>
    internal sealed class DerivedImages
    {
        private sealed record Entry(string Key, TaskCompletionSource<byte[]?> Done);

        private readonly System.Runtime.CompilerServices.ConditionalWeakTable<byte[], Entry> _entries = new();

        public byte[]? Get(byte[] image, string key, Func<byte[]?> make, CancellationToken ct)
        {
            while (true)
            {
                Entry entry;
                bool mine = false;
                lock (_entries)
                {
                    if (!_entries.TryGetValue(image, out entry!) || entry.Key != key)
                    {
                        entry = new Entry(key, new TaskCompletionSource<byte[]?>(TaskCreationOptions.RunContinuationsAsynchronously));
                        _entries.AddOrUpdate(image, entry);
                        mine = true;
                    }
                }
                if (mine)
                {
                    try { entry.Done.SetResult(make()); }
                    catch (Exception ex)
                    {
                        lock (_entries)
                            if (_entries.TryGetValue(image, out var current) && ReferenceEquals(current, entry)) _entries.Remove(image);
                        entry.Done.SetException(ex);
                        throw;
                    }
                }
                try { entry.Done.Task.Wait(ct); }
                catch (AggregateException) { continue; } // the maker failed: make it here
                return entry.Done.Task.Result;
            }
        }
    }

    private static string MemberName(SyntaxNode node) => node switch
    {
        MethodDeclarationSyntax m => m.Identifier.Text,
        PropertyDeclarationSyntax p => p.Identifier.Text,
        BaseTypeDeclarationSyntax t => t.Identifier.Text,
        ConstructorDeclarationSyntax => "constructor",
        _ => node.Kind().ToString(),
    };

    private const string CompileFailed = "C# compilation failed";
    private const string ContextErrors = "Errors outside your code";

    /// <summary>A failed body compile with the next step for its diagnostics, naming the patched method.</summary>
    internal static ToolError WithPatchNext(ToolError error, ResolvedSymbol target)
    {
        if (error.Code != ErrorCode.InvalidArgument || !error.Message.StartsWith(CompileFailed, StringComparison.Ordinal) || target.Member is not MethodDef method)
            return error;
        var ids = System.Text.RegularExpressions.Regex.Matches(error.Message, @"^\s+(CS\d{4}) at ", System.Text.RegularExpressions.RegexOptions.Multiline)
            .Select(m => m.Groups[1].Value).ToHashSet(StringComparer.Ordinal);
        var label = target.Label;
        var steps = new List<string>();
        if (ids.Contains("CS0127")) steps.Add($"{label} returns void: use 'return;' without a value");
        if (ids.Contains("CS0126")) steps.Add($"{label} returns {method.ReturnType.TypeName}: use 'return <value>;'");
        if (ids.Contains("CS0656"))
            steps.Add($"the references {target.Assembly.Id} compiles against lack a member the compiler needs: add_search_directory with the framework folder the app ships, then patch {label} again");
        if (ids.Contains("CS1705"))
            steps.Add($"a reference resolved older than the one {target.Assembly.Id} was built against: add_search_directory with the framework folder it targets");
        if (ids.Overlaps(["CS0102", "CS0111", "CS0542"]))
            steps.Add($"the decompiled {method.DeclaringType.Name} has colliding (obfuscated) member names: rename_symbol them first");
        if (error.Message.Contains(ContextErrors, StringComparison.Ordinal))
            steps.Add($"{(steps.Count > 0 ? "or " : "")}patch {label} with patch_method_il (its body does not depend on the decompiled type)");
        if (steps.Count == 0)
            steps.Add($"fix the body for {label} ({Format.MemberLabel(method)}) and call again");
        return new ToolError(error.Code, error.Message, string.Join("; ", steps)) { Details = error.Details, Partial = error.Partial };
    }

    private static string FormatErrors(IEnumerable<Diagnostic> diagnostics, SyntaxTree tree, List<string> missing)
    {
        var userNodes = tree.GetRoot().GetAnnotatedNodes(UserCode).ToList();
        var lines = tree.GetText().Lines;
        var errors = diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error).ToList();

        SyntaxNode? UserNodeAt(Diagnostic d) =>
            d.Location.SourceTree == tree ? userNodes.FirstOrDefault(n => n.Span.Contains(d.Location.SourceSpan.Start)) : null;

        var sb = new StringBuilder($"{CompileFailed} ({errors.Count} error(s)). Nothing was changed.\n");
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
            sb.AppendLine(ContextErrors + " come from the decompiled declaration of the surrounding type (e.g. signatures the decompiler cannot express). If they persist, use patch_method_il.");
        if (missing.Count > 0)
            sb.AppendLine($"Unresolved references (load them or add_search_directory): {string.Join(", ", missing)}");
        return sb.ToString();
    }
}
