using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using Syn = ICSharpCode.Decompiler.CSharp.Syntax;
using System.Text;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.ProjectDecompiler;
using ICSharpCode.Decompiler.Disassembler;
using ICSharpCode.Decompiler.TypeSystem;
using Corvus.Core;
using Dn = dnlib.DotNet;

namespace Corvus.Services;

/// <summary>C# decompilation and IL disassembly via the ILSpy engine (ICSharpCode.Decompiler).</summary>
public sealed class DecompilerService(AssemblyWorkspace workspace, ServerOptions options)
{
    // Weak keys: entries are collected with their assembly.
    private readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedAssembly, TypeSystemEntry> _typeSystems = new();

    private sealed record TypeSystemEntry(string Key, DecompilerTypeSystem TypeSystem);

    /// <summary>Documentation for no entity: output never shows XML documentation.</summary>
    internal sealed class NoDocumentation : ICSharpCode.Decompiler.Documentation.IDocumentationProvider
    {
        public static readonly NoDocumentation Instance = new();

        public string? GetDocumentation(IEntity entity) => null;
    }

    public static DecompilerSettings CreateSettings() => new(LanguageVersion.Latest)
    {
        ThrowOnAssemblyResolveErrors = false,
        ShowXmlDocumentation = false,
        LoadInMemory = true,
        UseSdkStyleProjectFormat = true,
    };

    internal DecompilerTypeSystem GetTypeSystem(LoadedAssembly asm)
    {
        var key = TypeSystemKey();
        if (_typeSystems.TryGetValue(asm, out var entry) && entry.Key == key)
            return entry.TypeSystem;
        var ts = new DecompilerTypeSystem(asm.GetPEFile(), workspace.CreateDecompilerResolver(asm), CreateSettings());
        _typeSystems.AddOrUpdate(asm, new TypeSystemEntry(key, ts));
        return ts;
    }

    /// <summary>The type systems' cache key: loaded assemblies with their edit versions, and the search directories.</summary>
    internal string TypeSystemKey()
    {
        var sb = new StringBuilder();
        foreach (var a in workspace.Assemblies)
            sb.Append(a.Id).Append(':').Append(a.Version).Append(':').Append(System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(a)).Append('|');
        foreach (var d in workspace.SearchDirectories) sb.Append(d).Append('|');
        return sb.ToString();
    }

    private CSharpDecompiler CreateDecompiler(LoadedAssembly asm, CancellationToken token, bool compilable = false)
    {
        // Workaround for icsharpcode/ILSpy#4275 (tested 11.1.0.9782; fixed in: pending): XML docs are read though off.
        var decompiler = new CSharpDecompiler(GetTypeSystem(asm), CreateSettings()) { CancellationToken = token, DocumentationProvider = NoDocumentation.Instance };
        AstCleanup.AddTo(decompiler, Frameworks.TargetFrameworkOf(asm.Module));
        // Compiler-generated names (<>c__DisplayClass1_0, <Run>d__4) shown as nested types do not parse as C#.
        if (compilable) decompiler.AstTransforms.Add(new ICSharpCode.Decompiler.CSharp.Transforms.EscapeInvalidIdentifiers());
        return decompiler;
    }

    /// <summary>Decompiles a whole type, falling back to member-by-member output if the engine fails on the type.</summary>
    /// <param name="compilable">Escape identifiers C# cannot express, for source that is compiled again (C# patches).</param>
    public string DecompileType(LoadedAssembly asm, Dn.TypeDef type, CancellationToken ct, bool compilable = false) => InvalidBodiesNote(asm, type) + WithTimeout(token =>
    {
        var decompiler = CreateDecompiler(asm, token, compilable);
        try
        {
            // The name API emits the namespace and usings; decompiling by handle does not. Nested and
            // compiler-generated types (empty from the name API) use the handle.
            if (type.DeclaringType == null)
            {
                var withNamespace = Print(decompiler.DecompileType(new FullTypeName(type.ReflectionFullName)));
                if (!string.IsNullOrWhiteSpace(withNamespace))
                    return withNamespace;
            }
            return Print(decompiler.Decompile(Handle(asm, type)));
        }
        catch (Exception ex) when (ex is not (OperationCanceledException or ToolError { Code: ErrorCode.LimitExceeded }))
        {
            var sb = new StringBuilder();
            sb.AppendLine($"// Whole-type decompilation failed ({ex.GetType().Name}: {FirstLine(ex.Message)}); decompiling members individually.");
            sb.AppendLine($"// {Format.TypeHeader(type)}");
            var trees = new Dictionary<Dn.TypeDef, Syn.SyntaxTree>();
            var members = type.Fields.Cast<Dn.IMemberDef>().Concat(type.Properties).Concat(type.Events)
                .Concat(type.Methods.Where(m => !m.IsGetter && !m.IsSetter && !m.IsAddOn && !m.IsRemoveOn))
                .Concat(type.NestedTypes);
            foreach (var m in members)
            {
                token.ThrowIfCancellationRequested();
                sb.AppendLine(DecompileMemberSafe(asm, m, decompiler, token, trees));
            }
            return sb.ToString();
        }
    }, ct);

    /// <summary>A note for a normalized view and a warning for invalid method bodies; empty otherwise.</summary>
    private static string InvalidBodiesNote(LoadedAssembly asm, Dn.TypeDef type)
    {
        // Decides whether the view is normalized.
        asm.GetPEFile();
        if (asm.IsDirty || asm.BodyHealth.Invalid == 0) return asm.DecompilerNote;
        var methods = type.Methods.Where(m => m.RVA != 0).ToList();
        int invalid = methods.Count(asm.BodyHealth.IsInvalid);
        return asm.DecompilerNote + (invalid == 0 ? "" : $"// Warning: {invalid} of {methods.Count} method bodies of this type are not valid IL (encrypted, or dumped before decryption): their code below is meaningless.\n");
    }

    /// <summary>Decompiles each member, falling back to IL for any member that fails.</summary>
    public string DecompileMembers(LoadedAssembly asm, IEnumerable<Dn.IMemberDef> members, CancellationToken ct) => WithTimeout(token =>
    {
        var decompiler = CreateDecompiler(asm, token);
        // Constructors shown in their type decompile the type once for all of them.
        var trees = new Dictionary<Dn.TypeDef, Syn.SyntaxTree>();
        var parts = members.Select(m => DecompileMemberSafe(asm, m, decompiler, token, trees));
        return asm.DecompilerNote + string.Join("\n", parts);
    }, ct);

    /// <summary>
    /// A constructor shown in its type with the initializers the engine moved out of its body; null when there are none.
    /// </summary>
    private static string? ConstructorInContext(LoadedAssembly asm, Dn.MethodDef ctor, CSharpDecompiler decompiler, Dictionary<Dn.TypeDef, Syn.SyntaxTree> trees)
    {
        if (!MayHaveInitializers(ctor)) return null;
        if (!trees.TryGetValue(ctor.DeclaringType, out var whole))
            trees[ctor.DeclaringType] = whole = decompiler.Decompile(Handle(asm, ctor.DeclaringType));
        var tree = (Syn.SyntaxTree)whole.Clone();
        var declaration = tree.Descendants.OfType<Syn.TypeDeclaration>().FirstOrDefault(t =>
            t.GetSymbol() is ITypeDefinition td && !td.MetadataToken.IsNil && MetadataTokens.GetToken(td.MetadataToken) == (int)asm.ImageToken(ctor.DeclaringType));
        if (declaration == null) return null;
        bool isStatic = ctor.IsStatic;
        bool Initialized(Syn.EntityDeclaration m) => m.HasModifier(Syn.Modifiers.Static) == isStatic && m switch
        {
            Syn.FieldDeclaration f => f.Variables.Any(v => v.Initializer is not null),
            Syn.PropertyDeclaration p => p.Initializer is not null,
            Syn.EventDeclaration e => e.Variables.Any(v => v.Initializer is not null),
            _ => false,
        };
        bool primary = !isStatic && declaration.PrimaryConstructorParameters.Count > 0;
        if (!primary && !declaration.Members.Any(Initialized)) return null;

        foreach (var m in declaration.Members.ToList())
            if (!(m is Syn.ConstructorDeclaration c && c.HasModifier(Syn.Modifiers.Static) == isStatic || Initialized(m)))
                m.Remove();
        using var writer = new StringWriter();
        tree.AcceptVisitor(new ICSharpCode.Decompiler.CSharp.OutputVisitor.CSharpOutputVisitor(writer,
            ICSharpCode.Decompiler.CSharp.OutputVisitor.FormattingOptionsFactory.CreateAllman()));
        return $"// {(primary ? "a primary constructor" : isStatic ? "static field initializers" : "field initializers")}: " +
               $"they run as part of this constructor{(isStatic ? "" : ", before the base constructor")}, so the type is shown around it\n" +
               writer.ToString().TrimEnd() + "\n";
    }

    /// <summary>
    /// Whether the constructor stores an own field before its base or this(...) call, so the engine may move it to initializers.
    /// </summary>
    private static bool MayHaveInitializers(Dn.MethodDef ctor)
    {
        var type = ctor.DeclaringType;
        bool Own(object? operand) => MetadataUtil.AsField(operand) is { } f && f.DeclaringType is { } owner && Dn.TypeEqualityComparer.Instance.Equals(owner, type);
        foreach (var instr in MetadataUtil.SafeInstructions(ctor))
        {
            if (instr.OpCode.Code is Dn.Emit.Code.Stfld or Dn.Emit.Code.Stsfld && Own(instr.Operand)) return true;
            // The base or this(...) call ends what can become initializers (a struct has none, so it is read to the end).
            if (!ctor.IsStatic && instr.OpCode.Code == Dn.Emit.Code.Call && MetadataUtil.AsMethod(instr.Operand) is { Name.String: ".ctor" }) return false;
        }
        return false;
    }

    private string DecompileMemberSafe(LoadedAssembly asm, Dn.IMemberDef member, CSharpDecompiler decompiler, CancellationToken token,
        Dictionary<Dn.TypeDef, Syn.SyntaxTree> trees)
    {
        var header = $"// {Format.MemberLabel(member)}  [token {Format.Token(member)}]";
        if (MetadataUtil.IsReferenceAssembly(asm.Module))
            header += "\n// Note: reference assembly; bodies are `throw null` (load the implementation from lib/).";
        if (member is Dn.MethodDef method && !asm.IsDirty && asm.BodyHealth.IsInvalid(method))
            header += "\n// Warning: this method body is not valid IL (encrypted, or dumped before decryption): the code below is meaningless.";
        try
        {
            if (member is Dn.MethodDef { IsConstructor: true } ctor && ConstructorInContext(asm, ctor, decompiler, trees) is { } inContext)
                return header + "\n" + inContext;
            // An accessor decompiles to a bare block; its property or event names it.
            if (member is Dn.MethodDef accessor && AccessorOwner(accessor) is { } owner)
                return header + $"\n// accessor of {owner.Name}, shown in it\n" + Print(decompiler.Decompile(Handle(asm, owner))).TrimEnd() + "\n";
            return header + "\n" + Print(decompiler.Decompile(Handle(asm, member))).TrimEnd() + "\n";
        }
        catch (Exception ex) when (ex is not (OperationCanceledException or ToolError { Code: ErrorCode.LimitExceeded }))
        {
            var sb = new StringBuilder(header).AppendLine();
            sb.AppendLine($"// C# decompilation failed: {ex.GetType().Name}: {FirstLine(ex.Message)}");
            sb.AppendLine("// IL fallback:");
            try { sb.AppendLine(Disassemble(asm, member, token)); }
            catch (Exception ilEx) when (ilEx is not OperationCanceledException) { sb.AppendLine($"// IL disassembly also failed: {FirstLine(ilEx.Message)}"); }
            return sb.ToString();
        }
    }

    /// <summary>The syntax tree as C# text, as the decompiler prints it, bounded by <see cref="BoundedWriter"/>.</summary>
    private static string Print(Syn.SyntaxTree tree)
    {
        using var writer = new BoundedWriter();
        tree.AcceptVisitor(new ICSharpCode.Decompiler.CSharp.OutputVisitor.CSharpOutputVisitor(writer, CreateSettings().CSharpFormattingOptions));
        return writer.ToString();
    }

    private static Dn.IMemberDef? AccessorOwner(Dn.MethodDef method) =>
        !method.IsSpecialName || method.DeclaringType is not { } type ? null
            : (Dn.IMemberDef?)type.Properties.FirstOrDefault(p => p.GetMethods.Contains(method) || p.SetMethods.Contains(method))
              ?? type.Events.FirstOrDefault(e => e.AddMethod == method || e.RemoveMethod == method || e.InvokeMethod == method);

    public string DecompileAssemblyAttributes(LoadedAssembly asm, CancellationToken ct) => WithTimeout(token =>
    {
        var decompiler = CreateDecompiler(asm, token);
        return asm.DecompilerNote + Print(decompiler.DecompileModuleAndAssemblyAttributes());
    }, ct);

    /// <summary>ildasm-style IL with metadata tokens and resolved operands; <paramref name="pdb"/> adds its source lines and local names.</summary>
    public string Disassemble(LoadedAssembly asm, Dn.IMemberDef member, CancellationToken ct, PortablePdb? pdb = null)
    {
        var output = new PlainTextOutput(new BoundedWriter());
        var dis = new ReflectionDisassembler(output, ct)
        {
            DetectControlStructure = true,
            ShowSequencePoints = pdb != null,
            DebugInfo = pdb,
            ShowMetadataTokens = true,
            ExpandMemberDefinitions = true,
        };
        var pe = asm.GetPEFile();
        var handle = Handle(asm, member);
        switch (handle.Kind)
        {
            case HandleKind.TypeDefinition: dis.DisassembleType(pe, (TypeDefinitionHandle)handle); break;
            case HandleKind.MethodDefinition: dis.DisassembleMethod(pe, (MethodDefinitionHandle)handle); break;
            case HandleKind.FieldDefinition: dis.DisassembleField(pe, (FieldDefinitionHandle)handle); break;
            case HandleKind.PropertyDefinition: dis.DisassembleProperty(pe, (PropertyDefinitionHandle)handle); break;
            case HandleKind.EventDefinition: dis.DisassembleEvent(pe, (EventDefinitionHandle)handle); break;
            default: throw new ToolError(ErrorCode.Unsupported, $"Cannot disassemble {member.GetType().Name}.");
        }
        return asm.DecompilerNote + (pdb != null ? PortablePdb.Compact(output.ToString()) : output.ToString());
    }

    /// <summary>
    /// Decompiles members as simplify_methods would leave them: the passes run on a scratch copy of the current image,
    /// so the loaded assembly does not change. Types include the methods of their nested types.
    /// </summary>
    public string DecompileSimplified(LoadedAssembly asm, IReadOnlyList<Dn.IMemberDef> members, Simplify.SimplifyOptions options, CancellationToken ct)
    {
        var image = asm.GetImageBytes();
        var tokens = members.Select(asm.ImageToken).ToList();
        byte[]? simplified = null;
        List<Simplify.MethodChange> changes;
        using (var scratch = new LoadedAssembly(asm.Id, asm.FilePath, image, LoadScratch(image, asm.FilePath)))
        {
            var methods = tokens.Select(t => scratch.Module.ResolveToken(t)).SelectMany(MethodsOf).Distinct().ToList();
            changes = new Simplify.MethodSimplifier(scratch.Module, options).Run(methods, ct);
            foreach (var c in changes.Where(c => c.Changed)) c.Method.Body = c.NewBody!;
            // Nothing changed: the loaded assembly is the view (writing and loading a large image costs seconds).
            if (changes.Any(c => c.Changed)) simplified = scratch.WriteToBytes();
        }

        string text;
        if (simplified == null) text = members is [Dn.TypeDef only] ? DecompileType(asm, only, ct) : DecompileMembers(asm, members, ct);
        else
        {
            using var view = new LoadedAssembly(asm.Id, asm.FilePath, simplified, LoadScratch(simplified, asm.FilePath));
            var viewMembers = tokens.Select(t => view.Module.ResolveToken(t) as Dn.IMemberDef
                                                 ?? throw new ToolError($"Member 0x{t:X8} is missing from the simplified image.")).ToList();
            text = viewMembers is [Dn.TypeDef type] ? DecompileType(view, type, ct) : DecompileMembers(view, viewMembers, ct);
        }

        var changed = changes.Where(c => c.Changed).ToList();
        var summary = $"// Simplified view ({options.Describe()}; the assembly is unchanged): {changed.Count} of {changes.Count} method(s) simplified";
        int folded = changed.Sum(c => c.Folded.Count), inlined = changed.Sum(c => c.Inlined.Count), branches = changed.Sum(c => c.ConstantBranches);
        int dispatchers = changed.Sum(c => c.Dispatchers);
        int blocks = changed.Sum(c => c.RemovedBlocks), bailed = changes.Sum(c => c.Bailouts.Count);
        int skipped = changes.Sum(c => c.Skipped.Count);
        var parts = new[] { (folded, "call(s) folded"), (inlined, "forwarder call(s) inlined"), (branches, "constant branch(es) folded"),
                            (dispatchers, "switch dispatcher(s) normalized"),
                            (blocks, "unreachable block(s) removed"), (bailed, "call(s) not evaluable"), (skipped, "switch dispatcher(s) kept") }
            .Where(p => p.Item1 > 0).Select(p => $"{p.Item1} {p.Item2}").ToList();
        if (parts.Count > 0) summary += ": " + string.Join(", ", parts);
        return summary + ".\n" + text;

        static IEnumerable<Dn.MethodDef> MethodsOf(object? member) => member switch
        {
            Dn.MethodDef m => [m],
            Dn.TypeDef t => t.Methods.Concat(t.NestedTypes.SelectMany(MethodsOf)),
            Dn.PropertyDef p => p.GetMethods.Concat(p.SetMethods).Concat(p.OtherMethods),
            Dn.EventDef e => new[] { e.AddMethod, e.RemoveMethod, e.InvokeMethod }.OfType<Dn.MethodDef>(),
            _ => [],
        };
    }

    private Dn.ModuleDefMD LoadScratch(byte[] image, string location)
    {
        var module = MetadataRows.Load(image, workspace.DnlibContext);
        module.Location = location;
        module.EnableTypeDefFindCache = true;
        return module;
    }

    /// <summary>XAML from a BAML resource, or null on failure.</summary>
    public string? DecompileBaml(LoadedAssembly asm, byte[] baml, CancellationToken ct)
    {
        try
        {
            var decompiler = new ICSharpCode.BamlDecompiler.XamlDecompiler((ICSharpCode.Decompiler.Metadata.PEFile)asm.GetPEFile(),
                workspace.CreateDecompilerResolver(asm), new ICSharpCode.BamlDecompiler.BamlDecompilerSettings()) { CancellationToken = ct };
            return decompiler.Decompile(new MemoryStream(baml, writable: false)).Xaml.ToString();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null;
        }
    }

    public sealed record ExportResult(string Directory, int FileCount, string? ProjectFile, IReadOnlyList<string> FailedTypes)
    {
        /// <summary>A previous export in the directory was replaced.</summary>
        public bool Replaced { get; init; }

        /// <summary>References written under a stub name, one line each; empty when every name was safe.</summary>
        public IReadOnlyList<string> Renamed { get; init; } = [];
    }

    /// <summary>
    /// Classifies references for the project writer: .NET shared-framework assemblies map to a runtime pack, .NET
    /// Framework assemblies are referenced by name, and everything else gets a HintPath.
    /// </summary>
    private sealed class FrameworkClassifier(bool netFramework, int? targetMajor, IReadOnlyList<string>? netFrameworkReferences)
        : ICSharpCode.Decompiler.Metadata.AssemblyReferenceClassifier
    {
        // Only assemblies present in the target's reference assemblies; e.g. System.Runtime.WindowsRuntime is in the GAC but not there.
        public override bool IsGacAssembly(ICSharpCode.Decompiler.Metadata.IAssemblyReference reference) =>
            netFramework && (reference.Name is "mscorlib" or "netstandard"
                             || (netFrameworkReferences != null
                                 ? netFrameworkReferences.Any(d => File.Exists(Path.Combine(d, reference.Name + ".dll")))
                                 : Frameworks.IsNetFrameworkAssembly(reference.Name)));

        public override bool IsSharedAssembly(ICSharpCode.Decompiler.Metadata.IAssemblyReference reference,
            [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? runtimePack)
        {
            // Checked against the targeted framework version, not the newest installed.
            runtimePack = netFramework ? null : Frameworks.SharedFrameworkOf(reference.Name, targetMajor)
                ?? (reference.Name is "netstandard" or "mscorlib" ? "Microsoft.NETCore.App" : null);
            // A plain SDK project lacks the ASP.NET Core framework; reference those files directly.
            if (runtimePack == "Microsoft.AspNetCore.App") runtimePack = null;
            return runtimePack != null;
        }
    }

    /// <summary>
    /// Writes a buildable C# project to an empty directory, or over a previous export with <paramref name="overwrite"/>;
    /// a failed or cancelled export leaves no output. Call without the workspace lock: it works on a snapshot taken under the shared lock.
    /// </summary>
    public ExportResult ExportProject(LoadedAssembly asm, string outputDirectory, Action<int, int, string>? onProgress, CancellationToken ct,
        bool overwrite = false)
    {
        using var output = ExportDirectory.Begin(outputDirectory, overwrite);
        using var snapshot = workspace.Read(() => ExportSnapshot.Take(workspace, asm), ct);
        var (project, failed) = Export(snapshot, output.Staging, onProgress, ct);
        var files = output.Commit();
        return new ExportResult(output.Final, files.Count, project == null ? null : output.ToFinal(project), failed)
        {
            Replaced = output.Replace,
            Renamed = snapshot.Names.Notes(),
        };
    }

    /// <summary>Exports <paramref name="snapshot"/> into <paramref name="dir"/>: the project file (or null) and the types that failed.</summary>
    private (string? Project, List<string> Failed) Export(ExportSnapshot snapshot, string dir, Action<int, int, string>? onProgress, CancellationToken ct)
    {
        // Project export gets 10x the normal timeout.
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(options.TimeoutSeconds * 10L));
        // Method-call LINQ: query syntax reconstruction can leak compiler names (<>h__TransparentIdentifier0).
        var exportSettings = CreateSettings();
        exportSettings.QueryExpressions = false;
        var framework = snapshot.Framework;
        bool netFramework = snapshot.NetFramework;
        var exporter = new ProjectExporter(framework, exportSettings, snapshot.Resolver(cts.Token), null,
            new FrameworkClassifier(netFramework, Frameworks.NetCoreMajor(framework), Frameworks.NetFrameworkReferenceDirs(framework)), null);
        if (onProgress != null)
            exporter.ProgressIndicator = new InlineProgress<DecompilationProgress>(p => onProgress(p.UnitsCompleted, p.TotalUnits, p.Status ?? "Decompiling"));
        try
        {
            exporter.DecompileProject(snapshot.Main, dir, cts.Token);
        }
        catch (NotSupportedException ex)
        {
            throw new ToolError(ErrorCode.Unsupported, $"{snapshot.Id} targets {framework ?? "a framework"} that an SDK-style project cannot express " +
                $"(portable profiles such as Profile328): {ex.Message}", "decompile_member writes a type as source; a build of the same library for .NET Standard or .NET Framework exports");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            int written = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).Count();
            throw new ToolError(ErrorCode.Timeout, $"Project export timed out after {options.TimeoutSeconds * 10}s with {written} files written; nothing was kept.",
                "decompile the types needed with decompile_member, or restart the server with a larger --timeout")
            {
                Partial = new { filesWritten = written },
            };
        }
        RenameUnsafeReferences(dir, snapshot.Names);
        if (snapshot.Inferred != null) UseInferredFramework(dir, snapshot.Inferred);
        FixFrameworkFileReferences(dir, framework, netFramework, snapshot.References.GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => (Version?)g.Max(r => r.Version), StringComparer.OrdinalIgnoreCase));
        IncludeEmbeddedReferences(snapshot, dir, ct);
        AddTransitiveReferences(snapshot, dir, framework, netFramework, ct);
        ThrowInFailedBodies(dir);
        UseUnionWindowsMetadata(dir);
        KeepIdentity(snapshot, dir);
        UsePreserializedResources(dir);
        var project = Directory.EnumerateFiles(dir, "*.csproj").FirstOrDefault();
        return (project, exporter.Errors.Select(e => FirstLine(e.Message)).ToList());
    }

    /// <summary>
    /// What an export reads, copied under the shared lock; references resolve to private copies disposed with the snapshot.
    /// </summary>
    private sealed class ExportSnapshot : IDisposable
    {
        private readonly AssemblyWorkspace _workspace;
        private readonly List<ICSharpCode.Decompiler.Metadata.MetadataFile> _owned = [];

        private ExportSnapshot(AssemblyWorkspace workspace, LoadedAssembly asm)
        {
            _workspace = workspace;
            var module = asm.Module;
            Id = asm.Id;
            FilePath = asm.FilePath;
            AssemblyName = asm.AssemblyName;
            OriginalBytes = asm.OriginalBytes;
            Main = Own(Copy(asm.GetPEFile()));
            Inferred = Frameworks.InferTargetFramework(module);
            Framework = Frameworks.TargetFrameworkOf(module) ?? Inferred;
            NetFramework = Framework != null ? Framework.StartsWith(".NETFramework", StringComparison.OrdinalIgnoreCase) : Frameworks.TargetsNetFramework(module);
            TargetsNetFramework = Frameworks.TargetsNetFramework(module);
            ResolvesAsNetFramework = Frameworks.ResolvesAsNetFramework(module);
            RequesterFramework = Frameworks.RequesterFramework(module);
            References = module.GetAssemblyRefs().Select(r => (r.Name.String, r.Version, r.PublicKeyOrToken?.Token?.Data)).ToList();
            EntryType = module.EntryPoint?.DeclaringType?.ReflectionFullName;
            PublicKey = module.Assembly?.PublicKey is { IsNullOrEmpty: false } key ? key.Data : null;
            SearchDirectories = [.. workspace.SearchDirectories];
            Names = new ReferenceNames(References.Select(r => r.Name).Append(AssemblyName));
        }

        public static ExportSnapshot Take(AssemblyWorkspace workspace, LoadedAssembly asm)
        {
            if (!workspace.Assemblies.Contains(asm))
                throw new ToolError(ErrorCode.NotLoaded, $"{asm.Id} is no longer loaded.", "list_assemblies shows what is loaded; load it again");
            return new ExportSnapshot(workspace, asm);
        }

        public string Id { get; }
        public string FilePath { get; }
        public string AssemblyName { get; }
        public byte[] OriginalBytes { get; }
        public ICSharpCode.Decompiler.Metadata.PEFile Main { get; }
        public string? Inferred { get; }
        public string? Framework { get; }
        public bool NetFramework { get; }
        public bool TargetsNetFramework { get; }
        public bool ResolvesAsNetFramework { get; }
        public string? RequesterFramework { get; }
        public List<(string Name, Version Version, byte[]? Token)> References { get; }
        public string? EntryType { get; }
        public byte[]? PublicKey { get; }
        public string[] SearchDirectories { get; }
        public ReferenceNames Names { get; }

        /// <summary><see cref="AssemblyWorkspace.LocateReference"/> under the shared lock, reduced to what it yields without the lock.</summary>
        public T Locate<T>(string name, Version? version, byte[]? token, string? requester, bool netFramework, string? framework,
            Func<AssemblyWorkspace.ReferenceTarget?, T> take, CancellationToken ct) =>
            _workspace.Read(() => take(_workspace.LocateReference(name, version, token, requester, netFramework, framework)), ct);

        /// <summary>A private copy of a reader's image (a loaded assembly's reader is replaced or disposed by edits and unloads).</summary>
        public static ICSharpCode.Decompiler.Metadata.PEFile Copy(ICSharpCode.Decompiler.Metadata.PEFile pe) =>
            Open(pe.FileName, pe.Reader.GetEntireImage().GetContent().ToArray());

        public static ICSharpCode.Decompiler.Metadata.PEFile Open(string name, byte[] image) =>
            new(name, new MemoryStream(image, writable: false), System.Reflection.PortableExecutable.PEStreamOptions.PrefetchEntireImage,
                System.Reflection.Metadata.MetadataReaderOptions.None);

        public T Own<T>(T file) where T : ICSharpCode.Decompiler.Metadata.MetadataFile
        {
            lock (_owned) _owned.Add(file);
            return file;
        }

        public ICSharpCode.Decompiler.Metadata.IAssemblyResolver Resolver(CancellationToken ct) => new SnapshotResolver(this, ct);

        public void Dispose()
        {
            lock (_owned)
            {
                foreach (var f in _owned) (f as IDisposable)?.Dispose();
                _owned.Clear();
            }
        }
    }

    /// <summary>Resolves the export's references to private readers, located as the workspace's decompiler resolver does.</summary>
    private sealed class SnapshotResolver(ExportSnapshot snapshot, CancellationToken ct) : ICSharpCode.Decompiler.Metadata.IAssemblyResolver
    {
        private readonly Dictionary<string, ICSharpCode.Decompiler.Metadata.MetadataFile?> _cache = new(StringComparer.Ordinal);
        private ICSharpCode.Decompiler.Metadata.UniversalAssemblyResolver? _fallback;

        private ICSharpCode.Decompiler.Metadata.UniversalAssemblyResolver Fallback
        {
            get
            {
                lock (_cache)
                {
                    if (_fallback != null) return _fallback;
                    string? tfm = null;
                    try { tfm = ICSharpCode.Decompiler.Metadata.DotNetCorePathFinderExtensions.DetectTargetFrameworkId(snapshot.Main); }
                    catch { }
                    var r = new ICSharpCode.Decompiler.Metadata.UniversalAssemblyResolver(snapshot.FilePath, false, tfm, null,
                        System.Reflection.PortableExecutable.PEStreamOptions.PrefetchEntireImage, System.Reflection.Metadata.MetadataReaderOptions.None);
                    foreach (var d in snapshot.SearchDirectories) r.AddSearchDirectory(d);
                    return _fallback = r;
                }
            }
        }

        public ICSharpCode.Decompiler.Metadata.MetadataFile? Resolve(ICSharpCode.Decompiler.Metadata.IAssemblyReference reference)
        {
            lock (_cache)
                if (_cache.TryGetValue(reference.FullName, out var known)) return known;
            var (name, image) = snapshot.Locate(reference.Name, reference.Version, reference.PublicKeyToken, snapshot.FilePath,
                snapshot.ResolvesAsNetFramework, snapshot.RequesterFramework, t => t?.Loaded is { } loaded
                    ? (loaded.FilePath, loaded.GetPEFile().Reader.GetEntireImage().GetContent().ToArray())
                    : (t?.File ?? $"{t?.EmbeddedIn ?? "stub"}!{snapshot.Names.Safe(reference.Name)}.dll", t?.Bytes), ct);
            ICSharpCode.Decompiler.Metadata.MetadataFile? file = null;
            try
            {
                if (image != null) file = snapshot.Own(ExportSnapshot.Open(name, image));
                else if (File.Exists(name)) file = snapshot.Own(ExportSnapshot.Open(name, File.ReadAllBytes(name)));
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { file = null; }
            // The fallback joins the reference name to its search folders.
            if (file == null && InputFiles.IsPlainName(reference.Name))
            {
                try { file = Fallback.Resolve(reference) is { } found ? snapshot.Own(found) : null; }
                catch (Exception ex) when (ex is not OperationCanceledException) { file = null; }
            }
            lock (_cache)
            {
                if (_cache.TryGetValue(reference.FullName, out var raced)) return raced;
                _cache[reference.FullName] = file;
            }
            return file;
        }

        public ICSharpCode.Decompiler.Metadata.MetadataFile? ResolveModule(ICSharpCode.Decompiler.Metadata.MetadataFile mainModule, string moduleName)
        {
            if (!InputFiles.IsPlainName(moduleName)) return null;
            try { return Fallback.ResolveModule(mainModule, moduleName) is { } found ? snapshot.Own(found) : null; }
            catch { return null; }
        }

        public Task<ICSharpCode.Decompiler.Metadata.MetadataFile?> ResolveAsync(ICSharpCode.Decompiler.Metadata.IAssemblyReference reference) =>
            Task.FromResult(Resolve(reference));

        public Task<ICSharpCode.Decompiler.Metadata.MetadataFile?> ResolveModuleAsync(ICSharpCode.Decompiler.Metadata.MetadataFile mainModule, string moduleName) =>
            Task.FromResult(ResolveModule(mainModule, moduleName));

        public IDisposable? BeginSnapshot() => null;
    }

    /// <summary>
    /// Reference names as the project file and <c>lib\</c> use them: a name unsafe in an XML comment, an MSBuild item
    /// or a file name gets a stub name, recorded for the result.
    /// </summary>
    private sealed class ReferenceNames(IEnumerable<string> taken)
    {
        private readonly Dictionary<string, string> _renamed = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _original = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _taken = new(taken.Where(IsSafe), StringComparer.OrdinalIgnoreCase);

        /// <summary>False for a name holding "--", "..", quotes, markup, path, MSBuild or control characters, or a device name.</summary>
        public static bool IsSafe(string name) =>
            name.Length is > 0 and <= 200 && !name.Contains("--", StringComparison.Ordinal) && !name.Contains("..", StringComparison.Ordinal)
            && !name.Any(c => char.IsControl(c) || "\"'<>&/\\:;%$@*?|".Contains(c)) && name.Trim(' ', '.') == name && !SafeFile.IsReservedName(name);

        /// <summary>The name itself when safe, else its stub name: letters, digits, '_', single '.' and '-'.</summary>
        public string Safe(string name)
        {
            if (IsSafe(name)) return name;
            lock (_renamed)
            {
                if (_renamed.TryGetValue(name, out var known)) return known;
                var chars = new string(name.Select(c => char.IsLetterOrDigit(c) || c is '_' or '.' or '-' ? c : '_').ToArray());
                var stem = System.Text.RegularExpressions.Regex.Replace(chars, @"\.{2,}|-{2,}", "_").Trim('.', '-');
                stem = stem.Length == 0 ? "Reference" : stem.Length > 100 ? stem[..100] : stem;
                if (SafeFile.IsReservedName(stem)) stem = "_" + stem;
                var safe = stem;
                for (int i = 2; !_taken.Add(safe); i++) safe = $"{stem}_{i}";
                _renamed[name] = safe;
                _original[safe] = name;
                return safe;
            }
        }

        /// <summary>The original of a stub name; any other name unchanged.</summary>
        public string Original(string name)
        {
            lock (_renamed) return _original.GetValueOrDefault(name, name);
        }

        /// <summary>One line per renamed reference, ordered by stub name.</summary>
        public IReadOnlyList<string> Notes()
        {
            var quote = new System.Text.Json.JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
            lock (_renamed)
                return [.. _renamed.OrderBy(r => r.Value, StringComparer.OrdinalIgnoreCase)
                    .Select(r => $"Reference {System.Text.Json.JsonSerializer.Serialize(r.Key, quote)} written as {r.Value}: the name is unsafe in a project file.")];
        }
    }

    private static readonly System.Text.RegularExpressions.Regex ReferenceInclude = new("<Reference Include=\"([^\"]*)\"");

    /// <summary>The assembly name of a decoded Include value: a full name loses its version, culture and key.</summary>
    private static string IncludeName(string value) => value.Contains(", Version=", StringComparison.Ordinal) ? value.Split(',')[0] : value;

    /// <summary>The original names of the project's references.</summary>
    private static HashSet<string> ReferencedNames(string text, ReferenceNames names) =>
        ReferenceInclude.Matches(text).Select(m => names.Original(IncludeName(System.Net.WebUtility.HtmlDecode(m.Groups[1].Value))))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>Writes the stub name of each reference the engine wrote with an unsafe name.</summary>
    private static void RenameUnsafeReferences(string dir, ReferenceNames names)
    {
        var project = Directory.GetFiles(dir, "*.csproj").FirstOrDefault();
        if (project == null) return;
        var text = File.ReadAllText(project);
        var renamed = ReferenceInclude.Replace(text, m =>
        {
            var name = IncludeName(System.Net.WebUtility.HtmlDecode(m.Groups[1].Value));
            return ReferenceNames.IsSafe(name) ? m.Value : $"<Reference Include=\"{names.Safe(name)}\"";
        });
        if (renamed != text) File.WriteAllText(project, renamed);
    }

    /// <summary>
    /// Writes embedded (e.g. Costura-wrapped) assemblies and stubs for unresolved references to <c>lib\</c>, points
    /// the engine's <c>Host!Name.dll</c> hint paths there, and references the remaining wrapped assemblies, which
    /// the compiler needs as transitive dependencies.
    /// </summary>
    private static void IncludeEmbeddedReferences(ExportSnapshot asm, string dir, CancellationToken ct)
    {
        var project = Directory.GetFiles(dir, "*.csproj").FirstOrDefault();
        if (project == null) return;
        var embedded = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        try
        {
            embedded = Containers.Open(asm.OriginalBytes, asm.FilePath, AnalysisLimits.Default, default).Items
                .Where(i => Core.Blob.Identify(i.Bytes) == ".NET assembly" && i.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                .GroupBy(i => Path.GetFileNameWithoutExtension(i.Name), StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First().Bytes, StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception) { /* not a container */ }
        // Unresolved references: use generated stubs so the project still builds.
        var stubs = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in asm.References)
            if (!embedded.ContainsKey(r.Name) && asm.Locate(r.Name, r.Version, r.Token, asm.FilePath, asm.TargetsNetFramework, asm.RequesterFramework,
                    t => t is { Stub: not null, Bytes: { } b } ? b : null, ct) is { } stubBytes)
                stubs[r.Name] = stubBytes;
        if (embedded.Count == 0 && stubs.Count == 0) return;

        var text = File.ReadAllText(project);
        foreach (var (name, bytes) in embedded.Concat(stubs))
            SafeFile.WriteUnderRoot(dir, Path.Combine("lib", asm.Names.Safe(name) + ".dll"), bytes, overwrite: true);
        if (stubs.Count > 0)
            text = text.Replace("</Project>", "  <!-- " + string.Join(", ", stubs.Keys.Select(asm.Names.Safe).Order(StringComparer.OrdinalIgnoreCase)) +
                                              (stubs.Count == 1 ? " was" : " were") + " not found at export: lib\\ holds stand-ins whose methods throw; " +
                                              "replace them with the real files to run it. -->\n</Project>");
        // Rewrite the engine's placeholder paths for embedded references.
        text = System.Text.RegularExpressions.Regex.Replace(text, @"<HintPath>[^<]*!([^<!]+\.dll)</HintPath>",
            m => $"<HintPath>lib\\{m.Groups[1].Value}</HintPath>");
        var referenced = ReferencedNames(text, asm.Names);
        var extra = embedded.Keys.Where(n => !referenced.Contains(n) && !n.EndsWith(".resources", StringComparison.OrdinalIgnoreCase))
            .Select(asm.Names.Safe).OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
            .Select(n => $"    <Reference Include=\"{n}\">\n      <HintPath>lib\\{n}.dll</HintPath>\n    </Reference>").ToList();
        if (extra.Count > 0)
            text = text.Replace("</Project>", "  <ItemGroup>\n    <!-- wrapped inside the original assembly (dependencies of its dependencies) -->\n" + string.Join("\n", extra) + "\n  </ItemGroup>\n</Project>");
        File.WriteAllText(project, text);
    }

    /// <summary>
    /// Writes the framework inferred from the references (<see cref="Frameworks.InferTargetFramework"/>) where the engine
    /// wrote .NET Framework 4.0 for every assembly without a TargetFrameworkAttribute.
    /// </summary>
    private static void UseInferredFramework(string dir, string framework)
    {
        var project = Directory.GetFiles(dir, "*.csproj").FirstOrDefault();
        if (project == null || Frameworks.ShortName(framework) is not { } tfm) return;
        var text = File.ReadAllText(project);
        var current = System.Text.RegularExpressions.Regex.Match(text, "<TargetFramework>([^<]*)</TargetFramework>");
        if (!current.Success) return;
        text = text.Replace(current.Value, $"<TargetFramework>{tfm}</TargetFramework>\n    <!-- inferred from the referenced core assemblies: the assembly has no TargetFrameworkAttribute -->");
        File.WriteAllText(project, text);
    }

    /// <summary>
    /// .NET Standard: drops framework-folder references (CS1069) and turns 1.x contracts into packages. .NET Framework:
    /// points an out-of-band library whose installed copy is a facade or older at its package's library.
    /// </summary>
    private static void FixFrameworkFileReferences(string dir, string? framework, bool netFramework, IReadOnlyDictionary<string, Version?> referenced)
    {
        var project = Directory.GetFiles(dir, "*.csproj").FirstOrDefault();
        if (project == null) return;
        bool standard = framework?.StartsWith(".NETStandard", StringComparison.OrdinalIgnoreCase) == true;
        if (!standard && !netFramework) return;
        bool standard1 = framework?.StartsWith(".NETStandard,Version=v1.", StringComparison.OrdinalIgnoreCase) == true;
        var text = File.ReadAllText(project);
        var packages = new List<string>();
        var fixedText = System.Text.RegularExpressions.Regex.Replace(text, @"[ \t]*<Reference Include=""([^""]+)"">\s*<HintPath>([^<]+)</HintPath>\s*</Reference>\r?\n?", m =>
        {
            var file = Path.GetFullPath(Path.Combine(dir, m.Groups[2].Value));
            var name = m.Groups[1].Value.Split(',')[0];
            if (standard)
            {
                // The contract packages of .NET Standard 1.x shipped as 4.3.0; a .NET Framework build of one (lib/net462) is not it.
                bool contract = standard1 && (name.StartsWith("System.", StringComparison.Ordinal) || name is "Microsoft.CSharp" or "Microsoft.Win32.Primitives" or "Microsoft.Win32.Registry");
                bool frameworkBuild = System.Text.RegularExpressions.Regex.IsMatch(file, @"[\\/]lib[\\/]net[1-4]\d*[\\/]", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (!IsFrameworkFile(file) && !(contract && frameworkBuild)) return m.Value;
                if (contract) packages.Add($"    <PackageReference Include=\"{name}\" Version=\"4.3.0\" />");
                return "";
            }
            if (!OutOfBand.Contains(name) || !Frameworks.InNetFrameworkDirectory(file) || !(IsFacade(file) || OlderThan(file, referenced.GetValueOrDefault(name))))
                return m.Value;
            return Frameworks.NetFrameworkPackageFile(name, framework) is { } package
                ? m.Value.Replace(m.Groups[2].Value, System.Security.SecurityElement.Escape(Path.GetRelativePath(dir, package)))
                : m.Value;
        });
        if (packages.Count > 0)
            fixedText = fixedText.Replace("</Project>", "  <ItemGroup>\n    <!-- .NET Standard 1.x contracts -->\n" + string.Join("\n", packages) + "\n  </ItemGroup>\n</Project>");
        if (fixedText != text) File.WriteAllText(project, fixedText);
    }

    /// <summary>Libraries shipped as packages for .NET Framework, whose copies in the installed runtime are facades or older.</summary>
    private static readonly HashSet<string> OutOfBand = new(StringComparer.OrdinalIgnoreCase)
        { "System.ValueTuple", "System.Numerics.Vectors", "System.Buffers", "System.Memory", "System.Runtime.CompilerServices.Unsafe", "System.Threading.Tasks.Extensions" };

    /// <summary>The file's assembly version is below <paramref name="wanted"/>.</summary>
    private static bool OlderThan(string file, Version? wanted)
    {
        if (wanted == null || Frameworks.IsWildcard(wanted)) return false;
        try { return System.Reflection.AssemblyName.GetAssemblyName(file).Version is { } v && v < wanted; }
        catch (Exception ex) when (ex is IOException or BadImageFormatException or UnauthorizedAccessException) { return false; }
    }

    /// <summary>An assembly that only forwards types (no type definitions of its own).</summary>
    private static bool IsFacade(string file)
    {
        try
        {
            using var pe = new System.Reflection.PortableExecutable.PEReader(File.OpenRead(file));
            if (!pe.HasMetadata) return false;
            var md = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
            return md.TypeDefinitions.Count <= 1 && md.ExportedTypes.Count > 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or BadImageFormatException) { return false; }
    }

    private static bool IsFrameworkFile(string file) => Frameworks.InNetFrameworkDirectory(file) || Frameworks.SharedFrameworkMajor(file) != null;

    /// <summary>
    /// References the dependencies of the referenced libraries (CS0012), preferring the application's own copies.
    /// </summary>
    private static void AddTransitiveReferences(ExportSnapshot asm, string dir, string? framework, bool netFramework, CancellationToken ct)
    {
        var project = Directory.GetFiles(dir, "*.csproj").FirstOrDefault();
        if (project == null) return;
        var text = File.ReadAllText(project);
        var referenced = ReferencedNames(text, asm.Names);
        var appDir = Path.GetDirectoryName(asm.FilePath);
        var queue = new Queue<(string Name, Version? Version, byte[]? Token, string From)>(
            asm.References.Select(r => (r.Name, (Version?)r.Version, r.Token, asm.FilePath)));
        var seen = new HashSet<string>(asm.References.Select(r => r.Name), StringComparer.OrdinalIgnoreCase) { asm.AssemblyName };
        var added = new List<string>();
        while (queue.Count > 0)
        {
            var (name, version, token, from) = queue.Dequeue();
            var file = asm.Locate(name, version, token, from, netFramework, framework, t => t?.Loaded?.FilePath ?? t?.File, ct);
            if (file == null || IsFrameworkFile(file) || name.Equals("netstandard", StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var (refName, refVersion, refToken) in ReferencesOf(file))
            {
                if (!seen.Add(refName)) continue;
                queue.Enqueue((refName, refVersion, refToken, file));
                if (referenced.Contains(refName) || ProvidedByFramework(refName, framework, netFramework)) continue;
                // An application's own copy (often newer than the framework's, e.g. System.Numerics.Vectors next to System.Memory).
                var local = appDir == null ? null : Path.Combine(appDir, refName + ".dll");
                string? found;
                if (local != null && File.Exists(local)) found = local;
                else if (netFramework && Frameworks.IsNetFrameworkAssembly(refName))
                {
                    // A version above the framework's (System.Numerics.Vectors 4.1.3 has Vector<T>, the framework's 4.0 does not) is its package.
                    if (OutOfBand.Contains(refName) && Frameworks.NetFrameworkFile(refName) is { } fx && OlderThan(fx, refVersion) && Frameworks.NetFrameworkPackageFile(refName, framework) is { } package)
                        found = package;
                    else
                    {
                        added.Add($"    <Reference Include=\"{asm.Names.Safe(refName)}\" />");
                        continue;
                    }
                }
                else found = asm.Locate(refName, refVersion, refToken, file, netFramework, framework, t => t is { Stub: null } ? t.Loaded?.FilePath ?? t.File : null, ct);
                if (found == null || IsFrameworkFile(found)) continue;
                added.Add($"    <Reference Include=\"{asm.Names.Safe(refName)}\">\n      <HintPath>{System.Security.SecurityElement.Escape(Path.GetRelativePath(dir, found))}</HintPath>\n    </Reference>");
            }
        }
        if (added.Count == 0) return;
        text = text.Replace("</Project>", "  <ItemGroup>\n    <!-- dependencies of the referenced libraries -->\n" + string.Join("\n", added) + "\n  </ItemGroup>\n</Project>");
        File.WriteAllText(project, text);
    }

    /// <summary>Assemblies the project's framework supplies itself: the shared framework (.NET), the .NET Standard surface, mscorlib.</summary>
    private static bool ProvidedByFramework(string name, string? framework, bool netFramework)
    {
        if (name is "mscorlib" or "netstandard" or "System.Private.CoreLib") return true;
        if (Frameworks.NetCoreMajor(framework) is { } major) return Frameworks.SharedFrameworkOf(name, major) != null;
        if (!netFramework && framework?.StartsWith(".NETStandard,Version=v2", StringComparison.OrdinalIgnoreCase) == true
            && Frameworks.NetStandardFile(new Version(2, framework.EndsWith("2.1", StringComparison.Ordinal) ? 1 : 0)) is { } standard)
            return File.Exists(Path.Combine(Path.GetDirectoryName(standard)!, name + ".dll"));
        return false;
    }

    private static List<(string Name, Version Version, byte[]? Token)> ReferencesOf(string file)
    {
        try
        {
            using var pe = new System.Reflection.PortableExecutable.PEReader(File.OpenRead(file));
            if (!pe.HasMetadata) return [];
            var md = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
            return md.AssemblyReferences.Select(h => md.GetAssemblyReference(h)).Select(r =>
            {
                var key = md.GetBlobBytes(r.PublicKeyOrToken);
                byte[]? token = key.Length == 8 ? key : key.Length > 0 ? new Dn.PublicKey(key).Token.Data : null;
                return (md.GetString(r.Name), r.Version, token);
            }).ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or BadImageFormatException or InvalidOperationException) { return []; }
    }

    /// <summary>
    /// Replaces individual Windows SDK contract .winmd references with the union <c>Windows</c> metadata, which
    /// System.Runtime.WindowsRuntime is compiled against (CS0012).
    /// </summary>
    private static void UseUnionWindowsMetadata(string dir)
    {
        var project = Directory.GetFiles(dir, "*.csproj").FirstOrDefault();
        if (project == null || Frameworks.WindowsMetadataFile("Windows", null) is not { } union) return;
        var text = File.ReadAllText(project);
        var contract = new System.Text.RegularExpressions.Regex(
            @"[ \t]*<Reference Include=""Windows\.[^""]*Contract"">\s*<HintPath>[^<]*\.winmd</HintPath>\s*</Reference>\r?\n?");
        if (!contract.IsMatch(text)) return;
        text = contract.Replace(text, "");
        if (!text.Contains("<Reference Include=\"Windows\">", StringComparison.Ordinal))
            text = text.Replace("</Project>", $"  <ItemGroup>\n    <Reference Include=\"Windows\">\n      <HintPath>{union}</HintPath>\n    </Reference>\n  </ItemGroup>\n</Project>");
        File.WriteAllText(project, text);
    }

    /// <summary>
    /// Preserves the original entry point class (StartupObject; WPF apps can have several Mains) and public key
    /// (public signing), so InternalsVisibleTo grants by key still apply (CS0281) and the identity is kept.
    /// </summary>
    private static void KeepIdentity(ExportSnapshot asm, string dir)
    {
        var project = Directory.GetFiles(dir, "*.csproj").FirstOrDefault();
        if (project == null) return;
        var text = File.ReadAllText(project);
        var settings = new List<string>();
        if (asm.EntryType is { } entryType && !text.Contains("<StartupObject>", StringComparison.Ordinal))
            settings.Add($"<StartupObject>{System.Security.SecurityElement.Escape(entryType.Replace('+', '.'))}</StartupObject>");
        if (asm.PublicKey is { } key && !text.Contains("<AssemblyOriginatorKeyFile>", StringComparison.Ordinal))
        {
            File.WriteAllBytes(Path.Combine(dir, "PublicKey.snk"), key);
            settings.Add("<SignAssembly>True</SignAssembly>");
            settings.Add("<PublicSign>True</PublicSign>");
            settings.Add("<AssemblyOriginatorKeyFile>PublicKey.snk</AssemblyOriginatorKeyFile>");
        }
        if (settings.Count == 0) return;
        int at = text.IndexOf("</PropertyGroup>", StringComparison.Ordinal);
        if (at < 0) return;
        text = text.Insert(at, string.Concat(settings.Select(x => "  " + x + "\n")) + "  ");
        File.WriteAllText(project, text);
    }

    /// <summary>
    /// dotnet build compiles .resx entries that are not strings (images, icons, byte arrays) for .NET Framework only as
    /// preserialized resources read by System.Resources.Extensions (MSB3822, MSB3823), which needs 4.6.2 or later.
    /// </summary>
    private static void UsePreserializedResources(string dir)
    {
        var project = Directory.GetFiles(dir, "*.csproj").FirstOrDefault();
        if (project == null) return;
        var text = File.ReadAllText(project);
        var tfm = System.Text.RegularExpressions.Regex.Match(text, @"<TargetFramework>net([1-4])(\d)(\d?)</TargetFramework>");
        if (!tfm.Success || text.Contains("<GenerateResourceUsePreserializedResources>", StringComparison.Ordinal)) return;
        var nonString = new System.Text.RegularExpressions.Regex(@"<data\s[^>]*\b(?:type|mimetype)=""");
        if (!Directory.EnumerateFiles(dir, "*.resx", SearchOption.AllDirectories).Any(f => nonString.IsMatch(File.ReadAllText(f)))) return;
        var settings = "    <GenerateResourceUsePreserializedResources>True</GenerateResourceUsePreserializedResources>\n";
        var version = tfm.Groups[1].Value + tfm.Groups[2].Value + (tfm.Groups[3].Value.Length > 0 ? tfm.Groups[3].Value : "0");
        if (int.Parse(version, System.Globalization.CultureInfo.InvariantCulture) < 462)
        {
            text = text.Replace(tfm.Value, "<TargetFramework>net462</TargetFramework>");
            settings += $"    <!-- was net{tfm.Value[20..^18]}: binary resources need System.Resources.Extensions, which supports net462 and later -->\n";
        }
        text = text.Replace("</Project>", $"  <PropertyGroup>\n{settings}  </PropertyGroup>\n  <ItemGroup>\n" +
                                          "    <PackageReference Include=\"System.Resources.Extensions\" Version=\"8.0.0\" />\n  </ItemGroup>\n</Project>");
        File.WriteAllText(project, text);
    }

    private const string FailedBodyMarker = "// ILSpy could not decompile this";

    /// <summary>
    /// Adds a <c>throw</c> to method bodies the engine left as a comment only (CS0161).
    /// </summary>
    private static void ThrowInFailedBodies(string dir)
    {
        foreach (var file in Directory.EnumerateFiles(dir, "*.cs", SearchOption.AllDirectories))
        {
            var text = File.ReadAllText(file);
            if (!text.Contains(FailedBodyMarker, StringComparison.Ordinal)) continue;
            var lines = text.Split('\n').ToList();
            for (int i = 0; i < lines.Count; i++)
            {
                if (!lines[i].TrimStart().StartsWith(FailedBodyMarker, StringComparison.Ordinal)) continue;
                int end = i;
                while (end + 1 < lines.Count && lines[end + 1].TrimStart().StartsWith("//", StringComparison.Ordinal)) end++;
                // Only when the comment is the entire body.
                if (i == 0 || lines[i - 1].Trim() != "{" || end + 1 >= lines.Count || lines[end + 1].Trim() != "}") continue;
                var indent = lines[i][..(lines[i].Length - lines[i].TrimStart().Length)];
                lines.Insert(end + 1, indent + "throw new global::System.NotSupportedException(\"The decompiler could not decompile this method; see the comment above.\");"
                                      + (lines[i].EndsWith('\r') ? "\r" : ""));
                i = end + 1;
            }
            File.WriteAllText(file, string.Join('\n', lines));
        }
    }

    /// <summary>Project exporter that applies <see cref="AstCleanup"/>.</summary>
    private sealed class ProjectExporter(string? targetFramework, DecompilerSettings settings, ICSharpCode.Decompiler.Metadata.IAssemblyResolver resolver,
        ICSharpCode.Decompiler.CSharp.ProjectDecompiler.IProjectFileWriter? projectWriter,
        ICSharpCode.Decompiler.Metadata.AssemblyReferenceClassifier? classifier, ICSharpCode.Decompiler.DebugInfo.IDebugInfoProvider? debugInfo)
        : WholeProjectDecompiler(settings, resolver, projectWriter, classifier, debugInfo)
    {
        protected override CSharpDecompiler CreateDecompiler(DecompilerTypeSystem ts)
        {
            var decompiler = base.CreateDecompiler(ts);
            AstCleanup.AddTo(decompiler, targetFramework);
            return decompiler;
        }
    }

    /// <summary>The C# statement that holds an IL offset of a method, and its line in the method's decompiled text.</summary>
    public sealed record IlStatement(string Text, int Line, int IlStart, int IlEnd);

    private const int MaxStatementChars = 300, MaxCachedStatementMethods = 64;
    private readonly LinkedList<(string Key, List<(int Start, int End, int Line, string Text)> Points)> _statements = new();

    /// <summary>
    /// The statement at a frame's IL offset, from sequence points; a state machine's MoveNext maps through the method that
    /// starts it. Null when none covers it or the assembly has edits.
    /// </summary>
    public IlStatement? StatementAt(LoadedAssembly asm, Dn.MethodDef method, int ilOffset, CancellationToken ct)
    {
        if (asm.IsDirty || !method.HasBody) return null;
        var source = StateMachineKickoff(method) ?? method;
        string key = $"{workspace.Generation}|{asm.Id}|{asm.Version}|{method.MDToken.Raw:X8}";
        List<(int Start, int End, int Line, string Text)>? points = null;
        lock (_statements)
            for (var n = _statements.First; n != null; n = n.Next)
                if (n.Value.Key == key)
                {
                    points = n.Value.Points;
                    _statements.Remove(n);
                    _statements.AddFirst(n);
                    break;
                }
        if (points == null)
        {
            points = [];
            var found = points;
            WithTimeout(token =>
            {
                var decompiler = CreateDecompiler(asm, token);
                var tree = decompiler.Decompile(Handle(asm, source));
                using var writer = new StringWriter();
                var tokens = ICSharpCode.Decompiler.CSharp.OutputVisitor.TokenWriter.WrapInWriterThatSetsLocationsInAST(
                    new ICSharpCode.Decompiler.CSharp.OutputVisitor.TextWriterTokenWriter(writer) { IndentationString = "    " });
                tree.AcceptVisitor(new ICSharpCode.Decompiler.CSharp.OutputVisitor.CSharpOutputVisitor(tokens, CreateSettings().CSharpFormattingOptions));
                var lines = writer.ToString().Split('\n');
                int token32 = (int)asm.ImageToken(method);
                foreach (var (function, list) in decompiler.CreateSequencePoints(tree))
                {
                    var owner = function.MoveNextMethod ?? function.Method;
                    if (owner == null || MetadataTokens.GetToken(owner.MetadataToken) != token32) continue;
                    foreach (var sp in list.Where(p => !p.IsHidden && p.StartLine >= 1 && p.EndLine <= lines.Length))
                        found.Add((sp.Offset, sp.EndOffset, sp.StartLine, Slice(lines, sp)));
                }
                return "";
            }, ct);
            lock (_statements)
            {
                _statements.AddFirst((key, points));
                while (_statements.Count > MaxCachedStatementMethods) _statements.RemoveLast();
            }
        }
        var hit = points.Where(p => p.Start <= ilOffset && ilOffset < p.End).OrderBy(p => p.End - p.Start).FirstOrDefault();
        return hit.Text == null ? null : new IlStatement(hit.Text, hit.Line, hit.Start, hit.End);
    }

    private static string Slice(string[] lines, ICSharpCode.Decompiler.DebugInfo.SequencePoint sp)
    {
        var sb = new StringBuilder();
        for (int l = sp.StartLine; l <= sp.EndLine; l++)
        {
            var line = lines[l - 1].TrimEnd('\r');
            int from = l == sp.StartLine ? Math.Clamp(sp.StartColumn - 1, 0, line.Length) : 0;
            int to = l == sp.EndLine ? Math.Clamp(sp.EndColumn - 1, from, line.Length) : line.Length;
            sb.Append(line.AsSpan(from, to - from).Trim()).Append(' ');
        }
        return Format.Clip(sb.ToString().Trim(), MaxStatementChars);
    }

    /// <summary>The async or iterator method a compiler-generated state machine's MoveNext belongs to.</summary>
    private static Dn.MethodDef? StateMachineKickoff(Dn.MethodDef method)
    {
        if (method.Name != "MoveNext" || method.DeclaringType is not { DeclaringType: { } outer } machine) return null;
        foreach (var m in outer.Methods)
            foreach (var a in m.CustomAttributes)
                if (a.TypeFullName is "System.Runtime.CompilerServices.AsyncStateMachineAttribute" or "System.Runtime.CompilerServices.IteratorStateMachineAttribute"
                        or "System.Runtime.CompilerServices.AsyncIteratorStateMachineAttribute"
                    && a.ConstructorArguments.Count == 1 && a.ConstructorArguments[0].Value is Dn.TypeDefOrRefSig { TypeDefOrRef: var t } && (t as Dn.TypeDef ?? Dn.Extensions.ResolveTypeDef(t)) == machine)
                    return m;
        return null;
    }

    /// <summary>The member's handle in the assembly's current image, including added members.</summary>
    internal static EntityHandle Handle(LoadedAssembly asm, Dn.IMDTokenProvider member) => MetadataTokens.EntityHandle((int)asm.ImageToken(member));

    private string WithTimeout(Func<CancellationToken, string> action, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(options.TimeoutSeconds));
        try
        {
            return action(cts.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new ToolError(ErrorCode.Timeout, $"Decompilation timed out after {options.TimeoutSeconds}s.",
                "decompile one method with decompile_member, use get_il, or restart the server with a larger --timeout");
        }
    }

    private static string FirstLine(string s)
    {
        int nl = s.IndexOf('\n');
        return (nl >= 0 ? s[..nl] : s).Trim();
    }

    /// <summary>Reports on the reporting thread: <see cref="Progress{T}"/> posts to the pool, so a report could arrive after the export returned or was cancelled.</summary>
    private sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value) => report(value);
    }
}
