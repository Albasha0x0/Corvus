using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using Syn = ICSharpCode.Decompiler.CSharp.Syntax;
using System.Text;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.ProjectDecompiler;
using ICSharpCode.Decompiler.Disassembler;
using ICSharpCode.Decompiler.TypeSystem;
using NetDecompilerMcp.Core;
using Dn = dnlib.DotNet;

namespace NetDecompilerMcp.Services;

/// <summary>C# decompilation and IL disassembly via the ILSpy engine (ICSharpCode.Decompiler).</summary>
public sealed class DecompilerService(AssemblyWorkspace workspace, ServerOptions options)
{
    // Weak keys: entries disappear with their assembly (unloaded assemblies, original views used for diffs).
    private readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedAssembly, TypeSystemEntry> _typeSystems = new();

    private sealed record TypeSystemEntry(long Key, DecompilerTypeSystem TypeSystem);

    public static DecompilerSettings CreateSettings() => new(LanguageVersion.Latest)
    {
        ThrowOnAssemblyResolveErrors = false,
        ShowXmlDocumentation = false,
        LoadInMemory = true,
        UseSdkStyleProjectFormat = true,
    };

    private DecompilerTypeSystem GetTypeSystem(LoadedAssembly asm)
    {
        // Keyed by workspace generation (other assemblies changed) and by the assembly's own edit version: several edits
        // can happen inside one write lock (undo replays), and each must see the module as it is now.
        long key = ((long)workspace.Generation << 32) | (uint)asm.Version;
        if (_typeSystems.TryGetValue(asm, out var entry) && entry.Key == key)
            return entry.TypeSystem;
        var ts = new DecompilerTypeSystem(asm.GetPEFile(), workspace.CreateDecompilerResolver(asm), CreateSettings());
        _typeSystems.AddOrUpdate(asm, new TypeSystemEntry(key, ts));
        return ts;
    }

    private CSharpDecompiler CreateDecompiler(LoadedAssembly asm, CancellationToken token)
    {
        var decompiler = new CSharpDecompiler(GetTypeSystem(asm), CreateSettings()) { CancellationToken = token };
        AstCleanup.AddTo(decompiler, Frameworks.TargetFrameworkOf(asm.Module));
        return decompiler;
    }

    /// <summary>Decompiles a whole type. If the engine fails on the type, falls back to member-by-member output so one bad method does not hide the rest.</summary>
    public string DecompileType(LoadedAssembly asm, Dn.TypeDef type, CancellationToken ct) => InvalidBodiesNote(asm, type) + WithTimeout(token =>
    {
        var decompiler = CreateDecompiler(asm, token);
        try
        {
            // Top-level types go through the full-type-name API, which emits the namespace declaration and usings
            // (decompiling by handle omits the namespace). Nested types are decompiled on their own by handle.
            // Compiler-generated types (e.g. <PrivateImplementationDetails>) come back empty from the name API, so fall back to the handle.
            if (type.DeclaringType == null)
            {
                var withNamespace = decompiler.DecompileTypeAsString(new FullTypeName(type.ReflectionFullName));
                if (!string.IsNullOrWhiteSpace(withNamespace))
                    return withNamespace;
            }
            return decompiler.DecompileAsString(Handle(asm, type));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"// Whole-type decompilation failed ({ex.GetType().Name}: {FirstLine(ex.Message)}); decompiling members individually.");
            sb.AppendLine($"// {Format.TypeHeader(type)}");
            var members = type.Fields.Cast<Dn.IMemberDef>().Concat(type.Properties).Concat(type.Events)
                .Concat(type.Methods.Where(m => !m.IsGetter && !m.IsSetter && !m.IsAddOn && !m.IsRemoveOn))
                .Concat(type.NestedTypes);
            foreach (var m in members)
            {
                token.ThrowIfCancellationRequested();
                sb.AppendLine(DecompileMemberSafe(asm, m, decompiler, token));
            }
            return sb.ToString();
        }
    }, ct);

    /// <summary>A leading comment when some of the type's method bodies are not valid IL (empty otherwise).</summary>
    private static string InvalidBodiesNote(LoadedAssembly asm, Dn.TypeDef type)
    {
        if (asm.IsDirty || asm.BodyHealth.Invalid == 0) return "";
        var methods = type.Methods.Where(m => m.RVA != 0).ToList();
        int invalid = methods.Count(asm.BodyHealth.IsInvalid);
        return invalid == 0 ? "" : $"// Warning: {invalid} of {methods.Count} method bodies of this type are not valid IL (encrypted, or dumped from memory before decryption): their code below is meaningless.\n";
    }

    /// <summary>Decompiles members (all overloads that matched). Failures fall back to IL for that member.</summary>
    public string DecompileMembers(LoadedAssembly asm, IEnumerable<Dn.IMemberDef> members, CancellationToken ct) => WithTimeout(token =>
    {
        var decompiler = CreateDecompiler(asm, token);
        var parts = members.Select(m => DecompileMemberSafe(asm, m, decompiler, token));
        return string.Join("\n", parts);
    }, ct);

    /// <summary>
    /// A constructor whose work the engine shows elsewhere: assignments made before the base constructor become field
    /// and property initializers, or a primary constructor (<c>class Safe(int x) : Plain { int f = x; }</c>), which the
    /// constructor alone does not show. Such a constructor is shown inside its type, trimmed to what runs as part of
    /// it: the type's header, the initializers of its kind (instance or static), and its constructors. Null when there
    /// is nothing of that kind.
    /// </summary>
    private static string? ConstructorInContext(LoadedAssembly asm, Dn.MethodDef ctor, CSharpDecompiler decompiler)
    {
        var tree = decompiler.Decompile(Handle(asm, ctor.DeclaringType));
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

    private string DecompileMemberSafe(LoadedAssembly asm, Dn.IMemberDef member, CSharpDecompiler decompiler, CancellationToken token)
    {
        var header = $"// {Format.MemberLabel(member)}  [token {Format.Token(member)}]";
        if (MetadataUtil.IsReferenceAssembly(asm.Module))
            header += "\n// Note: reference assembly — bodies are `throw null`, not the implementation (load the runtime's or the package's lib/ assembly).";
        if (member is Dn.MethodDef method && !asm.IsDirty && asm.BodyHealth.IsInvalid(method))
            header += "\n// Warning: this method body is not valid IL (encrypted, or dumped from memory before decryption): the code below is meaningless.";
        try
        {
            if (member is Dn.MethodDef { IsConstructor: true } ctor && ConstructorInContext(asm, ctor, decompiler) is { } inContext)
                return header + "\n" + inContext;
            return header + "\n" + decompiler.DecompileAsString(Handle(asm, member)).TrimEnd() + "\n";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var sb = new StringBuilder(header).AppendLine();
            sb.AppendLine($"// C# decompilation failed: {ex.GetType().Name}: {FirstLine(ex.Message)}");
            sb.AppendLine("// IL fallback:");
            try { sb.AppendLine(Disassemble(asm, member, token)); }
            catch (Exception ilEx) when (ilEx is not OperationCanceledException) { sb.AppendLine($"// IL disassembly also failed: {FirstLine(ilEx.Message)}"); }
            return sb.ToString();
        }
    }

    /// <summary>Assembly-level attributes and module info as C#.</summary>
    public string DecompileAssemblyAttributes(LoadedAssembly asm, CancellationToken ct) => WithTimeout(token =>
        CreateDecompiler(asm, token).DecompileModuleAndAssemblyAttributesToString(), ct);

    /// <summary>ildasm-style IL with metadata tokens and resolved operands.</summary>
    public string Disassemble(LoadedAssembly asm, Dn.IMemberDef member, CancellationToken ct)
    {
        var output = new PlainTextOutput();
        var dis = new ReflectionDisassembler(output, ct)
        {
            DetectControlStructure = true,
            ShowSequencePoints = false,
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
            default: throw new ToolError($"Cannot disassemble {member.GetType().Name}.");
        }
        return output.ToString();
    }

    /// <summary>XAML decompiled from a BAML resource entry (a WPF window / control), or null when it cannot be.</summary>
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

    public sealed record ExportResult(string Directory, int FileCount, string? ProjectFile, IReadOnlyList<string> FailedTypes);

    /// <summary>
    /// Tells the project writer which references are part of the target framework: shared-framework assemblies of a
    /// .NET (Core) app come from its runtime pack, .NET Framework assemblies are referenced by name (GAC). Only the
    /// app's own libraries get a HintPath.
    /// </summary>
    private sealed class FrameworkClassifier(bool netFramework, int? targetMajor, IReadOnlyList<string>? netFrameworkReferences)
        : ICSharpCode.Decompiler.Metadata.AssemblyReferenceClassifier
    {
        // implicit for the build only when the target's reference assemblies have it (System.Runtime.WindowsRuntime
        // is installed with .NET Framework but is not one of them: it gets a path)
        public override bool IsGacAssembly(ICSharpCode.Decompiler.Metadata.IAssemblyReference reference) =>
            netFramework && (reference.Name is "mscorlib" or "netstandard"
                             || (netFrameworkReferences != null
                                 ? netFrameworkReferences.Any(d => File.Exists(Path.Combine(d, reference.Name + ".dll")))
                                 : Frameworks.IsNetFrameworkAssembly(reference.Name)));

        public override bool IsSharedAssembly(ICSharpCode.Decompiler.Metadata.IAssemblyReference reference,
            [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? runtimePack)
        {
            // part of the framework the project targets (not merely of the newest one installed)
            runtimePack = netFramework ? null : Frameworks.SharedFrameworkOf(reference.Name, targetMajor)
                ?? (reference.Name is "netstandard" or "mscorlib" ? "Microsoft.NETCore.App" : null);
            // ASP.NET Core is not part of a plain project: a library using one of its assemblies (System.IO.Pipelines)
            // references the file instead
            if (runtimePack == "Microsoft.AspNetCore.App") runtimePack = null;
            return runtimePack != null;
        }
    }

    /// <summary>Writes a C# project (one file per type, .csproj, resources) to an empty directory.</summary>
    public ExportResult ExportProject(LoadedAssembly asm, string outputDirectory, Action<int, int, string>? onProgress, CancellationToken ct)
    {
        var dir = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(dir);
        if (Directory.EnumerateFileSystemEntries(dir).Any())
            throw new ToolError($"Output directory is not empty: {dir}. Choose an empty or new directory.");

        // Whole-project export is long-running by nature: it gets 10x the normal timeout.
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(options.TimeoutSeconds * 10L));
        // a project is for building: LINQ comes out as method calls, which the engine gets right where its query
        // syntax rebuild leaks compiler names (<>h__TransparentIdentifier0)
        var exportSettings = CreateSettings();
        exportSettings.QueryExpressions = false;
        var exporter = new ProjectExporter(Frameworks.TargetFrameworkOf(asm.Module), exportSettings, workspace.CreateDecompilerResolver(asm), null,
            new FrameworkClassifier(Frameworks.TargetsNetFramework(asm.Module), Frameworks.NetCoreMajor(Frameworks.TargetFrameworkOf(asm.Module)),
                Frameworks.NetFrameworkReferenceDirs(Frameworks.TargetFrameworkOf(asm.Module))), null);
        if (onProgress != null)
            exporter.ProgressIndicator = new Progress<DecompilationProgress>(p => onProgress(p.UnitsCompleted, p.TotalUnits, p.Status ?? "Decompiling"));
        try
        {
            exporter.DecompileProject(asm.GetPEFile(), dir, cts.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new ToolError($"Project export timed out after {options.TimeoutSeconds * 10}s. Partial output is in {dir}.");
        }
        IncludeEmbeddedReferences(asm, dir);
        ThrowInFailedBodies(dir);
        UseUnionWindowsMetadata(dir);
        KeepIdentity(asm, dir);
        var files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).ToList();
        var failed = exporter.Errors.Select(e => FirstLine(e.Message)).ToList();
        return new ExportResult(dir, files.Count, files.FirstOrDefault(f => f.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)), failed);
    }

    /// <summary>
    /// Assemblies packed inside the exported one (Costura) have no file to reference: they are written to the
    /// project's lib folder, the references the engine wrote ("Host!Name.dll") point there, and the other packed
    /// assemblies are referenced too (the compiler needs a dependency's own dependencies).
    /// </summary>
    private void IncludeEmbeddedReferences(LoadedAssembly asm, string dir)
    {
        var project = Directory.GetFiles(dir, "*.csproj").FirstOrDefault();
        if (project == null) return;
        var embedded = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        try
        {
            embedded = Services.Analysis.Containers.Open(asm.OriginalBytes, asm.FilePath, Services.Analysis.AnalysisLimits.Default, default).Items
                .Where(i => Services.Analysis.Blob.Identify(i.Bytes) == ".NET assembly" && i.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                .GroupBy(i => Path.GetFileNameWithoutExtension(i.Name), StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First().Bytes, StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception) { /* not a container */ }
        // references found nowhere: the stand-ins built from what this code uses, so the project still builds
        var stubs = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        bool netFramework = Frameworks.TargetsNetFramework(asm.Module);
        foreach (var r in asm.Module.GetAssemblyRefs())
            if (!embedded.ContainsKey(r.Name) && workspace.LocateReference(r.Name, r.Version, r.PublicKeyOrToken?.Token?.Data, asm.FilePath, netFramework,
                    Frameworks.TargetFrameworkOf(asm.Module)) is { Stub: not null, Bytes: { } stubBytes })
                stubs[r.Name] = stubBytes;
        if (embedded.Count == 0 && stubs.Count == 0) return;

        var text = File.ReadAllText(project);
        var lib = Path.Combine(dir, "lib");
        Directory.CreateDirectory(lib);
        foreach (var (name, bytes) in embedded.Concat(stubs))
            File.WriteAllBytes(Path.Combine(lib, name + ".dll"), bytes);
        if (stubs.Count > 0)
            text = text.Replace("</Project>", "  <!-- " + string.Join(", ", stubs.Keys.Order(StringComparer.OrdinalIgnoreCase)) +
                                              (stubs.Count == 1 ? " was" : " were") + " not found on the machine that exported this project: lib\\ holds stand-ins " +
                                              "built from what this code uses (their methods throw). Replace them with the real files to run it. -->\n</Project>");
        // the engine's placeholder paths for embedded references
        text = System.Text.RegularExpressions.Regex.Replace(text, @"<HintPath>[^<]*!([^<!]+\.dll)</HintPath>",
            m => $"<HintPath>lib\\{m.Groups[1].Value}</HintPath>");
        var referenced = System.Text.RegularExpressions.Regex.Matches(text, "<Reference Include=\"([^\"]+)\"")
            .Select(m => m.Groups[1].Value.Split(',')[0]).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var extra = embedded.Keys.Where(n => !referenced.Contains(n) && !n.EndsWith(".resources", StringComparison.OrdinalIgnoreCase))
            .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
            .Select(n => $"    <Reference Include=\"{n}\">\n      <HintPath>lib\\{n}.dll</HintPath>\n    </Reference>").ToList();
        if (extra.Count > 0)
            text = text.Replace("</Project>", "  <ItemGroup>\n    <!-- packed inside the original assembly (dependencies of its dependencies) -->\n" + string.Join("\n", extra) + "\n  </ItemGroup>\n</Project>");
        File.WriteAllText(project, text);
    }

    /// <summary>
    /// Windows Runtime API contracts referenced one by one (Windows.Foundation.FoundationContract.winmd...) do not mix
    /// with System.Runtime.WindowsRuntime, whose await support is written against the union "Windows" metadata
    /// (CS0012). The contracts from the Windows SDK are replaced by that one union reference, which holds every type
    /// they do.
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
    /// What the original build settings decided and the project would otherwise lose: the class whose method the header
    /// names as the entry point (StartupObject: a WPF app has its generated Main and often another one), and the public
    /// key (public signing with the original key, no private key needed), so friend assemblies that grant internals
    /// to it by key still do (CS0281) and the rebuilt assembly keeps its identity.
    /// </summary>
    private static void KeepIdentity(LoadedAssembly asm, string dir)
    {
        var project = Directory.GetFiles(dir, "*.csproj").FirstOrDefault();
        if (project == null) return;
        var text = File.ReadAllText(project);
        var settings = new List<string>();
        if (asm.Module.EntryPoint?.DeclaringType is { } entryType && !text.Contains("<StartupObject>", StringComparison.Ordinal))
            settings.Add($"<StartupObject>{System.Security.SecurityElement.Escape(entryType.ReflectionFullName.Replace('+', '.'))}</StartupObject>");
        if (asm.Module.Assembly?.PublicKey is { IsNullOrEmpty: false } key && !text.Contains("<AssemblyOriginatorKeyFile>", StringComparison.Ordinal))
        {
            File.WriteAllBytes(Path.Combine(dir, "PublicKey.snk"), key.Data);
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

    private const string FailedBodyMarker = "// ILSpy could not decompile this";

    /// <summary>
    /// A method the engine could not decompile is written as a body holding only its explanation comment, so the project
    /// does not build (CS0161 and others). Such bodies throw, saying so; the comment stays.
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
                // the comment fills the whole body: the line before opens it, the line after closes it
                if (i == 0 || lines[i - 1].Trim() != "{" || end + 1 >= lines.Count || lines[end + 1].Trim() != "}") continue;
                var indent = lines[i][..(lines[i].Length - lines[i].TrimStart().Length)];
                lines.Insert(end + 1, indent + "throw new global::System.NotSupportedException(\"The decompiler could not decompile this method; see the comment above.\");"
                                      + (lines[i].EndsWith('\r') ? "\r" : ""));
                i = end + 1;
            }
            File.WriteAllText(file, string.Join('\n', lines));
        }
    }

    /// <summary>Project export with the same output cleanup as single members.</summary>
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

    /// <summary>The decompiler handle of a member in the assembly's current image (added members included).</summary>
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
            throw new ToolError($"Decompilation timed out after {options.TimeoutSeconds}s. Decompile a smaller unit (one method via decompile_member), use get_il, or restart the server with a larger --timeout.");
        }
    }

    private static string FirstLine(string s)
    {
        int nl = s.IndexOf('\n');
        return (nl >= 0 ? s[..nl] : s).Trim();
    }
}
