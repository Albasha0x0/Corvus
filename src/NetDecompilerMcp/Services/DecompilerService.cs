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
    // Weak keys: entries are collected with their assembly.
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
        // Keyed by workspace generation and the assembly's edit version; several edits can occur under one write lock.
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

    /// <summary>Decompiles a whole type, falling back to member-by-member output if the engine fails on the type.</summary>
    public string DecompileType(LoadedAssembly asm, Dn.TypeDef type, CancellationToken ct) => InvalidBodiesNote(asm, type) + WithTimeout(token =>
    {
        var decompiler = CreateDecompiler(asm, token);
        try
        {
            // The name API emits the namespace and usings; decompiling by handle does not. Nested and
            // compiler-generated types (empty from the name API) use the handle.
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

    /// <summary>A warning line when some of the type's method bodies are not valid IL; empty otherwise.</summary>
    private static string InvalidBodiesNote(LoadedAssembly asm, Dn.TypeDef type)
    {
        if (asm.IsDirty || asm.BodyHealth.Invalid == 0) return "";
        var methods = type.Methods.Where(m => m.RVA != 0).ToList();
        int invalid = methods.Count(asm.BodyHealth.IsInvalid);
        return invalid == 0 ? "" : $"// Warning: {invalid} of {methods.Count} method bodies of this type are not valid IL (encrypted, or dumped from memory before decryption): their code below is meaningless.\n";
    }

    /// <summary>Decompiles each member, falling back to IL for any member that fails.</summary>
    public string DecompileMembers(LoadedAssembly asm, IEnumerable<Dn.IMemberDef> members, CancellationToken ct) => WithTimeout(token =>
    {
        var decompiler = CreateDecompiler(asm, token);
        var parts = members.Select(m => DecompileMemberSafe(asm, m, decompiler, token));
        return string.Join("\n", parts);
    }, ct);

    /// <summary>
    /// Shows a constructor within its type, trimmed to the header, the field/property initializers of the same kind
    /// (instance or static) and the constructors, since the engine moves part of its body into initializers or a
    /// primary constructor. Null when there are none.
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

    public sealed record ExportResult(string Directory, int FileCount, string? ProjectFile, IReadOnlyList<string> FailedTypes);

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

    /// <summary>Writes a buildable C# project (one file per type, .csproj, resources) to an empty directory.</summary>
    public ExportResult ExportProject(LoadedAssembly asm, string outputDirectory, Action<int, int, string>? onProgress, CancellationToken ct)
    {
        var dir = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(dir);
        if (Directory.EnumerateFileSystemEntries(dir).Any())
            throw new ToolError($"Output directory is not empty: {dir}. Choose an empty or new directory.");

        // Project export gets 10x the normal timeout.
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(options.TimeoutSeconds * 10L));
        // Method-call LINQ: query syntax reconstruction can leak compiler names (<>h__TransparentIdentifier0).
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
    /// Writes embedded (e.g. Costura-packed) assemblies and stubs for unresolved references to <c>lib\</c>, points
    /// the engine's <c>Host!Name.dll</c> hint paths there, and references the remaining packed assemblies, which
    /// the compiler needs as transitive dependencies.
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
        // Unresolved references: use generated stubs so the project still builds.
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
        // Rewrite the engine's placeholder paths for embedded references.
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
            throw new ToolError($"Decompilation timed out after {options.TimeoutSeconds}s. Decompile a smaller unit (one method via decompile_member), use get_il, or restart the server with a larger --timeout.");
        }
    }

    private static string FirstLine(string s)
    {
        int nl = s.IndexOf('\n');
        return (nl >= 0 ? s[..nl] : s).Trim();
    }
}
