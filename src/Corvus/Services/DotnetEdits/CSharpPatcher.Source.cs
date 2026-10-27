using System.Text.RegularExpressions;
using dnlib.DotNet;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Corvus.Core;
using static Corvus.Core.MetadataUtil;
using SF = Microsoft.CodeAnalysis.CSharp.SyntaxFactory;

namespace Corvus.Services;

/// <summary>Source handling: building the shadow tree, finding members in decompiled code, parsing user code and stubbing bodies.</summary>
public sealed partial class CSharpPatcher
{
    /// <summary>Decompiles the top-level type containing <paramref name="type"/> and applies <paramref name="transform"/>.</summary>
    private SyntaxTree ShadowTree(LoadedAssembly asm, TypeDef type, Func<CompilationUnitSyntax, TypeDeclarationSyntax, CompilationUnitSyntax> transform, CancellationToken ct)
    {
        var top = TopLevel(type);
        var key = $"{asm.Id}|{asm.Version}|{top.MDToken.Raw:X8}";
        string source;
        if (Replay.Value?.Sources.TryGetValue(key, out var earlier) == true) source = earlier;
        else
        {
            PrefetchFriendImage(asm, ct);
            source = decompiler.DecompileType(asm, top, ct, compilable: true);
            Replay.Value?.Sources[key] = source;
        }
        var parseOptions = new CSharpParseOptions(LanguageVersion.Preview);
        var root = CSharpSyntaxTree.ParseText(source, parseOptions, cancellationToken: ct).GetCompilationUnitRoot(ct);
        var typeNode = FindTypeDeclaration(root, type)
                       ?? throw new ToolError(ErrorCode.Unsupported, IsDelegate(type)
                           ? $"{type.FullName} is a delegate with methods or fields, which C# cannot declare; use patch_method_il."
                           : $"Could not locate {type.FullName} in its decompiled source; use patch_method_il instead.");
        return Reused(CSharpSyntaxTree.Create(UsingsInsideNamespaces((CompilationUnitSyntax)new InternalTypes().Visit(transform(root, typeNode))!), parseOptions));
    }

    /// <summary>Moves using directives (plus System) into each namespace's first segment, so imports bind before internal
    /// global types of references (an internal global Exception) but after enclosing namespaces.</summary>
    private static CompilationUnitSyntax UsingsInsideNamespaces(CompilationUnitSyntax root)
    {
        var usings = root.Usings.Where(u => u.GlobalKeyword.IsKind(SyntaxKind.None)).ToList();
        if (!root.Members.OfType<BaseNamespaceDeclarationSyntax>().Any()) return root;
        var moved = SF.List(usings.Select(Rooted));
        if (!moved.Any(u => u.Alias == null && u.StaticKeyword.IsKind(SyntaxKind.None) && u.Name?.ToString() == "global::System"))
            moved = moved.Insert(0, SF.ParseCompilationUnit("using global::System;\n").Usings[0]);
        root = root.WithUsings(SF.List(root.Usings.Where(u => !u.GlobalKeyword.IsKind(SyntaxKind.None))));
        return root.ReplaceNodes(root.Members.OfType<BaseNamespaceDeclarationSyntax>(), (_, ns) => Outermost(ns, moved));
    }

    private static MemberDeclarationSyntax Outermost(BaseNamespaceDeclarationSyntax ns, SyntaxList<UsingDirectiveSyntax> moved)
    {
        if (ns.Name is not QualifiedNameSyntax) return ns.WithUsings(moved.AddRange(ns.Usings));
        var (first, rest) = SplitFirst(ns.Name.ToString());
        // A file-scoped namespace (the decompiler's form) becomes a block, nested in the first segment's.
        var inner = ns is NamespaceDeclarationSyntax block ? block.WithName(SF.ParseName(rest).WithTriviaFrom(block.Name))
            : SF.NamespaceDeclaration(SF.Token(SyntaxKind.NamespaceKeyword).WithTrailingTrivia(SF.Space), SF.ParseName(rest),
                SF.Token(SyntaxKind.OpenBraceToken).WithTrailingTrivia(SF.LineFeed), ns.Externs, ns.Usings, ns.Members,
                SF.Token(SyntaxKind.CloseBraceToken).WithLeadingTrivia(SF.LineFeed), default);
        return SF.NamespaceDeclaration(SF.Token(SyntaxKind.NamespaceKeyword).WithTrailingTrivia(SF.Space), SF.IdentifierName(first),
            SF.Token(SyntaxKind.OpenBraceToken).WithTrailingTrivia(SF.LineFeed), default, moved,
            SF.SingletonList<MemberDeclarationSyntax>(inner), SF.Token(SyntaxKind.CloseBraceToken).WithLeadingTrivia(SF.LineFeed), default);
    }

    /// <summary>"A.B.C" as ("A", "B.C").</summary>
    internal static (string First, string Tail) SplitFirst(string name)
    {
        int dot = name.IndexOf('.');
        return dot < 0 ? (name, "") : (name[..dot].Trim(), name[(dot + 1)..].Trim());
    }

    /// <summary>The directive with its name from the global namespace: inside a namespace, 'System' could name a nested one.</summary>
    private static UsingDirectiveSyntax Rooted(UsingDirectiveSyntax u) =>
        u.Name == null || u.Name is AliasQualifiedNameSyntax || u.Name.ToString().StartsWith("global::", StringComparison.Ordinal) ? u
            : u.WithName(SF.ParseName("global::" + u.Name).WithTriviaFrom(u.Name));

    private static bool IsDelegate(TypeDef type) => type.BaseType?.FullName is "System.MulticastDelegate" or "System.Delegate";

    /// <summary>Makes decompiled types internal: IL lets a member use a less accessible type, C# rejects it
    /// (CS0050-CS0061).</summary>
    private sealed class InternalTypes : CSharpSyntaxRewriter
    {
        private static SyntaxTokenList Internal(SyntaxTokenList modifiers)
        {
            var kept = modifiers.Where(m => !m.IsKind(SyntaxKind.PrivateKeyword) && !m.IsKind(SyntaxKind.ProtectedKeyword) && !m.IsKind(SyntaxKind.PublicKeyword)
                                            && !m.IsKind(SyntaxKind.FileKeyword)).ToList();
            if (!kept.Any(m => m.IsKind(SyntaxKind.InternalKeyword)))
                kept.Insert(0, SF.Token(SyntaxKind.InternalKeyword).WithTrailingTrivia(SF.Space));
            return SF.TokenList(kept);
        }

        public override SyntaxNode? Visit(SyntaxNode? node) => node != null && node.HasAnnotation(UserCode) ? node : base.Visit(node);

        public override SyntaxNode? VisitClassDeclaration(ClassDeclarationSyntax node) => ((ClassDeclarationSyntax)base.VisitClassDeclaration(node)!).WithModifiers(Internal(node.Modifiers));
        public override SyntaxNode? VisitStructDeclaration(StructDeclarationSyntax node) => ((StructDeclarationSyntax)base.VisitStructDeclaration(node)!).WithModifiers(Internal(node.Modifiers));
        public override SyntaxNode? VisitInterfaceDeclaration(InterfaceDeclarationSyntax node) => ((InterfaceDeclarationSyntax)base.VisitInterfaceDeclaration(node)!).WithModifiers(Internal(node.Modifiers));
        public override SyntaxNode? VisitRecordDeclaration(RecordDeclarationSyntax node) => ((RecordDeclarationSyntax)base.VisitRecordDeclaration(node)!).WithModifiers(Internal(node.Modifiers));
        public override SyntaxNode? VisitEnumDeclaration(EnumDeclarationSyntax node) => ((EnumDeclarationSyntax)base.VisitEnumDeclaration(node)!).WithModifiers(Internal(node.Modifiers));
        public override SyntaxNode? VisitDelegateDeclaration(DelegateDeclarationSyntax node) => ((DelegateDeclarationSyntax)base.VisitDelegateDeclaration(node)!).WithModifiers(Internal(node.Modifiers));
    }

    /// <summary>A semantic model of <paramref name="tree"/> (not emitted; errors are irrelevant for binding).</summary>
    private SemanticModel Bind(LoadedAssembly asm, SyntaxTree tree, CancellationToken ct)
    {
        if (Replay.Value?.Models.TryGetValue(tree, out var earlier) == true) return earlier;
        var model = CreateCompilation(asm, tree, null, out _, withUsings: true, ct).GetSemanticModel(tree);
        Replay.Value?.Models[tree] = model;
        return model;
    }

    private CSharpCompilation CreateCompilation(LoadedAssembly asm, SyntaxTree tree, byte[]? targetImage, out List<string> missing, bool withUsings,
        CancellationToken ct, IReadOnlySet<string>? clashing = null)
    {
        var plain = CSharpCompilation.Create(asm.AssemblyName + PatchSuffix, [tree], BuildReferences(asm, targetImage, out missing, ct, clashing), CreateOptions());
        if (!withUsings) return plain;
        var usings = DefaultUsings.Where(ns => NamespaceExists(plain, ns)).ToList();
        return usings.Count == 0 ? plain
            : plain.AddSyntaxTrees(CSharpSyntaxTree.ParseText(string.Concat(usings.Select(u => $"global using {u};\n")), (CSharpParseOptions)tree.Options));
    }

    /// <summary>Simple names of the types reported in two references (CS0433), read from the source they occur at.</summary>
    private static HashSet<string> ClashingTypeNames(IEnumerable<Diagnostic> diagnostics)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var d in diagnostics.Where(d => d.Id == "CS0433" && d.Location.IsInSource))
        {
            var text = d.Location.SourceTree!.GetText().ToString(d.Location.SourceSpan);
            int lt = text.IndexOf('<');
            if (lt >= 0) text = text[..lt];
            text = text[(text.LastIndexOfAny(['.', ':']) + 1)..].Trim().TrimStart('@');
            if (text.Length == 0) continue;
            names.Add(text);
            // [DisallowNull] names DisallowNullAttribute
            if (d.Location.SourceTree.GetRoot().FindNode(d.Location.SourceSpan).AncestorsAndSelf().Any(n => n is AttributeSyntax) && !text.EndsWith("Attribute", StringComparison.Ordinal))
                names.Add(text + "Attribute");
        }
        foreach (var d in diagnostics.Where(d => d.Id == "CS0104"))
            if (AmbiguousPair().Match(d.GetMessage(System.Globalization.CultureInfo.InvariantCulture)) is { Success: true } m)
                names.Add(AmbiguousPrefix + MetadataName(m.Groups[1].Value) + "|" + MetadataName(m.Groups[2].Value));
        return names;
    }

    /// <summary>Marks a CS0104 pair "A|B" (metadata full names) among the clashing names; see <see cref="HideClashingTypes"/>.</summary>
    internal const string AmbiguousPrefix = "ambiguous:";

    [GeneratedRegex(@"between '([^']+)' and '([^']+)'")]
    private static partial Regex AmbiguousPair();

    /// <summary>"System.Func&lt;T, TResult&gt;" as System.Func`2.</summary>
    private static string MetadataName(string display)
    {
        int lt = display.IndexOf('<');
        return lt < 0 ? display : display[..lt] + "`" + (display[lt..].Count(c => c == ',') + 1).ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    private static byte[] WriteImage(ModuleDef module)
    {
        using var ms = new MemoryStream();
        var options = new dnlib.DotNet.Writer.ModuleWriterOptions(module) { Logger = DummyLogger.NoThrowInstance };
        options.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll;
        module.Write(ms, options);
        return ms.ToArray();
    }

    /// <summary>Compiles <paramref name="tree"/>, against <paramref name="targetImage"/> when given; reuses an earlier
    /// run's image (see <see cref="ReplayCache"/>).</summary>
    private ModuleDefMD Compile(LoadedAssembly asm, SyntaxTree tree, Func<byte[]>? targetImage, CancellationToken ct)
    {
        var cache = Replay.Value;
        var key = cache == null ? "" : (targetImage == null ? "module|" : "image|") + tree.GetText(ct);
        if (cache?.Images.TryGetValue(key, out var image) != true)
        {
            image = CompileImage(asm, tree, targetImage?.Invoke(), ct);
            cache?.Images[key] = image;
        }
        return ModuleDefMD.Load(image!, workspace.DnlibContext);
    }

    /// <summary>Roslyn compile runs of this patcher (tests check that an edit compiles each tree once).</summary>
    internal int Compiles;

    private byte[] CompileImage(LoadedAssembly asm, SyntaxTree tree, byte[]? targetImage, CancellationToken ct)
    {
        Interlocked.Increment(ref Compiles);
        var withUsings = CreateCompilation(asm, tree, targetImage, out var missing, withUsings: true, ct);
        // Drop decompiled using directives for namespaces no resolved reference provides; an unused import must not fail the patch.
        var root = tree.GetRoot(ct);
        var unknown = root.DescendantNodes().OfType<Microsoft.CodeAnalysis.CSharp.Syntax.UsingDirectiveSyntax>()
            .Where(u => u.Alias == null && u.StaticKeyword.IsKind(SyntaxKind.None) && u.Name != null && !u.HasAnnotation(UserCode)
                        && u.Ancestors().All(a => !a.HasAnnotation(UserCode)) && !NamespaceExists(withUsings, u.Name.ToString()))
            .ToList();
        if (unknown.Count > 0)
        {
            tree = tree.WithRootAndOptions(root.RemoveNodes(unknown, SyntaxRemoveOptions.KeepNoTrivia)!, tree.Options);
            withUsings = CreateCompilation(asm, tree, targetImage, out missing, withUsings: true, ct);
        }
        using var pe = new MemoryStream();
        var emit = withUsings.Emit(pe, cancellationToken: ct);
        if (!emit.Success && UnboundAttributes(emit.Diagnostics, tree) is { Count: > 0 } unbound)
        {
            // Drop attributes whose type the decompiler hides (EmbeddedAttribute); the patch does not need them.
            var newRoot = tree.GetRoot(ct).RemoveNodes(unbound.SelectMany(a => a.Parent is AttributeListSyntax { Attributes.Count: 1 } list ? [list] : new SyntaxNode[] { a }),
                SyntaxRemoveOptions.KeepNoTrivia)!;
            tree = tree.WithRootAndOptions(newRoot, tree.Options);
            withUsings = CreateCompilation(asm, tree, targetImage, out missing, withUsings: true, ct);
            pe.SetLength(0);
            emit = withUsings.Emit(pe, cancellationToken: ct);
        }
        HashSet<string>? clashing = null;
        if (!emit.Success && ClashingTypeNames(emit.Diagnostics) is { Count: > 0 } clashed)
        {
            clashing = clashed;
            withUsings = CreateCompilation(asm, tree, targetImage, out missing, withUsings: true, ct, clashing);
            pe.SetLength(0);
            emit = withUsings.Emit(pe, cancellationToken: ct);
        }
        if (!emit.Success && UnimplementableInterfaces(emit.Diagnostics, tree, withUsings) is { Count: > 0 } interfaces)
        {
            // The decompiled copy cannot implement interfaces returning the target's own type; only bodies are used, so drop them.
            using var retry = new MemoryStream();
            var without = tree.WithRootAndOptions(tree.GetRoot(ct).RemoveNodes(interfaces, SyntaxRemoveOptions.KeepNoTrivia)!, tree.Options);
            var compilation = CreateCompilation(asm, without, targetImage, out _, withUsings: true, ct, clashing);
            var result = compilation.Emit(retry, cancellationToken: ct);
            // Their explicit implementations (stubs unless one is the patched member) go too.
            var orphans = result.Diagnostics.Where(d => d.Id == "CS0540" && d.Location.SourceTree == without)
                .Select(d => without.GetRoot(ct).FindNode(d.Location.SourceSpan).AncestorsAndSelf().OfType<MemberDeclarationSyntax>().FirstOrDefault())
                .OfType<MemberDeclarationSyntax>().Distinct().ToList();
            if (!result.Success && orphans.Count > 0 && !orphans.Any(o => o.DescendantNodesAndSelf().Any(n => n.HasAnnotation(UserCode))))
            {
                without = without.WithRootAndOptions(without.GetRoot(ct).RemoveNodes(orphans, SyntaxRemoveOptions.KeepNoTrivia)!, tree.Options);
                retry.SetLength(0);
                result = CreateCompilation(asm, without, targetImage, out _, withUsings: true, ct, clashing).Emit(retry, cancellationToken: ct);
            }
            if (result.Success)
                return retry.ToArray();
        }
        if (!emit.Success && withUsings.SyntaxTrees.Length > 1)
        {
            using var retry = new MemoryStream();
            if (withUsings.RemoveSyntaxTrees(withUsings.SyntaxTrees.Skip(1)).Emit(retry, cancellationToken: ct).Success)
                return retry.ToArray();
        }
        if (!emit.Success)
            throw new ToolError(ErrorCode.InvalidArgument, FormatErrors(emit.Diagnostics, tree, missing));
        return pe.ToArray();
    }

    /// <summary>Interfaces in base lists of the decompiled declaration that its types fail to implement (CS0535, CS0738).</summary>
    private static List<SyntaxNode> UnimplementableInterfaces(IEnumerable<Diagnostic> diagnostics, SyntaxTree tree, CSharpCompilation compilation)
    {
        var root = tree.GetRoot();
        var model = compilation.GetSemanticModel(tree);
        return diagnostics
            .Where(d => d.Severity == DiagnosticSeverity.Error && d.Id is "CS0535" or "CS0738" && d.Location.SourceTree == tree)
            .Select(d => root.FindNode(d.Location.SourceSpan).AncestorsAndSelf().OfType<TypeDeclarationSyntax>().FirstOrDefault())
            .OfType<TypeDeclarationSyntax>()
            .Where(t => !t.AncestorsAndSelf().Any(n => n.HasAnnotation(UserCode)) && t.BaseList != null)
            .Distinct()
            .SelectMany(t =>
            {
                var interfaces = t.BaseList!.Types.Where(b => model.GetTypeInfo(b.Type).Type?.TypeKind == TypeKind.Interface).ToList();
                return interfaces.Count == t.BaseList.Types.Count ? [t.BaseList] : interfaces.Cast<SyntaxNode>();
            })
            .ToList();
    }

    /// <summary>Attributes outside the user's code whose type is not found (CS0246, CS0234) or is not an attribute (CS0616).</summary>
    private static List<AttributeSyntax> UnboundAttributes(IEnumerable<Diagnostic> diagnostics, SyntaxTree tree)
    {
        var root = tree.GetRoot();
        return diagnostics
            .Where(d => d.Severity == DiagnosticSeverity.Error && d.Id is "CS0246" or "CS0234" or "CS0616" && d.Location.SourceTree == tree)
            .Select(d => root.FindNode(d.Location.SourceSpan).AncestorsAndSelf().OfType<AttributeSyntax>().FirstOrDefault())
            .OfType<AttributeSyntax>()
            .Where(a => !a.AncestorsAndSelf().Any(n => n.HasAnnotation(UserCode)))
            .Distinct()
            .ToList();
    }

    private static bool NamespaceExists(Compilation compilation, string name)
    {
        INamespaceSymbol? ns = compilation.GlobalNamespace;
        foreach (var part in (name.StartsWith("global::", StringComparison.Ordinal) ? name[8..] : name).Split('.'))
        {
            ns = ns.GetNamespaceMembers().FirstOrDefault(n => n.Name == part);
            if (ns == null) return false;
        }
        return true;
    }

    private static TypeDeclarationSyntax? FindTypeDeclaration(CompilationUnitSyntax root, TypeDef type)
    {
        var chain = new Stack<TypeDef>();
        for (var t = type; t != null; t = t.DeclaringType) chain.Push(t);

        SyntaxNode scope = root;
        TypeDeclarationSyntax? found = null;
        while (chain.Count > 0)
        {
            var t = chain.Pop();
            var name = Format.StripArity(t.Name);
            int tick = t.Name.String.IndexOf('`');
            int arity = tick > 0 && int.TryParse(t.Name.String[(tick + 1)..], out var n) ? n : 0;
            found = scope.DescendantNodes(n => n == scope || n is BaseNamespaceDeclarationSyntax || n is CompilationUnitSyntax)
                .OfType<TypeDeclarationSyntax>()
                .FirstOrDefault(d => SameName(d.Identifier, name) && (d.TypeParameterList?.Parameters.Count ?? 0) == arity);
            if (found == null) return null;
            scope = found;
        }
        return found;
    }

    private static SyntaxNode FindMemberNode(TypeDeclarationSyntax typeNode, MethodDef method)
    {
        var members = typeNode.Members;
        int paramCount = ParamCount(method);
        string Unsupported(string what) => $"{Format.MemberLabel(method)} is {what}, which C# patching does not support; use patch_method_il.";

        if (method.IsConstructor)
        {
            var ctors = members.OfType<ConstructorDeclarationSyntax>()
                .Where(c => c.Modifiers.Any(SyntaxKind.StaticKeyword) == method.IsStatic && c.ParameterList.Parameters.Count == paramCount).ToList();
            return PickByParameters(ctors, c => c.ParameterList, method)
                   ?? throw new ToolError(ErrorCode.Unsupported, method.IsStatic
                       ? "The static constructor does not appear in the decompiled source (it only initializes fields there); use patch_method_il."
                       : "The constructor does not appear in the decompiled source (compiler-generated default constructor); use patch_method_il.");
        }

        var property = method.DeclaringType.Properties.FirstOrDefault(p => p.GetMethods.Contains(method) || p.SetMethods.Contains(method));
        if (property != null)
        {
            var keyword = property.GetMethods.Contains(method) ? SyntaxKind.GetAccessorDeclaration : SyntaxKind.SetAccessorDeclaration;
            var name = LastSegment(property.Name);
            BasePropertyDeclarationSyntax? decl = property.PropertySig?.Params.Count > 0
                ? members.OfType<IndexerDeclarationSyntax>().FirstOrDefault(i => i.ParameterList.Parameters.Count == property.PropertySig.Params.Count)
                : members.OfType<PropertyDeclarationSyntax>().FirstOrDefault(p => SameName(p.Identifier, name));
            if (decl == null) throw new ToolError(ErrorCode.NotFound, $"Property {property.Name} not found in the decompiled source.");
            if (decl is PropertyDeclarationSyntax { ExpressionBody: not null } or IndexerDeclarationSyntax { ExpressionBody: not null })
                return decl; // expression-bodied property; the rewriter converts it to a get accessor
            var accessor = decl.AccessorList?.Accessors.FirstOrDefault(a => a.IsKind(keyword) || (keyword == SyntaxKind.SetAccessorDeclaration && a.IsKind(SyntaxKind.InitAccessorDeclaration)));
            if (accessor == null) throw new ToolError(ErrorCode.NotFound, $"Accessor not found for {property.Name}.");
            if (accessor.Body == null && accessor.ExpressionBody == null)
                throw new ToolError(ErrorCode.Unsupported, Unsupported("an auto-property accessor"));
            return accessor;
        }

        var ev = method.DeclaringType.Events.FirstOrDefault(e => e.AddMethod == method || e.RemoveMethod == method);
        if (ev != null)
        {
            var decl = members.OfType<EventDeclarationSyntax>().FirstOrDefault(e => SameName(e.Identifier, LastSegment(ev.Name)))
                       ?? throw new ToolError(ErrorCode.Unsupported, Unsupported("an accessor of a field-like event"));
            var kind = ev.AddMethod == method ? SyntaxKind.AddAccessorDeclaration : SyntaxKind.RemoveAccessorDeclaration;
            return decl.AccessorList?.Accessors.FirstOrDefault(a => a.IsKind(kind)) ?? throw new ToolError(ErrorCode.NotFound, $"Accessor not found for event {ev.Name}.");
        }

        if (method.Name.StartsWith("op_", StringComparison.Ordinal))
            throw new ToolError(ErrorCode.Unsupported, Unsupported("an operator"));

        var methodName = LastSegment(method.Name);
        bool isExplicit = method.Name.String.Contains('.');
        var candidates = members.OfType<MethodDeclarationSyntax>()
            .Where(m => SameName(m.Identifier, methodName)
                        && (m.ExplicitInterfaceSpecifier != null) == isExplicit
                        && (m.TypeParameterList?.Parameters.Count ?? 0) == method.GenericParameters.Count
                        && m.ParameterList.Parameters.Count == paramCount)
            .ToList();
        var node = PickByParameters(candidates, m => m.ParameterList, method)
                   ?? throw new ToolError(ErrorCode.Unsupported, $"Could not find {Format.MemberLabel(method)} in the decompiled source (it may be compiler-generated); use patch_method_il.");
        if (node.Body == null && node.ExpressionBody == null)
            throw new ToolError(ErrorCode.Unsupported, Unsupported("declared without a body"));
        return node;
    }

    private static T? PickByParameters<T>(List<T> candidates, Func<T, ParameterListSyntax> parameters, MethodDef method) where T : SyntaxNode
    {
        if (candidates.Count <= 1) return candidates.FirstOrDefault();
        var wanted = method.MethodSig.Params.Select(p => NormalizeTypeText(Format.Type(p))).ToList();
        return candidates.FirstOrDefault(c => parameters(c).Parameters
                   .Select(p => NormalizeTypeText((p.Modifiers.Any(SyntaxKind.RefKeyword) || p.Modifiers.Any(SyntaxKind.OutKeyword) || p.Modifiers.Any(SyntaxKind.InKeyword) ? "ref " : "") + p.Type))
                   .SequenceEqual(wanted))
               ?? throw new ToolError(ErrorCode.Ambiguous, $"Several overloads of {method.Name} match by parameter count and none by parameter types; use patch_method_il with the token.");
    }

    private static string NormalizeTypeText(string type)
    {
        var s = type.Replace("global::", "").Replace(" ", "");
        s = Regex.Replace(s, @"Nullable<([^<>]+)>", "$1?");
        s = Regex.Replace(s, @"\b(?:[A-Za-z_]\w*\.)+(?=[A-Za-z_])", ""); // drop namespace qualifiers
        s = Regex.Replace(s, @"\bdecimal\b", "Decimal"); // System.Decimal has no element type: labels spell it Decimal
        return s.Replace("?", "");
    }

    /// <summary>The decompiler's compilable identifier for a metadata name (EscapeInvalidIdentifiers: other characters
    /// become _XXXX).</summary>
    internal static string SourceName(string name)
    {
        var escaped = string.Concat(name.Select(ch => char.IsLetterOrDigit(ch) || ch == '_' ? ch.ToString() : $"_{(int)ch:X4}"));
        return escaped.Length >= 1 && !char.IsLetter(escaped[0]) && escaped[0] != '_' ? "_" + escaped : escaped;
    }

    private static bool SameName(SyntaxToken identifier, string name) =>
        identifier.ValueText == name || identifier.Text == name || identifier.ValueText == SourceName(name);

    /// <summary>The full metadata name a type gets when its decompiled declaration is compiled again (see <see cref="SourceName"/>).</summary>
    internal static string CompiledFullName(TypeDef type)
    {
        string Simple(TypeDef t)
        {
            int tick = t.Name.String.IndexOf('`');
            return SourceName(Format.StripArity(t.Name)) + (tick > 0 ? t.Name.String[tick..] : "");
        }
        if (type.DeclaringType != null) return CompiledFullName(type.DeclaringType) + "/" + Simple(type);
        var ns = type.Namespace.String;
        return (ns.Length == 0 ? "" : string.Join(".", ns.Split('.').Select(SourceName)) + ".") + Simple(type);
    }

    private static string LastSegment(string name)
    {
        int dot = name.LastIndexOf('.');
        return dot >= 0 ? name[(dot + 1)..] : name;
    }

    private static BlockSyntax ParseBody(string code)
    {
        var text = code.Trim();
        if (text.Length == 0)
            throw new ToolError(ErrorCode.InvalidArgument, "The C# body is empty; pass 'return;' for a void method that does nothing.");
        if (!text.StartsWith('{'))
            text = "{\n" + text + "\n}";
        var statement = SF.ParseStatement(text, options: new CSharpParseOptions(LanguageVersion.Preview));
        if (statement is not BlockSyntax block || statement.GetDiagnostics().Any(d => d.Severity == DiagnosticSeverity.Error))
        {
            var errors = statement.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error)
                .Select(d => $"  line {d.Location.GetLineSpan().StartLinePosition.Line}: {d.GetMessage()}");
            throw new ToolError(ErrorCode.InvalidArgument, "The C# body does not parse; pass statements, not a whole method or class:\n" + string.Join("\n", errors));
        }
        return block;
    }

    /// <summary>Parses member declarations (methods, fields, properties, events, constructors, nested types) for a type named <paramref name="typeName"/>.</summary>
    private static List<MemberDeclarationSyntax> ParseMembers(string code, string typeName)
    {
        if (string.IsNullOrWhiteSpace(code))
            throw new ToolError(ErrorCode.InvalidArgument, "No member declarations given.");
        var unit = SF.ParseCompilationUnit("class __PatchMembers__ {\n" + code + "\n}", options: new CSharpParseOptions(LanguageVersion.Preview));
        var errors = unit.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
        var holder = unit.Members.OfType<ClassDeclarationSyntax>().FirstOrDefault();
        if (errors.Count > 0 || holder == null || unit.Members.Count != 1)
            throw new ToolError(ErrorCode.InvalidArgument, "The member declarations do not parse; pass complete declarations such as 'public int Twice(int x) { return x * 2; }':\n" +
                                string.Join("\n", errors.Take(10).Select(d => $"  line {d.Location.GetLineSpan().StartLinePosition.Line}: {d.GetMessage()}")));

        var result = new List<MemberDeclarationSyntax>();
        foreach (var member in holder.Members)
        {
            switch (member)
            {
                case FieldDeclarationSyntax f when !f.Modifiers.Any(SyntaxKind.ConstKeyword) && f.Declaration.Variables.Any(v => v.Initializer != null):
                case PropertyDeclarationSyntax { Initializer: not null }:
                    throw new ToolError(ErrorCode.Unsupported, "Added fields and properties cannot have initializers, which would have to run in existing constructors; set them from a method.");
            }
            var adjusted = member is ConstructorDeclarationSyntax ctor ? ctor.WithIdentifier(SF.Identifier(typeName)) : member;
            result.Add(adjusted.WithAdditionalAnnotations(UserCode));
        }
        if (result.Count == 0)
            throw new ToolError(ErrorCode.InvalidArgument, "No member declarations given.");
        return result;
    }

    /// <summary>Phase-1 declaration: method/accessor bodies that phase 2 compiles as helpers become "throw null".</summary>
    private static MemberDeclarationSyntax StubHelperBodies(MemberDeclarationSyntax member)
    {
        var stub = SF.Block(SF.ParseStatement("throw null;"));
        return member switch
        {
            MethodDeclarationSyntax m when (m.Body != null || m.ExpressionBody != null) && !m.DescendantNodes().OfType<BaseExpressionSyntax>().Any() =>
                m.WithBody(stub).WithExpressionBody(null).WithSemicolonToken(default),
            BasePropertyDeclarationSyntax p when !p.DescendantNodes().OfType<BaseExpressionSyntax>().Any() => StubAccessors(p, stub),
            _ => member,
        };
    }

    private static MemberDeclarationSyntax StubAccessors(BasePropertyDeclarationSyntax p, BlockSyntax stub)
    {
        if (p is PropertyDeclarationSyntax { ExpressionBody: not null } prop)
            return prop.WithExpressionBody(null).WithSemicolonToken(default)
                .WithAccessorList(SF.AccessorList(SF.SingletonList(SF.AccessorDeclaration(SyntaxKind.GetAccessorDeclaration, stub))));
        if (p is IndexerDeclarationSyntax { ExpressionBody: not null } indexer)
            return indexer.WithExpressionBody(null).WithSemicolonToken(default)
                .WithAccessorList(SF.AccessorList(SF.SingletonList(SF.AccessorDeclaration(SyntaxKind.GetAccessorDeclaration, stub))));
        if (p.AccessorList == null) return p;
        var accessors = p.AccessorList.Accessors.Select(a => a.Body != null || a.ExpressionBody != null
            ? a.WithBody(stub).WithExpressionBody(null).WithSemicolonToken(default) : a);
        return p.WithAccessorList(p.AccessorList.WithAccessors(SF.List(accessors)));
    }

    /// <summary>Phase-2 form: expression bodies become blocks so every body is a BlockSyntax the helper can compile.</summary>
    private static MemberDeclarationSyntax BlockBodies(MemberDeclarationSyntax member)
    {
        static BlockSyntax Block(ArrowExpressionClauseSyntax arrow, bool returns) =>
            SF.Block(returns ? SF.ReturnStatement(arrow.Expression.WithoutTrivia()) : SF.ExpressionStatement(arrow.Expression.WithoutTrivia())).NormalizeWhitespace();
        return member switch
        {
            MethodDeclarationSyntax { ExpressionBody: { } e } m =>
                m.WithBody(Block(e, ReturnsValue(m)))
                 .WithExpressionBody(null).WithSemicolonToken(default),
            PropertyDeclarationSyntax { ExpressionBody: { } e } p =>
                p.WithExpressionBody(null).WithSemicolonToken(default)
                 .WithAccessorList(SF.AccessorList(SF.SingletonList(SF.AccessorDeclaration(SyntaxKind.GetAccessorDeclaration, Block(e, true))))),
            IndexerDeclarationSyntax { ExpressionBody: { } e } i =>
                i.WithExpressionBody(null).WithSemicolonToken(default)
                 .WithAccessorList(SF.AccessorList(SF.SingletonList(SF.AccessorDeclaration(SyntaxKind.GetAccessorDeclaration, Block(e, true))))),
            BasePropertyDeclarationSyntax { AccessorList: { } list } p =>
                p.WithAccessorList(list.WithAccessors(SF.List(list.Accessors.Select(a => a.ExpressionBody is { } ae
                    ? a.WithBody(Block(ae, a.IsKind(SyntaxKind.GetAccessorDeclaration))).WithExpressionBody(null).WithSemicolonToken(default) : a)))),
            _ => member,
        };
    }

    /// <summary>Whether "=> expr" means "return expr;" (not for void, and not for async Task/ValueTask without a result).</summary>
    private static bool ReturnsValue(MethodDeclarationSyntax m)
    {
        if (m.ReturnType is PredefinedTypeSyntax { Keyword.RawKind: (int)SyntaxKind.VoidKeyword }) return false;
        bool isAsync = m.Modifiers.Any(SyntaxKind.AsyncKeyword);
        var typeName = m.ReturnType is QualifiedNameSyntax q ? q.Right.Identifier.Text : (m.ReturnType as IdentifierNameSyntax)?.Identifier.Text;
        return !(isAsync && typeName is "Task" or "ValueTask");
    }

    private static TypeDeclarationSyntax? OwnerTypeOf(SyntaxNode node) => node.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault();

    /// <summary>True for bodies inside a nested type the user added (those are compiled in phase 1).</summary>
    private static bool IsInNestedUserType(SyntaxNode node) =>
        node.Ancestors().OfType<BaseTypeDeclarationSyntax>().Any(t => t.HasAnnotation(UserCode));

    private static bool SameParameters(MethodDef compiled, IMethodSymbol symbol)
    {
        if (compiled.MethodSig.Params.Count != symbol.Parameters.Length) return false;
        for (int i = 0; i < symbol.Parameters.Length; i++)
            if (NormalizeTypeText(Format.Type(compiled.MethodSig.Params[i]).Replace("ref ", ""))
                != NormalizeTypeText(symbol.Parameters[i].Type.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat)))
                return false;
        return true;
    }

    /// <summary>Metadata names declared by the members, including accessor and constructor names.</summary>
    private static HashSet<string> DeclaredNames(IEnumerable<MemberDeclarationSyntax> members)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var m in members)
        {
            switch (m)
            {
                case MethodDeclarationSyntax md: names.Add(md.Identifier.Text); break;
                case ConstructorDeclarationSyntax cd: names.Add(cd.Modifiers.Any(SyntaxKind.StaticKeyword) ? ".cctor" : ".ctor"); break;
                case PropertyDeclarationSyntax pd: names.UnionWith([pd.Identifier.Text, "get_" + pd.Identifier.Text, "set_" + pd.Identifier.Text]); break;
                case IndexerDeclarationSyntax: names.UnionWith(["Item", "get_Item", "set_Item"]); break;
                case EventDeclarationSyntax ed: names.UnionWith([ed.Identifier.Text, "add_" + ed.Identifier.Text, "remove_" + ed.Identifier.Text]); break;
                case EventFieldDeclarationSyntax ef:
                    foreach (var v in ef.Declaration.Variables) names.UnionWith([v.Identifier.Text, "add_" + v.Identifier.Text, "remove_" + v.Identifier.Text]);
                    break;
                case FieldDeclarationSyntax fd:
                    foreach (var v in fd.Declaration.Variables) names.Add(v.Identifier.Text);
                    break;
                case BaseTypeDeclarationSyntax td: names.Add(td.Identifier.Text + (td is TypeDeclarationSyntax { TypeParameterList: { } tp } ? "`" + tp.Parameters.Count : "")); break;
                case DelegateDeclarationSyntax dd: names.Add(dd.Identifier.Text); break;
            }
        }
        return names;
    }

    /// <summary>Puts the new body on the target and "throw null" in other bodies, skipping user members; initializers are
    /// dropped unless a constructor of the same kind is patched.</summary>
    private sealed class StubRewriter(SyntaxNode? target, BlockSyntax? newBody) : CSharpSyntaxRewriter
    {
        private static readonly BlockSyntax Stub = SF.Block(SF.ParseStatement("throw null;"));

        private readonly bool _keepInstanceInitializers = target is ConstructorDeclarationSyntax c && !c.Modifiers.Any(SyntaxKind.StaticKeyword);
        private readonly bool _keepStaticInitializers = target is ConstructorDeclarationSyntax s && s.Modifiers.Any(SyntaxKind.StaticKeyword);

        private bool KeepInitializer(SyntaxTokenList modifiers) =>
            modifiers.Any(SyntaxKind.ConstKeyword) || (modifiers.Any(SyntaxKind.StaticKeyword) ? _keepStaticInitializers : _keepInstanceInitializers);

        private BlockSyntax BodyFor(SyntaxNode original) => original == target ? newBody! : Stub;

        public override SyntaxNode? Visit(SyntaxNode? node) => node != null && node.HasAnnotation(UserCode) ? node : base.Visit(node);

        public override SyntaxNode? VisitMethodDeclaration(MethodDeclarationSyntax node)
        {
            if (node.Body == null && node.ExpressionBody == null) return node;
            var rewritten = node.WithBody(BodyFor(node)).WithExpressionBody(null).WithSemicolonToken(default);
            // A stub compiled as async gets a state machine, which would be merged as a new, unused type.
            return node == target ? rewritten : rewritten.WithModifiers(SF.TokenList(rewritten.Modifiers.Where(m => !m.IsKind(SyntaxKind.AsyncKeyword))));
        }

        public override SyntaxNode? VisitConstructorDeclaration(ConstructorDeclarationSyntax node) =>
            node.Body == null && node.ExpressionBody == null ? node
                : node.WithBody(BodyFor(node)).WithExpressionBody(null).WithSemicolonToken(default);

        public override SyntaxNode? VisitDestructorDeclaration(DestructorDeclarationSyntax node) =>
            node.WithBody(Stub).WithExpressionBody(null).WithSemicolonToken(default);

        public override SyntaxNode? VisitOperatorDeclaration(OperatorDeclarationSyntax node) =>
            node.Body == null && node.ExpressionBody == null ? node : node.WithBody(Stub).WithExpressionBody(null).WithSemicolonToken(default);

        public override SyntaxNode? VisitConversionOperatorDeclaration(ConversionOperatorDeclarationSyntax node) =>
            node.Body == null && node.ExpressionBody == null ? node : node.WithBody(Stub).WithExpressionBody(null).WithSemicolonToken(default);

        public override SyntaxNode? VisitAccessorDeclaration(AccessorDeclarationSyntax node) =>
            node.Body == null && node.ExpressionBody == null ? node
                : node.WithBody(BodyFor(node)).WithExpressionBody(null).WithSemicolonToken(default);

        public override SyntaxNode? VisitPropertyDeclaration(PropertyDeclarationSyntax node)
        {
            var original = node;
            node = (PropertyDeclarationSyntax)base.VisitPropertyDeclaration(node)!;
            if (node.ExpressionBody != null)
                node = node.WithExpressionBody(null).WithSemicolonToken(default)
                    .WithAccessorList(SF.AccessorList(SF.SingletonList(SF.AccessorDeclaration(SyntaxKind.GetAccessorDeclaration, BodyFor(original)))));
            if (node.Initializer != null && !KeepInitializer(node.Modifiers))
                node = node.WithInitializer(null).WithSemicolonToken(default);
            return node;
        }

        public override SyntaxNode? VisitIndexerDeclaration(IndexerDeclarationSyntax node)
        {
            var original = node;
            node = (IndexerDeclarationSyntax)base.VisitIndexerDeclaration(node)!;
            return node.ExpressionBody == null ? node
                : node.WithExpressionBody(null).WithSemicolonToken(default)
                    .WithAccessorList(SF.AccessorList(SF.SingletonList(SF.AccessorDeclaration(SyntaxKind.GetAccessorDeclaration, BodyFor(original)))));
        }

        public override SyntaxNode? VisitFieldDeclaration(FieldDeclarationSyntax node) =>
            KeepInitializer(node.Modifiers) ? node
                : node.WithDeclaration(node.Declaration.WithVariables(SF.SeparatedList(node.Declaration.Variables.Select(v => v.WithInitializer(null)))));

        public override SyntaxNode? VisitEventFieldDeclaration(EventFieldDeclarationSyntax node) =>
            KeepInitializer(node.Modifiers) ? node
                : node.WithDeclaration(node.Declaration.WithVariables(SF.SeparatedList(node.Declaration.Variables.Select(v => v.WithInitializer(null)))));
    }
}
