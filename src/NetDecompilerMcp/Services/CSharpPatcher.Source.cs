using System.Text.RegularExpressions;
using dnlib.DotNet;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using NetDecompilerMcp.Core;
using static NetDecompilerMcp.Services.MetadataUtil;
using SF = Microsoft.CodeAnalysis.CSharp.SyntaxFactory;

namespace NetDecompilerMcp.Services;

/// <summary>Source handling: building the shadow tree, finding members in decompiled code, parsing user code and stubbing bodies.</summary>
public sealed partial class CSharpPatcher
{
    /// <summary>Decompiles the top-level type containing <paramref name="type"/> and applies <paramref name="transform"/>.</summary>
    private SyntaxTree ShadowTree(LoadedAssembly asm, TypeDef type, Func<CompilationUnitSyntax, TypeDeclarationSyntax, CompilationUnitSyntax> transform, CancellationToken ct)
    {
        var source = decompiler.DecompileType(asm, TopLevel(type), ct);
        var parseOptions = new CSharpParseOptions(LanguageVersion.Preview);
        var root = CSharpSyntaxTree.ParseText(source, parseOptions, cancellationToken: ct).GetCompilationUnitRoot(ct);
        var typeNode = FindTypeDeclaration(root, type)
                       ?? throw new ToolError($"Could not locate {type.FullName} in its decompiled source; use patch_method_il instead.");
        return CSharpSyntaxTree.Create(transform(root, typeNode), parseOptions);
    }

    /// <summary>A semantic model of <paramref name="tree"/> (not emitted; errors are irrelevant for binding).</summary>
    private SemanticModel Bind(LoadedAssembly asm, SyntaxTree tree, byte[]? targetImage)
    {
        var compilation = CreateCompilation(asm, tree, targetImage, out _, withUsings: true);
        return compilation.GetSemanticModel(tree);
    }

    private CSharpCompilation CreateCompilation(LoadedAssembly asm, SyntaxTree tree, byte[]? targetImage, out List<string> missing, bool withUsings)
    {
        var plain = CSharpCompilation.Create(asm.AssemblyName + ".__patch", [tree], BuildReferences(asm, targetImage, out missing), CreateOptions());
        if (!withUsings) return plain;
        var usings = DefaultUsings.Where(ns => NamespaceExists(plain, ns)).ToList();
        return usings.Count == 0 ? plain
            : plain.AddSyntaxTrees(CSharpSyntaxTree.ParseText(string.Concat(usings.Select(u => $"global using {u};\n")), (CSharpParseOptions)tree.Options));
    }

    private static byte[] WriteImage(ModuleDef module)
    {
        using var ms = new MemoryStream();
        var options = new dnlib.DotNet.Writer.ModuleWriterOptions(module) { Logger = DummyLogger.NoThrowInstance };
        options.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll;
        module.Write(ms, options);
        return ms.ToArray();
    }

    private ModuleDefMD Compile(LoadedAssembly asm, SyntaxTree tree, byte[]? targetImage, CancellationToken ct)
    {
        var withUsings = CreateCompilation(asm, tree, targetImage, out var missing, withUsings: true);
        // the decompiled context's using directives of namespaces no resolved reference provides (an unavailable WinRT
        // contract, a missing library) are dropped: an unused import must not fail the whole patch
        var root = tree.GetRoot(ct);
        var unknown = root.DescendantNodes().OfType<Microsoft.CodeAnalysis.CSharp.Syntax.UsingDirectiveSyntax>()
            .Where(u => u.Alias == null && u.StaticKeyword.IsKind(SyntaxKind.None) && u.Name != null && !u.HasAnnotation(UserCode)
                        && u.Ancestors().All(a => !a.HasAnnotation(UserCode)) && !NamespaceExists(withUsings, u.Name.ToString()))
            .ToList();
        if (unknown.Count > 0)
        {
            tree = tree.WithRootAndOptions(root.RemoveNodes(unknown, SyntaxRemoveOptions.KeepNoTrivia)!, tree.Options);
            withUsings = CreateCompilation(asm, tree, targetImage, out missing, withUsings: true);
        }
        using var pe = new MemoryStream();
        var emit = withUsings.Emit(pe, cancellationToken: ct);
        if (!emit.Success && withUsings.SyntaxTrees.Length > 1)
        {
            using var retry = new MemoryStream();
            if (withUsings.RemoveSyntaxTrees(withUsings.SyntaxTrees.Skip(1)).Emit(retry, cancellationToken: ct).Success)
                return ModuleDefMD.Load(retry.ToArray(), workspace.DnlibContext);
        }
        if (!emit.Success)
            throw new ToolError(FormatErrors(emit.Diagnostics, tree, missing));
        return ModuleDefMD.Load(pe.ToArray(), workspace.DnlibContext);
    }

    private static bool NamespaceExists(Compilation compilation, string name)
    {
        INamespaceSymbol? ns = compilation.GlobalNamespace;
        foreach (var part in name.Split('.'))
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
                .FirstOrDefault(d => d.Identifier.Text == name && (d.TypeParameterList?.Parameters.Count ?? 0) == arity);
            if (found == null) return null;
            scope = found;
        }
        return found;
    }

    private static SyntaxNode FindMemberNode(TypeDeclarationSyntax typeNode, MethodDef method)
    {
        var members = typeNode.Members;
        int paramCount = ParamCount(method);
        string Unsupported(string what) => $"{Format.MemberLabel(method)} is {what}; C# patching supports methods, constructors and property/indexer/event accessors. Use patch_method_il.";

        if (method.IsConstructor)
        {
            var ctors = members.OfType<ConstructorDeclarationSyntax>()
                .Where(c => c.Modifiers.Any(SyntaxKind.StaticKeyword) == method.IsStatic && c.ParameterList.Parameters.Count == paramCount).ToList();
            return PickByParameters(ctors, c => c.ParameterList, method)
                   ?? throw new ToolError(method.IsStatic
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
                : members.OfType<PropertyDeclarationSyntax>().FirstOrDefault(p => p.Identifier.Text == name);
            if (decl == null) throw new ToolError($"Property {property.Name} not found in the decompiled source.");
            if (decl is PropertyDeclarationSyntax { ExpressionBody: not null } or IndexerDeclarationSyntax { ExpressionBody: not null })
                return decl; // "=> expr" getter-only property: the rewriter turns it into a get accessor
            var accessor = decl.AccessorList?.Accessors.FirstOrDefault(a => a.IsKind(keyword) || (keyword == SyntaxKind.SetAccessorDeclaration && a.IsKind(SyntaxKind.InitAccessorDeclaration)));
            if (accessor == null) throw new ToolError($"Accessor not found for {property.Name}.");
            if (accessor.Body == null && accessor.ExpressionBody == null)
                throw new ToolError(Unsupported("an auto-property accessor"));
            return accessor;
        }

        var ev = method.DeclaringType.Events.FirstOrDefault(e => e.AddMethod == method || e.RemoveMethod == method);
        if (ev != null)
        {
            var decl = members.OfType<EventDeclarationSyntax>().FirstOrDefault(e => e.Identifier.Text == LastSegment(ev.Name))
                       ?? throw new ToolError(Unsupported("an accessor of a field-like event"));
            var kind = ev.AddMethod == method ? SyntaxKind.AddAccessorDeclaration : SyntaxKind.RemoveAccessorDeclaration;
            return decl.AccessorList?.Accessors.FirstOrDefault(a => a.IsKind(kind)) ?? throw new ToolError($"Accessor not found for event {ev.Name}.");
        }

        if (method.Name.StartsWith("op_", StringComparison.Ordinal))
            throw new ToolError(Unsupported("an operator"));

        var methodName = LastSegment(method.Name);
        bool isExplicit = method.Name.String.Contains('.');
        var candidates = members.OfType<MethodDeclarationSyntax>()
            .Where(m => m.Identifier.Text == methodName
                        && (m.ExplicitInterfaceSpecifier != null) == isExplicit
                        && (m.TypeParameterList?.Parameters.Count ?? 0) == method.GenericParameters.Count
                        && m.ParameterList.Parameters.Count == paramCount)
            .ToList();
        var node = PickByParameters(candidates, m => m.ParameterList, method)
                   ?? throw new ToolError($"Could not find {Format.MemberLabel(method)} in the decompiled source (it may be compiler-generated); use patch_method_il.");
        if (node.Body == null && node.ExpressionBody == null)
            throw new ToolError(Unsupported("declared without a body"));
        return node;
    }

    private static T? PickByParameters<T>(List<T> candidates, Func<T, ParameterListSyntax> parameters, MethodDef method) where T : SyntaxNode
    {
        if (candidates.Count <= 1) return candidates.FirstOrDefault();
        var wanted = method.MethodSig.Params.Select(p => NormalizeTypeText(Format.Type(p))).ToList();
        return candidates.FirstOrDefault(c => parameters(c).Parameters
                   .Select(p => NormalizeTypeText((p.Modifiers.Any(SyntaxKind.RefKeyword) || p.Modifiers.Any(SyntaxKind.OutKeyword) || p.Modifiers.Any(SyntaxKind.InKeyword) ? "ref " : "") + p.Type))
                   .SequenceEqual(wanted))
               ?? throw new ToolError($"Several overloads of {method.Name} match by parameter count and none by parameter types; use patch_method_il with the token.");
    }

    private static string NormalizeTypeText(string type)
    {
        var s = type.Replace("global::", "").Replace(" ", "");
        s = Regex.Replace(s, @"Nullable<([^<>]+)>", "$1?");
        s = Regex.Replace(s, @"\b(?:[A-Za-z_]\w*\.)+(?=[A-Za-z_])", ""); // drop namespace qualifiers
        return s.Replace("?", "");
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
            throw new ToolError("The C# body is empty. For a void method that does nothing, pass 'return;'.");
        if (!text.StartsWith('{'))
            text = "{\n" + text + "\n}";
        var statement = SF.ParseStatement(text, options: new CSharpParseOptions(LanguageVersion.Preview));
        if (statement is not BlockSyntax block || statement.GetDiagnostics().Any(d => d.Severity == DiagnosticSeverity.Error))
        {
            var errors = statement.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error)
                .Select(d => $"  line {d.Location.GetLineSpan().StartLinePosition.Line}: {d.GetMessage()}");
            throw new ToolError("The C# body does not parse. Pass statements (the method body), not a whole method or class:\n" + string.Join("\n", errors));
        }
        return block;
    }

    /// <summary>Parses member declarations (methods, fields, properties, events, constructors, nested types) for a type named <paramref name="typeName"/>.</summary>
    private static List<MemberDeclarationSyntax> ParseMembers(string code, string typeName)
    {
        if (string.IsNullOrWhiteSpace(code))
            throw new ToolError("No member declarations given.");
        var unit = SF.ParseCompilationUnit("class __NetDecompMembers__ {\n" + code + "\n}", options: new CSharpParseOptions(LanguageVersion.Preview));
        var errors = unit.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
        var holder = unit.Members.OfType<ClassDeclarationSyntax>().FirstOrDefault();
        if (errors.Count > 0 || holder == null || unit.Members.Count != 1)
            throw new ToolError("The member declarations do not parse. Pass complete member declarations (e.g. 'public int Twice(int x) { return x * 2; }'):\n" +
                                string.Join("\n", errors.Take(10).Select(d => $"  line {d.Location.GetLineSpan().StartLinePosition.Line}: {d.GetMessage()}")));

        var result = new List<MemberDeclarationSyntax>();
        foreach (var member in holder.Members)
        {
            switch (member)
            {
                case FieldDeclarationSyntax f when !f.Modifiers.Any(SyntaxKind.ConstKeyword) && f.Declaration.Variables.Any(v => v.Initializer != null):
                case PropertyDeclarationSyntax { Initializer: not null }:
                    throw new ToolError("Initializers on added fields/properties are not supported (they would have to run in existing constructors). Initialize them from a method instead.");
            }
            var adjusted = member is ConstructorDeclarationSyntax ctor ? ctor.WithIdentifier(SF.Identifier(typeName)) : member;
            result.Add(adjusted.WithAdditionalAnnotations(UserCode));
        }
        if (result.Count == 0)
            throw new ToolError("No member declarations given.");
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

    /// <summary>
    /// Puts the new body on the target (if any) and "throw null" in every other body; user-added members (annotated)
    /// are left untouched. Field/property initializers are dropped, except when patching a constructor: C# compiles
    /// initializers into constructors, so the matching (instance or static) initializers are kept.
    /// </summary>
    private sealed class StubRewriter(SyntaxNode? target, BlockSyntax? newBody) : CSharpSyntaxRewriter
    {
        private static readonly BlockSyntax Stub = SF.Block(SF.ParseStatement("throw null;"));

        private readonly bool _keepInstanceInitializers = target is ConstructorDeclarationSyntax c && !c.Modifiers.Any(SyntaxKind.StaticKeyword);
        private readonly bool _keepStaticInitializers = target is ConstructorDeclarationSyntax s && s.Modifiers.Any(SyntaxKind.StaticKeyword);

        private bool KeepInitializer(SyntaxTokenList modifiers) =>
            modifiers.Any(SyntaxKind.ConstKeyword) || (modifiers.Any(SyntaxKind.StaticKeyword) ? _keepStaticInitializers : _keepInstanceInitializers);

        private BlockSyntax BodyFor(SyntaxNode original) => original == target ? newBody! : Stub;

        public override SyntaxNode? Visit(SyntaxNode? node) => node != null && node.HasAnnotation(UserCode) ? node : base.Visit(node);

        public override SyntaxNode? VisitMethodDeclaration(MethodDeclarationSyntax node) =>
            node.Body == null && node.ExpressionBody == null ? node
                : node.WithBody(BodyFor(node)).WithExpressionBody(null).WithSemicolonToken(default);

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
