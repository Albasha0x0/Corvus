using System.Text;
using dnlib.DotNet;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Corvus.Core;
using SF = Microsoft.CodeAnalysis.CSharp.SyntaxFactory;

namespace Corvus.Services;

/// <summary>
/// Helper-method compilation of new method bodies.
///
/// A shadow type has a different identity from the original, so code passing `this` as the original type does not compile.
/// Each body is bound inside the shadow, rewritten so `this` becomes an explicit `@this` parameter and type members become
/// fully qualified, then compiled as a static `R M(T @this, ...params)` against the original assembly. Argument 0 maps to
/// `this` of the target method, so the IL transfers unchanged.
/// </summary>
public sealed partial class CSharpPatcher
{
    private const string HelperClass = "__PatchHelpers__";

    /// <summary>One body to compile: its block inside the bound shadow tree and the target method that receives it.</summary>
    private sealed record HelperJob(BlockSyntax Body, MethodDef Target);

    /// <summary>Whether a body can be compiled as a helper method (otherwise the shadow compilation is used).</summary>
    private static bool HelperApplicable(MethodDef method, SyntaxNode body) =>
        !method.IsConstructor
        && !HasGenericContext(method.DeclaringType)
        && !body.DescendantNodesAndSelf().OfType<BaseExpressionSyntax>().Any();

    private static bool HasGenericContext(TypeDef type)
    {
        for (var t = type; t != null; t = t.DeclaringType)
            if (t.HasGenericParameters) return true;
        return false;
    }

    /// <summary>
    /// Compiles every job's body as a method of one helper class and copies the results into the target methods.
    /// <paramref name="model"/> must belong to the tree that contains the job bodies (a shadow compilation, bound only).
    /// </summary>
    private Outcome CompileViaHelper(LoadedAssembly asm, SemanticModel model, IReadOnlyList<HelperJob> jobs, ModuleDef target, Func<byte[]>? targetImage, CancellationToken ct)
    {
        var root = (CompilationUnitSyntax)model.SyntaxTree.GetRoot(ct);
        var methods = new List<(IMethodSymbol Symbol, string Name)>();
        var source = new StringBuilder();
        // Inside the namespace, as in the shadow (see UsingsInsideNamespaces).
        var usings = string.Concat(root.DescendantNodes(n => n is CompilationUnitSyntax or BaseNamespaceDeclarationSyntax).OfType<UsingDirectiveSyntax>()
            .Select(u => Rooted(u) + "\n"));
        INamespaceSymbol? ns = null;
        var body = new StringBuilder();

        for (int i = 0; i < jobs.Count; i++)
        {
            var declaration = jobs[i].Body.Parent ?? throw new ToolError("Internal: helper body has no declaration.");
            var symbol = model.GetDeclaredSymbol(declaration, ct) as IMethodSymbol
                         ?? throw new ToolError($"Internal: no symbol for {declaration.Kind()}.");
            if (symbol.ReturnsByRef || symbol.ReturnsByRefReadonly)
                throw new ToolError(ErrorCode.Unsupported, "ref returns are not supported by helper compilation.");
            ns ??= symbol.ContainingType.ContainingNamespace;
            var name = $"{Sanitize(symbol.Name)}__patch{i}";
            methods.Add((symbol, name));
            var rewritten = (BlockSyntax)new ThisRewriter(model, symbol.ContainingType).Visit(jobs[i].Body)!;
            body.AppendLine(HelperMethod(symbol, name, rewritten));
        }

        bool hasNamespace = ns is { IsGlobalNamespace: false };
        if (hasNamespace) source.AppendLine($"namespace {ns!.ToDisplayString()} {{");
        source.Append(usings);
        source.AppendLine($"internal static class {HelperClass} {{");
        source.Append(body);
        source.AppendLine("}");
        if (hasNamespace) source.AppendLine("}");

        // Mark the bodies as user code so compile errors point at the user's lines.
        var parseOptions = new CSharpParseOptions(LanguageVersion.Preview);
        var helperRoot = CSharpSyntaxTree.ParseText(source.ToString(), parseOptions, cancellationToken: ct).GetCompilationUnitRoot(ct);
        var helperBodies = helperRoot.DescendantNodes().OfType<MethodDeclarationSyntax>().Where(m => m.Body != null).Select(m => m.Body!).ToList();
        helperRoot = helperRoot.ReplaceNodes(helperBodies, (original, _) => original.WithAdditionalAnnotations(UserCode));
        var helperTree = CSharpSyntaxTree.Create(helperRoot, parseOptions);

        using var compiled = CompileHelper(asm, helperTree, targetImage, methods, ct);
        var helperType = compiled.Find((hasNamespace ? ns!.ToDisplayString() + "." : "") + HelperClass, isReflectionName: false)
                         ?? throw new ToolError("Internal: compiled helper class not found.");
        var merger = new ModuleMerger(target, compiled, asm.AssemblyName);
        var targetType = jobs[0].Target.DeclaringType;
        merger.Alias(helperType, targetType);
        // State machines and lambdas carry their method's name: <Many__patch0>d__0 becomes <Many>d__0.
        DeclareGenerated(merger, compiled, generated => methods.Aggregate(generated, (n, m) => n.Replace($"<{m.Name}>", $"<{m.Symbol.MetadataName}>", StringComparison.Ordinal)));
        merger.Fill();

        var listing = new StringBuilder();
        var changed = new List<MethodDef>();
        for (int i = 0; i < jobs.Count; i++)
        {
            var compiledMethod = helperType.Methods.Single(m => m.Name == methods[i].Name);
            var targetMethod = jobs[i].Target;
            var newBody = merger.CopyBody(compiledMethod, targetMethod);
            ReplaceStateMachineAttributes(merger, compiledMethod, targetMethod, target);
            targetMethod.Body = newBody;
            targetMethod.ImplAttributes &= ~(dnlib.DotNet.MethodImplAttributes.InternalCall | dnlib.DotNet.MethodImplAttributes.Runtime);
            changed.Add(targetMethod);
        }
        merger.CopyNewBodies();
        ThrowIfUnmapped(merger);
        var relaxed = AccessFixer.Fix(target, [.. changed, .. merger.NewMethodTargets]);
        FinalizeBodies([.. changed, .. merger.NewMethodTargets]);
        if (jobs.Count == 1)
        {
            jobs[0].Target.Body.UpdateInstructionOffsets();
            listing.Append(string.Join("\n", jobs[0].Target.Body.Instructions.Select(x => "  " + x)));
        }
        return new Outcome(merger.Added, listing.ToString(), relaxed);
    }

    /// <summary>Compiles the helper class; diagnostics name the user's members, not the helper class and its methods.</summary>
    private ModuleDefMD CompileHelper(LoadedAssembly asm, SyntaxTree helperTree, Func<byte[]>? targetImage, List<(IMethodSymbol Symbol, string Name)> methods, CancellationToken ct)
    {
        try
        {
            return Compile(asm, helperTree, targetImage, ct);
        }
        catch (ToolError ex) when (ex.Code == ErrorCode.InvalidArgument)
        {
            var message = ex.Message;
            foreach (var (symbol, name) in methods)
                message = message.Replace($"{HelperClass}.{name}", $"{symbol.ContainingType.Name}.{symbol.Name}", StringComparison.Ordinal)
                                 .Replace(name, symbol.Name, StringComparison.Ordinal);
            message = message.Replace(HelperClass, methods[0].Symbol.ContainingType.Name, StringComparison.Ordinal);
            throw new ToolError(ex.Code, message, ex.Remediation) { Details = ex.Details, Partial = ex.Partial };
        }
    }

    private static string HelperMethod(IMethodSymbol symbol, string name, BlockSyntax body)
    {
        var fq = SymbolDisplayFormat.FullyQualifiedFormat;
        // Private avoids CS0051 when the signature uses internal types of the target; helpers are copied, never called.
        var sb = new StringBuilder("    private static unsafe ");
        if (symbol.IsAsync) sb.Append("async ");
        sb.Append(symbol.ReturnsVoid ? "void" : symbol.ReturnType.ToDisplayString(fq)).Append(' ').Append(name);
        if (symbol.TypeParameters.Length > 0)
            sb.Append('<').Append(string.Join(", ", symbol.TypeParameters.Select(t => t.Name))).Append('>');

        var parameters = new List<string>();
        if (!symbol.IsStatic)
            parameters.Add((symbol.ContainingType.IsValueType ? "ref " : "") + symbol.ContainingType.ToDisplayString(fq) + " @this");
        foreach (var p in symbol.Parameters)
        {
            var refKind = p.RefKind switch
            {
                RefKind.Ref => "ref ",
                RefKind.Out => "out ",
                RefKind.In => "in ",
                RefKind.RefReadOnlyParameter => "ref readonly ",
                _ => "",
            };
            parameters.Add($"{refKind}{p.Type.ToDisplayString(fq)} @{p.Name}");
        }
        sb.Append('(').Append(string.Join(", ", parameters)).Append(')');

        foreach (var tp in symbol.TypeParameters)
        {
            var constraints = new List<string>();
            if (tp.HasReferenceTypeConstraint) constraints.Add("class");
            if (tp.HasUnmanagedTypeConstraint) constraints.Add("unmanaged");
            else if (tp.HasValueTypeConstraint) constraints.Add("struct");
            if (tp.HasNotNullConstraint) constraints.Add("notnull");
            constraints.AddRange(tp.ConstraintTypes.Select(c => c.ToDisplayString(fq)));
            if (tp.HasConstructorConstraint && !tp.HasValueTypeConstraint) constraints.Add("new()");
            if (constraints.Count > 0) sb.Append($" where {tp.Name} : {string.Join(", ", constraints)}");
        }
        sb.AppendLine();
        sb.Append(body.ToFullString());
        return sb.ToString();
    }

    private static string Sanitize(string name)
    {
        var chars = name.Select(c => char.IsLetterOrDigit(c) || c == '_' ? c : '_').ToArray();
        var s = new string(chars);
        return s.Length == 0 || char.IsDigit(s[0]) ? "_" + s : s;
    }

    private static void ReplaceStateMachineAttributes(ModuleMerger merger, MethodDef compiled, MethodDef target, ModuleDef module)
    {
        foreach (var old in target.CustomAttributes.Where(IsStateMachineAttribute).ToList())
            target.CustomAttributes.Remove(old);
        merger.CopyAttributes(compiled, target,
            new Importer(module, ImporterOptions.TryToUseDefs, new GenericParamContext(target.DeclaringType, target)), IsStateMachineAttribute);
    }

    /// <summary>
    /// Rewrites a body bound in the shadow so it compiles outside the type: `this` and implicit instance member access
    /// become `@this`, and static members / nested types of the type (or its base and outer types) become fully qualified.
    /// </summary>
    private sealed class ThisRewriter(SemanticModel model, INamedTypeSymbol type) : CSharpSyntaxRewriter
    {
        private static readonly SymbolDisplayFormat Fq = SymbolDisplayFormat.FullyQualifiedFormat;

        public override SyntaxNode? VisitThisExpression(ThisExpressionSyntax node) =>
            SF.ParseExpression("@this").WithTriviaFrom(node);

        public override SyntaxNode? VisitIdentifierName(IdentifierNameSyntax node) => Rewrite(node, base.VisitIdentifierName(node)!);

        public override SyntaxNode? VisitGenericName(GenericNameSyntax node) => Rewrite(node, base.VisitGenericName(node)!);

        private SyntaxNode Rewrite(SimpleNameSyntax original, SyntaxNode visited)
        {
            if (IsQualifiedOrNonMemberName(original) || original.IsVar)
                return visited;
            var info = model.GetSymbolInfo(original);
            var symbol = info.Symbol ?? info.CandidateSymbols.FirstOrDefault();
            switch (symbol)
            {
                case IFieldSymbol or IPropertySymbol or IMethodSymbol or IEventSymbol when symbol.ContainingType != null && InScope(symbol.ContainingType):
                    if (symbol is IMethodSymbol { MethodKind: MethodKind.LocalFunction }) return visited;
                    var text = symbol.IsStatic
                        ? $"{symbol.ContainingType.OriginalDefinition.ToDisplayString(Fq)}.{visited}"
                        : $"@this.{visited}";
                    return SF.ParseExpression(text).WithTriviaFrom(original);
                case INamedTypeSymbol nested when nested.ContainingType != null && InScope(nested.ContainingType):
                    return SF.ParseName($"{nested.ContainingType.OriginalDefinition.ToDisplayString(Fq)}.{visited}").WithTriviaFrom(original);
                default:
                    return visited;
            }
        }

        /// <summary>The type itself, its base types, and the types it is nested in (whose members it can use unqualified).</summary>
        private bool InScope(INamedTypeSymbol owner)
        {
            var target = owner.OriginalDefinition;
            for (var t = type; t != null; t = t.ContainingType)
                for (var b = t; b != null; b = b.BaseType)
                    if (SymbolEqualityComparer.Default.Equals(b.OriginalDefinition, target))
                        return true;
            return false;
        }

        private static bool IsQualifiedOrNonMemberName(SimpleNameSyntax node) => node.Parent switch
        {
            MemberAccessExpressionSyntax ma => ma.Name == node,
            MemberBindingExpressionSyntax => true,
            QualifiedNameSyntax q => q.Right == node,
            AliasQualifiedNameSyntax => true,
            NameColonSyntax or NameEqualsSyntax => true,
            AssignmentExpressionSyntax a when a.Left == node && a.Parent is InitializerExpressionSyntax
                { RawKind: (int)SyntaxKind.ObjectInitializerExpression or (int)SyntaxKind.WithInitializerExpression } => true,
            _ => false,
        };
    }
}
