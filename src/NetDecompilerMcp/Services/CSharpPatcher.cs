using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using NetDecompilerMcp.Core;
using static NetDecompilerMcp.Services.MetadataUtil;
using SF = Microsoft.CodeAnalysis.CSharp.SyntaxFactory;

namespace NetDecompilerMcp.Services;

/// <summary>
/// C# editing of compiled assemblies: replace a method body, add members to a type, or add new types.
///
/// How: decompile the affected top-level type, splice in the user's code and replace every other body with
/// "throw null" (so decompiler output that does not round-trip cannot break the build), compile it with Roslyn against
/// the assembly's real references with accessibility checks off (private/internal members are usable), then merge the
/// result into the target module with <see cref="ModuleMerger"/>: shadow types map back onto the originals, while new
/// members and compiler-generated helpers (lambda closures, async/iterator state machines, local functions,
/// &lt;PrivateImplementationDetails&gt;) are copied in.
///
/// Every operation takes the module to modify, so callers can run it on a scratch copy first (dry run / validation).
/// </summary>
public sealed partial class CSharpPatcher(AssemblyWorkspace workspace, DecompilerService decompiler)
{
    private static readonly SyntaxAnnotation UserCode = new("netdecomp-user-code");
    private static readonly string[] StateMachineAttributes =
        ["AsyncStateMachineAttribute", "IteratorStateMachineAttribute", "AsyncIteratorStateMachineAttribute", "DebuggerStepThroughAttribute"];

    /// <summary>What a merge produced. Listing is the new IL of the patched method (empty for additions);
    /// Relaxed lists accessibility changes made so the new code passes the runtime's access checks.</summary>
    public sealed record Outcome(IReadOnlyList<string> Added, string Listing, IReadOnlyList<string> Relaxed);

    /// <summary>Namespaces available to user code without a using directive (only those present in the references).</summary>
    private static readonly string[] DefaultUsings =
        ["System", "System.Collections", "System.Collections.Generic", "System.Linq", "System.Text", "System.Threading", "System.Threading.Tasks"];

    // ------------------------------------------------------------------ replace a method body

    public Outcome PatchMethod(ResolvedSymbol symbol, string code, ModuleDef target, CancellationToken ct)
    {
        if (symbol.Member is not MethodDef method)
            throw new ToolError($"{symbol.Label} is a {symbol.Kind}, not a method.");
        if (method.IsAbstract || method.IsPinvokeImpl || method.IsRuntime || method.IsInternalCall)
            throw new ToolError($"{symbol.Label} has no IL body to replace (abstract/extern/runtime).");

        var asm = symbol.Assembly;
        var body = ParseBody(code).WithAdditionalAnnotations(UserCode);
        var tree = ShadowTree(asm, method.DeclaringType,
            (root, typeNode) => (CompilationUnitSyntax)new StubRewriter(FindMemberNode(typeNode, method), body).Visit(root)!, ct);

        // Preferred: compile the body as a helper method against the original assembly (keeps type identity).
        ToolError? helperError = null;
        if (HelperApplicable(method, body))
        {
            try
            {
                var model = Bind(asm, tree, null);
                var boundBody = tree.GetRoot(ct).GetAnnotatedNodes(UserCode).OfType<BlockSyntax>().First();
                return CompileViaHelper(asm, model, [new HelperJob(boundBody, Counterpart(target, method))], target, null, ct);
            }
            catch (ToolError ex)
            {
                helperError = ex;
            }
        }
        try
        {
            return PatchViaShadow(asm, tree, method, target, ct);
        }
        catch (ToolError) when (helperError != null)
        {
            throw helperError; // the helper's errors are about the user's code; the shadow is only a fallback
        }
    }

    /// <summary>Fallback: compile the decompiled type itself with the new body (constructors, generic types, base calls).</summary>
    private Outcome PatchViaShadow(LoadedAssembly asm, SyntaxTree tree, MethodDef method, ModuleDef target, CancellationToken ct)
    {
        using var compiled = Compile(asm, tree, null, ct);
        var compiledMethod = FindCompiledMethod(compiled, method);
        var merger = new ModuleMerger(target, compiled, asm.AssemblyName);
        DeclareGenerated(merger, compiled);
        merger.Fill();

        var targetMethod = Counterpart(target, method);
        var newBody = merger.CopyBody(compiledMethod, targetMethod);
        merger.CopyNewBodies();
        ThrowIfUnmapped(merger);
        ReplaceStateMachineAttributes(merger, compiledMethod, targetMethod, target);

        targetMethod.Body = newBody;
        targetMethod.ImplAttributes &= ~(dnlib.DotNet.MethodImplAttributes.InternalCall | dnlib.DotNet.MethodImplAttributes.Runtime);
        var relaxed = AccessFixer.Fix(target, [targetMethod, .. merger.NewMethodTargets]);
        FinalizeBodies([targetMethod, .. merger.NewMethodTargets]);
        newBody.UpdateInstructionOffsets();
        return new Outcome(merger.Added, string.Join("\n", newBody.Instructions.Select(i => "  " + i)), relaxed);
    }

    // ------------------------------------------------------------------ add members to an existing type

    public Outcome AddMembers(ResolvedSymbol typeSymbol, string code, ModuleDef target, CancellationToken ct)
    {
        if (typeSymbol.Member is not TypeDef type)
            throw new ToolError($"{typeSymbol.Label} is a {typeSymbol.Kind}, not a type.");
        if (type.IsInterface || type.IsEnum || type.IsDelegate)
            throw new ToolError($"Members can only be added to classes and structs ({type.FullName} is {Format.Kind(type)}).");

        var asm = typeSymbol.Assembly;
        var members = ParseMembers(code, Format.StripArity(type.Name));
        var names = DeclaredNames(members);
        // Bodies that can be compiled as helpers are stubbed for phase 1 (declarations); the rest compile in the shadow.
        bool helpers = !HasGenericContext(type);
        var declarations = members.Select(m => helpers ? StubHelperBodies(m) : m).ToList();

        // Phase 1: declare the new members (with stub bodies where phase 2 provides the real ones).
        var phase1 = ShadowTree(asm, type, (root, typeNode) =>
            (CompilationUnitSyntax)new StubRewriter(null, null).Visit(root.ReplaceNode(typeNode, typeNode.AddMembers(declarations.ToArray())))!, ct);
        using var compiled = Compile(asm, phase1, null, ct);
        var merger = new ModuleMerger(target, compiled, asm.AssemblyName);
        var compiledType = compiled.Find(type.FullName, isReflectionName: false)
                           ?? throw new ToolError($"Internal: compiled shadow of {type.FullName} not found.");
        var targetType = CounterpartType(target, type);
        var comparer = new SigComparer(SigComparerOptions.DontCompareTypeScope);

        // Members with a user-declared name that already exist are the original overloads/members of the shadow type
        // (a real duplicate declaration is a compile error, CS0111/CS0102): only the new ones are added.
        foreach (var nested in compiledType.NestedTypes.Where(n => names.Contains(n.Name) && !targetType.NestedTypes.Any(x => x.Name == n.Name)).ToList())
            merger.AddTypeTree(nested, targetType, nested.Name);
        var addedMethods = new List<(MethodDef Compiled, MethodDef Target)>();
        foreach (var m in compiledType.Methods.Where(m => names.Contains(m.Name) && !targetType.Methods.Any(x => x.Name == m.Name && comparer.Equals(x.MethodSig, m.MethodSig))).ToList())
            addedMethods.Add((m, merger.AddMethod(m, targetType, m.Name)));
        foreach (var f in compiledType.Fields.Where(f => (names.Contains(f.Name) || IsBackingFieldOf(f, names)) && !targetType.Fields.Any(x => x.Name == f.Name)).ToList())
            merger.AddField(f, targetType, f.Name);
        foreach (var p in compiledType.Properties.Where(p => names.Contains(p.Name) && !targetType.Properties.Any(x => x.Name == p.Name)).ToList())
            merger.AddProperty(p, targetType);
        foreach (var e in compiledType.Events.Where(e => names.Contains(e.Name) && !targetType.Events.Any(x => x.Name == e.Name)).ToList())
            merger.AddEvent(e, targetType);
        DeclareGenerated(merger, compiled);
        merger.Fill();
        merger.CopyNewBodies();
        ThrowIfUnmapped(merger);
        var relaxed = AccessFixer.Fix(target, merger.NewMethodTargets).ToList();
        FinalizeBodies(merger.NewMethodTargets);
        var added = merger.Added.ToList();

        // Phase 2: compile the real bodies as helper methods against the image that now contains the new members.
        if (helpers)
        {
            var phase2 = ShadowTree(asm, type, (root, typeNode) =>
                (CompilationUnitSyntax)new StubRewriter(null, null).Visit(root.ReplaceNode(typeNode, typeNode.AddMembers(members.Select(BlockBodies).ToArray())))!, ct);
            var model = Bind(asm, phase2, null);
            var jobs = new List<HelperJob>();
            foreach (var body in phase2.GetRoot(ct).GetAnnotatedNodes(UserCode).SelectMany(n => n.DescendantNodesAndSelf()).OfType<BlockSyntax>()
                         .Where(b => b.Parent is BaseMethodDeclarationSyntax or AccessorDeclarationSyntax && b.Parent is not ConstructorDeclarationSyntax && b.Parent.Parent?.Parent is not null))
            {
                if (OwnerTypeOf(body) is not { } owner || owner.Identifier.Text != Format.StripArity(type.Name) || IsInNestedUserType(body)) continue;
                if (model.GetDeclaredSymbol(body.Parent!, ct) is not IMethodSymbol symbol) continue;
                var targetMethod = addedMethods.FirstOrDefault(a => a.Compiled.Name == symbol.MetadataName && SameParameters(a.Compiled, symbol)).Target;
                if (targetMethod != null) jobs.Add(new HelperJob(body, targetMethod));
            }
            if (jobs.Count > 0)
            {
                var image = WriteImage(target);
                var outcome = CompileViaHelper(asm, model, jobs, target, image, ct);
                added.AddRange(outcome.Added);
                relaxed.AddRange(outcome.Relaxed);
            }
        }
        return new Outcome(added, "", relaxed);
    }

    // ------------------------------------------------------------------ add new types

    public Outcome AddTypes(LoadedAssembly asm, string code, ModuleDef target, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(code))
            throw new ToolError("The C# source is empty.");
        var tree = CSharpSyntaxTree.ParseText(code, new CSharpParseOptions(LanguageVersion.Preview), cancellationToken: ct);
        var root = tree.GetCompilationUnitRoot(ct).WithAdditionalAnnotations(UserCode);
        tree = CSharpSyntaxTree.Create(root, new CSharpParseOptions(LanguageVersion.Preview));
        if (!root.DescendantNodes().OfType<BaseTypeDeclarationSyntax>().Any())
            throw new ToolError("The source declares no types. Pass whole type declarations (optionally inside a namespace).");

        using var compiled = Compile(asm, tree, null, ct);
        var merger = new ModuleMerger(target, compiled, asm.AssemblyName);
        foreach (var t in compiled.Types.Where(t => t.FullName != "<Module>" && !t.Name.String.StartsWith('<') && !IsEmbeddedByCompiler(t)).ToList())
        {
            if (target.Find(t.FullName, isReflectionName: false) != null)
                throw new ToolError($"{t.FullName} already exists in {asm.Id}.");
            merger.AddTypeTree(t, null, t.Name);
        }
        DeclareGenerated(merger, compiled);
        merger.Fill();
        merger.CopyNewBodies();
        ThrowIfUnmapped(merger);
        var relaxed = AccessFixer.Fix(target, merger.NewMethodTargets);
        FinalizeBodies(merger.NewMethodTargets);
        return new Outcome(merger.Added, "", relaxed);
    }

    // ------------------------------------------------------------------ shared merge helpers

    /// <summary>
    /// Declares the compiler-generated helpers of the compiled code as new definitions: nested '&lt;...&gt;' types (closures,
    /// state machines) and '&lt;...&gt;' methods/fields on existing types (lambda bodies, local functions, caches), plus
    /// &lt;PrivateImplementationDetails&gt;. They are always copied under fresh names: an existing helper with the same
    /// name belongs to the original code and has different contents. Auto-property backing fields that exist are reused.
    /// </summary>
    private static void DeclareGenerated(ModuleMerger merger, ModuleDef compiled)
    {
        var target = merger.Target;
        foreach (var t in compiled.GetTypes().ToList())
        {
            if (merger.IsNew(t)) continue;
            if (t.DeclaringType == null)
            {
                if (t.Name.StartsWith("<PrivateImplementationDetails>", StringComparison.Ordinal))
                    merger.AddTypeTree(t, null, ModuleMerger.UniqueName(t.Name, target.Types.Select(x => x.Name.String)));
                continue;
            }
            if (!t.Name.String.StartsWith('<') || merger.IsNew(t.DeclaringType)) continue;
            if (merger.MapType(t.DeclaringType) is { } parent)
                merger.AddTypeTree(t, parent, ModuleMerger.UniqueName(t.Name, parent.NestedTypes.Select(x => x.Name.String)));
        }

        foreach (var t in compiled.GetTypes().ToList())
        {
            if (merger.IsNew(t) || t.Name.String.StartsWith('<') || merger.MapType(t) is not { } existing) continue;
            foreach (var m in t.Methods.Where(m => m.Name.String.StartsWith('<') && merger.MapMethodIfDeclared(m) == null))
                merger.AddMethod(m, existing, ModuleMerger.UniqueName(m.Name, existing.Methods.Select(x => x.Name.String)));
            foreach (var f in t.Fields.Where(f => f.Name.String.StartsWith('<') && merger.MapFieldIfDeclared(f) == null))
            {
                bool existingBackingField = f.Name.String.EndsWith("k__BackingField", StringComparison.Ordinal) && existing.Fields.Any(x => x.Name == f.Name);
                if (!existingBackingField)
                    merger.AddField(f, existing, ModuleMerger.UniqueName(f.Name, existing.Fields.Select(x => x.Name.String)));
            }
        }
    }

    private static void ThrowIfUnmapped(ModuleMerger merger)
    {
        if (merger.Unmapped.Count > 0)
            throw new ToolError("The compiled code references definitions that could not be mapped into the target assembly: " +
                                string.Join(", ", merger.Unmapped.Distinct().Take(10)) +
                                ". This usually means the decompiled declaration of the surrounding type does not match the original; use patch_method_il.");
    }


    /// <summary>Normalizes branches and validates the evaluation stack of every body produced.</summary>
    private static void FinalizeBodies(IEnumerable<MethodDef> methods)
    {
        foreach (var m in methods)
        {
            var body = m.Body;
            if (body == null) continue;
            body.SimplifyBranches();
            body.OptimizeBranches();
            body.UpdateInstructionOffsets();
            if (!dnlib.DotNet.Writer.MaxStackCalculator.GetMaxStack(body.Instructions, body.ExceptionHandlers, out _))
                throw new ToolError($"Internal: the compiled body of {Format.MemberLabel(m)} failed stack validation; nothing was changed.");
        }
    }

    private static bool IsStateMachineAttribute(CustomAttribute ca) => StateMachineAttributes.Contains(ca.AttributeType?.Name.String);

    private static bool IsEmbeddedByCompiler(TypeDef t) =>
        t.Namespace == "Microsoft.CodeAnalysis" ||
        (t.Namespace == "System.Runtime.CompilerServices" && t.CustomAttributes.Any(ca => ca.AttributeType?.FullName == "Microsoft.CodeAnalysis.EmbeddedAttribute"));

    private static bool IsBackingFieldOf(FieldDef f, HashSet<string> names) =>
        f.Name.String.StartsWith('<') && f.Name.String.EndsWith(">k__BackingField", StringComparison.Ordinal)
        && names.Contains(f.Name.String[1..f.Name.String.IndexOf('>')]);

    private static TypeDef CounterpartType(ModuleDef target, TypeDef type) =>
        ReferenceEquals(type.Module, target) ? type
            : target.Find(type.FullName, isReflectionName: false) ?? throw new ToolError($"Internal: {type.FullName} not found in the target module.");

    private static MethodDef Counterpart(ModuleDef target, MethodDef method)
    {
        if (ReferenceEquals(method.Module, target)) return method;
        var comparer = new SigComparer(SigComparerOptions.DontCompareTypeScope);
        return CounterpartType(target, method.DeclaringType).Methods.FirstOrDefault(m => m.Name == method.Name && comparer.Equals(m.MethodSig, method.MethodSig))
               ?? throw new ToolError($"Internal: {Format.MemberLabel(method)} not found in the target module.");
    }

    private static MethodDef FindCompiledMethod(ModuleDef compiled, MethodDef original)
    {
        var type = compiled.Find(original.DeclaringType.FullName, isReflectionName: false)
                   ?? throw new ToolError($"Internal: compiled shadow type {original.DeclaringType.FullName} not found. Compiled types: " +
                                          string.Join(", ", compiled.GetTypes().Take(15).Select(t => t.FullName)));
        var comparer = new SigComparer(SigComparerOptions.DontCompareTypeScope);
        return type.Methods.FirstOrDefault(m => m.Name == original.Name && comparer.Equals(m.MethodSig, original.MethodSig))
               ?? type.Methods.Single(m => m.Name == original.Name && ParamCount(m) == ParamCount(original));
    }

    // ------------------------------------------------------------------ source handling

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

    // ------------------------------------------------------------------ compile

    private static CSharpCompilationOptions CreateOptions()
    {
        var options = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary,
            optimizationLevel: OptimizationLevel.Release,
            allowUnsafe: true,
            nullableContextOptions: NullableContextOptions.Disable,
            metadataImportOptions: MetadataImportOptions.All,
            checkOverflow: false);
        // Roslyn's internal "ignore accessibility" binder flag (the same switch scripting/IDE tooling uses), so patched code
        // can call private and internal members of the original assembly exactly like the original method could.
        var flags = typeof(CSharpCompilationOptions).GetProperty("TopLevelBinderFlags", BindingFlags.Instance | BindingFlags.NonPublic);
        flags?.SetValue(options, Enum.ToObject(flags.PropertyType, 1u << 22));
        return options;
    }

    /// <summary>The assembly's own (current) image plus the transitive closure of its references.</summary>
    private List<MetadataReference> BuildReferences(LoadedAssembly asm, byte[]? targetImage, out List<string> missing)
    {
        missing = new List<string>();
        var references = new List<MetadataReference>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var queue = new Queue<(ModuleDef Module, bool Owned)>();

        void Enqueue(string name, byte[] image, ModuleDef module, bool owned)
        {
            if (!seen.Add(name)) { if (owned) module.Dispose(); return; }
            references.Add(MetadataReference.CreateFromImage(image));
            queue.Enqueue((module, owned));
        }

        Enqueue(asm.AssemblyName, targetImage ?? asm.GetImageBytes(), asm.Module, owned: false);
        while (queue.Count > 0)
        {
            var (module, owned) = queue.Dequeue();
            foreach (var r in module.GetAssemblyRefs())
            {
                string name = r.Name;
                if (seen.Contains(name)) continue;
                var loaded = workspace.FindByAssemblyName(name);
                if (loaded != null)
                {
                    Enqueue(name, loaded.GetImageBytes(), loaded.Module, owned: false);
                    continue;
                }
                var path = workspace.FindAssemblyFile(name);
                if (path == null) { seen.Add(name); missing.Add(name); continue; }
                try
                {
                    var bytes = File.ReadAllBytes(path);
                    Enqueue(name, bytes, ModuleDefMD.Load(bytes), owned: true);
                }
                catch
                {
                    seen.Add(name);
                    missing.Add(name);
                }
            }
            if (owned) module.Dispose();
        }
        return references;
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
                BlockSyntax => $"your code line {line - start}", // the body was wrapped in a "{" line
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
