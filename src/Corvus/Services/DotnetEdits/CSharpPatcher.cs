using System.Text.RegularExpressions;
using dnlib.DotNet;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Corvus.Core;
using static Corvus.Core.MetadataUtil;

namespace Corvus.Services;

/// <summary>Replaces method bodies and adds members or types in C#, compiled as helpers or in a stubbed "shadow" of the
/// decompiled type and merged by <see cref="ModuleMerger"/>; each operation takes the target module.</summary>
public sealed partial class CSharpPatcher(AssemblyWorkspace workspace, DecompilerService decompiler)
{
    private static readonly SyntaxAnnotation UserCode = new("user-code");
    private static readonly string[] StateMachineAttributes =
        ["AsyncStateMachineAttribute", "IteratorStateMachineAttribute", "AsyncIteratorStateMachineAttribute", "DebuggerStepThroughAttribute"];

    /// <summary>A merge result: added names, the patched method's IL (empty for additions), and access changes.</summary>
    public sealed record Outcome(IReadOnlyList<string> Added, string Listing, IReadOnlyList<string> Relaxed);

    /// <summary>Namespaces available to user code without a using directive (only those present in the references).</summary>
    private static readonly string[] DefaultUsings =
        ["System", "System.Collections", "System.Collections.Generic", "System.Linq", "System.Text", "System.Threading", "System.Threading.Tasks"];

    public Outcome PatchMethod(ResolvedSymbol symbol, string code, ModuleDef target, CancellationToken ct)
    {
        if (symbol.Member is not MethodDef method)
            throw new ToolError(ErrorCode.InvalidArgument, $"{symbol.Label} is a {symbol.Kind}, not a method.");
        if (method.IsAbstract || method.IsPinvokeImpl || method.IsRuntime || method.IsInternalCall)
            throw new ToolError(ErrorCode.Unsupported, $"{symbol.Label} has no IL body to replace (abstract/extern/runtime).");

        var asm = symbol.Assembly;
        var body = ParseBody(code).WithAdditionalAnnotations(UserCode);
        var tree = ShadowTree(asm, method.DeclaringType,
            (root, typeNode) => (CompilationUnitSyntax)new StubRewriter(FindMemberNode(typeNode, method), body).Visit(root)!, ct);

        // A helper compiled against the original assembly preserves type identity; the shadow is the fallback.
        ToolError? helperError = null;
        if (HelperApplicable(method, body))
        {
            try
            {
                var model = Bind(asm, tree, ct);
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
            throw helperError; // helper errors describe the user's code
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

    public Outcome AddMembers(ResolvedSymbol typeSymbol, string code, ModuleDef target, CancellationToken ct)
    {
        if (typeSymbol.Member is not TypeDef type)
            throw new ToolError(ErrorCode.InvalidArgument, $"{typeSymbol.Label} is a {typeSymbol.Kind}, not a type.");
        if (type.IsInterface || type.IsEnum || type.IsDelegate)
            throw new ToolError(ErrorCode.Unsupported, $"Members can only be added to classes and structs ({type.FullName} is {Format.Kind(type)}).");

        var asm = typeSymbol.Assembly;
        var members = ParseMembers(code, Format.StripArity(type.Name));
        var names = DeclaredNames(members);
        // Declare members with stub bodies, then compile real bodies as helpers; generic contexts compile in the shadow.
        bool helpers = !HasGenericContext(type);
        var declarations = members.Select(m => helpers ? StubHelperBodies(m) : m).ToList();

        var phase1 = ShadowTree(asm, type, (root, typeNode) =>
            (CompilationUnitSyntax)new StubRewriter(null, null).Visit(root.ReplaceNode(typeNode, typeNode.AddMembers(declarations.ToArray())))!, ct);
        using var compiled = Compile(asm, phase1, null, ct);
        var merger = new ModuleMerger(target, compiled, asm.AssemblyName);
        var compiledType = compiled.Find(type.FullName, isReflectionName: false) ?? compiled.Find(CompiledFullName(type), isReflectionName: false)
                           ?? throw new ToolError($"Internal: compiled shadow of {type.FullName} not found.");
        var targetType = CounterpartType(target, type);
        var comparer = new SigComparer(SigComparerOptions.DontCompareTypeScope);

        // Same-named members that already exist are original overloads (a true duplicate fails with CS0111/CS0102).
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

        // Compile the real bodies as helpers against the image that now contains the new members.
        if (helpers)
        {
            var phase2 = ShadowTree(asm, type, (root, typeNode) =>
                (CompilationUnitSyntax)new StubRewriter(null, null).Visit(root.ReplaceNode(typeNode, typeNode.AddMembers(members.Select(BlockBodies).ToArray())))!, ct);
            var model = Bind(asm, phase2, ct);
            var jobs = new List<HelperJob>();
            foreach (var body in phase2.GetRoot(ct).GetAnnotatedNodes(UserCode).SelectMany(n => n.DescendantNodesAndSelf()).OfType<BlockSyntax>()
                         .Where(b => b.Parent is BaseMethodDeclarationSyntax or AccessorDeclarationSyntax && b.Parent is not ConstructorDeclarationSyntax && b.Parent.Parent?.Parent is not null))
            {
                if (OwnerTypeOf(body) is not { } owner || !SameName(owner.Identifier, Format.StripArity(type.Name)) || IsInNestedUserType(body)) continue;
                if (model.GetDeclaredSymbol(body.Parent!, ct) is not IMethodSymbol symbol) continue;
                var targetMethod = addedMethods.FirstOrDefault(a => a.Compiled.Name == symbol.MetadataName && SameParameters(a.Compiled, symbol)).Target;
                if (targetMethod != null) jobs.Add(new HelperJob(body, targetMethod));
            }
            if (jobs.Count > 0)
            {
                var outcome = CompileViaHelper(asm, model, jobs, target, () => WriteImage(target), ct);
                added.AddRange(outcome.Added);
                relaxed.AddRange(outcome.Relaxed);
            }
        }
        return new Outcome(added, "", relaxed);
    }

    public Outcome AddTypes(LoadedAssembly asm, string code, ModuleDef target, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(code))
            throw new ToolError(ErrorCode.InvalidArgument, "The C# source is empty.");
        var tree = CSharpSyntaxTree.ParseText(code, new CSharpParseOptions(LanguageVersion.Preview), cancellationToken: ct);
        var root = UsingsInsideNamespaces(tree.GetCompilationUnitRoot(ct)).WithAdditionalAnnotations(UserCode);
        tree = CSharpSyntaxTree.Create(root, new CSharpParseOptions(LanguageVersion.Preview));
        if (!root.DescendantNodes().OfType<BaseTypeDeclarationSyntax>().Any())
            throw new ToolError(ErrorCode.InvalidArgument, "The source declares no types; pass whole type declarations, optionally in a namespace.");

        using var compiled = Compile(asm, tree, null, ct);
        var merger = new ModuleMerger(target, compiled, asm.AssemblyName);
        foreach (var t in compiled.Types.Where(t => t.FullName != "<Module>" && !t.Name.String.StartsWith('<') && !IsEmbeddedByCompiler(t)).ToList())
        {
            if (target.Find(t.FullName, isReflectionName: false) != null)
                throw new ToolError(ErrorCode.Conflict, $"{t.FullName} already exists in {asm.Id}.");
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

    /// <summary>Declares compiler-generated '&lt;...&gt;' types, methods and fields as new definitions under fresh names
    /// (same-named ones are the original's); existing backing fields are reused, <paramref name="rename"/> maps names.</summary>
    private static void DeclareGenerated(ModuleMerger merger, ModuleDef compiled, Func<string, string>? rename = null)
    {
        var target = merger.Target;
        rename ??= n => n;
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
                merger.AddTypeTree(t, parent, ModuleMerger.UniqueName(rename(t.Name), parent.NestedTypes.Select(x => x.Name.String)), rename);
        }

        foreach (var t in compiled.GetTypes().ToList())
        {
            if (merger.IsNew(t) || t.Name.String.StartsWith('<') || merger.MapType(t) is not { } existing) continue;
            foreach (var m in t.Methods.Where(m => m.Name.String.StartsWith('<') && merger.MapMethodIfDeclared(m) == null))
                merger.AddMethod(m, existing, ModuleMerger.UniqueName(rename(m.Name), existing.Methods.Select(x => x.Name.String)));
            foreach (var f in t.Fields.Where(f => f.Name.String.StartsWith('<') && merger.MapFieldIfDeclared(f) == null))
            {
                bool existingBackingField = f.Name.String.EndsWith("k__BackingField", StringComparison.Ordinal) && existing.Fields.Any(x => x.Name == f.Name);
                if (!existingBackingField)
                    merger.AddField(f, existing, ModuleMerger.UniqueName(rename(f.Name), existing.Fields.Select(x => x.Name.String)));
            }
        }
    }

    private static void ThrowIfUnmapped(ModuleMerger merger)
    {
        if (merger.Unmapped.Count > 0)
            throw new ToolError(ErrorCode.Unsupported, "The compiled code references definitions missing from the target: " +
                                string.Join(", ", merger.Unmapped.Distinct().Take(10)) +
                                "; the decompiled surrounding type likely differs from the original; use patch_method_il.");
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
        var type = compiled.Find(original.DeclaringType.FullName, isReflectionName: false) ?? compiled.Find(CompiledFullName(original.DeclaringType), isReflectionName: false)
                   ?? throw new ToolError($"Internal: compiled shadow type {original.DeclaringType.FullName} not found. Compiled types: " +
                                          string.Join(", ", compiled.GetTypes().Take(15).Select(t => t.FullName)));
        var comparer = new SigComparer(SigComparerOptions.DontCompareTypeScope);
        bool Named(MethodDef m) => m.Name == original.Name || m.Name == SourceName(original.Name);
        return type.Methods.FirstOrDefault(m => Named(m) && comparer.Equals(m.MethodSig, original.MethodSig))
               ?? type.Methods.Single(m => Named(m) && ParamCount(m) == ParamCount(original));
    }
}
