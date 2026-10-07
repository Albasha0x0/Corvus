using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using NetDecompilerMcp.Core;
using static NetDecompilerMcp.Services.MetadataUtil;
using SF = Microsoft.CodeAnalysis.CSharp.SyntaxFactory;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Compiles a new C# body for an existing method and returns IL ready to be placed in the original module.
///
/// How: decompile the method's top-level type, replace the target body with the new code and every other body with
/// "throw null" (so decompiler output that does not round-trip cannot break the build), compile it with Roslyn against
/// the assembly's real references with accessibility checks off (private/internal members are usable), then copy the
/// compiled body into the original method, remapping every type/member of the shadow type back to the original definitions.
/// </summary>
public sealed class CSharpPatcher(AssemblyWorkspace workspace, DecompilerService decompiler)
{
    private static readonly SyntaxAnnotation BodyAnnotation = new("netdecomp-patch-body");

    public sealed record Compiled(CilBody Body, string Listing);

    public Compiled Compile(ResolvedSymbol symbol, string code, CancellationToken ct)
    {
        if (symbol.Member is not MethodDef method)
            throw new ToolError($"{symbol.Label} is a {symbol.Kind}, not a method.");
        if (method.IsAbstract || method.IsPinvokeImpl || method.IsRuntime || method.IsInternalCall)
            throw new ToolError($"{symbol.Label} has no IL body to replace (abstract/extern/runtime).");

        var asm = symbol.Assembly;
        var top = TopLevel(method.DeclaringType);
        var source = decompiler.DecompileType(asm, top, ct);

        var parseOptions = new CSharpParseOptions(LanguageVersion.Preview);
        var root = CSharpSyntaxTree.ParseText(source, parseOptions, cancellationToken: ct).GetCompilationUnitRoot(ct);
        var typeNode = FindTypeDeclaration(root, method.DeclaringType)
                       ?? throw new ToolError($"Could not locate {method.DeclaringType.FullName} in its decompiled source; use patch_method_il instead.");
        var target = FindMemberNode(typeNode, method);
        var body = ParseBody(code).WithAdditionalAnnotations(BodyAnnotation);
        var rewritten = (CompilationUnitSyntax)new StubRewriter(target, body).Visit(root)!;
        var tree = CSharpSyntaxTree.Create(rewritten, parseOptions);

        var compilation = CSharpCompilation.Create(asm.AssemblyName + ".__patch", [tree], BuildReferences(asm, out var missing), CreateOptions());
        using var pe = new MemoryStream();
        var emit = compilation.Emit(pe, cancellationToken: ct);
        if (!emit.Success)
            throw new ToolError(FormatErrors(emit.Diagnostics, tree, missing));

        using var compiledModule = ModuleDefMD.Load(pe.ToArray(), workspace.DnlibContext);
        var compiledMethod = FindCompiledMethod(compiledModule, method);
        var newBody = Transplant(compiledMethod, method, compiledModule);

        newBody.UpdateInstructionOffsets();
        var listing = string.Join("\n", newBody.Instructions.Select(i => "  " + i));
        return new Compiled(newBody, listing);
    }

    // ------------------------------------------------------------------ locate the target in decompiled source

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

    /// <summary>
    /// Puts the new body on the target and "throw null" in every other body. Field/property initializers are dropped,
    /// except when patching a constructor: C# compiles initializers into constructors, so the matching (instance or
    /// static) initializers are kept and the patched constructor still initializes fields like the original.
    /// </summary>
    private sealed class StubRewriter(SyntaxNode target, BlockSyntax newBody) : CSharpSyntaxRewriter
    {
        private static readonly BlockSyntax Stub = SF.Block(SF.ParseStatement("throw null;"));

        private readonly bool _keepInstanceInitializers = target is ConstructorDeclarationSyntax c && !c.Modifiers.Any(SyntaxKind.StaticKeyword);
        private readonly bool _keepStaticInitializers = target is ConstructorDeclarationSyntax s && s.Modifiers.Any(SyntaxKind.StaticKeyword);

        private bool KeepInitializer(SyntaxTokenList modifiers) =>
            modifiers.Any(SyntaxKind.ConstKeyword) || (modifiers.Any(SyntaxKind.StaticKeyword) ? _keepStaticInitializers : _keepInstanceInitializers);

        private BlockSyntax BodyFor(SyntaxNode original) => original == target ? newBody : Stub;

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
    private List<MetadataReference> BuildReferences(LoadedAssembly asm, out List<string> missing)
    {
        missing = new List<string>();
        var references = new List<MetadataReference>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var queue = new Queue<(byte[] Image, ModuleDef Module, bool Owned)>();

        void Enqueue(string name, byte[] image, ModuleDef module, bool owned)
        {
            if (!seen.Add(name)) { if (owned) module.Dispose(); return; }
            references.Add(MetadataReference.CreateFromImage(image));
            queue.Enqueue((image, module, owned));
        }

        Enqueue(asm.AssemblyName, asm.GetImageBytes(), asm.Module, owned: false);
        while (queue.Count > 0)
        {
            var (_, module, owned) = queue.Dequeue();
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

    private static string FormatErrors(IEnumerable<Diagnostic> diagnostics, SyntaxTree tree, List<string> missing)
    {
        var bodyNode = tree.GetRoot().GetAnnotatedNodes(BodyAnnotation).First();
        var bodySpan = bodyNode.GetLocation().GetLineSpan();
        var lines = tree.GetText().Lines;
        var errors = diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error).ToList();

        var sb = new StringBuilder($"C# compilation failed ({errors.Count} error(s)). Nothing was changed.\n");
        foreach (var d in errors.Take(20))
        {
            var span = d.Location.GetLineSpan();
            int line = span.StartLinePosition.Line;
            bool inBody = d.Location.SourceTree == tree && bodyNode.Span.Contains(d.Location.SourceSpan.Start);
            var where = inBody
                ? $"your code line {line - bodySpan.StartLinePosition.Line}"
                : $"decompiled context line {line + 1}";
            var text = d.Location.IsInSource ? lines[line].ToString().Trim() : "";
            sb.AppendLine($"  {d.Id} at {where}: {d.GetMessage()}{(text.Length > 0 ? $"\n      > {Format.Clip(text, 160)}" : "")}");
        }
        if (errors.Count > 20) sb.AppendLine($"  … {errors.Count - 20} more");
        if (errors.Any(e => !(e.Location.SourceTree == tree && bodyNode.Span.Contains(e.Location.SourceSpan.Start))))
            sb.AppendLine("Errors outside your code come from the decompiled declaration of the surrounding type (e.g. signatures the decompiler cannot express). If they persist, use patch_method_il.");
        if (missing.Count > 0)
            sb.AppendLine($"Unresolved references (load them or add_search_directory): {string.Join(", ", missing)}");
        return sb.ToString();
    }

    // ------------------------------------------------------------------ transplant compiled IL

    private static MethodDef FindCompiledMethod(ModuleDef compiled, MethodDef original)
    {
        var type = compiled.Find(original.DeclaringType.FullName, isReflectionName: false)
                   ?? throw new ToolError($"Internal: compiled shadow type {original.DeclaringType.FullName} not found. Compiled types: " +
                                          string.Join(", ", compiled.GetTypes().Take(15).Select(t => t.FullName)));
        var comparer = new SigComparer(SigComparerOptions.DontCompareTypeScope);
        return type.Methods.FirstOrDefault(m => m.Name == original.Name && comparer.Equals(m.MethodSig, original.MethodSig))
               ?? type.Methods.Single(m => m.Name == original.Name && ParamCount(m) == ParamCount(original));
    }

    private static CilBody Transplant(MethodDef source, MethodDef target, ModuleDef compiled)
    {
        var module = target.Module;
        var mapper = new ShadowMapper(module, compiled, target.Module.Assembly?.Name ?? "");
        var importer = new Importer(module, ImporterOptions.TryToUseDefs, new GenericParamContext(target.DeclaringType, target), mapper);
        var src = source.Body ?? throw new ToolError("Internal: compiled method has no body.");

        var body = new CilBody { InitLocals = src.InitLocals, KeepOldMaxStack = false };
        var locals = new Dictionary<Local, Local>();
        foreach (var l in src.Variables)
            locals[l] = body.Variables.Add(new Local(importer.Import(l.Type), l.Name));

        var map = new Dictionary<Instruction, Instruction>();
        foreach (var i in src.Instructions)
        {
            var copy = new Instruction(i.OpCode);
            map[i] = copy;
            body.Instructions.Add(copy);
        }
        foreach (var i in src.Instructions)
        {
            map[i].Operand = i.Operand switch
            {
                Instruction t => map[t],
                Instruction[] ts => ts.Select(t => map[t]).ToArray(),
                Local l => locals[l],
                Parameter p => target.Parameters[p.Index],
                _ when AsField(i.Operand) is { } f => mapper.ResolveOwn(f) ?? Imported(importer.Import(f), f),
                _ when AsMethod(i.Operand) is { } m => mapper.ResolveOwn(m, importer) ?? Imported(importer.Import(m), m),
                ITypeDefOrRef t => importer.Import(t),
                MethodSig sig => importer.Import(sig),
                _ => i.Operand,
            };
        }
        foreach (var h in src.ExceptionHandlers)
        {
            body.ExceptionHandlers.Add(new ExceptionHandler(h.HandlerType)
            {
                TryStart = Map(h.TryStart), TryEnd = Map(h.TryEnd),
                HandlerStart = Map(h.HandlerStart), HandlerEnd = Map(h.HandlerEnd),
                FilterStart = Map(h.FilterStart),
                CatchType = h.CatchType == null ? null : importer.Import(h.CatchType),
            });
        }

        if (mapper.Unmapped.Count > 0)
            throw new ToolError("The compiled code needs compiler-generated helpers that do not exist in the original assembly: " +
                                string.Join(", ", mapper.Unmapped.Distinct().Take(10)) +
                                ". These come from lambdas, local functions, async/await, yield, LINQ query syntax, large string switches or array initializers. " +
                                "Rewrite the body without them (e.g. plain loops / if-chains), or use patch_method_il.");
        return body;

        Instruction? Map(Instruction? i) => i == null ? null : map[i];
    }

    private static T Imported<T>(T? imported, object original) where T : class =>
        imported ?? throw new ToolError($"Internal: could not import operand {original} into the target module; use patch_method_il.");

    /// <summary>Maps the shadow type (and the reference copy of the original assembly) back onto the original definitions.</summary>
    private sealed class ShadowMapper(ModuleDef target, ModuleDef compiled, string targetAssemblyName) : ImportMapper
    {
        private static readonly SigComparer Comparer = new(SigComparerOptions.DontCompareTypeScope);
        private Dictionary<string, TypeRef>? _existingTypeRefs;

        public List<string> Unmapped { get; } = new();

        public override ITypeDefOrRef? Map(ITypeDefOrRef source)
        {
            switch (source)
            {
                case TypeDef td when td.Module == compiled:
                    return FindType(td.FullName);
                case TypeRef tr when IsTargetScope(tr):
                    return FindType(tr.FullName);
                case TypeRef tr:
                    // Keep the module's own reference scopes (e.g. System.Runtime / mscorlib) instead of whatever
                    // implementation assembly Roslyn bound to (e.g. System.Private.CoreLib).
                    return ExistingTypeRefs.GetValueOrDefault(tr.FullName);
                default:
                    return null;
            }
        }

        public override IField? Map(FieldDef source) =>
            source.Module != compiled ? null : FindField(source.DeclaringType.FullName, source.Name, Format.MemberLabel(source));

        public override IMethod? Map(MethodDef source) =>
            source.Module != compiled ? null : FindMethod(source.DeclaringType.FullName, source.Name, source.MethodSig, Format.MemberLabel(source));

        /// <summary>Member references into the original assembly become the original definitions (dnlib's importer can't do this for fields).</summary>
        public IMethod? ResolveOwn(IMethod method, Importer importer) => method switch
        {
            MethodDef md when md.Module == compiled => Map(md),
            MemberRef { DeclaringType: TypeRef tr } mr when IsTargetScope(tr) => FindMethod(tr.FullName, mr.Name, mr.MethodSig, Format.MemberLabel(mr)),
            MethodSpec spec when ResolveOwn(spec.Method, importer) is IMethodDefOrRef inner =>
                new MethodSpecUser(inner, importer.Import(spec.GenericInstMethodSig)),
            _ => null,
        };

        public IField? ResolveOwn(IField field) => field switch
        {
            FieldDef fd when fd.Module == compiled => Map(fd),
            MemberRef { DeclaringType: TypeRef tr } mr when IsTargetScope(tr) => FindField(tr.FullName, mr.Name, Format.MemberLabel(mr)),
            _ => null,
        };

        private bool IsTargetScope(TypeRef tr) => tr.DefinitionAssembly?.Name == targetAssemblyName;

        private Dictionary<string, TypeRef> ExistingTypeRefs => _existingTypeRefs ??=
            ((target as ModuleDefMD)?.GetTypeRefs() ?? []).GroupBy(t => t.FullName).ToDictionary(g => g.Key, g => g.First());

        private FieldDef? FindField(string typeName, string name, string label)
        {
            var field = FindType(typeName)?.Fields.FirstOrDefault(f => f.Name == name);
            if (field == null) Unmapped.Add(label);
            return field;
        }

        private MethodDef? FindMethod(string typeName, string name, MethodSig sig, string label)
        {
            var method = FindType(typeName)?.Methods.FirstOrDefault(m => m.Name == name && Comparer.Equals(m.MethodSig, sig));
            if (method == null) Unmapped.Add(label);
            return method;
        }

        private TypeDef? FindType(string fullName)
        {
            var t = target.Find(fullName, isReflectionName: false);
            if (t == null) Unmapped.Add(fullName);
            return t;
        }
    }
}
