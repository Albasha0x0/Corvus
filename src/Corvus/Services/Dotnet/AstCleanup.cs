using System.Reflection.Metadata;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.Syntax;
using ICSharpCode.Decompiler.CSharp.Transforms;
using ICSharpCode.Decompiler.TypeSystem;
using Corvus.Core;

namespace Corvus.Services;

/// <summary>
/// AST transforms that rewrite decompiler output which does not compile into valid C#. Run after the engine's own transforms.
/// </summary>
internal static class AstCleanup
{
    public static void AddTo(CSharpDecompiler decompiler, string? targetFramework)
    {
        decompiler.AstTransforms.Add(new Guarded(new InlineRefTemporaries()));
        if (Frameworks.NetCoreMajor(targetFramework) >= 5)
            decompiler.AstTransforms.Add(new Guarded(new UninitializedRefLocals()));
        if (Frameworks.NetCoreMajor(targetFramework) >= 8)
            decompiler.AstTransforms.Add(new Guarded(new ReturnRefThroughLocalCopy()));
        decompiler.AstTransforms.Add(new Guarded(new ScopedSpanLocals()));
        decompiler.AstTransforms.Add(new Guarded(new StackAllocInitializers()));
        decompiler.AstTransforms.Add(new Guarded(new UncheckedNegativeCasts()));
        decompiler.AstTransforms.Add(new Guarded(new ReservedAttributes()));
        decompiler.AstTransforms.Add(new Guarded(new BaseConstructorCalls()));
        decompiler.AstTransforms.Add(new Guarded(new ParameterFieldInitializers()));
        decompiler.AstTransforms.Add(new Guarded(new NestedLocalNames()));
        decompiler.AstTransforms.Add(new Guarded(new PatternDisposeCalls()));
        decompiler.AstTransforms.Add(new Guarded(new SetterOnlyAutoProperties()));
        decompiler.AstTransforms.Add(new Guarded(new BoolToIntCasts()));
        decompiler.AstTransforms.Add(new Guarded(new SourceGeneratorTriggers()));
        decompiler.AstTransforms.Add(new Guarded(new OperatorNamedArguments()));
        decompiler.AstTransforms.Add(new Guarded(new AccessorValueParameters()));
        decompiler.AstTransforms.Add(new Guarded(new PositionalNamedArguments()));
        decompiler.AstTransforms.Add(new Guarded(new UnconstrainedNew()));
        decompiler.AstTransforms.Add(new Guarded(new RenamedEntryPoint()));
        decompiler.AstTransforms.Add(new Guarded(new NullConditionalExtensionCalls()));
        decompiler.AstTransforms.Add(new Guarded(new GenericDelegateDefaults()));
        decompiler.AstTransforms.Add(new Guarded(new SwitchExpressionHelpers()));
        decompiler.AstTransforms.Add(new Guarded(new MissingLocalFunctions()));
        decompiler.AstTransforms.Add(new Guarded(new DiscardParameters()));
        if (Frameworks.PublicTypeNames(targetFramework) is { } frameworkTypes)
            decompiler.AstTransforms.Add(new Guarded(new FrameworkAmbiguousNames(frameworkTypes)));
    }

    /// <summary>Number of transforms that threw; the engine output was kept in each case.</summary>
    internal static int Failures;

    internal static string? LastError;

    /// <summary>Rewrite decisions, recorded when CORVUS_CLEANUP_LOG is set.</summary>
    internal static readonly System.Collections.Concurrent.ConcurrentQueue<string> Log = new();
    internal static readonly bool Logging = Environment.GetEnvironmentVariable("CORVUS_CLEANUP_LOG") != null;

    /// <summary>Isolates a transform: if it throws, the engine output is kept instead of failing the member.</summary>
    private sealed class Guarded(IAstTransform inner) : IAstTransform
    {

        public void Run(AstNode rootNode, TransformContext context)
        {
            try { inner.Run(rootNode, context); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Interlocked.Increment(ref Failures);
                LastError = $"{inner.GetType().Name}: {ex}";
            }
        }
    }
}

/// <summary>
/// Inlines ref temporaries from span slicing: <c>ref Span&lt;T&gt; r; r = ref x; r.Slice(...)</c> → <c>x.Slice(...)</c>
/// (CS8174, CS8352, CS8374, CS9096). Only where the aliased location is certain.
/// </summary>
internal sealed class InlineRefTemporaries : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var body in rootNode.DescendantsAndSelf.OfType<BlockStatement>().Where(b => !b.Ancestors.OfType<BlockStatement>().Any()).ToList())
            foreach (var declarations in body.Descendants.OfType<VariableDeclarationStatement>()
                         .Where(d => d.Type is ComposedType { HasRefSpecifier: true } && d.Variables.Count == 1)
                         .GroupBy(d => d.Variables.Single().Name).ToList())
                Inline(body, declarations.Key, declarations.ToList());
    }

    /// <summary>Handles all ref locals of one name together; the engine reuses a name across branches.</summary>
    private static void Inline(BlockStatement body, string name, List<VariableDeclarationStatement> declarations)
    {
        bool IsName(AstNode n) => n is IdentifierExpression { Identifier: var id, TypeArguments.Count: 0 } && id == name;
        bool IsRefAssignment(AstNode n) => n is AssignmentExpression { Operator: AssignmentOperatorType.Assign, Right: DirectionExpression { FieldDirection: FieldDirection.Ref } } a && IsName(a.Left);

        // Bindings: the declaration's initializer and `name = ref E;` statements.
        var bindings = new List<(Statement Statement, Expression Target)>();
        foreach (var declaration in declarations)
            if (declaration.Variables.Single().Initializer is DirectionExpression { FieldDirection: FieldDirection.Ref } init)
                bindings.Add((declaration, init.Expression));
        foreach (var s in body.Descendants.OfType<ExpressionStatement>())
            if (IsRefAssignment(s.Expression))
                bindings.Add((s, ((DirectionExpression)((AssignmentExpression)s.Expression).Right).Expression));
        if (bindings.Count == 0) return;
        // Innermost first, so a loop body's bindings claim its uses before an enclosing binding does.
        bindings = bindings.OrderByDescending(b => b.Statement.Ancestors.Count()).ToList();

        var inlined = new List<Statement>();
        foreach (var (statement, target) in bindings)
        {
            if (!IsFixedLocation(target) || statement.Parent is not BlockStatement) continue;
            var uses = new List<IdentifierExpression>();
            bool safe = true;
            for (var s = NextStatement(statement); s != null; s = NextStatement(s))
            {
                var rebinds = s.DescendantsAndSelf.Any(IsRefAssignment);
                var here = s.DescendantsAndSelf.OfType<IdentifierExpression>()
                    .Where(i => IsName(i) && !(i.Parent is AssignmentExpression a && a.Left == i && IsRefAssignment(a))).ToList();
                if (rebinds)
                {
                    // Rebound within this statement (e.g. a loop): a use here may see either binding.
                    if (here.Count > 0) safe = false;
                    break;
                }
                uses.AddRange(here);
            }
            if (!safe) continue;
            foreach (var use in uses)
                use.ReplaceWith(target.Clone());
            inlined.Add(statement);
        }

        // Remove bindings and declarations only when every use was inlined.
        bool stillUsed = body.Descendants.OfType<IdentifierExpression>()
            .Any(i => IsName(i) && !(i.Parent is AssignmentExpression a && a.Left == i && IsRefAssignment(a)));
        if (stillUsed || inlined.Count != bindings.Count) return;
        foreach (var s in inlined)
            if (s.Parent != null) s.Remove();
        foreach (var declaration in declarations)
            if (declaration.Parent != null) declaration.Remove();
    }

    private static Statement? NextStatement(AstNode node)
    {
        for (var n = node.NextSibling; n != null; n = n.NextSibling)
            if (n is Statement s) return s;
        return null;
    }

    /// <summary>A local, parameter, or field of <c>this</c> or a type: a location that cannot change between uses.</summary>
    private static bool IsFixedLocation(Expression e) => e switch
    {
        IdentifierExpression { TypeArguments.Count: 0 } => true,
        MemberReferenceExpression { Target: ThisReferenceExpression or TypeReferenceExpression, TypeArguments.Count: 0 } => true,
        _ => false,
    };
}

/// <summary>
/// Folds <c>Unsafe.CopyBlockUnaligned(ptr, ref &lt;PrivateImplementationDetails&gt;.X, n)</c> back into a
/// <c>stackalloc T[n] { ... }</c> initializer (CS0103).
/// </summary>
internal sealed class StackAllocInitializers : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var copy in rootNode.Descendants.OfType<ExpressionStatement>().ToList())
        {
            if (copy.Expression is not InvocationExpression { Target: MemberReferenceExpression { MemberName: "CopyBlockUnaligned" or "CopyBlock" }, Arguments.Count: 3 } call)
                continue;
            var args = call.Arguments.ToList();
            if (args[0] is not IdentifierExpression pointer
                || args[1] is not DirectionExpression { FieldDirection: FieldDirection.Ref, Expression: var source }
                || args[2] is not PrimitiveExpression { Value: int or uint } lengthArg
                || source.GetSymbol() is not IField field
                || PreviousStatement(copy) is not VariableDeclarationStatement { Variables.Count: 1 } declaration
                || declaration.Variables.Single() is not { Initializer: StackAllocExpression { CountExpression: PrimitiveExpression { Value: int count } } alloc } variable
                || alloc.Initializer is { Elements.Count: > 0 }
                || variable.Name != pointer.Identifier
                || alloc.Type is not PrimitiveType { Keyword: var keyword }
                || ElementSize(keyword) is not { } size
                || size * count != Convert.ToInt32(lengthArg.Value)
                || ReadData(field, size * count) is not { } data)
                continue;

            var initializer = new ArrayInitializerExpression();
            for (int i = 0; i < count; i++)
                initializer.Elements.Add(new PrimitiveExpression(Element(keyword, data, i * size)));
            alloc.Initializer = initializer;
            if (copy.PrevSibling is Comment { Content: var text } comment && text.Contains("cpblk", StringComparison.Ordinal))
                comment.Remove();
            copy.Remove();
        }
    }

    private static Statement? PreviousStatement(AstNode node)
    {
        for (var n = node.PrevSibling; n != null; n = n.PrevSibling)
            if (n is Statement s) return s;
        return null;
    }

    private static byte[]? ReadData(IField field, int length)
    {
        try
        {
            if (field.ParentModule?.MetadataFile is not { } file || field.MetadataToken.IsNil) return null;
            var definition = file.Metadata.GetFieldDefinition((FieldDefinitionHandle)field.MetadataToken);
            var reader = definition.GetInitialValue(file, field.ParentModule.Compilation);
            return reader.Length >= length ? reader.ReadBytes(length) : null;
        }
        catch
        {
            return null;
        }
    }

    private static int? ElementSize(string keyword) => keyword switch
    {
        "byte" or "sbyte" or "bool" => 1,
        "short" or "ushort" or "char" => 2,
        "int" or "uint" or "float" => 4,
        "long" or "ulong" or "double" => 8,
        _ => null,
    };

    private static object Element(string keyword, byte[] data, int at) => keyword switch
    {
        "byte" => data[at],
        "sbyte" => (sbyte)data[at],
        "bool" => data[at] != 0,
        "short" => BitConverter.ToInt16(data, at),
        "ushort" => BitConverter.ToUInt16(data, at),
        "char" => BitConverter.ToChar(data, at),
        "int" => BitConverter.ToInt32(data, at),
        "uint" => BitConverter.ToUInt32(data, at),
        "float" => BitConverter.ToSingle(data, at),
        "long" => BitConverter.ToInt64(data, at),
        "ulong" => BitConverter.ToUInt64(data, at),
        _ => BitConverter.ToDouble(data, at),
    };
}

/// <summary>
/// Wraps negative constants cast to unsigned types in <c>unchecked(...)</c>: <c>(nuint)(-70)</c> (CS0221).
/// </summary>
internal sealed class UncheckedNegativeCasts : IAstTransform
{
    private static readonly HashSet<string> Unsigned = ["nuint", "ulong", "uint", "ushort", "byte", "char"];

    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var cast in rootNode.Descendants.OfType<CastExpression>().ToList())
        {
            if (cast.Type is not PrimitiveType { Keyword: var keyword } || !Unsigned.Contains(keyword)) continue;
            if (!IsNegativeConstant(cast.Expression)) continue;
            if (cast.Ancestors.Any(a => a is UncheckedExpression or UncheckedStatement)) continue;
            var replacement = new UncheckedExpression();
            cast.ReplaceWith(replacement);
            replacement.Expression = cast;
        }
    }

    private static bool IsNegativeConstant(Expression e) => e switch
    {
        ParenthesizedExpression p => IsNegativeConstant(p.Expression),
        UnaryOperatorExpression { Operator: UnaryOperatorType.Minus, Expression: PrimitiveExpression { Value: not null } } => true,
        PrimitiveExpression { Value: sbyte or short or int or long or decimal } pe => Convert.ToDecimal(pe.Value) < 0,
        _ => false,
    };
}

/// <summary>
/// Removes compiler-reserved assembly/module attributes such as <c>[module: RefSafetyRules(11)]</c> (CS8335).
/// The compiler re-emits them.
/// </summary>
internal sealed class ReservedAttributes : IAstTransform
{
    private static readonly HashSet<string> Reserved =
    [
        "NullablePublicOnlyAttribute", "NullableAttribute", "NullableContextAttribute", "RefSafetyRulesAttribute",
        "IsReadOnlyAttribute", "IsByRefLikeAttribute", "IsUnmanagedAttribute", "NativeIntegerAttribute", "ScopedRefAttribute",
        "RequiresLocationAttribute", "ParamCollectionAttribute", "EmbeddedAttribute",
    ];

    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var section in rootNode.Descendants.OfType<AttributeSection>().ToList())
        {
            if (section.AttributeTarget is not ("assembly" or "module")) continue;
            foreach (var attribute in section.Attributes.ToList())
                if (attribute.Type.GetSymbol() is ITypeDefinition { Namespace: "System.Runtime.CompilerServices" or "Microsoft.CodeAnalysis" } type
                    && Reserved.Contains(type.Name))
                    attribute.Remove();
            if (section.Attributes.Count == 0) section.Remove();
        }
    }
}

/// <summary>
/// Turns <c>base._002Ector(x);</c> in a constructor body into the initializer <c>: base(x)</c> (CS0117, CS7036).
/// Assignments preceding the call then run after the base constructor, so this is only done when the base
/// constructor chain calls nothing overridable (checked in IL). An unreadable base constructor is assumed safe.
/// </summary>
internal sealed class BaseConstructorCalls : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var ctor in rootNode.Descendants.OfType<ConstructorDeclaration>().ToList())
        {
            // An explicit base(...) or this(...) initializer already exists.
            if (ctor.Initializer is { } existing && (existing.Arguments.Any() || existing.ConstructorInitializerType == ConstructorInitializerType.This)
                || ctor.Body is not { Statements.Count: > 0 })
                continue;
            var call = ctor.Body.Statements.OfType<ExpressionStatement>().FirstOrDefault(s =>
                s.Expression is InvocationExpression
                {
                    Target: MemberReferenceExpression { MemberName: ".ctor" or "_002Ector", Target: BaseReferenceExpression or ThisReferenceExpression }
                });
            if (call == null) continue;
            var invocation = (InvocationExpression)call.Expression;
            bool viaThis = ((MemberReferenceExpression)invocation.Target).Target is ThisReferenceExpression;
            // Only plain assignments may be reordered past the base call.
            var before = ctor.Body.Statements.TakeWhile(s => s != call).ToList();
            if (before.Any(s => s is not ExpressionStatement { Expression: AssignmentExpression })) continue;

            var target = invocation.GetSymbol() as IMethod;
            var safety = before.Count == 0 ? "nothing moved" : target == null ? "base constructor unknown" : VirtualCalls(target, 0, []) ?? "safe";
            if (AstCleanup.Logging)
                AstCleanup.Log.Enqueue($"BaseConstructorCalls {(ctor.GetSymbol() as IEntity)?.DeclaringType?.FullName}: {before.Count} assignment(s) moved after {target?.DeclaringType?.FullName}..ctor: {safety}");
            // An override could observe the unassigned members: keep the compiled order.
            if (safety.StartsWith("calls overridable", StringComparison.Ordinal)) continue;

            var initializer = new ConstructorInitializer
            {
                ConstructorInitializerType = viaThis ? ConstructorInitializerType.This : ConstructorInitializerType.Base,
            };
            foreach (var argument in invocation.Arguments)
                initializer.Arguments.Add(argument.Clone());
            ctor.Initializer = initializer;
            call.Remove();
        }
    }

    /// <summary>
    /// Describes the first virtual call on the instance made by <paramref name="method"/>, following base
    /// constructors and non-virtual helpers up to three levels deep; null if none.
    /// </summary>
    internal static string? VirtualCalls(IMethod method, int depth, HashSet<IMethod> seen)
    {
        if (depth > 3 || !seen.Add(method)) return null;
        if (method.ParentModule?.MetadataFile is not ICSharpCode.Decompiler.Metadata.PEFile file || method.MetadataToken.IsNil
            || method.MetadataToken.Kind != System.Reflection.Metadata.HandleKind.MethodDefinition)
            return method.DeclaringType?.FullName == "System.Object" ? null : $"{method.DeclaringType?.FullName}..ctor not readable";
        if (method.ParentModule is not ICSharpCode.Decompiler.TypeSystem.MetadataModule module) return null;
        var definition = file.Metadata.GetMethodDefinition((System.Reflection.Metadata.MethodDefinitionHandle)method.MetadataToken);
        if (definition.RelativeVirtualAddress == 0) return null;
        System.Reflection.Metadata.BlobReader il;
        try { il = file.Reader.GetMethodBody(definition.RelativeVirtualAddress).GetILReader(); }
        catch (Exception) { return $"{method.FullName} body not readable"; }
        while (il.RemainingBytes > 0)
        {
            var opCode = ICSharpCode.Decompiler.Disassembler.ILParser.DecodeOpCode(ref il);
            if (opCode is System.Reflection.Metadata.ILOpCode.Call or System.Reflection.Metadata.ILOpCode.Callvirt or System.Reflection.Metadata.ILOpCode.Ldvirtftn)
            {
                var token = System.Reflection.Metadata.Ecma335.MetadataTokens.EntityHandle(il.ReadInt32());
                IMethod? callee;
                try { callee = module.ResolveMethod(token, default); }
                catch (Exception) { continue; }
                if (callee == null || callee.IsStatic) continue;
                bool onObject = method.DeclaringType != null && method.DeclaringType.GetAllBaseTypeDefinitions().Contains(callee.DeclaringTypeDefinition)
                                || callee.DeclaringTypeDefinition?.Kind == TypeKind.Interface;
                if (!onObject) continue;
                if (opCode != System.Reflection.Metadata.ILOpCode.Call && callee.IsOverridable && !callee.IsConstructor)
                    return $"calls overridable {callee.FullName}";
                // Base constructor or non-virtual helper: recurse.
                if (callee.IsConstructor || !callee.IsOverridable)
                    if (VirtualCalls(callee, depth + 1, seen) is { } inner) return inner;
                continue;
            }
            ICSharpCode.Decompiler.Disassembler.ILParser.SkipOperand(ref il, opCode);
        }
        return null;
    }
}

/// <summary>
/// Moves field initializers that reference a constructor parameter back into the start of the single
/// instance constructor (CS0103).
/// </summary>
internal sealed class ParameterFieldInitializers : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var type in rootNode.Descendants.OfType<TypeDeclaration>().ToList())
        {
            var ctors = type.Members.OfType<ConstructorDeclaration>().Where(c => !c.HasModifier(Modifiers.Static)).ToList();
            if (ctors.Count != 1 || ctors[0].Body is not { } body) continue;
            // The assignment now runs after the base constructor; skip if an override could observe that.
            if (type.ClassType != ClassType.Struct && type.GetSymbol() is ITypeDefinition typeDef)
            {
                var baseCtor = ctors[0].Initializer?.GetSymbol() as IMethod
                               ?? typeDef.DirectBaseTypes.FirstOrDefault(b => b.Kind == TypeKind.Class)?.GetConstructors(c => c.Parameters.Count == 0).FirstOrDefault();
                var safety = baseCtor == null ? "base constructor unknown" : BaseConstructorCalls.VirtualCalls(baseCtor, 0, []);
                if (AstCleanup.Logging) AstCleanup.Log.Enqueue($"ParameterFieldInitializers {typeDef.FullName}: {safety ?? "safe"}");
                if (safety?.StartsWith("calls overridable", StringComparison.Ordinal) == true) continue;
            }
            var parameters = ctors[0].Parameters.Select(p => p.Name).ToHashSet();
            var members = type.Members.Select(m => m.Name).ToHashSet();
            int insertAt = 0;
            foreach (var field in type.Members.OfType<FieldDeclaration>().Where(f => !f.HasModifier(Modifiers.Static) && !f.HasModifier(Modifiers.Const)).ToList())
                foreach (var variable in field.Variables)
                {
                    if (variable.Initializer is not { } init) continue;
                    if (!init.DescendantsAndSelf.OfType<IdentifierExpression>().Any(i => parameters.Contains(i.Identifier) && !members.Contains(i.Identifier))) continue;
                    var value = init.Clone();
                    variable.Initializer = null!;
                    var assign = new ExpressionStatement(new AssignmentExpression(
                        new MemberReferenceExpression(new ThisReferenceExpression(), variable.Name), value));
                    if (insertAt < body.Statements.Count) body.Statements.InsertBefore(body.Statements.ElementAt(insertAt), assign);
                    else body.Statements.Add(assign);
                    insertAt++;
                }
        }
    }
}

/// <summary>
/// Renames a local that shadows a same-named local of an enclosing scope (CS0136).
/// </summary>
internal sealed class NestedLocalNames : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var body in rootNode.DescendantsAndSelf.OfType<BlockStatement>().Where(b => !b.Ancestors.OfType<BlockStatement>().Any()).ToList())
        {
            var declarations = body.DescendantsAndSelf.OfType<VariableDeclarationStatement>()
                .SelectMany(d => d.Variables.Select(v => (Statement: (Statement)d, Variable: v))).ToList();
            var taken = body.Descendants.OfType<Identifier>().Select(i => i.Name).ToHashSet();
            foreach (var group in declarations.GroupBy(d => d.Variable.Name).Where(g => g.Count() > 1))
                foreach (var inner in group)
                {
                    var innerBlock = inner.Statement.Parent as BlockStatement;
                    if (innerBlock == null) continue;
                    var innerScope = Scope(innerBlock);
                    bool clashes = group.Any(o => o.Variable != inner.Variable && o.Statement.Parent is BlockStatement outerBlock
                                                  && Scope(outerBlock) is var outer && outer != innerScope && innerScope.Ancestors.Contains(outer));
                    if (!clashes) continue;
                    var name = inner.Variable.Name;
                    var fresh = Enumerable.Range(2, 100).Select(n => name + n).First(n => !taken.Contains(n));
                    taken.Add(fresh);
                    inner.Variable.Name = fresh;
                    foreach (var use in innerBlock.Descendants.OfType<IdentifierExpression>().Where(i => i.Identifier == name).ToList())
                        use.Identifier = fresh;
                }
        }
    }

    /// <summary>
    /// The effective source scope: the body of a braceless <c>using var</c> is a separate block in the AST but
    /// shares the enclosing block's scope.
    /// </summary>
    private static BlockStatement Scope(BlockStatement block)
    {
        while (block.Parent is UsingStatement { IsEnhanced: true } && block.Parent.Parent is BlockStatement enclosing)
            block = enclosing;
        return block;
    }
}

/// <summary>
/// Pattern-based disposal of a struct: <c>IDisposable d = e as IDisposable; if (d != null) d.Dispose();</c> →
/// <c>e.Dispose();</c> (CS0039). Same for <c>DisposeAsync</c>.
/// </summary>
internal sealed class PatternDisposeCalls : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var declaration in rootNode.Descendants.OfType<VariableDeclarationStatement>().ToList())
        {
            if (declaration.Variables.Count != 1 || declaration.Variables.Single() is not { Initializer: AsExpression { Expression: var source, Type: var asType } } variable)
                continue;
            if (asType.GetSymbol() is not ITypeDefinition { FullName: "System.IAsyncDisposable" or "System.IDisposable" } iface) continue;
            if (source.GetResolveResult()?.Type is not { IsReferenceType: false } sourceType
                || sourceType.GetAllBaseTypes().Any(b => b.FullName == iface.FullName))
                continue;
            if (declaration.NextSibling is not IfElseStatement { FalseStatement: null } check
                || check.Condition is not BinaryOperatorExpression { Operator: BinaryOperatorType.InEquality, Left: IdentifierExpression { Identifier: var tested }, Right: NullReferenceExpression }
                || tested != variable.Name)
                continue;
            bool isAsync = iface.FullName == "System.IAsyncDisposable";
            Expression call = new InvocationExpression(new MemberReferenceExpression(source.Clone(), isAsync ? "DisposeAsync" : "Dispose"));
            if (isAsync) call = new UnaryOperatorExpression(UnaryOperatorType.Await, call);
            check.ReplaceWith(new ExpressionStatement(call));
            declaration.Remove();
        }
    }
}

/// <summary>
/// Adds a getter to setter-only auto-properties, typically left by IL trimming (CS8051).
/// </summary>
internal sealed class SetterOnlyAutoProperties : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var property in rootNode.Descendants.OfType<PropertyDeclaration>().ToList())
        {
            if (property.Setter is null || property.Getter is not null) continue;
            if (property.Setter.Body is not null || property.HasModifier(Modifiers.Abstract) || property.HasModifier(Modifiers.Extern)) continue;
            if (property.Parent is TypeDeclaration { ClassType: ClassType.Interface }) continue;
            property.Getter = new Accessor();
        }
    }
}

/// <summary>
/// Bool-to-integer casts (CS0030): <c>(int)b</c> → <c>(int)(b ? 1 : 0)</c>; nullable bools use a switch expression.
/// </summary>
internal sealed class BoolToIntCasts : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var cast in rootNode.Descendants.OfType<CastExpression>().ToList())
        {
            if (cast.Type.GetResolveResult()?.Type is not { } target || cast.Expression.GetResolveResult()?.Type is not { } source) continue;
            bool sourceNullable = NullableType.IsNullable(source);
            if (!NullableType.GetUnderlyingType(source).IsKnownType(KnownTypeCode.Boolean)) continue;
            var targetCore = NullableType.GetUnderlyingType(target);
            if (targetCore.IsKnownType(KnownTypeCode.Boolean) || targetCore.GetDefinition()?.KnownTypeCode is not
                (KnownTypeCode.Int32 or KnownTypeCode.UInt32 or KnownTypeCode.Int64 or KnownTypeCode.UInt64 or KnownTypeCode.Byte or
                 KnownTypeCode.SByte or KnownTypeCode.Int16 or KnownTypeCode.UInt16))
                continue;
            Expression replacement;
            if (sourceNullable)
            {
                var sw = new SwitchExpression { Expression = cast.Expression.Clone() };
                sw.SwitchSections.Add(new SwitchExpressionSection { Pattern = new PrimitiveExpression(true), Body = new PrimitiveExpression(1) });
                sw.SwitchSections.Add(new SwitchExpressionSection { Pattern = new PrimitiveExpression(false), Body = new PrimitiveExpression(0) });
                sw.SwitchSections.Add(new SwitchExpressionSection { Pattern = new NullReferenceExpression(), Body = new NullReferenceExpression() });
                replacement = new CastExpression(cast.Type.Clone(), new ParenthesizedExpression(sw));
            }
            else
            {
                replacement = new CastExpression(cast.Type.Clone(), new ParenthesizedExpression(
                    new ConditionalExpression(cast.Expression.Clone(), new PrimitiveExpression(1), new PrimitiveExpression(0))));
            }
            cast.ReplaceWith(replacement);
        }
    }
}

/// <summary>
/// Fully qualifies type names that clash with a framework type in another imported namespace (CS0104). The engine
/// misses these because it does not see framework assemblies the code does not reference.
/// </summary>
internal sealed class FrameworkAmbiguousNames(IReadOnlyDictionary<string, HashSet<string>> frameworkTypes) : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        var imported = rootNode.DescendantsAndSelf.OfType<UsingDeclaration>().Select(u => u.Namespace).ToHashSet();
        if (imported.Count == 0) return;
        foreach (var simple in rootNode.Descendants.OfType<SimpleType>().ToList())
        {
            if (simple.Parent is MemberType or UsingDeclaration or UsingAliasDeclaration) continue;
            if (simple.GetSymbol() is not ITypeDefinition { DeclaringTypeDefinition: null } type) continue;
            if (simple.Identifier is not { Length: > 0 } identifier) continue;
            var key = simple.TypeArguments.Count > 0 ? $"{identifier}`{simple.TypeArguments.Count}" : identifier;
            // Enclosing namespaces take precedence over using directives.
            var enclosing = simple.Ancestors.OfType<NamespaceDeclaration>().Select(n => n.FullName).ToList();
            if (enclosing.Any(n => n == type.Namespace || n.StartsWith(type.Namespace + ".", StringComparison.Ordinal))) continue;
            bool clash = imported.Any(ns => ns != type.Namespace && frameworkTypes.TryGetValue(ns, out var names) && names.Contains(key));
            if (!clash) continue;
            AstType qualified = new SimpleType("global");
            bool first = true;
            foreach (var part in type.Namespace.Split('.', StringSplitOptions.RemoveEmptyEntries))
            {
                qualified = new MemberType(qualified, part) { IsDoubleColon = first };
                first = false;
            }
            var full = new MemberType(qualified, identifier) { IsDoubleColon = first };
            foreach (var argument in simple.TypeArguments)
                full.TypeArguments.Add(argument.Clone());
            full.CopyAnnotationsFrom(simple);
            simple.ReplaceWith(full);
        }
    }
}

/// <summary>
/// Removes source-generator trigger attributes (<c>[GeneratedRegex]</c>, <c>[LibraryImport]</c>, ...). The generated
/// code is already decompiled; on rebuild the generator would require partial declarations (SYSLIB1043) or duplicate it.
/// </summary>
internal sealed class SourceGeneratorTriggers : IAstTransform
{
    private static readonly HashSet<string> Triggers =
    [
        "System.Text.RegularExpressions.GeneratedRegexAttribute",
        "System.Runtime.InteropServices.LibraryImportAttribute",
        "System.Runtime.InteropServices.Marshalling.GeneratedComInterfaceAttribute",
        "System.Runtime.InteropServices.Marshalling.GeneratedComClassAttribute",
        "System.Runtime.InteropServices.Marshalling.CustomMarshallerAttribute",
        "System.Runtime.InteropServices.Marshalling.NativeMarshallingAttribute",
        "System.Runtime.InteropServices.Marshalling.MarshalUsingAttribute",
        "Microsoft.Extensions.Logging.LoggerMessageAttribute",
        "System.Text.Json.Serialization.JsonSerializableAttribute",
        "System.Text.Json.Serialization.JsonSourceGenerationOptionsAttribute",
        "Microsoft.Extensions.Options.OptionsValidatorAttribute",
        "Microsoft.Extensions.Configuration.Binder.SourceGeneration.InterceptsLocationAttribute",
        "System.Runtime.CompilerServices.InterceptsLocationAttribute",
    ];

    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var attribute in rootNode.Descendants.OfType<ICSharpCode.Decompiler.CSharp.Syntax.Attribute>().ToList())
        {
            if (attribute.Type.GetSymbol() is not ITypeDefinition type || !Triggers.Contains(type.FullName)) continue;
            var section = attribute.Parent as AttributeSection;
            attribute.Remove();
            if (section is { Attributes.Count: 0 }) section.Remove();
        }
    }
}

/// <summary>
/// Initializes uninitialized ref locals with <c>ref Unsafe.NullRef&lt;T&gt;()</c> (CS8174; .NET 5+). The IL always
/// assigns them before reading.
/// </summary>
internal sealed class UninitializedRefLocals : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var declaration in rootNode.Descendants.OfType<VariableDeclarationStatement>().ToList())
        {
            if (declaration.Type is not ComposedType { HasRefSpecifier: true } refType) continue;
            foreach (var variable in declaration.Variables)
            {
                if (variable.Initializer is not null) continue;
                var element = refType.Clone();
                if (element is ComposedType composed) { composed.HasRefSpecifier = false; composed.HasReadOnlySpecifier = false; }
                AstType target = element is ComposedType { PointerRank: 0, ArraySpecifiers.Count: 0, HasNullableSpecifier: false } bare ? bare.BaseType.Clone() : element;
                var unsafeType = new MemberType(new MemberType(new MemberType(new MemberType(new SimpleType("global"), "System") { IsDoubleColon = true },
                    "Runtime"), "CompilerServices"), "Unsafe");
                var call = new InvocationExpression(new MemberReferenceExpression(new TypeReferenceExpression(unsafeType), "NullRef", target));
                variable.Initializer = new DirectionExpression(FieldDirection.Ref, call);
            }
        }
    }
}

/// <summary>
/// Restores <c>scoped</c> on span locals assigned stack memory (CS8352); local <c>scoped</c> is not in metadata.
/// Only applied to locals that never escape the method.
/// </summary>
internal sealed class ScopedSpanLocals : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var body in rootNode.DescendantsAndSelf.OfType<BlockStatement>().Where(b => !b.Ancestors.OfType<BlockStatement>().Any()).ToList())
        {
            // A `scoped` local in an inner block cannot flow into a parameter (CS8352): hoist it to the method block.
            var parameters = body.Parent?.Children.OfType<ParameterDeclaration>().Select(p => p.Name).ToHashSet() ?? [];
            foreach (var declaration in body.Descendants.OfType<VariableDeclarationStatement>().Where(d =>
                         (d.Modifiers & Modifiers.Scoped) != 0 && d.Variables.Count == 1 && d.Variables.Single().Initializer is null
                         && d.Parent != body).ToList())
            {
                var name = declaration.Variables.Single().Name;
                if (!body.Descendants.OfType<AssignmentExpression>().Any(x =>
                        x.Left is IdentifierExpression { Identifier: var target } && parameters.Contains(target)
                        && x.Right.DescendantsAndSelf.OfType<IdentifierExpression>().Any(i => i.Identifier == name)))
                    continue;
                var anchor = declaration.Ancestors.OfType<Statement>().LastOrDefault(a => a.Parent == body);
                if (anchor == null || declaration.Parent is not BlockStatement block) continue;
                var others = body.Descendants.OfType<VariableDeclarationStatement>().Where(d => d != declaration && d.Variables.Any(v => v.Name == name));
                if (others.Any())
                {
                    var taken = body.Descendants.OfType<Identifier>().Select(i => i.Name).ToHashSet();
                    var fresh = Enumerable.Range(2, 100).Select(n => name + n).First(n => !taken.Contains(n));
                    foreach (var use in block.Descendants.OfType<IdentifierExpression>().Where(i => i.Identifier == name).ToList())
                        use.Identifier = fresh;
                    declaration.Variables.Single().Name = fresh;
                }
                declaration.Remove();
                body.Statements.InsertBefore(anchor, declaration);
            }

            var locals = body.Descendants.OfType<VariableDeclarationStatement>()
                .Where(d => d.Variables.Count == 1 && (d.Modifiers & Modifiers.Scoped) == 0 && d.Type is not ComposedType { HasRefSpecifier: true } && IsSpan(d.Variables.Single()))
                // Names declared more than once are distinct variables; skip them.
                .GroupBy(d => d.Variables.Single().Name).Where(g => g.Count() == 1)
                .ToDictionary(g => g.Key, g => g.Single());
            if (locals.Count == 0) continue;
            // Locals holding stack memory: stackalloc results and already-scoped locals.
            var stack = body.Descendants.OfType<VariableDeclarationStatement>()
                .Where(d => (d.Modifiers & Modifiers.Scoped) != 0 || d.Variables.Any(v => v.Initializer?.DescendantsAndSelf.OfType<StackAllocExpression>().Any() == true))
                .SelectMany(d => d.Variables.Select(v => v.Name)).ToHashSet();
            foreach (var a in body.Descendants.OfType<AssignmentExpression>())
                if (a.Left is IdentifierExpression { Identifier: var n } && a.Right.DescendantsAndSelf.OfType<StackAllocExpression>().Any())
                    stack.Add(n);

            bool changed = true;
            while (changed)
            {
                changed = false;
                foreach (var a in body.Descendants.OfType<AssignmentExpression>())
                {
                    if (a.Left is not IdentifierExpression { Identifier: { } name } || !locals.TryGetValue(name, out var declaration)) continue;
                    if (stack.Contains(name)) continue;
                    if (!a.Right.DescendantsAndSelf.OfType<IdentifierExpression>().Any(i => stack.Contains(i.Identifier))) continue;
                    if (Escapes(body, name)) continue;
                    declaration.Modifiers |= Modifiers.Scoped;
                    stack.Add(name);
                    changed = true;
                }
            }
        }
    }

    private static bool IsSpan(VariableInitializer v) =>
        v.GetResolveResult()?.Type is { Kind: not TypeKind.Unknown } t && t.FullName is "System.Span" or "System.ReadOnlySpan"
        || v.Parent is VariableDeclarationStatement { Type: SimpleType { Identifier: "Span" or "ReadOnlySpan" } };

    /// <summary>True if returned, captured, passed by ref/out, or stored anywhere but a local.</summary>
    private static bool Escapes(BlockStatement body, string name)
    {
        foreach (var use in body.Descendants.OfType<IdentifierExpression>().Where(i => i.Identifier == name))
        {
            if (use.Ancestors.Any(a => a is ReturnStatement or YieldReturnStatement or LambdaExpression or AnonymousMethodExpression)) return true;
            if (use.Parent is DirectionExpression) return true;
            if (use.Ancestors.OfType<AssignmentExpression>().FirstOrDefault() is { } assignment
                && assignment.Right.DescendantsAndSelf.Contains(use)
                && assignment.Left is not IdentifierExpression) return true;
        }
        return false;
    }
}

/// <summary>
/// Drops named-argument markers on operator operands: <c>a == second: false</c> → <c>a == false</c> (CS1003).
/// </summary>
internal sealed class OperatorNamedArguments : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var named in rootNode.Descendants.OfType<NamedArgumentExpression>().ToList())
            if (named.Parent is BinaryOperatorExpression or UnaryOperatorExpression)
                named.ReplaceWith(named.Expression.Clone());
    }
}

/// <summary>
/// Renames uses of a transformed setter/adder/remover value parameter back to <c>value</c> (CS0103).
/// </summary>
internal sealed class AccessorValueParameters : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var accessor in rootNode.Descendants.OfType<Accessor>().ToList())
        {
            if (accessor.Body is not { } body || accessor.GetSymbol() is not IMethod { AccessorKind: System.Reflection.MethodSemanticsAttributes.Setter
                    or System.Reflection.MethodSemanticsAttributes.Adder or System.Reflection.MethodSemanticsAttributes.Remover } method
                || method.Parameters.Count == 0) continue;
            // Indexer setters take the index parameters first; value is last.
            int valueIndex = method.Parameters.Count - 1;
            foreach (var use in body.Descendants.OfType<IdentifierExpression>().ToList())
            {
                if (use.Identifier == "value") continue;
                // Match the accessor's own parameter, not a nested lambda's.
                bool isValue = use.GetILVariable() is { Kind: ICSharpCode.Decompiler.IL.VariableKind.Parameter } v
                    ? v.Index == valueIndex && Equals(v.Function?.Method, method)
                    : use.GetSymbol() is IParameter p && Equals(p.Owner, method) && p.Name == method.Parameters[valueIndex].Name;
                if (isValue) use.Identifier = "value";
            }
        }
    }
}

/// <summary>
/// Makes named arguments with unspeakable (transformed) names, e.g. <c>_0020:</c>, positional when already in
/// position (CS1739).
/// </summary>
internal sealed class PositionalNamedArguments : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var named in rootNode.Descendants.OfType<NamedArgumentExpression>().ToList())
        {
            if (IsPlainIdentifier(named.Name)) continue;
            if (named.Parent is not { } call) continue;
            var arguments = call switch
            {
                InvocationExpression i => i.Arguments.ToList(),
                ObjectCreateExpression o => o.Arguments.ToList(),
                ConstructorInitializer c => c.Arguments.ToList(),
                _ => null,
            };
            if (arguments == null || call.GetSymbol() is not IParameterizedMember member) continue;
            int position = arguments.IndexOf(named);
            // Valid only if all preceding arguments are positional.
            if (position < 0 || position >= member.Parameters.Count || arguments.Take(position).Any(a => a is NamedArgumentExpression)) continue;
            named.ReplaceWith(named.Expression.Clone());
        }
    }

    /// <summary>Letters, digits and underscores only, with no escaped character such as <c>_0020</c>.</summary>
    private static bool IsPlainIdentifier(string? name) =>
        !string.IsNullOrEmpty(name) && (char.IsLetter(name[0]) || name[0] == '_') && name.All(c => char.IsLetterOrDigit(c) || c == '_')
        && !System.Text.RegularExpressions.Regex.IsMatch(name, "_[0-9A-F]{4}");
}

/// <summary>
/// Adds the missing <c>new()</c> constraint to a type parameter used in <c>new T()</c> (CS0304). The IL calls
/// <c>Activator.CreateInstance&lt;T&gt;()</c>, which requires the constructor anyway.
/// </summary>
internal sealed class UnconstrainedNew : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var create in rootNode.Descendants.OfType<ObjectCreateExpression>().ToList())
        {
            if (create.Arguments.Count > 0) continue;
            if (create.GetResolveResult()?.Type is not ITypeParameter { HasDefaultConstructorConstraint: false, HasValueTypeConstraint: false } parameter) continue;
            var owner = create.Ancestors.OfType<EntityDeclaration>()
                .FirstOrDefault(d => d is MethodDeclaration or TypeDeclaration && d.GetSymbol() is { } symbol && Equals(symbol, parameter.Owner));
            var constraints = owner switch
            {
                MethodDeclaration m => m.Constraints,
                TypeDeclaration t => t.Constraints,
                _ => null,
            };
            if (constraints == null) continue;
            var constraint = constraints.FirstOrDefault(c => c.TypeParameter is SimpleType { Identifier: var n } && n == parameter.Name);
            if (constraint == null)
            {
                constraint = new Constraint { TypeParameter = new SimpleType(parameter.Name) };
                constraints.Add(constraint);
            }
            if (!constraint.BaseTypes.Any(b => b is PrimitiveType { Keyword: "new" }))
                constraint.BaseTypes.Add(new PrimitiveType("new"));
        }
    }
}

/// <summary>
/// Adds a <c>Main</c> that forwards to a renamed entry point (CS5001), copying <c>[STAThread]</c>/<c>[MTAThread]</c>.
/// </summary>
internal sealed class RenamedEntryPoint : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        if (context.TypeSystem.MainModule.MetadataFile is not ICSharpCode.Decompiler.Metadata.PEFile pe) return;
        int token = pe.Reader.PEHeaders.CorHeader?.EntryPointTokenOrRelativeVirtualAddress ?? 0;
        if (token == 0 || (pe.Reader.PEHeaders.CorHeader!.Flags & System.Reflection.PortableExecutable.CorFlags.NativeEntryPoint) != 0) return;
        foreach (var method in rootNode.Descendants.OfType<MethodDeclaration>().ToList())
        {
            if (method.GetSymbol() is not IMethod symbol || symbol.Name == "Main"
                || System.Reflection.Metadata.Ecma335.MetadataTokens.GetToken(symbol.MetadataToken) != token) continue;
            if (method.Parent is not TypeDeclaration type || type.Members.Any(m => m.Name == "Main")) continue;
            var call = new InvocationExpression(new IdentifierExpression(method.Name ?? symbol.Name),
                method.Parameters.Select(p => (Expression)new IdentifierExpression(p.Name ?? "")));
            var main = new MethodDeclaration
            {
                Name = "Main",
                Modifiers = Modifiers.Static,
                ReturnType = method.ReturnType.Clone(),
                Body = new BlockStatement
                {
                    symbol.ReturnType.IsKnownType(KnownTypeCode.Void) ? new ExpressionStatement(call) : new ReturnStatement(call),
                },
            };
            foreach (var parameter in method.Parameters)
                main.Parameters.Add((ParameterDeclaration)parameter.Clone());
            foreach (var section in method.Attributes)
                if (section.Attributes.Any(a => a.Type.GetSymbol() is ITypeDefinition { FullName: "System.STAThreadAttribute" or "System.MTAThreadAttribute" }))
                    main.Attributes.Add((AttributeSection)section.Clone());
            type.Members.InsertAfter(method, main);
            return;
        }
    }
}

/// <summary>
/// Static extension calls on a null-conditional chain (CS0019): <c>Enumerable.Contains(x?.F(), d)</c> →
/// <c>x?.F().Contains(d)</c>, restoring short-circuiting.
/// </summary>
internal sealed class NullConditionalExtensionCalls : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var call in rootNode.Descendants.OfType<InvocationExpression>().ToList())
        {
            if (call.Target is not MemberReferenceExpression { Target: TypeReferenceExpression } target) continue;
            if (call.GetSymbol() is not IMethod { IsExtensionMethod: true } || call.Arguments.Count == 0) continue;
            var first = call.Arguments.First();
            if (first is UnaryOperatorExpression { Operator: UnaryOperatorType.NullConditionalRewrap } rewrap) first = rewrap.Expression;
            if (!HasNullConditional(first)) continue;
            var rest = call.Arguments.Skip(1).Select(a => a.Clone()).ToList();
            var member = new MemberReferenceExpression(first.Clone(), target.MemberName, target.TypeArguments.Select(t => t.Clone()));
            call.ReplaceWith(new InvocationExpression(member, rest));
        }
    }

    /// <summary>True for a member-access chain containing a null-conditional step (<c>a?.B().C</c>).</summary>
    private static bool HasNullConditional(Expression e)
    {
        while (true)
        {
            switch (e)
            {
                case UnaryOperatorExpression { Operator: UnaryOperatorType.NullConditional }: return true;
                case InvocationExpression i: e = i.Target; break;
                case MemberReferenceExpression m: e = m.Target; break;
                case IndexerExpression x when x.Target is not null: e = x.Target; break;
                default: return false;
            }
        }
    }
}

/// <summary>
/// Drops defaults on generic-typed parameters of compiler-generated anonymous delegates (CS1750). IL call sites
/// pass every argument explicitly.
/// </summary>
internal sealed class GenericDelegateDefaults : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var declaration in rootNode.Descendants.OfType<DelegateDeclaration>())
        {
            var typeParameters = declaration.TypeParameters.Select(t => t.Name).ToHashSet();
            foreach (var parameter in declaration.Parameters)
                if (parameter.DefaultExpression is { } value && value is not (NullReferenceExpression or DefaultValueExpression)
                    && parameter.Type is SimpleType { TypeArguments.Count: 0, Identifier: { } name } && typeParameters.Contains(name))
                    parameter.DefaultExpression = null!;
        }
    }
}

/// <summary>
/// <c>&lt;PrivateImplementationDetails&gt;.ThrowSwitchExpressionException(v)</c> → <c>throw new SwitchExpressionException(v)</c> (CS0103).
/// </summary>
internal sealed class SwitchExpressionHelpers : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var statement in rootNode.Descendants.OfType<ExpressionStatement>().ToList())
        {
            if (statement.Expression is not InvocationExpression { Target: MemberReferenceExpression { MemberName: var name } } call
                || name is not ("ThrowSwitchExpressionException" or "ThrowSwitchExpressionExceptionNoValue" or "ThrowInvalidOperationException")
                || call.GetSymbol() is not IMethod { DeclaringType.Name: "<PrivateImplementationDetails>" })
                continue;
            var exception = name == "ThrowInvalidOperationException"
                ? new MemberType(new MemberType(new SimpleType("global"), "System") { IsDoubleColon = true }, "InvalidOperationException")
                : new MemberType(new MemberType(new MemberType(new MemberType(new SimpleType("global"), "System") { IsDoubleColon = true },
                    "Runtime"), "CompilerServices"), "SwitchExpressionException");
            statement.ReplaceWith(new ThrowStatement(new ObjectCreateExpression(exception, call.Arguments.Select(a => a.Clone()))));
        }
    }
}

/// <summary>
/// Recovers local functions the engine references but never declares (compiled into a closure class shared with
/// lambdas). The method is decompiled separately, closure field accesses become captured variables, and the
/// declaration is placed in the innermost block containing all uses.
/// </summary>
internal sealed class MissingLocalFunctions : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        // Member bodies only; local function bodies are covered by their containing member.
        foreach (var body in rootNode.DescendantsAndSelf.OfType<BlockStatement>()
                     .Where(b => b.Parent is EntityDeclaration or Accessor && !b.Ancestors.Any(a => a is LocalFunctionDeclarationStatement)).ToList())
        {
            var declared = body.Descendants.OfType<LocalFunctionDeclarationStatement>().Select(d => d.Declaration.Name).ToHashSet();
            var uses = body.Descendants.OfType<IdentifierExpression>()
                .Where(i => !declared.Contains(i.Identifier) && LocalFunction(i) != null)
                .GroupBy(i => i.Identifier).ToList();
            foreach (var group in uses)
            {
                var method = LocalFunction(group.First())!;
                if (Recover(method, group.Key, context) is not { } declaration) continue;
                var block = CommonBlock(group.ToList()) ?? body;
                var last = block.Statements.LastOrDefault();
                if (last is BreakStatement or ReturnStatement or ContinueStatement or GotoStatement or ThrowStatement)
                    block.Statements.InsertBefore(last, declaration);
                else
                    block.Statements.Add(declaration);
            }
        }
    }

    /// <summary>The local function an identifier refers to, as a call target or a method group.</summary>
    private static IMethod? LocalFunction(IdentifierExpression i) =>
        (i.GetSymbol() ?? (i.Parent is InvocationExpression call && call.Target == i ? call.GetSymbol() : null)
            ?? (i.GetResolveResult() as ICSharpCode.Decompiler.Semantics.MethodGroupResolveResult)?.Methods.FirstOrDefault()) is IMethod { IsLocalFunction: true } m
            ? m : null;

    private static LocalFunctionDeclarationStatement? Recover(IMethod method, string name, TransformContext context)
    {
        if (method.MetadataToken.IsNil || method.MetadataToken.Kind != System.Reflection.Metadata.HandleKind.MethodDefinition) return null;
        var decompiler = new CSharpDecompiler(context.TypeSystem, context.Settings) { CancellationToken = context.CancellationToken, DocumentationProvider = DecompilerService.NoDocumentation.Instance };
        var tree = decompiler.Decompile(method.MetadataToken);
        if (tree.Descendants.OfType<MethodDeclaration>().FirstOrDefault() is not { Body: { } compiledBody } compiled) return null;

        // Closure struct parameters (passed by ref) are compiler-added.
        var closureParameters = compiled.Parameters
            .Where(p => p.Type is { } pt && pt.GetResolveResult()?.Type is { } t && IsClosure(t) || p.Type is ComposedType { BaseType: { } b } && b.GetResolveResult()?.Type is { } bt && IsClosure(bt))
            .Select(p => p.Name).ToHashSet();
        var bodyCopy = (BlockStatement)compiledBody.Clone();

        // Closure fields (`this.x`, `x`, `P_1.x`): `<>4__this` → `this`, outer-closure hops are dropped, others → captured local.
        bool ClosureField(AstNode n, out IField field)
        {
            field = (n.GetSymbol() as IField)!;
            return field != null && field.DeclaringType != null && IsClosure(field.DeclaringType);
        }
        string Captured(IField field) => field.Name.StartsWith('<') ? field.Name.Trim('<', '>') : field.Name;
        bool IsThisCopy(IField field) => field.Name.EndsWith("4__this", StringComparison.Ordinal);
        foreach (var node in bodyCopy.Descendants.Where(n => n is MemberReferenceExpression or IdentifierExpression).ToList())
        {
            if (node.Parent == null || !ClosureField(node, out var field)) continue;
            if (node is MemberReferenceExpression member && !(member.Target is ThisReferenceExpression
                    || member.Target is IdentifierExpression { Identifier: var t } && closureParameters.Contains(t)
                    || member.Target.GetSymbol() is IField outer && outer.DeclaringType != null && IsClosure(outer.DeclaringType) && IsClosure(outer.Type)))
                continue;
            if (IsClosure(field.Type)) continue; // outer-closure hop: handled below
            node.ReplaceWith(IsThisCopy(field) ? new ThisReferenceExpression() : new IdentifierExpression(Captured(field)));
        }
        // Remaining outer-closure hops: `CS$<>8__locals1.x` → `x`.
        foreach (var member in bodyCopy.Descendants.OfType<MemberReferenceExpression>().ToList())
            if (member.Parent != null && member.Target.GetSymbol() is IField hop && hop.DeclaringType != null && IsClosure(hop.DeclaringType) && IsClosure(hop.Type))
                member.ReplaceWith(member.GetSymbol() is IField f && IsThisCopy(f) ? new ThisReferenceExpression() : new IdentifierExpression(member.MemberName));

        // `<Outer>g__Name|1_0(..., ref P_2)` → `Name(...)`, without the closure argument.
        foreach (var call in bodyCopy.Descendants.OfType<InvocationExpression>().ToList())
        {
            if (call.GetSymbol() is not IMethod callee || LocalName(callee.Name) is not { } calleeName) continue;
            var arguments = call.Arguments.Where(a => !(a is DirectionExpression { Expression: var e } && e.GetResolveResult()?.Type is { } at && IsClosure(at)
                                                        || a.GetResolveResult()?.Type is { } t && IsClosure(t)))
                .Select(a => a.Clone()).ToList();
            call.ReplaceWith(new InvocationExpression(new IdentifierExpression(calleeName), arguments));
        }

        // Fully qualify types: the target file may not import their namespaces.
        var builder = new ICSharpCode.Decompiler.CSharp.Syntax.TypeSystemAstBuilder();
        foreach (var type in bodyCopy.Descendants.OfType<AstType>().Where(t => t.Parent is not AstType).ToList())
            if (type.GetResolveResult() is ICSharpCode.Decompiler.Semantics.TypeResolveResult { Type: { Kind: not TypeKind.Unknown } resolved } && resolved.Kind != TypeKind.TypeParameter)
                type.ReplaceWith(builder.ConvertType(resolved));
        foreach (var reference in bodyCopy.Descendants.OfType<TypeReferenceExpression>().ToList())
            if (reference.GetResolveResult() is ICSharpCode.Decompiler.Semantics.TypeResolveResult { Type: { Kind: not TypeKind.Unknown } resolved } && resolved.Kind != TypeKind.TypeParameter)
                reference.Type = builder.ConvertType(resolved);

        var function = new MethodDeclaration
        {
            Name = name,
            ReturnType = compiled.ReturnType.Clone(),
            Modifiers = compiled.Modifiers & (Modifiers.Async | Modifiers.Unsafe),
            Body = bodyCopy,
        };
        foreach (var tp in compiled.TypeParameters) function.TypeParameters.Add((TypeParameterDeclaration)tp.Clone());
        foreach (var p in compiled.Parameters)
            if (!closureParameters.Contains(p.Name)) function.Parameters.Add((ParameterDeclaration)p.Clone());
        return new LocalFunctionDeclarationStatement(function);
    }

    /// <summary>Extracts <c>Name</c> from <c>&lt;Outer&gt;g__Name|1_0</c>; null for other methods.</summary>
    private static string? LocalName(string compiled)
    {
        int g = compiled.IndexOf(">g__", StringComparison.Ordinal);
        if (!compiled.StartsWith('<') || g < 0) return null;
        int bar = compiled.IndexOf('|', g);
        return bar > g + 4 ? compiled[(g + 4)..bar] : null;
    }

    private static bool IsClosure(IType type) =>
        type.Name.Contains("DisplayClass", StringComparison.Ordinal) && type.GetDefinition()?.HasAttribute(KnownAttribute.CompilerGenerated) != false;

    /// <summary>The innermost block containing every use.</summary>
    private static BlockStatement? CommonBlock(List<IdentifierExpression> uses)
    {
        var chains = uses.Select(u => u.Ancestors.OfType<BlockStatement>().Reverse().ToList()).ToList();
        BlockStatement? common = null;
        for (int depth = 0; chains.All(c => c.Count > depth) && chains.All(c => c[depth] == chains[0][depth]); depth++)
            common = chains[0][depth];
        // Move out of a lambda that does not contain every use.
        while (common != null && common.Ancestors.Any(a => a is LambdaExpression or AnonymousMethodExpression)
               && uses.Any(u => !u.Ancestors.Contains(common)))
            common = common.Ancestors.OfType<BlockStatement>().FirstOrDefault();
        return common;
    }
}

/// <summary>
/// Renames a lambda parameter named <c>_</c> when its body contains discards: <c>_ = ...</c> would otherwise assign
/// the parameter (CS0029 or a silent change in meaning).
/// </summary>
internal sealed class DiscardParameters : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var function in rootNode.Descendants.Where(n => n is LambdaExpression or AnonymousMethodExpression).ToList())
        {
            var parameters = function is LambdaExpression l ? l.Parameters : ((AnonymousMethodExpression)function).Parameters;
            if (parameters.FirstOrDefault(p => p.Name == "_") is not { } parameter) continue;
            var body = function is LambdaExpression lambda ? lambda.Body : ((AnonymousMethodExpression)function).Body;
            // Discards in this function's own body, excluding nested lambdas.
            bool discards = body.DescendantsAndSelf.OfType<AssignmentExpression>().Any(a =>
                a.Left is IdentifierExpression { Identifier: "_" } && a.Left.GetSymbol() is not IParameter
                && a.Ancestors.TakeWhile(x => x != function).All(x => x is not (LambdaExpression or AnonymousMethodExpression)));
            if (!discards) continue;
            var taken = function.Descendants.OfType<Identifier>().Select(i => i.Name).ToHashSet();
            var fresh = Enumerable.Range(1, 100).Select(n => "_" + n).First(n => !taken.Contains(n));
            parameter.Name = fresh;
            foreach (var use in body.DescendantsAndSelf.OfType<IdentifierExpression>().Where(i => i.Identifier == "_" && i.GetSymbol() is IParameter).ToList())
                use.Identifier = fresh;
        }
    }
}

/// <summary>
/// Returning a ref obtained through a local passed by <c>in</c>/<c>ref</c> (CS8157): <c>return ref r;</c> →
/// <c>return ref Unsafe.AsRef(in r);</c>. Requires .NET 8+, where the parameter is scoped; the reference is unchanged.
/// </summary>
internal sealed class ReturnRefThroughLocalCopy : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var ret in rootNode.Descendants.OfType<ReturnStatement>().ToList())
        {
            if (ret.Expression is not DirectionExpression { FieldDirection: FieldDirection.Ref, Expression: IdentifierExpression { Identifier: var name } }) continue;
            var body = ret.Ancestors.OfType<BlockStatement>().LastOrDefault(b => b.Parent is EntityDeclaration);
            if (body == null) continue;
            var declaration = body.Descendants.OfType<VariableDeclarationStatement>()
                .FirstOrDefault(d => d.Type is ComposedType { HasRefSpecifier: true } && d.Variables.Any(v => v.Name == name));
            if (declaration?.Variables.First(v => v.Name == name).Initializer is not DirectionExpression { Expression: InvocationExpression call }) continue;
            if (!PassesLocalCopy(call, body)) continue;
            var unsafeType = new MemberType(new MemberType(new MemberType(new MemberType(new SimpleType("global"), "System") { IsDoubleColon = true },
                "Runtime"), "CompilerServices"), "Unsafe");
            var asRef = new InvocationExpression(new MemberReferenceExpression(new TypeReferenceExpression(unsafeType), "AsRef"),
                new DirectionExpression(FieldDirection.In, new IdentifierExpression(name)));
            ret.Expression = new DirectionExpression(FieldDirection.Ref, asRef);
        }
    }

    /// <summary>True if the call takes a by-value local by reference (an in/ref argument or a <c>this in</c> receiver).</summary>
    private static bool PassesLocalCopy(InvocationExpression call, BlockStatement body)
    {
        var locals = body.Descendants.OfType<VariableDeclarationStatement>().Where(d => d.Type is not ComposedType { HasRefSpecifier: true })
            .SelectMany(d => d.Variables.Select(v => v.Name))
            .Concat(body.Descendants.OfType<ForeachStatement>().Where(f => f.VariableType is not ComposedType { HasRefSpecifier: true })
                .Select(f => f.VariableDesignation is SingleVariableDesignation sv ? sv.Identifier : null).OfType<string>())
            .ToHashSet();
        bool IsLocal(Expression e) => e is IdentifierExpression { Identifier: var n } && locals.Contains(n);
        if (call.Arguments.Any(a => a is DirectionExpression { FieldDirection: FieldDirection.In or FieldDirection.Ref, Expression: var x } && IsLocal(x)))
            return true;
        return call.Target is MemberReferenceExpression { Target: var receiver } && IsLocal(receiver)
               && call.GetSymbol() is IMethod m && (m.ReducedFrom ?? m) is { IsExtensionMethod: true, Parameters: [{ ReferenceKind: ReferenceKind.In or ReferenceKind.Ref or ReferenceKind.RefReadOnly }, ..] };
    }
}
