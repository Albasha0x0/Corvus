using System.Reflection.Metadata;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.Syntax;
using ICSharpCode.Decompiler.CSharp.Transforms;
using ICSharpCode.Decompiler.TypeSystem;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Rewrites engine output that does not compile back into what the compiler accepts. Runs after the engine's own
/// transforms, on decompiled members and exported projects alike.
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

    /// <summary>How many times a cleanup failed and the engine output was kept (tests check it stays 0).</summary>
    internal static int Failures;

    /// <summary>The last cleanup failure (tests and diagnostics).</summary>
    internal static string? LastError;

    /// <summary>A cleanup that fails leaves the engine's output as it is, instead of failing the whole member.</summary>
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
/// Span slicing (<c>x[a..]</c>) compiles to a <c>ref</c> temporary that the engine shows as one ref local reassigned
/// before every use (<c>ref Span&lt;T&gt; reference; ... reference = ref x; reference.Slice(...)</c>). That does not
/// compile: a ref local needs an initializer, and a stackalloc span cannot escape into it (CS8174, CS8352, CS8374,
/// CS9096). The alias is replaced by the variable it points to wherever that is certain.
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

    /// <summary>All ref locals of one name in a body (the engine reuses a name across branches) are handled together.</summary>
    private static void Inline(BlockStatement body, string name, List<VariableDeclarationStatement> declarations)
    {
        bool IsName(AstNode n) => n is IdentifierExpression { Identifier: var id, TypeArguments.Count: 0 } && id == name;
        bool IsRefAssignment(AstNode n) => n is AssignmentExpression { Operator: AssignmentOperatorType.Assign, Right: DirectionExpression { FieldDirection: FieldDirection.Ref } } a && IsName(a.Left);

        // the points where the alias is (re)bound: the declaration's initializer and `name = ref E;` statements
        var bindings = new List<(Statement Statement, Expression Target)>();
        foreach (var declaration in declarations)
            if (declaration.Variables.Single().Initializer is DirectionExpression { FieldDirection: FieldDirection.Ref } init)
                bindings.Add((declaration, init.Expression));
        foreach (var s in body.Descendants.OfType<ExpressionStatement>())
            if (IsRefAssignment(s.Expression))
                bindings.Add((s, ((DirectionExpression)((AssignmentExpression)s.Expression).Right).Expression));
        if (bindings.Count == 0) return;
        // innermost first: a loop body's own bindings take its uses before an enclosing binding looks past the loop
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
                    // rebound inside this statement (a loop body): a use here may see either binding
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

        // gone entirely: drop the bindings and the declaration that no longer compile
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

    /// <summary>A local, parameter or field of this / a type: its storage location cannot change between uses.</summary>
    private static bool IsFixedLocation(Expression e) => e switch
    {
        IdentifierExpression { TypeArguments.Count: 0 } => true,
        MemberReferenceExpression { Target: ThisReferenceExpression or TypeReferenceExpression, TypeArguments.Count: 0 } => true,
        _ => false,
    };
}

/// <summary>
/// <c>stackalloc T[n] { ... }</c> compiles to a block copy from compiler data the engine leaves as
/// <c>Unsafe.CopyBlockUnaligned(ptr, ref &lt;PrivateImplementationDetails&gt;.X, n)</c>, a name that cannot be written in C#
/// (CS0103). The copy is folded back into the initializer.
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
/// <c>(nuint)(-70)</c> and the like: a negative constant cast to an unsigned type is a compile error outside an
/// unchecked context (CS0221), though the IL just reinterprets the bits. Wrapped in <c>unchecked(...)</c>.
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
/// Attributes only the compiler may emit (CS8335), written out by the engine at assembly or module level:
/// <c>[assembly: NullablePublicOnly(false)]</c>, <c>[module: RefSafetyRules(11)]</c>. The compiler adds them again.
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
/// A constructor that assigns members before calling the base constructor (what a primary constructor or a
/// <c>required</c>-style initializer compiles to) comes out as <c>base._002Ector(type);</c> in the body, which is not
/// C# (CS0117, CS7036). The call becomes the constructor initializer <c>: base(type)</c>, so the plain assignments
/// before it now run after the base constructor: the same unless that constructor calls overridden members reading them.
/// </summary>
internal sealed class BaseConstructorCalls : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var ctor in rootNode.Descendants.OfType<ConstructorDeclaration>().ToList())
        {
            // a real initializer already there (an explicit base(...) or this(...)): the body call is something else
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
            // only plain assignments may come first: anything else could depend on running before the base call
            var before = ctor.Body.Statements.TakeWhile(s => s != call).ToList();
            if (before.Any(s => s is not ExpressionStatement { Expression: AssignmentExpression })) continue;

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
}

/// <summary>
/// A constructor parameter used in a field initializer: the engine moved <c>index = (int)(code - 4611)</c> out of
/// <c>MvexInfo(Code code)</c> into the field declaration, where <c>code</c> does not exist (CS0103). Moved back to
/// the start of the only constructor that has that parameter.
/// </summary>
internal sealed class ParameterFieldInitializers : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var type in rootNode.Descendants.OfType<TypeDeclaration>().ToList())
        {
            var ctors = type.Members.OfType<ConstructorDeclaration>().Where(c => !c.HasModifier(Modifiers.Static)).ToList();
            if (ctors.Count != 1 || ctors[0].Body is not { } body) continue;
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
/// The same local name declared in a block and again in an enclosing one (<c>byte[] properties</c> inside a
/// <c>using</c> block and after it): fine in IL, CS0136 in C#. The inner one is renamed.
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
                    // an enclosing scope (not this one) declares the same name: rename this one within its block
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
    /// The block a statement's names live in as printed: the body of a braceless <c>using var x = ...;</c> is a block of
    /// its own in the tree but shares the enclosing block's scope in the source.
    /// </summary>
    private static BlockStatement Scope(BlockStatement block)
    {
        while (block.Parent is UsingStatement { IsEnhanced: true } && block.Parent.Parent is BlockStatement enclosing)
            block = enclosing;
        return block;
    }
}

/// <summary>
/// <c>await using</c> / <c>foreach</c> over a struct enumerator that disposes by pattern (a DisposeAsync / Dispose
/// method, not the interface): the engine writes <c>IAsyncDisposable d = enumerator as IAsyncDisposable; if (d != null)
/// await d.DisposeAsync();</c>, which does not compile for a struct that does not implement it (CS0039). Written as the
/// direct call the compiler made.
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
/// An auto-property with a setter but no getter (the getter trimmed away, as in trimmed framework builds): not C#
/// (CS8051). Given back a getter of the same accessibility as the property.
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
/// A bool used as an integer (IL makes no difference): the engine writes <c>(int?)methodSig?.ImplicitThis</c>,
/// which C# rejects (CS0030). Written as <c>x switch { true => 1, false => 0, null => null }</c> (or <c>x ? 1 : 0</c>).
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
/// A type whose short name also exists in another namespace the file imports, in a framework assembly the code
/// does not reference itself (Newtonsoft's <c>ErrorEventArgs</c> and <c>System.IO.ErrorEventArgs</c>): the engine
/// does not see the clash, the build does (CS0104). Such names are fully qualified.
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
            // the type's own namespace and the namespaces enclosing the code win over using directives: no clash then
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
/// Attributes that make a source generator write code (<c>[GeneratedRegex]</c>, <c>[LibraryImport]</c>,
/// <c>[LoggerMessage]</c>, <c>[JsonSerializable]</c>...). The generated code is already in the decompiled output, so on a
/// rebuild the generator would demand partial declarations (SYSLIB1043) or emit everything a second time. Removed;
/// the members keep the bodies the generator gave them.
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
/// A ref local the IL assigns only inside a loop or a branch (<c>ref Entry reference; while (...) { reference = ref
/// entries[i]; ... }</c>) cannot be written without an initializer (CS8174). It starts as
/// <c>ref Unsafe.NullRef&lt;T&gt;()</c> (.NET 5+), never read before the IL's own assignment.
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
                // the referenced type: the declared type without `ref` / `ref readonly`
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
/// <c>scoped</c> on a local leaves nothing in metadata, so the engine drops it, and a span local that later takes a
/// stack-allocated span (<c>partial = stackBuffer.Slice(0, 3)</c>) no longer compiles (CS8352). Such locals get
/// <c>scoped</c> back when they never leave the method (not returned, not stored outside a local).
/// </summary>
internal sealed class ScopedSpanLocals : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var body in rootNode.DescendantsAndSelf.OfType<BlockStatement>().Where(b => !b.Ancestors.OfType<BlockStatement>().Any()).ToList())
        {
            // a `scoped` local declared in an inner block lives only as long as that block, so its value can no longer
            // go into a parameter of the method (CS8352): the declaration moves to the method's own block, as written
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
                // a name declared in several scopes is several variables: left as it is
                .GroupBy(d => d.Variables.Single().Name).Where(g => g.Count() == 1)
                .ToDictionary(g => g.Key, g => g.Single());
            if (locals.Count == 0) continue;
            // stack memory: stackalloc'd locals and scoped ones (the engine keeps `scoped` where metadata says so)
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

    /// <summary>Returned, or stored anywhere but a local (field, parameter, element, out / ref argument).</summary>
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
/// A user-defined operator call written as an operator but with the engine's named-argument marker kept on an
/// operand (<c>RunAsVirtualAccount == second: false</c>): a syntax error (CS1003). The marker is dropped.
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
/// An obfuscator renamed the implicit <c>value</c> parameter of a setter / adder / remover (<c>set { field = num; }</c>):
/// C# only knows it as <c>value</c> (CS0103). Uses of that parameter are renamed back.
/// </summary>
internal sealed class AccessorValueParameters : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var accessor in rootNode.Descendants.OfType<Accessor>().ToList())
        {
            // only accessors that take a value: setters, init, event add / remove (an indexer getter's parameters are its indexes)
            if (accessor.Body is not { } body || accessor.GetSymbol() is not IMethod { AccessorKind: System.Reflection.MethodSemanticsAttributes.Setter
                    or System.Reflection.MethodSemanticsAttributes.Adder or System.Reflection.MethodSemanticsAttributes.Remover } method
                || method.Parameters.Count == 0) continue;
            // indexer setters: the index parameters come first, the value is the last one
            int valueIndex = method.Parameters.Count - 1;
            foreach (var use in body.Descendants.OfType<IdentifierExpression>().ToList())
            {
                if (use.Identifier == "value") continue;
                // the accessor's own parameter, not a lambda's inside it (which has its own index 0)
                bool isValue = use.GetILVariable() is { Kind: ICSharpCode.Decompiler.IL.VariableKind.Parameter } v
                    ? v.Index == valueIndex && Equals(v.Function?.Method, method)
                    : use.GetSymbol() is IParameter p && Equals(p.Owner, method) && p.Name == method.Parameters[valueIndex].Name;
                if (isValue) use.Identifier = "value";
            }
        }
    }
}

/// <summary>
/// Named arguments whose names an obfuscator made unspeakable (a parameter named " " comes out as <c>_0020:</c>),
/// so the call does not bind (CS1739). A named argument already in its parameter's position becomes positional.
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
            // every argument before it positional, and it sits where its parameter is
            if (position < 0 || position >= member.Parameters.Count || arguments.Take(position).Any(a => a is NamedArgumentExpression)) continue;
            named.ReplaceWith(named.Expression.Clone());
        }
    }

    /// <summary>An identifier as a person writes it: letters, digits, underscore, no escaped character (_0020).</summary>
    private static bool IsPlainIdentifier(string? name) =>
        !string.IsNullOrEmpty(name) && (char.IsLetter(name[0]) || name[0] == '_') && name.All(c => char.IsLetterOrDigit(c) || c == '_')
        && !System.Text.RegularExpressions.Regex.IsMatch(name, "_[0-9A-F]{4}");
}

/// <summary>
/// <c>new T()</c> or <c>new T { ... }</c> for a type parameter without the <c>new()</c> constraint (an obfuscator
/// dropped it; the IL calls <c>Activator.CreateInstance&lt;T&gt;()</c>, which needs that constructor anyway): CS0304.
/// The constraint is put back on the type parameter's declaration.
/// </summary>
internal sealed class UnconstrainedNew : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        foreach (var create in rootNode.Descendants.OfType<ObjectCreateExpression>().ToList())
        {
            if (create.Arguments.Count > 0) continue;
            if (create.GetResolveResult()?.Type is not ITypeParameter { HasDefaultConstructorConstraint: false, HasValueTypeConstraint: false } parameter) continue;
            // the method or type that declares it, in this syntax tree
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
/// An executable whose entry point an obfuscator renamed (<c>C7.SY::Ory()</c>): the runtime starts whatever method the
/// header names, but C# needs a <c>Main</c> (CS5001). A <c>Main</c> calling it is added to its class, with its
/// <c>[STAThread]</c>.
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
/// An extension method called on a null-conditional chain, written as a static call
/// (<c>Enumerable.Contains(x?.GetInvocationList(), d)</c>): the call no longer short-circuits on null and its result
/// is not nullable, so <c>... ?? true</c> does not compile (CS0019). Written as the extension call inside the chain:
/// <c>x?.GetInvocationList().Contains(d)</c>.
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

    /// <summary>A member-access chain (a?.B().C) with a null-conditional step in it.</summary>
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
/// The delegate type the compiler makes for a lambda with default parameters (<c>&lt;&gt;f__AnonymousDelegate0&lt;T1,
/// TResult&gt;(T1 arg = true)</c>): the default belongs to the instantiation, and a generic parameter cannot have it
/// (CS1750). Calls in IL pass every argument, so the default is dropped.
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
/// A switch expression the engine could not rebuild leaves a call to the compiler's hidden helper
/// (<c>&lt;PrivateImplementationDetails&gt;.ThrowSwitchExpressionException(value)</c>), which C# cannot name (CS0103).
/// Written as what it does: <c>throw new SwitchExpressionException(value)</c>.
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
/// A local function the engine calls but does not declare: it is compiled as a method of the closure class (because
/// lambdas in the same method capture its variables), and the engine drops it, losing its code. Its method is
/// decompiled on its own, the closure's fields become the captured variables again, and it is declared as a local
/// function in the block that holds all its uses.
/// </summary>
internal sealed class MissingLocalFunctions : IAstTransform
{
    public void Run(AstNode rootNode, TransformContext context)
    {
        // member bodies only: a local function's own body is part of its member's (its declaration is a method node too)
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

    /// <summary>The local function an identifier names: called (the call has the symbol) or as a method group.</summary>
    private static IMethod? LocalFunction(IdentifierExpression i) =>
        (i.GetSymbol() ?? (i.Parent is InvocationExpression call && call.Target == i ? call.GetSymbol() : null)
            ?? (i.GetResolveResult() as ICSharpCode.Decompiler.Semantics.MethodGroupResolveResult)?.Methods.FirstOrDefault()) is IMethod { IsLocalFunction: true } m
            ? m : null;

    /// <summary>The local function's declaration, from its compiled method.</summary>
    private static LocalFunctionDeclarationStatement? Recover(IMethod method, string name, TransformContext context)
    {
        if (method.MetadataToken.IsNil || method.MetadataToken.Kind != System.Reflection.Metadata.HandleKind.MethodDefinition) return null;
        var decompiler = new CSharpDecompiler(context.TypeSystem, context.Settings) { CancellationToken = context.CancellationToken };
        var tree = decompiler.Decompile(method.MetadataToken);
        if (tree.Descendants.OfType<MethodDeclaration>().FirstOrDefault() is not { Body: { } compiledBody } compiled) return null;

        // parameters that carry the closure (a struct passed by ref) are not the local function's
        var closureParameters = compiled.Parameters
            .Where(p => p.Type is { } pt && pt.GetResolveResult()?.Type is { } t && IsClosure(t) || p.Type is ComposedType { BaseType: { } b } && b.GetResolveResult()?.Type is { } bt && IsClosure(bt))
            .Select(p => p.Name).ToHashSet();
        var bodyCopy = (BlockStatement)compiledBody.Clone();

        // closure fields: the closure's copy of the outer `this` is `this`; a field holding an outer closure is a hop
        // to drop; any other field is the captured variable of that name. Written `this.x`, `x` or `P_1.x`.
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
            if (IsClosure(field.Type)) continue; // an outer closure: its members are rewritten below, this hop goes with them
            node.ReplaceWith(IsThisCopy(field) ? new ThisReferenceExpression() : new IdentifierExpression(Captured(field)));
        }
        // what remains of hops to outer closures (`CS$<>8__locals1.x` became `CS$<>8__locals1` . x): x
        foreach (var member in bodyCopy.Descendants.OfType<MemberReferenceExpression>().ToList())
            if (member.Parent != null && member.Target.GetSymbol() is IField hop && hop.DeclaringType != null && IsClosure(hop.DeclaringType) && IsClosure(hop.Type))
                member.ReplaceWith(member.GetSymbol() is IField f && IsThisCopy(f) ? new ThisReferenceExpression() : new IdentifierExpression(member.MemberName));

        // calls to compiled local functions (itself when recursive, `<Outer>g__Name|1_0(..., ref P_2)`): by name, without the closure
        foreach (var call in bodyCopy.Descendants.OfType<InvocationExpression>().ToList())
        {
            if (call.GetSymbol() is not IMethod callee || LocalName(callee.Name) is not { } calleeName) continue;
            var arguments = call.Arguments.Where(a => !(a is DirectionExpression { Expression: var e } && e.GetResolveResult()?.Type is { } at && IsClosure(at)
                                                        || a.GetResolveResult()?.Type is { } t && IsClosure(t)))
                .Select(a => a.Clone()).ToList();
            call.ReplaceWith(new InvocationExpression(new IdentifierExpression(calleeName), arguments));
        }

        // types fully qualified: the file that receives the body may not import their namespaces
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

    /// <summary>The name of a compiled local function (<c>&lt;Outer&gt;g__Name|1_0</c>): Name; null for any other method.</summary>
    private static string? LocalName(string compiled)
    {
        int g = compiled.IndexOf(">g__", StringComparison.Ordinal);
        if (!compiled.StartsWith('<') || g < 0) return null;
        int bar = compiled.IndexOf('|', g);
        return bar > g + 4 ? compiled[(g + 4)..bar] : null;
    }

    private static bool IsClosure(IType type) =>
        type.Name.Contains("DisplayClass", StringComparison.Ordinal) && type.GetDefinition()?.HasAttribute(KnownAttribute.CompilerGenerated) != false;

    /// <summary>The innermost block that contains every use.</summary>
    private static BlockStatement? CommonBlock(List<IdentifierExpression> uses)
    {
        var chains = uses.Select(u => u.Ancestors.OfType<BlockStatement>().Reverse().ToList()).ToList();
        BlockStatement? common = null;
        for (int depth = 0; chains.All(c => c.Count > depth) && chains.All(c => c[depth] == chains[0][depth]); depth++)
            common = chains[0][depth];
        // not inside a lambda that only some uses are in
        while (common != null && common.Ancestors.Any(a => a is LambdaExpression or AnonymousMethodExpression)
               && uses.Any(u => !u.Ancestors.Contains(common)))
            common = common.Ancestors.OfType<BlockStatement>().FirstOrDefault();
        return common;
    }
}

/// <summary>
/// A lambda parameter named <c>_</c> (<c>(CustomButton _) => { _ = item.rewardData; }</c>): the engine writes discards
/// as <c>_ = ...</c>, which inside such a lambda assign the parameter instead (CS0029, or a silent change of meaning).
/// The parameter is renamed when the body also discards.
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
            // discards written in this function's own body (not in a nested lambda that has its own parameters)
            bool discards = body.DescendantsAndSelf.OfType<AssignmentExpression>().Any(a =>
                a.Left is IdentifierExpression { Identifier: "_" } && a.Left.GetSymbol() is not IParameter
                && a.Ancestors.TakeWhile(x => x != function).All(x => x is not (LambdaExpression or AnonymousMethodExpression)));
            if (!discards) continue;
            var taken = function.Descendants.OfType<Identifier>().Select(i => i.Name).ToHashSet();
            var fresh = Enumerable.Range(1, 100).Select(n => "_" + n).First(n => !taken.Contains(n));
            parameter.Name = fresh;
            // reads of the parameter (not discard targets) follow it
            foreach (var use in body.DescendantsAndSelf.OfType<IdentifierExpression>().Where(i => i.Identifier == "_" && i.GetSymbol() is IParameter).ToList())
                use.Identifier = fresh;
        }
    }
}

/// <summary>
/// <c>ref readonly T r = ref entity.TryGet&lt;T&gt;(out ok); return ref r;</c> where <c>entity</c> is a local copy passed
/// by <c>in</c> / <c>ref</c>: the IL returns that reference (an IL-level rewrite of the original code), C# refuses it
/// (CS8157). Written as <c>return ref Unsafe.AsRef(in r)</c> (.NET 8+, whose parameter is scoped): the same reference,
/// so the same behaviour as the compiled code.
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

    /// <summary>The call gets a by-value local of this method by reference (an `in` / `ref` argument, or the receiver of a `this in` extension).</summary>
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
