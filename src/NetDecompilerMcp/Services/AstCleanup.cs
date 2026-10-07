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
        if (Frameworks.PublicTypeNames(targetFramework) is { } frameworkTypes)
            decompiler.AstTransforms.Add(new Guarded(new FrameworkAmbiguousNames(frameworkTypes)));
    }

    /// <summary>How many times a cleanup failed and the engine output was kept (tests check it stays 0).</summary>
    internal static int Failures;

    /// <summary>A cleanup that fails leaves the engine's output as it is, instead of failing the whole member.</summary>
    private sealed class Guarded(IAstTransform inner) : IAstTransform
    {

        public void Run(AstNode rootNode, TransformContext context)
        {
            try { inner.Run(rootNode, context); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Interlocked.Increment(ref Failures);
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
                .ToDictionary(d => d.Variables.Single().Name, d => d);
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
