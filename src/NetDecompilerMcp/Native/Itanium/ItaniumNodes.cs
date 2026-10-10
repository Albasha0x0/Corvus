using System.Text;

namespace NetDecompilerMcp.Native.Itanium;

/// <summary>Operator precedence of expression nodes, tightest first (decides parentheses when printing).</summary>
internal enum Prec
{
    Primary,
    Postfix,
    Unary,
    Cast,
    PtrMem,
    Multiplicative,
    Additive,
    Shift,
    Spaceship,
    Relational,
    Equality,
    And,
    Xor,
    Ior,
    AndIf,
    OrIf,
    Conditional,
    Assign,
    Comma,
    Default,
}

/// <summary>The output buffer: text plus the state pack expansion and template-argument printing need.</summary>
internal sealed class Output
{
    public readonly StringBuilder Text = new();
    public int PackIndex = int.MaxValue;
    public int PackMax = int.MaxValue;
    /// <summary>Inside template arguments a '>' operator must be parenthesized.</summary>
    public bool InTemplateArgs;
    public int Depth;

    public int Length => Text.Length;
    public char Last => Text.Length > 0 ? Text[^1] : '\0';
    public Output Add(string s) { Text.Append(s); return this; }
    public Output Add(char c) { Text.Append(c); return this; }
}

/// <summary>A demangled entity; types print in two halves around declarators (function pointers, arrays).</summary>
internal abstract class Node
{
    public virtual Prec Precedence => Prec.Primary;
    /// <summary>Whether printing has a right-hand part (function parameter lists, array bounds).</summary>
    public virtual bool HasRight(Output o) => false;
    public virtual bool HasArray(Output o) => false;
    public virtual bool HasFunction(Output o) => false;
    /// <summary>The node a template parameter or pack element stands for (itself for ordinary nodes).</summary>
    public virtual Node Resolve(Output o) => this;
    public virtual string? BaseName => null;

    public abstract void Left(Output o);
    public virtual void Right(Output o) { }

    public void Print(Output o)
    {
        if (++o.Depth > 256) throw new ItaniumDemangler.TooDeep();
        Left(o);
        if (HasRight(o)) Right(o);
        o.Depth--;
    }

    /// <summary>Prints as an operand of an operator with precedence <paramref name="p"/>, parenthesized when needed.</summary>
    public void PrintAsOperand(Output o, Prec p, bool strictlyWorse)
    {
        bool paren = (int)Precedence >= (int)p + (strictlyWorse ? 1 : 0);
        if (paren) o.Add('(');
        Print(o);
        if (paren) o.Add(')');
    }

    public override string ToString()
    {
        var o = new Output();
        Print(o);
        return o.Text.ToString();
    }

    /// <summary>Prints <paramref name="nodes"/> separated by ", ", dropping the separator of elements that print nothing (empty packs).</summary>
    public static void PrintList(Output o, IReadOnlyList<Node> nodes)
    {
        bool first = true;
        foreach (var n in nodes)
        {
            int before = o.Length;
            if (!first) o.Add(", ");
            int start = o.Length;
            n.Print(o);
            if (o.Length == start) { o.Text.Length = before; continue; }
            first = false;
        }
    }
}

internal sealed class NameNode(string name) : Node
{
    public string Name { get; } = name;
    public override string? BaseName => Name;
    public override void Left(Output o) => o.Add(Name);
}

/// <summary>A type with a suffix (" complex", " imaginary").</summary>
internal sealed class PostfixType(Node child, string postfix) : Node
{
    public override void Left(Output o) { child.Print(o); o.Add(postfix); }
}

internal sealed class AbiTagged(Node child, string tag) : Node
{
    public override string? BaseName => child.BaseName;
    public override void Left(Output o) { child.Print(o); o.Add("[abi:").Add(tag).Add(']'); }
}

/// <summary>A vendor-extended type qualifier (U &lt;source-name&gt;): "int AS1".</summary>
internal sealed class VendorQualified(Node child, string qualifier, Node? args) : Node
{
    public override void Left(Output o)
    {
        child.Print(o);
        o.Add(' ').Add(qualifier);
        args?.Print(o);
    }
}

[Flags]
internal enum Cv { None = 0, Const = 1, Volatile = 2, Restrict = 4 }

internal enum RefQualifier { None, LValue, RValue }

internal sealed class QualifiedType(Node child, Cv quals) : Node
{
    public Node Child { get; } = child;
    public Cv Quals { get; } = quals;
    public override bool HasRight(Output o) => Child.HasRight(o);
    public override bool HasArray(Output o) => Child.HasArray(o);
    public override bool HasFunction(Output o) => Child.HasFunction(o);

    public static void PrintQuals(Output o, Cv q)
    {
        if ((q & Cv.Const) != 0) o.Add(" const");
        if ((q & Cv.Volatile) != 0) o.Add(" volatile");
        if ((q & Cv.Restrict) != 0) o.Add(" restrict");
    }

    public override void Left(Output o) { Child.Left(o); PrintQuals(o, Quals); }
    public override void Right(Output o) => Child.Right(o);
}

internal sealed class ConversionOperatorType(Node type) : Node
{
    public override void Left(Output o) { o.Add("operator "); type.Print(o); }
}

/// <summary>An Objective-C object type with a protocol; a pointer to objc_object&lt;P&gt; prints as id&lt;P&gt;.</summary>
internal sealed class ObjCProtoName(Node type, string protocol) : Node
{
    public string Protocol { get; } = protocol;
    public bool IsObjCObject => type is NameNode { Name: "objc_object" };
    public override void Left(Output o) { type.Print(o); o.Add('<').Add(Protocol).Add('>'); }
}

internal sealed class PointerType(Node pointee) : Node
{
    public Node Pointee { get; } = pointee;
    public override bool HasRight(Output o) => Pointee is not ObjCProtoName { IsObjCObject: true } && Pointee.HasRight(o);

    public override void Left(Output o)
    {
        if (Pointee is ObjCProtoName { IsObjCObject: true } proto)
        {
            o.Add("id<").Add(proto.Protocol).Add('>');
            return;
        }
        Pointee.Left(o);
        bool array = Pointee.HasArray(o);
        if (array) o.Add(' ');
        if (array || Pointee.HasFunction(o)) o.Add('(');
        o.Add('*');
    }

    public override void Right(Output o)
    {
        if (Pointee is ObjCProtoName { IsObjCObject: true }) return;
        if (Pointee.HasArray(o) || Pointee.HasFunction(o)) o.Add(')');
        Pointee.Right(o);
    }
}

internal sealed class ReferenceType(Node pointee, bool rvalue) : Node
{
    public Node Pointee { get; } = pointee;
    public bool RValue { get; } = rvalue;
    public override bool HasRight(Output o) => Pointee.HasRight(o);

    /// <summary>Reference collapsing: T&amp; &amp;&amp; is T&amp;; the result's kind and the type finally referenced.</summary>
    private (bool RValue, Node Pointee) Collapse(Output o)
    {
        bool rvalue = RValue;
        Node p = Pointee;
        var seen = new HashSet<Node>();
        while (seen.Add(p))
        {
            var resolved = p.Resolve(o);
            if (resolved is not ReferenceType r) { p = resolved; break; }
            rvalue = rvalue && r.RValue;
            p = r.Pointee;
        }
        return (rvalue, p);
    }

    public override void Left(Output o)
    {
        var (rvalue, p) = Collapse(o);
        p.Left(o);
        bool array = p.HasArray(o);
        if (array) o.Add(' ');
        if (array || p.HasFunction(o)) o.Add('(');
        o.Add(rvalue ? "&&" : "&");
    }

    public override void Right(Output o)
    {
        var (_, p) = Collapse(o);
        if (p.HasArray(o) || p.HasFunction(o)) o.Add(')');
        p.Right(o);
    }
}

internal sealed class PointerToMemberType(Node classType, Node memberType) : Node
{
    public override bool HasRight(Output o) => memberType.HasRight(o);

    public override void Left(Output o)
    {
        memberType.Left(o);
        o.Add(memberType.HasArray(o) || memberType.HasFunction(o) ? "(" : " ");
        classType.Print(o);
        o.Add("::*");
    }

    public override void Right(Output o)
    {
        if (memberType.HasArray(o) || memberType.HasFunction(o)) o.Add(')');
        memberType.Right(o);
    }
}

internal sealed class ArrayType(Node element, Node? dimension) : Node
{
    public override bool HasRight(Output o) => true;
    public override bool HasArray(Output o) => true;
    public override void Left(Output o) => element.Left(o);

    public override void Right(Output o)
    {
        if (o.Last != ']') o.Add(' ');
        o.Add('[');
        dimension?.Print(o);
        o.Add(']');
        element.Right(o);
    }
}

internal sealed class VectorType(Node element, Node? dimension, bool pixel) : Node
{
    public override void Left(Output o)
    {
        if (pixel) { o.Add("pixel vector["); dimension?.Print(o); o.Add(']'); return; }
        element.Print(o);
        o.Add(" vector[");
        dimension?.Print(o);
        o.Add(']');
    }
}

internal sealed class FunctionType(Node ret, IReadOnlyList<Node> parameters, Cv quals, RefQualifier refQualifier, Node? exceptionSpec) : Node
{
    public override bool HasRight(Output o) => true;
    public override bool HasFunction(Output o) => true;
    public override void Left(Output o) { ret.Left(o); o.Add(' '); }

    public override void Right(Output o)
    {
        o.Add('(');
        PrintList(o, parameters);
        o.Add(')');
        ret.Right(o);
        QualifiedType.PrintQuals(o, quals);
        if (refQualifier == RefQualifier.LValue) o.Add(" &");
        else if (refQualifier == RefQualifier.RValue) o.Add(" &&");
        if (exceptionSpec != null) { o.Add(' '); exceptionSpec.Print(o); }
    }
}

internal sealed class NoexceptSpec(Node? expression) : Node
{
    public override void Left(Output o)
    {
        o.Add("noexcept");
        if (expression != null) { o.Add('('); expression.Print(o); o.Add(')'); }
    }
}

internal sealed class DynamicExceptionSpec(IReadOnlyList<Node> types) : Node
{
    public override void Left(Output o) { o.Add("throw("); PrintList(o, types); o.Add(')'); }
}

/// <summary>A function name with its signature; the return type is mangled only for templates.</summary>
internal sealed class FunctionEncoding(Node? ret, Node name, IReadOnlyList<Node> parameters, Cv quals, RefQualifier refQualifier) : Node
{
    public Node Name { get; } = name;
    public override bool HasRight(Output o) => true;
    public override bool HasFunction(Output o) => true;

    public override void Left(Output o)
    {
        if (ret != null)
        {
            ret.Left(o);
            if (!ret.HasRight(o)) o.Add(' ');
        }
        Name.Print(o);
    }

    public override void Right(Output o)
    {
        o.Add('(');
        PrintList(o, parameters);
        o.Add(')');
        ret?.Right(o);
        QualifiedType.PrintQuals(o, quals);
        if (refQualifier == RefQualifier.LValue) o.Add(" &");
        else if (refQualifier == RefQualifier.RValue) o.Add(" &&");
    }
}

/// <summary>vtable for, typeinfo for, thunks, guard variables, ...</summary>
internal sealed class SpecialName(string prefix, Node child) : Node
{
    public override void Left(Output o) { o.Add(prefix); child.Print(o); }
}

internal sealed class CtorVtableSpecialName(Node first, Node second) : Node
{
    public override void Left(Output o) { o.Add("construction vtable for "); first.Print(o); o.Add("-in-"); second.Print(o); }
}

internal sealed class NestedName(Node qualifier, Node name) : Node
{
    public Node Qualifier { get; } = qualifier;
    public Node Name { get; } = name;
    public override string? BaseName => Name.BaseName;
    public override void Left(Output o) { Qualifier.Print(o); o.Add("::"); Name.Print(o); }
}

internal sealed class LocalName(Node encoding, Node entity) : Node
{
    public override void Left(Output o) { encoding.Print(o); o.Add("::"); entity.Print(o); }
}

internal sealed class StdQualifiedName(Node child) : Node
{
    public override string? BaseName => child.BaseName;
    public override void Left(Output o) { o.Add("std::"); child.Print(o); }
}

internal sealed class NameWithTemplateArgs(Node name, Node args) : Node
{
    public Node Name { get; } = name;
    public override string? BaseName => Name.BaseName;
    public override void Left(Output o) { Name.Print(o); args.Print(o); }
}

internal sealed class TemplateArgs(IReadOnlyList<Node> args) : Node
{
    public IReadOnlyList<Node> Args { get; } = args;

    public override void Left(Output o)
    {
        bool saved = o.InTemplateArgs;
        o.InTemplateArgs = true;
        o.Add('<');
        PrintList(o, Args);
        o.Add('>');
        o.InTemplateArgs = saved;
    }
}

/// <summary>J ... E: the elements of a pack template argument.</summary>
internal sealed class TemplateArgumentPack(IReadOnlyList<Node> elements) : Node
{
    public IReadOnlyList<Node> Elements { get; } = elements;
    public override void Left(Output o) => PrintList(o, Elements);
}

/// <summary>A template parameter bound to a pack: prints the element of the expansion being printed.</summary>
internal sealed class ParameterPack(IReadOnlyList<Node> elements) : Node
{
    private void Initialize(Output o)
    {
        if (o.PackMax == int.MaxValue)
        {
            o.PackMax = elements.Count;
            o.PackIndex = 0;
        }
    }

    private Node? Current(Output o)
    {
        Initialize(o);
        return o.PackIndex < elements.Count ? elements[o.PackIndex] : null;
    }

    public override Node Resolve(Output o) => Current(o)?.Resolve(o) ?? this;
    public override bool HasRight(Output o) => Current(o)?.HasRight(o) == true;
    public override bool HasArray(Output o) => Current(o)?.HasArray(o) == true;
    public override bool HasFunction(Output o) => Current(o)?.HasFunction(o) == true;
    public override void Left(Output o) => Current(o)?.Left(o);
    public override void Right(Output o) => Current(o)?.Right(o);
}

/// <summary>Dp / sp: the pattern printed once per element of the pack it mentions.</summary>
internal sealed class PackExpansion(Node child) : Node
{
    public override void Left(Output o)
    {
        int savedIndex = o.PackIndex, savedMax = o.PackMax;
        o.PackIndex = int.MaxValue;
        o.PackMax = int.MaxValue;
        int start = o.Length;
        child.Print(o);
        if (o.PackMax == int.MaxValue) o.Add("...");
        else if (o.PackMax == 0) o.Text.Length = start;
        else
            for (int i = 1, max = o.PackMax; i < max; i++)
            {
                o.Add(", ");
                o.PackIndex = i;
                child.Print(o);
            }
        o.PackIndex = savedIndex;
        o.PackMax = savedMax;
    }
}

/// <summary>A template parameter used before its arguments are parsed (conversion operator types); resolved at the end.</summary>
internal sealed class ForwardTemplateReference(int index) : Node
{
    public int Index { get; } = index;
    public Node? Target;
    private bool printing;

    public override Node Resolve(Output o) => Target?.Resolve(o) ?? this;
    public override bool HasRight(Output o) => !printing && Target?.HasRight(o) == true;
    public override bool HasArray(Output o) => !printing && Target?.HasArray(o) == true;
    public override bool HasFunction(Output o) => !printing && Target?.HasFunction(o) == true;

    public override void Left(Output o)
    {
        if (printing || Target == null) return;
        printing = true;
        Target.Left(o);
        printing = false;
    }

    public override void Right(Output o)
    {
        if (printing || Target == null) return;
        printing = true;
        Target.Right(o);
        printing = false;
    }
}

internal sealed class CtorDtorName(Node basis, bool destructor) : Node
{
    public override void Left(Output o)
    {
        if (destructor) o.Add('~');
        o.Add(basis.BaseName ?? basis.ToString());
    }
}

internal sealed class ClosureTypeName(IReadOnlyList<Node> templateParams, IReadOnlyList<Node> parameters, string count) : Node
{
    public override void Left(Output o)
    {
        o.Add("'lambda").Add(count).Add('\'');
        if (templateParams.Count > 0) { o.Add('<'); PrintList(o, templateParams); o.Add('>'); }
        o.Add('(');
        PrintList(o, parameters);
        o.Add(')');
    }
}

internal sealed class UnnamedTypeName(string count) : Node
{
    public override void Left(Output o) => o.Add("'unnamed").Add(count).Add('\'');
}

internal enum SpecialSubstitutionKind { Allocator, BasicString, String, IStream, OStream, IOStream }

/// <summary>Sa, Sb, Ss, Si, So, Sd; constructors and destructors use the expanded form.</summary>
internal sealed class SpecialSubstitution(SpecialSubstitutionKind kind, bool expanded) : Node
{
    public SpecialSubstitutionKind Kind { get; } = kind;

    public override string? BaseName => Kind switch
    {
        SpecialSubstitutionKind.Allocator => "allocator",
        SpecialSubstitutionKind.BasicString or SpecialSubstitutionKind.String => "basic_string",
        SpecialSubstitutionKind.IStream => "basic_istream",
        SpecialSubstitutionKind.OStream => "basic_ostream",
        _ => "basic_iostream",
    };

    public override void Left(Output o)
    {
        if (!expanded || Kind is SpecialSubstitutionKind.Allocator or SpecialSubstitutionKind.BasicString)
        {
            o.Add(Kind switch
            {
                SpecialSubstitutionKind.Allocator => "std::allocator",
                SpecialSubstitutionKind.BasicString => "std::basic_string",
                SpecialSubstitutionKind.String => "std::string",
                SpecialSubstitutionKind.IStream => "std::istream",
                SpecialSubstitutionKind.OStream => "std::ostream",
                _ => "std::iostream",
            });
            return;
        }
        o.Add("std::").Add(BaseName!).Add("<char, std::char_traits<char>");
        if (Kind == SpecialSubstitutionKind.String) o.Add(", std::allocator<char>");
        o.Add('>');
    }
}

internal sealed class EnclosingExpr(string prefix, Node child, string postfix = ")") : Node
{
    public override void Left(Output o) { o.Add(prefix); child.Print(o); o.Add(postfix); }
}

internal sealed class IntegerLiteral(string type, string value) : Node
{
    public override void Left(Output o)
    {
        if (type.Length > 3) o.Add('(').Add(type).Add(')');
        if (value.Length > 0 && value[0] == 'n') o.Add('-').Add(value[1..]);
        else o.Add(value);
        if (type.Length <= 3) o.Add(type);
    }
}

internal sealed class EnumLiteral(Node type, string value) : Node
{
    public override void Left(Output o)
    {
        o.Add('(');
        type.Print(o);
        o.Add(')');
        if (value.Length > 0 && value[0] == 'n') o.Add('-').Add(value[1..]);
        else o.Add(value);
    }
}

internal sealed class BoolLiteral(bool value) : Node
{
    public override void Left(Output o) => o.Add(value ? "true" : "false");
}

internal sealed class FloatLiteral(string text) : Node
{
    public override void Left(Output o) => o.Add(text);
}

internal sealed class BinaryExpr(Node left, string op, Node right, Prec precedence) : Node
{
    public override Prec Precedence => precedence;

    public override void Left(Output o)
    {
        bool parenAll = o.InTemplateArgs && op is ">" or ">>";
        if (parenAll) o.Add('(');
        bool assign = precedence == Prec.Assign;
        left.PrintAsOperand(o, assign ? Prec.OrIf : precedence, !assign);
        if (op != ",") o.Add(' ');
        o.Add(op).Add(' ');
        right.PrintAsOperand(o, precedence, assign);
        if (parenAll) o.Add(')');
    }
}

internal sealed class PrefixExpr(string prefix, Node child, Prec precedence) : Node
{
    public override Prec Precedence => precedence;
    public override void Left(Output o) { o.Add(prefix); child.PrintAsOperand(o, precedence, false); }
}

internal sealed class PostfixExpr(Node child, string op, Prec precedence) : Node
{
    public override Prec Precedence => precedence;
    public override void Left(Output o) { child.PrintAsOperand(o, precedence, true); o.Add(op); }
}

internal sealed class CallExpr(Node callee, IReadOnlyList<Node> args) : Node
{
    public override Prec Precedence => Prec.Postfix;

    public override void Left(Output o)
    {
        callee.Print(o);
        o.Add('(');
        PrintList(o, args);
        o.Add(')');
    }
}

internal sealed class CastExpr(string kind, Node type, Node expr) : Node
{
    public override Prec Precedence => Prec.Postfix;

    public override void Left(Output o)
    {
        o.Add(kind).Add('<');
        type.Print(o);
        o.Add(">(");
        expr.Print(o);
        o.Add(')');
    }
}

/// <summary>A C-style cast "(type)expr" (cv with one operand).</summary>
internal sealed class ConversionExpr(Node type, IReadOnlyList<Node> exprs) : Node
{
    public override Prec Precedence => Prec.Cast;

    public override void Left(Output o)
    {
        o.Add('(');
        type.Print(o);
        o.Add(")(");
        PrintList(o, exprs);
        o.Add(')');
    }
}

internal sealed class MemberExpr(Node left, string kind, Node right) : Node
{
    public override Prec Precedence => Prec.Postfix;
    public override void Left(Output o) { left.PrintAsOperand(o, Prec.Postfix, true); o.Add(kind); right.Print(o); }
}

internal sealed class ConditionalExpr(Node cond, Node then, Node otherwise) : Node
{
    public override Prec Precedence => Prec.Conditional;

    public override void Left(Output o)
    {
        cond.PrintAsOperand(o, Prec.Conditional, false);
        o.Add(" ? ");
        then.PrintAsOperand(o, Prec.Assign, false);
        o.Add(" : ");
        otherwise.PrintAsOperand(o, Prec.Assign, true);
    }
}

internal sealed class ArraySubscriptExpr(Node array, Node index) : Node
{
    public override Prec Precedence => Prec.Postfix;
    public override void Left(Output o) { array.PrintAsOperand(o, Prec.Postfix, false); o.Add('['); index.Print(o); o.Add(']'); }
}
