using System.Globalization;
using System.Text;

namespace NetDecompilerMcp.Native.Msvc;

/// <summary>A malformed or unsupported mangled name; caught at the API boundary.</summary>
internal sealed class MangledNameException(string message, int offset) : Exception(message)
{
    public int Offset { get; } = offset;
}

[Flags]
internal enum Quals
{
    None = 0,
    Const = 1,
    Volatile = 2,
    Restrict = 4,
    Unaligned = 8,
    Ptr64 = 16,
}

[Flags]
internal enum FuncClass
{
    None = 0,
    Public = 1 << 0,
    Protected = 1 << 1,
    Private = 1 << 2,
    Global = 1 << 3,
    Static = 1 << 4,
    Virtual = 1 << 5,
    Far = 1 << 6,
    ExternC = 1 << 7,
    NoParameterList = 1 << 8,
    VirtualThisAdjust = 1 << 9,
    VirtualThisAdjustEx = 1 << 10,
    StaticThisAdjust = 1 << 11,
}

internal enum Affinity { Pointer, Reference, RValueReference, Handle, TrackingReference }

internal enum StorageClass { PrivateStatic, ProtectedStatic, PublicStatic, Global, FunctionLocalStatic }

/// <summary>Text output with a length cap; output flags select the parts of a declaration that are printed.</summary>
internal sealed class Printer(int limit, bool decodeStrings, bool ptr64 = false, bool nameOnly = false)
{
    private readonly StringBuilder sb = new();

    public bool DecodeStrings { get; } = decodeStrings;

    /// <summary>Print the __ptr64 pointer qualifier of 64-bit names.</summary>
    public bool Ptr64 { get; } = ptr64;

    /// <summary>Name-only output: no class/struct/union keywords (enum stays, as in DbgHelp); enclosing functions of local names print as names.</summary>
    public bool NameOnly { get; } = nameOnly;

    public Printer Append(string text)
    {
        sb.Append(text);
        if (sb.Length > limit)
            throw new MangledNameException($"demangled text longer than {limit} characters", -1);
        return this;
    }

    public Printer Append(long value) => Append(value.ToString(CultureInfo.InvariantCulture));

    public Printer Append(ulong value) => Append(value.ToString(CultureInfo.InvariantCulture));

    public char Last => sb.Length == 0 ? '\0' : sb[^1];

    private int depth;

    /// <summary>Recursion guard for printing nested names and types.</summary>
    public void Enter()
    {
        if (++depth > 4 * MsvcDemangler.MaxDepth)
            throw new MangledNameException("demangled name nested too deeply", -1);
    }

    public void Leave() => depth--;

    /// <summary>A space between an identifier or a closing template bracket and what follows.</summary>
    public void SpaceIfNeeded()
    {
        char c = Last;
        if (char.IsAsciiLetterOrDigit(c) || c == '>' || c == '_')
            sb.Append(' ');
    }

    public void Qualifiers(Quals q, bool spaceBefore, bool spaceAfter)
    {
        int start = sb.Length;
        spaceBefore = One(q, Quals.Const, "const", spaceBefore);
        spaceBefore = One(q, Quals.Volatile, "volatile", spaceBefore);
        One(q, Quals.Restrict, "__restrict", spaceBefore);
        if (spaceAfter && sb.Length > start)
            Append(" ");
    }

    private bool One(Quals q, Quals mask, string text, bool spaceBefore)
    {
        if ((q & mask) == 0) return spaceBefore;
        if (spaceBefore) Append(" ");
        Append(text);
        return true;
    }

    public override string ToString() => sb.ToString();
}

[Flags]
internal enum OutFlags
{
    None = 0,
    NoCallingConvention = 1,
    NoReturnType = 2,
}

internal abstract class Node
{
    public abstract void Output(Printer p, OutFlags f = OutFlags.None);

    public string Render()
    {
        var p = new Printer(MsvcDemangler.MaxOutputLength, decodeStrings: true);
        Output(p);
        return p.ToString();
    }
}

// ---- types ----

internal abstract class TypeNode : Node
{
    public Quals Quals;

    public abstract void Pre(Printer p, OutFlags f);

    public virtual void Post(Printer p, OutFlags f) { }

    public override void Output(Printer p, OutFlags f = OutFlags.None)
    {
        p.Enter();
        Pre(p, f);
        Post(p, f);
        p.Leave();
    }
}

internal sealed class PrimitiveType(string name) : TypeNode
{
    public string Name { get; } = name;

    public override void Pre(Printer p, OutFlags f)
    {
        p.Append(Name);
        p.Qualifiers(Quals, spaceBefore: true, spaceAfter: false);
    }
}

internal sealed class TagType(string tag, QualifiedName name) : TypeNode
{
    public string Tag { get; } = tag;
    public QualifiedName Name { get; } = name;

    public override void Pre(Printer p, OutFlags f)
    {
        if (!p.NameOnly || Tag == "enum") p.Append(Tag).Append(" ");
        Name.Output(p, f);
        p.Qualifiers(Quals, spaceBefore: true, spaceAfter: false);
    }
}

internal sealed class CustomType(Identifier id) : TypeNode
{
    public override void Pre(Printer p, OutFlags f)
    {
        id.Output(p, f);
        p.Qualifiers(Quals, spaceBefore: true, spaceAfter: false);
    }
}

internal sealed class PointerType : TypeNode
{
    public Affinity Affinity;
    public TypeNode Pointee = null!;
    public QualifiedName? ClassParent;
    /// <summary>A pointer variable's own __ptr64 storage qualifier (printed after its cv-qualifiers).</summary>
    public bool StoragePtr64;

    public override void Pre(Printer p, OutFlags f)
    {
        p.Enter();
        if (Pointee is FunctionType fn)
            fn.Pre(p, OutFlags.NoCallingConvention);
        else
            Pointee.Pre(p, f);
        p.Leave();
        p.SpaceIfNeeded();
        if ((Quals & Quals.Unaligned) != 0)
            p.Append("__unaligned ");
        if (Pointee is ArrayType)
            p.Append("(");
        else if (Pointee is FunctionType fn2)
        {
            p.Append("(");
            if (fn2.CallingConvention != null) p.Append(fn2.CallingConvention).Append(" ");
        }
        if (ClassParent != null)
        {
            ClassParent.Output(p, f);
            p.Append("::");
        }
        p.Append(Affinity switch
        {
            Affinity.Reference => "&",
            Affinity.RValueReference => "&&",
            Affinity.Handle => "^",
            Affinity.TrackingReference => "%",
            _ => "*",
        });
        if (p.Ptr64 && (Quals & Quals.Ptr64) != 0)
            p.Append(" __ptr64");
        p.Qualifiers(Quals, spaceBefore: true, spaceAfter: false);
        if (p.Ptr64 && StoragePtr64)
            p.Append(" __ptr64");
    }

    public override void Post(Printer p, OutFlags f)
    {
        if (Pointee is ArrayType or FunctionType)
            p.Append(")");
        p.Enter();
        Pointee.Post(p, f);
        p.Leave();
    }
}

/// <summary>C++/CLI managed array handle: "cli::array&lt;T, rank&gt;^".</summary>
internal sealed class CliArrayType : TypeNode
{
    public TypeNode Element = null!;
    public int Rank;
    public bool Ptr64;

    public override void Pre(Printer p, OutFlags f)
    {
        p.Append("cli::array<");
        Element.Output(p);
        if (Rank > 1) p.Append(", ").Append(Rank);
        p.Append(">^");
        if (p.Ptr64 && Ptr64) p.Append(" __ptr64");
        p.Qualifiers(Quals, spaceBefore: true, spaceAfter: false);
    }
}

internal sealed class ArrayType : TypeNode
{
    public TypeNode Element = null!;
    public List<ulong> Dimensions = [];

    public override void Pre(Printer p, OutFlags f)
    {
        Element.Pre(p, f);
        p.Qualifiers(Quals, spaceBefore: true, spaceAfter: false);
    }

    public override void Post(Printer p, OutFlags f)
    {
        foreach (var d in Dimensions)
            p.Append("[").Append(d).Append("]");
        Element.Post(p, f);
    }
}

/// <summary>A function signature; also the type of a function symbol and of function pointees.</summary>
internal class FunctionType : TypeNode
{
    public FuncClass Class;
    public string? CallingConvention;
    public TypeNode? ReturnType;
    public List<TypeNode>? Parameters; // null: "(void)"
    public bool IsVariadic;
    public bool IsNoexcept;
    public Affinity? RefQualifier;
    /// <summary>cv-qualifiers dropped from a returned pointer (kept for conversion operator targets).</summary>
    public Quals DroppedReturnQuals;

    public override void Pre(Printer p, OutFlags f)
    {
        if ((Class & FuncClass.Public) != 0) p.Append("public: ");
        if ((Class & FuncClass.Protected) != 0) p.Append("protected: ");
        if ((Class & FuncClass.Private) != 0) p.Append("private: ");
        if ((Class & FuncClass.Global) == 0 && (Class & FuncClass.Static) != 0) p.Append("static ");
        if ((Class & FuncClass.Virtual) != 0) p.Append("virtual ");
        if ((Class & FuncClass.ExternC) != 0 && (Class & FuncClass.NoParameterList) == 0) p.Append("extern \"C\" ");
        if ((f & OutFlags.NoReturnType) == 0 && ReturnType != null)
        {
            ReturnType.Pre(p, OutFlags.None);
            p.Append(" ");
        }
        if ((f & OutFlags.NoCallingConvention) == 0 && CallingConvention != null)
            p.Append(CallingConvention);
    }

    public override void Post(Printer p, OutFlags f)
    {
        if ((Class & FuncClass.NoParameterList) == 0)
        {
            p.Append("(");
            if (Parameters == null)
                p.Append("void");
            else
                for (int i = 0; i < Parameters.Count; i++)
                {
                    if (i > 0) p.Append(", ");
                    Parameters[i].Output(p);
                }
            if (IsVariadic)
            {
                if (p.Last != '(') p.Append(", ");
                p.Append("...");
            }
            p.Append(")");
        }
        if ((Quals & Quals.Const) != 0) p.Append(" const");
        if ((Quals & Quals.Volatile) != 0) p.Append(" volatile");
        if (p.Ptr64 && (Quals & Quals.Ptr64) != 0) p.Append(" __ptr64");
        if ((Quals & Quals.Restrict) != 0) p.Append(" __restrict");
        if ((Quals & Quals.Unaligned) != 0) p.Append(" __unaligned");
        if (IsNoexcept) p.Append(" noexcept");
        if (RefQualifier == Affinity.Reference) p.Append(" &");
        else if (RefQualifier == Affinity.RValueReference) p.Append(" &&");
        if ((f & OutFlags.NoReturnType) == 0)
            ReturnType?.Post(p, OutFlags.None);
    }
}

/// <summary>A this-adjusting thunk: "[thunk]:" before, "`adjustor{n}'" / "`vtordisp{a, b}'" after the name.</summary>
internal sealed class ThunkType : FunctionType
{
    public long StaticOffset, VBPtrOffset, VBOffsetOffset, VtordispOffset;

    public override void Pre(Printer p, OutFlags f)
    {
        p.Append("[thunk]: ");
        base.Pre(p, f);
    }

    public override void Post(Printer p, OutFlags f)
    {
        if ((Class & FuncClass.StaticThisAdjust) != 0)
            p.Append("`adjustor{").Append(StaticOffset).Append("}'");
        else if ((Class & FuncClass.VirtualThisAdjust) != 0)
        {
            if ((Class & FuncClass.VirtualThisAdjustEx) != 0)
                p.Append("`vtordispex{").Append(VBPtrOffset).Append(", ").Append(VBOffsetOffset).Append(", ")
                    .Append(VtordispOffset).Append(", ").Append(StaticOffset).Append("}'");
            else
                p.Append("`vtordisp{").Append(VtordispOffset).Append(", ").Append(StaticOffset).Append("}'");
        }
        base.Post(p, f);
    }
}

// ---- template arguments that are not types ----

internal sealed class IntegerLiteral(ulong value, bool negative) : Node
{
    public override void Output(Printer p, OutFlags f = OutFlags.None)
    {
        if (negative) p.Append("-");
        p.Append(value);
    }
}

/// <summary>A non-type template argument naming a symbol or a member pointer: "&amp;f", "{&amp;A::f, 4}", "{0, 4}".</summary>
internal sealed class SymbolArgument : Node
{
    public SymbolNode? Symbol;
    public List<long> Offsets = [];
    public bool IsReference;

    public override void Output(Printer p, OutFlags f = OutFlags.None)
    {
        if (Offsets.Count > 0) p.Append("{");
        else if (!IsReference) p.Append("&");
        if (Symbol != null)
        {
            if (p.NameOnly) Symbol.OutputName(p);
            else Symbol.Output(p, f);
            if (Offsets.Count > 0) p.Append(", ");
        }
        for (int i = 0; i < Offsets.Count; i++)
        {
            if (i > 0) p.Append(", ");
            p.Append(Offsets[i]);
        }
        if (Offsets.Count > 0) p.Append("}");
    }
}

// ---- names ----

internal abstract class Identifier : Node
{
    public List<Node>? TemplateArgs;

    protected void OutputTemplateArgs(Printer p)
    {
        if (TemplateArgs == null) return;
        p.Append("<");
        for (int i = 0; i < TemplateArgs.Count; i++)
        {
            if (i > 0) p.Append(", ");
            TemplateArgs[i].Output(p);
        }
        p.Append(">");
    }
}

internal sealed class NamedIdentifier(string name) : Identifier
{
    public string Name { get; } = name;

    public override void Output(Printer p, OutFlags f = OutFlags.None)
    {
        p.Append(Name);
        OutputTemplateArgs(p);
    }
}

/// <summary>A name back-reference ("0".."9"): prints the memorized name with the current output options.</summary>
internal sealed class BackrefIdentifier(Identifier target) : Identifier
{
    public override void Output(Printer p, OutFlags f = OutFlags.None)
    {
        p.Enter();
        target.Output(p, f);
        OutputTemplateArgs(p);
        p.Leave();
    }
}

/// <summary>A scope inside a function body: "`int __cdecl f(void)'::`2'".</summary>
internal sealed class LocalScopeIdentifier(SymbolNode function, ulong number) : Identifier
{
    public override void Output(Printer p, OutFlags f = OutFlags.None)
    {
        p.Append("`");
        p.Enter();
        if (p.NameOnly) function.OutputName(p);
        else function.Output(p);
        p.Leave();
        p.Append("'::`").Append(number).Append("'");
    }
}

/// <summary>An explicit interface implementation scope (C++/CX): "[Platform::IDisposable]".</summary>
internal sealed class InterfaceScopeIdentifier(QualifiedName name) : Identifier
{
    public override void Output(Printer p, OutFlags f = OutFlags.None)
    {
        p.Append("[");
        name.Output(p, f);
        p.Append("]");
    }
}

internal sealed class StructorIdentifier(bool destructor) : Identifier
{
    public Identifier? Class;

    public override void Output(Printer p, OutFlags f = OutFlags.None)
    {
        if (destructor) p.Append("~");
        Class?.Output(p, f);
        OutputTemplateArgs(p);
    }
}

internal sealed class ConversionOperatorIdentifier : Identifier
{
    public TypeNode? Target;

    public override void Output(Printer p, OutFlags f = OutFlags.None)
    {
        p.Append("operator");
        OutputTemplateArgs(p);
        p.Append(" ");
        Target?.Output(p);
    }
}

internal sealed class LocalStaticGuardIdentifier(bool thread) : Identifier
{
    public ulong ScopeIndex;

    public override void Output(Printer p, OutFlags f = OutFlags.None)
    {
        p.Append(thread ? "`local static thread guard'" : "`local static guard'");
        // DbgHelp / undname form, closing quote included
        if (ScopeIndex > 0 && !p.NameOnly) p.Append("{").Append(ScopeIndex).Append("}'");
    }
}

internal sealed class DynamicStructorIdentifier(bool destructor) : Identifier
{
    public VariableSymbol? Variable;
    public QualifiedName? Name;

    public override void Output(Printer p, OutFlags f = OutFlags.None)
    {
        p.Append(destructor ? "`dynamic atexit destructor for " : "`dynamic initializer for ");
        if (Variable != null)
        {
            p.Append("`");
            Variable.Output(p, f);
            p.Append("''");
        }
        else
        {
            p.Append("'");
            Name?.Output(p, f);
            p.Append("''");
        }
    }
}

internal sealed class VcallThunkIdentifier : Identifier
{
    public ulong Offset;

    public override void Output(Printer p, OutFlags f = OutFlags.None)
    {
        if (p.NameOnly) p.Append("`vcall'{").Append(Offset).Append("}'");
        else p.Append("`vcall'{").Append(Offset).Append(", {flat}}");
    }
}

internal sealed class RttiBaseClassDescriptorIdentifier : Identifier
{
    public long NonVirtualOffset, VBPtrOffset, VBTableOffset, Flags;

    public override void Output(Printer p, OutFlags f = OutFlags.None) =>
        p.Append("`RTTI Base Class Descriptor at (").Append(NonVirtualOffset).Append(", ").Append(VBPtrOffset).Append(", ")
            .Append(VBTableOffset).Append(", ").Append(Flags).Append(")'");
}

internal sealed class QualifiedName(List<Identifier> components) : Node
{
    public List<Identifier> Components { get; } = components;

    public Identifier Last => Components[^1];

    public override void Output(Printer p, OutFlags f = OutFlags.None)
    {
        p.Enter();
        for (int i = 0; i < Components.Count; i++)
        {
            if (i > 0) p.Append("::");
            Components[i].Output(p, f);
        }
        p.Leave();
    }
}

// ---- symbols ----

internal abstract class SymbolNode : Node
{
    public QualifiedName? Name;

    public abstract MsvcSymbolKind Kind { get; }

    /// <summary>The name-only form; the qualified name for most symbols.</summary>
    public virtual void OutputName(Printer p) => Name?.Output(p);
}

internal sealed class FunctionSymbol : SymbolNode
{
    public FunctionType Signature = null!;

    public override MsvcSymbolKind Kind => Signature is ThunkType || Name?.Last is VcallThunkIdentifier ? MsvcSymbolKind.Thunk : MsvcSymbolKind.Function;

    public override void Output(Printer p, OutFlags f = OutFlags.None)
    {
        // A conversion operator's return type is its name.
        var flags = Name?.Last is ConversionOperatorIdentifier ? f | OutFlags.NoReturnType : f;
        Signature.Pre(p, flags);
        p.SpaceIfNeeded();
        Name?.Output(p, f);
        Signature.Post(p, flags);
    }
}

internal sealed class VariableSymbol : SymbolNode
{
    public StorageClass StorageClass = StorageClass.Global;
    public TypeNode? Type;
    public MsvcSymbolKind SymbolKind = MsvcSymbolKind.Variable;

    public override MsvcSymbolKind Kind => SymbolKind;

    public override void Output(Printer p, OutFlags f = OutFlags.None)
    {
        switch (StorageClass)
        {
            case StorageClass.PrivateStatic: p.Append("private: static "); break;
            case StorageClass.ProtectedStatic: p.Append("protected: static "); break;
            case StorageClass.PublicStatic: p.Append("public: static "); break;
        }
        if (SymbolKind is MsvcSymbolKind.RttiTypeDescriptor or MsvcSymbolKind.TypeName && Type != null)
        {
            // the name follows the complete type: "bool (__cdecl *)(int) `RTTI Type Descriptor'"
            Type.Output(p, f);
            p.Append(" ");
            Name?.Output(p, f);
            return;
        }
        if (Type != null)
        {
            Type.Pre(p, f);
            p.SpaceIfNeeded();
        }
        Name?.Output(p, f);
        Type?.Post(p, f);
    }

    /// <summary>Type descriptors keep their type in the name-only form: "A `RTTI Type Descriptor'".</summary>
    public override void OutputName(Printer p)
    {
        if (SymbolKind is not (MsvcSymbolKind.RttiTypeDescriptor or MsvcSymbolKind.TypeName) || Type == null)
        {
            base.OutputName(p);
            return;
        }
        Type.Output(p);
        p.Append(" ");
        Name?.Output(p);
    }
}

internal sealed class SpecialTableSymbol : SymbolNode
{
    public Quals Quals;
    public List<QualifiedName> Targets = [];
    public MsvcSymbolKind SymbolKind = MsvcSymbolKind.SpecialTable;

    public override MsvcSymbolKind Kind => SymbolKind;

    public override void Output(Printer p, OutFlags f = OutFlags.None)
    {
        p.Qualifiers(Quals, spaceBefore: false, spaceAfter: true);
        Name?.Output(p, f);
        if (Targets.Count == 0) return;
        p.Append("{for `");
        for (int i = 0; i < Targets.Count; i++)
        {
            if (i > 0) p.Append("'s `");
            Targets[i].Output(p, f);
        }
        p.Append("'}");
    }
}

internal sealed class LocalStaticGuardVariable : SymbolNode
{
    public bool IsVisible;

    public override MsvcSymbolKind Kind => MsvcSymbolKind.LocalStaticGuard;

    public override void Output(Printer p, OutFlags f = OutFlags.None) => Name?.Output(p, f);
}

internal sealed class StringLiteralSymbol : SymbolNode
{
    public string Prefix = "";
    public string Text = "";
    public bool IsTruncated;

    public override MsvcSymbolKind Kind => MsvcSymbolKind.StringLiteral;

    public override void Output(Printer p, OutFlags f = OutFlags.None)
    {
        if (!p.DecodeStrings)
        {
            p.Append("`string'");
            return;
        }
        p.Append(Prefix).Append("\"").Append(Text).Append("\"");
        if (IsTruncated) p.Append("...");
    }

    public override void OutputName(Printer p) => Output(p);
}

internal sealed class Md5Symbol(string text) : SymbolNode
{
    public override MsvcSymbolKind Kind => MsvcSymbolKind.Md5Hash;

    public override void Output(Printer p, OutFlags f = OutFlags.None) => p.Append(text);

    public override void OutputName(Printer p) => p.Append(text);
}
