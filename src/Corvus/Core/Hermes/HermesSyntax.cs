using System.Globalization;
using System.Text;

namespace Corvus.Core.Hermes;

// The decompiler's JavaScript-like syntax tree: expressions, flat statements and structured statements.

internal abstract class Ex
{
    /// <summary>JavaScript precedence: 20 primary, 18 member and call, 15 unary, 13 * / %, 12 + -, 11 shifts, 10 relational, 9 equality, 8–6 bitwise, 5 &amp;&amp;, 4 ||, 3 ?:.</summary>
    public virtual int Prec => 20;

    /// <summary>Reading it has no side effect and its value does not change when other code runs (constants, closures, parameters).</summary>
    public virtual bool Pure => false;

    public abstract void Write(StringBuilder sb);

    public virtual Ex Map(Func<Ex, Ex> f) => f(this);

    public virtual void Visit(Action<Ex> f) => f(this);

    public void Write(StringBuilder sb, int prec)
    {
        if (Prec < prec) { sb.Append('('); Write(sb); sb.Append(')'); }
        else Write(sb);
    }

    public override string ToString()
    {
        var sb = new StringBuilder();
        Write(sb);
        return sb.ToString();
    }
}

internal sealed class RegEx(long reg) : Ex
{
    public long Reg { get; } = reg;
    public override bool Pure => true;
    public override void Write(StringBuilder sb) => sb.Append('r').Append(Reg.ToString(CultureInfo.InvariantCulture));
}

/// <summary>A constant, a literal or a name that never changes (parameters, this, builtins).</summary>
internal sealed class LitEx(string text, bool pure = true) : Ex
{
    public string Text { get; } = text;
    public override bool Pure { get; } = pure;
    public override void Write(StringBuilder sb) => sb.Append(Text);
}

/// <summary>A variable that code may change: a global or a closure variable.</summary>
internal sealed class NameEx(string name) : Ex
{
    public string Name { get; } = name;
    public override void Write(StringBuilder sb) => sb.Append(Name);
}

/// <summary>The exception a catch block receives: constant within its handler, never copied into code that may run in another.</summary>
internal sealed class CaughtEx : Ex
{
    public override bool Pure => true;
    public override void Write(StringBuilder sb) => sb.Append('e');
}

internal sealed class GlobalEx : Ex
{
    public static readonly GlobalEx Value = new();
    public override bool Pure => true;
    public override void Write(StringBuilder sb) => sb.Append("globalThis");
}

internal sealed class FuncEx(int function, string text) : Ex
{
    public int Function { get; } = function;
    public override bool Pure => true;
    public override void Write(StringBuilder sb) => sb.Append(text);
}

/// <summary>The object 'new' allocates before the constructor runs; dropped when the construct result is selected.</summary>
internal sealed class ThisAllocEx(Ex proto) : Ex
{
    public Ex Proto { get; } = proto;
    public override bool Pure => true;
    public override void Write(StringBuilder sb) { sb.Append("Object.create("); Proto.Write(sb, 3); sb.Append(')'); }
    public override Ex Map(Func<Ex, Ex> f) => f(new ThisAllocEx(Proto.Map(f)));
    public override void Visit(Action<Ex> f) { f(this); Proto.Visit(f); }
}

internal sealed class BinEx(string op, Ex left, Ex right, int prec) : Ex
{
    public string Op { get; } = op;
    public Ex Left { get; } = left;
    public Ex Right { get; } = right;
    public override int Prec { get; } = prec;
    public override bool Pure => Left.Pure && Right.Pure;

    public override void Write(StringBuilder sb)
    {
        Left.Write(sb, Prec);
        sb.Append(' ').Append(Op).Append(' ');
        Right.Write(sb, Prec + 1);
    }

    public override Ex Map(Func<Ex, Ex> f) => f(new BinEx(Op, Left.Map(f), Right.Map(f), Prec));
    public override void Visit(Action<Ex> f) { f(this); Left.Visit(f); Right.Visit(f); }

    public static int PrecOf(string op) => op switch
    {
        "*" or "/" or "%" => 13, "+" or "-" => 12, "<<" or ">>" or ">>>" => 11, "<" or ">" or "<=" or ">=" or "instanceof" or "in" => 10,
        "==" or "!=" or "===" or "!==" => 9, "&" => 8, "^" => 7, "|" => 6, "&&" => 5, "||" or "??" => 4, _ => 2,
    };
}

internal sealed class UnEx(string op, Ex operand) : Ex
{
    public string Op { get; } = op;
    public Ex Operand { get; } = operand;
    public override int Prec => 15;
    public override bool Pure => Operand.Pure && Op != "delete";

    public override void Write(StringBuilder sb)
    {
        sb.Append(Op);
        if (Op is "typeof" or "delete") sb.Append(' ');
        Operand.Write(sb, 15);
    }

    public override Ex Map(Func<Ex, Ex> f) => f(new UnEx(Op, Operand.Map(f)));
    public override void Visit(Action<Ex> f) { f(this); Operand.Visit(f); }

    /// <summary>The negation of a condition: comparisons flip, double negation cancels, anything else gets '!'.</summary>
    public static Ex Not(Ex e) => e switch
    {
        UnEx { Op: "!" } u => u.Operand,
        BinEx { Op: "===" } b => new BinEx("!==", b.Left, b.Right, 9),
        BinEx { Op: "!==" } b => new BinEx("===", b.Left, b.Right, 9),
        BinEx { Op: "==" } b => new BinEx("!=", b.Left, b.Right, 9),
        BinEx { Op: "!=" } b => new BinEx("==", b.Left, b.Right, 9),
        BinEx { Op: "||" } b => new BinEx("&&", Not(b.Left), Not(b.Right), 5),
        BinEx { Op: "&&" } b => new BinEx("||", Not(b.Left), Not(b.Right), 4),
        _ => new UnEx("!", e),
    };
}

internal sealed class MemberEx(Ex obj, string name) : Ex
{
    public Ex Obj { get; } = obj;
    public string Name { get; } = name;
    public override int Prec => 18;

    public override void Write(StringBuilder sb)
    {
        if (Obj is GlobalEx && HermesNames.IsVariable(Name)) { sb.Append(Name); return; }
        Obj.Write(sb, 18);
        if (HermesNames.IsPropertyName(Name)) sb.Append('.').Append(Name);
        else sb.Append('[').Append(HermesCode.Quote(Name)).Append(']');
    }

    public override Ex Map(Func<Ex, Ex> f) => f(new MemberEx(Obj.Map(f), Name));
    public override void Visit(Action<Ex> f) { f(this); Obj.Visit(f); }
}

internal sealed class IndexEx(Ex obj, Ex key) : Ex
{
    public Ex Obj { get; } = obj;
    public Ex Key { get; } = key;
    public override int Prec => 18;

    public override void Write(StringBuilder sb)
    {
        Obj.Write(sb, 18);
        sb.Append('[');
        Key.Write(sb, 2);
        sb.Append(']');
    }

    public override Ex Map(Func<Ex, Ex> f) => f(new IndexEx(Obj.Map(f), Key.Map(f)));
    public override void Visit(Action<Ex> f) { f(this); Obj.Visit(f); Key.Visit(f); }
}

internal sealed class CallEx(Ex callee, Ex? self, Ex[] args, bool isNew) : Ex
{
    public Ex Callee { get; } = callee;
    public Ex? Self { get; } = self;
    public Ex[] Args { get; } = args;
    public bool IsNew { get; } = isNew;
    public override int Prec => !IsNew && Self != null && Callee is MemberEx { Name: "concat", Obj: MemberEx { Name: "HermesInternal", Obj: GlobalEx } } ? 12 : 18;

    public override void Write(StringBuilder sb)
    {
        // Template literals: HermesInternal.concat called on the first part.
        if (!IsNew && Self != null && Callee is MemberEx { Name: "concat", Obj: MemberEx { Name: "HermesInternal", Obj: GlobalEx } })
        {
            Self.Write(sb, 13);
            foreach (var a in Args) { sb.Append(" + "); a.Write(sb, 13); }
            return;
        }
        if (IsNew) sb.Append("new ");
        bool method = Self != null && Callee is MemberEx m && Same(m.Obj, Self) || Self != null && Callee is IndexEx x && Same(x.Obj, Self);
        if (Self == null || IsNew || method || Self is LitEx { Text: "undefined" } || Self is GlobalEx)
        {
            Callee.Write(sb, IsNew && Callee is CallEx ? 19 : 18);
            sb.Append('(');
            Join(sb, Args);
        }
        else
        {
            Callee.Write(sb, 18);
            sb.Append(".call(");
            Join(sb, [Self, .. Args]);
        }
        sb.Append(')');
    }

    private static void Join(StringBuilder sb, Ex[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            if (i > 0) sb.Append(", ");
            args[i].Write(sb, 3);
        }
    }

    /// <summary>The same register or the same object expression (a method call's receiver).</summary>
    public static bool Same(Ex a, Ex b) => a is RegEx ra && b is RegEx rb ? ra.Reg == rb.Reg : ReferenceEquals(a, b) || a is GlobalEx && b is GlobalEx;

    public override Ex Map(Func<Ex, Ex> f)
    {
        var callee = Callee.Map(f);
        // A method receiver read once for both the callee's object and 'this' stays one expression.
        var self = Self == null ? null : Callee is MemberEx m && Same(m.Obj, Self) && callee is MemberEx m2 ? m2.Obj
            : Callee is IndexEx x && Same(x.Obj, Self) && callee is IndexEx x2 ? x2.Obj : Self.Map(f);
        return f(new CallEx(callee, self, [.. Args.Select(a => a.Map(f))], IsNew));
    }

    public override void Visit(Action<Ex> f)
    {
        f(this);
        Callee.Visit(f);
        bool method = Self != null && (Callee is MemberEx m && Same(m.Obj, Self) || Callee is IndexEx x && Same(x.Obj, Self));
        if (Self != null && !method) Self.Visit(f);
        foreach (var a in Args) a.Visit(f);
    }
}

internal sealed class CondEx(Ex test, Ex then, Ex otherwise) : Ex
{
    public override int Prec => 3;
    public override void Write(StringBuilder sb)
    {
        test.Write(sb, 4);
        sb.Append(" ? ");
        then.Write(sb, 3);
        sb.Append(" : ");
        otherwise.Write(sb, 3);
    }

    public override Ex Map(Func<Ex, Ex> f) => f(new CondEx(test.Map(f), then.Map(f), otherwise.Map(f)));
    public override void Visit(Action<Ex> f) { f(this); test.Visit(f); then.Visit(f); otherwise.Visit(f); }
}

/// <summary>A statement: one per instruction before structuring, and the structured forms after.</summary>
internal abstract class St
{
    public virtual long? Def => null;
    public virtual IEnumerable<Ex> Exprs => [];
    public virtual bool SideEffects => true;
    public virtual St Map(Func<Ex, Ex> f) => this;
}

internal sealed class AssignSt(long reg, Ex value, long[]? extra = null) : St
{
    public long Reg { get; } = reg;
    public Ex Value { get; } = value;

    /// <summary>Registers the instruction writes besides <see cref="Reg"/> (iterator and generator state); such an assignment stays where it is.</summary>
    public long[] Extra { get; } = extra ?? [];
    public override long? Def => Reg;
    public override IEnumerable<Ex> Exprs => [Value];
    public override bool SideEffects => !Value.Pure || Extra.Length > 0;
    public override St Map(Func<Ex, Ex> f) => new AssignSt(Reg, Value.Map(f), Extra);
}

/// <summary>Statements one instruction becomes; flattened into the block.</summary>
internal sealed class SeqSt(St[] items) : St
{
    public St[] Items { get; } = items;
}

/// <summary>target = value, for properties, closure variables and globals.</summary>
internal sealed class StoreSt(Ex target, Ex value, string op = "=") : St
{
    public Ex Target { get; } = target;
    public Ex Value { get; } = value;
    public string Op { get; } = op;
    public override IEnumerable<Ex> Exprs => [Target, Value];
    public override St Map(Func<Ex, Ex> f) => new StoreSt(Target.Map(f), Value.Map(f), Op);
}

internal sealed class ExprSt(Ex value) : St
{
    public Ex Value { get; } = value;
    public override IEnumerable<Ex> Exprs => [Value];
    public override St Map(Func<Ex, Ex> f) => new ExprSt(Value.Map(f));
}

/// <summary>return, throw: the function ends here.</summary>
internal sealed class ExitSt(string keyword, Ex value) : St
{
    public string Keyword { get; } = keyword;
    public Ex Value { get; } = value;
    public override IEnumerable<Ex> Exprs => [Value];
    public override St Map(Func<Ex, Ex> f) => new ExitSt(Keyword, Value.Map(f));
}

/// <summary>Text for what has no JavaScript form (generator steps, declarations); reads the registers it names.</summary>
internal sealed class RawSt(string text, Ex[]? reads = null) : St
{
    public string Text { get; } = text;
    public Ex[] Reads { get; } = reads ?? [];
    public override IEnumerable<Ex> Exprs => Reads;
    public override St Map(Func<Ex, Ex> f) => new RawSt(Text, [.. Reads.Select(r => r.Map(f))]);
}

/// <summary>Block terminators before structuring.</summary>
internal sealed class BranchSt(Ex cond, int target) : St
{
    public Ex Cond { get; } = cond;
    public int Target { get; } = target;
    public override IEnumerable<Ex> Exprs => [Cond];
    public override St Map(Func<Ex, Ex> f) => new BranchSt(Cond.Map(f), Target);
}

internal sealed class JumpSt(int target) : St
{
    public int Target { get; } = target;
    public override bool SideEffects => false;
}

internal sealed class SwitchSt(Ex value, HermesSwitch table) : St
{
    public Ex Value { get; } = value;
    public HermesSwitch Table { get; } = table;
    public override IEnumerable<Ex> Exprs => [Value];
    public override St Map(Func<Ex, Ex> f) => new SwitchSt(Value.Map(f), Table);
}

// Structured statements.
internal sealed class IfSt(Ex cond, List<St> then, List<St> otherwise) : St
{
    public Ex Cond { get; set; } = cond;
    public List<St> Then { get; set; } = then;
    public List<St> Else { get; set; } = otherwise;
}

internal sealed class LoopSt(List<St> body, string label) : St
{
    public List<St> Body { get; set; } = body;
    public string Label { get; } = label;
    public Ex? While { get; set; }
    public Ex? DoWhile { get; set; }
    public bool Labelled { get; set; }
}

internal sealed class JumpOutSt(string keyword, string? label) : St
{
    public string Keyword { get; } = keyword;
    public string? Label { get; } = label;
}

internal sealed class TrySt(List<St> body, List<St> handler) : St
{
    public List<St> Body { get; } = body;
    public List<St> Handler { get; } = handler;
}

internal sealed class SwitchBlockSt(Ex value, List<(List<long> Values, bool Default, List<St> Body)> cases, string label) : St
{
    public Ex Value { get; } = value;
    public List<(List<long> Values, bool Default, List<St> Body)> Cases { get; } = cases;
    public string Label { get; } = label;
    public bool Labelled { get; set; }
}

internal sealed class GotoSt(int target) : St
{
    public int Target { get; } = target;
}

internal sealed class LabelSt(int offset) : St
{
    public int Offset { get; } = offset;
    public override bool SideEffects => false;
}
