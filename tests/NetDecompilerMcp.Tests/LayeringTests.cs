using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Project layering, checked on the built assembly's metadata. Layers are the namespaces under NetDecompilerMcp
/// (Core, Native, Services, Tools, Mcp, Setup; the root holds Program and ServerInstructions). Core and Native are the
/// bottom and may use each other; Services builds on them; Tools and Mcp on Services; Setup only on Mcp; Relay only on Native.
/// </summary>
public class LayeringTests
{
    /// <summary>What each layer may not reference; "" is the root. Nested namespaces belong to their top-level layer.</summary>
    private static readonly Dictionary<string, string[]> Forbidden = new()
    {
        ["Core"] = ["Services", "Tools", "Mcp", "Setup", ""],
        ["Native"] = ["Services", "Tools", "Mcp", "Setup", ""],
        ["Services"] = ["Tools", "Mcp", "Setup", ""],
        ["Mcp"] = ["Tools", "Setup", ""],
        ["Setup"] = ["Services", "Tools", ""],
        // The development relay stays small: process ownership from Native, nothing that analyzes.
        ["Relay"] = ["Core", "Services", "Tools", "Mcp", "Setup", ""],
    };

    [Fact]
    public void LowerLayers_DoNotReferenceUpperLayers()
    {
        var edges = Dependencies();
        Assert.Contains(edges, e => Layer(e.From) == "Tools" && Layer(e.To) == "Services"); // the scan sees references at all
        var problems = edges
            .Where(e => Forbidden.TryGetValue(Layer(e.From), out var no) && no.Contains(Layer(e.To)))
            .Select(e => $"{e.From} -> {e.To}")
            .Order(StringComparer.Ordinal).ToList();
        Assert.True(problems.Count == 0, "Layering violations:\n" + string.Join("\n", problems));
    }

    private const string Root = "NetDecompilerMcp";

    /// <summary>The top-level layer of a type's namespace: "Core" for NetDecompilerMcp.Core.X, "" for the root.</summary>
    private static string Layer(string typeName)
    {
        var rest = typeName.Substring(Root.Length).TrimStart('.');
        int dot = rest.IndexOf('.');
        return dot < 0 ? "" : rest[..dot];
    }

    /// <summary>Distinct (from type, to type) references between this assembly's top-level types.</summary>
    private static HashSet<(string From, string To)> Dependencies()
    {
        using var module = ModuleDefMD.Load(typeof(NetDecompilerMcp.Core.ToolError).Assembly.Location);
        // Types in parallel (dnlib reads thread-safely): one thread took 8-25 s, the quick suite's longest test.
        var edges = new System.Collections.Concurrent.ConcurrentDictionary<(string, string), byte>();
        Parallel.ForEach(module.GetTypes().ToList(), type =>
        {
            var from = TopLevel(type);
            if (!Ours(from)) return;
            var refs = new References(module);
            refs.Visit(type);
            foreach (var to in refs.Found)
                if (to != from && Ours(to)) edges.TryAdd((from.FullName, to.FullName), 0);
        });
        return edges.Keys.ToHashSet();
    }

    /// <summary>In the NetDecompilerMcp namespace tree; excludes compiler-generated helpers and generated regex types.</summary>
    private static bool Ours(TypeDef t) => t.Namespace == Root || t.Namespace.String.StartsWith(Root + ".", StringComparison.Ordinal);

    private static TypeDef TopLevel(TypeDef t)
    {
        while (t.DeclaringType != null) t = t.DeclaringType;
        return t;
    }

    /// <summary>Every type of the module a type definition reaches: signatures, base types, attributes and method bodies.</summary>
    private sealed class References(ModuleDef module)
    {
        public readonly HashSet<TypeDef> Found = new();
        private readonly HashSet<object> _seen = new();

        public void Visit(TypeDef type)
        {
            Add(type.BaseType);
            foreach (var i in type.Interfaces) Add(i.Interface);
            Attributes(type);
            Generics(type.GenericParameters);
            foreach (var f in type.Fields) { Sig(f.FieldSig?.Type); Attributes(f); }
            foreach (var p in type.Properties) { Sig(p.PropertySig); Attributes(p); }
            foreach (var e in type.Events) { Add(e.EventType); Attributes(e); }
            foreach (var m in type.Methods) Method(m);
        }

        private void Method(MethodDef m)
        {
            Sig(m.MethodSig);
            Attributes(m);
            foreach (var p in m.ParamDefs) Attributes(p);
            Generics(m.GenericParameters);
            foreach (var o in m.Overrides) { Member(o.MethodBody); Member(o.MethodDeclaration); }
            if (!m.HasBody) return;
            foreach (var l in m.Body.Variables) Sig(l.Type);
            foreach (var h in m.Body.ExceptionHandlers) Add(h.CatchType);
            foreach (var i in m.Body.Instructions)
                switch (i.Operand)
                {
                    case ITypeDefOrRef t: Add(t); break;
                    case IMethod or IField: Member((IMemberRef)i.Operand); break;
                    case MethodSig s: Sig(s); break; // calli
                }
        }

        private void Generics(IEnumerable<GenericParam> parameters)
        {
            foreach (var g in parameters)
                foreach (var c in g.GenericParamConstraints) Add(c.Constraint);
        }

        private void Attributes(IHasCustomAttribute owner)
        {
            foreach (var a in owner.CustomAttributes)
            {
                Member(a.Constructor);
                foreach (var arg in a.ConstructorArguments.Concat(a.NamedArguments.Select(n => n.Argument))) Argument(arg);
            }
        }

        private void Argument(CAArgument arg)
        {
            Sig(arg.Type);
            if (arg.Value is TypeSig t) Sig(t);
            else if (arg.Value is IList<CAArgument> list) foreach (var a in list) Argument(a);
            else if (arg.Value is CAArgument boxed) Argument(boxed);
        }

        private void Member(IMemberRef? member)
        {
            switch (member)
            {
                case MethodSpec spec: Member(spec.Method); foreach (var g in spec.GenericInstMethodSig?.GenericArguments ?? []) Sig(g); break;
                case MemberRef mr: Add(mr.DeclaringType); Sig(mr.Signature as MethodSig); Sig((mr.Signature as FieldSig)?.Type); break;
                case MethodDef md: Add(md.DeclaringType); break;
                case FieldDef fd: Add(fd.DeclaringType); break;
            }
        }

        private void Sig(CallingConventionSig? sig)
        {
            if (sig is MethodBaseSig m)
            {
                Sig(m.RetType);
                foreach (var p in m.Params) Sig(p);
                foreach (var p in m.ParamsAfterSentinel ?? []) Sig(p);
            }
        }

        private void Sig(TypeSig? sig)
        {
            while (sig != null && _seen.Add(sig))
            {
                switch (sig)
                {
                    case TypeDefOrRefSig t: Add(t.TypeDefOrRef); return;
                    case GenericInstSig g: Sig(g.GenericType); foreach (var a in g.GenericArguments) Sig(a); return;
                    case FnPtrSig f: Sig(f.MethodSig); return;
                    case ModifierSig mod: Add(mod.Modifier); break;
                }
                sig = sig.Next;
            }
        }

        private void Add(ITypeDefOrRef? t)
        {
            switch (t)
            {
                case TypeDef d when d.Module == module: Found.Add(TopLevel(d)); break;
                case TypeSpec s: Sig(s.TypeSig); break;
            }
        }
    }
}
