using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Corvus.Tests;

/// <summary>Namespaces under Corvus layer as Core and Native, then Services, then Tools and Mcp, then Setup; Relay uses only Native.</summary>
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
    public void Lower_layers_do_not_reference_upper_layers()
    {
        var edges = Dependencies();
        Assert.Contains(edges, e => Layer(e.From) == "Tools" && Layer(e.To) == "Services"); // the scan sees references at all
        var problems = edges
            .Where(e => Forbidden.TryGetValue(Layer(e.From), out var no) && no.Contains(Layer(e.To)))
            .Select(e => $"{e.From} -> {e.To}")
            .Order(StringComparer.Ordinal).ToList();
        Assert.True(problems.Count == 0, "Layering violations:\n" + string.Join("\n", problems));
    }

    // Files that write what the server names itself (caches, staging and
    // temporary folders), with their write counts; every other write goes
    // through SafeFile.
    private static readonly Dictionary<string, (int Writes, string Reason)> OwnFileWriters = new(StringComparer.Ordinal)
    {
        ["Services/Analysis/Dependencies/OsvAdvisories.cs"] = (1, "the component list osv-scanner reads, in a private temporary folder"),
        ["Services/Analysis/NativeCapa.cs"] = (1, "a copy of the input for capa, in a private temporary folder"),
        ["Services/Analysis/ProgramEmulationOps.cs"] = (4, "the emulator's input copy, saved files and regions, in the folder the emulation names"),
        ["Services/Analysis/WebGlBuild.cs"] = (2, "unpacked build files in the cache folder"),
        ["Services/AotBuild/AotBuildLoader.cs"] = (1, "the cache marker in the data folder's staging folder"),
        ["Services/AotBuild/AotBuildModel.cs"] = (2, "the saved model in the data folder's cache"),
        ["Services/AotBuild/AotDummyBuilder.cs"] = (1, "dummy assemblies in the data folder's cache"),
        ["Services/AotBuild/AotMetadataOnly.cs"] = (1, "dummy assemblies in the data folder's cache"),
        ["Services/AotBuild/AotPackages.cs"] = (2, "files read from a package, in the data folder's cache"),
        ["Services/AotBuild/CacheHolds.cs"] = (2, "lock files in the data folder's cache"),
        ["Services/AotMetadata/AotCapa.cs"] = (1, "the feature file capa reads, in a private temporary folder"),
        ["Services/Dotnet/DecompilerService.cs"] = (10, "project files in the export's staging folder, checked by ExportDirectory before the commit"),
        ["Services/Dotnet/ExportDirectory.cs"] = (1, "the export marker in the staging folder"),
        ["Services/Engines/NativeEngineService.cs"] = (1, "the patched bytes an engine opens, in a private temporary folder"),
        ["Services/Engines/PackedDatabaseInput.cs"] = (5, "a copy of a packed engine database in the engine's cache folder"),
        ["Services/Live/LiveYara.cs"] = (1, "the memory capture index in a private temporary folder"),
        ["Services/Mobile/JavaSourceCache.cs"] = (2, "decompiled sources in the data folder's cache"),
    };

    private static readonly System.Text.RegularExpressions.Regex FileWrite = new(
        @"(?<![\w.])File\.(?:Write\w*|AppendAll\w*|AppendText|Move|Copy|Create|CreateText|OpenWrite)\s*\(" +
        @"|new\s+FileStream\s*\([^;]*?(?:FileMode\.(?:Create|CreateNew|OpenOrCreate|Append|Truncate)|FileAccess\.(?:Write|ReadWrite))");

    [Fact]
    public void Tools_and_services_write_files_only_through_SafeFile()
    {
        var src = Path.Combine(DocsTests.RepoRoot(), "src", Root);
        var found = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var folder in new[] { "Tools", "Services" })
            foreach (var file in Directory.EnumerateFiles(Path.Combine(src, folder), "*.cs", SearchOption.AllDirectories))
            {
                var code = string.Join('\n', File.ReadLines(file).Where(l => !l.TrimStart().StartsWith("//", StringComparison.Ordinal)));
                if (FileWrite.Count(code) is var n and > 0) found[Path.GetRelativePath(src, file).Replace('\\', '/')] = n;
            }
        var problems = found.Where(f => !OwnFileWriters.TryGetValue(f.Key, out var allowed) || allowed.Writes != f.Value)
            .Select(f => $"{f.Key}: {f.Value} write(s)")
            .Concat(OwnFileWriters.Keys.Where(k => !found.ContainsKey(k)).Select(k => $"{k}: listed but writes nothing"))
            .Order(StringComparer.Ordinal).ToList();
        Assert.True(problems.Count == 0, "Writes outside SafeFile:\n" + string.Join("\n", problems));
    }

    private static readonly System.Text.RegularExpressions.Regex HttpConstruction = new(
        @"new\s+(?:HttpClient|HttpClientHandler|SocketsHttpHandler|WebClient|HttpMessageInvoker)\s*\(|\b(?:Http)?WebRequest\.Create(?:Http)?\s*\(");

    private static readonly System.Text.RegularExpressions.Regex StringLiteral = new(@"""(?:[^""\\\n]|\\.)*""");

    [Fact]
    public void Only_the_network_policy_builds_an_http_client()
    {
        var src = Path.Combine(DocsTests.RepoRoot(), "src", Root);
        var problems = new List<string>();
        foreach (var file in Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(src, file).Replace('\\', '/');
            if (relative == "Core/NetworkPolicy.cs" || relative.Contains("/obj/", StringComparison.Ordinal) || relative.StartsWith("obj/", StringComparison.Ordinal)) continue;
            var code = StringLiteral.Replace(string.Join('\n', File.ReadLines(file).Where(l => !l.TrimStart().StartsWith("//", StringComparison.Ordinal))), "\"\"");
            if (HttpConstruction.Count(code) is var n and > 0) problems.Add($"{relative}: {n}");
        }
        Assert.True(problems.Count == 0, "HTTP clients outside NetworkPolicy:\n" + string.Join("\n", problems));
    }

    private const string Root = "Corvus";

    /// <summary>The top-level layer of a type's namespace: "Core" for Corvus.Core.X, "" for the root.</summary>
    private static string Layer(string typeName)
    {
        var rest = typeName.Substring(Root.Length).TrimStart('.');
        int dot = rest.IndexOf('.');
        return dot < 0 ? "" : rest[..dot];
    }

    /// <summary>Distinct (from type, to type) references between this assembly's top-level types.</summary>
    private static HashSet<(string From, string To)> Dependencies()
    {
        using var module = ModuleDefMD.Load(typeof(Corvus.Core.ToolError).Assembly.Location);
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

    /// <summary>In the Corvus namespace tree; excludes compiler-generated helpers and generated regex types.</summary>
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
