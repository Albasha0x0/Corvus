using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Services.Simplify;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class DecompileTools(AssemblyWorkspace workspace, DecompilerService decompiler, OutputPager pager)
{
    private const int MaxMembersPerCall = 25;

    [McpServerTool(Name = "decompile_type", Title = "Decompile type to C#")]
    [Description("Decompile a whole type (class/struct/interface/enum/delegate, including nested types) to C#. Long output is paged: call again with the offset from the footer. " +
                 "If one method breaks the decompiler, the rest is still returned with IL for the broken part.")]
    public Task<string> DecompileType(
        [Description("Type name or token. " + SymbolDescription)] string type,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(SimplifiedDescription)] bool simplified = false,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, type, SymbolKind.Type);
        return pager.Page(TypeSource(sym, simplified, cancellationToken), offset, maxChars);
    }, cancellationToken);

    [McpServerTool(Name = "decompile_member", Title = "Decompile member to C#")]
    [Description("Decompile a method, property, field, event or constructor to C#. When a name has several overloads all are returned, unless a parameter list narrows it ('Ns.Type::Foo(int, string)'). " +
                 "Async/iterator state machines and lambdas are folded back into the original method. A type name decompiles the whole type.")]
    public Task<string> DecompileMember(
        [Description(SymbolDescription)] string member,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Restrict to: method, field, property, event (default any).")] string? kind = null,
        [Description(SimplifiedDescription)] bool simplified = false,
        [Description("Start with comment lines that pin the output to its build: file SHA-256 and MVID, each member's token, and for methods " +
                     "the normalized IL hash and the raw IL SHA-256 (docs/il-hash.md).")] bool provenance = false,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var all = SymbolResolver.Resolve(workspace, assembly, member, SymbolResolver.ParseKind(kind));
        if (all.Count == 1 && all[0].Member is TypeDef)
            return pager.Page((provenance ? Provenance(all[0].Assembly, [all[0].Member]) : "") + TypeSource(all[0], simplified, cancellationToken), offset, maxChars);
        RequireFew(all, member);

        var text = pager.GetOrCreate(CacheKey((simplified ? "member-simplified" : "member") + (provenance ? "-provenance" : ""), all), () =>
            string.Join("\n", all.GroupBy(a => a.Assembly).Select(g =>
                $"// [{g.Key.Id}]\n" + (provenance ? Provenance(g.Key, g.Select(s => s.Member)) : "") + (simplified
                    ? decompiler.DecompileSimplified(g.Key, g.Select(s => s.Member).ToList(), new SimplifyOptions(), cancellationToken)
                    : decompiler.DecompileMembers(g.Key, g.Select(s => s.Member), cancellationToken)))));
        return pager.Page(text, offset, maxChars);
    }, cancellationToken);

    /// <summary>Comment lines tying decompiled output to its build; hashes in full (docs/il-hash.md).</summary>
    private static string Provenance(LoadedAssembly asm, IEnumerable<IMemberDef> members)
    {
        var sb = new StringBuilder($"// Provenance: {asm.BuildIdentity}{(asm.IsDirty ? " (file as loaded; unsaved edits not included)" : "")}\n");
        using var raw = IlHash.RawReader(asm);
        foreach (var m in members)
        {
            sb.Append("//   ").Append(Format.MemberLabel(m)).Append("  token ").Append(Format.Token(m)).Append('\n');
            IEnumerable<MethodDef> methods = m switch
            {
                MethodDef md => [md],
                PropertyDef p => p.GetMethods.Concat(p.SetMethods).Concat(p.OtherMethods),
                EventDef e => new[] { e.AddMethod, e.RemoveMethod, e.InvokeMethod }.Where(x => x != null).Concat(e.OtherMethods),
                _ => [],
            };
            foreach (var method in methods)
                sb.Append("//     ").Append(m is MethodDef ? "" : $"{method.Name} {Format.Token(method)}: ").Append("IL hash ").Append(IlHash.Of(asm, method) ?? "none")
                  .Append("  raw IL SHA-256 ").Append(IlHash.RawSha256(raw, method) ?? "none").Append('\n');
        }
        return sb.ToString();
    }

    [McpServerTool(Name = "get_il", Title = "IL disassembly")]
    [Description("IL disassembly (ildasm style, with /* metadata token */ comments, IL offsets and structured try/catch blocks) of a method, field, property, event, or a whole type. " +
                 "Each method starts with its normalized IL hash (stable across rebuilds), the SHA-256 of its raw IL bytes (exact build) and any invalid exception clause. " +
                 "Use it when the C# looks wrong, for transformed code, or as the starting point for patch_method_il.")]
    public Task<string> GetIL(
        [Description(SymbolDescription)] string symbol,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var all = SymbolResolver.Resolve(workspace, assembly, symbol);
        RequireFew(all, symbol);
        var text = pager.GetOrCreate(CacheKey("il", all), () => string.Join("\n", all.Select(s =>
            $"// [{s.Assembly.Id}] {s.Label}\n{HashLines(s)}{decompiler.Disassemble(s.Assembly, s.Member, cancellationToken)}")));
        return pager.Page(text, offset, maxChars);
    }, cancellationToken);

    /// <summary>One "// IL hash:" line per method of the symbol with its raw IL SHA-256 (docs/il-hash.md), and the method's name unless the symbol is that method.</summary>
    private static string HashLines(ResolvedSymbol s)
    {
        IEnumerable<MethodDef> methods = s.Member switch
        {
            MethodDef m => [m],
            PropertyDef p => p.GetMethods.Concat(p.SetMethods).Concat(p.OtherMethods),
            EventDef e => new[] { e.AddMethod, e.RemoveMethod, e.InvokeMethod }.Where(m => m != null).Concat(e.OtherMethods),
            TypeDef t => t.Methods,
            _ => [],
        };
        var sb = new StringBuilder();
        using var raw = IlHash.RawReader(s.Assembly);
        foreach (var m in methods)
        {
            var hash = IlHash.Of(s.Assembly, m);
            var value = hash != null ? IlHash.Short(hash)
                : m.RVA == 0 && MetadataUtil.SafeBody(m) == null ? "none (no body)" : "none (body not valid IL)";
            sb.Append("// IL hash: ").Append(value);
            if (IlHash.RawSha256(raw, m) is { } bytes)
                sb.Append("  raw IL SHA-256: ").Append(IlHash.Short(bytes)).Append(s.Assembly.IsDirty ? " (file as loaded)" : "");
            if (s.Member is not MethodDef) sb.Append("  ").Append(m.Name).Append('(').Append(Format.ParameterTypes(m.MethodSig)).Append(')');
            sb.Append('\n');
            if (!s.Assembly.IsDirty)
                foreach (var issue in s.Assembly.BodyHealth.ClauseIssues(m))
                    sb.Append("// invalid exception clause: ").Append(issue).Append('\n');
        }
        return sb.ToString();
    }

    [McpServerTool(Name = "decompile_assembly_attributes", Title = "Decompile assembly attributes")]
    [Description("Decompile assembly- and module-level attributes (InternalsVisibleTo, versions, TargetFramework...) to C#.")]
    public Task<string> DecompileAssemblyAttributes(
        [Description(AssemblyDescription)] string assembly,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
            pager.Page(decompiler.DecompileAssemblyAttributes(workspace.Get(assembly), cancellationToken)), cancellationToken);

    [McpServerTool(Name = "export_project", Title = "Export C# project")]
    [Description("Decompile an entire assembly into a C# project on disk (one .cs file per type, a .csproj, and resources). Best way to grep or browse a large codebase with normal file tools. Reports progress.")]
    public Task<string> ExportProject(
        [Description(AssemblyDescription)] string assembly,
        [Description("Empty or new output directory.")] string outputDirectory,
        RequestContext<CallToolRequestParams> context = null!, // bound by the SDK
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, progress => Read(workspace, () =>
    {
        var asm = workspace.Get(assembly);
        var result = decompiler.ExportProject(asm, outputDirectory, (done, total, status) => Report(progress, done, total, status), cancellationToken);
        var summary = $"Exported {asm.Id} to {result.Directory}: {result.FileCount} files.{(result.ProjectFile != null ? $" Project: {result.ProjectFile}" : "")}";
        if (result.FailedTypes.Count > 0)
            summary += $"\n{Plural(result.FailedTypes.Count, "type")} failed to decompile (their files contain the error):\n  " +
                       string.Join("\n  ", result.FailedTypes.Take(20));
        return summary;
    }, cancellationToken));

    private const string SimplifiedDescription =
        "Show the code as simplify_methods would leave it (constant strings folded, dead branches removed, forwarders inlined), without changing the assembly.";

    private string TypeSource(ResolvedSymbol sym, bool simplified, CancellationToken ct) =>
        pager.GetOrCreate(CacheKey(simplified ? "type-simplified" : "type", [sym]), () => $"// [{sym.Assembly.Id}] {sym.Label}\n" + (simplified
            ? decompiler.DecompileSimplified(sym.Assembly, [sym.Member], new SimplifyOptions(), ct)
            : decompiler.DecompileType(sym.Assembly, (TypeDef)sym.Member, ct)));

    private string CacheKey(string kind, IEnumerable<ResolvedSymbol> symbols) =>
        $"{workspace.Generation}|{kind}|{string.Join(",", symbols.Select(s => s.Assembly.Id + Format.Token(s.Member)))}";

    private static void RequireFew(IReadOnlyList<ResolvedSymbol> all, string query)
    {
        if (all.Count > MaxMembersPerCall)
            throw new ToolError(ErrorCode.Ambiguous, $"'{query}' matches {all.Count} symbols; narrow it with a type name, parameter list or token. First matches:\n" +
                                string.Join("\n", all.Take(MaxMembersPerCall).Select(a => "  " + a)));
    }
}
