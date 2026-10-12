using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Simplify;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class DecompileTools(AssemblyWorkspace workspace, DecompilerService decompiler, OutputPager pager, NotesService? notes = null,
    Services.Mobile.AndroidProjectExport? android = null)
{
    private const int MaxMembersPerCall = 25;

    [McpServerTool(Name = "decompile_type", Title = "Decompile type to C#")]
    [Description("Decompile a whole type (nested types included) to C#; decompile_member is cheaper for one method. A method that breaks the decompiler is shown as IL.")]
    public Task<string> DecompileType(
        [Description(SymbolDescription)] string type,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(SimplifiedDescription)] bool simplified = false,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, type, SymbolKind.Type);
        return pager.Page(TypeSource(sym, simplified, cancellationToken), offset, maxTokens);
    }, cancellationToken);

    [McpServerTool(Name = "decompile_member", Title = "Decompile member to C#")]
    [Description("Decompile a method, property, field, event or constructor to C#: every overload unless a parameter list narrows it; async / iterator state " +
                 "machines and lambdas fold back into the method. A type name decompiles the whole type.")]
    public Task<string> DecompileMember(
        [Description(SymbolDescription)] string member,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Restrict to this kind (default any).")] string? kind = null,
        [Description(SimplifiedDescription)] bool simplified = false,
        [Description("Start with comments pinning the output to its build: SHA-256, MVID, tokens, IL hashes (docs/il-hash.md).")] bool provenance = false,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var all = SymbolResolver.Resolve(workspace, assembly, member, SymbolResolver.ParseKind(kind));
        var header = offset == 0 ? NotesHeader(all) : "";
        if (all.Count == 1 && all[0].Member is TypeDef)
            return header + pager.Page((provenance ? Provenance(all[0].Assembly, [all[0].Member]) : "") + TypeSource(all[0], simplified, cancellationToken), offset, maxTokens);
        RequireFew(all, member);

        var text = pager.GetOrCreate(CacheKey((simplified ? "member-simplified" : "member") + (provenance ? "-provenance" : ""), all), () =>
            string.Join("\n", all.GroupBy(a => a.Assembly).Select(g =>
                $"// [{g.Key.Id}]\n" + (provenance ? Provenance(g.Key, g.Select(s => s.Member)) : "") + (simplified
                    ? decompiler.DecompileSimplified(g.Key, g.Select(s => s.Member).ToList(), new SimplifyOptions(), cancellationToken)
                    : decompiler.DecompileMembers(g.Key, g.Select(s => s.Member), cancellationToken)))));
        return header + pager.Page(text, offset, maxTokens);
    }, cancellationToken);

    /// <summary>One line when the members (a type: and its members) have open notes; empty otherwise, so it costs nothing without notes.</summary>
    private string NotesHeader(IReadOnlyList<ResolvedSymbol> symbols)
    {
        if (notes == null) return "";
        int open = 0;
        foreach (var g in symbols.GroupBy(s => s.Assembly))
        {
            if (g.Key.Module.Mvid is not { } mvid) continue;
            var tokens = g.SelectMany(s => s.Member is TypeDef t
                ? t.Methods.Cast<IMemberDef>().Concat(t.Fields).Concat(t.Properties).Concat(t.Events).Append(t)
                : [s.Member]).Select(m => m.MDToken.Raw).ToHashSet();
            open += notes.OpenCount(new NoteAnchor(NoteAnchor.DotNet, Mvid: mvid.ToString()).StoreKey, a => a.Token is { } token && tokens.Contains(token));
        }
        var first = symbols.Count > 0 ? symbols[0] : null;
        return first == null ? "" : NotesService.Header(open, symbols.Count == 1 ? $"{first.Assembly.Id}:{Format.Token(first.Member)}" : first.Assembly.Id);
    }

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
    [Description("IL disassembly (ildasm style, /* token */ comments, offsets, try blocks) of a member or type; each method starts with its normalized IL hash " +
                 "(stable across rebuilds) and raw IL SHA-256. For when the C# looks wrong, transformed code, or as patch_method_il input.")]
    public Task<string> GetIL(
        [Description(SymbolDescription)] string symbol,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var all = SymbolResolver.Resolve(workspace, assembly, symbol);
        RequireFew(all, symbol);
        var text = pager.GetOrCreate(CacheKey("il", all), () => string.Join("\n", all.Select(s =>
            $"// [{s.Assembly.Id}] {s.Label}\n{HashLines(s)}{decompiler.Disassemble(s.Assembly, s.Member, cancellationToken)}")));
        return pager.Page(text, offset, maxTokens);
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
    [Description("Decompile an assembly into a C# project on disk (.cs per type, .csproj, resources), to grep or browse a large codebase with file tools. " +
                 "An .apk / .aab path gives a Gradle project (decoded manifest and resources, Java through JADX when configured, else smali).")]
    public Task<string> ExportProject(
        [Description(AssemblyDescription)] string assembly,
        [Description("Empty or new output directory.")] string outputDirectory,
        RequestContext<CallToolRequestParams> context = null!, // bound by the SDK
        CancellationToken cancellationToken = default)
    {
        if (android != null && Services.Mobile.AndroidProjectExport.IsPackagePath(assembly) && File.Exists(assembly.Trim()))
            return OrderedProgress.Run(context, async progress =>
            {
                var r = await android.Export(assembly.Trim(), outputDirectory, (done, total, status) => Report(progress, done, total, status), cancellationToken).ConfigureAwait(false);
                var summary = $"Exported {Path.GetFileName(assembly.Trim())} to {r.Directory} as a Gradle project: {r.Files} files, {r.Classes} classes as {r.Sources}" +
                              (r.SourceFailures > 0 ? $" ({r.SourceFailures} failed; their files hold the error)" : "") + ".";
                return r.Notes.Count == 0 ? summary : summary + "\n" + string.Join("\n", r.Notes.Take(20));
            });
        return ExportAssembly(assembly, outputDirectory, context, cancellationToken);
    }

    private Task<string> ExportAssembly(string assembly, string outputDirectory, RequestContext<CallToolRequestParams> context, CancellationToken cancellationToken) =>
        OrderedProgress.Run(context, progress => Read(workspace, () =>
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
        "Show the code as simplify_methods would leave it, without changing the assembly.";

    private string TypeSource(ResolvedSymbol sym, bool simplified, CancellationToken ct) =>
        pager.GetOrCreate(CacheKey(simplified ? "type-simplified" : "type", [sym]), () => $"// [{sym.Assembly.Id}] {sym.Label}\n" + (simplified
            ? decompiler.DecompileSimplified(sym.Assembly, [sym.Member], new SimplifyOptions(), ct)
            : decompiler.DecompileType(sym.Assembly, (TypeDef)sym.Member, ct)));

    private string CacheKey(string kind, IEnumerable<ResolvedSymbol> symbols) =>
        $"{workspace.Generation}|{kind}|{string.Join(",", symbols.Select(s => s.Assembly.Id + (s.Member.MDToken.Rid != 0 ? Format.Token(s.Member) : Format.MemberLabel(s.Member))))}"; // added members share token (new)

    private static void RequireFew(IReadOnlyList<ResolvedSymbol> all, string query)
    {
        if (all.Count > MaxMembersPerCall)
            throw new ToolError(ErrorCode.Ambiguous, $"'{query}' matches {all.Count} symbols; narrow it with a type name, parameter list or token. First matches:\n" +
                                string.Join("\n", all.Take(MaxMembersPerCall).Select(a => "  " + a)));
    }
}
