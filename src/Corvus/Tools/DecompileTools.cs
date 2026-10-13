using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using Corvus.Services.Simplify;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class DecompileTools(AssemblyWorkspace workspace, DecompilerService decompiler, OutputPager pager, NotesService? notes = null,
    Services.Mobile.AndroidProjectExport? android = null, ServerOptions? options = null)
{
    private const int MaxMembersPerCall = 25;

    [McpServerTool(Name = "decompile_member", Title = "Decompile to C#", UseStructuredContent = true, OutputSchemaType = typeof(CodePage))]
    [Description("Decompile a type, method, property, field, event or constructor to C#: every overload unless a parameter list narrows it; async / iterator " +
                 "state machines and lambdas fold back into the method; a type decompiles whole (nested types included). A method that breaks the decompiler is shown as IL.")]
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
        {
            var source = (provenance ? Provenance(all[0].Assembly, [all[0].Member]) : "") + TypeSource(all[0], simplified, cancellationToken);
            return header + ToolOutput.Text(pager, source, offset, Page("csharp", all), maxTokens);
        }
        RequireFew(all, member);

        var text = pager.GetOrCreate(CacheKey((simplified ? "member-simplified" : "member") + (provenance ? "-provenance" : ""), all), () =>
            string.Join("\n", all.GroupBy(a => a.Assembly).Select(g =>
                $"// [{g.Key.Id}]\n" + (provenance ? Provenance(g.Key, g.Select(s => s.Member)) : "") + (simplified
                    ? decompiler.DecompileSimplified(g.Key, g.Select(s => s.Member).ToList(), new SimplifyOptions(), cancellationToken)
                    : decompiler.DecompileMembers(g.Key, g.Select(s => s.Member), cancellationToken)))));
        return header + ToolOutput.Text(pager, text, offset, Page("csharp", all), maxTokens);
    }, cancellationToken);

    /// <summary>The record of a code page; the call filter fills in the page.</summary>
    private static CodePage Page(string language, IReadOnlyList<ResolvedSymbol> symbols, IReadOnlyList<IlMethodHash>? methods = null) =>
        new(language, "", 0, null, 0) { Symbols = symbols.Select(SymbolRef.Of).ToList(), Methods = methods };

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

    [McpServerTool(Name = "get_il", Title = "IL disassembly", UseStructuredContent = true, OutputSchemaType = typeof(CodePage))]
    [Description("IL disassembly (ildasm style, tokens, offsets, try blocks) of a member or type; each method starts with its normalized IL hash " +
                 "(stable across rebuilds) and raw IL SHA-256. For when the C# looks wrong, or as patch_method_il input.")]
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
        var hashes = all.SelectMany(s =>
        {
            using var raw = IlHash.RawReader(s.Assembly);
            return MethodsOf(s.Member).Select(m => new IlMethodHash(Format.Token(m), IlHash.Of(s.Assembly, m), IlHash.RawSha256(raw, m))).ToList();
        }).Take(200).ToList();
        return ToolOutput.Text(pager, text, offset, Page("il", all, hashes), maxTokens);
    }, cancellationToken);

    private static IEnumerable<MethodDef> MethodsOf(IMemberDef member) => member switch
    {
        MethodDef m => [m],
        PropertyDef p => p.GetMethods.Concat(p.SetMethods).Concat(p.OtherMethods),
        EventDef e => new[] { e.AddMethod, e.RemoveMethod, e.InvokeMethod }.Where(m => m != null).Concat(e.OtherMethods),
        TypeDef t => t.Methods,
        _ => [],
    };

    /// <summary>One "// IL hash:" line per method of the symbol with its raw IL SHA-256 (docs/il-hash.md), and the method's name unless the symbol is that method.</summary>
    private static string HashLines(ResolvedSymbol s)
    {
        var methods = MethodsOf(s.Member);
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

    [McpServerTool(Name = "export_project", Title = "Export C# project", UseStructuredContent = true, OutputSchemaType = typeof(ExportOutcome))]
    [Description("Decompile an assembly into a C# project on disk (.cs per type, .csproj, resources), to grep or browse a large codebase with file tools. " +
                 "An .apk / .aab path gives a Gradle project (decoded manifest and resources, Java through JADX when configured, else smali). " +
                 "Written whole or not at all.")]
    public Task<string> ExportProject(
        [Description(AssemblyDescription)] string assembly,
        [Description("Empty or new output directory.")] string outputDirectory,
        [Description("Replace a previous export in outputDirectory.")] bool overwrite = false,
        RequestContext<CallToolRequestParams> context = null!, // bound by the SDK
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        // The call's token also ends at its deadline; the export stops only when the client cancels, else it finishes in the background.
        var stop = OutputCall.Current is { } call ? call.ClientCancel : cancellationToken;
        int answered = 0, done = 0, total = 0;
        void Progress(int d, int t, string status)
        {
            (done, total) = (d, t);
            if (Volatile.Read(ref answered) == 0) Report(progress, d, t, status);
        }
        bool package = android != null && Services.Mobile.AndroidProjectExport.IsPackagePath(assembly) && File.Exists(assembly.Trim());
        var job = Task.Run(() => package ? ExportPackage(assembly.Trim(), outputDirectory, overwrite, Progress, stop)
            : Task.FromResult(ExportAssembly(assembly, outputDirectory, overwrite, Progress, stop)), CancellationToken.None);
        var deadline = new TaskCompletionSource();
        using (cancellationToken.Register(() => deadline.TrySetResult()))
            if (await Task.WhenAny(job, deadline.Task) == job || stop.IsCancellationRequested) return Render(await job);
        Volatile.Write(ref answered, 1);
        if (options != null) LeftoverWork.For(options).Track(job);
        _ = job.ContinueWith(t => t.Exception, TaskContinuationOptions.OnlyOnFaulted);
        throw new ToolError(ErrorCode.Timeout, $"The export of {assembly} is still running at the call's deadline ({done} of {total} units done); it goes on in the background " +
            $"and {SafeFile.FullPath(outputDirectory)} appears once it is complete (nothing is written there before).",
            "list the output directory later; if it does not appear, export again (overwrite=true replaces a finished export)")
        {
            Partial = new { done, total, outputDirectory = SafeFile.FullPath(outputDirectory) },
            Details = new { stillRunning = true, partial = true },
            RetryAfter = LeftoverWork.RetryAfter,
        };
    });

    private ExportOutcome ExportAssembly(string assembly, string outputDirectory, bool overwrite, Action<int, int, string> progress, CancellationToken ct)
    {
        var asm = workspace.Read(() => workspace.Get(assembly), ct);
        var r = decompiler.ExportProject(asm, outputDirectory, progress, ct, overwrite);
        return new ExportOutcome(true, asm.Id, r.Directory, r.FileCount, r.ProjectFile, r.FailedTypes) { Replaced = r.Replaced };
    }

    private async Task<ExportOutcome> ExportPackage(string path, string outputDirectory, bool overwrite, Action<int, int, string> progress, CancellationToken ct)
    {
        using var output = ExportDirectory.Begin(outputDirectory, overwrite);
        var r = await android!.Export(path, output.Staging, progress, ct).ConfigureAwait(false);
        var files = output.Commit();
        var notes = new List<string> { $"{r.Classes} classes as {r.Sources}" + (r.SourceFailures > 0 ? $" ({r.SourceFailures} failed; their files hold the error)" : "") };
        notes.AddRange(r.Notes.Take(20));
        return new ExportOutcome(true, Path.GetFileName(path), output.Final, files.Count, files.FirstOrDefault(f => f.StartsWith("build.gradle", StringComparison.Ordinal)) is { } gradle
            ? Path.Combine(output.Final, gradle) : null, []) { Replaced = output.Replace, Notes = notes };
    }

    private static string Render(ExportOutcome r)
    {
        var text = $"Exported {r.Source} to {r.OutputDirectory}: {r.Files} files.{(r.ProjectFile != null ? $" Project: {r.ProjectFile}" : "")}{(r.Replaced ? " (replaced the previous export)" : "")}";
        if (r.Notes is { Count: > 0 } notes) text += "\n" + string.Join("\n", notes);
        if (r.FailedTypes.Count > 0)
            text += $"\n{Plural(r.FailedTypes.Count, "type")} failed to decompile (their files contain the error):\n  " + string.Join("\n  ", r.FailedTypes.Take(20));
        return ToolOutput.With(text, r);
    }

    private const string SimplifiedDescription =
        "Show the code as simplify_methods would leave it, without changing the assembly.";

    private string TypeSource(ResolvedSymbol sym, bool simplified, CancellationToken ct) =>
        pager.GetOrCreate(CacheKey(simplified ? "type-simplified" : "type", [sym]), () => $"// [{sym.Assembly.Id}] {sym.Label}\n" + (simplified
            ? decompiler.DecompileSimplified(sym.Assembly, [sym.Member], new SimplifyOptions(), ct)
            : decompiler.DecompileType(sym.Assembly, (TypeDef)sym.Member, ct)));

    private string CacheKey(string kind, IEnumerable<ResolvedSymbol> symbols) =>
        $"{decompiler.TypeSystemKey()}|{kind}|{string.Join(",", symbols.Select(s => s.Assembly.Id + (s.Member.MDToken.Rid != 0 ? Format.Token(s.Member) : Format.MemberLabel(s.Member))))}"; // added members share token (new)

    /// <summary>More than 25 matches: ambiguous, naming up to 25 in details.matches and as many as fit the error budget in the text.</summary>
    private static void RequireFew(IReadOnlyList<ResolvedSymbol> all, string query)
    {
        if (all.Count <= MaxMembersPerCall) return;
        var first = all.Take(MaxMembersPerCall).ToList();
        var lines = new List<string>();
        int chars = 0;
        foreach (var a in first)
        {
            var line = "  " + a;
            if (chars + line.Length > 2_000) break;
            lines.Add(line);
            chars += line.Length + 1;
        }
        throw new ToolError(ErrorCode.Ambiguous, $"'{query}' matches {all.Count} symbols. First matches:\n" + string.Join("\n", lines) +
                            (lines.Count < all.Count ? $"\n  ... {all.Count - lines.Count} more" : ""),
            "narrow it with a type name, a parameter list (Method(int, string)) or a token from details.matches")
        { Details = new { matches = first.Select(SymbolRef.Of).ToList(), total = all.Count } };
    }
}
