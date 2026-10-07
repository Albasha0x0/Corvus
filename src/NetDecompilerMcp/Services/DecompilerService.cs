using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.ProjectDecompiler;
using ICSharpCode.Decompiler.Disassembler;
using ICSharpCode.Decompiler.TypeSystem;
using NetDecompilerMcp.Core;
using Dn = dnlib.DotNet;

namespace NetDecompilerMcp.Services;

/// <summary>C# decompilation and IL disassembly via the ILSpy engine (ICSharpCode.Decompiler).</summary>
public sealed class DecompilerService(AssemblyWorkspace workspace, ServerOptions options)
{
    private readonly Dictionary<LoadedAssembly, (int Generation, DecompilerTypeSystem TypeSystem)> _typeSystems = new();

    public static DecompilerSettings CreateSettings() => new(LanguageVersion.Latest)
    {
        ThrowOnAssemblyResolveErrors = false,
        ShowXmlDocumentation = false,
        LoadInMemory = true,
        UseSdkStyleProjectFormat = true,
    };

    private DecompilerTypeSystem GetTypeSystem(LoadedAssembly asm)
    {
        lock (_typeSystems)
        {
            if (_typeSystems.TryGetValue(asm, out var entry) && entry.Generation == workspace.Generation)
                return entry.TypeSystem;
            foreach (var stale in _typeSystems.Keys.Where(k => !workspace.Assemblies.Contains(k)).ToList())
                _typeSystems.Remove(stale);
        }
        var ts = new DecompilerTypeSystem(asm.GetPEFile(), workspace.CreateDecompilerResolver(asm), CreateSettings());
        lock (_typeSystems)
            _typeSystems[asm] = (workspace.Generation, ts);
        return ts;
    }

    private CSharpDecompiler CreateDecompiler(LoadedAssembly asm, CancellationToken token) =>
        new(GetTypeSystem(asm), CreateSettings()) { CancellationToken = token };

    /// <summary>Decompiles a whole type. If the engine fails on the type, falls back to member-by-member output so one bad method does not hide the rest.</summary>
    public string DecompileType(LoadedAssembly asm, Dn.TypeDef type, CancellationToken ct) => WithTimeout(token =>
    {
        var decompiler = CreateDecompiler(asm, token);
        try
        {
            // Top-level types go through the full-type-name API, which emits the namespace declaration and usings
            // (decompiling by handle omits the namespace). Nested types are decompiled on their own by handle.
            // Compiler-generated types (e.g. <PrivateImplementationDetails>) come back empty from the name API, so fall back to the handle.
            if (type.DeclaringType == null)
            {
                var withNamespace = decompiler.DecompileTypeAsString(new FullTypeName(type.ReflectionFullName));
                if (!string.IsNullOrWhiteSpace(withNamespace))
                    return withNamespace;
            }
            return decompiler.DecompileAsString(ToHandle(type));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"// Whole-type decompilation failed ({ex.GetType().Name}: {FirstLine(ex.Message)}); decompiling members individually.");
            sb.AppendLine($"// {Format.TypeHeader(type)}");
            var members = type.Fields.Cast<Dn.IMemberDef>().Concat(type.Properties).Concat(type.Events)
                .Concat(type.Methods.Where(m => !m.IsGetter && !m.IsSetter && !m.IsAddOn && !m.IsRemoveOn))
                .Concat(type.NestedTypes);
            foreach (var m in members)
            {
                token.ThrowIfCancellationRequested();
                sb.AppendLine(DecompileMemberSafe(asm, m, decompiler, token));
            }
            return sb.ToString();
        }
    }, ct);

    /// <summary>Decompiles members (all overloads that matched). Failures fall back to IL for that member.</summary>
    public string DecompileMembers(LoadedAssembly asm, IEnumerable<Dn.IMemberDef> members, CancellationToken ct) => WithTimeout(token =>
    {
        var decompiler = CreateDecompiler(asm, token);
        var parts = members.Select(m => DecompileMemberSafe(asm, m, decompiler, token));
        return string.Join("\n", parts);
    }, ct);

    private string DecompileMemberSafe(LoadedAssembly asm, Dn.IMemberDef member, CSharpDecompiler decompiler, CancellationToken token)
    {
        var header = $"// {Format.MemberLabel(member)}  [token {Format.Token(member)}]";
        try
        {
            return header + "\n" + decompiler.DecompileAsString(ToHandle(member)).TrimEnd() + "\n";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var sb = new StringBuilder(header).AppendLine();
            sb.AppendLine($"// C# decompilation failed: {ex.GetType().Name}: {FirstLine(ex.Message)}");
            sb.AppendLine("// IL fallback:");
            try { sb.AppendLine(Disassemble(asm, member, token)); }
            catch (Exception ilEx) when (ilEx is not OperationCanceledException) { sb.AppendLine($"// IL disassembly also failed: {FirstLine(ilEx.Message)}"); }
            return sb.ToString();
        }
    }

    /// <summary>Assembly-level attributes and module info as C#.</summary>
    public string DecompileAssemblyAttributes(LoadedAssembly asm, CancellationToken ct) => WithTimeout(token =>
        CreateDecompiler(asm, token).DecompileModuleAndAssemblyAttributesToString(), ct);

    /// <summary>ildasm-style IL with metadata tokens and resolved operands.</summary>
    public string Disassemble(LoadedAssembly asm, Dn.IMemberDef member, CancellationToken ct)
    {
        var output = new PlainTextOutput();
        var dis = new ReflectionDisassembler(output, ct)
        {
            DetectControlStructure = true,
            ShowSequencePoints = false,
            ShowMetadataTokens = true,
            ExpandMemberDefinitions = true,
        };
        var pe = asm.GetPEFile();
        switch (ToHandle(member).Kind)
        {
            case HandleKind.TypeDefinition: dis.DisassembleType(pe, (TypeDefinitionHandle)ToHandle(member)); break;
            case HandleKind.MethodDefinition: dis.DisassembleMethod(pe, (MethodDefinitionHandle)ToHandle(member)); break;
            case HandleKind.FieldDefinition: dis.DisassembleField(pe, (FieldDefinitionHandle)ToHandle(member)); break;
            case HandleKind.PropertyDefinition: dis.DisassembleProperty(pe, (PropertyDefinitionHandle)ToHandle(member)); break;
            case HandleKind.EventDefinition: dis.DisassembleEvent(pe, (EventDefinitionHandle)ToHandle(member)); break;
            default: throw new ToolError($"Cannot disassemble {member.GetType().Name}.");
        }
        return output.ToString();
    }

    public sealed record ExportResult(string Directory, int FileCount, string? ProjectFile, IReadOnlyList<string> FailedTypes);

    /// <summary>Writes a C# project (one file per type, .csproj, resources) to an empty directory.</summary>
    public ExportResult ExportProject(LoadedAssembly asm, string outputDirectory, Action<int, int, string>? onProgress, CancellationToken ct)
    {
        var dir = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(dir);
        if (Directory.EnumerateFileSystemEntries(dir).Any())
            throw new ToolError($"Output directory is not empty: {dir}. Choose an empty or new directory.");

        // Whole-project export is long-running by nature: it gets 10x the normal timeout.
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(options.TimeoutSeconds * 10L));
        var exporter = new WholeProjectDecompiler(CreateSettings(), workspace.CreateDecompilerResolver(asm), null, null, null);
        if (onProgress != null)
            exporter.ProgressIndicator = new Progress<DecompilationProgress>(p => onProgress(p.UnitsCompleted, p.TotalUnits, p.Status ?? "Decompiling"));
        try
        {
            exporter.DecompileProject(asm.GetPEFile(), dir, cts.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new ToolError($"Project export timed out after {options.TimeoutSeconds * 10}s. Partial output is in {dir}.");
        }
        var files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).ToList();
        var failed = exporter.Errors.Select(e => FirstLine(e.Message)).ToList();
        return new ExportResult(dir, files.Count, files.FirstOrDefault(f => f.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)), failed);
    }

    internal static EntityHandle ToHandle(Dn.IMDTokenProvider member) => MetadataTokens.EntityHandle((int)member.MDToken.Raw);

    private string WithTimeout(Func<CancellationToken, string> action, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(options.TimeoutSeconds));
        try
        {
            return action(cts.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new ToolError($"Decompilation timed out after {options.TimeoutSeconds}s. Decompile a smaller unit (one method via decompile_member), use get_il, or restart the server with a larger --timeout.");
        }
    }

    private static string FirstLine(string s)
    {
        int nl = s.IndexOf('\n');
        return (nl >= 0 ? s[..nl] : s).Trim();
    }
}
