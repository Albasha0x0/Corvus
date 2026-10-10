using System.Text;
using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>Assembly overview used by the get_assembly_info tool and the assembly info resource.</summary>
public sealed class AssemblyReport(AssemblyWorkspace workspace, Il2CppService il2cpp)
{
    /// <summary>Call under the workspace read lock.</summary>
    public string Build(LoadedAssembly asm)
    {
        var m = asm.Module;
        var types = MetadataUtil.CountedTypes(m);
        var sb = new StringBuilder();
        sb.AppendLine($"Id: {asm.Id}");
        sb.AppendLine($"Assembly: {asm.FullAssemblyName}");
        sb.AppendLine($"File: {asm.FilePath}");
        sb.AppendLine($"Module: {m.Name}  MVID {m.Mvid}");
        sb.AppendLine($"Runtime: {m.RuntimeVersion}  Kind: {m.Kind}  Machine: {m.Machine}  IL-only: {m.IsILOnly}  32-bit required: {m.Is32BitRequired}");
        var tfa = m.Assembly?.CustomAttributes.FirstOrDefault(c => c.TypeFullName == "System.Runtime.Versioning.TargetFrameworkAttribute");
        if (tfa?.ConstructorArguments.Count > 0)
            sb.AppendLine($"Target framework: {tfa.ConstructorArguments[0].Value}");
        if (m.EntryPoint != null)
            sb.AppendLine($"Entry point: {Format.MemberLabel(m.EntryPoint)}  ({Format.Token(m.EntryPoint)})");
        sb.AppendLine($"Types: {types.Count} ({types.Count(t => t.DeclaringType != null)} nested)  Namespaces: {MetadataUtil.NamespaceCount(types)}  " +
                      $"Methods: {m.GetTypes().Sum(t => t.Methods.Count)}  Fields: {m.GetTypes().Sum(t => t.Fields.Count)}  Resources: {m.Resources.Count}");
        if (MetadataUtil.IsReferenceAssembly(m))
            sb.AppendLine("Reference assembly: metadata only (compile-time API surface); method bodies are `throw null`. Load the implementation " +
                          "(the runtime's assembly, or the package's lib/ folder instead of ref/) to read code.");
        int addressed = il2cpp.GetIndex(asm).Count;
        if (addressed > 0)
            sb.AppendLine($"Il2Cpp metadata: {addressed} methods carry [Address] attributes (dummy DLL; method bodies are stubs — use get_il2cpp_info / find_method_by_address).");
        var health = asm.BodyHealth;
        if (health.MostlyInvalid)
            sb.AppendLine($"IL: {health.Describe()} Load the decrypted image (e.g. a dump taken after the code ran) to read code.");
        else if (health.Invalid > 0)
            sb.AppendLine($"IL: {health.Invalid} of {health.Bodies} method bodies are not valid IL (e.g. " +
                          string.Join(", ", m.GetTypes().SelectMany(t => t.Methods).Where(health.IsInvalid).Take(3).Select(Format.MemberLabel)) + ").");
        if (ReadyToRunService.Summary(workspace, asm) is { } readyToRun)
            sb.AppendLine(readyToRun);
        if (asm.IsDirty)
            sb.AppendLine($"Unsaved edits: {string.Join("; ", asm.Edits)}");
        AppendPeInfo(sb, m);
        AppendMetadataIssues(sb, asm);

        sb.AppendLine("References:");
        foreach (var r in m.GetAssemblyRefs())
        {
            var target = workspace.LocateReference(r.Name, r.Version, r.PublicKeyOrToken?.Token?.Data, asm.FilePath, Frameworks.TargetsNetFramework(m), Frameworks.TargetFrameworkOf(m));
            var status = target?.Describe() ?? "not found";
            // Flag a resolved major version that differs from the requested one; .NET Framework 2.0-4.x unification is expected.
            if (target?.File is { } file && r.Version is { } wanted && !Frameworks.IsWildcard(wanted)
                && !(wanted.Major <= 4 && Frameworks.IsNetFrameworkAssembly(r.Name)))
            {
                Version? found = null;
                try { found = System.Reflection.AssemblyName.GetAssemblyName(file).Version; } catch (Exception) { }
                if (found != null && !Frameworks.IsWildcard(found) && found.Major != wanted.Major)
                    status += $", version {found} (no {wanted.Major}.x on this machine)";
            }
            sb.AppendLine($"  {r.FullName}  [{status}]");
        }

        var attrs = m.Assembly?.CustomAttributes.Where(c => c != tfa).ToList() ?? [];
        if (attrs.Count > 0)
        {
            sb.AppendLine("Assembly attributes:");
            foreach (var ca in attrs.Take(40)) sb.AppendLine("  " + Format.Attribute(ca));
        }
        return sb.ToString();
    }

    private static void AppendPeInfo(StringBuilder sb, ModuleDefMD m)
    {
        try
        {
            var pe = m.Metadata.PEImage;
            var fh = pe.ImageNTHeaders.FileHeader;
            var oh = pe.ImageNTHeaders.OptionalHeader;
            var stamp = DateTimeOffset.FromUnixTimeSeconds(fh.TimeDateStamp);
            sb.AppendLine($"PE: {(oh.Magic == 0x20B ? "PE32+" : "PE32")}  ImageBase 0x{oh.ImageBase:X}  Subsystem {oh.Subsystem}  " +
                          $"Characteristics {fh.Characteristics}  DllCharacteristics {oh.DllCharacteristics}");
            sb.AppendLine($"Timestamp: 0x{fh.TimeDateStamp:X8}{(stamp.Year is > 1995 and < 2100 ? $" ({stamp:yyyy-MM-dd HH:mm} UTC)" : " (deterministic build hash)")}  " +
                          $"CLR flags: {m.Metadata.ImageCor20Header.Flags}  Metadata version: {m.Metadata.VersionString}");
            sb.AppendLine("Sections:");
            foreach (var s in pe.ImageSectionHeaders)
                sb.AppendLine($"  {s.DisplayName,-8} VA 0x{(uint)s.VirtualAddress:X8}  VSize 0x{s.VirtualSize:X}  Raw 0x{s.PointerToRawData:X}+0x{s.SizeOfRawData:X}  flags 0x{s.Characteristics:X8}");
            sb.AppendLine("Metadata streams: " + string.Join(", ", m.Metadata.AllStreams.Select(st => $"{st.Name} ({st.StreamLength} bytes)")));
        }
        catch (Exception ex)
        {
            sb.AppendLine($"PE: unavailable ({ex.Message})");
        }
    }

    /// <summary>Structural metadata problems (obfuscator-style) with their locations; nothing when there are none.</summary>
    private static void AppendMetadataIssues(StringBuilder sb, LoadedAssembly asm)
    {
        var issues = MetadataSurvey.Survey(asm.OriginalBytes).Concat(MetadataSurvey.ImplMapRows(asm.Module).Values).ToList();
        if (issues.Count == 0) return;
        sb.AppendLine($"Metadata issues ({issues.Count}; the rest of the metadata is read leniently):");
        foreach (var issue in issues.Take(20))
            sb.AppendLine($"  {issue.Code} at {issue.Location}{(issue.FileOffset != null ? $", file offset {issue.FileOffset}" : "")}: {issue.Detail}");
    }
}
