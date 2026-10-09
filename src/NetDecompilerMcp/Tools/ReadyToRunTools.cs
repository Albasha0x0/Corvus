using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.ReadyToRun;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

/// <summary>ReadyToRun: the precompiled native code of managed methods, and the method at a native address.</summary>
[McpServerToolType]
public sealed class ReadyToRunTools(AssemblyWorkspace workspace, ReadyToRunService r2r, OutputPager pager)
{
    private const string AssemblyPathNote = " A full path to an assembly that is not loaded yet loads it.";

    /// <summary>Loads the assembly first when given as the full path of a file that is not loaded.</summary>
    private void LoadIfPath(string? assembly)
    {
        var path = assembly?.Trim();
        if (string.IsNullOrEmpty(path) || !Path.IsPathFullyQualified(path) || !File.Exists(path)) return;
        if (workspace.Read(() => workspace.FindByPath(path)) == null) workspace.Load(path);
    }

    [McpServerTool(Name = "get_r2r_code", Title = "ReadyToRun native code of a method", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("The precompiled native code of a method in a ReadyToRun assembly (crossgen / PublishReadyToRun; the .NET shared framework's " +
                 "assemblies are ReadyToRun): entry address, every code range (hot body, exception funclets, cold code), the import cells " +
                 "its fixups resolve before it first runs, and its x86 / x64 disassembly with import cells named by what they resolve to " +
                 "(called methods as 'call qword ptr [Ns.Type::Method(int)]', type handles, static bases, helpers, string literals). " +
                 "A generic method has code only for the instantiations compiled into the image (e.g. over __Canon); each is shown. " +
                 "For a component of a composite image the code is read from the composite file next to it.")]
    public Task<string> GetR2RCode(
        [Description("Method. " + SymbolDescription)] string method,
        [Description(AssemblyFilterDescription + AssemblyPathNote)] string? assembly = null,
        [Description("Only bodies whose name contains this text (case-insensitive), e.g. an instantiation argument such as 'Int32' or '__Canon'.")] string? instantiation = null,
        [Description("Max method bodies disassembled (default 4); the rest are listed with their addresses.")] int maxBodies = 4,
        [Description("Max instructions per body (default 5000).")] int maxInstructions = 5000,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        LoadIfPath(assembly);
        return workspace.Read(() =>
        {
            var symbols = SymbolResolver.Resolve(workspace, assembly, method);
            var methods = symbols.Where(s => s.Member is MethodDef).Take(20).ToList();
            if (methods.Count == 0)
                throw new ToolError(ErrorCode.InvalidArgument, $"'{method}' is a {symbols[0].Kind}, not a method.", "pass Ns.Type::Method; resolve_symbol lists what a name matches");
            int bodiesLimit = Math.Clamp(maxBodies, 1, 100);
            int insnLimit = Math.Clamp(maxInstructions, 1, 200_000);
            var sb = new StringBuilder();
            var missing = new List<string>();
            int shown = 0;
            foreach (var sym in methods)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var md = (MethodDef)sym.Member;
                var code = r2r.Require(sym.Assembly, cancellationToken);
                var bodies = code.ByMethodDef.TryGetValue(md.Rid, out var list) ? list : [];
                if (instantiation is { Length: > 0 } filter)
                    bodies = bodies.Where(b => code.Label(b).Contains(filter, StringComparison.OrdinalIgnoreCase)).ToList();
                if (bodies.Count == 0)
                {
                    missing.Add($"{Format.MemberLabel(md)} [{sym.Assembly.Id}] {Format.Token(md)}: {NoCodeReason(md, code, instantiation)}");
                    continue;
                }
                foreach (var body in bodies)
                {
                    if (shown++ < bodiesLimit) AppendBody(sb, code, body, md, insnLimit, cancellationToken);
                    else sb.AppendLine($"(not disassembled) {code.Label(body)}  entry {NativeAddress.Va(code.CodeImage!.Image, body.EntryRva)}, {body.Size} bytes");
                }
            }
            if (shown == 0)
                throw new ToolError(ErrorCode.Unsupported, "No precompiled code: " + string.Join("; ", missing),
                    "decompile_member / get_il show the IL the JIT compiles at run time" + (instantiation != null ? "; or drop the instantiation filter" : ""));
            if (shown > bodiesLimit) sb.AppendLine($"({shown - bodiesLimit} more bodies not disassembled; raise maxBodies or filter with instantiation)");
            foreach (var m in missing) sb.AppendLine("No precompiled code: " + m);
            return pager.Page(sb.ToString(), offset, maxChars);
        });
    }, cancellationToken);

    private static string NoCodeReason(MethodDef md, ReadyToRunService.AssemblyCode code, string? filter)
    {
        if (filter != null && code.ByMethodDef.ContainsKey(md.Rid)) return $"no compiled body matches '{filter}'";
        if (!md.HasBody) return "it has no IL body (abstract, extern or implemented by the runtime)";
        if (md.HasGenericParameters || md.DeclaringType.HasGenericParameters)
            return "generic, and no instantiation of it was compiled into the image; the JIT compiles the instantiations it needs";
        return "crossgen did not compile it (rejected, outside the version bubble, or left to the JIT), so the runtime JIT-compiles it";
    }

    private static void AppendBody(StringBuilder sb, ReadyToRunService.AssemblyCode code, R2RBody body, MethodDef md, int maxInstructions, CancellationToken ct)
    {
        var image = code.CodeImage!;
        var pe = image.Image;
        sb.AppendLine($"{code.Label(body)}  [{code.Assembly.Id}] {Format.Token(md)}");
        sb.AppendLine($"  native code in {Path.GetFileName(code.CodeFile)} (ReadyToRun {image.MajorVersion}.{image.MinorVersion}, {image.MachineName}): " +
                      $"entry {NativeAddress.Va(pe, body.EntryRva)} (rva 0x{body.EntryRva:X}), {body.Size} bytes in {Plural(body.Ranges.Count, "range")}");
        var (sharing, _) = code.Map!.BodiesAt(body.EntryRva);
        if (sharing.Count > 1)
            sb.AppendLine("  code shared with: " + string.Join("; ", sharing.Where(b => b != body).Take(5).Select(code.Label)) + (sharing.Count > 6 ? "; ..." : ""));
        var fixups = image.Fixups(body.Entry.FixupsRva);
        if (fixups.Count > 0)
        {
            sb.AppendLine($"  fixups resolved before the code first runs: {fixups.Count}");
            foreach (var (section, cell) in fixups.Take(200))
            {
                var s = image.ImportSections[section];
                uint rva = s.Rva + (uint)cell * s.EntrySize;
                sb.AppendLine($"    [{NativeAddress.Va(pe, rva)}] {code.Symbols.CellAt(rva)?.Describe() ?? "(unreadable signature)"}");
            }
            if (fixups.Count > 200) sb.AppendLine($"    ... {fixups.Count - 200} more");
        }
        if (!R2RDisassembly.CanDecode(image.Arch))
        {
            sb.AppendLine($"  ({image.MachineName} instructions are not decoded; ranges:)");
            foreach (var r in body.Ranges) sb.AppendLine("  " + R2RDisassembly.RangeLine(pe, r));
        }
        else
        {
            ct.ThrowIfCancellationRequested();
            sb.Append(R2RDisassembly.Text(R2RDisassembly.Disassembler(image, code.Symbols), pe, body, maxInstructions));
        }
        sb.AppendLine();
    }

    [McpServerTool(Name = "find_r2r_method", Title = "Managed method at a ReadyToRun address", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("The managed method whose precompiled ReadyToRun code contains a native address (e.g. from a crash dump, profiler or debugger): " +
                 "its name and token, which range (hot body, funclet, cold code) and offset, and the instruction there. An import cell address " +
                 "is described by what it resolves to. Addresses are in the file holding the code (the assembly, or its composite image).")]
    public Task<string> FindR2RMethod(
        [Description(AssemblyDescription + AssemblyPathNote)] string assembly,
        [Description("Address in the code image: a VA (0x180012340, inside the image base range), an RVA, or rva:/va:/off: prefixed.")] string address,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        LoadIfPath(assembly);
        return workspace.Read(() =>
        {
            var asm = workspace.Get(assembly);
            var code = r2r.Require(asm, cancellationToken);
            var image = code.CodeImage!;
            var pe = image.Image;
            uint rva = NativeAddress.Parse(pe, address);
            var (bodies, range) = code.Map!.BodiesAt(rva);
            var sb = new StringBuilder($"{NativeAddress.Describe(pe, rva)} in {Path.GetFileName(code.CodeFile)}\n");
            if (range == null)
            {
                if (image.CellAt(rva) is { } found)
                {
                    var (section, cell) = found;
                    sb.AppendLine($"import cell {cell} of import section {section.Index} ({(section.IsEager ? "eager" : "lazy")}, {section.Count} cells): " +
                                  (code.Symbols.CellAt(rva)?.Describe() ?? "(no signature)"));
                    return sb.ToString();
                }
                throw new ToolError(ErrorCode.NotFound, $"No precompiled method contains {NativeAddress.Va(pe, rva)} in {Path.GetFileName(code.CodeFile)}.",
                    "get_r2r_code shows a method's code ranges; addresses are VAs or RVAs of the file holding the code");
            }
            var r = range;
            sb.AppendLine($"+0x{rva - r.Function.Begin:X} into the {r.Kind.ToString().ToLowerInvariant()} code {NativeAddress.Va(pe, r.Function.Begin)}-{NativeAddress.Va(pe, r.Function.End)} of:");
            foreach (var body in bodies.Take(10))
            {
                var md = code.MethodOf(body);
                string owner = md != null ? $"[{code.Assembly.Id}] {Format.Token(md)}"
                    : body.Entry.Component >= 0 && body.Entry.Component != code.Component
                        ? $"[component {image.Components[body.Entry.Component].Name}] 0x{0x06000000 | body.Entry.MethodDefRid:X8}"
                        : "[another assembly's method]";
                sb.AppendLine($"  {code.Label(body)}  {owner}  entry {NativeAddress.Va(pe, body.EntryRva)}, {body.Size} bytes in {Plural(body.Ranges.Count, "range")}");
            }
            if (bodies.Count > 10) sb.AppendLine($"  ... {bodies.Count - 10} more sharing this code");
            if (R2RDisassembly.CanDecode(image.Arch) && R2RDisassembly.Disassembler(image, code.Symbols).DecodeOne(rva) is { } line)
                sb.AppendLine("instruction:" + R2RDisassembly.Line(line));
            return sb.ToString();
        });
    }, cancellationToken);
}
