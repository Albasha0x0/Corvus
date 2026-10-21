using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.ReadyToRun;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>ReadyToRun: the precompiled native code of managed methods, and the method at a native address.</summary>
[McpServerToolType]
public sealed class ReadyToRunTools(AssemblyWorkspace workspace, ReadyToRunService r2r, OutputPager pager)
{

    [McpServerTool(Name = "get_r2r_code", Title = "ReadyToRun native code of a method", UseStructuredContent = true, OutputSchemaType = typeof(CodePage))]
    [Description("Precompiled native code of a method in a ReadyToRun assembly (shared framework too): entry, code ranges, fixup cells and x86 / x64 " +
                 "disassembly with cells named by their targets; generics per compiled instantiation, composite images included.")]
    public Task<string> GetR2RCode(
        [Description(SymbolDescription)] string method,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Only bodies whose name contains this text (Int32, __Canon).")] string? instantiation = null,
        [Description("Max bodies disassembled; the rest listed with addresses.")] int maxBodies = 4,
        [Description("Max instructions per body.")] int maxInstructions = 1500,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        Targets.Prepare(workspace, assembly);
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
            var listed = new List<R2rBody>();
            var shownSymbols = new List<ResolvedSymbol>();
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
                shownSymbols.Add(sym);
                foreach (var body in bodies)
                {
                    bool disassembled = shown++ < bodiesLimit;
                    if (disassembled) AppendBody(sb, code, body, md, insnLimit, cancellationToken);
                    else sb.AppendLine($"(not disassembled) {code.Label(body)}  entry {NativeAddress.Va(code.CodeImage!.Image, body.EntryRva)}, {body.Size} bytes");
                    if (listed.Count < 100)
                        listed.Add(new R2rBody(code.Label(body), NativeAddress.Va(code.CodeImage!.Image, body.EntryRva), (int)body.Size, body.Ranges.Count) { Disassembled = disassembled });
                }
            }
            if (shown == 0)
                throw new ToolError(ErrorCode.Unsupported, "No precompiled code: " + string.Join("; ", missing),
                    "decompile_member / get_il show the IL the JIT compiles at run time" + (instantiation != null ? "; or drop the instantiation filter" : ""));
            if (shown > bodiesLimit) sb.AppendLine($"({shown - bodiesLimit} more bodies not disassembled; raise maxBodies or filter with instantiation)");
            foreach (var m in missing) sb.AppendLine("No precompiled code: " + m);
            return ToolOutput.Text(pager, sb.ToString(), offset,
                new CodePage("asm", "", 0, null, 0) { Symbols = shownSymbols.Select(SymbolRef.Of).ToList(), Bodies = listed }, maxTokens);
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

    [McpServerTool(Name = "find_r2r_method", Title = "Managed method at a ReadyToRun address", UseStructuredContent = true, OutputSchemaType = typeof(R2rLookup))]
    [Description("Managed method whose ReadyToRun code holds a native address (dump, profiler, debugger): name, token, range, offset and " +
                 "instruction, or what an import cell resolves to. Addresses are in the file holding the code.")]
    public Task<string> FindR2RMethod(
        [Description(AssemblyDescription)] string assembly,
        [Description("A VA or RVA in the code image (rva:/va:/off: prefix).")] string address,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        Targets.Prepare(workspace, assembly);
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
                    var target = code.Symbols.CellAt(rva)?.Describe() ?? "(no signature)";
                    sb.AppendLine($"import cell {cell} of import section {section.Index} ({(section.IsEager ? "eager" : "lazy")}, {section.Count} cells): " + target);
                    return ToolOutput.Report(sb.ToString(), new R2rLookup(NativeAddress.Va(pe, rva), Path.GetFileName(code.CodeFile), "import_cell") { ImportCell = target });
                }
                throw new ToolError(ErrorCode.NotFound, $"No precompiled method contains {NativeAddress.Va(pe, rva)} in {Path.GetFileName(code.CodeFile)}.",
                    "get_r2r_code shows a method's code ranges; addresses are VAs or RVAs of the file holding the code");
            }
            var r = range;
            var methods = new List<R2rMethod>();
            sb.AppendLine($"+0x{rva - r.Function.Begin:X} into the {r.Kind.ToString().ToLowerInvariant()} code {NativeAddress.Va(pe, r.Function.Begin)}-{NativeAddress.Va(pe, r.Function.End)} of:");
            foreach (var body in bodies.Take(10))
            {
                var md = code.MethodOf(body);
                string owner = md != null ? $"[{code.Assembly.Id}] {Format.Token(md)}"
                    : body.Entry.Component >= 0 && body.Entry.Component != code.Component
                        ? $"[component {image.Components[body.Entry.Component].Name}] 0x{0x06000000 | body.Entry.MethodDefRid:X8}"
                        : "[another assembly's method]";
                sb.AppendLine($"  {code.Label(body)}  {owner}  entry {NativeAddress.Va(pe, body.EntryRva)}, {body.Size} bytes in {Plural(body.Ranges.Count, "range")}");
                methods.Add(new R2rMethod(code.Label(body), NativeAddress.Va(pe, body.EntryRva), (int)body.Size)
                {
                    Token = md != null ? Format.Token(md) : $"0x{0x06000000 | body.Entry.MethodDefRid:X8}",
                    Assembly = md != null ? code.Assembly.Id : body.Entry.Component >= 0 && body.Entry.Component != code.Component ? image.Components[body.Entry.Component].Name : null,
                });
            }
            if (bodies.Count > 10) sb.AppendLine($"  ... {bodies.Count - 10} more sharing this code");
            string? instruction = null;
            if (R2RDisassembly.CanDecode(image.Arch) && R2RDisassembly.Disassembler(image, code.Symbols).DecodeOne(rva) is { } line)
            {
                instruction = R2RDisassembly.Line(line).Trim();
                sb.AppendLine("instruction:" + R2RDisassembly.Line(line));
            }
            return ToolOutput.Report(sb.ToString(), new R2rLookup(NativeAddress.Va(pe, rva), Path.GetFileName(code.CodeFile), r.Kind.ToString().ToLowerInvariant())
            {
                Begin = NativeAddress.Va(pe, r.Function.Begin),
                End = NativeAddress.Va(pe, r.Function.End),
                Offset = $"0x{rva - r.Function.Begin:X}",
                Methods = methods,
                Instruction = instruction,
            });
        });
    }, cancellationToken);
}
