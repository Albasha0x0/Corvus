using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class Il2CppTools(AssemblyWorkspace workspace, Il2CppService il2cpp, Il2CppExporter exporter, Il2CppStringService strings,
    Il2CppNavigator navigator, OutputPager pager)
{
    private const int DefaultListLimit = 20;

    [McpServerTool(Name = "get_il2cpp_info", Title = "Il2Cpp addresses and offsets")]
    [Description("Il2Cpp dummy DLLs (built-in reader, Il2CppDumper or Cpp2IL): native addresses (RVA, VA, file offset, vtable slot) of a method or every method of a type, " +
                 "field offsets and tokens. With script.json (always for the built-in reader): function bounds, methods sharing the code, MethodInfo slot, " +
                 "generic instantiations, a type's metadata slots (Ns.Type_TypeInfo), and names only script.json has ('List`1<int>::Add', 'Method$Ns.Type.M()'). " +
                 "With stringliteral.json and the binary: the string literals a method's code loads.")]
    public Task<string> GetIl2CppInfo(
        [Description(SymbolDescription + " Or a script.json name of an instantiation or metadata slot.")] string symbol,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("With a type: a vtable slot number to resolve to its implementing method, or 'all'.")] string? slot = null,
        [Description("Index of the first entry of each long list.")] int offset = 0,
        [Description("Max entries of each long list.")] int limit = DefaultListLimit,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        offset = Math.Max(0, offset);
        limit = ClampLimit(limit);
        // script.json forms ("Type<int>$$Method", "List`1<int>::Add") name instantiations, which no dummy symbol is.
        if (Il2CppNames.LooksInstantiated(symbol) && ScriptLookup(symbol, assembly, offset, limit, cancellationToken) is { } instantiation)
            return pager.Page(instantiation);
        IReadOnlyList<ResolvedSymbol> symbols;
        try { symbols = SymbolResolver.Resolve(workspace, assembly, symbol); }
        catch (ToolError) when (ScriptLookup(symbol, assembly, offset, limit, cancellationToken) is { } found)
        {
            return pager.Page(found);
        }

        var sb = new StringBuilder();
        bool any = false;
        // A symbol may match in both managed and Il2Cpp dummy assemblies; only the dummy side has addresses.
        var withMetadata = symbols.Where(s => il2cpp.GetIndex(s.Assembly).Count > 0).ToList();
        if (withMetadata.Count > 0 && withMetadata.Count < symbols.Count)
        {
            sb.AppendLine($"({symbols.Count - withMetadata.Count} match(es) in assemblies without Il2Cpp metadata skipped: " +
                          string.Join(", ", symbols.Except(withMetadata).Select(s => s.Assembly.Id).Distinct().Take(5)) + ")");
            sb.AppendLine();
            symbols = withMetadata;
        }
        if (slot != null && !symbols.Any(s => s.Member is TypeDef))
            throw new ToolError(ErrorCode.InvalidArgument, $"slot needs a type; '{symbol}' is not one.");
        foreach (var sym in symbols.Take(25))
        {
            sb.AppendLine($"{sym.Kind} {sym.Label}  [{sym.Assembly.Id}] {Format.Token(sym.Member)}");
            foreach (var a in Il2CppService.GetAttributes(sym.Member)) { sb.AppendLine("  " + a); any = true; }
            var image = il2cpp.GetIndex(sym.Assembly).Count > 0 ? navigator.ImageOf(sym.Assembly) : null;
            if (sym.Member is MethodDef method)
            {
                if (image != null) AppendCode(sb, image, sym.Assembly, method, offset, limit, cancellationToken);
                AppendLiterals(sb, sym.Assembly, method);
            }
            if (sym.Member is TypeDef t)
            {
                if (image?.Script is { } script) AppendTypeMetadata(sb, script, t, offset, limit);
                if (slot != null) { AppendSlot(sb, t, slot, offset, limit); any = true; }
                else
                {
                    foreach (var f in t.Fields)
                        if (Il2CppService.GetAttributes(f) is { Count: > 0 } fa) { sb.AppendLine($"  field  {Format.Field(f)}  {string.Join(" ", fa)}"); any = true; }
                    foreach (var m in t.Methods)
                        if (Il2CppService.GetAttributes(m) is { Count: > 0 } ma) { sb.AppendLine($"  method {Format.Method(m, withModifiers: false)}  {string.Join(" ", ma)}"); any = true; }
                }
            }
            sb.AppendLine();
        }
        if (!any)
            sb.AppendLine("No Il2Cpp attributes found. This needs Il2Cpp dummy DLLs: load_assembly the game folder or its global-metadata.dat (built-in reader), or an Il2CppDumper / Cpp2IL DummyDll folder (with attribute injection).");
        return pager.Page(sb.ToString());
    }, cancellationToken);

    /// <summary>A method's native code: function bounds, the methods sharing it, its MethodInfo slot and generic instantiations.</summary>
    private void AppendCode(StringBuilder sb, Il2CppNavigator.Image image, LoadedAssembly asm, MethodDef method, int offset, int limit, CancellationToken ct)
    {
        var rva = il2cpp.GetIndex(asm).FirstOrDefault(e => e.Method == method)?.Rva;
        if (image.Problem != null) sb.AppendLine($"  ({image.Problem})");
        if (rva is <= uint.MaxValue && Il2CppNavigator.Function(image, (uint)rva) is { IsExactStart: true } f)
        {
            if (image.Script != null && f.End is { } end)
                sb.AppendLine($"  native code: RVA 0x{f.Start:X}-0x{end:X} (0x{end - f.Start:X} bytes up to the next function start)");
            var (methods, scriptMethods) = Il2CppNavigator.MethodsSharing(image, f.Start);
            int total = methods.Count + scriptMethods.Count;
            if (total > 1) sb.AppendLine($"  code shared by {total} methods (identical code or shared generics; find_method_by_address 0x{f.Start:X} lists them)");
        }
        if (image.Script is not { } script) return;
        foreach (var info in Il2CppNavigator.MethodInfos(script, method, rva).Take(5))
            sb.AppendLine($"  MethodInfo slot: RVA 0x{script.MethodInfoAddress(info):X}" +
                          (script.MethodInfoTarget(info) is var target and > 0 ? $" (describes the function at RVA 0x{target:X})" : " (no code of its own)"));
        var instances = navigator.Instantiations(image, method, ct);
        var entries = instances.Entries;
        if (entries.Count == 0 && instances.Unmatched == 0) return;
        int ambiguous = entries.Count(x => x.Match.Outcome == Il2CppOverloads.Outcome.Ambiguous);
        sb.AppendLine($"  generic instantiations in script.json: {entries.Count}{Showing(offset, limit, entries.Count)}" +
                      (instances.Overloads > 1 ? $"; {instances.Overloads} methods share the name, told apart by generic arity and C signature" +
                                                 (ambiguous > 0 ? $" ({ambiguous} ambiguous)" : "") : ""));
        foreach (var (e, match) in entries.Skip(offset).Take(limit))
            sb.AppendLine($"    {script.MethodName(e)}  RVA 0x{script.MethodAddress(e):X}" +
                          (match.Outcome == Il2CppOverloads.Outcome.Ambiguous
                              ? $"  (ambiguous, {match.Basis} as {string.Join("; ", match.Methods.Where(m => m != method).Select(MethodLine))})" : ""));
        AppendMore(sb, offset, limit, entries.Count, "    ");
        if (instances.Unmatched > 0)
            sb.AppendLine($"  ({instances.Unmatched} more script.json {(instances.Unmatched == 1 ? "entry" : "entries")} of the name fit no overload's parameter count)");
    }

    private string MethodLine(MethodDef m) =>
        $"{Format.MemberLabel(m)}  [{workspace.Assemblies.FirstOrDefault(a => a.Module == m.Module)?.Id}] {Format.Token(m)}";

    /// <summary>The dummy method a script.json entry instantiates, or why none is picked. Null when no method has its name.</summary>
    private string? DefinitionLine(Il2CppNavigator.Image image, int entry)
    {
        var match = navigator.DefinitionOf(image, entry);
        if (match.Methods.Count == 0) return null;
        return match.Outcome switch
        {
            Il2CppOverloads.Outcome.Resolved => $"definition: {MethodLine(match.Methods[0])}" +
                                                (match.Named > 1 ? $" (one of {match.Named} methods named like it, by {match.Basis})" : ""),
            Il2CppOverloads.Outcome.Ambiguous => $"definition: ambiguous between {match.Methods.Count} of the {match.Named} methods named like it ({match.Basis}): " +
                                                 string.Join("; ", match.Methods.Select(MethodLine)),
            _ => $"definition: none of the {match.Named} methods named like it has its parameter count: " + string.Join("; ", match.Methods.Take(5).Select(MethodLine)),
        };
    }

    private static void AppendTypeMetadata(StringBuilder sb, Il2CppScript script, TypeDef type, int offset, int limit)
    {
        var slots = Il2CppNavigator.TypeMetadata(script, type);
        if (slots.Count == 0) return;
        bool generic = type.HasGenericParameters || type.DeclaringType?.HasGenericParameters == true;
        sb.AppendLine($"  metadata slots{(generic ? " of its instantiations" : "")}: {slots.Count}{Showing(offset, limit, slots.Count)}");
        foreach (var e in slots.Skip(offset).Take(limit))
        {
            var signature = script.ReadMetadata(e).Signature;
            sb.AppendLine($"    {script.MetadataName(e)}  RVA 0x{script.MetadataAddress(e):X}{(string.IsNullOrEmpty(signature) ? "" : $"  ({signature})")}");
        }
        AppendMore(sb, offset, limit, slots.Count, "    ");
    }

    private void AppendSlot(StringBuilder sb, TypeDef type, string slot, int offset, int limit)
    {
        var vtable = Il2CppNavigator.VTable(type);
        if (slot.Trim().Equals("all", StringComparison.OrdinalIgnoreCase))
        {
            sb.AppendLine($"  vtable slots declared by it and its base types: {vtable.Count}{Showing(offset, limit, vtable.Count)}");
            foreach (var (n, m) in vtable.Skip(offset).Take(limit))
                sb.AppendLine($"    slot {n}: {SlotLine(type, m)}");
            AppendMore(sb, offset, limit, vtable.Count, "    ");
            return;
        }
        if (Il2CppService.ParseNumber(slot) is not { } number || number > int.MaxValue)
            throw new ToolError(ErrorCode.InvalidArgument, $"slot '{slot}' is not a number or 'all'.");
        sb.AppendLine(vtable.TryGetValue((int)number, out var method)
            ? $"  slot {number}: {SlotLine(type, method)}"
            : $"  slot {number}: no method of {type.FullName} or its base types declares it" +
              (vtable.Count > 0 ? $" (declared slots: {vtable.Keys.First()}-{vtable.Keys.Last()})" : " (no slots: the dummy methods carry no Slot values)"));
    }

    private string SlotLine(TypeDef type, MethodDef m)
    {
        var address = Il2CppService.CompactSummary(m);
        var owner = m.DeclaringType == type ? "" : $"  (inherited from {m.DeclaringType.FullName})";
        var asm = workspace.Assemblies.FirstOrDefault(a => a.Module == m.Module);
        return $"{Format.MemberLabel(m)}  {address ?? "no native code"}{owner}  [{asm?.Id}] {Format.Token(m)}";
    }

    /// <summary>A name only script.json has: generic instantiations, metadata and MethodInfo slots. Null when it names nothing there.</summary>
    private string? ScriptLookup(string query, string? assembly, int offset, int limit, CancellationToken ct)
    {
        var images = navigator.ImagesFor(workspace.Scope(assembly)).Where(i => i.Script != null).ToList();
        if (images.Count == 0) return null;
        var sb = new StringBuilder();
        var rows = new List<(Il2CppNavigator.Image Image, int Entry)>();
        foreach (var image in images)
        {
            var script = image.Script!;
            var (metadata, infos) = Il2CppNavigator.FindSlots(script, query);
            foreach (var e in metadata)
            {
                var m = script.ReadMetadata(e);
                sb.AppendLine($"metadata slot {m.Name}: RVA 0x{script.MetadataAddress(e):X}{(string.IsNullOrEmpty(m.Signature) ? "" : $"  ({m.Signature})")}");
                foreach (var t in navigator.TypeOfMetadata(image, m.Name).Take(5))
                    sb.AppendLine($"  type {t.Label}  [{t.Assembly.Id}] {Format.Token(t.Member)}");
            }
            foreach (var e in infos)
                sb.AppendLine($"MethodInfo slot {query.Trim()}: RVA 0x{script.MethodInfoAddress(e):X}" +
                              (script.MethodInfoTarget(e) is var target and > 0 ? $"; its code: RVA 0x{target:X} (find_method_by_address 0x{target:X})" : "; no code of its own"));
            rows.AddRange(Il2CppNavigator.FindScriptMethods(script, query, ct).Select(e => (image, e)));
        }
        if (rows.Count == 0) return sb.Length > 0 ? sb.ToString() : null;

        sb.AppendLine($"script.json: {Plural(rows.Count, "method")} named '{query}'{Showing(offset, limit, rows.Count)}:");
        foreach (var (image, e) in rows.Skip(offset).Take(limit))
        {
            var script = image.Script!;
            uint address = script.MethodAddress(e);
            var name = script.MethodName(e);
            var line = new StringBuilder($"  {name}  RVA 0x{address:X}");
            var f = Il2CppNavigator.Function(image, address);
            if (f?.End is { } end) line.Append($" (0x{end - address:X} bytes)");
            var (methods, scriptMethods) = Il2CppNavigator.MethodsSharing(image, address);
            if (methods.Count + scriptMethods.Count > 1) line.Append($"; code shared by {methods.Count + scriptMethods.Count} methods");
            // Overloads share a MethodInfo name; the slot describing this function is the one.
            var infos = script.MethodInfosNamed("Method$" + name.Replace("$$", ".") + "()");
            if (infos.FirstOrDefault(i => script.MethodInfoTarget(i) == address, infos.FirstOrDefault(-1)) is var info and >= 0)
                line.Append($"; MethodInfo slot RVA 0x{script.MethodInfoAddress(info):X}");
            sb.AppendLine(line.ToString());
            if (DefinitionLine(image, e) is { } definition) sb.AppendLine("      " + definition);
        }
        AppendMore(sb, offset, limit, rows.Count, "");
        return sb.ToString();
    }

    private static string Showing(int offset, int limit, int total) =>
        total > limit || offset > 0 ? offset >= total ? $" (none from offset {offset})" : $" (showing {offset + 1}-{Math.Min(total, offset + limit)})" : "";

    private static void AppendMore(StringBuilder sb, int offset, int limit, int total, string indent)
    {
        if (offset + limit < total) sb.AppendLine($"{indent}[More: offset={offset + limit}]");
    }

    private const int MaxLiteralsPerMethod = 100;

    private void AppendLiterals(StringBuilder sb, LoadedAssembly asm, MethodDef method)
    {
        if (strings.DumpsFor([asm]) is not [var (dump, _)] || il2cpp.GetIndex(asm).FirstOrDefault(e => e.Method == method)?.Rva is not { } rva || rva > uint.MaxValue)
            return;
        if (dump.References == null) { sb.AppendLine($"  string literals: unknown ({dump.ReferenceProblem})"); return; }
        var used = strings.LiteralsUsedBy(dump, (uint)rva);
        sb.AppendLine($"  string literals loaded by its native code: {used.Count}");
        foreach (var (literal, sites) in used.Take(MaxLiteralsPerMethod))
            sb.AppendLine($"    {Format.Literal(Format.Clip(dump.Values[literal], 200))}  slot RVA 0x{dump.Addresses[literal]:X}{(sites > 1 ? $" x{sites}" : "")}");
        if (used.Count > MaxLiteralsPerMethod) sb.AppendLine($"    … {used.Count - MaxLiteralsPerMethod} more");
    }

    [McpServerTool(Name = "export_il2cpp_symbols", Title = "Export IDA/Ghidra scripts")]
    [Description("Export Il2Cpp dummy-DLL metadata for native analysis: IDA Python and Ghidra scripts that create, name (Ns.Type$$Method) and comment every function " +
                 "(RVAs, so any image base works), a C header of struct layouts, and an Il2CppDumper-style script.json.")]
    public Task<string> ExportIl2CppSymbols(
        [Description("Output directory.")] string outputDirectory,
        [Description("Comma-separated: ida, ghidra, header, json or all.")] string formats = "all",
        [Description("Base name of the generated files.")] string baseName = "il2cpp",
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Replace files of the same names if they exist.")] bool overwrite = false,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var result = exporter.Export(workspace.Scope(assembly), outputDirectory, formats, baseName, cancellationToken, overwrite);
        return $"Exported {result.Methods} functions and {result.Structs} struct layouts:\n  " + string.Join("\n  ", result.Files) +
               "\nIDA: File > Script file... on the _ida.py. Ghidra: run the _ghidra.py from the Script Manager; import the .h with File > Parse C Source.";
    }, cancellationToken);

    [McpServerTool(Name = "find_method_by_address", Title = "Native address to method")]
    [Description("Map a native address (from IDA, Ghidra or a crash log) of an Il2Cpp game to the method(s) whose function contains it, or the string literal, " +
                 "type metadata or MethodInfo slot at it; generic instantiations are named with script.json (without it a containing method is a guess). " +
                 "Code shared by many methods is paged.")]
    public Task<string> FindMethodByAddress(
        [Description("Hex as IDA / Ghidra show it ('0x1A2B3C', '1A2B3Ch', '00000001`8001A2B3'); 'd:' prefix for decimal.")] string address,
        [Description("auto: a VA at or above the image base, else an RVA, else a file offset.")] string kind = "auto",
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Index of the first method to list when many share the code.")] int offset = 0,
        [Description("Max methods listed.")] int limit = DefaultListLimit,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var value = Il2CppService.ParseAddress(address) ?? throw new ToolError(ErrorCode.InvalidArgument, $"'{address}' is not a valid hex address.");
        offset = Math.Max(0, offset);
        limit = ClampLimit(limit);
        var scope = workspace.Scope(assembly);
        var results = navigator.Locate(value, kind, scope);
        if (results.Count == 0)
        {
            var known = navigator.ImagesFor(scope).Where(i => i.Script != null).ToList();
            return known.Count == 0
                ? $"No method found at or before 0x{value:X}."
                : $"0x{value:X} is not inside a known function or at a metadata slot ({string.Join("; ", known.Select(i => $"functions of {Path.GetFileName(i.Script!.Path)} start at RVA 0x{i.Starts[0]:X}-0x{i.Starts[^1]:X}"))}).";
        }
        var sb = new StringBuilder($"Address 0x{value:X}:\n");
        foreach (var r in results)
        {
            var k = r.Kind.ToUpperInvariant();
            if (r.Kind == "offset" && !kind.Equals("offset", StringComparison.OrdinalIgnoreCase))
                sb.AppendLine($"  (nothing at RVA 0x{value:X}; read as a file offset: RVA 0x{r.Rva:X})");
            if (r.Slot is { } slot) { AppendSlot(sb, r, slot, k); continue; }
            var f = r.Function!;
            if (r.Image.Problem != null) sb.AppendLine($"  ({r.Image.Problem})");
            if (r.Total > 1 || (r.Image.Script != null && f.End != null))
                sb.AppendLine($"  function at RVA 0x{f.Start:X}{(r.Image.Script != null && f.End is { } end ? $" (0x{end - f.Start:X} bytes up to the next function start)" : "")}" +
                              (r.Total > 1 ? $": {r.Total} methods share this code ({r.Methods.Count} dummy-DLL, {r.ScriptMethods.Count} script.json only){Showing(offset, limit, r.Total)}" : ""));
            if (r.Total == 0)
                sb.AppendLine($"  [{k}] {f.Relation}: function at 0x{r.InKind(f.Start):X} (no method name in the dump)");
            var start = r.InKind(f.Start);
            foreach (var m in r.Methods.Skip(offset).Take(limit))
                sb.AppendLine($"  [{k}] {f.Relation}: {Format.MemberLabel(m.Method)}  (start 0x{start:X})  [{m.Assembly.Id}] {Format.Token(m.Method)}");
            var script = r.Image.Script;
            foreach (var e in r.ScriptMethods.Skip(Math.Max(0, offset - r.Methods.Count)).Take(Math.Max(0, offset + limit - Math.Max(offset, r.Methods.Count))))
            {
                sb.AppendLine($"  [{k}] {f.Relation}: {script!.MethodName(e)}  (start 0x{start:X})  script.json (no dummy-DLL method)");
                if (DefinitionLine(r.Image, e) is { } definition) sb.AppendLine("      " + definition);
            }
            AppendMore(sb, offset, limit, r.Total, "  ");
        }
        return pager.Page(sb.ToString());
    }, cancellationToken);

    private void AppendSlot(StringBuilder sb, Il2CppNavigator.AddressResult r, Il2CppNavigator.DataSlot slot, string k)
    {
        var at = r.Rva > slot.Address ? $" (+0x{r.Rva - slot.Address:X} into the slot at 0x{r.InKind(slot.Address):X})" : "";
        var script = r.Image.Script;
        switch (slot.Kind)
        {
            case Il2CppNavigator.SlotKind.Literal:
                sb.AppendLine($"  [{k}] string literal slot: {Format.Literal(Format.Clip(r.Image.Dump!.Values[slot.Entry], 200))}{at}  (search_strings lists the code that loads it)");
                break;
            case Il2CppNavigator.SlotKind.Metadata:
                var m = script!.ReadMetadata(slot.Entry);
                sb.AppendLine($"  [{k}] metadata slot: {m.Name}{at}{(string.IsNullOrEmpty(m.Signature) ? "" : $"  ({m.Signature})")}");
                foreach (var t in navigator.TypeOfMetadata(r.Image, m.Name).Take(5))
                    sb.AppendLine($"      type {t.Label}  [{t.Assembly.Id}] {Format.Token(t.Member)}");
                break;
            case Il2CppNavigator.SlotKind.MethodInfo:
                var info = script!.ReadMethodInfo(slot.Entry);
                sb.AppendLine($"  [{k}] MethodInfo slot: {info.Name}{at}");
                if (script.MethodInfoTarget(slot.Entry) is not (var target and > 0)) { sb.AppendLine("      no code of its own (generic definition, or never compiled)"); break; }
                var (methods, scriptMethods) = Il2CppNavigator.MethodsSharing(r.Image, target);
                var named = methods.Select(x => $"{Format.MemberLabel(x.Method)}  [{x.Assembly.Id}] {Format.Token(x.Method)}")
                    .Concat(scriptMethods.Select(e => script.MethodName(e))).FirstOrDefault();
                sb.AppendLine($"      its code: RVA 0x{target:X}{(named != null ? $" ({named}{(methods.Count + scriptMethods.Count > 1 ? $" and {methods.Count + scriptMethods.Count - 1} more sharing it" : "")})" : "")}");
                break;
        }
    }
}
