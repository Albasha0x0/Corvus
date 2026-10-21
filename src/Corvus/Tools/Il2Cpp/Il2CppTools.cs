using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class Il2CppTools(AssemblyWorkspace workspace, Il2CppService il2cpp, Il2CppExporter exporter, Il2CppStringService strings,
    Il2CppNavigator navigator)
{
    private const int DefaultListLimit = 20;

    /// <summary>What get_il2cpp_info found: member rows in full, rows of the long lists from offset (the longest list sets total).</summary>
    private sealed class Facts
    {
        public readonly List<Il2CppRow> Members = [];
        public readonly List<Il2CppRow> Items = [];
        public int Total;

        public void Page(IEnumerable<Il2CppRow> rows, int count)
        {
            Items.AddRange(rows);
            Total = Math.Max(Total, count);
        }
    }

    [McpServerTool(Name = "get_il2cpp_info", Title = "Il2Cpp addresses and offsets", UseStructuredContent = true, OutputSchemaType = typeof(Il2CppInfo))]
    [Description("Native addresses (RVA, VA, file offset, vtable slot) of an Il2Cpp method or a type's methods, field offsets and tokens. With " +
                 "script.json: function bounds, methods sharing the code, MethodInfo slot, generic instantiations, metadata slots. With " +
                 "stringliteral.json and the binary: literals a method loads.")]
    public Task<string> GetIl2CppInfo(
        [Description("Type or member (Ns.Type::M(int), short name, token) or script.json name (List`1<int>::Add).")] string symbol,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("With a type: a vtable slot number to resolve to its method, or all.")] string? slot = null,
        [Description("First entry of each long list.")] int offset = 0,
        [Description("Max entries of each long list.")] int limit = DefaultListLimit,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        offset = Math.Max(0, offset);
        limit = ClampLimit(limit);
        var facts = new Facts();
        string Done(string text) => ToolOutput.Report(text.ReplaceLineEndings("\n"), new Il2CppInfo(symbol, facts.Members, facts.Items, offset, facts.Total));
        // script.json forms ("Type<int>$$Method", "List`1<int>::Add") name instantiations, which no dummy symbol is.
        if (Il2CppNames.LooksInstantiated(symbol) && ScriptLookup(symbol, assembly, offset, limit, facts, cancellationToken) is { } instantiation)
            return Done(instantiation);
        IReadOnlyList<ResolvedSymbol> symbols;
        try { symbols = SymbolResolver.Resolve(workspace, assembly, symbol); }
        catch (ToolError) when (ScriptLookup(symbol, assembly, offset, limit, facts, cancellationToken) is { } found)
        {
            return Done(found);
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
            throw new ToolError(ErrorCode.InvalidArgument, $"slot needs a type; '{symbol}' is not one.", "pass a type as symbol, or leave slot out");
        foreach (var sym in symbols.Take(25))
        {
            sb.AppendLine($"{sym.Kind} {sym.Label}  [{sym.Assembly.Id}] {Format.Token(sym.Member)}");
            var attributes = Il2CppService.GetAttributes(sym.Member);
            foreach (var a in attributes) { sb.AppendLine("  " + a); any = true; }
            var row = MemberRow(sym.Kind, sym.Label, sym.Assembly, sym.Member);
            var image = il2cpp.GetIndex(sym.Assembly).Count > 0 ? navigator.ImageOf(sym.Assembly) : null;
            if (sym.Member is MethodDef method)
            {
                if (image != null) row = AppendCode(sb, image, sym.Assembly, method, offset, limit, facts, row, cancellationToken);
                facts.Members.Insert(0, row);
                AppendLiterals(sb, sym.Assembly, method, facts);
                continue;
            }
            facts.Members.Add(row);
            if (sym.Member is TypeDef t)
            {
                if (image?.Script is { } script) AppendTypeMetadata(sb, script, t, offset, limit, facts);
                if (slot != null) { AppendSlot(sb, t, slot, offset, limit, facts); any = true; }
                else
                {
                    foreach (var f in t.Fields)
                        if (Il2CppService.GetAttributes(f) is { Count: > 0 } fa)
                        {
                            sb.AppendLine($"  field  {Format.Field(f)}  {string.Join(" ", fa)}");
                            facts.Members.Add(MemberRow("field", Format.Field(f), sym.Assembly, f));
                            any = true;
                        }
                    foreach (var m in t.Methods)
                        if (Il2CppService.GetAttributes(m) is { Count: > 0 } ma)
                        {
                            sb.AppendLine($"  method {Format.Method(m, withModifiers: false)}  {string.Join(" ", ma)}");
                            facts.Members.Add(MemberRow("method", Format.MemberLabel(m), sym.Assembly, m));
                            any = true;
                        }
                }
            }
            sb.AppendLine();
        }
        if (!any)
            sb.AppendLine("No Il2Cpp attributes found. This needs Il2Cpp dummy DLLs: load_assembly the game folder or its global-metadata.dat (built-in reader), or an Il2CppDumper / Cpp2IL DummyDll folder (with attribute injection).");
        return Done(sb.ToString());
    }, cancellationToken);

    /// <summary>A member's row: its [Address] numbers (real=false with the reason when they cannot be a location), or a field's offset.</summary>
    private static Il2CppRow MemberRow(string kind, string name, LoadedAssembly asm, IMemberDef member)
    {
        var row = new Il2CppRow(kind, name) { Token = Format.Token(member), Assembly = asm.Id };
        foreach (var a in Il2CppService.GetAttributes(member))
        {
            string? V(string key) => a.Values.TryGetValue(key, out var v) && v != "-1" ? v : null;
            if (a.Name.Contains("Address", StringComparison.Ordinal))
                row = row with
                {
                    Rva = V("RVA"), Va = V("VA"), FileOffset = V("Offset"), Slot = V("Slot"),
                    Real = a.InvalidAddress ? false : null,
                    Detail = a.InvalidAddress ? "not a real address: no native code of its own (a generic method used only through shared instantiations)" : row.Detail,
                };
            else if (a.Name == "FieldOffsetAttribute") row = row with { FieldOffset = V("Offset") };
        }
        return row;
    }

    /// <summary>A method's native code: function bounds, the methods sharing it, its MethodInfo slot and generic instantiations.</summary>
    private Il2CppRow AppendCode(StringBuilder sb, Il2CppNavigator.Image image, LoadedAssembly asm, MethodDef method, int offset, int limit, Facts facts, Il2CppRow row,
        CancellationToken ct)
    {
        var rva = il2cpp.GetIndex(asm).FirstOrDefault(e => e.Method == method)?.Rva;
        if (image.Problem != null) sb.AppendLine($"  ({image.Problem})");
        if (rva is <= uint.MaxValue && Il2CppNavigator.Function(image, (uint)rva) is { IsExactStart: true } f)
        {
            if (image.Script != null && f.End is { } end)
            {
                sb.AppendLine($"  native code: RVA 0x{f.Start:X}-0x{end:X} (0x{end - f.Start:X} bytes up to the next function start)");
                row = row with { Size = $"0x{end - f.Start:X}" };
            }
            var (methods, scriptMethods) = Il2CppNavigator.MethodsSharing(image, f.Start);
            int total = methods.Count + scriptMethods.Count;
            if (total > 1)
            {
                sb.AppendLine($"  code shared by {total} methods (identical code or shared generics; find_method_by_address 0x{f.Start:X} lists them)");
                row = row with { Detail = $"code shared by {total} methods" };
            }
        }
        if (image.Script is not { } script) return row;
        foreach (var info in Il2CppNavigator.MethodInfos(script, method, rva).Take(5))
        {
            var target = script.MethodInfoTarget(info);
            sb.AppendLine($"  MethodInfo slot: RVA 0x{script.MethodInfoAddress(info):X}" +
                          (target > 0 ? $" (describes the function at RVA 0x{target:X})" : " (no code of its own)"));
            facts.Members.Add(new Il2CppRow("method_info", script.ReadMethodInfo(info).Name)
                { Rva = $"0x{script.MethodInfoAddress(info):X}", Detail = target > 0 ? $"describes the function at RVA 0x{target:X}" : "no code of its own" });
        }
        var instances = navigator.Instantiations(image, method, ct);
        var entries = instances.Entries;
        if (entries.Count == 0 && instances.Unmatched == 0) return row;
        int ambiguous = entries.Count(x => x.Match.Outcome == Il2CppOverloads.Outcome.Ambiguous);
        sb.AppendLine($"  generic instantiations in script.json: {entries.Count}{Showing(offset, limit, entries.Count)}" +
                      (instances.Overloads > 1 ? $"; {instances.Overloads} methods share the name, told apart by generic arity and C signature" +
                                                 (ambiguous > 0 ? $" ({ambiguous} ambiguous)" : "") : ""));
        var page = new List<Il2CppRow>();
        foreach (var (e, match) in entries.Skip(offset).Take(limit))
        {
            string? why = match.Outcome == Il2CppOverloads.Outcome.Ambiguous
                ? $"ambiguous, {match.Basis} as {string.Join("; ", match.Methods.Where(m => m != method).Select(MethodLine))}" : null;
            sb.AppendLine($"    {script.MethodName(e)}  RVA 0x{script.MethodAddress(e):X}" + (why != null ? $"  ({why})" : ""));
            page.Add(new Il2CppRow("instantiation", script.MethodName(e)) { Rva = $"0x{script.MethodAddress(e):X}", Detail = why });
        }
        facts.Page(page, entries.Count);
        AppendMore(sb, offset, limit, entries.Count, "    ");
        if (instances.Unmatched > 0)
            sb.AppendLine($"  ({instances.Unmatched} more script.json {(instances.Unmatched == 1 ? "entry" : "entries")} of the name fit no overload's parameter count)");
        return row;
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

    private static void AppendTypeMetadata(StringBuilder sb, Il2CppScript script, TypeDef type, int offset, int limit, Facts facts)
    {
        var slots = Il2CppNavigator.TypeMetadata(script, type);
        if (slots.Count == 0) return;
        bool generic = type.HasGenericParameters || type.DeclaringType?.HasGenericParameters == true;
        sb.AppendLine($"  metadata slots{(generic ? " of its instantiations" : "")}: {slots.Count}{Showing(offset, limit, slots.Count)}");
        var page = new List<Il2CppRow>();
        foreach (var e in slots.Skip(offset).Take(limit))
        {
            var signature = script.ReadMetadata(e).Signature;
            sb.AppendLine($"    {script.MetadataName(e)}  RVA 0x{script.MetadataAddress(e):X}{(string.IsNullOrEmpty(signature) ? "" : $"  ({signature})")}");
            page.Add(new Il2CppRow("metadata_slot", script.MetadataName(e)) { Rva = $"0x{script.MetadataAddress(e):X}", Detail = string.IsNullOrEmpty(signature) ? null : signature });
        }
        facts.Page(page, slots.Count);
        AppendMore(sb, offset, limit, slots.Count, "    ");
    }

    private void AppendSlot(StringBuilder sb, TypeDef type, string slot, int offset, int limit, Facts facts)
    {
        var vtable = Il2CppNavigator.VTable(type);
        if (slot.Trim().Equals("all", StringComparison.OrdinalIgnoreCase))
        {
            sb.AppendLine($"  vtable slots declared by it and its base types: {vtable.Count}{Showing(offset, limit, vtable.Count)}");
            var page = new List<Il2CppRow>();
            foreach (var (n, m) in vtable.Skip(offset).Take(limit))
            {
                sb.AppendLine($"    slot {n}: {SlotLine(type, m)}");
                page.Add(SlotRow(type, n, m));
            }
            facts.Page(page, vtable.Count);
            AppendMore(sb, offset, limit, vtable.Count, "    ");
            return;
        }
        if (Il2CppService.ParseNumber(slot) is not { } number || number > int.MaxValue)
            throw new ToolError(ErrorCode.InvalidArgument, $"slot '{slot}' is not a number or 'all'.", "pass a vtable slot number, or slot=all to list them");
        if (vtable.TryGetValue((int)number, out var method))
        {
            sb.AppendLine($"  slot {number}: {SlotLine(type, method)}");
            facts.Members.Add(SlotRow(type, (int)number, method));
        }
        else
            sb.AppendLine($"  slot {number}: no method of {type.FullName} or its base types declares it" +
                          (vtable.Count > 0 ? $" (declared slots: {vtable.Keys.First()}-{vtable.Keys.Last()})" : " (no slots: the dummy methods carry no Slot values)"));
    }

    private Il2CppRow SlotRow(TypeDef type, int slot, MethodDef m)
    {
        var asm = workspace.Assemblies.FirstOrDefault(a => a.Module == m.Module);
        return (asm != null ? MemberRow("vtable_slot", Format.MemberLabel(m), asm, m) : new Il2CppRow("vtable_slot", Format.MemberLabel(m)) { Token = Format.Token(m) }) with
        {
            Slot = slot.ToString(System.Globalization.CultureInfo.InvariantCulture),
            Detail = m.DeclaringType == type ? null : $"inherited from {m.DeclaringType.FullName}",
        };
    }

    private string SlotLine(TypeDef type, MethodDef m)
    {
        var address = Il2CppService.CompactSummary(m);
        var owner = m.DeclaringType == type ? "" : $"  (inherited from {m.DeclaringType.FullName})";
        var asm = workspace.Assemblies.FirstOrDefault(a => a.Module == m.Module);
        return $"{Format.MemberLabel(m)}  {address ?? "no native code"}{owner}  [{asm?.Id}] {Format.Token(m)}";
    }

    /// <summary>A name only script.json has: generic instantiations, metadata and MethodInfo slots. Null when it names nothing there.</summary>
    private string? ScriptLookup(string query, string? assembly, int offset, int limit, Facts facts, CancellationToken ct)
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
                var types = navigator.TypeOfMetadata(image, m.Name).Take(5).ToList();
                foreach (var t in types)
                    sb.AppendLine($"  type {t.Label}  [{t.Assembly.Id}] {Format.Token(t.Member)}");
                facts.Members.Add(new Il2CppRow("metadata_slot", m.Name)
                {
                    Rva = $"0x{script.MetadataAddress(e):X}",
                    Detail = string.Join("; ", new[] { string.IsNullOrEmpty(m.Signature) ? null : m.Signature }.Concat(types.Select(t => $"type {t.Label} [{t.Assembly.Id}] {Format.Token(t.Member)}")).OfType<string>()) is { Length: > 0 } d ? d : null,
                });
            }
            foreach (var e in infos)
            {
                var target = script.MethodInfoTarget(e);
                sb.AppendLine($"MethodInfo slot {query.Trim()}: RVA 0x{script.MethodInfoAddress(e):X}" +
                              (target > 0 ? $"; its code: RVA 0x{target:X} (find_method_by_address 0x{target:X})" : "; no code of its own"));
                facts.Members.Add(new Il2CppRow("method_info", query.Trim())
                    { Rva = $"0x{script.MethodInfoAddress(e):X}", Detail = target > 0 ? $"its code: RVA 0x{target:X}" : "no code of its own" });
            }
            rows.AddRange(Il2CppNavigator.FindScriptMethods(script, query, ct).Select(e => (image, e)));
        }
        if (rows.Count == 0) return sb.Length > 0 ? sb.ToString() : null;

        sb.AppendLine($"script.json: {Plural(rows.Count, "method")} named '{query}'{Showing(offset, limit, rows.Count)}:");
        var page = new List<Il2CppRow>();
        foreach (var (image, e) in rows.Skip(offset).Take(limit))
        {
            var script = image.Script!;
            uint address = script.MethodAddress(e);
            var name = script.MethodName(e);
            var line = new StringBuilder($"  {name}  RVA 0x{address:X}");
            var row = new Il2CppRow("script_method", name) { Rva = $"0x{address:X}" };
            var details = new List<string>();
            var f = Il2CppNavigator.Function(image, address);
            if (f?.End is { } end)
            {
                line.Append($" (0x{end - address:X} bytes)");
                row = row with { Size = $"0x{end - address:X}" };
            }
            var (methods, scriptMethods) = Il2CppNavigator.MethodsSharing(image, address);
            if (methods.Count + scriptMethods.Count > 1)
            {
                line.Append($"; code shared by {methods.Count + scriptMethods.Count} methods");
                details.Add($"code shared by {methods.Count + scriptMethods.Count} methods");
            }
            // Overloads share a MethodInfo name; the slot describing this function is the one.
            var infos = script.MethodInfosNamed("Method$" + name.Replace("$$", ".") + "()");
            if (infos.FirstOrDefault(i => script.MethodInfoTarget(i) == address, infos.FirstOrDefault(-1)) is var info and >= 0)
            {
                line.Append($"; MethodInfo slot RVA 0x{script.MethodInfoAddress(info):X}");
                details.Add($"MethodInfo slot RVA 0x{script.MethodInfoAddress(info):X}");
            }
            sb.AppendLine(line.ToString());
            if (DefinitionLine(image, e) is { } definition)
            {
                sb.AppendLine("      " + definition);
                details.Add(definition);
            }
            page.Add(row with { Detail = details.Count > 0 ? string.Join("; ", details) : null });
        }
        facts.Page(page, rows.Count);
        AppendMore(sb, offset, limit, rows.Count, "");
        return sb.ToString();
    }

    private static string Showing(int offset, int limit, int total) =>
        total > limit || offset > 0 ? offset >= total ? $" (none from offset {offset})" : $" (showing {offset + 1}-{Math.Min(total, (long)offset + limit)})" : "";

    private static void AppendMore(StringBuilder sb, int offset, int limit, int total, string indent)
    {
        if ((long)offset + limit < total) sb.AppendLine($"{indent}[More: offset={offset + limit}]"); // long: offset may be int.MaxValue
    }

    private const int MaxLiteralsPerMethod = 100;

    private void AppendLiterals(StringBuilder sb, LoadedAssembly asm, MethodDef method, Facts facts)
    {
        if (strings.DumpsFor([asm]) is not [var (dump, _)] || il2cpp.GetIndex(asm).FirstOrDefault(e => e.Method == method)?.Rva is not { } rva || rva > uint.MaxValue)
            return;
        if (dump.References == null) { sb.AppendLine($"  string literals: unknown ({dump.ReferenceProblem})"); return; }
        var used = strings.LiteralsUsedBy(dump, (uint)rva);
        sb.AppendLine($"  string literals loaded by its native code: {used.Count}");
        foreach (var (literal, sites) in used.Take(MaxLiteralsPerMethod))
        {
            var value = Format.Clip(dump.Values[literal], 200);
            sb.AppendLine($"    {Format.Literal(value)}  slot RVA 0x{dump.Addresses[literal]:X}{(sites > 1 ? $" x{sites}" : "")}");
            facts.Members.Add(new Il2CppRow("literal", value) { Rva = $"0x{dump.Addresses[literal]:X}", Detail = sites > 1 ? $"loaded at {sites} sites" : null });
        }
        if (used.Count > MaxLiteralsPerMethod) sb.AppendLine($"    … {used.Count - MaxLiteralsPerMethod} more");
    }

    [McpServerTool(Name = "export_il2cpp_symbols", Title = "Export IDA/Ghidra scripts", UseStructuredContent = true, OutputSchemaType = typeof(Il2CppExport))]
    [Description("Export Il2Cpp dummy-DLL metadata for native analysis: IDA Python and Ghidra scripts that create, name (Ns.Type$$Method) and comment " +
                 "every function (by RVA), a C header of struct layouts, and an Il2CppDumper-style script.json.")]
    public Task<string> ExportIl2CppSymbols(
        [Description("Output directory.")] string outputDirectory,
        [Description("Comma-separated: ida, ghidra, header, json or all.")] string formats = "all",
        [Description("Base name of the generated files.")] string baseName = "il2cpp",
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Replace same-named files.")] bool overwrite = false,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var result = exporter.Export(workspace.Scope(assembly), outputDirectory, formats, baseName, cancellationToken, overwrite);
        var files = result.Files.Select(f => new Il2CppExportFile(f, new FileInfo(f).Length, Sha256Of(f))).ToList();
        return ToolOutput.With($"Exported {result.Methods} functions and {result.Structs} struct layouts:\n  " + string.Join("\n  ", result.Files) +
               "\nIDA: File > Script file... on the _ida.py. Ghidra: run the _ghidra.py from the Script Manager; import the .h with File > Parse C Source.",
            new Il2CppExport(result.Methods, result.Structs, files));
    }, cancellationToken);

    private static string Sha256Of(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(stream));
    }

    [McpServerTool(Name = "find_method_by_address", Title = "Native address to method", UseStructuredContent = true, OutputSchemaType = typeof(Il2CppLookup))]
    [Description("Map a native address (IDA, Ghidra, crash log) of an Il2Cpp game to the method(s) whose function holds it, or the string literal, " +
                 "type metadata or MethodInfo slot at it; script.json names generic instantiations (without it, a guess).")]
    public Task<string> FindMethodByAddress(
        [Description("Hex as IDA / Ghidra show it (0x1A2B3C, 1A2B3Ch, 00000001`8001A2B3); d: prefix for decimal.")] string address,
        [Description("auto: a VA at or above the image base, else an RVA, else a file offset.")] string kind = "auto",
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Max methods listed.")] int limit = DefaultListLimit,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var value = Il2CppService.ParseAddress(address) ?? throw new ToolError(ErrorCode.InvalidArgument, $"'{address}' is not a valid hex address.",
            "pass hex as IDA or Ghidra shows it (0x1A2B3C, 1A2B3Ch), or d:<decimal>");
        offset = Math.Max(0, offset);
        limit = ClampLimit(limit);
        var scope = workspace.Scope(assembly);
        var results = navigator.Locate(value, kind, scope);
        var rows = new List<Il2CppMatch>();
        int total = 0;
        string Done(string text) => ToolOutput.Report(text.ReplaceLineEndings("\n"), new Il2CppLookup($"0x{value:X}", rows, offset, total));
        if (results.Count == 0)
        {
            var known = navigator.ImagesFor(scope).Where(i => i.Script != null).ToList();
            return Done(known.Count == 0
                ? $"No method found at or before 0x{value:X}."
                : $"0x{value:X} is not inside a known function or at a metadata slot ({string.Join("; ", known.Select(i => $"functions of {Path.GetFileName(i.Script!.Path)} start at RVA 0x{i.Starts[0]:X}-0x{i.Starts[^1]:X}"))}).");
        }
        var sb = new StringBuilder($"Address 0x{value:X}:\n");
        foreach (var r in results)
        {
            var k = r.Kind.ToUpperInvariant();
            if (r.Kind == "offset" && !kind.Equals("offset", StringComparison.OrdinalIgnoreCase))
                sb.AppendLine($"  (nothing at RVA 0x{value:X}; read as a file offset: RVA 0x{r.Rva:X})");
            if (r.Slot is { } slot)
            {
                rows.Add(AppendSlot(sb, r, slot, k));
                total = Math.Max(total, 1);
                continue;
            }
            var f = r.Function!;
            if (r.Image.Problem != null) sb.AppendLine($"  ({r.Image.Problem})");
            string? size = f.End is { } fe ? $"0x{fe - f.Start:X}" : null;
            // Exact bounds (a start, or inside a known length) are observed; past a length or the last start, a guess.
            string? basis = f.Relation.StartsWith("exact", StringComparison.Ordinal) || f.Relation.StartsWith("inside", StringComparison.Ordinal) ? null : "inferred";
            Il2CppMatch Match(string kindName, string method) => new(kindName, method, r.Kind, $"0x{r.Rva:X}")
                { Function = $"0x{f.Start:X}", Size = size, OffsetInFunction = $"0x{r.Rva - f.Start:X}", Basis = basis, Relation = f.Relation };
            if (r.Total > 1 || (r.Image.Script != null && f.End != null))
                sb.AppendLine($"  function at RVA 0x{f.Start:X}{(r.Image.Script != null && f.End is { } end ? $" (0x{end - f.Start:X} bytes up to the next function start)" : "")}" +
                              (r.Total > 1 ? $": {r.Total} methods share this code ({r.Methods.Count} dummy-DLL, {r.ScriptMethods.Count} script.json only){Showing(offset, limit, r.Total)}" : ""));
            if (r.Total == 0)
            {
                sb.AppendLine($"  [{k}] {f.Relation}: function at 0x{r.InKind(f.Start):X} (no method name in the dump)");
                rows.Add(Match("function", $"sub_{f.Start:X}"));
            }
            total = Math.Max(total, Math.Max(r.Total, 1));
            var start = r.InKind(f.Start);
            foreach (var m in r.Methods.Skip(offset).Take(limit))
            {
                sb.AppendLine($"  [{k}] {f.Relation}: {Format.MemberLabel(m.Method)}  (start 0x{start:X})  [{m.Assembly.Id}] {Format.Token(m.Method)}");
                rows.Add(Match("method", Format.MemberLabel(m.Method)) with { Token = Format.Token(m.Method), Assembly = m.Assembly.Id });
            }
            var script = r.Image.Script;
            foreach (var e in r.ScriptMethods.Skip(Math.Max(0, offset - r.Methods.Count)).Take((int)Math.Max(0, (long)offset + limit - Math.Max(offset, r.Methods.Count))))
            {
                sb.AppendLine($"  [{k}] {f.Relation}: {script!.MethodName(e)}  (start 0x{start:X})  script.json (no dummy-DLL method)");
                var definition = DefinitionLine(r.Image, e);
                if (definition != null) sb.AppendLine("      " + definition);
                rows.Add(Match("script_method", script.MethodName(e)) with { Detail = definition });
            }
            AppendMore(sb, offset, limit, r.Total, "  ");
        }
        return Done(sb.ToString());
    }, cancellationToken);

    private Il2CppMatch AppendSlot(StringBuilder sb, Il2CppNavigator.AddressResult r, Il2CppNavigator.DataSlot slot, string k)
    {
        var at = r.Rva > slot.Address ? $" (+0x{r.Rva - slot.Address:X} into the slot at 0x{r.InKind(slot.Address):X})" : "";
        var script = r.Image.Script;
        var row = new Il2CppMatch("literal", "", r.Kind, $"0x{r.Rva:X}") { Function = $"0x{slot.Address:X}", OffsetInFunction = $"0x{r.Rva - slot.Address:X}" };
        switch (slot.Kind)
        {
            case Il2CppNavigator.SlotKind.Literal:
                var value = Format.Clip(r.Image.Dump!.Values[slot.Entry], 200);
                sb.AppendLine($"  [{k}] string literal slot: {Format.Literal(value)}{at}  (search_strings lists the code that loads it)");
                return row with { Method = value };
            case Il2CppNavigator.SlotKind.Metadata:
                var m = script!.ReadMetadata(slot.Entry);
                sb.AppendLine($"  [{k}] metadata slot: {m.Name}{at}{(string.IsNullOrEmpty(m.Signature) ? "" : $"  ({m.Signature})")}");
                var types = navigator.TypeOfMetadata(r.Image, m.Name).Take(5).ToList();
                foreach (var t in types)
                    sb.AppendLine($"      type {t.Label}  [{t.Assembly.Id}] {Format.Token(t.Member)}");
                return row with
                {
                    Kind = "metadata_slot", Method = m.Name,
                    Token = types.FirstOrDefault() is { } first ? Format.Token(first.Member) : null, Assembly = types.FirstOrDefault()?.Assembly.Id,
                    Detail = string.IsNullOrEmpty(m.Signature) ? null : m.Signature,
                };
            default:
                var info = script!.ReadMethodInfo(slot.Entry);
                sb.AppendLine($"  [{k}] MethodInfo slot: {info.Name}{at}");
                row = row with { Kind = "method_info", Method = info.Name };
                if (script.MethodInfoTarget(slot.Entry) is not (var target and > 0))
                {
                    sb.AppendLine("      no code of its own (generic definition, or never compiled)");
                    return row with { Detail = "no code of its own" };
                }
                var (methods, scriptMethods) = Il2CppNavigator.MethodsSharing(r.Image, target);
                var named = methods.Select(x => $"{Format.MemberLabel(x.Method)}  [{x.Assembly.Id}] {Format.Token(x.Method)}")
                    .Concat(scriptMethods.Select(e => script.MethodName(e))).FirstOrDefault();
                var code = $"its code: RVA 0x{target:X}{(named != null ? $" ({named}{(methods.Count + scriptMethods.Count > 1 ? $" and {methods.Count + scriptMethods.Count - 1} more sharing it" : "")})" : "")}";
                sb.AppendLine("      " + code);
                return row with { Detail = code };
        }
    }
}

/// <summary>A get_il2cpp_info row: a member with its native numbers, or an entry of one of the long lists.</summary>
public sealed record Il2CppRow(
    [property: Description("type, method, field, method_info, literal, vtable_slot, metadata_slot, instantiation or script_method.")] string Kind,
    string Name)
{
    public string? Token { get; init; }
    public string? Assembly { get; init; }
    public string? Rva { get; init; }
    public string? Va { get; init; }
    public string? FileOffset { get; init; }
    public string? Slot { get; init; }
    [Description("Fields: the offset in the object.")] public string? FieldOffset { get; init; }
    [Description("Native code size up to the next function start.")] public string? Size { get; init; }
    [Description("false: the dumper's address is not a real location (detail says why).")] public bool? Real { get; init; }
    public string? Detail { get; init; }
}

/// <summary>get_il2cpp_info: members resolved in full; items are the long lists' entries from offset (instantiations, metadata or vtable slots, script.json methods).</summary>
public sealed record Il2CppInfo(string Symbol, IReadOnlyList<Il2CppRow> Members, IReadOnlyList<Il2CppRow> Items, int Offset,
    [property: Description("Entries of the longest list.")] int Total);

/// <summary>A find_method_by_address row: a method whose function holds the address, or the data slot at it.</summary>
public sealed record Il2CppMatch(
    [property: Description("method, script_method, function (no name), literal, metadata_slot or method_info.")] string Kind,
    [property: Description("The method, slot name or literal.")] string Method,
    [property: Description("How the address was read: va, rva or offset.")] string AddressKind,
    string Rva)
{
    public string? Token { get; init; }
    public string? Assembly { get; init; }
    [Description("RVA of the function (or slot) start.")] public string? Function { get; init; }
    public string? Size { get; init; }
    public string? OffsetInFunction { get; init; }
    [Description("inferred: past the function's known end or last start, a guess; absent: in bounds.")] public string? Basis { get; init; }
    public string? Relation { get; init; }
    public string? Detail { get; init; }
}

public sealed record Il2CppLookup(string Address, IReadOnlyList<Il2CppMatch> Items, int Offset, int Total);

public sealed record Il2CppExportFile(string Path, long Bytes, string Sha256);

public sealed record Il2CppExport(int Functions, int Structs, IReadOnlyList<Il2CppExportFile> Files);
