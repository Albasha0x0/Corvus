using System.ComponentModel;
using System.Text;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

/// <summary>Native PE images: headers, imports, exports, addresses and bytes.</summary>
[McpServerToolType]
public sealed class NativeTools(AssemblyWorkspace workspace, OutputPager pager, NativeCodeService? code = null, NativeLinkService? link = null)
{
    public const string ImageDescription = "Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded.";

    /// <summary>Runs work on a loaded native image under the read lock; a path that is not loaded yet is loaded first.</summary>
    private Task<string> OnImage(string image, Func<LoadedNative, string> work, CancellationToken ct) => Task.Run(() =>
    {
        var id = workspace.Read(() => workspace.FindNative(image)?.Id);
        if (id == null && !string.IsNullOrWhiteSpace(image) && Path.IsPathFullyQualified(image.Trim()) && File.Exists(image.Trim()))
        {
            var (assembly, native) = workspace.LoadAny(image.Trim());
            id = native?.Id ?? throw new ToolError(ErrorCode.Unsupported, $"{image} is a .NET assembly (loaded as {assembly!.Id}), not a native image.",
                "use the .NET tools for it");
        }
        return workspace.Read(() => work(workspace.GetNative(id ?? image)));
    }, ct);
    public const string AddressDescription =
        "Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name.";

    [McpServerTool(Name = "get_pe_info", Title = "PE overview")]
    [Description("Overview of a native PE image: machine, kind, subsystem, image base, entry point, timestamps, linker, sections (with flags and entropy), " +
                 "security mitigations (ASLR, DEP, CFG, SafeSEH, GS cookie, CET...), import/export counts, TLS callbacks, debug info (PDB path and GUID), " +
                 "load config, version resource, manifest, rich header (toolchain), checksum, overlay, Authenticode signature, and anything malformed.")]
    public Task<string> GetPeInfo(
        [Description(ImageDescription)] string image,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => OnImage(image, native =>
    {
        var index = code?.Ready(native);
        return pager.Page(pager.GetOrCreate($"peinfo|{native.Id}|{native.Image.Sha256}|{PdbTools.Status(native)}|{index != null}",
            () => PeInfo(native, code == null ? "" : NativeCallTools.DynamicSection(index, cancellationToken))), offset, maxChars);
    }, cancellationToken);

    private static string PeInfo(LoadedNative native, string dynamicImports = "")
    {
        var pe = native.Image;
        var sb = new StringBuilder();
        sb.AppendLine($"{native.Id}: {pe.MachineName} {(pe.IsDll ? "DLL" : "executable")} ({(pe.Is64Bit ? "PE32+" : "PE32")}), {pe.SubsystemName}");
        sb.AppendLine($"  {native.FilePath}");
        sb.AppendLine($"  {pe.FileSize:N0} bytes, sha256 {pe.Sha256}");
        sb.AppendLine($"  image base 0x{pe.ImageBase:X}, size 0x{pe.SizeOfImage:X}, entry point " +
                      (pe.EntryPointRva == 0 ? "none" : NativeAddress.Describe(pe, pe.EntryPointRva)));
        sb.AppendLine($"  linker {pe.Optional.MajorLinkerVersion}.{pe.Optional.MinorLinkerVersion}, OS {pe.Optional.MajorOperatingSystemVersion}.{pe.Optional.MinorOperatingSystemVersion}, " +
                      $"subsystem {pe.Optional.MajorSubsystemVersion}.{pe.Optional.MinorSubsystemVersion}, timestamp 0x{pe.Coff.TimeDateStamp:X8}" +
                      (pe.Coff.TimeDateStamp is > 0x30000000 and < 0x7FFFFFFF ? $" ({DateTimeOffset.FromUnixTimeSeconds(pe.Coff.TimeDateStamp):yyyy-MM-dd HH:mm} UTC)" : " (not a date: reproducible build hash or zeroed)"));
        sb.AppendLine($"  characteristics: {string.Join(", ", pe.CharacteristicNames)}");
        if (pe.DllCharacteristicNames.Count > 0) sb.AppendLine($"  DLL characteristics: {string.Join(", ", pe.DllCharacteristicNames)}");
        if (pe.IsDotNet) sb.AppendLine("  has .NET metadata (mixed-mode or loaded as native): the .NET tools apply to it too");

        var m = pe.Mitigations;
        var on = new List<string>();
        var off = new List<string>();
        void M(string name, bool value) => (value ? on : off).Add(name);
        M("ASLR", m.Aslr); M("high-entropy VA", m.HighEntropyVa); M("DEP", m.Dep); M("CFG", m.ControlFlowGuard); M("SafeSEH", m.SafeSeh);
        M("GS cookie", m.GsCookie); M("CET", m.CetCompatible); M("XFG", m.Xfg); M("EH continuation", m.EhContinuation); M("force integrity", m.ForceIntegrity);
        sb.AppendLine($"Mitigations: on: {(on.Count > 0 ? string.Join(", ", on) : "none")}; off: {(off.Count > 0 ? string.Join(", ", off) : "none")}" + (m.NoSeh ? "; no SEH" : ""));

        sb.AppendLine($"Sections ({pe.Sections.Count}):");
        foreach (var layout in pe.SectionLayouts)
        {
            var s = layout.Section;
            sb.AppendLine($"  {s.Name,-8} rva 0x{s.Rva:X8} vsize 0x{s.VirtualSize:X8} raw 0x{s.RawOffset:X8}+0x{s.RawSize:X} " +
                          $"{Access(s.Access)} entropy {Entropy(pe, layout):0.00}" + (layout.CharacteristicNames.Count > 0 ? $"  [{string.Join(", ", layout.CharacteristicNames)}]" : ""));
        }

        sb.AppendLine($"Imports: {Plural(pe.ImportModules.Count, "module")}, {Plural(pe.ImportModules.Sum(i => i.Functions.Count), "function")}" +
                      (pe.DelayImportModules.Count > 0 ? $"; delay-loaded: {Plural(pe.DelayImportModules.Count, "module")}, {Plural(pe.DelayImportModules.Sum(i => i.Functions.Count), "function")}" : "") +
                      (pe.BoundImports.Count > 0 ? $"; {Plural(pe.BoundImports.Count, "bound module")}" : "") + " (list_imports)");
        sb.Append(dynamicImports);
        sb.AppendLine($"Exports: {Plural(pe.Exports.Count, "entry")}" +
                      (pe.ExportDirectory is { } ed ? $" (name {ed.DllName ?? "none"}, {Plural(pe.Exports.Count(e => e.ForwardedTo != null), "forwarder")})" : "") + " (list_exports)");
        if (pe.RuntimeFunctions.Count > 0) sb.AppendLine($"Exception directory: {Plural(pe.RuntimeFunctions.Count, "function range")}");
        if (pe.TlsCallbackRvas.Count > 0)
            sb.AppendLine($"TLS callbacks (run before the entry point): {string.Join(", ", pe.TlsCallbackRvas.Take(16).Select(r => NativeAddress.Va(pe, r)))}");
        foreach (var d in pe.DebugEntries.Take(8))
            sb.AppendLine($"Debug: {PeFile.DebugTypeName(d.Type)}");
        if (pe.CodeView is { } cv) sb.AppendLine($"  PDB: {cv.PdbPath} ({cv.Format}, GUID {cv.Guid:D}, age {cv.Age})");
        if (PdbTools.Status(native) is { } pdbStatus) sb.AppendLine("  " + pdbStatus);
        if (pe.LoadConfig is { } lc)
        {
            sb.Append($"Load config: version {lc.MajorVersion}.{lc.MinorVersion}, size {lc.Size}");
            if (lc.SecurityCookie != 0) sb.Append($", security cookie at 0x{lc.SecurityCookie:X}");
            if (lc.SeHandlerRvas.Count > 0) sb.Append($", {Plural(lc.SeHandlerRvas.Count, "SafeSEH handler")}");
            if (lc.GuardCfFunctions.Count > 0) sb.Append($", {Plural(lc.GuardCfFunctions.Count, "CFG target")}");
            if (lc.GuardFlagNames.Count > 0) sb.Append($"; guard flags: {string.Join(", ", lc.GuardFlagNames)}");
            sb.AppendLine();
        }
        if (pe.VersionInfo is { } vi)
        {
            if (vi.Fixed is { } fx) sb.AppendLine($"Version: file {fx.FileVersionText}, product {fx.ProductVersionText}");
            foreach (var table in vi.StringTables.Take(2))
                foreach (var (key, value) in table.Strings.Where(kv => kv.Value.Length > 0).Take(12))
                    sb.AppendLine($"  {key}: {Format.Clip(value, 200)}");
        }
        if (pe.Manifest is { } manifest)
        {
            var level = System.Text.RegularExpressions.Regex.Match(manifest, "requestedExecutionLevel[^>]*level=\"([^\"]+)\"");
            sb.AppendLine($"Manifest: {manifest.Length:N0} chars" + (level.Success ? $", requested execution level {level.Groups[1].Value}" : "") + " (get_resource for the text)");
        }
        var resourceCount = pe.Resources.Count;
        if (resourceCount > 0)
            sb.AppendLine($"Resources: {Plural(resourceCount, "entry")} by type: " +
                          string.Join(", ", pe.Resources.GroupBy(r => r.TypeName).Select(g => $"{g.Key} {g.Count()}")) + " (list_resources)");
        if (pe.RichHeader is { } rich)
            sb.AppendLine($"Rich header: {Plural(rich.Entries.Count, "toolchain record")}{(rich.ChecksumValid ? "" : " (checksum does not match: edited after linking)")}; " +
                          string.Join(", ", rich.Entries.OrderByDescending(e => e.Count).Take(6).Select(e => $"product {e.ProductId} build {e.Build} x{e.Count}")));
        var ck = pe.Checksum;
        sb.AppendLine(ck.Stored == 0 ? $"Checksum: not set (computed 0x{ck.Computed:X8})" : $"Checksum: stored 0x{ck.Stored:X8}, computed 0x{ck.Computed:X8}{(ck.Matches ? " (matches)" : " (DIFFERS: modified after linking)")}");
        if (pe.Overlay is { } ov)
            sb.AppendLine($"Overlay: {ov.Size:N0} bytes at file 0x{ov.Offset:X}{(ov.IsCertificateTableOnly ? " (the signature only)" : " (data appended after the image)")}");
        var cert = pe.Certificate;
        sb.AppendLine(cert.Present ? $"Signature: {cert.Signer} (issuer {cert.Issuer}, thumbprint {cert.Thumbprint})" : "Signature: none");
        if (pe.Issues.Count > 0)
        {
            sb.AppendLine($"Parse issues ({pe.Issues.Count}):");
            foreach (var issue in pe.Issues.Take(50))
                sb.AppendLine($"  {issue.Area}: {issue.Message}" + (issue.FileOffset is { } fo ? $" (file 0x{fo:X})" : ""));
        }
        return sb.ToString();
    }

    private static string Access(SectionAccess a) =>
        $"{((a & SectionAccess.Read) != 0 ? 'r' : '-')}{((a & SectionAccess.Write) != 0 ? 'w' : '-')}{((a & SectionAccess.Execute) != 0 ? 'x' : '-')}";

    /// <summary>Shannon entropy of the section's file bytes in bits per byte (near 8: compressed or encrypted).</summary>
    private static double Entropy(PeFile pe, PeSectionLayout layout)
    {
        if (layout.LoadedFileSize == 0 || layout.LoadedFileOffset >= pe.FileSize) return 0;
        var bytes = pe.FileBytes.Span.Slice((int)layout.LoadedFileOffset, (int)Math.Min(layout.LoadedFileSize, pe.FileSize - layout.LoadedFileOffset));
        Span<int> counts = stackalloc int[256];
        foreach (var b in bytes) counts[b]++;
        double h = 0;
        foreach (var c in counts)
            if (c > 0) { double p = (double)c / bytes.Length; h -= p * Math.Log2(p); }
        return h;
    }

    [McpServerTool(Name = "list_imports", Title = "List native imports")]
    [Description("Functions a native image imports, per DLL (delay-loaded marked), with the IAT slot address code calls through. " +
                 "API set names (api-ms-win-*) are shown with the DLL they resolve to on this system. With bind=true each import is bound like the " +
                 "loader does (DLL search order, API sets, forwarders, jump thunks in loaded providers) to its export: 'at VA [image]' when the provider " +
                 "is loaded (disassemble / native_call_tree work on it), its path when not (load_assembly with that path, or with this image and " +
                 "loadProviders=true), or the reason it does not resolve (dll_not_found, api_set_unmapped, missing_export, missing_ordinal, forwarder_broken). " +
                 "includeDynamic adds late-bound imports (GetProcAddress with a constant name or ordinal, the module traced from LoadLibrary / " +
                 "GetModuleHandle), marked [dynamic].")]
    public async Task<string> ListImports(
        [Description(ImageDescription)] string image,
        [Description("Only this DLL (name with or without .dll).")] string? module = null,
        [Description("Only functions whose name contains this text (case-insensitive).")] string? filter = null,
        [Description("Bind each import to the export it reaches and summarize: bound / provider not loaded / unresolved by reason.")] bool bind = false,
        [Description("Index of the first row.")] int offset = 0,
        [Description("Max rows (default 500).")] int limit = 500,
        [Description("Also list late-bound imports (waits for the code index).")] bool includeDynamic = false,
        CancellationToken cancellationToken = default)
    {
        if (bind && link != null) await link.WarmUp(null, cancellationToken);
        List<string>? dynamicRows = null;
        if (includeDynamic && code != null)
        {
            await OnImage(image, _ => "", cancellationToken); // loads a path
            var loaded = workspace.Read(() => workspace.FindNative(image.Trim()) ?? workspace.GetNative(image));
            var index = await code.Index(loaded, null, cancellationToken);
            dynamicRows = await Task.Run(() => NativeCallTools.DynamicImportRows(index, module, filter, cancellationToken), cancellationToken);
        }
        return await OnImage(image, native =>
        {
            var pe = native.Image;
            var apiSets = ApiSets.Value;
            var rows = new List<string>();
            var bindings = new List<NativeLinkService.Binding>();
            var bySlot = bind && link != null
                ? pe.Imports.Zip(link.BindAll(native, cancellationToken)).GroupBy(p => p.First.SlotRva).ToDictionary(g => g.Key, g => g.First().Second)
                : null;
            foreach (var mod in pe.ImportModules.Concat(pe.DelayImportModules))
            {
                if (module != null && !string.Equals(Path.GetFileNameWithoutExtension(mod.Name), Path.GetFileNameWithoutExtension(module.Trim()), StringComparison.OrdinalIgnoreCase)) continue;
                var host = ApiSetSchema.IsApiSetName(mod.Name) ? apiSets?.Resolve(mod.Name, native.FilePath) : null;
                foreach (var f in mod.Functions)
                {
                    var name = f.Name ?? $"#{f.Ordinal}";
                    if (filter != null && !name.Contains(filter, StringComparison.OrdinalIgnoreCase)) continue;
                    var row = $"{NativeAddress.Va(pe, f.SlotRva)}  {mod.Name}{(host != null ? $" ({host})" : "")}!{name}{(f.IsDelayLoad ? "  [delay]" : "")}";
                    if (bySlot != null && bySlot.TryGetValue(f.SlotRva, out var b))
                    {
                        b = link!.FollowThunks(b);
                        bindings.Add(b);
                        row += "  -> " + NativeLinkService.Describe(b);
                    }
                    rows.Add(row);
                }
            }
            if (dynamicRows != null) rows.AddRange(dynamicRows);
            var head = "";
            if (bySlot != null)
            {
                var (bound, notLoaded, unresolved) = link!.Summary(bindings);
                int files = bindings.Where(b => b.Status == NativeLinkService.NotLoaded).Select(b => b.FinalFile).Distinct(StringComparer.OrdinalIgnoreCase).Count();
                head = $"Bindings: {bound} bound to loaded images, {notLoaded} in {Plural(files, "image")} not loaded, {unresolved.Values.Sum()} unresolved" +
                       (unresolved.Count > 0 ? $" ({string.Join(", ", unresolved.OrderByDescending(kv => kv.Value).Select(kv => $"{kv.Key} {kv.Value}"))})" : "") + "\n";
            }
            else if (bind) head = "Bindings: not available in this configuration\n";
            return head + pager.PageRows(rows, offset, limit, "import");
        }, cancellationToken);
    }

    [McpServerTool(Name = "list_exports", Title = "List native exports")]
    [Description("Functions and data a native image exports: ordinal, address (VA), name (with the demangled C++ form for MSVC names), and forwarders.")]
    public Task<string> ListExports(
        [Description(ImageDescription)] string image,
        [Description("Only exports whose name contains this text (case-insensitive; matches the demangled form too).")] string? filter = null,
        [Description("Index of the first row.")] int offset = 0,
        [Description("Max rows (default 500).")] int limit = 500,
        CancellationToken cancellationToken = default) => OnImage(image, native =>
    {
        var pe = native.Image;
        var rows = new List<string>();
        foreach (var e in pe.Exports)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var name = e.Name ?? "(no name)";
            var demangled = e.Name is { } n && (n.StartsWith('?') || n.StartsWith('@') || n.StartsWith('_')) ? Native.Msvc.MsvcDemangler.Undecorate(n, Native.Msvc.MsvcNameStyle.Full) : null;
            if (filter != null && !name.Contains(filter, StringComparison.OrdinalIgnoreCase) && demangled?.Contains(filter, StringComparison.OrdinalIgnoreCase) != true) continue;
            rows.Add($"#{e.Ordinal,-5} {(e.ForwardedTo != null ? "forwarder".PadRight(18) : NativeAddress.Va(pe, e.Rva).PadRight(18))} {name}" +
                     (demangled != null && demangled != name ? $"  = {demangled}" : "") + (e.ForwardedTo != null ? $"  -> {e.ForwardedTo}" : ""));
        }
        return pager.PageRows(rows, offset, limit, "export");
    }, cancellationToken);

    [McpServerTool(Name = "resolve_address", Title = "Resolve native address")]
    [Description("What an address in a native image is: RVA, VA and file offset, the section and its permissions, the nearest export or import at or before it, " +
                 "and, once the code index is built, its name and the name's source (user, pdb, il2cpp); after apply_il2cpp_names the managed method or metadata slot. " +
                 "For an IAT slot, the export it is bound to (in a loaded image: its address and image); for an export, the loaded images importing it.")]
    public Task<string> ResolveAddress(
        [Description(ImageDescription)] string image,
        [Description(AddressDescription)] string address,
        CancellationToken cancellationToken = default) => OnImage(image, native =>
    {
        var pe = native.Image;
        var index = code?.Ready(native);
        var rva = NativeAddress.Parse(pe, address, index != null ? index.AddressOfName : null);
        var sb = new StringBuilder($"{address.Trim()}: {NativeAddress.Describe(pe, rva)}\n");
        if (index?.Sourced.NameAt(rva) is { } named) sb.AppendLine($"  name {named.Name} ({named.Source.Id()})");
        foreach (var line in Il2CppNativeNames.Describe(native, index, rva)) sb.AppendLine("  " + line);
        var section = pe.SectionAt(rva);
        sb.AppendLine(section != null
            ? $"  section {section.Name} ({Access(section.Access)}), +0x{rva - section.Rva:X} into it"
            : rva < pe.Optional.SizeOfHeaders ? "  in the PE headers" : "  in no section");
        var slot = pe.Imports.FirstOrDefault(i => i.SlotRva == rva);
        if (slot != null) sb.AppendLine($"  IAT slot of {slot.Module}!{slot.Name ?? "#" + slot.Ordinal}");
        if (slot != null && link != null) sb.AppendLine($"  bound to {NativeLinkService.Describe(link.BindImport(native, slot))}");
        if (link != null) foreach (var line in link.DescribeManaged(native, rva)) sb.AppendLine("  " + line);
        if (link != null && link.ImportersOf(native, rva, cancellationToken) is { Count: > 0 } importers)
            sb.AppendLine($"  imported by {string.Join(", ", importers.GroupBy(i => i.Importer.Id).Select(g => $"{g.Key} ({string.Join(", ", g.Select(i => NativeCodeIndex.ImportName(i.Import)).Distinct())})"))}; find_xrefs lists the call sites");
        var export = pe.Exports.Where(e => e.ForwardedTo == null && e.Rva <= rva).MaxBy(e => e.Rva);
        if (export != null) sb.AppendLine(export.Rva == rva ? $"  export {export.Name ?? "#" + export.Ordinal}" : $"  nearest export before it: {export.Name ?? "#" + export.Ordinal} + 0x{rva - export.Rva:X}");
        var function = FindRuntimeFunction(pe, rva);
        if (function != null) sb.AppendLine($"  inside the unwind range 0x{pe.ImageBase + function.BeginRva:X}-0x{pe.ImageBase + function.EndRva:X}");
        return sb.ToString();
    }, cancellationToken);

    private static RuntimeFunction? FindRuntimeFunction(PeFile pe, uint rva)
    {
        var list = pe.RuntimeFunctions;
        int lo = 0, hi = list.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (list[mid].BeginRva > rva) hi = mid - 1;
            else if (list[mid].EndRva <= rva) lo = mid + 1;
            else return list[mid];
        }
        return null;
    }

    [McpServerTool(Name = "search_bytes", Title = "Search native bytes")]
    [Description("Find a byte pattern in a native image's mapped sections: hex bytes with ?? wildcards ('48 8B 05 ?? ?? ?? ?? C3'), or text with text=\"...\" " +
                 "(searched as ASCII and UTF-16). Reports each hit's VA, section and file offset.")]
    public Task<string> SearchBytes(
        [Description(ImageDescription)] string image,
        [Description("Hex bytes with ?? wildcards, or the text to find when text=true.")] string pattern,
        [Description("Treat pattern as text (ASCII and UTF-16LE).")] bool text = false,
        [Description("Only this section (e.g. .text, .rdata).")] string? section = null,
        [Description("Max hits (default 200).")] int limit = 200,
        [Description("Index of the first hit.")] int offset = 0,
        CancellationToken cancellationToken = default) => OnImage(image, native =>
    {
        var pe = native.Image;
        var patterns = text
            ? new List<(byte[] Bytes, bool[] Mask, string Label)> { Exact(Encoding.ASCII.GetBytes(pattern), "ASCII"), Exact(Encoding.Unicode.GetBytes(pattern), "UTF-16") }
            : [ParseHexPattern(pattern)];
        if (patterns.Any(p => p.Bytes.Length == 0))
            throw new ToolError(ErrorCode.InvalidArgument, "The pattern is empty.", "pass hex bytes such as '48 8B 05 ?? ?? ?? ??' or text with text=true");
        int max = ClampLimit(limit, 10_000);
        offset = Math.Max(0, offset);
        var hits = new List<string>();
        long total = 0;
        int chars = 0;
        void Hit(NativeSection s, uint rva, string label)
        {
            // Rows stop at the page size; the rest is reached with offset.
            if (total++ < offset || hits.Count >= max || chars >= 50_000) return;
            var row = $"{NativeAddress.Va(pe, rva)}  {s.Name}{(patterns.Count > 1 ? "  " + label : "")}" +
                      (pe.TryRvaToFileOffset(rva, out var fo) ? $"  file 0x{fo:X}" : "  (zero fill, not in the file)");
            hits.Add(row);
            chars += row.Length + 1;
        }
        // The file-backed part of each section is read in 1 MB chunks overlapping by the pattern length; matches in the
        // zero fill after it (which can be gigabytes) are counted, not scanned.
        int longest = patterns.Max(p => p.Bytes.Length);
        var data = new byte[(1 << 20) + longest];
        foreach (var s in pe.Sections)
        {
            if (section != null && !s.Name.Equals(section.Trim(), StringComparison.OrdinalIgnoreCase)) continue;
            uint size = (uint)Math.Min(s.MappedSize, Math.Max(0L, (long)pe.SizeOfImage - s.Rva));
            uint backed = (uint)pe.FileBackedLength(s.Rva, size);
            for (uint at = 0; at < backed; at += 1 << 20)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int read = pe.Read(s.Rva + at, data.AsSpan(0, (int)Math.Min((uint)data.Length, size - at)));
                if (read <= 0) break;
                var span = data.AsSpan(0, read);
                int starts = (int)Math.Min(Math.Min(read, 1 << 20), backed - at);
                foreach (var (bytes, mask, label) in patterns)
                {
                    // Candidates are found with a vectorized search for the fixed bytes the pattern starts with.
                    int fixedPrefix = Array.IndexOf(mask, false) is var w and >= 0 ? w : mask.Length;
                    var prefix = bytes.AsSpan(0, fixedPrefix);
                    for (int i = 0; i < starts && i + bytes.Length <= span.Length; i++)
                    {
                        int k = span[i..Math.Min(span.Length, starts + prefix.Length - 1)].IndexOf(prefix);
                        if (k < 0) break;
                        i += k;
                        if (i < starts && i + bytes.Length <= span.Length && Matches(span, i, bytes, mask)) Hit(s, s.Rva + at + (uint)i, label);
                    }
                }
            }
            foreach (var (bytes, mask, label) in patterns)
            {
                if (bytes.Where((b, i) => mask[i] && b != 0).Any() || (long)size - backed < bytes.Length) continue;
                long zeroStarts = (long)size - backed - bytes.Length + 1;
                long skip = Math.Clamp(offset - total, 0, zeroStarts);
                total += skip;
                long i = skip;
                for (; i < zeroStarts && hits.Count < max && chars < 50_000; i++) Hit(s, s.Rva + backed + (uint)i, label);
                total += zeroStarts - i;
            }
        }
        if (section != null && !pe.Sections.Any(s => s.Name.Equals(section.Trim(), StringComparison.OrdinalIgnoreCase)))
            throw new ToolError(ErrorCode.NotFound, $"No section '{section}'. Sections: {string.Join(", ", pe.Sections.Select(s => s.Name))}.");
        var more = offset + hits.Count < total ? $"\n[More: call again with offset={offset + hits.Count}]" : "";
        return $"{total} hit{(total == 1 ? "" : "s")}{(offset > 0 || hits.Count < total ? $" (showing {(hits.Count == 0 ? 0 : offset + 1)}-{offset + hits.Count})" : "")}\n" +
               string.Join("\n", hits) + more;
    }, cancellationToken);

    private static (byte[], bool[], string) Exact(byte[] bytes, string label) => (bytes, bytes.Select(_ => true).ToArray(), label);

    internal static (byte[] Bytes, bool[] Mask, string Label) ParseHexPattern(string pattern)
    {
        var tokens = pattern.Replace(",", " ").Split(' ', StringSplitOptions.RemoveEmptyEntries);
        // Unspaced hex ("488B05") is split into byte pairs.
        if (tokens.Length == 1 && tokens[0].Length > 2) tokens = Enumerable.Range(0, (tokens[0].Length + 1) / 2).Select(i => tokens[0].Substring(i * 2, Math.Min(2, tokens[0].Length - i * 2))).ToArray();
        if (tokens.Length > 4096) throw new ToolError(ErrorCode.LimitExceeded, "The pattern is longer than 4096 bytes.");
        var bytes = new byte[tokens.Length];
        var mask = new bool[tokens.Length];
        for (int i = 0; i < tokens.Length; i++)
        {
            var t = tokens[i];
            if (t is "?" or "??" or "**") continue;
            if (t.Length != 2 || !byte.TryParse(t, System.Globalization.NumberStyles.AllowHexSpecifier, null, out bytes[i]))
                throw new ToolError(ErrorCode.InvalidArgument, $"'{t}' is not a hex byte or ??.", "write the pattern as hex bytes separated by spaces, e.g. 'E8 ?? ?? ?? ?? 85 C0'");
            mask[i] = true;
        }
        if (mask.Length > 0 && !mask[0]) throw new ToolError(ErrorCode.InvalidArgument, "The pattern must start with a fixed byte, not a wildcard.");
        return (bytes, mask, "hex");
    }

    private static bool Matches(ReadOnlySpan<byte> data, int at, byte[] bytes, bool[] mask)
    {
        if (data[at] != bytes[0]) return false;
        for (int j = 1; j < bytes.Length; j++)
            if (mask[j] && data[at + j] != bytes[j]) return false;
        return true;
    }

    [McpServerTool(Name = "read_bytes", Title = "Hex dump native bytes")]
    [Description("Hex dump (with ASCII) of a native image's mapped bytes at an address, as the loader maps them.")]
    public Task<string> ReadBytes(
        [Description(ImageDescription)] string image,
        [Description(AddressDescription)] string address,
        [Description("Bytes to dump (default 256, max 65536).")] int length = 256,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => OnImage(image, native =>
    {
        var pe = native.Image;
        var rva = NativeAddress.Parse(pe, address);
        var buffer = new byte[Math.Clamp(length, 1, 65_536)];
        int read = pe.Read(rva, buffer);
        var sb = new StringBuilder($"{NativeAddress.Describe(pe, rva)}, {Plural(read, "byte")}{(read < buffer.Length ? " (end of the mapped image)" : "")}\n");
        for (int row = 0; row < read; row += 16)
        {
            int n = Math.Min(16, read - row);
            sb.Append($"{pe.ImageBase + rva + (uint)row:X}  ");
            for (int i = 0; i < 16; i++) sb.Append(i < n ? $"{buffer[row + i]:X2} " : "   ");
            sb.Append(' ');
            for (int i = 0; i < n; i++) sb.Append(buffer[row + i] is >= 0x20 and < 0x7F ? (char)buffer[row + i] : '.');
            sb.AppendLine();
        }
        return pager.Page(sb.ToString(), offset, maxChars);
    }, cancellationToken);

    private static readonly Lazy<ApiSetSchema?> ApiSets = new(() => ApiSetSchema.FromSystem(PeFile.Open));
}
