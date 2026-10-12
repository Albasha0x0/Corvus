using System.ComponentModel;
using System.Text;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Pe;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>Native images (PE, ELF, Mach-O): headers, imports, exports, addresses and bytes.</summary>
[McpServerToolType]
public sealed partial class NativeTools(AssemblyWorkspace workspace, OutputPager pager, NativeCodeService? code = null, NativeLinkService? link = null)
{
    public const string EngineTimeoutDescription = "Seconds per engine request (default CORVUS_ENGINE_REQUEST_TIMEOUT); scans then answer partial.";

    /// <summary>A tool's timeoutSeconds as an engine request limit; null when not given.</summary>
    public static TimeSpan? EngineTimeout(int? seconds) => seconds is { } s ? TimeSpan.FromSeconds(Math.Clamp(s, 1, 3600)) : null;

    public const string ImageDescription = "Native image id, file name or path (a path is loaded).";

    /// <summary>Runs work on a loaded native image under the read lock; a path that is not loaded yet is loaded first.</summary>
    private Task<string> OnImage(string image, Func<LoadedNative, string> work, CancellationToken ct) => Task.Run(() =>
    {
        var id = Targets.Native(workspace, image).Id;
        return workspace.Read(() => work(workspace.GetNative(id)));
    }, ct);
    /// <summary>A function name as people read it: MSVC-decorated names as the qualified name, Itanium and Swift mangled ones demangled; others as given.</summary>
    internal static string DisplayName(string name, ImageFormat format = ImageFormat.Pe)
    {
        if (name.Length > 1 && name[0] == '?') return Native.Pdb.PdbNaming.Display(name);
        return Demangled(name, format) ?? name;
    }

    /// <summary>The Itanium (C++) or Swift demangling of a mangled name, or null.</summary>
    internal static string? Demangled(string? name, ImageFormat format)
    {
        bool macho = format == ImageFormat.MachO;
        if (Native.Itanium.ItaniumDemangler.IsMangled(name, macho) && Native.Itanium.ItaniumDemangler.Demangle(name, macho) is { Length: > 0 } plain) return plain;
        return Native.Swift.SwiftDemangler.IsMangled(name) ? Native.Swift.SwiftDemangler.Demangle(name) : null;
    }

    /// <summary>"A::f" for a mangled name with the symbol beside it ("; symbol ?f@A@@QEAAXXZ"), so the name stays usable as input.</summary>
    internal static (string Display, string Symbol) Named(string name, ImageFormat format)
    {
        var display = DisplayName(name, format);
        return (display, display == name ? "" : $"; symbol {name}");
    }

    public const string AddressDescription =
        "Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name.";

    [McpServerTool(Name = "get_pe_info", Title = "Native image overview", UseStructuredContent = true, OutputSchemaType = typeof(PeSummary))]
    [Description("Overview of a native image. PE: machine, kind, subsystem, base, entry point, timestamps, linker, sections (flags, entropy), packers, " +
                 "mitigations (ASLR, DEP, CFG, CET...), import / export counts, TLS callbacks, PDB identity, load config, version, manifest, rich " +
                 "header, checksum, overlay, signature, anything malformed. ELF: program headers, soname, build id, relocations, hardening. Mach-O: " +
                 "slice, segments, libraries, fixups, code signature, entitlements, encryption. Go build info. Capabilities the static imports imply " +
                 "(never the code index: list_functions has its statistics).")]
    public Task<string> GetPeInfo(
        [Description(ImageDescription)] string image,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => OnImage(image, native =>
    {
        var capabilities = Capabilities(native.Image);
        var text = pager.GetOrCreate($"peinfo|{native.Id}|{native.Image.Sha256}|{PdbTools.Status(native)}",
            () => PeInfo(native) + CodeText(native.Image, capabilities));
        return StructuredOutput.With(pager.Page(text, offset, maxChars), Summary(native) with
        {
            Capabilities = capabilities.Select(c => new CapabilityEntry(c.Group, c.Count, c.Apis)).ToList(),
        });
    }, cancellationToken);

    private static string PeInfo(LoadedNative native)
    {
        if (native.Pe == null) return FormatInfo(native);
        var pe = native.RequirePe("get_pe_info");
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
        if (PeHybrid.Of(pe) is { } hybrid) HybridLines(sb, pe, hybrid);

        var (on, off) = Mitigations(pe);
        sb.AppendLine($"Mitigations: on: {(on.Count > 0 ? string.Join(", ", on) : "none")}; off: {(off.Count > 0 ? string.Join(", ", off) : "none")}" + (pe.Mitigations.NoSeh ? "; no SEH" : ""));

        sb.AppendLine($"Sections ({pe.Sections.Count}):");
        foreach (var layout in pe.SectionLayouts)
        {
            var s = layout.Section;
            sb.AppendLine($"  {s.Name,-8} rva 0x{s.Rva:X8} vsize 0x{s.VirtualSize:X8} raw 0x{s.RawOffset:X8}+0x{s.RawSize:X} " +
                          $"{Access(s.Access)} entropy {Entropy(pe, layout):0.00}" + (layout.CharacteristicNames.Count > 0 ? $"  [{string.Join(", ", layout.CharacteristicNames)}]" : ""));
        }

        PackerLines(sb, pe, pe.FileBytes.Span);
        sb.AppendLine($"Imports: {Plural(pe.ImportModules.Count, "module")}, {Plural(pe.ImportModules.Sum(i => i.Functions.Count), "function")}" +
                      (pe.DelayImportModules.Count > 0 ? $"; delay-loaded: {Plural(pe.DelayImportModules.Count, "module")}, {Plural(pe.DelayImportModules.Sum(i => i.Functions.Count), "function")}" : "") +
                      (pe.BoundImports.Count > 0 ? $"; {Plural(pe.BoundImports.Count, "bound module")}" : "") + " (list_imports)");
        sb.AppendLine($"Exports: {Plural(pe.Exports.Count, "entry")}" +
                      (pe.ExportDirectory is { } ed ? $" (name {ed.DllName ?? "none"}, {Plural(pe.Exports.Count(e => e.ForwardedTo != null), "forwarder")})" : "") + " (list_exports)");
        if (pe.RuntimeFunctions.Count > 0) sb.AppendLine($"Exception directory: {Plural(pe.RuntimeFunctions.Count, "function range")}");
        GoLine(sb, pe);
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

    private static void HybridLines(StringBuilder sb, PeFile pe, PeHybrid h)
    {
        sb.AppendLine(h.Kind == "ARM64X"
            ? $"  {h.Kind}: ARM64 code and ARM64EC / x64 code in one file; this is the ARM64 view" +
              (h.ViewMachine != null || h.ViewEntryRva != null || h.ViewDirectories.Count > 0
                  ? $"; the x64 view ({h.Arm64XFixups} ARM64X fixups): machine {h.ViewMachine ?? pe.MachineName}" +
                    (h.ViewEntryRva is { } e ? $", entry point {NativeAddress.Va(pe, e)}" : "") +
                    (h.ViewDirectories.Count > 0 ? $", its own {string.Join(", ", h.ViewDirectories)} directories" : "")
                  : "")
            : $"  {h.Kind}: an x64 image whose code is partly ARM64EC (runs natively on ARM64, x64 code under emulation)");
        var bytes = h.CodeRanges.GroupBy(r => r.Arch).Select(g => $"{g.Key} {g.Sum(r => (long)r.Length):N0} bytes");
        sb.AppendLine($"  CHPE metadata version {h.MetadataVersion}: code map of {Plural(h.CodeRanges.Count, "range")} ({string.Join(", ", bytes)})" +
                      (h.AlternateEntryRva is { } alt ? $", alternate entry point {NativeAddress.Va(pe, alt)}" : "") +
                      (h.AuxiliaryIatRva is { } aux ? $", auxiliary IAT at {NativeAddress.Va(pe, aux)}" : ""));
    }

    private static (List<string> On, List<string> Off) Mitigations(PeFile pe)
    {
        var m = pe.Mitigations;
        var on = new List<string>();
        var off = new List<string>();
        void M(string name, bool value) => (value ? on : off).Add(name);
        M("ASLR", m.Aslr); M("high-entropy VA", m.HighEntropyVa); M("DEP", m.Dep); M("CFG", m.ControlFlowGuard); M("SafeSEH", m.SafeSeh);
        M("GS cookie", m.GsCookie); M("CET", m.CetCompatible); M("XFG", m.Xfg); M("EH continuation", m.EhContinuation); M("force integrity", m.ForceIntegrity);
        return (on, off);
    }

    /// <summary>get_pe_info's facts as fields.</summary>
    private static PeSummary Summary(LoadedNative native)
    {
        if (native.Pe == null) return FormatSummary(native);
        var pe = native.RequirePe("get_pe_info");
        var (on, off) = Mitigations(pe);
        var cv = pe.CodeView;
        var ck = pe.Checksum;
        return new PeSummary(native.Id, native.FilePath, pe.MachineName, pe.IsDll ? "dll" : "exe", pe.Is64Bit ? "PE32+" : "PE32", pe.SubsystemName, pe.FileSize, pe.Sha256,
            $"0x{pe.ImageBase:X}", pe.EntryPointRva == 0 ? null : NativeAddress.Va(pe, pe.EntryPointRva), $"0x{pe.Coff.TimeDateStamp:X8}", pe.IsDotNet, on, off,
            pe.SectionLayouts.Select(l => new SectionEntry(l.Section.Name, $"0x{l.Section.Rva:X}", $"0x{l.Section.VirtualSize:X}", $"0x{l.Section.RawOffset:X}",
                $"0x{l.Section.RawSize:X}", Access(l.Section.Access), Math.Round(Entropy(pe, l), 2), l.CharacteristicNames.ToList())).ToList(),
            pe.ImportModules.Count, pe.ImportModules.Sum(i => i.Functions.Count), pe.DelayImportModules.Count, pe.Exports.Count, pe.TlsCallbackRvas.Count,
            cv?.PdbPath, cv?.Guid.ToString("D"), cv != null ? (int)cv.Age : null, pe.Certificate.Present ? pe.Certificate.Signer : null,
            ck.Stored == 0 ? null : ck.Matches, pe.Overlay?.Size, pe.Issues.Count);
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

    [McpServerTool(Name = "list_imports", Title = "List native imports", UseStructuredContent = true, OutputSchemaType = typeof(ImportList))]
    [Description("Functions a native image imports, per DLL or library (delay-loaded and lazy binding marked), with the IAT slot address code calls " +
                 "through; API set names show the DLL they resolve to. bind=true binds each import like the loader to its export: 'at VA [image]' " +
                 "when the provider is loaded, its path when not (load it, or load_assembly loadProviders=true), or the reason it does not resolve. " +
                 "includeDynamic adds GetProcAddress imports with a constant name, marked [dynamic].")]
    public async Task<string> ListImports(
        [Description(ImageDescription)] string image,
        [Description("Only this DLL (name with or without .dll).")] string? module = null,
        [Description("Name substring (case-insensitive).")] string? filter = null,
        [Description("Bind each import to the export it reaches, with a summary.")] bool bind = false,
        [Description("Index of the first row.")] int offset = 0,
        [Description("Max rows.")] int limit = 500,
        [Description("Also list late-bound imports (waits for the code index).")] bool includeDynamic = false,
        CancellationToken cancellationToken = default)
    {
        if (bind && link != null) await link.WarmUp(null, cancellationToken);
        List<string>? dynamicRows = null;
        if (includeDynamic && code != null)
        {
            var loaded = await Task.Run(() => Targets.Native(workspace, image), cancellationToken);
            var index = await code.Index(loaded, null, cancellationToken);
            dynamicRows = await Task.Run(() => NativeCallTools.DynamicImportRows(index, module, filter, cancellationToken), cancellationToken);
        }
        return await OnImage(image, native =>
        {
            if (native.Pe == null) return FormatImports(native, module, filter, bind, offset, limit);
            var pe = native.RequirePe("list_imports");
            var apiSets = ApiSets.Value;
            var rows = new List<string>();
            var bindings = new List<NativeLinkService.Binding>();
            var items = new List<ImportEntry>();
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
                    string? binding = null;
                    if (bySlot != null && bySlot.TryGetValue(f.SlotRva, out var b))
                    {
                        b = link!.FollowThunks(b);
                        bindings.Add(b);
                        binding = NativeLinkService.Describe(b);
                        row += "  -> " + binding;
                    }
                    rows.Add(row);
                    items.Add(new ImportEntry(NativeAddress.Va(pe, f.SlotRva), mod.Name, name, host, f.IsDelayLoad, false, binding, null));
                }
            }
            if (dynamicRows != null)
            {
                rows.AddRange(dynamicRows);
                // "VA  module!name  [dynamic: where; confidence; how]"
                foreach (var d in dynamicRows)
                    items.Add(DynamicRow().Match(d) is { Success: true } m
                        ? new ImportEntry(m.Groups[1].Value, m.Groups[2].Value, m.Groups[3].Value, null, false, true, null, m.Groups[4].Value)
                        : new ImportEntry("", "", d, null, false, true, null, null));
            }
            var head = "";
            if (bySlot != null)
            {
                var (bound, notLoaded, unresolved) = link!.Summary(bindings);
                int files = bindings.Where(b => b.Status == NativeLinkService.NotLoaded).Select(b => b.FinalFile).Distinct(StringComparer.OrdinalIgnoreCase).Count();
                head = $"Bindings: {bound} bound to loaded images, {notLoaded} in {Plural(files, "image")} not loaded, {unresolved.Values.Sum()} unresolved" +
                       (unresolved.Count > 0 ? $" ({string.Join(", ", unresolved.OrderByDescending(kv => kv.Value).Select(kv => $"{kv.Key} {kv.Value}"))})" : "") + "\n";
            }
            else if (bind) head = "Bindings: not available in this configuration\n";
            return StructuredOutput.With(head + pager.PageRows(rows, offset, limit, "import"),
                Paged(items, offset, limit, (page, o, total, more) => new ImportList(native.Id, page, o, total, more, head.Length > 0 ? head.Trim() : null)));
        }, cancellationToken);
    }

    [System.Text.RegularExpressions.GeneratedRegex(@"^(\S+)\s+(.+?)!(\S+)\s+\[dynamic: (.*)\]$")]
    private static partial System.Text.RegularExpressions.Regex DynamicRow();

    [McpServerTool(Name = "list_exports", Title = "List native exports", UseStructuredContent = true, OutputSchemaType = typeof(ExportList))]
    [Description("A native image's exported functions and data: ordinal, VA, name (demangled C++ form, ELF symbol version), forwarders and re-exports.")]
    public Task<string> ListExports(
        [Description(ImageDescription)] string image,
        [Description("Name substring (case-insensitive; the demangled form too).")] string? filter = null,
        [Description("Index of the first row.")] int offset = 0,
        [Description("Max rows.")] int limit = 500,
        CancellationToken cancellationToken = default) => OnImage(image, native =>
    {
        var pe = native.Image;
        bool ordinals = pe.Format == ImageFormat.Pe;
        var rows = new List<string>();
        var items = new List<ExportEntry>();
        foreach (var e in pe.Exports)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var name = e.Name ?? "(no name)";
            var demangled = !ordinals ? Demangled(e.Name, pe.Format)
                : e.Name is { } n && (n.StartsWith('?') || n.StartsWith('@') || n.StartsWith('_')) ? Native.Msvc.MsvcDemangler.Undecorate(n, Native.Msvc.MsvcNameStyle.Full) : null;
            if (filter != null && !name.Contains(filter, StringComparison.OrdinalIgnoreCase) && demangled?.Contains(filter, StringComparison.OrdinalIgnoreCase) != true) continue;
            rows.Add($"{(ordinals ? $"#{e.Ordinal,-5} " : "")}{(e.ForwardedTo != null ? (ordinals ? "forwarder" : "re-export").PadRight(18) : NativeAddress.Va(pe, e.Rva).PadRight(18))} {name}{e.Version}" +
                     (demangled != null && demangled != name ? $"  = {demangled}" : "") + (e.ForwardedTo != null ? $"  -> {e.ForwardedTo}" : ""));
            items.Add(new ExportEntry((int)e.Ordinal, e.ForwardedTo != null ? null : NativeAddress.Va(pe, e.Rva), e.Name,
                demangled != null && demangled != name ? demangled : null, e.ForwardedTo, e.Version));
        }
        return StructuredOutput.With(pager.PageRows(rows, offset, limit, "export"),
            Paged(items, offset, limit, (page, o, total, more) => new ExportList(native.Id, page, o, total, more)));
    }, cancellationToken);

    [McpServerTool(Name = "resolve_address", Title = "Resolve native address", UseStructuredContent = true, OutputSchemaType = typeof(AddressInfo))]
    [Description("What a native address is: RVA, VA, file offset, section and access, nearest export or import, name and source; the Il2Cpp " +
                 "method or metadata slot, or NativeAOT MethodTable, object or method; an IAT slot's bound export, an export's importers. With the " +
                 "code index: function and offset, instruction start, mid-instruction or data item, comment, references by kind. In a PDB global, the field.")]
    public Task<string> ResolveAddress(
        [Description(ImageDescription)] string image,
        [Description(AddressDescription)] string? address = null,
        [Description("Instead of address: up to 100 addresses.")] string[]? addresses = null,
        CancellationToken cancellationToken = default) => OnImage(image, native =>
    {
        if ((addresses is { Length: > 0 }) == !string.IsNullOrWhiteSpace(address))
            throw new ToolError(ErrorCode.InvalidArgument, "Pass address or addresses (one of them).", "address=<one>, or addresses=[...] for several");
        if (addresses == null)
        {
            var (single, record) = Resolve(native, address!, cancellationToken);
            return StructuredOutput.With(single, record);
        }
        if (addresses.Length > 100) throw new ToolError(ErrorCode.InvalidArgument, $"{addresses.Length} addresses; at most 100 per call.", "split the addresses");
        var text = new StringBuilder();
        var records = new List<AddressInfo>();
        foreach (var a in addresses)
        {
            try
            {
                var (one, info) = Resolve(native, a, cancellationToken);
                text.Append(one);
                records.Add(info);
            }
            catch (ToolError e)
            {
                var line = $"{a.Trim()}: error {ToolError.CodeName(e.Code)}: {e.Message}";
                text.AppendLine(line);
                records.Add(new AddressInfo(native.Id, "", "", null, null, null, null, null, null, null, null, [line]));
            }
        }
        return StructuredOutput.With(text.ToString(), records[0] with { More = records.Skip(1).ToList() });
    }, cancellationToken);

    /// <summary>resolve_address for one address.</summary>
    private (string Text, AddressInfo Info) Resolve(LoadedNative native, string address, CancellationToken cancellationToken)
    {
        var pe = native.Image;
        var index = code?.Ready(native);
        var rva = NativeAddress.Parse(pe, address, index != null ? index.AddressesOfName : null);
        var sb = new StringBuilder($"{address.Trim()}: {NativeAddress.Describe(pe, rva)}\n");
        var named = index?.Sourced.NameAt(rva);
        if (named is { } n) sb.AppendLine($"  name {n.Name} ({n.Source.Id()})");
        foreach (var line in Il2CppNativeNames.Describe(native, index, rva)) sb.AppendLine("  " + line);
        if (NativeTypeCatalog.DescribeTypedData(native, rva) is { } typed) sb.AppendLine("  " + typed);
        foreach (var line in NativeAotNames.Describe(native, rva, cancellationToken)) sb.AppendLine("  " + line);
        var section = pe.SectionAt(rva);
        sb.AppendLine(section != null
            ? $"  section {section.Name} ({Access(section.Access)}), +0x{rva - section.Rva:X} into it"
            : pe is PeFile { Optional.SizeOfHeaders: var headers } && rva < headers ? "  in the PE headers" : "  in no section");
        var slot = pe.Imports.FirstOrDefault(i => i.SlotRva == rva);
        if (slot != null) sb.AppendLine($"  IAT slot of {slot.Module}!{slot.Name ?? "#" + slot.Ordinal}");
        var boundTo = slot != null && link != null ? NativeLinkService.Describe(link.BindImport(native, slot)) : null;
        if (boundTo != null) sb.AppendLine($"  bound to {boundTo}");
        if (link != null) foreach (var line in link.DescribeManaged(native, rva)) sb.AppendLine("  " + line);
        if (link != null && link.ImportersOf(native, rva, cancellationToken) is { Count: > 0 } importers)
            sb.AppendLine($"  imported by {string.Join(", ", importers.GroupBy(i => i.Importer.Id).Select(g => $"{g.Key} ({string.Join(", ", g.Select(i => NativeCodeIndex.ImportName(i.Import)).Distinct())})"))}; find_xrefs lists the call sites");
        var export = pe.Exports.Where(e => e.ForwardedTo == null && e.Rva <= rva).MaxBy(e => e.Rva);
        if (export != null) sb.AppendLine(export.Rva == rva ? $"  export {export.Name ?? "#" + export.Ordinal}" : $"  nearest export before it: {export.Name ?? "#" + export.Ordinal} + 0x{rva - export.Rva:X}");
        var function = FindRuntimeFunction(pe, rva);
        if (function != null) sb.AppendLine($"  inside the unwind range 0x{pe.ImageBase + function.BeginRva:X}-0x{pe.ImageBase + function.EndRva:X}");
        var facets = index != null ? CodeFacets(sb, index, rva, cancellationToken) : null;
        var text = sb.ToString();
        return (text, new AddressInfo(native.Id, $"0x{rva:X}", NativeAddress.Va(pe, rva),
            pe.TryRvaToFileOffset(rva, out var fileOffset) ? $"0x{fileOffset:X}" : null, section?.Name, section != null ? Access(section.Access) : null,
            named?.Name, named?.Source.Id(), slot != null ? $"{slot.Module}!{slot.Name ?? "#" + slot.Ordinal}" : null, boundTo,
            export == null ? null : export.Rva == rva ? export.Name ?? "#" + export.Ordinal : $"{export.Name ?? "#" + export.Ordinal}+0x{rva - export.Rva:X}",
            text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList())
        {
            Function = facets?.Function, Status = facets?.Status, ContainingInstruction = facets?.ContainingInstruction, DataItem = facets?.DataItem,
            Comment = facets?.Comment, ReferencesTo = facets?.References,
        });
    }

    private sealed record Facets(string? Function, string? Status, string? ContainingInstruction, string? DataItem, string? Comment, IReadOnlyDictionary<string, int>? References);

    /// <summary>resolve_address lines from the code index: function, instruction boundary or data item, comment, references by kind.</summary>
    private static Facets CodeFacets(StringBuilder sb, NativeCodeIndex index, uint rva, CancellationToken ct)
    {
        string Va(uint r) => NativeAddress.Va(index.Image, r);
        string? function = index.FunctionAt(rva) is { } f ? (rva == f.Start ? f.Name : $"{f.Name}+0x{rva - f.Start:X}") : null;
        if (function != null) sb.AppendLine($"  in function {function}");
        string? status = null, containing = null, item = null;
        if (index.Support == CodeSupport.Full)
        {
            var c = new AddressClassifier(index).Classify(rva, ct);
            status = c.StatusName;
            switch (c.Status)
            {
                case AddressStatus.Decoded:
                    sb.AppendLine("  an instruction start" + (c.Overlapping ? " (overlapping code: another decoding covers it)" : ""));
                    break;
                case AddressStatus.MidInstruction:
                    containing = Va(c.InstructionStart!.Value);
                    var text = index.CreateDisassembler().DecodeOne(c.InstructionStart.Value)?.Text;
                    sb.AppendLine($"  inside the instruction at {containing}{(text != null ? $" ({text})" : "")}: not an instruction boundary");
                    break;
                case AddressStatus.Data when c.Item is { Kind: not "section" } d:
                    item = $"{d.Kind}: {d.Text}";
                    sb.AppendLine($"  {d.Kind.Replace('_', ' ')} {Va(d.Start)}-{Va(d.End)}" + (d.Start != rva ? $" (+0x{rva - d.Start:X} into it)" : "") + $": {d.Text}");
                    break;
                case AddressStatus.NotInFunction:
                    sb.AppendLine("  executable, but no known function contains it");
                    break;
                case AddressStatus.Unmapped when c.Section != null:
                    sb.AppendLine("  " + c.Note);
                    break;
            }
        }
        if (index.Sourced.CommentAt(rva) is { } comment) sb.AppendLine($"  comment ({comment.Source.Id()}): {comment.Text}");
        var refs = index.RefsTo(rva).Concat(index.VirtualEdgesTo(rva)).GroupBy(x => x.Kind).OrderByDescending(g => g.Count())
            .ToDictionary(g => g.Key.ToString(), g => g.Count());
        if (refs.Count > 0) sb.AppendLine($"  referenced {Plural(refs.Values.Sum(), "time")}: {string.Join(", ", refs.Select(r => $"{r.Value} {r.Key}"))}; find_xrefs lists them");
        return new Facets(function, status, containing, item, index.Sourced.CommentAt(rva)?.Text, refs.Count > 0 ? refs : null);
    }

    private static RuntimeFunction? FindRuntimeFunction(INativeImage pe, uint rva)
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
    [Description("Find a byte pattern in a native image's mapped sections (hex with ?? wildcards, or text as ASCII and UTF-16): each hit's VA, " +
                 "section and file offset.")]
    public Task<string> SearchBytes(
        [Description(ImageDescription)] string image,
        [Description("Hex bytes with ?? wildcards ('48 8B 05 ?? ?? ?? ??'), or text when text=true.")] string? pattern = null,
        [Description("pattern is text (ASCII and UTF-16LE).")] bool text = false,
        [Description("Only this section (e.g. .text, .rdata).")] string? section = null,
        [Description("Max hits.")] int limit = 200,
        [Description("Index of the first hit.")] int offset = 0,
        [Description("Instead of pattern: up to 50 patterns.")] string[]? patterns = null,
        CancellationToken cancellationToken = default) => OnImage(image, native =>
    {
        if ((patterns is { Length: > 0 }) == !string.IsNullOrEmpty(pattern))
            throw new ToolError(ErrorCode.InvalidArgument, "Pass pattern or patterns (one of them).", "pattern='48 8B 05 ?? ?? ?? ??', or patterns=[...] for several");
        if (patterns == null) return SearchOne(native, pattern!, text, section, limit, offset, cancellationToken);
        if (patterns.Length > 50) throw new ToolError(ErrorCode.InvalidArgument, $"{patterns.Length} patterns; at most 50 per call.", "split the patterns");
        var sb = new StringBuilder();
        for (int i = 0; i < patterns.Length; i++)
        {
            sb.Append($"[{i + 1}/{patterns.Length}] {patterns[i]}: ");
            try { sb.AppendLine(SearchOne(native, patterns[i], text, section, limit, offset, cancellationToken)); }
            catch (ToolError e) when (e.Code is ErrorCode.InvalidArgument) { sb.AppendLine($"error {ToolError.CodeName(e.Code)}: {e.Message}"); }
        }
        return pager.Page(sb.ToString());
    }, cancellationToken);

    /// <summary>search_bytes for one pattern.</summary>
    private static string SearchOne(LoadedNative native, string pattern, bool text, string? section, int limit, int offset, CancellationToken cancellationToken)
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
                    // Candidates are found with a vectorized search for the first run of fixed bytes (after any leading wildcards).
                    int lead = Array.IndexOf(mask, true);
                    int run = (Array.IndexOf(mask, false, lead) is var w and >= 0 ? w : mask.Length) - lead;
                    var prefix = bytes.AsSpan(lead, run);
                    for (int i = 0; i < starts && i + bytes.Length <= span.Length; i++)
                    {
                        int k = span[(i + lead)..Math.Min(span.Length, starts + lead + prefix.Length - 1)].IndexOf(prefix);
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
        var more = offset + hits.Count < total ? $"\n[More: offset={offset + hits.Count}]" : "";
        return $"{total} hit{(total == 1 ? "" : "s")}{(offset > 0 || hits.Count < total ? $" (showing {(hits.Count == 0 ? 0 : offset + 1)}-{offset + hits.Count})" : "")}\n" +
               string.Join("\n", hits) + more;
    }

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
        if (mask.Length > 0 && !mask.Contains(true)) throw new ToolError(ErrorCode.InvalidArgument, "The pattern has no fixed byte, only wildcards.");
        return (bytes, mask, "hex");
    }

    private static bool Matches(ReadOnlySpan<byte> data, int at, byte[] bytes, bool[] mask)
    {
        for (int j = 0; j < bytes.Length; j++)
            if (mask[j] && data[at + j] != bytes[j]) return false;
        return true;
    }

    [McpServerTool(Name = "read_bytes", Title = "Read native bytes or values")]
    [Description("Hex dump (with ASCII) of a native image's bytes at an address, as the loader maps them (.bss as ??). type= reads length values " +
                 "instead: u8-u64, i8-i64 (be suffix: u32be), f32, f64, ptr (target named), C names (int, DWORD, char *), cstr or wstr. Structs: " +
                 "get_native_type read=true.")]
    public Task<string> ReadBytes(
        [Description(ImageDescription)] string image,
        [Description(AddressDescription)] string address,
        [Description("Bytes to dump (default 256, max 65536); with type, values to read (default 1, max 4096).")] int? length = null,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        [Description("Value type to read instead of dumping bytes.")] string? type = null,
        CancellationToken cancellationToken = default) => OnImage(image, native =>
    {
        var pe = native.Image;
        var rva = NativeAddress.Parse(pe, address);
        if (!string.IsNullOrWhiteSpace(type)) return pager.Page(ReadValues(native, rva, type.Trim(), length ?? 1), offset, maxChars);
        var buffer = new byte[Math.Clamp(length ?? 256, 1, 65_536)];
        int read = pe.Read(rva, buffer);
        var unset = new bool[read];
        for (int i = 0; i < read; i++) unset[i] = Uninitialized(pe, rva + (uint)i);
        var sb = new StringBuilder(NativeAddress.Describe(pe, rva) + ", " + (read < buffer.Length
            ? $"{read:N0} of {buffer.Length:N0} bytes requested: incomplete, nothing is mapped at 0x{pe.ImageBase + rva + (uint)read:X}"
            : Plural(read, "byte")) + (length > buffer.Length ? $" (length {length:N0} capped at {buffer.Length:N0})" : "") + "\n");
        for (int row = 0; row < read; row += 16)
        {
            int n = Math.Min(16, read - row);
            sb.Append($"{pe.ImageBase + rva + (uint)row:X}  ");
            for (int i = 0; i < 16; i++) sb.Append(i >= n ? "   " : unset[row + i] ? "?? " : $"{buffer[row + i]:X2} ");
            sb.Append(' ');
            for (int i = 0; i < n; i++) sb.Append(unset[row + i] ? '?' : buffer[row + i] is >= 0x20 and < 0x7F ? (char)buffer[row + i] : '.');
            sb.AppendLine();
        }
        var gaps = new List<string>();
        for (int i = 0; i < read; i++)
        {
            if (!unset[i]) continue;
            int start = i;
            while (i + 1 < read && unset[i + 1]) i++;
            uint at = rva + (uint)start;
            gaps.Add($"0x{pe.ImageBase + at:X}-0x{pe.ImageBase + rva + (uint)i + 1:X} ({Plural(i - start + 1, "byte")}{(pe.SectionAt(at) is { } s ? $", {s.Name}" : "")})");
        }
        if (gaps.Count > 0)
            sb.AppendLine($"?? uninitialized (no file data; zero at load, run-time values in a process): {string.Join(", ", gaps)}");
        return pager.Page(sb.ToString(), offset, maxChars);
    }, cancellationToken);

    /// <summary>read_bytes type=: <paramref name="count"/> values of a scalar type (le / be suffix for the byte order), or strings one after another.</summary>
    private string ReadValues(LoadedNative native, uint rva, string type, int count)
    {
        var pe = native.Image;
        var index = code?.Ready(native);
        Func<uint, string?> nameAt = r => index?.NameAt(r);
        var head = NativeAddress.Describe(pe, rva);
        count = Math.Clamp(count, 1, 4096);
        // bytes without file data read as 0 here and hold what the program stores at run time
        string Fill(uint at, int size) => Uninitialized(pe, at) || Uninitialized(pe, at + (uint)size - 1) ? "  [?? uninitialized]" : "";
        var (name, bigEndian) = ByteOrder(type);
        if (StringWidth(name, pe) is { } width)
        {
            var sb = new StringBuilder($"{head}, {Plural(count, width == 2 ? "UTF-16 string" : "string")}\n");
            uint at = rva;
            for (int i = 0; i < count; i++)
            {
                if (NativeValues.ReadString(pe, at, width == 2) is not { } text) { sb.AppendLine($"{pe.ImageBase + at:X}  (not mapped)"); break; }
                if (Uninitialized(pe, at)) { sb.AppendLine($"{pe.ImageBase + at:X}  ?? uninitialized"); break; }
                int units = Terminator(pe, at, width);
                sb.AppendLine($"{pe.ImageBase + at:X}  {text}{Fill(at, Math.Max(width, units * width))}");
                if (units < 0) break;
                at += (uint)((units + 1) * width);
            }
            return sb.ToString();
        }
        var scalar = NativeValues.Classify(name, pe.Is64Bit ? 8 : 4)
            ?? throw new ToolError(ErrorCode.InvalidArgument, $"'{type}' is not a scalar type read_bytes knows.",
                "use u8-u64 or i8-i64 (le or be suffix: u32be), f32, f64, ptr, cstr, wstr or a C scalar name; get_native_type read=true reads structs and enums");
        var values = new StringBuilder();
        var bytes = new byte[scalar.Size];
        for (int i = 0; i < count; i++)
        {
            uint at = rva + (uint)(i * scalar.Size);
            if (pe.Read(at, bytes) < bytes.Length) { values.AppendLine($"{pe.ImageBase + at:X}  (not mapped)"); break; }
            if (bigEndian) Array.Reverse(bytes);
            if (Uninitialized(pe, at) && Uninitialized(pe, at + (uint)scalar.Size - 1)) { values.AppendLine($"{pe.ImageBase + at:X}  ?? uninitialized"); continue; }
            values.AppendLine($"{pe.ImageBase + at:X}  {NativeValues.Format(pe, bytes, scalar, nameAt)}{Fill(at, scalar.Size)}");
        }
        return $"{head}, {count} x {name}{(bigEndian ? " big-endian" : "")} ({scalar.Size} byte(s) each)\n" + values;
    }

    /// <summary>Mapped but with no file data behind it (virtual size past raw size, .bss): zero in the file image, unknown at run time.</summary>
    private static bool Uninitialized(INativeImage pe, uint rva) => !pe.TryRvaToFileOffset(rva, out _);

    /// <summary>The type without a byte-order suffix (u32be, i16_le, f64:be) and whether it is big-endian; other types as given.</summary>
    internal static (string Type, bool BigEndian) ByteOrder(string type)
    {
        var t = type.Trim();
        if (t.Length > 2 && (t.EndsWith("be", StringComparison.OrdinalIgnoreCase) || t.EndsWith("le", StringComparison.OrdinalIgnoreCase)))
        {
            var core = t[..^2].TrimEnd('_', ':', ' ', '.');
            bool numeric = core.Length > 1 && core[0] is 'u' or 'i' or 'f' && core[1..].All(char.IsAsciiDigit);
            if (numeric || core == "ptr")
                return (core, t.EndsWith("be", StringComparison.OrdinalIgnoreCase));
        }
        return (t, false);
    }

    /// <summary>1 for a C string type (string, cstr, char[]), 2 for UTF-16 (string16, wstr, wchar_t[]); null for other types.</summary>
    private static int? StringWidth(string type, INativeImage pe) => type switch
    {
        "string" or "cstr" or "str" => 1,
        "string16" or "wstr" or "wstring" => 2,
        _ => NativeValues.Classify(type, pe.Is64Bit ? 8 : 4) switch { { Kind: "string" } => 1, { Kind: "string16" } => 2, _ => null },
    };

    /// <summary>Characters before the terminator of the string at <paramref name="rva"/> (at most 1 MB is scanned); -1 when none is found.</summary>
    private static int Terminator(INativeImage pe, uint rva, int width)
    {
        var chunk = new byte[4096];
        for (int done = 0; done < 1 << 20; done += chunk.Length)
        {
            int read = pe.Read(rva + (uint)done, chunk);
            for (int i = 0; i + width <= read; i += width)
                if (chunk[i] == 0 && (width == 1 || chunk[i + 1] == 0)) return (done + i) / width;
            if (read < chunk.Length) return -1;
        }
        return -1;
    }

    private static readonly Lazy<ApiSetSchema?> ApiSets = new(() => ApiSetSchema.FromSystem(PeFile.Open));
}
