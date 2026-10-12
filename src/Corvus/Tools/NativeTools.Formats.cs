using System.Text;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Elf;
using Corvus.Native.MachO;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>get_pe_info for ELF and Mach-O images: the same overview, from each format's own structures.</summary>
public sealed partial class NativeTools
{
    private static string FormatInfo(LoadedNative native) => native.Image switch
    {
        ElfFile elf => ElfInfo(native, elf),
        MachOFile macho => MachOInfo(native, macho),
        _ => throw LoadedNative.PeOnly(native.Image, "get_pe_info"),
    };

    private static void Head(StringBuilder sb, LoadedNative native, INativeImage image)
    {
        sb.AppendLine($"{native.Id}: {image.KindText()}");
        sb.AppendLine($"  {native.FilePath}");
        sb.AppendLine($"  {image.FileSize:N0} bytes, sha256 {image.Sha256}");
        sb.AppendLine($"  image base 0x{image.ImageBase:X}, size 0x{image.SizeOfImage:X}, entry point " +
                      (image.EntryPointRva == 0 ? "none" : NativeAddress.Describe(image, image.EntryPointRva)));
    }

    private static void Tail(StringBuilder sb, INativeImage image, ReadOnlySpan<byte> file)
    {
        var (on, off) = FormatMitigations(image);
        sb.AppendLine($"Mitigations: on: {(on.Count > 0 ? string.Join(", ", on) : "none")}; off: {(off.Count > 0 ? string.Join(", ", off) : "none")}");
        sb.AppendLine($"Sections ({image.Sections.Count}):");
        foreach (var s in image.Sections)
            sb.AppendLine($"  {s.Name,-20} rva 0x{s.Rva:X8} size 0x{s.VirtualSize:X8} file 0x{s.RawOffset:X8}+0x{s.RawSize:X} {Access(s.Access)} " +
                          $"entropy {FileEntropy(file, s):0.00}" + (SectionFlags(image, s) is { Count: > 0 } f ? $"  [{string.Join(", ", f)}]" : ""));
        PackerLines(sb, image, file);
        if (image.Dependencies.Count > 0)
            sb.AppendLine($"Dependencies ({image.Dependencies.Count}): {string.Join(", ", image.Dependencies.Take(64))}" + (image.Dependencies.Count > 64 ? ", …" : ""));
        sb.AppendLine($"Imports: {Plural(image.Imports.Count, "symbol")} from {Plural(image.Imports.Select(i => i.Module).Distinct().Count(), "module")}" +
                      (image.Imports.Any(i => i.IsDelayLoad) ? $", {image.Imports.Count(i => i.IsDelayLoad)} bound lazily" : "") + " (list_imports)");
        sb.AppendLine($"Exports: {Plural(image.Exports.Count, "entry")}" +
                      (image.Exports.Any(e => e.ForwardedTo != null) ? $" ({Plural(image.Exports.Count(e => e.ForwardedTo != null), "re-export")})" : "") + " (list_exports)");
        if (image.Symbols.Count > 0) sb.AppendLine($"Symbols: {Plural(image.Symbols.Count, "defined symbol")} ({image.Symbols.Count(s => s.Kind == ImageSymbolKind.Function)} functions)");
        if (image.DeclaredFunctions.Count > 0)
            sb.AppendLine($"Declared function starts: {image.DeclaredFunctions.Count} (" +
                          string.Join(", ", image.DeclaredFunctions.GroupBy(d => d.Source).Select(g => $"{SourceName(g.Key)} {g.Count()}")) + ")");
        GoLine(sb, image);
        sb.AppendLine($"Relocated pointers: {image.RelocationRvas.Count}");
        if (image.BuildId is { } id) sb.AppendLine($"Build id: {id}");
        foreach (var e in image.EncryptedRanges)
            sb.AppendLine($"Encrypted: 0x{e.Size:X} bytes at rva 0x{e.Rva:X} (cryptid {e.CryptId}, FairPlay): load a decrypted copy to analyze that code");
        if (image.Issues.Count > 0)
        {
            sb.AppendLine($"Parse issues ({image.Issues.Count}):");
            foreach (var issue in image.Issues.Take(50))
                sb.AppendLine($"  {issue.Area}: {issue.Message}" + (issue.FileOffset is { } fo ? $" (file 0x{fo:X})" : ""));
        }
    }

    /// <summary>Packers and protectors the image shows signs of (detection only).</summary>
    private static void PackerLines(StringBuilder sb, INativeImage image, ReadOnlySpan<byte> file)
    {
        foreach (var p in PackerDetection.Detect(image, file))
            sb.AppendLine(p.Kind == "suspicious" ? $"Possibly packed: {p.Evidence}" : $"Packed: {p.Name} ({p.Kind}): {p.Evidence}");
    }

    private static void GoLine(StringBuilder sb, INativeImage image)
    {
        if (Native.Go.GoFunctionTable.Of(image) is { } go)
            sb.AppendLine($"Go function table: {Plural(go.Functions.Count, "function")} with names ({go.VersionText} layout) at rva 0x{go.Rva:X}");
        if (Native.Go.GoBuildInfo.Of(image) is not { } build) return;
        sb.AppendLine($"Go build: {build.GoVersion}" + (build.Path != null ? $", package {build.Path}" : "") + (build.Main != null ? $", module {build.Main}" : "") +
                      (build.Main?.Sum != null ? $" {build.Main.Sum}" : ""));
        if (build.Settings.Count > 0) sb.AppendLine($"  settings: {string.Join(", ", build.Settings.Select(s => $"{s.Key}={s.Value}"))}");
        if (build.Dependencies.Count > 0) sb.AppendLine($"  dependencies ({build.Dependencies.Count}):");
        foreach (var d in build.Dependencies.Take(MaxGoDependencies))
            sb.AppendLine($"    {d}" + ((d.Replace?.Sum ?? d.Sum) is { } sum ? $" {sum}" : ""));
        if (build.Dependencies.Count > MaxGoDependencies) sb.AppendLine($"    … {build.Dependencies.Count - MaxGoDependencies} more");
    }

    private const int MaxGoDependencies = 200;

    private static string SourceName(DeclaredSource s) => s switch
    {
        DeclaredSource.Unwind => "unwind",
        DeclaredSource.FunctionStarts => "function starts",
        DeclaredSource.Symbol => "symbols",
        _ => "initializers",
    };

    private static string ElfInfo(LoadedNative native, ElfFile elf)
    {
        var sb = new StringBuilder();
        Head(sb, native, elf);
        sb.AppendLine($"  {(elf.BigEndian ? "big" : "little")} endian, OS/ABI {elf.OsAbi}, e_type {elf.TypeName}, e_flags 0x{elf.Flags:X}" +
                      (elf.IsMappedDump ? "; a memory image (segments at their addresses)" : ""));
        if (elf.SoName != null) sb.AppendLine($"  soname {elf.SoName}");
        if (elf.Interpreter != null) sb.AppendLine($"  interpreter {elf.Interpreter}");
        if (elf.RunPath != null) sb.AppendLine($"  runpath {elf.RunPath}");
        if (elf.AndroidIdent is { } android)
            sb.AppendLine($"  Android API level {android.ApiLevel}" + (android.NdkVersion is { Length: > 0 } ndk ? $", NDK {ndk}" : "") + (android.NdkBuild is { Length: > 0 } b ? $" ({b})" : ""));
        sb.AppendLine($"  binding: {(elf.BindNow ? "immediate (BIND_NOW)" : "lazy")}; {Plural(elf.PltEntries.Count, "PLT stub")}");
        sb.AppendLine($"Program headers ({elf.Segments.Count}):");
        foreach (var s in elf.Segments.Take(64))
            sb.AppendLine($"  {s.TypeName,-14} file 0x{s.Offset:X8}+0x{s.FileSize:X} vaddr 0x{s.VirtualAddress:X} memsz 0x{s.MemorySize:X} " +
                          $"{(s.Readable ? 'r' : '-')}{(s.Writable ? 'w' : '-')}{(s.Executable ? 'x' : '-')} align 0x{s.Align:X}");
        if (elf.SectionHeaders.Count == 0) sb.AppendLine("No section headers: sections below are synthesized from the load segments.");
        if (elf.Relocations.Count > 0)
            sb.AppendLine($"Dynamic relocations: {elf.Relocations.Count} (" +
                          string.Join(", ", elf.Relocations.GroupBy(r => r.Kind).OrderByDescending(g => g.Count()).Select(g => $"{g.Key} {g.Count()}")) + ")");
        Tail(sb, elf, elf.FileBytes.Span);
        return sb.ToString();
    }

    private static string MachOInfo(LoadedNative native, MachOFile m)
    {
        var sb = new StringBuilder();
        Head(sb, native, m);
        sb.AppendLine($"  {(m.Is64Bit ? "64" : "32")}-bit {(m.BigEndian ? "big" : "little")} endian, flags 0x{m.HeaderFlags:X}, {Plural(m.LoadCommands.Count, "load command")}");
        if (m.Slice != null) sb.AppendLine($"  slice {m.Slice.Name} at file 0x{m.Slice.Offset:X}+0x{m.Slice.Size:X}; file offsets below are relative to the slice; load_assembly slice= selects another");
        if (m.InstallName != null) sb.AppendLine($"  install name {m.InstallName}");
        if (m.BuildVersion is { } bv) sb.AppendLine($"  platform {bv.PlatformName}, minimum OS {MachONames.Version(bv.MinOs)}, SDK {MachONames.Version(bv.Sdk)}");
        foreach (var r in m.Rpaths.Take(16)) sb.AppendLine($"  rpath {r}");
        sb.AppendLine($"Segments ({m.Segments.Count}):");
        foreach (var s in m.Segments)
            sb.AppendLine($"  {s.SegmentName,-16} vm 0x{s.VmAddress:X}+0x{s.VmSize:X} file 0x{s.FileOffset:X}+0x{s.FileSize:X} " +
                          $"{(s.Readable ? 'r' : '-')}{(s.Writable ? 'w' : '-')}{(s.Executable ? 'x' : '-')}");
        if (m.Dylibs.Count > 0)
            sb.AppendLine($"Libraries ({m.Dylibs.Count}): " + string.Join(", ", m.Dylibs.Take(64).Select(d => d.Path + (d.Kind == MachODylibKind.Load ? "" : $" ({d.Kind.ToString().ToLowerInvariant()})"))));
        var fx = m.Fixups;
        sb.AppendLine($"Fixups: {fx.Source}" + (fx.PointerFormat is { } pf ? $" ({MachONames.PointerFormat(pf)})" : "") + $", {fx.RebaseCount} rebases, {fx.BindCount} binds" +
                      (fx.WeakBinds.Count > 0 ? $", {fx.WeakBinds.Count} weak binds" : ""));
        if (m.DataInCode.Count > 0) sb.AppendLine($"Data in code: {Plural(m.DataInCode.Count, "range")}");
        if (m.CodeSignature is { } sig)
        {
            var cd = sig.Primary;
            sb.AppendLine($"Code signature: {(sig.IsAdHoc ? "ad-hoc" : sig.SignerSubject ?? "signed")}" + (cd != null ? $", identifier {cd.Identifier}" + (cd.TeamId != null ? $", team {cd.TeamId}" : "") +
                          $", {cd.HashName}, cdhash {cd.CdHashHex}" : "") + (sig.Entitlements != null || sig.DerEntitlements != null ? ", has entitlements" : "") +
                          " (not verified against Apple's roots)");
        }
        else sb.AppendLine("Code signature: none");
        Tail(sb, m, m.FileBytes.Span);
        return sb.ToString();
    }

    /// <summary>Hardening the image's own structures show; imports count for the stack protector.</summary>
    private static (List<string> On, List<string> Off) FormatMitigations(INativeImage image)
    {
        var on = new List<string>();
        var off = new List<string>();
        void M(string name, bool value) => (value ? on : off).Add(name);
        bool Imports(params string[] names) => image.Imports.Any(i => i.Name != null && names.Contains(i.Name.TrimStart('_')));
        switch (image)
        {
            case ElfFile elf:
                M("PIE", elf.Type == 3);
                M("NX stack", elf.Segments.Any(s => s.Type == 0x6474E551 && !s.Executable));
                M("RELRO", elf.Segments.Any(s => s.Type == 0x6474E552));
                M("BIND_NOW", elf.BindNow);
                M("stack protector", Imports("stack_chk_fail"));
                M("FORTIFY_SOURCE", image.Imports.Any(i => i.Name is { } n && n.StartsWith("__", StringComparison.Ordinal) && n.EndsWith("_chk", StringComparison.Ordinal) && n != "__stack_chk_fail"));
                break;
            case MachOFile m:
                M("PIE", (m.HeaderFlags & 0x200000) != 0 || m.FileType != 2);
                M("no heap execution", (m.HeaderFlags & 0x1000000) != 0);
                M("stack protector", Imports("stack_chk_fail"));
                M("code signature", m.CodeSignature != null);
                M("hardened runtime", m.CodeSignature?.Primary is { } cd && (cd.Flags & 0x10000) != 0);
                break;
        }
        return (on, off);
    }

    private static List<string> SectionFlags(INativeImage image, NativeSection s)
    {
        var result = new List<string>();
        switch (image)
        {
            case ElfFile elf when elf.Section(s.Name) is { } h:
                result.Add(h.TypeName);
                if (h.IsAllocated) result.Add("SHF_ALLOC");
                if (h.IsWritable) result.Add("SHF_WRITE");
                if (h.IsExecutable) result.Add("SHF_EXECINSTR");
                break;
            case MachOFile m when m.AllSections.FirstOrDefault(x => x.FullName == s.Name) is { } ms:
                if (ms.HasInstructions) result.Add("instructions");
                if (ms.IsZeroFill) result.Add("zero fill");
                break;
        }
        return result;
    }

    /// <summary>Shannon entropy of the section's bytes in the file (the slice for a universal Mach-O).</summary>
    private static double FileEntropy(ReadOnlySpan<byte> file, NativeSection s)
    {
        if (s.RawSize == 0 || s.RawOffset >= file.Length) return 0;
        return Blob.Entropy(file.Slice((int)s.RawOffset, (int)Math.Min(s.RawSize, file.Length - s.RawOffset)));
    }

    /// <summary>get_pe_info's fields for an ELF or Mach-O image.</summary>
    private static PeSummary FormatSummary(LoadedNative native)
    {
        var image = native.Image;
        var (on, off) = FormatMitigations(image);
        var file = image switch { ElfFile e => e.FileBytes, MachOFile m => m.FileBytes, _ => ReadOnlyMemory<byte>.Empty };
        string format = image is ElfFile elf ? $"ELF{(elf.Is64Bit ? "64" : "32")}" : $"Mach-O {(image.Is64Bit ? "64" : "32")}-bit";
        string kind = image switch { ElfFile e => e.KindName, MachOFile m => m.FileTypeName, _ => "" };
        var sig = (image as MachOFile)?.CodeSignature;
        return new PeSummary(native.Id, native.FilePath, image.MachineName, image.IsDll ? "dll" : "exe", format, kind, image.FileSize, image.Sha256,
            $"0x{image.ImageBase:X}", image.EntryPointRva == 0 ? null : NativeAddress.Va(image, image.EntryPointRva), "none", false, on, off,
            image.Sections.Select(s => new SectionEntry(s.Name, $"0x{s.Rva:X}", $"0x{s.VirtualSize:X}", $"0x{s.RawOffset:X}", $"0x{s.RawSize:X}", Access(s.Access),
                Math.Round(FileEntropy(file.Span, s), 2), SectionFlags(image, s))).ToList(),
            image.Imports.Select(i => i.Module).Distinct().Count(), image.Imports.Count, 0, image.Exports.Count, 0,
            null, null, null, sig == null ? null : sig.IsAdHoc ? "ad-hoc" : sig.SignerSubject ?? sig.Identifier, null, null, image.Issues.Count);
    }

    /// <summary>
    /// list_imports for ELF and Mach-O: one row per bound slot, "module!name" with the version library (ELF, "*" when the
    /// symbol is unversioned: any loaded library may provide it) or the two-level namespace dylib (Mach-O).
    /// </summary>
    private string FormatImports(LoadedNative native, string? module, string? filter, bool bind, int offset, int limit)
    {
        var image = native.Image;
        bool macho = image is MachOFile;
        var rows = new List<string>();
        var items = new List<ImportEntry>();
        foreach (var i in image.Imports.OrderBy(i => i.Module, StringComparer.Ordinal).ThenBy(i => i.SlotRva))
        {
            if (module != null && !ModuleMatches(i.Module, module.Trim())) continue;
            var name = i.Name ?? $"#{i.Ordinal}";
            var demangled = Demangled(name, image.Format);
            if (filter != null && !name.Contains(filter, StringComparison.OrdinalIgnoreCase) && demangled?.Contains(filter, StringComparison.OrdinalIgnoreCase) != true) continue;
            rows.Add($"{NativeAddress.Va(image, i.SlotRva)}  {i.Module}!{name}{(i.IsDelayLoad ? "  [lazy]" : "")}" + (demangled != null ? $"  = {demangled}" : ""));
            items.Add(new ImportEntry(NativeAddress.Va(image, i.SlotRva), i.Module, name, null, i.IsDelayLoad, false, null, null));
        }
        var head = bind ? $"Bindings: resolved for PE images only ({image.Format} image)\n" : "";
        return StructuredOutput.With(head + pager.PageRows(rows, offset, limit, "import"),
            Paged(items, offset, limit, (page, o, total, more) => new ImportList(native.Id, page, o, total, more, head.Length > 0 ? head.Trim() : null)));
    }

    /// <summary>A library named in full, by file name, or by file name without extensions ("libc" matches "libc.so.6").</summary>
    private static bool ModuleMatches(string library, string query)
    {
        if (library.Equals(query, StringComparison.OrdinalIgnoreCase)) return true;
        var file = Path.GetFileName(library);
        if (file.Equals(query, StringComparison.OrdinalIgnoreCase)) return true;
        int dot = file.IndexOf('.');
        return dot > 0 && file[..dot].Equals(query, StringComparison.OrdinalIgnoreCase);
    }
}
