using System.Diagnostics;
using System.Globalization;
using System.Reflection.PortableExecutable;
using System.Text;
using Corvus.Native;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>
/// Independent PE readers the native parser is checked against. Each Compare method returns the disagreements it
/// finds ("area: detail"); an oracle that cannot read a file returns null.
/// </summary>
internal static class PeOracles
{
    private const int MaxDiffsPerArea = 5;

    private static void Diff(List<string> diffs, string area, string detail)
    {
        if (diffs.Count(d => d.StartsWith(area + ":", StringComparison.Ordinal)) < MaxDiffsPerArea) diffs.Add($"{area}: {detail}");
    }

    private static void Check<T>(List<string> diffs, string area, string field, T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual)) Diff(diffs, area, $"{field}: oracle {expected}, parser {actual}");
    }

    /// <summary>Headers, data directories and section table against System.Reflection.PortableExecutable.</summary>
    public static List<string>? CompareWithPeReader(PeFile pe, byte[] bytes)
    {
        PEHeaders h;
        try
        {
            using var reader = new PEReader(new MemoryStream(bytes));
            h = reader.PEHeaders;
        }
        catch (BadImageFormatException) { return null; }
        var diffs = new List<string>();
        Check(diffs, "coff", "machine", (ushort)h.CoffHeader.Machine, pe.Coff.Machine);
        Check(diffs, "coff", "sections", (int)h.CoffHeader.NumberOfSections, (int)pe.Coff.NumberOfSections);
        Check(diffs, "coff", "characteristics", (ushort)h.CoffHeader.Characteristics, pe.Coff.Characteristics);
        Check(diffs, "coff", "timestamp", (uint)h.CoffHeader.TimeDateStamp, pe.Coff.TimeDateStamp);
        if (h.PEHeader is { } p)
        {
            var o = pe.Optional;
            Check(diffs, "optional", "magic", (ushort)p.Magic, o.Magic);
            Check(diffs, "optional", "entry", (uint)p.AddressOfEntryPoint, o.AddressOfEntryPoint);
            Check(diffs, "optional", "image base", p.ImageBase, o.ImageBase);
            Check(diffs, "optional", "size of image", (uint)p.SizeOfImage, o.SizeOfImage);
            Check(diffs, "optional", "size of headers", (uint)p.SizeOfHeaders, o.SizeOfHeaders);
            Check(diffs, "optional", "checksum", p.CheckSum, o.CheckSum);
            Check(diffs, "optional", "subsystem", (ushort)p.Subsystem, o.Subsystem);
            Check(diffs, "optional", "dll characteristics", (ushort)p.DllCharacteristics, o.DllCharacteristics);
            Check(diffs, "optional", "file alignment", (uint)p.FileAlignment, o.FileAlignment);
            Check(diffs, "optional", "section alignment", (uint)p.SectionAlignment, o.SectionAlignment);
            Check(diffs, "optional", "stack reserve", p.SizeOfStackReserve, o.SizeOfStackReserve);
            Check(diffs, "optional", "heap commit", p.SizeOfHeapCommit, o.SizeOfHeapCommit);
            var dirs = new[]
            {
                p.ExportTableDirectory, p.ImportTableDirectory, p.ResourceTableDirectory, p.ExceptionTableDirectory, p.CertificateTableDirectory,
                p.BaseRelocationTableDirectory, p.DebugTableDirectory, p.CopyrightTableDirectory, p.GlobalPointerTableDirectory,
                p.ThreadLocalStorageTableDirectory, p.LoadConfigTableDirectory, p.BoundImportTableDirectory, p.ImportAddressTableDirectory,
                p.DelayImportTableDirectory, p.CorHeaderTableDirectory,
            };
            for (int i = 0; i < dirs.Length && i < p.NumberOfRvaAndSizes; i++)
            {
                var d = pe.Directory(i);
                if ((uint)dirs[i].RelativeVirtualAddress != d.Rva || (uint)dirs[i].Size != d.Size)
                    Diff(diffs, "directories", $"{PeDirectory.Name(i)}: oracle 0x{dirs[i].RelativeVirtualAddress:X}/0x{dirs[i].Size:X}, parser 0x{d.Rva:X}/0x{d.Size:X}");
            }
        }
        Check(diffs, "sections", "count", h.SectionHeaders.Length, pe.Sections.Count);
        for (int i = 0; i < Math.Min(h.SectionHeaders.Length, pe.Sections.Count); i++)
        {
            var e = h.SectionHeaders[i];
            var s = pe.Sections[i];
            if (!e.Name.StartsWith('/')) Check(diffs, "sections", $"[{i}] name", e.Name, s.Name);
            Check(diffs, "sections", $"[{i}] rva", (uint)e.VirtualAddress, s.Rva);
            Check(diffs, "sections", $"[{i}] virtual size", (uint)e.VirtualSize, s.VirtualSize);
            Check(diffs, "sections", $"[{i}] raw offset", (uint)e.PointerToRawData, s.RawOffset);
            Check(diffs, "sections", $"[{i}] raw size", (uint)e.SizeOfRawData, s.RawSize);
            Check(diffs, "sections", $"[{i}] characteristics", (uint)e.SectionCharacteristics, s.Characteristics);
        }
        return diffs;
    }

    /// <summary>
    /// The PE checksum against ImageHlp's CheckSumMappedFile, and the fixed version info against the version API
    /// (FileVersionInfo). Windows only.
    /// </summary>
    public static List<string> CompareWithWindows(PeFile pe, byte[] bytes, string path)
    {
        var diffs = new List<string>();
        if (!OperatingSystem.IsWindows()) return diffs;
        var handle = System.Runtime.InteropServices.GCHandle.Alloc(bytes, System.Runtime.InteropServices.GCHandleType.Pinned);
        try
        {
            if (CheckSumMappedFile(handle.AddrOfPinnedObject(), (uint)bytes.Length, out uint stored, out uint computed) != IntPtr.Zero)
            {
                Check(diffs, "checksum", "stored", stored, pe.Checksum.Stored);
                Check(diffs, "checksum", "computed", computed, pe.Checksum.Computed);
            }
        }
        finally { handle.Free(); }

        var info = FileVersionInfo.GetVersionInfo(path);
        var fixedInfo = pe.VersionInfo?.Fixed;
        string expected = $"{info.FileMajorPart}.{info.FileMinorPart}.{info.FileBuildPart}.{info.FilePrivatePart} / {info.ProductMajorPart}.{info.ProductMinorPart}.{info.ProductBuildPart}.{info.ProductPrivatePart}";
        string actual = fixedInfo == null ? "0.0.0.0 / 0.0.0.0" : $"{fixedInfo.FileVersionText} / {fixedInfo.ProductVersionText}";
        Check(diffs, "version", "fixed file / product version", expected, actual);
        return diffs;
    }

    [System.Runtime.InteropServices.DllImport("imagehlp.dll")]
    private static extern IntPtr CheckSumMappedFile(IntPtr baseAddress, uint fileLength, out uint headerSum, out uint checkSum);

    /// <summary>Imports, exports, relocations, TLS, .pdata, CodeView and the resource tree against AsmResolver.PE.</summary>
    public static List<string>? CompareWithAsmResolver(PeFile pe, byte[] bytes)
    {
        AsmResolver.PE.PEImage image;
        try { image = AsmResolver.PE.PEImage.FromBytes(bytes); }
        catch (Exception) { return null; }
        var diffs = new List<string>();
        Area(diffs, "imports", () => CompareImports(pe, image, diffs));
        Area(diffs, "exports", () => CompareExports(pe, image, diffs));
        Area(diffs, "relocations", () => CompareRelocations(pe, image, diffs));
        Area(diffs, "tls", () => CompareTls(pe, image, diffs));
        Area(diffs, "pdata", () => CompareRuntimeFunctions(pe, image, diffs));
        Area(diffs, "debug", () => CompareDebug(pe, image, diffs));
        Area(diffs, "resources", () => CompareResources(pe, image, diffs));
        return diffs;
    }

    /// <summary>Areas AsmResolver itself fails to read are skipped (counted by the caller as oracle failures).</summary>
    private static void Area(List<string> diffs, string area, Action compare)
    {
        try { compare(); }
        catch (Exception ex) when (ex is not Xunit.Sdk.XunitException)
        {
            diffs.Add($"oracle-failed {area}: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static void CompareImports(PeFile pe, AsmResolver.PE.PEImage image, List<string> diffs)
    {
        var expected = image.Imports.ToList();
        var actual = pe.ImportModules;
        Check(diffs, "imports", "module count", expected.Count, actual.Count);
        for (int m = 0; m < Math.Min(expected.Count, actual.Count); m++)
        {
            var e = expected[m];
            var a = actual[m];
            Check(diffs, "imports", $"[{m}] name", e.Name, a.Name);
            var es = e.Symbols.ToList();
            Check(diffs, "imports", $"{a.Name} count", es.Count, a.Functions.Count);
            for (int i = 0; i < Math.Min(es.Count, a.Functions.Count); i++)
            {
                var x = es[i];
                var y = a.Functions[i];
                string ex = x.IsImportByName ? $"{x.Name} hint {x.Hint}" : $"#{x.Ordinal}";
                string ac = y.Name != null ? $"{y.Name} hint {y.Hint}" : $"#{y.Ordinal}";
                Check(diffs, "imports", $"{a.Name}[{i}]", ex, ac);
                if (x.AddressTableEntry is { } slot) Check(diffs, "imports", $"{a.Name}[{i}] slot", slot.Rva, y.SlotRva);
            }
        }
    }

    private static void CompareExports(PeFile pe, AsmResolver.PE.PEImage image, List<string> diffs)
    {
        var expected = new HashSet<string>(StringComparer.Ordinal);
        if (image.Exports is { } dir)
        {
            Check(diffs, "exports", "dll name", dir.Name, pe.ExportDirectory?.DllName);
            foreach (var e in dir.Entries)
            {
                if (e.Address.Rva == 0 && e.Name == null) continue;
                expected.Add(e.IsForwarder ? $"{e.Ordinal} {e.Name} -> {e.ForwarderName}" : $"{e.Ordinal} {e.Name} @{e.Address.Rva:X}");
            }
        }
        var actual = new HashSet<string>(pe.Exports.Select(e => e.ForwardedTo != null ? $"{e.Ordinal} {e.Name} -> {e.ForwardedTo}" : $"{e.Ordinal} {e.Name} @{e.Rva:X}"), StringComparer.Ordinal);
        SetDiff(diffs, "exports", expected, actual);
    }

    private static void CompareRelocations(PeFile pe, AsmResolver.PE.PEImage image, List<string> diffs)
    {
        // AsmResolver lists the ABSOLUTE (type 0) entries that only pad blocks to 4 bytes; the parser drops them.
        var expected = image.Relocations.Where(r => r.Type != AsmResolver.PE.Relocations.RelocationType.Absolute).Select(r => $"{r.Location.Rva:X} {(int)r.Type}").ToList();
        var actual = pe.BaseRelocations.Select(r => $"{r.Rva:X} {(int)r.Type}").ToList();
        Check(diffs, "relocations", "count", expected.Count, actual.Count);
        SetDiff(diffs, "relocations", expected.ToHashSet(), actual.ToHashSet());
    }

    private static void CompareTls(PeFile pe, AsmResolver.PE.PEImage image, List<string> diffs)
    {
        var expected = image.TlsDirectory?.CallbackFunctions.Select(c => c.Rva).ToList() ?? [];
        Check(diffs, "tls", "callbacks", string.Join(",", expected.Select(r => r.ToString("X"))), string.Join(",", pe.TlsCallbackRvas.Select(r => r.ToString("X"))));
    }

    private static void CompareRuntimeFunctions(PeFile pe, AsmResolver.PE.PEImage image, List<string> diffs)
    {
        if (pe.Arch != NativeArch.X64 || image.Exceptions == null) return;
        // Entries with End <= Begin (seen in msquic.sys and msedge.dll) describe no code; the parser drops them with an
        // issue, AsmResolver lists them.
        var expected = image.Exceptions.GetFunctions().Where(f => f.End.Rva > f.Begin.Rva)
            .Select(f => $"{f.Begin.Rva:X}-{f.End.Rva:X}").ToHashSet();
        var actual = pe.RuntimeFunctions.Select(f => $"{f.BeginRva:X}-{f.EndRva:X}").ToHashSet();
        SetDiff(diffs, "pdata", expected, actual);
    }

    private static void CompareDebug(PeFile pe, AsmResolver.PE.PEImage image, List<string> diffs)
    {
        Check(diffs, "debug", "entries", image.DebugData.Count, pe.DebugEntries.Count);
        var rsds = image.DebugData.Select(d => d.Contents).OfType<AsmResolver.PE.Debug.RsdsDataSegment>().FirstOrDefault();
        if (rsds != null)
        {
            Check(diffs, "debug", "guid", rsds.Guid, pe.CodeView?.Guid ?? Guid.Empty);
            Check(diffs, "debug", "age", rsds.Age, pe.CodeView?.Age ?? 0);
            Check(diffs, "debug", "path", (string?)rsds.Path, pe.CodeView?.PdbPath);
        }
    }

    private static void CompareResources(PeFile pe, AsmResolver.PE.PEImage image, List<string> diffs)
    {
        var expected = new List<string>();
        if (image.Resources is { } root) Walk(root, [], expected);
        var actual = pe.Resources.Select(r => $"{string.Join("/", r.Path)} {r.Size}").ToList();
        Check(diffs, "resources", "count", expected.Count, actual.Count);
        SetDiff(diffs, "resources", expected.ToHashSet(), actual.ToHashSet());

        static void Walk(AsmResolver.PE.Win32Resources.ResourceDirectory dir, List<string> path, List<string> into)
        {
            foreach (var entry in dir.Entries)
            {
                path.Add(entry.Name ?? "#" + entry.Id);
                if (entry is AsmResolver.PE.Win32Resources.ResourceDirectory sub) Walk(sub, path, into);
                else if (entry is AsmResolver.PE.Win32Resources.ResourceData data) into.Add($"{string.Join("/", path)} {data.Contents?.GetPhysicalSize() ?? 0}");
                path.RemoveAt(path.Count - 1);
            }
        }
    }

    private static void SetDiff(List<string> diffs, string area, IReadOnlySet<string> expected, IReadOnlySet<string> actual)
    {
        foreach (var e in expected.Where(e => !actual.Contains(e)).Take(MaxDiffsPerArea)) Diff(diffs, area, $"missing {e}");
        foreach (var a in actual.Where(a => !expected.Contains(a)).Take(MaxDiffsPerArea)) Diff(diffs, area, $"extra {a}");
    }

    /// <summary>
    /// Imports (regular and delay-load, by module in table order), exports and load config against dumpbin's
    /// /imports /exports /loadconfig text.
    /// </summary>
    public static List<string> CompareWithDumpbin(PeFile pe, Dumpbin.Result d)
    {
        var diffs = new List<string>();
        CompareModules(diffs, "dumpbin imports", d.Imports, pe.ImportModules, pe);
        CompareModules(diffs, "dumpbin delay imports", d.DelayImports, pe.DelayImportModules, pe);
        Check(diffs, "dumpbin bound imports", "modules", string.Join(", ", d.BoundImports),
            string.Join(", ", pe.BoundImports.Select(b => $"{b.Module} [{b.TimeDateStamp:X8}]")));

        var expected = d.Exports.ToHashSet();
        var actual = pe.Exports.Select(e => e.ForwardedTo != null ? $"{e.Ordinal} {e.Name ?? "[NONAME]"} -> {e.ForwardedTo}" : $"{e.Ordinal} {e.Name ?? "[NONAME]"} @{e.Rva:X8}").ToHashSet();
        SetDiff(diffs, "dumpbin exports", expected, actual);

        if (d.LoadConfig.Count > 0)
        {
            var lc = pe.LoadConfig;
            void Field(string label, ulong? value)
            {
                if (d.LoadConfig.TryGetValue(label, out ulong e)) Check(diffs, "dumpbin loadconfig", label, e, value ?? 0);
            }
            Field("size", lc?.Size);
            Field("Security Cookie", lc?.SecurityCookie);
            Field("Safe Exception Handler Table", lc?.SeHandlerTable);
            Field("Safe Exception Handler Count", lc?.SeHandlerCount);
            Field("Guard CF function table", lc?.GuardCfFunctionTable);
            Field("Guard CF function count", lc?.GuardCfFunctionCount);
            Field("Guard Flags", lc?.GuardFlags);
            Field("Guard CF address taken IAT entry table", lc?.GuardAddressTakenIatEntryTable);
            Field("Guard CF address taken IAT entry count", lc?.GuardAddressTakenIatEntryCount);
            Field("Guard CF long jump target table", lc?.GuardLongJumpTargetTable);
            Field("Guard CF long jump target count", lc?.GuardLongJumpTargetCount);
            Field("Guard EH continuation table", lc?.GuardEhContinuationTable);
            Field("Guard EH continuation count", lc?.GuardEhContinuationCount);
            if (lc != null)
            {
                Check(diffs, "dumpbin loadconfig", "SEH handlers", string.Join(",", d.SafeSehHandlers.Select(v => v.ToString("X"))),
                    string.Join(",", lc.SeHandlerRvas.Select(r => (pe.ImageBase + r).ToString("X"))));
                Check(diffs, "dumpbin loadconfig", "CF functions", string.Join(",", d.GuardCfFunctions.Select(v => v.ToString("X"))),
                    string.Join(",", lc.GuardCfFunctions.Select(r => (pe.ImageBase + r.Rva).ToString("X"))));
            }
        }
        return diffs;
    }

    private static void CompareModules(List<string> diffs, string area, List<Dumpbin.Module> expected, IReadOnlyList<PeImportModule> actual, PeFile pe)
    {
        Check(diffs, area, "module count", expected.Count, actual.Count);
        for (int m = 0; m < Math.Min(expected.Count, actual.Count); m++)
        {
            var e = expected[m];
            var a = actual[m];
            Check(diffs, area, $"[{m}] name", e.Name, a.Name);
            if (e.AddressTable is { } iat) Check(diffs, area, $"{a.Name} IAT", iat, pe.ImageBase + a.AddressTableRva);
            var functions = a.Functions.Select(f => f.Name != null ? $"{f.Hint:X} {f.Name}" : $"#{f.Ordinal}").ToList();
            if (e.Functions.Count != functions.Count)
                Diff(diffs, area, $"{a.Name} count: oracle {e.Functions.Count} (last '{e.Functions.LastOrDefault()}'), parser {functions.Count} (last '{functions.LastOrDefault()}')");
            for (int i = 0; i < Math.Min(e.Functions.Count, functions.Count); i++)
                Check(diffs, area, $"{a.Name}[{i}]", e.Functions[i], functions[i]);
        }
    }
}

/// <summary>dumpbin.exe from a Visual Studio or Build Tools install, found through vswhere or the standard layout.</summary>
internal static class Dumpbin
{
    public sealed record Module(string Name, ulong? AddressTable, List<string> Functions);

    public sealed class Result
    {
        public List<Module> Imports { get; } = [];
        public List<Module> DelayImports { get; } = [];
        /// <summary>"MODULE [stamp]" per bound import descriptor.</summary>
        public List<string> BoundImports { get; } = [];
        /// <summary>"ordinal name @RVA" or "ordinal name -> forwarder"; name is [NONAME] for ordinal-only exports.</summary>
        public List<string> Exports { get; } = [];
        public Dictionary<string, ulong> LoadConfig { get; } = new(StringComparer.Ordinal);
        public List<ulong> SafeSehHandlers { get; } = [];
        public List<ulong> GuardCfFunctions { get; } = [];
    }

    private static readonly Lazy<string?> Exe = new(Find);

    public static string? Path => Exe.Value;

    private static string? Find()
    {
        if (!OperatingSystem.IsWindows()) return null;
        var roots = new List<string>();
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var vswhere = System.IO.Path.Combine(programFilesX86, "Microsoft Visual Studio", "Installer", "vswhere.exe");
        if (File.Exists(vswhere))
        {
            var (code, output) = Tools.Run(new ProcessStartInfo(vswhere, "-products * -prerelease -property installationPath"), 60_000);
            if (code == 0) roots.AddRange(output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        }
        foreach (var pf in new[] { programFilesX86, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) })
        {
            var vs = System.IO.Path.Combine(pf, "Microsoft Visual Studio");
            if (System.IO.Directory.Exists(vs))
                foreach (var year in System.IO.Directory.GetDirectories(vs))
                    roots.AddRange(System.IO.Directory.GetDirectories(year));
        }
        foreach (var root in roots)
        {
            var msvc = System.IO.Path.Combine(root, "VC", "Tools", "MSVC");
            if (!System.IO.Directory.Exists(msvc)) continue;
            foreach (var version in System.IO.Directory.GetDirectories(msvc).OrderByDescending(v => v, StringComparer.OrdinalIgnoreCase))
            {
                var exe = System.IO.Path.Combine(version, "bin", "Hostx64", "x64", "dumpbin.exe");
                if (File.Exists(exe)) return exe;
            }
        }
        return null;
    }

    /// <summary>Runs dumpbin over <paramref name="files"/> in one process; results keyed by full path (case-insensitive).</summary>
    public static Dictionary<string, Result> Run(IReadOnlyList<string> files, bool loadConfig)
    {
        var psi = new ProcessStartInfo(Path ?? throw new InvalidOperationException("dumpbin not found"));
        foreach (var a in new[] { "/nologo", "/imports", "/exports" }) psi.ArgumentList.Add(a);
        if (loadConfig) psi.ArgumentList.Add("/loadconfig");
        foreach (var f in files) psi.ArgumentList.Add(f);
        // Standard output only: warnings on standard error would land at arbitrary points of the listing.
        psi.RedirectStandardOutput = psi.RedirectStandardError = true;
        psi.UseShellExecute = false;
        using var p = Process.Start(psi)!;
        p.ErrorDataReceived += (_, _) => { };
        p.BeginErrorReadLine();
        var output = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        return Parse(output);
    }

    private enum Section { None, ExportHeader, Exports, Imports, DelayImports, BoundImports, LoadConfig, SafeSeh, GuardCf, OtherTable }

    public static Dictionary<string, Result> Parse(string output)
    {
        var results = new Dictionary<string, Result>(StringComparer.OrdinalIgnoreCase);
        Result? current = null;
        var section = Section.None;
        Module? module = null;
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            var t = line.Trim();
            if (line.StartsWith("Dump of file ", StringComparison.Ordinal))
            {
                current = new Result();
                results[line["Dump of file ".Length..].Trim()] = current;
                section = Section.None;
                module = null;
                continue;
            }
            if (current == null || t.Length == 0 || t.StartsWith("LINK : ", StringComparison.Ordinal)) continue; // linker warnings are interleaved
            if (t.StartsWith("Section contains the following exports", StringComparison.Ordinal)) { section = Section.ExportHeader; continue; }
            if (section == Section.ExportHeader && t.StartsWith("ordinal hint", StringComparison.Ordinal)) { section = Section.Exports; continue; }
            if (t == "Section contains the following imports:") { section = Section.Imports; module = null; continue; }
            if (t == "Section contains the following delay load imports:") { section = Section.DelayImports; module = null; continue; }
            if (t == "Section contains the following load config:") { section = Section.LoadConfig; continue; }
            if (t == "Header contains the following bound import information:") { section = Section.BoundImports; continue; }
            if (section == Section.BoundImports)
            {
                if (t.StartsWith("Bound to ", StringComparison.Ordinal)) current.BoundImports.Add(t["Bound to ".Length..t.IndexOf(']')] + "]");
                continue;
            }
            if (t == "Summary") { section = Section.None; continue; }
            if (section is Section.LoadConfig or Section.SafeSeh or Section.GuardCf or Section.OtherTable)
            {
                if (t == "Safe Exception Handler Table") { section = Section.SafeSeh; continue; }
                if (t == "Guard CF Function Table") { section = Section.GuardCf; continue; }
                if (t.EndsWith("Table", StringComparison.Ordinal) && !char.IsAsciiHexDigit(t[0])) { section = Section.OtherTable; continue; }
            }
            switch (section)
            {
                case Section.Exports:
                    ParseExport(t, current);
                    break;
                case Section.Imports:
                case Section.DelayImports:
                    var list = section == Section.Imports ? current.Imports : current.DelayImports;
                    if (line.StartsWith("    ", StringComparison.Ordinal) && !line.StartsWith("     ", StringComparison.Ordinal))
                    {
                        module = new Module(t, null, []);
                        list.Add(module);
                    }
                    else if (module != null) ParseImportLine(t, module, list, section == Section.DelayImports);
                    break;
                case Section.LoadConfig:
                    var parts = t.Split(' ', 2, StringSplitOptions.TrimEntries);
                    if (parts.Length == 2 && ulong.TryParse(parts[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong v))
                        current.LoadConfig.TryAdd(parts[1], v);
                    break;
                case Section.SafeSeh:
                case Section.GuardCf:
                    // "[flags]  ADDRESS" rows under an "Address" / "--------" heading: zero or more one-letter flags
                    // ("E X" for an export-suppressed target), then an address of 8 or 16 hex digits.
                    if (t is "Address" || t.All(c => c == '-')) break;
                    var cells = t.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    var last = cells[^1];
                    if (cells[..^1].All(c => c.Length == 1 && char.IsAsciiLetter(c[0])) && last.Length is 8 or 16 && last.All(char.IsAsciiHexDigit)
                        && ulong.TryParse(last, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong a))
                        (section == Section.SafeSeh ? current.SafeSehHandlers : current.GuardCfFunctions).Add(a);
                    else section = Section.OtherTable;
                    break;
            }
        }
        return results;
    }

    private static void ParseExport(string t, Result r)
    {
        // "ordinal hint RVA name", hint and RVA optional; name may be "[NONAME]"; forwarders end in "(forwarded to X)".
        var tokens = t.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length < 2 || !uint.TryParse(tokens[0], out uint ordinal)) return;
        string? forwarder = null;
        int fwd = t.IndexOf(" (forwarded to ", StringComparison.Ordinal);
        if (fwd >= 0)
        {
            forwarder = t[(fwd + " (forwarded to ".Length)..].TrimEnd(')');
            tokens = t[..fwd].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        }
        // Remaining after the ordinal: [hint] [rva] name; hints are short hex, RVAs 8 hex digits.
        var rest = tokens.Skip(1).ToList();
        string name = rest[^1];
        string? rva = rest.Count >= 2 && rest[^2].Length == 8 && rest[^2].All(char.IsAsciiHexDigit) ? rest[^2] : null;
        if (name.Length == 8 && name.All(char.IsAsciiHexDigit) && rest.Count >= 1 && t.EndsWith(name, StringComparison.Ordinal) && fwd < 0 && rva == null)
            return; // no name column: not an export line
        r.Exports.Add(forwarder != null ? $"{ordinal} {name} -> {forwarder}" : $"{ordinal} {name} @{rva ?? "00000000"}");
    }

    private static void ParseImportLine(string t, Module module, List<Module> list, bool delay)
    {
        var tokens = t.Split(' ', 2, StringSplitOptions.TrimEntries);
        if (tokens.Length == 2 && tokens[1] == "Import Address Table" && ulong.TryParse(tokens[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong iat))
        {
            list[^1] = module with { AddressTable = iat };
            return;
        }
        if (tokens.Length == 2 && tokens[1] is "Import Name Table" or "Bound Import Name Table" or "Unload Import Name Table" or "time date stamp"
            or "Index of first forwarder reference" or "Characteristics" or "Address of HMODULE") return;
        var parts = t.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
        while (parts.Count >= 3 && parts[0].Length >= 8 && parts[0].All(char.IsAsciiHexDigit)) parts.RemoveAt(0); // bound address and delay IAT columns
        if (parts.Count == 2 && parts[0] == "Ordinal") list[^1].Functions.Add("#" + parts[1]);
        else if (parts.Count >= 2) list[^1].Functions.Add($"{parts[0].TrimStart('0').PadLeft(1, '0')} {string.Join(' ', parts.Skip(1))}");
    }
}
