using System.Security.Cryptography;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Where a rebuilt image places its sections: at file-aligned offsets, or at their virtual addresses as in memory.</summary>
public enum OutputLayout { File, Mapped }

/// <summary>What the import address table holds in a rebuilt image: names restored, or the addresses the loader wrote.</summary>
public enum ImportMode { Restore, Keep }

/// <summary>The image base of a rebuilt image: the address it was loaded at, or its preferred base with relocations undone.</summary>
public enum BaseMode { Loaded, Preferred }

/// <summary>How a module is rebuilt from process memory.</summary>
/// <param name="ImageDirectories">Folders searched for the module's file on disk, besides its recorded path; null for the recorded path only.</param>
public sealed record RebuildOptions(OutputLayout Layout = OutputLayout.File, ImportMode Imports = ImportMode.Restore, BaseMode Base = BaseMode.Loaded,
    bool CompareWithDisk = true, string? ImageDirectories = null)
{
    public static readonly RebuildOptions Default = new();
}

/// <summary>One check of a rebuilt image: its name, state (ok, partial, failed, skipped, unknown) and a one-line detail.</summary>
public sealed record RebuildCheck(string Name, string State, string Detail)
{
    public static RebuildCheck Ok(string name, string detail) => new(name, "ok", detail);
    public static RebuildCheck Partial(string name, string detail) => new(name, "partial", detail);
    public static RebuildCheck Failed(string name, string detail) => new(name, "failed", detail);
    public static RebuildCheck Skipped(string name, string detail) => new(name, "skipped", detail);
    public static RebuildCheck Unknown(string name, string detail) => new(name, "unknown", detail);
}

/// <summary>Where a module to rebuild came from: the loader's module list, the runtime's assembly list, or a header found in unlisted memory.</summary>
public enum ModuleOrigin { Listed, Managed, Unlisted }

/// <summary>A module to rebuild: its name, base, mapped size, origin and the file the process loaded it from (null when it has none).</summary>
public sealed record RebuildTarget(string Name, ulong Base, uint Size, ModuleOrigin Origin, string? Path = null)
{
    public static RebuildTarget Of(DumpModule m) => new(m.FileName, m.Base, m.Size, ModuleOrigin.Listed, m.Path);
}

/// <summary>A module image read from process memory, always in mapped layout (offset = RVA), with the pages that were captured.</summary>
/// <param name="Image">The mapped image; pages that were not captured are zero.</param>
/// <param name="Captured">One flag per 4 KB page: true when the page was read.</param>
/// <param name="InputLayout">How the image lay in memory: mapped by a loader, or flat (a file read into memory, as Assembly.Load(byte[]) keeps it).</param>
public sealed record CapturedImage(RebuildTarget Target, byte[] Image, bool[] Captured, string InputLayout)
{
    public long CapturedBytes => (long)Captured.Count(c => c) * 0x1000;
    public int CapturedPercent => Captured.Length == 0 ? 0 : (int)(Captured.Count(c => c) * 100L / Captured.Length);
    public bool PageCaptured(uint rva) => rva / 0x1000 < Captured.Length && Captured[rva / 0x1000];
}

/// <summary>The import address table after a rebuild: entries named from intact name tables, named from exports, and left as addresses.</summary>
public sealed record ImportSummary(int Modules, int Restored, int Resolved, int Unresolved, bool DirectoryRebuilt)
{
    /// <summary>The slots named from exports, in image order; empty when none was.</summary>
    public IReadOnlyList<ResolvedImport> Names { get; init; } = [];
}

/// <summary>An import address table slot and the export it points at: slot RVA as hex text, and <c>module!name</c>.</summary>
public sealed record ResolvedImport(string Slot, string Name);

/// <summary>A difference between a rebuilt image and its file on disk: section, RVA range, and whether it is code.</summary>
public sealed record DiskDifference(string Section, string Start, int Length, bool Code);

/// <summary>A rebuilt image compared with its file on disk, relocations and the import address table excluded.</summary>
/// <param name="Differences">The first differing ranges, at most <see cref="DiskCompare.MaxRanges"/>.</param>
public sealed record DiskComparison(string File, bool SameBuild, int DifferingBytes, int Ranges, IReadOnlyList<DiskDifference> Differences);

/// <summary>A module rebuilt from process memory: its bytes and every check made on them.</summary>
/// <param name="Bytes">The rebuilt file; null when the module was refused (<see cref="Refused"/> says why).</param>
public sealed record RebuiltModule(RebuildTarget Target, string Format, string InputLayout, byte[]? Bytes, int CapturedPercent,
    IReadOnlyList<RebuildCheck> Checks, ImportSummary? Imports = null, DiskComparison? Disk = null, string? Metadata = null, string? MetadataReason = null,
    string? Refused = null)
{
    public string? Sha256 => Bytes == null ? null : Convert.ToHexStringLower(SHA256.HashData(Bytes));
}

/// <summary>Rebuilds loaded modules of a dump, core or running process into files a disassembler, decompiler or loader reads.</summary>
public static class ModuleRebuild
{
    /// <summary>Largest image rebuilt, and most bytes rebuilt in one call.</summary>
    public const long MaxImageBytes = 512L << 20, MaxTotalBytes = 2L << 30;

    /// <summary>
    /// The modules <paramref name="module"/> names: "all" (listed and managed in-memory), "unlisted" (headers found outside the module
    /// list), a base address (0x...), or a file name; empty when nothing matches.
    /// </summary>
    public static IReadOnlyList<RebuildTarget> Select(IProcessMemory memory, string module, CancellationToken ct)
    {
        var listed = memory.Modules.Select(RebuildTarget.Of).ToList();
        var managed = ManagedImages.InMemoryAssemblies(memory, ct).Where(m => !listed.Any(l => l.Base == m.Base)).ToList();
        var known = listed.Concat(managed).ToList();
        if (module.Equals("all", StringComparison.OrdinalIgnoreCase)) return known;
        if (module.Equals("unlisted", StringComparison.OrdinalIgnoreCase))
            return [.. UnlistedImages.Find(memory, ct).Where(u => !known.Any(k => k.Base == u.Base))];
        if (TryAddress(module, out ulong address))
            return [.. known.Concat(UnlistedImages.Find(memory, ct)).Where(t => address >= t.Base && address - t.Base < Math.Max(1u, t.Size)).Take(1)];
        return [.. known.Where(t => t.Name.Equals(module, StringComparison.OrdinalIgnoreCase)
            || Path.GetFileNameWithoutExtension(t.Name).Equals(module, StringComparison.OrdinalIgnoreCase))];
    }

    /// <summary>Rebuilds <paramref name="target"/> from <paramref name="memory"/>; a module that cannot be rebuilt is returned with its reason, never thrown.</summary>
    public static RebuiltModule Rebuild(IProcessMemory memory, RebuildTarget target, RebuildOptions options, CancellationToken ct)
    {
        if (target.Size > MaxImageBytes) return Refuse(target, $"larger than {MaxImageBytes >> 20} MB");
        if (memory is CoreFile core) return ElfRebuild.FromCore(core, target, options, ct);
        if (target.Origin == ModuleOrigin.Managed && target.Base == 0) return Refuse(target, "an emitted assembly has no image to rebuild");
        var read = CapturedImageReader.Read(memory, target, ct);
        if (read == null) return Refuse(target, "the memory does not hold the image headers");
        var captured = read;
        var checks = new List<RebuildCheck>();
        var image = (byte[])captured.Image.Clone();
        // Relocations and imports are fixed in mapped layout, where offsets are RVAs; the file layout is made last.
        PeRelocations.Apply(image, captured, options.Base, checks);
        var imports = PeImportRestore.Restore(ref image, ref captured, memory, options.Imports, checks, ct);
        var bytes = options.Layout == OutputLayout.File ? PeFileLayout.ToFileLayout(image, captured, checks) : PeFileLayout.AsMapped(image, captured, checks);
        if (bytes == null) return Refuse(target, checks[^1].Detail);
        var verified = PeVerify.Check(bytes, target, checks);
        var disk = options.CompareWithDisk ? DiskCompare.Compare(bytes, captured, options, checks) : null;
        return new RebuiltModule(target, "pe", captured.InputLayout, bytes, captured.CapturedPercent, checks, imports, disk, verified?.State, verified?.Reason);
    }

    private static bool TryAddress(string text, out ulong address)
    {
        address = 0;
        return text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            && ulong.TryParse(text.AsSpan(2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out address);
    }

    /// <summary>A module that could not be rebuilt, with the reason.</summary>
    public static RebuiltModule Refuse(RebuildTarget target, string reason) =>
        new(target, "unknown", "unknown", null, 0, [RebuildCheck.Failed("headers", reason)], Refused: reason);
}
