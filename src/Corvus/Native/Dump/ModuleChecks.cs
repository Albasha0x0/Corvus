using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using Corvus.Core;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump;

/// <summary>A module's local file signature: the signer and how it was read.</summary>
public sealed record ModuleSignature(string? Signer, string State);

/// <summary>A module's code section in memory against the local file: the outcome and what was compared.</summary>
public sealed record CodeComparison(string State, string Detail);

/// <summary>Per-module checks of a dump or a running process: load path class, local file signature, and code section against the file.</summary>
public static class ModuleChecks
{
    /// <summary>Largest local file whose signature is read, and most code bytes compared for one module.</summary>
    public const long MaxSignedFile = 256L << 20, MaxCompareBytes = 64L << 20;

    private const int Page = 0x1000, Chunk = 0x10000, Lead = 8, MaxCached = 1024;

    private static readonly ConcurrentDictionary<(string Path, long Length, long Written), ModuleSignature> Signatures = new();

    /// <summary>The kind of folder a module path lies in: network, temp, user_writable, system, program_files or other; null for an empty path.</summary>
    public static string? PathClass(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var p = path.Replace('/', '\\');
        if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase) || p.StartsWith(@"\\", StringComparison.Ordinal) && !p.StartsWith(@"\\?\", StringComparison.Ordinal)
            && !p.StartsWith(@"\\.\", StringComparison.Ordinal)) return "network";
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p[4..];
        if (p.Length > 2 && p[1] == ':')
        {
            var rest = p[2..];
            if (Segment(rest, @"\temp\") || Segment(rest, @"\tmp\")) return "temp";
            if (StartsFolder(rest, @"\users\") || StartsFolder(rest, @"\programdata\") || StartsFolder(rest, @"\documents and settings\")) return "user_writable";
            if (StartsFolder(rest, @"\windows\")) return "system";
            if (StartsFolder(rest, @"\program files\") || StartsFolder(rest, @"\program files (x86)\")) return "program_files";
            return "other";
        }
        if (p.StartsWith('\\'))
        {
            // POSIX path of a core file, with the separators as normalized above.
            var q = p.Replace('\\', '/');
            if (q.StartsWith("/tmp/", StringComparison.Ordinal) || q.StartsWith("/var/tmp/", StringComparison.Ordinal) || q.StartsWith("/dev/shm/", StringComparison.Ordinal)
                || q.StartsWith("/private/tmp/", StringComparison.Ordinal) || q.StartsWith("/private/var/folders/", StringComparison.Ordinal)) return "temp";
            if (q.StartsWith("/home/", StringComparison.Ordinal) || q.StartsWith("/Users/", StringComparison.Ordinal) || q.StartsWith("/root/", StringComparison.Ordinal)) return "user_writable";
            foreach (var prefix in new[] { "/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/System/", "/Library/", "/opt/" })
                if (q.StartsWith(prefix, StringComparison.Ordinal)) return "system";
        }
        return "other";
    }

    private static bool StartsFolder(string rest, string folder) => rest.StartsWith(folder, StringComparison.OrdinalIgnoreCase);

    private static bool Segment(string rest, string segment) => rest.Contains(segment, StringComparison.OrdinalIgnoreCase);

    /// <summary>The signer of the local file at <paramref name="path"/> (embedded signature, else a Microsoft catalog on Windows); state unknown when the file is not read.</summary>
    public static ModuleSignature Signature(string path)
    {
        FileInfo info;
        try
        {
            if (InputFiles.NamedProblem(path) != null) return new ModuleSignature(null, "unknown");
            info = new FileInfo(path);
            if (!info.Exists || info.Length > MaxSignedFile) return new ModuleSignature(null, "unknown");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return new ModuleSignature(null, "unknown"); }
        var key = (info.FullName, info.Length, info.LastWriteTimeUtc.Ticks);
        if (Signatures.TryGetValue(key, out var known)) return known;
        var result = Read(info);
        if (Signatures.Count >= MaxCached) Signatures.Clear();
        Signatures[key] = result;
        return result;
    }

    private static ModuleSignature Read(FileInfo file)
    {
        try
        {
            using var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.SequentialScan);
            var head = new byte[Math.Min(Chunk, file.Length)];
            stream.ReadExactly(head);
            if (PeImage.TryParse(head) == null) return new ModuleSignature(null, "unknown");
            var info = Certificates.Read(stream, head);
            if (info.Problem != null) return new ModuleSignature(info.Signer is { } s ? Name(s) : null, "unreadable");
            if (info.Present) return new ModuleSignature(info.Signer is { } subject ? Name(subject) : null, info.DigestMatches == false ? "digest_mismatch" : info.SignatureValid == false ? "invalid" : "signed");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or EndOfStreamException) { return new ModuleSignature(null, "unknown"); }
        if (OperatingSystem.IsWindows())
        {
            try
            {
                if (CatalogSignature.Verify(file.FullName, "Microsoft Corporation", out _) == null) return new ModuleSignature("Microsoft Corporation", "catalog");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return new ModuleSignature(null, "unknown"); }
        }
        return new ModuleSignature(null, "unsigned");
    }

    /// <summary>The common name of a certificate subject, else its organization, else the subject.</summary>
    private static string Name(string subject)
    {
        try
        {
            string? organization = null;
            foreach (var rdn in new X500DistinguishedName(subject).EnumerateRelativeDistinguishedNames())
            {
                if (rdn.GetSingleElementType().Value == "2.5.4.3") return rdn.GetSingleElementValue() ?? subject;
                if (rdn.GetSingleElementType().Value == "2.5.4.10") organization = rdn.GetSingleElementValue();
            }
            return organization ?? subject;
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or InvalidOperationException) { return subject; }
    }

    /// <summary>Compares the .text section (else the first read-only code section) of <paramref name="module"/> in <paramref name="memory"/> with <paramref name="image"/>, the matching file mapped by section; the file's base relocations are applied first. At most <paramref name="limit"/> bytes are compared; pages past it are named as left out, not as compared.</summary>
    public static CodeComparison CompareCode(IProcessMemory memory, DumpModule module, PeFile image, long limit = MaxCompareBytes)
    {
        var code = image.Sections.Where(s => (s.Access & (SectionAccess.Execute | SectionAccess.Code)) != 0 && (s.Access & SectionAccess.Write) == 0 && s.MappedSize > 0).ToList();
        // The loader writes into other code sections (hot-patch thunks, import stubs); .text is the code the program shipped.
        var sections = code.Where(s => s.Name == ".text").ToList() is { Count: > 0 } text ? text : code.Take(1).ToList();
        if (sections.Count == 0) return new CodeComparison("unknown", "the file has no read-only code section");
        long delta = unchecked((long)module.Base - (long)image.ImageBase);
        var pointer = image.Is64Bit ? PeRelocationType.Dir64 : PeRelocationType.HighLow;
        var relocations = image.BaseRelocations.Where(r => r.Type == pointer).OrderBy(r => r.Rva).ToList();
        long budget = limit, pages = 0, missing = 0, differing = 0, bytesDiffering = 0;
        uint? first = null;
        string? firstSection = null;
        bool capped = false;
        long total = sections.Sum(s => ((long)s.MappedSize + Page - 1) / Page);
        // Eight bytes either side of a chunk hold the parts of relocated fields that straddle its edges.
        var local = new byte[Lead + Chunk + 8];
        var live = new byte[Chunk];
        foreach (var section in sections)
        {
            for (uint offset = 0; offset < section.MappedSize; offset += Chunk)
            {
                int want = (int)Math.Min(Chunk, section.MappedSize - offset);
                if (budget <= 0) { capped = true; break; }
                budget -= want;
                uint rva = section.Rva + offset;
                int lead = offset == 0 ? 0 : Lead;
                if (image.Read(rva - (uint)lead, local.AsSpan(0, lead + want + 8)) < lead + want) { missing += (want + Page - 1) / Page; pages += (want + Page - 1) / Page; continue; }
                Relocate(local, rva - (uint)lead, lead + want, delta, relocations, image.Is64Bit);
                int got = memory.ReadMemory(module.Base + rva, live.AsSpan(0, want));
                for (int at = 0; at < want; at += Page)
                {
                    int n = Math.Min(Page, want - at);
                    pages++;
                    if (got < at + n && memory.ReadMemory(module.Base + rva + (uint)at, live.AsSpan(at, n)) < n) { missing++; continue; }
                    var a = local.AsSpan(lead + at, n);
                    var b = live.AsSpan(at, n);
                    if (a.SequenceEqual(b)) continue;
                    differing++;
                    for (int i = 0; i < n; i++)
                        if (a[i] != b[i])
                        {
                            bytesDiffering++;
                            if (first == null) (first, firstSection) = (rva + (uint)at + (uint)i, section.Name);
                        }
                }
            }
        }
        // Pages are counted against the whole section, so a left-out page
        // shows as a shortfall.
        string scope = $"{pages - missing} of {total} page(s) of {string.Join(", ", sections.Select(s => s.Name))} compared";
        if (capped) scope += $"; the rest is past the {limit >> 20} MB limit";
        if (bytesDiffering > 0)
            return new CodeComparison("differs", $"{bytesDiffering:N0} differing byte(s) in {differing:N0} page(s), first at RVA 0x{first:X} in {firstSection}; {scope}");
        if (missing > 0 || capped || pages - missing == 0)
            return new CodeComparison("partial", scope + (missing > 0 ? "; the other pages are not in the dump" : ""));
        return new CodeComparison("same", scope);
    }

    /// <summary>Adds the load delta to each pointer-sized field the base relocation table places in [rva, rva + length), as the loader did.</summary>
    private static void Relocate(byte[] bytes, uint rva, int length, long delta, List<PeRelocation> relocations, bool is64)
    {
        if (delta == 0 || relocations.Count == 0) return;
        int lo = 0, hi = relocations.Count;
        while (lo < hi)
        {
            int mid = (lo + hi) >>> 1;
            if (relocations[mid].Rva < rva) lo = mid + 1; else hi = mid;
        }
        for (int i = lo; i < relocations.Count && relocations[i].Rva < rva + length; i++)
        {
            var field = bytes.AsSpan((int)(relocations[i].Rva - rva), is64 ? 8 : 4);
            if (is64) BinaryPrimitives.WriteUInt64LittleEndian(field, unchecked(BinaryPrimitives.ReadUInt64LittleEndian(field) + (ulong)delta));
            else BinaryPrimitives.WriteUInt32LittleEndian(field, unchecked(BinaryPrimitives.ReadUInt32LittleEndian(field) + (uint)delta));
        }
    }
}
