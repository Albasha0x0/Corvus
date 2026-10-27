using System.Globalization;
using System.Text.Json;
using Corvus.Core;

namespace Corvus.Native.Dump;

/// <summary>A region-set region: <see cref="Size"/> bytes at <see cref="Base"/>, of which <see cref="File"/> holds <see cref="Held"/>; the rest is unknown.</summary>
public sealed record RegionSetRegion(ulong Base, ulong Size, string File, string FullPath, bool Missing, ulong Held, uint Protect)
{
    public ulong End => Base + Size;
}

/// <summary>A region-set dump: a JSON manifest of memory region files read as one process's memory; a missing file reads as unknown.</summary>
/// <remarks><see cref="Open"/> rejects an unknown format, overlapping regions and a file outside the manifest's folder.</remarks>
public sealed class RegionSetFile : IProcessMemory
{
    /// <summary>The manifest format this build reads.</summary>
    public const int Format = 1;

    private const int MaxManifestBytes = 16 << 20;
    private const int MaxRegions = 1 << 16;

    private readonly RegionSetRegion[] _regions;
    private readonly List<DumpModule> _modules = [];
    private readonly List<ParseIssue> _issues = [];

    private RegionSetFile(string path, NativeArch arch, uint? processId, string? source, RegionSetRegion[] regions, string identity)
    {
        Path = path;
        Arch = arch;
        ProcessId = processId;
        Source = source;
        _regions = regions;
        Identity = identity;
    }

    public string Path { get; }
    public NativeArch Arch { get; }
    public bool Is64Bit => Arch is NativeArch.X64 or NativeArch.Arm64;
    public string Identity { get; }

    /// <summary>The process the regions belong to, or null when the manifest does not name it.</summary>
    public uint? ProcessId { get; }

    /// <summary>The manifest's label for the tool or run that saved the regions, or null.</summary>
    public string? Source { get; }

    /// <summary>The regions, sorted by base address, never overlapping.</summary>
    public IReadOnlyList<RegionSetRegion> Regions => _regions;

    public IReadOnlyList<DumpModule> Modules => _modules;
    public IReadOnlyList<DumpUnloadedModule> UnloadedModules => [];
    public IReadOnlyList<ParseIssue> Issues => _issues;

    /// <summary>Bytes the region files hold.</summary>
    public ulong CapturedBytes => _regions.Aggregate(0UL, (sum, r) => sum + r.Held);

    /// <summary>Whether the file starts with a JSON object naming <c>"format"</c> and <c>"regions"</c>; false when it cannot be read.</summary>
    public static bool IsManifest(string path)
    {
        try
        {
            using var f = System.IO.File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var head = new byte[4096];
            int n = RandomAccess.Read(f, head, 0);
            var text = System.Text.Encoding.UTF8.GetString(head, 0, n).TrimStart('﻿', ' ', '\t', '\r', '\n');
            return text.StartsWith('{') && text.Contains("\"format\"", StringComparison.Ordinal) && text.Contains("\"regions\"", StringComparison.Ordinal);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return false; }
    }

    /// <summary>Reads the manifest at <paramref name="path"/>; throws a <see cref="ToolError"/> naming what it cannot read.</summary>
    public static RegionSetFile Open(string path)
    {
        var full = InputFiles.RequireRegularFile(path, "region-set manifest");
        var info = new FileInfo(full);
        if (!info.Exists) throw Targets.FileNotFound(path);
        if (info.Length > MaxManifestBytes)
            throw new ToolError(ErrorCode.LimitExceeded, $"The region-set manifest {full} is {info.Length:N0} bytes; at most {MaxManifestBytes:N0} are read.");
        JsonDocument doc;
        try { doc = JsonDocument.Parse(System.IO.File.ReadAllBytes(full), new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip }); }
        catch (JsonException ex) { throw Bad(full, $"it is not valid JSON: {ex.Message}"); }
        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw Bad(full, "the top level is not an object");
            if (!root.TryGetProperty("format", out var format) || !format.TryGetInt32(out int version))
                throw Bad(full, "it has no \"format\" number");
            if (version != Format)
                throw new ToolError(ErrorCode.Unsupported, $"The region-set manifest {full} is format {version}; this build reads format {Format}.",
                    "write the manifest as \"format\": 1");
            var arch = Text(root, "arch")?.ToLowerInvariant() switch
            {
                "x64" or "amd64" or "x86_64" => NativeArch.X64,
                "x86" or "i386" or "ia32" => NativeArch.X86,
                "arm64" or "aarch64" => NativeArch.Arm64,
                "arm" => NativeArch.Arm,
                null => throw Bad(full, "it has no \"arch\" (x86, x64, arm or arm64)"),
                var other => throw Bad(full, $"\"arch\" is '{other}', not x86, x64, arm or arm64"),
            };
            uint? pid = Number(root, "processId", full, "processId") is { } p ? (uint)p : null;
            string folder = System.IO.Path.GetDirectoryName(full)!;
            if (!root.TryGetProperty("regions", out var list) || list.ValueKind != JsonValueKind.Array) throw Bad(full, "it has no \"regions\" array");
            if (list.GetArrayLength() > MaxRegions)
                throw new ToolError(ErrorCode.LimitExceeded, $"The region-set manifest {full} lists {list.GetArrayLength():N0} regions; at most {MaxRegions:N0} are read.");
            var regions = new List<RegionSetRegion>();
            var issues = new List<ParseIssue>();
            int index = 0;
            foreach (var r in list.EnumerateArray())
            {
                string where = $"regions[{index++}]";
                if (r.ValueKind != JsonValueKind.Object) throw Bad(full, $"{where} is not an object");
                var file = Text(r, "file") ?? throw Bad(full, $"{where} has no \"file\"");
                ulong start = Number(r, "base", full, where + ".base") ?? throw Bad(full, $"{where} has no \"base\"");
                ulong size = Number(r, "size", full, where + ".size") ?? throw Bad(full, $"{where} has no \"size\"");
                if (size == 0 || start + size < start) throw Bad(full, $"{where} ({file}) has size 0x{size:X} at 0x{start:X}, which is empty or wraps the address space");
                if (Number(r, "processId", full, where + ".processId") is { } rp)
                {
                    if (pid is { } other && other != rp)
                        throw Bad(full, $"{where} ({file}) belongs to process {rp} and the manifest to process {other}; one manifest holds one process");
                    pid = (uint)rp;
                }
                if (System.IO.Path.IsPathRooted(file)) throw Bad(full, $"{where} names an absolute path ({file}); region files are paths inside the manifest's folder");
                var at = System.IO.Path.GetFullPath(System.IO.Path.Combine(folder, file));
                if (!at.StartsWith(folder.TrimEnd(System.IO.Path.DirectorySeparatorChar) + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    throw Bad(full, $"{where} names {file}, which is outside the manifest's folder");
                var fi = new FileInfo(at);
                ulong held = fi.Exists ? Math.Min(size, (ulong)fi.Length) : 0;
                if (!fi.Exists) issues.Add(new ParseIssue("regions", $"{file} is missing: 0x{start:X}-0x{start + size:X} is unknown"));
                else if (held < size) issues.Add(new ParseIssue("regions", $"{file} holds 0x{held:X} of 0x{size:X} bytes: 0x{start + held:X}-0x{start + size:X} is unknown"));
                regions.Add(new RegionSetRegion(start, size, file, at, !fi.Exists, held, Protection(Text(r, "protect"), full, where)));
            }
            regions.Sort((a, b) => a.Base.CompareTo(b.Base));
            for (int i = 1; i < regions.Count; i++)
                if (regions[i].Base < regions[i - 1].End)
                    throw Bad(full, $"{regions[i - 1].File} (0x{regions[i - 1].Base:X}-0x{regions[i - 1].End:X}) and {regions[i].File} (0x{regions[i].Base:X}-0x{regions[i].End:X}) overlap");
            var set = new RegionSetFile(full, arch, pid, Text(root, "source"), [.. regions], $"regions|{full}|{info.Length}|{info.LastWriteTimeUtc.Ticks}");
            set._issues.AddRange(issues);
            var modules = new List<DumpModule>();
            if (root.TryGetProperty("modules", out var mods) && mods.ValueKind == JsonValueKind.Array)
            {
                index = 0;
                foreach (var m in mods.EnumerateArray())
                {
                    string where = $"modules[{index++}]";
                    var name = Text(m, "path") ?? Text(m, "name") ?? throw Bad(full, $"{where} has no \"name\"");
                    ulong start = Number(m, "base", full, where + ".base") ?? throw Bad(full, $"{where} ({name}) has no \"base\"");
                    ulong size = Number(m, "size", full, where + ".size") ?? set.ImageSize(start);
                    if (size == 0) set._issues.Add(new ParseIssue("modules", $"{name}: no \"size\" and no readable PE header at 0x{start:X}; its extent is unknown"));
                    modules.Add(new DumpModule(start, (uint)Math.Min(size, uint.MaxValue), 0, set.TimeDateStamp(start), name, null, null, null));
                }
            }
            set._modules.AddRange(modules.OrderBy(m => m.Base));
            return set;
        }
    }

    private static ToolError Bad(string path, string what) =>
        new(ErrorCode.InvalidArgument, $"The region-set manifest {path} cannot be read: {what}.",
            "a manifest is {\"format\": 1, \"arch\": \"x64\", \"regions\": [{\"file\": \"r.bin\", \"base\": \"0x10000\", \"size\": 4096}]}");

    private static string? Text(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    /// <summary>A number or a "0x" hex string; null when absent.</summary>
    private static ulong? Number(JsonElement e, string name, string path, string where)
    {
        if (!e.TryGetProperty(name, out var v) || v.ValueKind == JsonValueKind.Null) return null;
        if (v.ValueKind == JsonValueKind.Number && v.TryGetUInt64(out var n)) return n;
        if (v.ValueKind == JsonValueKind.String && v.GetString() is { } s)
        {
            var t = s.Trim();
            if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && ulong.TryParse(t[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out n)) return n;
            if (ulong.TryParse(t, NumberStyles.None, CultureInfo.InvariantCulture, out n)) return n;
        }
        throw Bad(path, $"{where} is not a number or a 0x hex string");
    }

    /// <summary>PAGE_* protection of "r", "rw", "rx" or "rwx"; 0 (unknown) when absent.</summary>
    private static uint Protection(string? text, string path, string where) => text?.ToLowerInvariant() switch
    {
        null => 0,
        "r" => 0x02,
        "rw" => 0x04,
        "x" or "rx" => 0x20,
        "rwx" => 0x40,
        "none" or "" => 0x01,
        var other => throw Bad(path, $"{where}.protect is '{other}', not r, rw, rx or rwx"),
    };

    private ulong ImageSize(ulong start)
    {
        Span<byte> b = stackalloc byte[4];
        if (ReadMemory(start + 0x3C, b) < 4) return 0;
        uint lfanew = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(b);
        if (lfanew > 0x1000 || ReadMemory(start + lfanew, b) < 4 || b[0] != 'P' || b[1] != 'E') return 0;
        return ReadMemory(start + lfanew + 0x50, b) == 4 ? System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(b) : 0;
    }

    private uint TimeDateStamp(ulong start)
    {
        Span<byte> b = stackalloc byte[4];
        if (ReadMemory(start + 0x3C, b) < 4) return 0;
        uint lfanew = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(b);
        if (lfanew > 0x1000 || ReadMemory(start + lfanew, b) < 4 || b[0] != 'P' || b[1] != 'E') return 0;
        return ReadMemory(start + lfanew + 8, b) == 4 ? System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(b) : 0;
    }

    /// <summary>The region holding <paramref name="address"/>, or null.</summary>
    public RegionSetRegion? RegionSetAt(ulong address)
    {
        int lo = 0, hi = _regions.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            var r = _regions[mid];
            if (address < r.Base) hi = mid - 1;
            else if (address >= r.End) lo = mid + 1;
            else return r;
        }
        return null;
    }

    public int ReadMemory(ulong address, Span<byte> destination)
    {
        int done = 0;
        while (done < destination.Length && RegionSetAt(address + (ulong)done) is { } r)
        {
            ulong offset = address + (ulong)done - r.Base;
            if (offset >= r.Held) break;
            int want = (int)Math.Min((ulong)(destination.Length - done), r.Held - offset);
            int got;
            try
            {
                using var f = System.IO.File.OpenHandle(r.FullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                got = RandomAccess.Read(f, destination.Slice(done, want), (long)offset);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { break; }
            done += got;
            if (got < want) break;
        }
        return done;
    }

    public DumpModule? ModuleAt(ulong address)
    {
        foreach (var m in _modules)
            if (m.Contains(address)) return m;
        return null;
    }

    public DumpMemoryRegion? RegionAt(ulong address) =>
        RegionSetAt(address) is { } r ? new DumpMemoryRegion(r.Base, r.Base, r.Protect, r.Size, 0x1000, r.Protect, 0) : null;

    public ulong ReadableExtent(ulong start, ulong size)
    {
        ulong done = 0;
        while (done < size && RegionSetAt(start + done) is { } r)
        {
            ulong offset = start + done - r.Base;
            if (offset >= r.Held) break;
            done += Math.Min(size - done, r.Held - offset);
        }
        return done;
    }
}
