using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native.Elf;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Rebuilds an ELF module from the segments a core file captured.</summary>
public static class ElfRebuild
{
    private const int PageSize = 0x1000;
    private const ushort EtDyn = 3;

    private sealed record Load(ulong Offset, ulong VirtualAddress, ulong FileSize);

    /// <summary>The rebuilt module; refused with the reason when the core lacks its headers.</summary>
    public static RebuiltModule FromCore(CoreFile core, RebuildTarget target, RebuildOptions options, CancellationToken ct)
    {
        var head = new byte[64];
        int read = core.ReadMemory(target.Base, head);
        if (read < 52 || head[0] != 0x7F || head[1] != 'E' || head[2] != 'L' || head[3] != 'F')
            return ModuleRebuild.Refuse(target, "the core does not hold the ELF header");
        bool is64 = head[4] == 2;
        if (head[5] != 1) return ModuleRebuild.Refuse(target, "only little-endian ELF modules are rebuilt");
        if (is64 && read < 64) return ModuleRebuild.Refuse(target, "the core does not hold the ELF header");

        var span = head.AsSpan();
        ushort type = BinaryPrimitives.ReadUInt16LittleEndian(span[16..]);
        ulong phoff = is64 ? BinaryPrimitives.ReadUInt64LittleEndian(span[32..]) : BinaryPrimitives.ReadUInt32LittleEndian(span[28..]);
        int phentsize = BinaryPrimitives.ReadUInt16LittleEndian(span[(is64 ? 54 : 42)..]);
        int phnum = BinaryPrimitives.ReadUInt16LittleEndian(span[(is64 ? 56 : 44)..]);
        int minEntry = is64 ? 56 : 32;
        ulong tableBytes = (ulong)phnum * (ulong)phentsize;
        if (phnum == 0 || phentsize < minEntry || tableBytes > PageSize * 16 || phoff > ModuleRebuild.MaxImageBytes)
            return ModuleRebuild.Refuse(target, "the ELF header holds no usable program header table");
        var table = new byte[tableBytes];
        if (core.ReadMemory(target.Base + phoff, table) < table.Length)
            return ModuleRebuild.Refuse(target, "the core does not hold the program headers");

        var loads = new List<Load>();
        for (int i = 0; i < phnum; i++)
        {
            var e = table.AsSpan(i * phentsize, phentsize);
            if (BinaryPrimitives.ReadUInt32LittleEndian(e) != 1) continue;
            loads.Add(is64
                ? new Load(BinaryPrimitives.ReadUInt64LittleEndian(e[8..]), BinaryPrimitives.ReadUInt64LittleEndian(e[16..]), BinaryPrimitives.ReadUInt64LittleEndian(e[32..]))
                : new Load(BinaryPrimitives.ReadUInt32LittleEndian(e[4..]), BinaryPrimitives.ReadUInt32LittleEndian(e[8..]), BinaryPrimitives.ReadUInt32LittleEndian(e[16..])));
        }
        if (loads.Count == 0) return ModuleRebuild.Refuse(target, "the program headers hold no PT_LOAD segment");

        ulong end = Math.Max(phoff + tableBytes, 64);
        foreach (var l in loads)
        {
            if (l.Offset > ModuleRebuild.MaxImageBytes || l.FileSize > ModuleRebuild.MaxImageBytes) return ModuleRebuild.Refuse(target, $"larger than {ModuleRebuild.MaxImageBytes >> 20} MB");
            end = Math.Max(end, l.Offset + l.FileSize);
        }
        if (end > (ulong)ModuleRebuild.MaxImageBytes) return ModuleRebuild.Refuse(target, $"larger than {ModuleRebuild.MaxImageBytes >> 20} MB");

        // A shared object loads at its base; an executable keeps its link-time addresses.
        ulong bias = type == EtDyn ? target.Base - (loads.Min(l => l.VirtualAddress) & ~(ulong)(PageSize - 1)) : 0;
        var bytes = new byte[end];
        long wanted = 0, missing = 0;
        foreach (var l in loads)
        {
            ct.ThrowIfCancellationRequested();
            ulong done = 0;
            while (done < l.FileSize)
            {
                ulong at = l.VirtualAddress + bias + done;
                int chunk = (int)Math.Min(l.FileSize - done, PageSize - (at & (PageSize - 1)));
                int got = core.ReadMemory(at, bytes.AsSpan((int)(l.Offset + done), chunk));
                missing += chunk - got;
                done += (ulong)chunk;
            }
            wanted += (long)l.FileSize;
        }

        var checks = new List<RebuildCheck>();
        checks.Add(RebuildCheck.Skipped("relocations", "kept as loaded"));
        checks.Add(missing == 0
            ? RebuildCheck.Ok("layout", $"{loads.Count} load segments written at their file offsets; section headers are not in memory, so e_shoff, e_shnum and e_shstrndx are 0")
            : RebuildCheck.Partial("layout", $"{missing} of {wanted} segment bytes are not in the core and are zero; section headers are not in memory, so e_shoff, e_shnum and e_shstrndx are 0"));
        // Section headers are not in memory.
        bytes.AsSpan(is64 ? 0x28 : 0x20, is64 ? 8 : 4).Clear();
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(is64 ? 0x3C : 0x30), 0);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(is64 ? 0x3E : 0x32), 0);
        try
        {
            var elf = ElfFile.FromBytes(bytes, target.Name);
            checks.Add(RebuildCheck.Ok("parse", $"{elf.LoadSegments.Count} load segments read back"));
        }
        catch (ToolError e)
        {
            checks.Add(RebuildCheck.Failed("parse", e.Message));
        }
        int percent = wanted == 0 ? 0 : (int)((wanted - missing) * 100 / wanted);
        return new RebuiltModule(target, "elf", "mapped", bytes, percent, checks);
    }
}
