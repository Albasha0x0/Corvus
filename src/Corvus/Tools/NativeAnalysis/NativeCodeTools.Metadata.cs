using System.Buffers.Binary;
using Corvus.Native;
using Corvus.Native.Pe;

namespace Corvus.Tools;

/// <summary>find_xrefs kind=metadata: format tables holding an address (.pdata, CFG tables, the export address table).</summary>
public sealed partial class NativeCodeTools
{
    /// <summary>Rows in find_xrefs form ("VA  Metadata  (no function)  what") for the PE tables that name <paramref name="rva"/>.</summary>
    internal static List<string> MetadataRows(INativeImage image, uint rva)
    {
        var rows = new List<string>();
        if (image is not PeFile pe) return rows;
        string Va(uint r) => NativeAddress.Va(pe, r);
        void Row(uint at, string what) => rows.Add($"{Va(at)}  Metadata   (no function)  {what}");

        var dir = pe.Directory(PeDirectory.Exception);
        int entry = pe.Arch == NativeArch.X64 ? 12 : pe.Arch is NativeArch.Arm64 or NativeArch.Arm ? 8 : 0;
        if (entry > 0 && dir.Rva != 0 && dir.Size >= entry && dir.Size <= 64 << 20)
        {
            var bytes = new byte[dir.Size];
            int read = pe.Read(dir.Rva, bytes);
            for (int i = 0; i + entry <= read; i += entry)
            {
                if (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i)) == rva) Row(dir.Rva + (uint)i, ".pdata RUNTIME_FUNCTION begin");
                if (entry == 12 && BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i + 4)) == rva) Row(dir.Rva + (uint)i + 4, ".pdata RUNTIME_FUNCTION end");
            }
        }
        if (pe.LoadConfig is { } lc)
        {
            void Table(ulong va, IReadOnlyList<PeGuardEntry> entries, string name)
            {
                if (va < pe.ImageBase) return;
                uint start = (uint)(va - pe.ImageBase);
                for (int i = 0; i < entries.Count; i++)
                    if (entries[i].Rva == rva) Row(start + (uint)(i * lc.GuardTableStride), name);
            }
            Table(lc.GuardCfFunctionTable, lc.GuardCfFunctions, "Control Flow Guard function table");
            Table(lc.GuardLongJumpTargetTable, lc.GuardLongJumpTargets, "Control Flow Guard longjmp target table");
            Table(lc.GuardEhContinuationTable, lc.GuardEhContinuationTargets, "Control Flow Guard EH continuation table");
        }
        if (pe.ExportDirectory is { FunctionTableRva: not 0 } ed && ed.NumberOfFunctions <= 1 << 20)
        {
            var eat = new byte[ed.NumberOfFunctions * 4];
            int read = pe.Read(ed.FunctionTableRva, eat);
            for (int i = 0; i + 4 <= read; i += 4)
                if (BinaryPrimitives.ReadUInt32LittleEndian(eat.AsSpan(i)) == rva) Row(ed.FunctionTableRva + (uint)i, $"export address table (ordinal {ed.OrdinalBase + i / 4})");
        }
        return rows;
    }
}
