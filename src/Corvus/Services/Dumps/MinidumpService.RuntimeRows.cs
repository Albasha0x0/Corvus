using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Services;

public sealed partial class MinidumpService
{
    /// <summary>One <c>section</c> row per section written at run time, naming the bytes written and the bytes not captured; empty when there are none.</summary>
    internal static IReadOnlyList<ModuleChange> RuntimeSectionRows(RebuildTarget target, byte[] mapped, CapturedImage captured, PeFile file)
    {
        var rows = new List<ModuleChange>();
        foreach (var section in RuntimeSections.Find(mapped, captured, file))
        {
            var layout = file.Sections.First(s => s.Rva == section.Rva && s.Name == section.Name);
            long rawEnd = Math.Min(section.RawSize, layout.MappedSize);
            long extent = Math.Min(layout.MappedSize, mapped.Length - section.Rva) - rawEnd;
            string description = section.RawSize == 0
                ? $"no raw data in the file; {section.WrittenBytes} of {extent} bytes written at run time"
                : $"raw data ends at 0x{target.Base + section.Rva + (ulong)rawEnd:X}; {section.WrittenBytes} bytes past it written";
            if (section.UnknownBytes > 0) description += $"; {section.UnknownBytes} bytes not captured";
            rows.Add(new ModuleChange(target.Name, section.Name, $"0x{target.Base + section.Rva:X}", $"0x{section.Rva:X}", (int)Math.Min(extent + rawEnd, int.MaxValue),
                "section", null, description, null, null, null));
        }
        return rows;
    }
}
