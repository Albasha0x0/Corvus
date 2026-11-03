namespace Corvus.Native.Dump;

/// <summary>Reads the process environment block of a dumped Windows process.</summary>
public static class ProcessEnvironment
{
    // Offsets of the documented TEB and PEB layouts, by pointer width.
    private const ulong Teb64Peb = 0x60, Teb32Peb = 0x30, Peb64ApiSetMap = 0x68, Peb32ApiSetMap = 0x38;

    /// <summary>
    /// The address of the API set map the PEB points to, found through the TEB of a thread of the dump.
    /// Returns null with <paramref name="reason"/> when the process is not a Windows minidump or no thread TEB, PEB or pointer was captured.
    /// </summary>
    public static ulong? ApiSetMapAddress(IProcessMemory memory, out string? reason)
    {
        reason = null;
        if (memory is not MinidumpFile dump)
        {
            reason = "only a Windows minidump has a process environment block";
            return null;
        }
        bool wide = memory.Is64Bit;
        ulong pebAt = wide ? Teb64Peb : Teb32Peb, mapAt = wide ? Peb64ApiSetMap : Peb32ApiSetMap;
        var tebs = dump.Threads.Select(t => t.Teb).Where(t => t != 0).Distinct().ToList();
        if (tebs.Count == 0)
        {
            reason = "no thread records a TEB address";
            return null;
        }
        foreach (ulong teb in tebs)
        {
            if (!memory.TryReadPointer(teb + pebAt, out ulong peb) || peb == 0) continue;
            if (!memory.TryReadPointer(peb + mapAt, out ulong map) || map == 0) continue;
            return map;
        }
        reason = "the dump holds no TEB page with a PEB pointer, or no PEB page with an API set map pointer";
        return null;
    }
}
