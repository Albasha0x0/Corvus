namespace Corvus.Native.Pe;

/// <summary>Short text forms of PE facts shared by tools and file views.</summary>
public static class PeDescribe
{
    /// <summary>Mitigation names split into those the image enables and those it does not.</summary>
    public static (List<string> On, List<string> Off) Mitigations(PeFile pe)
    {
        var m = pe.Mitigations;
        var on = new List<string>();
        var off = new List<string>();
        void M(string name, bool value) => (value ? on : off).Add(name);
        M("ASLR", m.Aslr); M("high-entropy VA", m.HighEntropyVa); M("DEP", m.Dep); M("CFG", m.ControlFlowGuard);
        // SafeSEH is an x86 table; 64-bit images unwind through the exception directory.
        if (!pe.Is64Bit) M("SafeSEH", m.SafeSeh);
        M("GS cookie", m.GsCookie); M("CET", m.CetCompatible); M("XFG", m.Xfg); M("EH continuation", m.EhContinuation); M("force integrity", m.ForceIntegrity);
        if (!m.GsCookie && pe.CodeSecurityCookieRva != null)
        {
            off.Remove("GS cookie");
            on.Add(pe.LoadConfig == null ? "GS cookie (used by code, load config absent)" : "GS cookie (used by code, load config names none)");
        }
        return (on, off);
    }

    /// <summary>Section access as three characters, such as r-x.</summary>
    public static string Access(SectionAccess a) =>
        $"{((a & SectionAccess.Read) != 0 ? 'r' : '-')}{((a & SectionAccess.Write) != 0 ? 'w' : '-')}{((a & SectionAccess.Execute) != 0 ? 'x' : '-')}";
}
