namespace Corvus.Native.Dump.Rebuild;

/// <summary>Rebuilds an ELF module from the segments a core file captured.</summary>
public static class ElfRebuild
{
    /// <summary>The rebuilt module; refused with the reason when the core lacks its headers.</summary>
    public static RebuiltModule FromCore(CoreFile core, RebuildTarget target, RebuildOptions options, CancellationToken ct) =>
        ModuleRebuild.Refuse(target, "ELF modules are not rebuilt from a core file");
}
