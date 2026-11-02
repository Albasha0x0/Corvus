using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Reopens a rebuilt PE file with the PE and metadata readers.</summary>
public static class PeVerify
{
    /// <summary>Adds the parse check; the managed metadata state of a .NET image, else null.</summary>
    public static ManagedMetadataState? Check(byte[] bytes, RebuildTarget target, List<RebuildCheck> checks)
    {
        try
        {
            var pe = PeFile.FromBytes(bytes, target.Name);
            checks.Add(RebuildCheck.Ok("parse", $"{pe.Sections.Count} sections read back"));
            return DumpManagedMetadata.Inspect(pe);
        }
        catch (ToolError e)
        {
            checks.Add(RebuildCheck.Failed("parse", e.Message));
            return null;
        }
    }
}
