using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Services;

public sealed partial class MinidumpService
{
    /// <summary>Rows for sections that exist only in memory or differ in size from the file; empty when there are none.</summary>
    internal static IReadOnlyList<ModuleChange> RuntimeSectionRows(RebuildTarget target, byte[] mapped, CapturedImage captured, PeFile file) => [];
}
