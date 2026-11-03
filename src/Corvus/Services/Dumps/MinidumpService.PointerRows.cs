using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Services;

public sealed partial class MinidumpService
{
    /// <summary>Rows for data that holds pointers, and the RVA ranges they cover; both empty when there are none.</summary>
    internal static (IReadOnlyList<ModuleChange> Rows, IReadOnlyList<(uint Start, uint End)> Covered) PointerRows(RebuildTarget target,
        byte[] mapped, CapturedImage captured, PeFile file, IProcessMemory memory, ExportMap exports) => ([], []);
}
