using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Services;

public sealed partial class MinidumpService
{
    /// <summary>Text appended after a transfer target in a change description; empty when the target adds nothing.</summary>
    internal static string ChainText(IProcessMemory memory, ExportMap exports, ulong target, NativeArch machine) => "";
}
