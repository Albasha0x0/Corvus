namespace Corvus.Core.Python;

/// <summary>
/// The PyInstaller and Nuitka onefile executables a stream opens (a file too large to read whole); the built-in path in
/// <see cref="Containers.Open"/> reads every freezer, files beside the executable included.
/// </summary>
internal sealed class FrozenPythonReader : IContainerReader
{
    public string Kind => "frozen python";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => FrozenPython.LooksStreamable(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        FrozenPython.Open(data, name, null, allFiles, limits, ct) ?? Bootloader();

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        FrozenPython.Read(stream, name, allFiles, limits, ct)?.ToContainer(allFiles, limits, ct) ?? Bootloader();

    private static ContainerContents Bootloader() =>
        new("none", [], ["A PyInstaller or Nuitka launcher without its archive (no cookie or payload found): the archive was cut off or kept in a separate file."]);
}
