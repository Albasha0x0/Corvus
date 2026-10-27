namespace Corvus.Core.Python;

/// <summary>PyInstaller and Nuitka onefile executables opened as streams, for files too large to read whole; <see cref="Containers.Open"/> reads every freezer.</summary>
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
