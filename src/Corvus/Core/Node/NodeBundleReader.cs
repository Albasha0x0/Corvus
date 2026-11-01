namespace Corvus.Core.Node;

/// <summary>Node SEA, pkg, nexe, Bun and Deno executables, listed and extracted by <c>unpack_container</c>.</summary>
internal sealed class NodeBundleReader : IContainerReader
{
    public string Kind => "node bundle";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => NodeBundle.Accepts(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        NodeBundle.Open(data, limits, ct);
}
