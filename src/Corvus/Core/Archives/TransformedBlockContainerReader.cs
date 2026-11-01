using System.Buffers.Binary;

namespace Corvus.Core.Archives;

/// <summary>
/// A file of 0xFFFFFFFF, a u32 payload length, then the payload in 8-byte
/// transformed blocks; listed as one entry with its blocks and entropy.
/// </summary>
internal sealed class TransformedBlockContainerReader : IContainerReader
{
    private const uint Marker = 0xFFFFFFFF;

    private const int HeaderSize = 8;

    private const int BlockSize = 8;

    private static readonly string[] Extensions = [".luae", ".jsone", ".pbe"];

    public string Kind => "transformed block container";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => HasExtension(name) && Layout(data) is not null;

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var (declared, available) = Layout(data) ?? throw new ToolError($"{name}: not a transformed block container.");
        var notes = new List<string>();
        var entries = new List<ContainerEntry>();
        var items = new List<ExtractedItem>();
        long blocks = available / BlockSize;
        bool partial = available < declared;
        bool overLimit = available > limits.MaxItemBytes;
        var payload = data.AsSpan(HeaderSize, checked((int)Math.Min(available, data.Length - HeaderSize)));
        string detail = $"offset 0x{HeaderSize:X}, {blocks:N0} blocks, entropy {Blob.Entropy(payload):F2}";
        if (partial)
        {
            entries.Add(new ContainerEntry("payload", declared, EntryDamage.Detail("runs past the end of the file", HeaderSize)));
            notes.Add($"payload: unknown contents, only {available:N0} of {declared:N0} bytes are in the file.");
        }
        else entries.Add(new ContainerEntry("payload", declared, detail));
        if (overLimit)
            notes.Add($"Stopped: {available:N0} bytes are over the item limit of {limits.MaxItemBytes:N0}; set {AnalysisLimits.RaiseVariable} above {limits.MaxItemBytes / (1024 * 1024):N0} (MB) to extract them.");
        else if (available > 0)
        {
            items.Add(new ExtractedItem("payload", payload.ToArray(), partial ? "transformed blocks, partial" : "transformed blocks") { Member = true });
            // Open receives no path, so the note cannot name one.
            notes.Add($"unpack_container on this file writes the {(partial ? "present " : "transformed ")}payload ({available:N0} bytes).");
        }
        notes.Insert(0, $"{blocks:N0} blocks of {BlockSize} bytes are transformed; the decoded content is unknown without the block transform.");
        long trailing = data.Length - HeaderSize - available;
        if (trailing > 0) notes.Add($"{trailing:N0} bytes after the payload belong to no entry.");
        return new ContainerContents(Kind, items, notes) { Entries = entries };
    }

    private static bool HasExtension(string name) => Extensions.Any(e => name.EndsWith(e, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// The declared payload length and the bytes of it present; null when the
    /// marker is wrong or the length is zero or not a whole number of blocks.
    /// The bytes present never exceed the file length.
    /// </summary>
    private static (long Declared, long Available)? Layout(ReadOnlySpan<byte> data)
    {
        if (data.Length < HeaderSize) return null;
        if (BinaryPrimitives.ReadUInt32LittleEndian(data) != Marker) return null;
        uint declared = BinaryPrimitives.ReadUInt32LittleEndian(data[4..]);
        if (declared == 0 || declared % BlockSize != 0) return null;
        long available = Math.Min(declared, (data.Length - HeaderSize) / BlockSize * BlockSize);
        return (declared, available);
    }
}
