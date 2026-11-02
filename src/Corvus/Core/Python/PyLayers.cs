using System.Text;

namespace Corvus.Core.Python;

/// <summary>A code object carried as an encoded constant of another: where it sits, the encodings peeled and the size of the decoded data.</summary>
public sealed record PyLayer(int Depth, string Location, string Encodings, string Filename, int Size, PyCode Code, (int, int) Version)
{
    /// <summary>The layer as a .pyc with its header restored; built on each call.</summary>
    public byte[] ToPyc() =>
        PyVersion.WithHeader(PyVersion.MagicOf(Version) ?? [0, 0, (byte)'\r', (byte)'\n'], Version, PyMarshalWriter.Write(Code, Version));
}

/// <summary>Finds code objects stored as bytes or text constants (marshal, zlib, base64 and combinations) in a module's code and peels them layer by layer.</summary>
public static class PyLayers
{
    private const int MaxLayers = 64, MaxDepth = 16, MaxChain = 8, MinConstant = 24, MaxVisits = 100_000, MaxNesting = 256;

    /// <summary>The layers of <paramref name="root"/>, outer before inner; empty when no constant decodes to code. Decoded data of all layers together stays within <paramref name="maxBytes"/>.</summary>
    public static List<PyLayer> Find(PyCode root, (int, int) version, long maxBytes, CancellationToken ct)
    {
        var found = new List<PyLayer>();
        var budget = new Budget { Remaining = maxBytes };
        Scan(root, version, 1, 0, "", maxBytes, found, budget, ct);
        return found;
    }

    private sealed class Budget { public long Remaining; public int Visits; }

    private static void Scan(PyCode code, (int, int) version, int depth, int nesting, string path, long maxBytes, List<PyLayer> found, Budget budget, CancellationToken ct)
    {
        if (depth > MaxDepth || nesting > MaxNesting || found.Count >= MaxLayers) return;
        string here = path.Length == 0 ? code.QualName : path;
        for (int i = 0; i < code.Consts.Length; i++)
        {
            if (++budget.Visits > MaxVisits) return;
            if ((budget.Visits & 0xFF) == 0) ct.ThrowIfCancellationRequested();
            switch (code.Consts[i])
            {
                case PyCode nested:
                    Scan(nested, version, depth, nesting + 1, nested.QualName.Length > 0 ? nested.QualName : here, maxBytes, found, budget, ct);
                    break;
                case PyBytes or string when Peel(code.Consts[i], version, Math.Min(maxBytes, budget.Remaining)) is var (inner, encodings, size):
                    if (found.Count >= MaxLayers) return;
                    budget.Remaining -= size;
                    found.Add(new PyLayer(depth, $"{here}, constant {i}", encodings, inner.Filename, size, inner, version));
                    Scan(inner, version, depth + 1, nesting + 1, "", maxBytes, found, budget, ct);
                    break;
            }
        }
    }

    private static (PyCode Code, string Encodings, int Size)? Peel(object constant, (int, int) version, long maxBytes)
    {
        byte[] data = constant switch { PyBytes b => b.Value, string s => Encoding.Latin1.GetBytes(s), _ => [] };
        if (data.Length < MinConstant) return null;
        var chain = new List<string>();
        for (int step = 0; step <= MaxChain; step++)
        {
            // A header-less code object or a whole .pyc ends the chain.
            if (data[0] == 'c' || data[0] == 0xE3)
            {
                if (PyMarshal.TryRead(data, version, out _) is PyCode raw) return (raw, string.Join(" > ", chain.Append("marshal")), data.Length);
            }
            else if (PyVersion.LooksLikePyc(data) && PyVersion.FromMagic(data) is { } v
                && PyMarshal.TryRead(data, v, out _, PyVersion.HeaderLength(v)) is PyCode whole)
                return (whole, string.Join(" > ", chain.Append("pyc")), data.Length);
            if (data.Length >= 2 && data[0] == 0x78 && Blob.TryDecompress(data, "zlib", maxBytes) is { Length: > 0 } inflated)
            {
                chain.Add("zlib");
                data = inflated;
            }
            else if (Base64(data) is { } decoded)
            {
                chain.Add("base64");
                data = decoded;
            }
            else return null;
            if (data.Length < 4) return null;
        }
        return null;
    }

    private static byte[]? Base64(byte[] text)
    {
        foreach (var c in text)
            if (!(c is >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z' or >= (byte)'0' and <= (byte)'9' or (byte)'+' or (byte)'/' or (byte)'=' or (byte)'\n' or (byte)'\r'))
                return null;
        try { return Convert.FromBase64String(Encoding.ASCII.GetString(text)); }
        catch (FormatException) { return null; }
    }

    /// <summary>A .pyc as a container: each layer as an item, "none" when it holds none.</summary>
    internal static ContainerContents Open(byte[] data, CancellationToken ct)
    {
        // An unknown magic is unknown input, not a layerless module.
        if (PyVersion.FromMagic(data) is not { } version)
            return new ContainerContents("none", [], ["Not a compiled Python module: the magic number names no known version."]);
        var label = PyVersion.Label(version);
        if (PyMarshal.TryRead(data, version, out _, PyVersion.HeaderLength(version)) is PyCode code
            && Find(code, version, AnalysisLimits.Default.MaxItemBytes, ct) is { Count: > 0 } layers)
        {
            var items = layers.Select((l, i) => new ExtractedItem($"layer{i + 1}.pyc", l.ToPyc(), $"{l.Encodings} in {l.Location}")).ToList();
            return new ContainerContents("Python bytecode", items, [$"A compiled Python module (.pyc, Python {label}) holding {layers.Count:N0} encoded layers."]);
        }
        return new ContainerContents("none", [], [$"A compiled Python module (.pyc, Python {label}): code, not a container."]);
    }
}
