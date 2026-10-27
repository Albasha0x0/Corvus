using System.Globalization;
using System.Numerics;
using Corvus.Core;
using Corvus.Core.Models;

namespace Corvus.Services.Analysis;

/// <summary>view=model: a safetensors, GGUF, ONNX, PyTorch or pickle file's metadata, tensors (offset=, limit=) and parameter count; nothing is unpickled or run.</summary>
// ONNX adds graph inputs, outputs and operators; a pickle adds its imports and calls, checked against
// torch.load(weights_only=True).
internal sealed class ModelFileView : IFileSummaryView
{
    private const int DefaultLimit = 50, MaxLimit = 1000, MaxMetadata = 200;

    public sealed record MetadataRow(string Key, string Value, string? Type, long? Count);

    /// <summary>Offset is absolute in the file (in the external file for ONNX); Location names a PyTorch storage or an ONNX external file.</summary>
    public sealed record TensorRow(string Name, string Type, string Shape, long? Offset, long? Size, string? Location);

    public sealed record OnnxFacts(long IrVersion, string? Producer, string? Domain, long ModelVersion, string? DocString,
        IReadOnlyList<string> Opsets, string? Graph, IReadOnlyList<OnnxModel.Value> Inputs, IReadOnlyList<OnnxModel.Value> Outputs, int Nodes,
        IReadOnlyDictionary<string, int> Operators, int Subgraphs, int SubgraphNodes, IReadOnlyList<string> Functions, int SparseInitializers,
        IReadOnlyList<string> ExternalFiles, bool TrainingInfo);

    /// <summary><see cref="OutsideWeightsOnly"/> and <see cref="OpcodesOutsideWeightsOnly"/> are what torch.load(weights_only=True) refuses.</summary>
    public sealed record PickleFacts(string? Container, int Protocol, long Opcodes, bool Complete, IReadOnlyList<PickleScan.Import> Imports,
        IReadOnlyDictionary<string, int> Calls, int PersistentIds, IReadOnlyList<string> OutsideWeightsOnly,
        IReadOnlyList<string> OpcodesOutsideWeightsOnly, string? Version, string? ByteOrder);

    public sealed record Facts(string Format, int Tensors, string Parameters, IReadOnlyDictionary<string, int> TensorTypes,
        IReadOnlyList<MetadataRow> Metadata, int MetadataCount, IReadOnlyList<TensorRow> TensorPage, long Offset, long? Next,
        OnnxFacts? Onnx, PickleFacts? Pickle, IReadOnlyList<string> Issues);

    public string Name => "model";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        var head = file.Head;
        var issues = new List<string>();
        var metadata = new List<MetadataRow>();
        var tensors = new List<TensorRow>();
        BigInteger parameters = 0;
        OnnxFacts? onnx = null;
        PickleFacts? pickle = null;
        string format = "", line;
        using var s = file.OpenRead();
        try
        {
            if (Gguf.Looks(head))
            {
                var g = Gguf.Read(s, file.Length, ct);
                format = $"gguf v{g.Version}" + (g.BigEndian ? " (big-endian)" : "");
                metadata.AddRange(g.Metadata.Select(m => new MetadataRow(m.Key, m.Value, m.Type, m.Count)));
                foreach (var t in g.Tensors)
                {
                    tensors.Add(new TensorRow(t.Name, t.Type, "[" + string.Join(", ", t.Shape) + "]", t.Offset, t.Size, null));
                    parameters += t.Shape.Aggregate(BigInteger.One, (a, d) => a * d);
                }
                issues.AddRange(g.Issues);
                string? Meta(string key) => g.Metadata.FirstOrDefault(m => m.Key == key)?.Value;
                line = $"GGUF v{g.Version} model" + (Meta("general.architecture") is { } arch ? $" ({arch}" + (Meta("general.name") is { } n ? $", {n})" : ")") : "");
            }
            else if (Safetensors.Looks(head, file.Length))
            {
                var st = Safetensors.Read(s, file.Length);
                format = "safetensors";
                metadata.AddRange(st.Metadata.Select(m => new MetadataRow(m.Key, m.Value, null, null)));
                foreach (var t in st.Tensors)
                {
                    tensors.Add(new TensorRow(t.Name, t.Dtype, "[" + string.Join(", ", t.Shape) + "]", 8 + st.HeaderSize + t.Begin, t.End - t.Begin, null));
                    parameters += Safetensors.Elements(t.Shape);
                }
                issues.AddRange(st.Issues);
                line = "safetensors file" + (st.Metadata.TryGetValue("format", out var f) ? $" (format {f})" : "");
            }
            else if (file.Kind == "zip" && TorchCheckpoint.IsZip(file.HasZipEntry))
            {
                var c = TorchCheckpoint.ReadZip(s, ct);
                (format, line) = ("pytorch zip", "PyTorch checkpoint (zip)");
                pickle = Pickle(c.Pickle, c.Prefix, c.Version, c.ByteOrder, tensors, ref parameters);
                issues.AddRange(c.Pickle.Issues);
                issues.AddRange(c.Issues);
            }
            else if (TorchCheckpoint.IsLegacy(head))
            {
                var c = TorchCheckpoint.ReadLegacy(s, file.Length, ct);
                (format, line) = ("pytorch legacy", "PyTorch checkpoint (legacy format)");
                pickle = Pickle(c.Pickle, null, null, null, tensors, ref parameters);
                issues.AddRange(c.Pickle.Issues);
            }
            else if (PickleScan.Looks(head))
            {
                format = "pickle";
                var p = PickleScan.Read(s, file.Length, ct);
                if (p.Opcodes < 3 || (!p.Complete && p.Imports.Count == 0)) return null;
                line = $"Python pickle (protocol {p.Protocol})";
                pickle = Pickle(p, null, null, null, tensors, ref parameters);
                issues.AddRange(p.Issues);
                if (p.Complete && p.End < file.Length) issues.Add($"{file.Length - p.End:N0} bytes follow the pickle's STOP");
            }
            else if (OnnxModel.Looks(head))
            {
                format = "onnx";
                var m = OnnxModel.Read(s, file.Length, ct);
                metadata.AddRange(m.Metadata.Select(x => new MetadataRow(x.Key, x.Value, null, null)));
                foreach (var i in m.Initializers)
                {
                    tensors.Add(new TensorRow(i.Name, i.DataType, "[" + string.Join(", ", i.Dims) + "]", i.Offset, i.Length, i.Location));
                    parameters += i.Dims.Aggregate(BigInteger.One, (a, d) => a * d);
                }
                issues.AddRange(m.Issues);
                onnx = new OnnxFacts(m.IrVersion, Join(m.ProducerName, m.ProducerVersion), m.Domain, m.ModelVersion, m.DocString,
                    [.. m.Opsets.Select(o => $"{(o.Domain.Length == 0 ? "ai.onnx" : o.Domain)} {o.Version}")], m.GraphName, m.Inputs, m.Outputs, m.Nodes,
                    m.Operators, m.Subgraphs, m.SubgraphNodes, m.Functions, m.SparseInitializers,
                    [.. m.Initializers.Select(i => i.Location).OfType<string>().Distinct(StringComparer.Ordinal)], m.HasTrainingInfo);
                line = $"ONNX model (IR {m.IrVersion}" + (onnx.Producer is { } pr ? $", {pr}" : "") + $", {string.Join(", ", onnx.Opsets)}): " +
                       $"{m.Nodes:N0} nodes, {m.Operators.Count} operator types, {m.Inputs.Count} input(s), {m.Outputs.Count} output(s)";
            }
            else return null;
        }
        // The pickle and ONNX checks are loose; a file that only resembles one is not this view's.
        catch (InvalidDataException) when (format is "pickle" or "onnx")
        {
            return null;
        }

        int limit = Math.Clamp(file.Options.Limit ?? DefaultLimit, 1, MaxLimit);
        long offset = Math.Max(0, file.Options.Offset);
        var page = tensors.Skip((int)Math.Min(offset, int.MaxValue)).Take(limit).ToList();
        long shown = offset + page.Count;
        long? next = shown < tensors.Count ? shown : null;
        var types = tensors.GroupBy(t => t.Type).OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.Count());
        if (next != null) issues.Add($"offset={next} lists the next tensors");
        if (metadata.Count > MaxMetadata) issues.Add($"the first {MaxMetadata} of {metadata.Count:N0} metadata entries are shown");
        var count = tensors.Count > 0 ? $": {tensors.Count:N0} tensor(s), {Count(parameters)} parameters" + (types.Count > 0 ? $" ({string.Join(", ", types.Take(4).Select(t => $"{t.Key} {t.Value}"))})" : "") : "";
        if (onnx == null) line += count;
        if (pickle != null)
            line += (pickle.OutsideWeightsOnly.Count + pickle.OpcodesOutsideWeightsOnly.Count == 0
                ? $"; {pickle.Imports.Count} import(s), all in torch.load(weights_only=True)'s allowlist"
                : $"; {pickle.Imports.Count} import(s)" + (pickle.OutsideWeightsOnly.Count > 0 ? $", outside torch.load(weights_only=True)'s allowlist: {string.Join(", ", pickle.OutsideWeightsOnly.Take(6))}" : "") +
                  (pickle.OpcodesOutsideWeightsOnly.Count > 0 ? $"; opcodes weights_only does not read: {string.Join(", ", pickle.OpcodesOutsideWeightsOnly)}" : ""));
        if (issues.Count > 0 && !issues[0].StartsWith("offset=", StringComparison.Ordinal)) line += $"; {issues.Count} issue(s), first: {issues[0]}";
        return new FileView(new Facts(format, tensors.Count, parameters.ToString(CultureInfo.InvariantCulture), types, metadata.Take(MaxMetadata).ToList(),
            metadata.Count, page, offset, next, onnx, pickle, issues), [line + "."]);
    }

    private static PickleFacts Pickle(PickleScan p, string? container, string? version, string? byteOrder, List<TensorRow> tensors, ref BigInteger parameters)
    {
        foreach (var t in p.TorchTensors(int.MaxValue))
        {
            tensors.Add(new TensorRow(t.Name, t.Dtype, "[" + string.Join(", ", t.Shape) + "]", null, null,
                $"data/{t.StorageKey}" + (t.Location is { } l ? $" ({l})" : "") + (t.StorageOffset > 0 ? $" from element {t.StorageOffset:N0}" : "")));
            parameters += t.Shape.Aggregate(BigInteger.One, (a, d) => a * d);
        }
        return new PickleFacts(container, p.Protocol, p.Opcodes, p.Complete, p.Imports, p.Calls, p.PersistentIds, [.. p.OutsideWeightsOnly],
            [.. p.OpcodesOutsideWeightsOnly], version, byteOrder);
    }

    private static string? Join(string? a, string? b) => a is { Length: > 0 } ? b is { Length: > 0 } ? $"{a} {b}" : a : null;

    private static string Count(BigInteger n) => n >= 1_000_000_000 ? $"{(double)n / 1e9:0.##}B" : n >= 1_000_000 ? $"{(double)n / 1e6:0.##}M" : n.ToString("N0", CultureInfo.InvariantCulture);
}
