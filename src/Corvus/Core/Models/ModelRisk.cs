using System.IO.Compression;
using System.Text.Json;
using System.Text.RegularExpressions;
using Corvus.Core.Firmware;

namespace Corvus.Core.Models;

/// <summary>What a model file loads when opened: pickle globals, Keras layers, chat templates and ONNX data paths; read statically, nothing is unpickled or run.</summary>
public static class ModelRisk
{
    private const long MaxDecoded = 32L << 20;

    /// <summary>A model finding; Level is "noteworthy" or "review".</summary>
    public sealed record Hit(string Level, string Detail);

    /// <summary>Code-running globals, other globals outside the weights-only allowlist, other hits, and why a part was not read (null when all was).</summary>
    public sealed record Result(IReadOnlyList<string> Code, IReadOnlyList<string> Other, IReadOnlyList<Hit> Hits, string? NotRead);

    private static readonly string[] Extensions =
        [".pt", ".pth", ".pkl", ".pickle", ".ckpt", ".npy", ".npz", ".joblib", ".keras", ".h5", ".hdf5", ".gguf", ".onnx"];

    // Structural globals of numpy's and joblib's array records (numpy 2.x and joblib 1.x source).
    private static readonly HashSet<string> ArrayRecord = new(StringComparer.Ordinal)
    {
        "numpy.core.multiarray._reconstruct", "numpy._core.multiarray._reconstruct", "numpy.ndarray", "numpy.dtype",
        "numpy.core.multiarray.scalar", "numpy._core.multiarray.scalar", "joblib.numpy_pickle.NumpyArrayWrapper",
    };

    private static readonly Regex ObjectDtype = new(@"'[|<>=]?O\d*'", RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

    // Jinja attribute walks that reach the interpreter's classes, globals and builtins.
    private static readonly Regex AttributeWalk = new(@"__(?:class|globals|subclasses|mro|bases?|builtins|import|init|getattribute)__",
        RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

    /// <summary>True when the path has a model file extension.</summary>
    public static bool IsModelFile(string path) => Extensions.Any(e => path.EndsWith(e, StringComparison.OrdinalIgnoreCase));

    /// <summary>True for a pickle global that runs code or a command when loaded.</summary>
    public static bool RunsCode(string name) =>
        name is "builtins.exec" or "builtins.eval" or "builtins.compile" or "builtins.__import__"
            or "__builtin__.exec" or "__builtin__.eval" or "__builtin__.compile" or "__builtin__.__import__" or "os.system" or "os.popen"
        || name.StartsWith("os.exec", StringComparison.Ordinal) || name.StartsWith("os.spawn", StringComparison.Ordinal)
        || name.StartsWith("os.posix_spawn", StringComparison.Ordinal)
        || name.StartsWith("posix.", StringComparison.Ordinal) || name.StartsWith("nt.", StringComparison.Ordinal)
        || name.StartsWith("subprocess.", StringComparison.Ordinal) || name.StartsWith("runpy.", StringComparison.Ordinal)
        || name.StartsWith("importlib.", StringComparison.Ordinal);

    /// <summary>Reads one model file; a part that cannot be read is named in <see cref="Result.NotRead"/>, and a file of no model format gives an empty result.</summary>
    public static Result Scan(string path, byte[] bytes, CancellationToken ct = default)
    {
        var f = new Found();
        Walk(path, bytes, f, 0, ct);
        return new Result([.. f.Imports.Distinct(StringComparer.Ordinal).Where(RunsCode)],
            [.. f.Outside.Distinct(StringComparer.Ordinal).Where(n => !RunsCode(n) && !ArrayRecord.Contains(n))], f.Hits, f.NotRead.Count == 0 ? null : string.Join("; ", f.NotRead));
    }

    private static void Walk(string path, byte[] b, Found f, int depth, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            if (b.AsSpan().StartsWith("PK\x03\x04"u8)) Zip(path, b, f, depth, ct);
            else if (b.AsSpan().StartsWith((ReadOnlySpan<byte>)[0x93, 0x4E, 0x55, 0x4D, 0x50, 0x59])) Npy(b, f, ct);
            else if (b.AsSpan().StartsWith((ReadOnlySpan<byte>)[0x89, 0x48, 0x44, 0x46, 0x0D, 0x0A, 0x1A, 0x0A])) f.NotRead.Add("HDF5 not read");
            else if (Gguf.Looks(b)) Template(b, f, ct);
            else if (OnnxModel.Looks(b) && path.EndsWith(".onnx", StringComparison.OrdinalIgnoreCase)) DataPaths(b, f, ct);
            else if (Codec(b) is { } codec) Compressed(path, b, codec, f, depth, ct);
            else if (TorchCheckpoint.IsLegacy(b)) Add(TorchCheckpoint.ReadLegacy(new MemoryStream(b, writable: false), b.Length, ct).Pickle, f);
            else if (PickleScan.Looks(b) || PickleScan.LooksUnversioned(b))
                Add(PickleScan.Read(new MemoryStream(b, writable: false), b.Length, ct), f);
        }
        catch (Exception ex) when (ex is InvalidDataException or EndOfStreamException or JsonException)
        {
            f.NotRead.Add(ex.Message);
        }
    }

    private sealed class Found
    {
        public readonly List<string> Imports = [], Outside = [], NotRead = [];
        public readonly List<Hit> Hits = [];
    }

    private static void Add(PickleScan scan, Found f)
    {
        f.Imports.AddRange(scan.Imports.Select(i => i.Name));
        f.Outside.AddRange(scan.OutsideWeightsOnly);
    }

    private static string? Codec(byte[] b) =>
        b.AsSpan().StartsWith((ReadOnlySpan<byte>)[0x1F, 0x8B]) ? "gzip"
        : b.AsSpan().StartsWith((ReadOnlySpan<byte>)[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) ? "xz"
        : b.AsSpan().StartsWith((ReadOnlySpan<byte>)[0x04, 0x22, 0x4D, 0x18]) ? "lz4"
        : b.AsSpan().StartsWith("BZh"u8) ? "bzip2"
        : b.Length >= 2 && b[0] == 0x78 && (b[0] * 256 + b[1]) % 31 == 0 ? "zlib" : null;

    // A joblib file compressed whole; its pickle is read after one layer is removed.
    private static void Compressed(string path, byte[] b, string codec, Found f, int depth, CancellationToken ct)
    {
        if (depth > 0) { f.NotRead.Add($"{codec} data inside {codec} data not read"); return; }
        Walk(path, FsCodec.DecodeStream(codec, b, MaxDecoded), f, depth + 1, ct);
    }

    private static void Zip(string path, byte[] b, Found f, int depth, CancellationToken ct)
    {
        using var zip = new ZipArchive(new MemoryStream(b, writable: false), ZipArchiveMode.Read);
        if (TorchCheckpoint.IsZip(f => zip.Entries.Any(e => f(e.FullName))))
        {
            Add(TorchCheckpoint.ReadZip(new MemoryStream(b, writable: false), ct, MaxDecoded).Pickle, f);
            return;
        }
        if (zip.GetEntry("config.json") is { } config && path.EndsWith(".keras", StringComparison.OrdinalIgnoreCase))
        {
            if (config.Length > MaxDecoded) throw new InvalidDataException($"config.json is {config.Length:N0} bytes, over the {MaxDecoded:N0} byte limit");
            using var s = config.Open();
            using var doc = JsonDocument.Parse(s);
            Layers(doc.RootElement, f);
            return;
        }
        if (depth > 0) return;
        foreach (var e in zip.Entries.Where(e => e.FullName.EndsWith(".npy", StringComparison.OrdinalIgnoreCase)).Take(1024))
        {
            if (e.Length > MaxDecoded) { f.NotRead.Add($"{e.FullName} over {MaxDecoded >> 20} MiB not read"); continue; }
            var bytes = new byte[e.Length];
            using (var s = e.Open()) s.ReadExactly(bytes);
            Walk(e.FullName, bytes, f, depth + 1, ct);
        }
    }

    // An .npy header, then the array data; an object array stores its elements as a pickle.
    private static void Npy(byte[] b, Found f, CancellationToken ct)
    {
        if (b.Length < 10) throw new InvalidDataException("the .npy header is cut short");
        int major = b[6];
        int lengthSize = major == 1 ? 2 : 4;
        if (major is < 1 or > 3 || b.Length < 8 + lengthSize) throw new InvalidDataException($".npy version {major}");
        long headerLength = lengthSize == 2 ? BitConverter.ToUInt16(b, 8) : BitConverter.ToUInt32(b, 8);
        long start = 8 + lengthSize;
        if (start + headerLength > b.Length) throw new InvalidDataException("the .npy header runs past the end");
        var header = System.Text.Encoding.Latin1.GetString(b, (int)start, (int)headerLength);
        if (!ObjectDtype.IsMatch(header)) return;
        f.Hits.Add(new Hit("review", "an .npy object array, stored as a pickle that numpy.load reads only with allow_pickle=True"));
        var data = new MemoryStream(b, writable: false) { Position = start + headerLength };
        Add(PickleScan.Read(data, b.Length, ct), f);
    }

    // Keras 3 config.json: layers are objects with class_name, module and registered_name.
    private static void Layers(JsonElement e, Found f)
    {
        if (e.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in e.EnumerateArray()) Layers(item, f);
            return;
        }
        if (e.ValueKind != JsonValueKind.Object) return;
        string? Text(string key) => e.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        var cls = Text("class_name");
        var module = Text("module");
        if (cls == "Lambda" || Text("function_type") == "lambda")
            f.Hits.Add(new Hit("noteworthy", $"a Keras {cls ?? "function"} layer carries Python code that runs when the model loads with safe_mode off"));
        else if (cls != null && module != null && !module.StartsWith("keras", StringComparison.Ordinal) && !module.StartsWith("tf_keras", StringComparison.Ordinal))
            f.Hits.Add(new Hit("review", $"a Keras layer {cls} from module {module} is custom code the loader imports"));
        foreach (var p in e.EnumerateObject()) Layers(p.Value, f);
    }

    private static void Template(byte[] b, Found f, CancellationToken ct)
    {
        var g = Gguf.Read(new MemoryStream(b, writable: false), b.Length, ct);
        if (g.ChatTemplate is null && g.Metadata.Any(e => e.Key == "tokenizer.chat_template"))
            f.NotRead.Add("the chat_template over 1 MiB not read");
        if (g.ChatTemplate is { } t && AttributeWalk.Match(t) is { Success: true } m)
            f.Hits.Add(new Hit("noteworthy", $"the chat_template reaches {m.Value}, an attribute walk out of the template sandbox"));
    }

    private static void DataPaths(byte[] b, Found f, CancellationToken ct)
    {
        var m = OnnxModel.Read(new MemoryStream(b, writable: false), b.Length, ct);
        var outside = m.Initializers.Select(i => i.Location).OfType<string>().Distinct(StringComparer.Ordinal).Where(Leaves).Take(5);
        foreach (var location in outside) f.Hits.Add(new Hit("noteworthy", $"the ONNX external data path {location} leaves the model's folder"));
    }

    private static bool Leaves(string location)
    {
        var normal = location.Replace('\\', '/');
        return normal.StartsWith('/') || Path.IsPathRooted(location) || (normal.Length > 1 && normal[1] == ':') || normal.Split('/').Contains("..");
    }
}
