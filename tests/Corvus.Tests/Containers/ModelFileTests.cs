using System.Diagnostics;
using System.Globalization;
using System.Text;
using Corvus.Core;
using Corvus.Core.Models;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Model files: safetensors and GGUF headers, ONNX graphs, PyTorch checkpoints and pickles, read without running them.</summary>
public sealed class ModelFileTests
{
    private const string ModelPython = "CORVUS_MODEL_PYTHON";
    private const string ModelFiles = "CORVUS_MODEL_FILES";

    private static Safetensors ReadSafetensors(byte[] b) => Safetensors.Read(new MemoryStream(b), b.Length);

    [Fact]
    public void Safetensors_header_lists_tensors_in_data_order_with_metadata()
    {
        var b = ModelSamples.Safetensors("""{"b":{"dtype":"F16","shape":[2],"data_offsets":[24,28]},"__metadata__":{"format":"pt"},"a":{"dtype":"F32","shape":[2,3],"data_offsets":[0,24]}}""", 28);
        var st = ReadSafetensors(b);
        Assert.Empty(st.Issues);
        Assert.Equal(["a F32 [2,3] 0-24", "b F16 [2] 24-28"], st.Tensors.Select(t => $"{t.Name} {t.Dtype} [{string.Join(",", t.Shape)}] {t.Begin}-{t.End}"));
        Assert.Equal("pt", st.Metadata["format"]);
        Assert.Equal("safetensors", Blob.Identify(b));
    }

    [Fact]
    public void Safetensors_gaps_sizes_and_trailing_data_are_named()
    {
        var b = ModelSamples.Safetensors("""{"a":{"dtype":"F32","shape":[2],"data_offsets":[0,8]},"b":{"dtype":"I64","shape":[1],"data_offsets":[12,16]},"c":{"dtype":"X9","shape":[1],"data_offsets":[16,17]}}""", 20);
        Assert.Equal(["b: starts at 12, after a gap from 8", "b: 4 bytes for 1 I64 elements", "c: unknown dtype X9", "3 bytes after the last tensor"], ReadSafetensors(b).Issues);
        Assert.Throws<InvalidDataException>(() => ReadSafetensors(ModelSamples.Safetensors("[1]", 0)));
    }

    private static byte[] GgufSample() => ModelSamples.Gguf(w =>
    {
        w.Key("general.architecture", 8); w.String("llama");
        w.Key("general.alignment", 4); w.U32(64);
        w.Key("tokens", 9); w.U32(8); w.U64(10); for (int i = 0; i < 10; i++) w.String($"t{i}");
        w.Key("eps", 6); w.U32(BitConverter.SingleToUInt32Bits(0.5f));
    }, 4, [("w", 0, [4, 2], 0), ("q", 8, [64], 64)], alignment: 64, dataBytes: 64 + 68);

    // Regression: a header name with a byte that is not UTF-8 made JsonDocument
    // throw InvalidOperationException when the name was read.
    [Fact]
    public void A_safetensors_header_that_is_not_UTF8_is_invalid_data()
    {
        var b = ModelSamples.Safetensors("""{"a":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}""", 8);
        b[8 + 2] = 0xD1;
        Assert.Contains("not UTF-8", Assert.Throws<InvalidDataException>(() => ReadSafetensors(b)).Message);
    }

    [Fact]
    public void Gguf_header_reads_metadata_and_places_tensors_after_the_alignment()
    {
        var b = GgufSample();
        var g = Gguf.Read(new MemoryStream(b), b.Length);
        Assert.Empty(g.Issues);
        Assert.Equal((3u, 64u), (g.Version, g.Alignment));
        Assert.Equal("array[string] 10 [\"t0\", \"t1\", \"t2\", \"t3\", \"t4\", \"t5\", \"t6\", \"t7\", ...]", $"{g.Metadata[2].Type} {g.Metadata[2].Count} {g.Metadata[2].Value}");
        Assert.Equal("0.5", g.Metadata[3].Value);
        Assert.Equal([$"w F32 4x2 {g.DataOffset} 32", $"q Q8_0 64 {g.DataOffset + 64} 68"],
            g.Tensors.Select(t => $"{t.Name} {t.Type} {string.Join("x", t.Shape)} {t.Offset} {t.Size}"));
        Assert.Equal(0, g.DataOffset % 64);
    }

    [Fact]
    public void Gguf_tensors_past_the_end_and_unknown_types_are_named()
    {
        var b = ModelSamples.Gguf(_ => { }, 0, [("x", 0, [8], 0), ("y", 99, [1], 32)]);
        var g = Gguf.Read(new MemoryStream(b), b.Length);
        Assert.Contains($"x: ends at {g.DataOffset + 32}, past the file's {b.Length} bytes", g.Issues);
        Assert.Contains("y: unknown tensor type 99", g.Issues);
        Assert.Throws<InvalidDataException>(() => Gguf.Read(new MemoryStream(b[..30]), 30));
    }

    [Fact]
    public void Onnx_model_reports_its_graph_operators_subgraphs_and_external_data()
    {
        var b = ModelSamples.Onnx();
        Assert.Equal("onnx", Blob.Identify(b));
        var m = OnnxModel.Read(new MemoryStream(b), b.Length);
        Assert.Equal((9L, "writer", "2.0", "main"), (m.IrVersion, m.ProducerName, m.ProducerVersion, m.GraphName));
        Assert.Equal([("", 18L)], m.Opsets);
        Assert.Equal("x FLOAT[N,3] -> y FLOAT[N,3]", $"{m.Inputs[0].Name} {m.Inputs[0].Type} -> {m.Outputs[0].Name} {m.Outputs[0].Type}");
        Assert.Equal("Add 1, If 1, Relu 1", string.Join(", ", m.Operators.Select(o => $"{o.Key} {o.Value}")));
        Assert.Equal((3, 2, 2), (m.Nodes, m.Subgraphs, m.SubgraphNodes));
        Assert.Equal(["b FLOAT [3]   ", "w INT64 [4,4] w.bin 128 128"],
            m.Initializers.Select(i => $"{i.Name} {i.DataType} [{string.Join(",", i.Dims)}] {i.Location} {i.Offset} {i.Length}"));
        Assert.Equal(("author", "tests"), m.Metadata.Single());
    }

    [Fact]
    public void A_state_dict_pickle_names_its_tensors_and_stays_in_the_weights_only_allowlist()
    {
        var b = ModelSamples.StateDict();
        Assert.Equal("pickle", Blob.Identify(b));
        var p = PickleScan.Read(new MemoryStream(b), b.Length);
        Assert.True(p.Complete, string.Join("; ", p.Issues));
        Assert.Equal(["collections.OrderedDict GLOBAL 1", "torch._utils._rebuild_tensor_v2 GLOBAL 1", "torch.FloatStorage GLOBAL 1", "torch.HalfStorage GLOBAL 1"],
            p.Imports.Select(i => $"{i.Name} {i.Opcode} {i.Count}"));
        Assert.Equal((3, 2), (p.Calls["collections.OrderedDict"], p.Calls["torch._utils._rebuild_tensor_v2"]));
        Assert.Empty(p.OutsideWeightsOnly);
        Assert.Empty(p.OpcodesOutsideWeightsOnly);
        Assert.Equal(["weight float32 [3,4] 0 12", "bias float16 [3] 1 3"],
            p.TorchTensors(10).Select(t => $"{t.Name} {t.Dtype} [{string.Join(",", t.Shape)}] {t.StorageKey} {t.StorageElements}"));
    }

    [Fact]
    public void Imports_outside_the_allowlist_and_newer_opcodes_are_reported_without_importing_them()
    {
        // Protocol 4: STACK_GLOBAL datetime.date, called with REDUCE on a bytes argument; then a truncated GLOBAL.
        var b = new ModelSamples.Pickle().Proto(4).Short("datetime").Short("date").Op(0x93).Op('C').Op(4).Op(0x07).Op(0xE8).Op(1).Op(2).Op(0x85).Op('R').Op('.').ToArray();
        var p = PickleScan.Read(new MemoryStream(b), b.Length);
        Assert.True(p.Complete);
        Assert.Equal("datetime.date STACK_GLOBAL 1", p.Imports.Select(i => $"{i.Name} {i.Opcode} {i.Count}").Single());
        Assert.Equal(["datetime.date"], p.OutsideWeightsOnly);
        Assert.Equal(["SHORT_BINBYTES", "SHORT_BINUNICODE", "STACK_GLOBAL"], p.OpcodesOutsideWeightsOnly);

        var cut = new ModelSamples.Pickle().Proto(2).Global("collections", "OrderedDict").ToArray()[..^5];
        var q = PickleScan.Read(new MemoryStream(cut), cut.Length);
        Assert.False(q.Complete);
        Assert.Equal("the pickle ends without STOP (offset 22)", q.Issues.Single());
    }

    [Fact]
    public void A_torch_zip_checkpoint_checks_storage_sizes()
    {
        var c = TorchCheckpoint.ReadZip(new MemoryStream(ModelSamples.TorchZip()));
        Assert.Equal(("archive", "3", "little"), (c.Prefix, c.Version, c.ByteOrder));
        Assert.Empty(c.Issues);
        var bad = TorchCheckpoint.ReadZip(new MemoryStream(ModelSamples.TorchZip(biasBytes: 4)));
        Assert.Equal("bias: storage data/1 holds 4 bytes for 3 float16 elements", bad.Issues.Single());
    }

    [Fact]
    public void The_model_view_pages_tensors_and_summarizes_the_file()
    {
        using var dir = new TempDir();
        FileView View(string name, byte[] bytes, int? limit = null, long offset = 0)
        {
            var path = dir.File(name);
            File.WriteAllBytes(path, bytes);
            var input = FileInput.Open(path);
            input.Options = new FileViewOptions { View = "model", Limit = limit, Offset = offset };
            return new ModelFileView().Inspect(input, default)!;
        }
        var zip = View("model.pt", ModelSamples.TorchZip(), limit: 1, offset: 1);
        var facts = (ModelFileView.Facts)zip.Detail;
        Assert.Equal(("pytorch zip", 2, "15", null), (facts.Format, facts.Tensors, facts.Parameters, facts.Next));
        Assert.Equal("bias float16 [3] data/1 (cpu)", facts.TensorPage.Select(t => $"{t.Name} {t.Type} {t.Shape} {t.Location}").Single());
        Assert.Equal("PyTorch checkpoint (zip): 2 tensor(s), 15 parameters (float16 1, float32 1); 4 import(s), all in torch.load(weights_only=True)'s allowlist.", zip.Highlights[0]);

        var gguf = (ModelFileView.Facts)View("m.gguf", GgufSample()).Detail;
        Assert.Equal(("gguf v3", 2, "72"), (gguf.Format, gguf.Tensors, gguf.Parameters));
        var onnx = View("m.onnx", ModelSamples.Onnx());
        Assert.Equal("ONNX model (IR 9, writer 2.0, ai.onnx 18): 3 nodes, 3 operator types, 1 input(s), 1 output(s).", onnx.Highlights[0]);
        Assert.Equal(["w.bin"], ((ModelFileView.Facts)onnx.Detail).Onnx!.ExternalFiles);
        Assert.Null(new ModelFileView().Inspect(new FileInput("x.bin", "\x80\x02garbage"u8.ToArray(), "pickle"), default));
    }

    [Fact]
    [FuzzEntry(typeof(Safetensors), typeof(Gguf), typeof(OnnxModel), typeof(PickleScan), typeof(TorchCheckpoint), typeof(ModelFileView), typeof(ModelRisk))]
    public void Fuzzed_model_files_never_throw_unexpectedly()
    {
        byte[][] seeds = [ModelSamples.Safetensors("""{"a":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}""", 8), GgufSample(), ModelSamples.Onnx(),
            ModelSamples.StateDict(), ModelSamples.TorchZip(), ModelRiskTests.Npy("'|O'", ModelRiskTests.Call("os", "system")), ModelRiskTests.Keras("Lambda")];
        var failures = seeds.SelectMany(seed => FormatFuzz.Run(seed, b =>
        {
            try { Safetensors.Read(new MemoryStream(b), b.Length); } catch (InvalidDataException) { } catch (EndOfStreamException) { }
            try { Gguf.Read(new MemoryStream(b), b.Length); } catch (InvalidDataException) { }
            try { OnnxModel.Read(new MemoryStream(b), b.Length); } catch (InvalidDataException) { } catch (EndOfStreamException) { }
            PickleScan.Read(new MemoryStream(b), b.Length).TorchTensors(100);
            try { TorchCheckpoint.ReadZip(new MemoryStream(b)); } catch (InvalidDataException) { }
            ModelRisk.Scan("x.keras", b);
            ModelRisk.Scan("x.npy", b);
            ModelRisk.Scan("x.onnx", b);
            try { new ModelFileView().Inspect(new FileInput("x", b, Blob.Identify(b)), default); } catch (InvalidDataException) { } catch (EndOfStreamException) { }
        }, 200)).ToList();
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    // The vendor libraries (CORVUS_MODEL_PYTHON: safetensors, gguf, onnx, torch) read each file under CORVUS_MODEL_FILES;
    // compared: tensors, metadata, the ONNX graph, pickle imports and the torch.load(weights_only=True) verdict.
    [RequiresRealDataFact(ModelPython, ModelFiles)]
    [Trait("Speed", "Slow")]
    public void Real_model_files_match_the_vendor_libraries()
    {
        using var dir = new TempDir();
        var script = dir.File("reference.py");
        File.WriteAllText(script, Reference);
        var files = Directory.EnumerateFiles(Environment.GetEnvironmentVariable(ModelFiles)!, "*", SearchOption.AllDirectories)
            .Where(f => !f.EndsWith(".data", StringComparison.Ordinal)).ToList();
        int compared = 0;
        foreach (var file in files)
        {
            var input = FileInput.Open(file);
            input.Options = new FileViewOptions { View = "model", Limit = 1000 };
            if (new ModelFileView().Inspect(input, default) is not { } view) continue;
            var facts = (ModelFileView.Facts)view.Detail;
            var expected = Run(Environment.GetEnvironmentVariable(ModelPython)!, script, file).Split('\n', StringSplitOptions.RemoveEmptyEntries).Order(StringComparer.Ordinal).ToList();
            var actual = Lines(facts).Select(l => string.Join(" ", l.Split(" ", StringSplitOptions.RemoveEmptyEntries))).Order(StringComparer.Ordinal).ToList();
            Assert.True(expected.SequenceEqual(actual), $"{file}:\n{string.Join("\n", expected.Except(actual))}\n---\n{string.Join("\n", actual.Except(expected))}");
            compared++;
        }
        Assert.True(compared > 0, "no model files were read");
    }

    private static string Number(string v) =>
        double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && v.Any(c => c is '.' or 'E' or 'e') ? d.ToString("R", CultureInfo.InvariantCulture).ToLowerInvariant() : v;

    private static IEnumerable<string> Lines(ModelFileView.Facts f)
    {
        bool gguf = f.Format.StartsWith("gguf", StringComparison.Ordinal);
        foreach (var t in f.TensorPage)
            yield return gguf ? $"tensor {t.Name} {t.Type} {t.Shape} {t.Offset} {t.Size}" : $"tensor {t.Name} {t.Type} {t.Shape}" + (f.Onnx != null ? $" {t.Location} {t.Offset} {t.Size}" : "");
        foreach (var m in f.Metadata)
            // gguf-py flattens an array of arrays, so only its type is compared.
            yield return m.Type?.StartsWith("array[array", StringComparison.Ordinal) == true ? $"meta {m.Key} {m.Type}"
                : m.Count != null ? $"meta {m.Key} {m.Type} {m.Count}" : m.Type is "f32" or "f64" ? $"meta {m.Key} {m.Type} {Number(m.Value)}" : $"meta {m.Key} {m.Type} {m.Value}".TrimEnd();
        if (f.Onnx is { } o)
        {
            yield return $"ir {o.IrVersion} {o.Producer} {o.Graph} nodes {o.Nodes} subgraphs {o.Subgraphs} {o.SubgraphNodes}";
            foreach (var s in o.Opsets) yield return $"opset {s}";
            foreach (var i in o.Inputs) yield return $"input {i.Name} {i.Type}";
            foreach (var i in o.Outputs) yield return $"output {i.Name} {i.Type}";
            foreach (var (k, v) in o.Operators) yield return $"op {k} {v}";
            foreach (var fn in o.Functions) yield return $"function {fn}";
        }
        if (f.Pickle is { } p)
        {
            foreach (var i in p.Imports) yield return $"import {i.Name} {i.Count}";
            yield return $"weights_only {(p.OutsideWeightsOnly.Count + p.OpcodesOutsideWeightsOnly.Count == 0 ? "ok" : "refused")}";
        }
    }

    private static string Run(string python, string script, string file)
    {
        var start = new ProcessStartInfo(python) { RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8 };
        foreach (var a in new[] { "-I", script, file }) start.ArgumentList.Add(a);
        start.Environment["PYTHONIOENCODING"] = "utf-8";
        using var p = Process.Start(start)!;
        var output = p.StandardOutput.ReadToEndAsync();
        var error = p.StandardError.ReadToEndAsync();
        p.WaitForExit();
        Assert.True(p.ExitCode == 0, $"reference {file}: exit {p.ExitCode}: {error.Result}");
        return output.Result.Replace("\r", "");
    }

    // Reads a model file with the vendor libraries; pickles go through Unpickler subclasses that record find_class and
    // return inert stand-ins, so nothing the file names is imported.
    private const string Reference = """
        import sys, io, pickle, zipfile, struct
        path = sys.argv[1]
        out = []
        head = open(path, "rb").read(16)

        class Inert:
            def __new__(cls, *a, **k): return object.__new__(cls)
            def __init__(self, *a, **k): pass
            def __setstate__(self, s): pass
            def __setitem__(self, k, v): pass
            def append(self, v): pass
            def extend(self, v): pass

        class Recorder(pickle.Unpickler):
            def __init__(self, f, counts):
                super().__init__(f, encoding="bytes")
                self.counts = counts
            def find_class(self, module, name):
                key = f"{module}.{name}"
                self.counts[key] = self.counts.get(key, 0) + 1
                return type(name, (Inert,), {})
            def persistent_load(self, pid): return Inert()

        def imports(f):
            counts = {}
            Recorder(f, counts).load()
            for k, v in counts.items(): out.append(f"import {k} {v}")

        def tensors(obj, prefix=""):
            import torch
            if isinstance(obj, torch.Tensor):
                out.append(f"tensor {prefix} {str(obj.dtype)[6:]} [{', '.join(str(d) for d in obj.shape)}]")
            elif isinstance(obj, dict):
                for k, v in obj.items(): tensors(v, f"{prefix}.{k}" if prefix else str(k))
            elif isinstance(obj, (list, tuple)):
                for i, v in enumerate(obj): tensors(v, f"{prefix}.{i}" if prefix else str(i))

        def num32(v):
            import numpy as np
            s = str(np.float32(v))
            return s[:-2] if s.endswith(".0") else s

        def num64(v):
            s = repr(float(v))
            return s[:-2] if s.endswith(".0") else s

        if head[:4] == b"GGUF":
            import gguf
            r = gguf.GGUFReader(path)
            names = {gguf.GGUFValueType.UINT8: "u8", gguf.GGUFValueType.INT8: "i8", gguf.GGUFValueType.UINT16: "u16", gguf.GGUFValueType.INT16: "i16",
                     gguf.GGUFValueType.UINT32: "u32", gguf.GGUFValueType.INT32: "i32", gguf.GGUFValueType.FLOAT32: "f32", gguf.GGUFValueType.BOOL: "bool",
                     gguf.GGUFValueType.STRING: "string", gguf.GGUFValueType.UINT64: "u64", gguf.GGUFValueType.INT64: "i64", gguf.GGUFValueType.FLOAT64: "f64",
                     gguf.GGUFValueType.ARRAY: "array"}
            for f in r.fields.values():
                if f.name.startswith("GGUF."): continue
                t = f.types[0]
                if t == gguf.GGUFValueType.ARRAY:
                    tn = lambda ts: (f"array[{tn(ts[1:])}]" if len(ts) > 1 else "array") if ts[0] == gguf.GGUFValueType.ARRAY else names[ts[0]]
                    name = tn(f.types)
                    out.append(f"meta {f.name} {name}" if name.startswith("array[array") else f"meta {f.name} {name} {len(f.data)}")
                    continue
                v = f.contents()
                if t == gguf.GGUFValueType.BOOL: v = "true" if v else "false"
                elif t == gguf.GGUFValueType.FLOAT32: v = num32(v)
                elif t == gguf.GGUFValueType.FLOAT64: v = num64(v)
                out.append(f"meta {f.name} {names[t]} {v}".rstrip())
            for t in r.tensors:
                shape = ", ".join(str(int(d)) for d in t.shape)
                out.append(f"tensor {t.name} {t.tensor_type.name} [{shape}] {t.data_offset} {t.n_bytes}")
        elif zipfile.is_zipfile(path):
            import torch
            z = zipfile.ZipFile(path)
            pkl = min((n for n in z.namelist() if n == "data.pkl" or n.endswith("/data.pkl")), key=len)
            imports(io.BytesIO(z.read(pkl)))
            try:
                tensors(torch.load(path, weights_only=True, map_location="cpu")); out.append("weights_only ok")
            except Exception:
                out.append("weights_only refused")
        elif head[:2] == b"\x80\x02" and head[2:4] == b"\x8a\x0a":
            import torch
            f = open(path, "rb")
            for _ in range(3): pickle.load(f)
            imports(f)
            try:
                tensors(torch.load(path, weights_only=True, map_location="cpu")); out.append("weights_only ok")
            except Exception:
                out.append("weights_only refused")
        elif head[0] == 0x80 and 2 <= head[1] <= 5:
            import torch._weights_only_unpickler as w
            imports(open(path, "rb"))
            try:
                w.Unpickler(open(path, "rb")).load(); out.append("weights_only ok")
            except Exception:
                out.append("weights_only refused")
        elif struct.unpack("<Q", head[:8])[0] < 100_000_000 and head[8:9] == b"{":
            from safetensors import safe_open
            with safe_open(path, framework="numpy") as f:
                for k, v in (f.metadata() or {}).items(): out.append(f"meta {k}  {v}".replace("  ", " "))
                for k in f.keys():
                    s = f.get_slice(k)
                    out.append(f"tensor {k} {s.get_dtype()} [{', '.join(str(d) for d in s.get_shape())}]")
        else:
            import onnx
            from onnx import TensorProto
            m = onnx.load(path, load_external_data=False)
            dt = lambda t: TensorProto.DataType.Name(t)
            def ty(t):
                k = t.WhichOneof("value")
                if k == "tensor_type" or k == "sparse_tensor_type":
                    tt = getattr(t, k)
                    s = dt(tt.elem_type)
                    if tt.HasField("shape"):
                        s += "[" + ",".join(str(d.dim_value) if d.HasField("dim_value") else d.dim_param if d.HasField("dim_param") else "?" for d in tt.shape.dim) + "]"
                    return ("sparse " if k == "sparse_tensor_type" else "") + s
                if k == "sequence_type": return f"seq({ty(t.sequence_type.elem_type)})"
                if k == "optional_type": return f"optional({ty(t.optional_type.elem_type)})"
                if k == "map_type": return f"map({dt(t.map_type.key_type)}, {ty(t.map_type.value_type)})"
                return ""
            def sub(g):
                n = c = 0
                for node in g.node:
                    for a in node.attribute:
                        for sg in ([a.g] if a.HasField("g") else []) + list(a.graphs):
                            sn, sc = sub(sg)
                            c += 1 + sc; n += len(sg.node) + sn
                return n, c
            g = m.graph
            sn, sc = sub(g)
            producer = " ".join(x for x in [m.producer_name, m.producer_version] if x) if m.producer_name else ""
            out.append(f"ir {m.ir_version} {producer} {g.name} nodes {len(g.node)} subgraphs {sc} {sn}".replace("  ", " "))
            for o in m.opset_import: out.append(f"opset {o.domain or 'ai.onnx'} {o.version}")
            for i in g.input: out.append(f"input {i.name} {ty(i.type)}")
            for i in g.output: out.append(f"output {i.name} {ty(i.type)}")
            ops = {}
            for node in g.node:
                k = node.op_type if node.domain in ("", "ai.onnx") else f"{node.domain}:{node.op_type}"
                ops[k] = ops.get(k, 0) + 1
            for k, v in ops.items(): out.append(f"op {k} {v}")
            for f in m.functions: out.append(f"function {f.domain + ':' if f.domain else ''}{f.name}")
            for p in m.metadata_props: out.append(f"meta {p.key}  {p.value}".replace("  ", " "))
            for t in g.initializer:
                ext = {e.key: e.value for e in t.external_data}
                out.append(f"tensor {t.name} {dt(t.data_type)} [{', '.join(str(d) for d in t.dims)}] {ext.get('location', '')} {ext.get('offset', '')} {ext.get('length', '')}".rstrip())
        print("\n".join(" ".join(x for x in l.split(" ") if x) for l in out))
        """;
}
