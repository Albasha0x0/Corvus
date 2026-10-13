using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Code;
using Corvus.Native.Patching;
using Corvus.Native.Pe;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// export_native_patches: each format applied to the original file bytes (by small appliers written here, independent
/// of the exporter) gives exactly the bytes save_native writes, including relocation-table edits and the PE checksum;
/// the IDAPython script carries every entry; IPS handles its end-marker offset and the 16 MB limit.
/// </summary>
public class NativePatchExportTests(ITestOutputHelper output)
{
    // ---- independent appliers ----

    /// <summary>Applies an IDA .dif: after the header, "offset: orig new" per line; the original byte must match.</summary>
    public static byte[] ApplyDif(byte[] original, string dif)
    {
        var bytes = (byte[])original.Clone();
        var lines = dif.Split('\n');
        Assert.Equal("This difference file was created by IDA", lines[0].TrimEnd('\r'));
        Assert.Equal("", lines[1].TrimEnd('\r'));
        foreach (var raw in lines.Skip(3))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0) continue;
            var parts = line.Split(':', 2);
            long offset = Convert.ToInt64(parts[0], 16);
            var values = parts[1].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            Assert.Equal(Convert.ToByte(values[0], 16), bytes[offset]);
            bytes[offset] = Convert.ToByte(values[1], 16);
        }
        return bytes;
    }

    /// <summary>Applies an IPS ("PATCH" ... "EOF", 3-byte offsets) or IPS32 ("IPS32" ... "EEOF", 4-byte offsets) patch, incl. RLE records.</summary>
    public static byte[] ApplyIps(byte[] original, byte[] ips)
    {
        var bytes = new List<byte>(original); // IPS records past the end of file extend it
        void Ensure(long end) { while (bytes.Count < end) bytes.Add(0); }
        bool ips32 = Encoding.ASCII.GetString(ips, 0, 5) == "IPS32";
        Assert.True(ips32 || Encoding.ASCII.GetString(ips, 0, 5) == "PATCH");
        int at = 5;
        while (true)
        {
            if (!ips32 && Encoding.ASCII.GetString(ips, at, 3) == "EOF") { Assert.Equal(at + 3, ips.Length); break; }
            if (ips32 && Encoding.ASCII.GetString(ips, at, 4) == "EEOF") { Assert.Equal(at + 4, ips.Length); break; }
            long offset = ips32 ? BinaryPrimitives.ReadUInt32BigEndian(ips.AsSpan(at)) : ips[at] << 16 | ips[at + 1] << 8 | ips[at + 2];
            at += ips32 ? 4 : 3;
            int size = BinaryPrimitives.ReadUInt16BigEndian(ips.AsSpan(at));
            at += 2;
            if (size == 0)
            {
                int run = BinaryPrimitives.ReadUInt16BigEndian(ips.AsSpan(at));
                Ensure(offset + run);
                for (int i = 0; i < run; i++) bytes[(int)offset + i] = ips[at + 2];
                at += 3;
            }
            else
            {
                Ensure(offset + size);
                for (int i = 0; i < size; i++) bytes[(int)offset + i] = ips[at + i];
                at += size;
            }
        }
        return bytes.ToArray();
    }

    /// <summary>Applies the JSON patch set: each patch's replacement, its relocation edits and the checksum, checking the original bytes.</summary>
    public static byte[] ApplyJson(byte[] original, string json)
    {
        var bytes = new List<byte>(original);
        void Ensure(long end) { while (bytes.Count < end) bytes.Add(0); }
        using var doc = JsonDocument.Parse(json);
        void Put(long offset, string originalHex, string replacementHex)
        {
            var o = Convert.FromHexString(originalHex);
            var r = Convert.FromHexString(replacementHex);
            Ensure(offset + o.Length);
            for (int i = 0; i < o.Length; i++) Assert.Equal(o[i], bytes[(int)offset + i]);
            Ensure(offset + r.Length);
            for (int i = 0; i < r.Length; i++) bytes[(int)offset + i] = r[i];
        }
        static long Hex(JsonElement e) => Convert.ToInt64(e.GetString()!, 16);
        foreach (var p in doc.RootElement.GetProperty("patches").EnumerateArray())
        {
            Put(Hex(p.GetProperty("fileOffset")), p.GetProperty("original").GetString()!, p.GetProperty("replacement").GetString()!);
            foreach (var e in p.GetProperty("relocationEdits").EnumerateArray())
            {
                long at = Hex(e.GetProperty("fileOffset"));
                Assert.Equal((ushort)Hex(e.GetProperty("original")), BinaryPrimitives.ReadUInt16LittleEndian(CollectionsMarshal.AsSpan(bytes).Slice((int)at)));
                BinaryPrimitives.WriteUInt16LittleEndian(CollectionsMarshal.AsSpan(bytes).Slice((int)at), (ushort)Hex(e.GetProperty("replacement")));
            }
        }
        // version-2 header edits (section count, the new section header, SizeOfImage/Code) outside any recorded patch body
        if (doc.RootElement.TryGetProperty("extraEdits", out var extra))
            foreach (var e in extra.EnumerateArray())
                Put(Hex(e.GetProperty("fileOffset")), e.GetProperty("original").GetString()!, e.GetProperty("replacement").GetString()!);
        if (doc.RootElement.GetProperty("checksum") is { ValueKind: JsonValueKind.Object } cs)
            Put(Hex(cs.GetProperty("fileOffset")), cs.GetProperty("original").GetString()!, cs.GetProperty("replacement").GetString()!);
        // the appended section grows the file
        if (doc.RootElement.TryGetProperty("append", out var app) && app.ValueKind == JsonValueKind.Object)
        {
            long at = Hex(app.GetProperty("fileOffset"));
            var tail = Convert.FromHexString(app.GetProperty("bytes").GetString()!);
            Ensure(at + tail.Length);
            for (int i = 0; i < tail.Length; i++) bytes[(int)at + i] = tail[i];
        }
        return bytes.ToArray();
    }

    private sealed class Harness : IDisposable
    {
        public readonly TempDir Dir = new();
        public readonly Env Env = new();
        public readonly NativeCodeService Code;
        public readonly NativeEditService Edits;
        public readonly NativePatchTools Tools;
        public readonly string Path;

        public Harness(byte[] image, string name = "patchme.dll")
        {
            Code = new NativeCodeService(Env.Workspace, Env.Options, null, new AnnotationStore(Dir.File("ann")));
            Edits = new NativeEditService(Env.Workspace, Code);
            Tools = new NativePatchTools(Env.Workspace, Code, Edits);
            Path = Dir.File(name);
            File.WriteAllBytes(Path, image);
        }

        public async Task<(LoadedNative, NativeCodeIndex)> Open()
        {
            var n = Env.Workspace.LoadAny(Path).Native!;
            return (n, await Code.Index(n, null, default));
        }

        public NativeEditService.PatchResult Asm(NativeCodeIndex index, uint rva, string text)
        {
            var r = X86Assembler.Assemble(index.Image.Arch, index.Image.ImageBase + rva, text);
            return Edits.PreparePatch(index, rva, r.Bytes, false, "patch_asm", RelocationMode.Auto, r.Constants, text);
        }

        public void Dispose() { Env.Dispose(); Dir.Dispose(); }
    }

    /// <summary>Exports every format, applies each to the original bytes and compares with save_native's file.</summary>
    private static async Task<Dictionary<string, NativePatchTools.PatchExportReport>> RoundTrip(Harness h, LoadedNative native, string label, ITestOutputHelper? log = null)
    {
        var saved = h.Dir.File(label + "-saved.bin");
        var save = h.Edits.Save(native, saved, overwrite: true, stripSignature: false);
        Assert.Contains("Verified", save);
        var expected = File.ReadAllBytes(saved);
        var original = native.Patches.OriginalBytes();
        var reports = new Dictionary<string, NativePatchTools.PatchExportReport>();
        foreach (var format in new[] { "dif", "ips", "ips32", "json", "ida" })
        {
            var path = h.Dir.File($"{label}.{format}");
            var r = await h.Tools.ExportNativePatches(native.Id, path, format);
            reports[format] = r;
            Assert.Equal(format, r.Format);
            Assert.Equal(new FileInfo(path).Length, r.Bytes);
            byte[]? applied = format switch
            {
                "dif" => ApplyDif(original, File.ReadAllText(path)),
                "ips" or "ips32" => ApplyIps(original, File.ReadAllBytes(path)),
                "json" => ApplyJson(original, File.ReadAllText(path)),
                _ => null,
            };
            if (applied != null) Assert.True(expected.AsSpan().SequenceEqual(applied), $"{label}: {format} applied to the original differs from save_native's output");
            log?.WriteLine($"{label}: {format} {r.Bytes:N0} bytes, {r.Records} record(s), {r.ChangedBytes} changed byte(s), checksum {r.ChecksumUpdated}");
        }
        return reports;
    }

    [Fact]
    public async Task Every_format_reproduces_save_native_including_relocation_edits_and_checksum()
    {
        var image = NativeRelocationPatchTests.X86Image();
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(PeBuilder.PeOffset + 24 + 64), 0x1234); // a stored checksum: save recomputes it
        using var h = new Harness(image);
        var (native, index) = await h.Open();
        // a relocated operand moved one byte (entries neutralized and added), then a raw patch further on
        h.Edits.ApplyPatch(native, index, h.Asm(index, 0x1000, "nop\nmov eax, dword ptr [0x10002004]"), dryRun: false);
        index = await h.Code.Index(native, null, default);
        h.Edits.ApplyPatch(native, index, h.Edits.PreparePatch(index, 0x1020, [0xCC, 0xCC], false, "patch_bytes 2 bytes"), dryRun: false);

        var reports = await RoundTrip(h, native, "x86", output);
        Assert.All(reports.Values, r => Assert.True(r.ChecksumUpdated));
        Assert.Equal(2, reports["json"].Patches);
        Assert.True(reports["json"].RelocationEdits >= 2);

        // json: the patch set, with the assembly text, relocation changes and the original hash
        using var doc = JsonDocument.Parse(File.ReadAllText(h.Dir.File("x86.json")));
        Assert.Equal(PatchExport.JsonKind, doc.RootElement.GetProperty("kind").GetString());
        Assert.Equal(native.OriginalSha256, doc.RootElement.GetProperty("image").GetProperty("sha256").GetString());
        var first = doc.RootElement.GetProperty("patches")[0];
        Assert.Equal("asm", first.GetProperty("origin").GetString());
        Assert.Contains("mov eax", first.GetProperty("assembly").GetString());
        Assert.Contains(first.GetProperty("relocationChanges").EnumerateArray(), c => c.GetProperty("action").GetString() == "added");
        Assert.Equal("bytes", doc.RootElement.GetProperty("patches")[1].GetProperty("origin").GetString());

        // ida: rebased at run time, original bytes checked, one entry per patch, relocation edit and the checksum
        var script = File.ReadAllText(h.Dir.File("x86.ida"));
        Assert.Contains("base = idaapi.get_imagebase()", script);
        Assert.Contains("ida_bytes.patch_bytes(ea, new)", script);
        Assert.Contains("if found != orig:", script);
        Assert.Matches(@"\(""#1 patch_asm(, \d+ bytes \(\d+ given, \d+ NOP padding\))?"", 0x1000, ", script);
        Assert.Contains("(\"#2 patch_bytes 2 bytes\", 0x1020, ", script);
        Assert.Contains("#1 relocation entry", script);
        Assert.Contains("(\"PE checksum\", 0x", script);
        Assert.Equal(reports["ida"].Records, script.Split('\n').Count(l => l.StartsWith("    (\"", StringComparison.Ordinal)));
        Assert.DoesNotContain('\r', script);
        Assert.DoesNotContain('\t', script);
    }

    [Fact]
    public void Grown_file_renders_in_each_format_and_ips_json_reproduce_the_output()
    {
        // An image "grown" by a fake appended section plus a header-area byte edit (as section growth would make).
        var original = new byte[0x600];
        new Random(1).NextBytes(original);
        var output = new byte[0x800];
        original.CopyTo(output, 0);
        output[0x94] = (byte)(original[0x94] + 1);                 // a header edit no patch body covers -> extraEdits
        for (int i = 0x600; i < 0x800; i++) output[i] = (byte)(i & 0xFF); // the appended section bytes
        var src = new PatchExportSource("grown.dll", "", 0x400000, NativeArch.X64, [], original, output, -1, _ => null,
            [new AppendedSection(".patch", 0x5000, 0x200, 0x600, output[0x600..])]);

        // .dif cannot grow the file: refused with a typed reason
        var ex = Assert.Throws<ToolError>(() => PatchExport.Render(src, PatchExport.Format.Dif));
        Assert.Contains("grown_file", ex.Message);
        Assert.Contains("ips", ex.Remediation);

        // IPS / IPS32 and JSON applied to the original reproduce the output exactly
        foreach (var fmt in new[] { PatchExport.Format.Ips, PatchExport.Format.Ips32 })
        {
            var r = PatchExport.Render(src, fmt);
            Assert.Equal(output, ApplyIps(original, r.Content));
            Assert.Equal(0x200 + 1, r.ChangedBytes); // the appended section plus the one header byte
        }
        var json = PatchExport.Render(src, PatchExport.Format.Json);
        Assert.Equal(output, ApplyJson(original, Encoding.UTF8.GetString(json.Content)));
        using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(json.Content));
        Assert.Equal(2, doc.RootElement.GetProperty("version").GetInt32());
        Assert.Equal(0x800, doc.RootElement.GetProperty("image").GetProperty("outputFileSize").GetInt32());
        Assert.Equal("0x600", doc.RootElement.GetProperty("append").GetProperty("fileOffset").GetString());
        Assert.Contains(doc.RootElement.GetProperty("extraEdits").EnumerateArray(), e => e.GetProperty("fileOffset").GetString() == "0x94");
        Assert.Contains(doc.RootElement.GetProperty("appendedSections").EnumerateArray(), e => e.GetProperty("name").GetString() == ".patch");

        // the IDAPython script renders, creates the segment and still parses structurally
        var ida = Encoding.UTF8.GetString(PatchExport.Render(src, PatchExport.Format.Ida).Content);
        Assert.Contains("ida_segment", ida);
        Assert.Contains("add_segments()", ida);
        Assert.Contains("(\".patch\", 0x5000,", ida);
    }

    /// <summary>
    /// The IDAPython script under stand-in IDA modules: a segment goes only where nothing is (or where an earlier run put
    /// it); when another segment holds the range, nothing is written, the site patches included.
    /// </summary>
    [Fact]
    public void Ida_script_places_a_segment_only_where_the_range_is_free()
    {
        var python = PythonLocator.Find([], []);
        if (python == null) { output.WriteLine("no Python: script not run"); return; }
        var original = new byte[0x600];
        var output2 = new byte[0x800];
        original.CopyTo(output2, 0);
        output2[0x410] = 0xE9;
        var patch = new NativePatch(0x1010, 0x410, [0x00], [0xE9], "patch_bytes 1 bytes", RelocationPlan.None);
        var src = new PatchExportSource("grown.dll", "", 0x400000, NativeArch.X64, [patch], original, output2, -1, _ => null,
            [new AppendedSection(".patch", 0x5000, 0x200, 0x600, output2[0x600..])]);
        using var dir = new TempDir();
        var script = dir.File("patches.py");
        File.WriteAllBytes(script, PatchExport.Render(src, PatchExport.Format.Ida).Content);
        var driver = dir.File("fake_ida.py");
        File.WriteAllText(driver, """
            import sys, types
            BASE = 0x400000
            class Seg:
                def __init__(self, s, e, n): self.start_ea, self.end_ea, self.name = s, e, n
            segs = []
            mem = {}
            existing = sys.argv[2]
            if existing == "foreign": segs.append(Seg(BASE + 0x5000, BASE + 0x6000, ".other"))
            if existing == "next": segs.append(Seg(BASE + 0x5100, BASE + 0x6000, ".other"))
            if existing == "ours": segs.append(Seg(BASE + 0x5000, BASE + 0x5200, ".patch"))
            mem.update({BASE + 0x1010: 0})
            def getseg(ea): return next((s for s in segs if s.start_ea <= ea < s.end_ea), None)
            def get_next_seg(ea): return min((s for s in segs if s.start_ea > ea), key=lambda s: s.start_ea, default=None)
            def add_segm_ex(s, name, cls, flags): segs.append(Seg(s.start_ea, s.end_ea, name)); return True
            seg = types.ModuleType("ida_segment")
            seg.getseg, seg.get_next_seg, seg.add_segm_ex, seg.ADDSEG_NOSREG = getseg, get_next_seg, add_segm_ex, 0
            seg.get_segm_name = lambda s: s.name
            api = types.ModuleType("idaapi")
            api.get_imagebase = lambda: BASE
            api.segment_t = type("segment_t", (), {})
            api.get_inf_structure = lambda: types.SimpleNamespace(is_64bit=lambda: True)
            api.SEGPERM_EXEC, api.SEGPERM_READ = 1, 4
            b = types.ModuleType("ida_bytes")
            def patch_bytes(ea, data):
                for i, x in enumerate(data): mem[ea + i] = x
            b.patch_bytes = patch_bytes
            b.is_loaded = lambda ea: ea in mem
            b.get_bytes = lambda ea, n: bytes(mem.get(ea + i, 0) for i in range(n))
            auto = types.ModuleType("ida_auto")
            auto.plan_range = lambda s, e: None
            auto.auto_wait = lambda: None
            sys.modules.update({"idaapi": api, "ida_bytes": b, "ida_auto": auto, "ida_segment": seg})
            g = {"__name__": "__main__"}
            exec(compile(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1], "exec"), g)
            print("RESULT", g["CORVUS_SEGMENTS_RESULT"][0], g["CORVUS_SEGMENTS_RESULT"][1], g["CORVUS_PATCH_RESULT"][0], mem[BASE + 0x1010])
            """);
        string Run(string existing)
        {
            var run = PythonLocator.RunCapture(python.Executable, ["-I", driver, script, existing], TimeSpan.FromSeconds(30));
            output.WriteLine(run.Stdout + run.Stderr);
            return run.Stdout.Split('\n').Single(l => l.StartsWith("RESULT", StringComparison.Ordinal)).Trim();
        }
        Assert.Equal("RESULT 1 0 1 233", Run("none"));      // created, then the site patched
        Assert.Equal("RESULT 0 0 1 233", Run("ours"));      // an earlier run's segment is reused
        Assert.Equal("RESULT 0 1 0 0", Run("foreign"));     // another segment holds the start: nothing written
        Assert.Equal("RESULT 0 1 0 0", Run("next"));        // another segment starts inside the range
    }

    [Fact]
    public void Ips_moves_a_record_off_the_end_marker_offset_and_refuses_offsets_past_16_MB()
    {
        PatchExportSource Source(int size, params long[] offsets)
        {
            var original = new byte[size];
            var patched = (byte[])original.Clone();
            foreach (var o in offsets) patched[o] = 0xAB;
            return new PatchExportSource("big.bin", "", 0x400000, NativeArch.X86, [], original, patched, -1, _ => null);
        }

        // a change at 0x454F46 ("EOF" as an offset): the record starts at 0x454F45
        var eof = Source((int)PatchExport.IpsEofOffset + 16, 0x10, PatchExport.IpsEofOffset);
        var ips = PatchExport.Render(eof, PatchExport.Format.Ips);
        Assert.Contains(ips.Notes, n => n.Contains("one byte earlier"));
        // (the applier stops at a record that reads "EOF" and then fails on the trailing bytes)
        Assert.Equal(eof.Output, ApplyIps(eof.Original, ips.Content));

        // past 16 MB: ips refuses with a clear error, ips32 carries it
        var big = Source(0x1000010, 0x20, 0x1000008);
        var ex = Assert.Throws<ToolError>(() => PatchExport.Render(big, PatchExport.Format.Ips));
        Assert.Contains("16 MB", ex.Message);
        Assert.Contains("ips32", ex.Remediation);
        var ips32 = PatchExport.Render(big, PatchExport.Format.Ips32);
        Assert.Equal(big.Output, ApplyIps(big.Original, ips32.Content));
        Assert.Equal(2, ips32.Records);
    }

    /// <summary>
    /// A copy of System32 version.dll patched with patch_asm (a 'xor eax, eax ; ret' at an export) and patch_bytes: the
    /// .dif, IPS and JSON exports reproduce save_native's file; then the IDAPython script runs under idalib against a
    /// fresh database of the original and every patched byte in the database matches the saved file.
    /// </summary>
    [Trait("Speed", "Slow")]
    [WindowsFact]
    public async Task Real_dll_round_trips_and_the_ida_script_applies_under_idalib()
    {
        var src = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "version.dll");
        if (!File.Exists(src)) return;
        using var h = new Harness(File.ReadAllBytes(src), "version.dll");
        var (native, index) = await h.Open();
        var exports = native.Image.Exports.Where(e => e.Rva != 0 && index.FunctionByStart(e.Rva) != null).Take(2).ToList();
        Assert.Equal(2, exports.Count);
        h.Edits.ApplyPatch(native, index, h.Asm(index, exports[0].Rva, "xor eax, eax\nret"), dryRun: false);
        index = await h.Code.Index(native, null, default);
        h.Edits.ApplyPatch(native, index, h.Edits.PreparePatch(index, exports[1].Rva, [0xCC], false, "patch_bytes 1 bytes"), dryRun: false);
        var sw = Stopwatch.StartNew();
        var reports = await RoundTrip(h, native, "version", output);
        output.WriteLine($"exports in {sw.ElapsedMilliseconds} ms");

        // the script parses as Python
        var script = h.Dir.File("version.ida");
        var log = new List<string>();
        var python = PythonLocator.Find([], log);
        if (python == null) { output.WriteLine("no Python: script not run"); return; }
        var parse = PythonLocator.RunCapture(python.Executable, ["-I", "-c", "import ast,sys; ast.parse(open(sys.argv[1], encoding='utf-8').read()); print('ok')", script], TimeSpan.FromSeconds(30));
        Assert.Equal("ok", parse.Stdout.Trim());

        var ida = IdaInstallation.Locate(null, out var reason, out _);
        if (ida == null) { output.WriteLine("IDA not run: " + reason); return; }
        var db = h.Dir.File("ida-input.dll");
        File.Copy(src, db);
        var driver = h.Dir.File("drive.py");
        File.WriteAllText(driver, """
            import os, sys
            sys.path.insert(0, os.path.join(os.environ["IDADIR"], "idalib", "python"))
            import idapro
            target, script, saved = sys.argv[1], sys.argv[2], sys.argv[3]
            if idapro.open_database(target, True) != 0:
                print("open failed"); sys.exit(2)
            import idaapi, ida_bytes, ida_segment
            g = {"__name__": "__main__"}
            exec(compile(open(script, encoding="utf-8").read(), script, "exec"), g)
            applied, already, differ, missing = g["CORVUS_PATCH_RESULT"]
            # every loaded byte equals the saved file's byte at its file offset
            import ida_loader
            data = open(saved, "rb").read()
            base = idaapi.get_imagebase()
            checked = bad = 0
            for label, rva, original, replacement in g["PATCHES"]:
                ea = base + rva
                n = len(replacement) // 2
                if not all(ida_bytes.is_loaded(ea + i) for i in range(n)):
                    continue
                off = ida_loader.get_fileregion_offset(ea)
                checked += 1
                if ida_bytes.get_bytes(ea, n) != data[off:off + n]:
                    bad += 1
            # IDA's own .dif of the patched database, for comparison with ours
            import ida_fpro, ida_ida
            f = ida_fpro.qfile_t()
            if f.open(sys.argv[4], "wb"):
                ida_loader.gen_file(ida_loader.OFILE_DIF, f.get_fp(), ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea(), 0)
                f.close()
            # a second run finds everything applied
            g2 = {"__name__": "__main__"}
            exec(compile(open(script, encoding="utf-8").read(), script, "exec"), g2)
            print("RESULT %d %d %d %d checked %d bad %d rerun_applied %d" % (applied, already, differ, missing, checked, bad, g2["CORVUS_PATCH_RESULT"][0]))
            idapro.close_database(False)
            """);
        var env = new Dictionary<string, string?> { ["IDADIR"] = ida.Directory, ["TVHEADLESS"] = "1", ["IDA_IS_INTERACTIVE"] = null };
        sw.Restart();
        var idaDif = h.Dir.File("ida-own.dif");
        var run = PythonLocator.RunCapture(python.Executable, ["-I", "-u", driver, db, script, h.Dir.File("version-saved.bin"), idaDif], TimeSpan.FromMinutes(5), env);
        output.WriteLine(run.Stdout);
        output.WriteLine(run.Stderr);
        var line = run.Stdout.Split('\n').FirstOrDefault(l => l.StartsWith("RESULT", StringComparison.Ordinal));
        Assert.True(line != null, $"no RESULT line (exit {run.ExitCode}, timed out {run.TimedOut}, start error {run.StartError}):\n{run.Stdout}\n{run.Stderr}");
        var f = line!.Split(' ');
        int applied = int.Parse(f[1]), differ = int.Parse(f[3]), checkedEntries = int.Parse(f[6]), bad = int.Parse(f[8]), rerun = int.Parse(f[10]);
        Assert.True(applied >= 2, line);
        Assert.Equal(0, differ);
        Assert.Equal(0, bad);
        Assert.True(checkedEntries >= 2, line);
        Assert.Equal(0, rerun);

        // IDA's own .dif of the database (which has no PE header or .reloc loaded) has our header and a subset of our lines
        var theirs = File.ReadAllText(idaDif).Split('\n');
        var ours = File.ReadAllText(h.Dir.File("version.dif")).Split('\n');
        output.WriteLine($"IDA's .dif: {theirs.Length - 4} line(s); ours: {ours.Length - 4}");
        Assert.Equal(theirs[0], ours[0]);
        Assert.Equal(theirs[1], ours[1]);
        Assert.Equal("ida-input.dll", theirs[2]);
        Assert.True(theirs.Length > 4, "IDA wrote no changed bytes");
        Assert.All(theirs.Skip(3).Where(l => l.Length > 0), l => Assert.Contains(l, ours));
        output.WriteLine($"idalib: {line} in {sw.Elapsed.TotalSeconds:0.0} s (of {reports["ida"].Records} entries)");
    }

    /// <summary>
    /// An extension placed in a new section: the IDAPython script run under idalib against a fresh database of the original
    /// creates the segment at its RVA with the saved file's section bytes, then applies the site jump; a second run creates
    /// nothing and applies nothing.
    /// </summary>
    [Trait("Speed", "Slow")]
    [WindowsFact]
    public async Task Ida_script_creates_the_appended_segment_under_idalib()
    {
        var src = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "version.dll");
        if (!File.Exists(src)) return;
        using var h = new Harness(File.ReadAllBytes(src), "version.dll");
        var (native, index) = await h.Open();
        // the first instruction boundary past a prologue (unwind info) that takes a stub
        NativeEditService.PatchResult? prepared = null;
        foreach (var fn in native.Image.Exports.Where(e => e.Rva != 0).Select(e => index.FunctionByStart(e.Rva)).OfType<NativeFunction>())
        {
            for (uint at = fn.Start; at < fn.End && prepared == null; at += (uint)(index.Decode(at)?.Length ?? 1))
            {
                var code = X86Assembler.Assemble(index.Image.Arch, index.Image.ImageBase + at, "xor eax, eax\nret").Bytes;
                try { prepared = h.Edits.PrepareExtendedPatch(index, at, code, "xor eax, eax\nret", StubMode.Replace, "patch_asm (stub)", null, StubPlacement.Section); }
                catch (ToolError) { }
            }
            if (prepared != null) break;
        }
        Assert.NotNull(prepared);
        h.Edits.ApplyPatch(native, index, prepared, dryRun: false);
        var growth = Assert.Single(native.Patches.Patches).Growth!;
        var saved = h.Dir.File("grown-saved.bin");
        Assert.Contains("Verified", h.Edits.Save(native, saved, overwrite: true, stripSignature: false));
        var script = h.Dir.File("grown.ida");
        await h.Tools.ExportNativePatches(native.Id, script, "ida");

        var log = new List<string>();
        var python = PythonLocator.Find([], log);
        var ida = IdaInstallation.Locate(null, out var reason, out _);
        if (python == null || ida == null) { output.WriteLine("IDA not run: " + (python == null ? "no Python" : reason)); return; }
        var db = h.Dir.File("ida-input.dll");
        File.Copy(src, db);
        var driver = h.Dir.File("drive.py");
        File.WriteAllText(driver, """
            import os, sys
            sys.path.insert(0, os.path.join(os.environ["IDADIR"], "idalib", "python"))
            import idapro
            target, script, saved, name, rva, offset, size = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5], 16), int(sys.argv[6], 16), int(sys.argv[7], 16)
            if idapro.open_database(target, True) != 0:
                print("open failed"); sys.exit(2)
            import idaapi, ida_bytes, ida_segment
            def run():
                g = {"__name__": "__main__"}
                exec(compile(open(script, encoding="utf-8").read(), script, "exec"), g)
                return g["CORVUS_SEGMENTS_RESULT"], g["CORVUS_PATCH_RESULT"]
            (created, blocked), (applied, already, differ, missing) = run()
            ea = idaapi.get_imagebase() + rva
            seg = ida_segment.getseg(ea)
            data = open(saved, "rb").read()
            same = seg is not None and ida_bytes.get_bytes(ea, size) == data[offset:offset + size]
            segname = ida_segment.get_segm_name(seg) if seg is not None else "-"
            (created2, blocked2), (applied2, _, _, _) = run()
            print("RESULT %d %d %d %d %d %s %d %d %d" % (created, blocked, applied, differ, 1 if same else 0, segname, created2, blocked2, applied2))
            idapro.close_database(False)
            """);
        var env = new Dictionary<string, string?> { ["IDADIR"] = ida.Directory, ["TVHEADLESS"] = "1", ["IDA_IS_INTERACTIVE"] = null };
        var run = PythonLocator.RunCapture(python.Executable, ["-I", "-u", driver, db, script, saved, growth.SectionName, $"{growth.SectionRva:X}", $"{growth.AppendFileOffset:X}",
            $"{Math.Min(growth.AppendedData.Length, growth.SectionVirtualSize):X}"], TimeSpan.FromMinutes(5), env);
        output.WriteLine(run.Stdout);
        output.WriteLine(run.Stderr);
        var line = run.Stdout.Split('\n').FirstOrDefault(l => l.StartsWith("RESULT", StringComparison.Ordinal));
        Assert.True(line != null, $"no RESULT line (exit {run.ExitCode}, timed out {run.TimedOut}):\n{run.Stdout}\n{run.Stderr}");
        var f = line!.Trim().Split(' ');
        Assert.Equal(["1", "0"], f[1..3]);          // the segment was created
        Assert.True(int.Parse(f[3]) >= 1, line);    // the site jump applied
        Assert.Equal("0", f[4]);                    // no original bytes differed
        Assert.Equal("1", f[5]);                    // the segment holds the saved file's section bytes
        Assert.Equal(growth.SectionName, f[6]);
        Assert.Equal(["0", "0", "0"], f[7..10]);    // a second run reuses the segment and applies nothing
    }
}
