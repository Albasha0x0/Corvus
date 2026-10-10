using System.Diagnostics;
using System.Text.Json;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Function starts and direct call edges compared with IDA (idalib, auto-analysis, PDB loading off) on a few system
/// DLLs. Skipped when IDA or a Python that can import idapro is missing. NDM_IDA_ORACLE_FILES (paths separated by
/// ';') replaces the default sample. IDA results are cached per file hash under %TEMP%\ndm-ida-oracle.
/// </summary>
[Trait("Speed", "Slow")]
public class NativeCodeOracleTests(ITestOutputHelper output)
{
    private const string Script = """
        import sys, json
        import idapro
        rc = idapro.open_database(sys.argv[1], True, "-Opdb:off")
        if rc != 0:
            sys.exit(10 + rc)
        import ida_auto, ida_funcs, idautils, ida_nalt, ida_idp, ida_xref, ida_segment, idc
        ida_auto.auto_wait()
        base = ida_nalt.get_imagebase()
        def is_code(ea):
            s = ida_segment.getseg(ea)
            return s is not None and s.type == ida_segment.SEG_CODE
        funcs, thunks, calls, chunks = [], [], set(), []
        for ea in idautils.Functions():
            if not is_code(ea):
                continue
            f = ida_funcs.get_func(ea)
            funcs.append(ea - base)
            if f.flags & ida_funcs.FUNC_THUNK:
                thunks.append(ea - base)
            for c in idautils.Chunks(ea):
                chunks.append([c[0] - base, c[1] - base])
            for head in idautils.FuncItems(ea):
                # direct calls only: IDA also adds edges for calls through pointer variables, from their initial value
                if ida_idp.is_call_insn(head) and idc.get_operand_type(head, 0) in (idc.o_near, idc.o_far):
                    for x in idautils.XrefsFrom(head, ida_xref.XREF_FAR):
                        if x.type in (ida_xref.fl_CN, ida_xref.fl_CF) and is_code(x.to):
                            calls.add((head - base, x.to - base))
        import ida_bytes
        orphans = []
        for s in idautils.Segments():
            if not is_code(s):
                continue
            for h in idautils.Heads(s, ida_segment.getseg(s).end_ea):
                if ida_bytes.is_code(ida_bytes.get_flags(h)) and ida_funcs.get_func(h) is None:
                    orphans.append(h - base)
        json.dump({"functions": funcs, "thunks": thunks, "calls": sorted(calls), "chunks": chunks, "orphans": orphans}, open(sys.argv[2], "w"))
        idapro.close_database(False)
        """;

    /// <summary>IDA's functions, thunks, direct call edges, function chunks and code heads that belong to no function.</summary>
    private sealed record IdaResult(List<uint> Functions, List<uint> Thunks, List<List<uint>> Calls, List<List<uint>>? Chunks, List<uint>? Orphans);

    private static string? IdaDirectory()
    {
        if (!OperatingSystem.IsWindows()) return null;
        var config = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Hex-Rays", "IDA Pro", "ida-config.json");
        if (!File.Exists(config)) return null;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(config));
            var dir = doc.RootElement.GetProperty("Paths").GetProperty("ida-install-dir").GetString();
            return dir != null && File.Exists(Path.Combine(dir, "idalib.dll")) ? dir : null;
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException) { return null; }
    }

    private static IEnumerable<string> Samples()
    {
        if (RealData.Get("NDM_IDA_ORACLE_FILES") is { } list) return list.Split(';', StringSplitOptions.RemoveEmptyEntries);
        var sys32 = Environment.SystemDirectory;
        var wow = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");
        string[] names = ["version.dll", "cabinet.dll", "msvcp_win.dll", "wininet.dll"];
        return names.Select(n => Path.Combine(sys32, n)).Concat(names.Select(n => Path.Combine(wow, n))).Where(File.Exists);
    }

    [Fact]
    public void Function_starts_and_calls_match_ida()
    {
        var ida = IdaDirectory();
        if (ida == null) { output.WriteLine("IDA not found: skipped"); return; }
        var cache = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "ndm-ida-oracle")).FullName;
        File.WriteAllText(Path.Combine(cache, "oracle.py"), Script);

        var totals = new Dictionary<NativeArch, (int Ours, int Ida, int Both, int InIda, int OurCalls, int IdaCalls, int BothCalls)>();
        foreach (var path in Samples())
        {
            var image = CodeTestImage.Load(path);
            if (image.Arch is not (NativeArch.X86 or NativeArch.X64)) continue;
            var result = RunIda(ida, cache, path, image.Sha256);
            if (result == null) { output.WriteLine($"{path}: IDA run failed, skipped"); continue; }
            var sw = Stopwatch.StartNew();
            var index = NativeCodeIndex.Build(image);
            sw.Stop();

            var ours = index.Functions.Select(f => f.Start).ToHashSet();
            var theirs = result.Functions.ToHashSet();
            var both = ours.Intersect(theirs).Count();
            var ourCalls = new HashSet<(uint, uint)>();
            foreach (var f in index.Functions)
                foreach (var x in index.RefsFrom(f))
                    if (x.Kind == XrefKind.Call && image.SectionAt(x.To) is { IsExecutable: true }) ourCalls.Add((x.From, x.To));
            var idaCalls = result.Calls.Select(c => (c[0], c[1])).ToHashSet();
            int bothCalls = ourCalls.Intersect(idaCalls).Count();

            output.WriteLine($"{Path.GetFileName(Path.GetDirectoryName(path))}\\{Path.GetFileName(path)} ({image.Arch}, {sw.ElapsedMilliseconds} ms): " +
                $"functions ours {ours.Count} ida {theirs.Count} both {both} | precision {Ratio(both, ours.Count)} recall {Ratio(both, theirs.Count)} | " +
                $"calls ours {ourCalls.Count} ida {idaCalls.Count} precision {Ratio(bothCalls, ourCalls.Count)} recall {Ratio(bothCalls, idaCalls.Count)}");
            var missing = theirs.Except(ours).Order().ToList();
            var extra = ours.Except(theirs).Order().ToList();
            // where IDA has code we call a separate function: IDA made it a chunk of another function
            // or as code outside any function (IDA decoded it but made no function, e.g. x86 delay-load thunks)
            var chunks = (result.Chunks ?? []).Select(c => (Start: c[0], End: c[1])).OrderBy(c => c.Start).ToArray();
            var orphans = (result.Orphans ?? []).ToHashSet();
            bool InIdaChunk(uint a) => orphans.Contains(a) || chunks.Any(c => a >= c.Start && a < c.End);
            int extraInChunks = extra.Count(InIdaChunk);
            int missingInOurs = missing.Count(a => index.FunctionAt(a) != null);
            output.WriteLine($"  only IDA ({missing.Count}, {missingInOurs} inside one of our functions): " +
                string.Join(" ", missing.Take(14).Select(a => $"{a:X}{(result.Thunks.Contains(a) ? "(thunk)" : "")}{(index.FunctionAt(a) is { } o ? $"<{o.Start:X}" : "")}")));
            output.WriteLine($"  only ours ({extra.Count}, {extraInChunks} inside IDA functions): " +
                string.Join(" ", extra.Take(14).Select(a => $"{a:X}[{index.FunctionByStart(a)!.Sources}]{(InIdaChunk(a) ? "*" : "")}")));
            output.WriteLine("  only ours by source: " + string.Join(", ", extra.GroupBy(a => (index.FunctionByStart(a)!.Sources, InIdaChunk(a)))
                .OrderByDescending(g => g.Count()).Select(g => $"{g.Key.Sources}{(g.Key.Item2 ? " (in IDA function)" : "")} {g.Count()} e.g. {g.First():X}")));
            var callsMissing = idaCalls.Except(ourCalls).Order().ToList();
            if (callsMissing.Count > 0)
                output.WriteLine($"  calls only IDA ({callsMissing.Count}, {callsMissing.Count(c => index.FunctionAt(c.Item1) == null)} from code we did not reach): " +
                    string.Join(" ", callsMissing.Take(10).Select(c => $"{c.Item1:X}->{c.Item2:X}")));
            var t = totals.GetValueOrDefault(image.Arch);
            totals[image.Arch] = (t.Ours + ours.Count, t.Ida + theirs.Count, t.Both + both, t.InIda + extraInChunks,
                t.OurCalls + ourCalls.Count, t.IdaCalls + idaCalls.Count, t.BothCalls + bothCalls);
        }
        // "in IDA code": our extra starts that IDA has as code, inside one of its functions (.pdata funclets and
        // exception handler stubs IDA attaches to their parent function) or in no function
        foreach (var (arch, t) in totals)
            output.WriteLine($"TOTAL {arch}: functions precision {Ratio(t.Both, t.Ours)} (counting starts in IDA code {Ratio(t.Both + t.InIda, t.Ours)}) " +
                $"recall {Ratio(t.Both, t.Ida)}; calls precision {Ratio(t.BothCalls, t.OurCalls)} recall {Ratio(t.BothCalls, t.IdaCalls)}");
        foreach (var (arch, t) in totals)
        {
            // floors below the measured values: a regression check, not a target
            Assert.True(t.Both + t.InIda >= 0.97 * t.Ours, $"{arch} function precision {Ratio(t.Both + t.InIda, t.Ours)}");
            // exception funclets and handlers attached to their functions (IDA keeps x64 C++ funclets as functions, as we do)
            Assert.True(t.Both >= (arch == NativeArch.X64 ? 0.99 : 0.93) * t.Ours, $"{arch} strict function precision {Ratio(t.Both, t.Ours)}");
            Assert.True(t.Both >= (arch == NativeArch.X64 ? 0.99 : 0.95) * t.Ida, $"{arch} function recall {Ratio(t.Both, t.Ida)}");
            Assert.True(t.BothCalls >= 0.98 * t.OurCalls, $"{arch} call precision {Ratio(t.BothCalls, t.OurCalls)}");
            Assert.True(t.BothCalls >= (arch == NativeArch.X64 ? 0.99 : 0.95) * t.IdaCalls, $"{arch} call recall {Ratio(t.BothCalls, t.IdaCalls)}");
        }
    }

    private static string Ratio(int a, int b) => b == 0 ? "n/a" : $"{100.0 * a / b:F2}%";

    private IdaResult? RunIda(string ida, string cache, string path, string sha)
    {
        string scriptVersion = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(Script)))[..8];
        var cached = Path.Combine(cache, $"{sha}-{scriptVersion}.json");
        if (!File.Exists(cached))
        {
            var work = Directory.CreateDirectory(Path.Combine(cache, sha)).FullName;
            var copy = Path.Combine(work, Path.GetFileName(path));
            File.Copy(path, copy, overwrite: true);
            var psi = new ProcessStartInfo("python");
            psi.ArgumentList.Add(Path.Combine(cache, "oracle.py"));
            psi.ArgumentList.Add(copy);
            psi.ArgumentList.Add(cached + ".tmp");
            psi.Environment["IDADIR"] = ida;
            psi.Environment["PYTHONPATH"] = Path.Combine(ida, "idalib", "python");
            var (code, text) = Tools.Run(psi, timeoutMs: 1_200_000);
            try { Directory.Delete(work, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            if (code != 0 || !File.Exists(cached + ".tmp"))
            {
                output.WriteLine($"idalib exit {code}: {text[..Math.Min(text.Length, 400)]}");
                return null;
            }
            File.Move(cached + ".tmp", cached, overwrite: true);
        }
        return JsonSerializer.Deserialize<IdaResult>(File.ReadAllText(cached), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    }
}
