using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Core.Pcap;
using Corvus.Native.Providers;
using Xunit.Abstractions;
using static Corvus.Tests.CaptureObjectsTests;
using static Corvus.Tests.PcapTests;

namespace Corvus.Tests;

/// <summary>HTTP objects from captures compared with TShark --export-objects (CORVUS_TSHARK); CORVUS_CAPTURES adds real captures.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class CaptureObjectsTSharkTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private static byte[] A(string s) => Encoding.ASCII.GetBytes(s);

    private static byte[] Compress(byte[] data, Func<Stream, Stream> wrap)
    {
        var ms = new MemoryStream();
        using (var s = wrap(ms)) s.Write(data);
        return ms.ToArray();
    }

    /// <summary>One connection per body framing: Content-Length, chunked, codings, pipelining, resent segments, ranges, bodies ending at close.</summary>
    private static List<(string Name, byte[] Capture)> Synthetic()
    {
        var text = string.Concat(Enumerable.Range(0, 400).Select(i => $"line {i}\n"));
        var gzip = Compress(A(text), s => new GZipStream(s, CompressionLevel.Optimal, leaveOpen: true));
        var zlib = Compress(A(text), s => new ZLibStream(s, CompressionLevel.Optimal, leaveOpen: true));
        var brotli = Compress(A(text), s => new BrotliStream(s, CompressionLevel.Optimal, leaveOpen: true));
        string Chunks(byte[] body, int size) => string.Concat(body.Chunk(size).Select(c => $"{c.Length:x}\r\n{Encoding.Latin1.GetString(c)}\r\n")) + "0\r\n\r\n";
        static string Get(string path) => $"GET {path} HTTP/1.1\r\nHost: files.example.com\r\n\r\n";
        var cases = new List<(string, List<(bool, byte[])>, int, bool)>
        {
            ("length", [(true, A(Get("/a.txt"))), (false, A($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {text.Length}\r\n\r\n{text}"))], 1400, false),
            ("chunked", [(true, A(Get("/b.txt"))), (false, A($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n{Chunks(A(text), 700)}"))], 1400, false),
            ("chunked-gzip", [(true, A(Get("/c.txt"))), (false, Encoding.Latin1.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n{Chunks(gzip, 300)}"))], 1400, false),
            ("deflate", [(true, A(Get("/d.txt"))), (false, [.. A($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: deflate\r\nContent-Length: {zlib.Length}\r\n\r\n"), .. zlib])], 1400, false),
            ("brotli", [(true, A(Get("/e.txt"))), (false, [.. A($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: br\r\nContent-Length: {brotli.Length}\r\n\r\n"), .. brotli])], 1400, false),
            ("pipelined", [(true, A(Get("/p1.txt") + Get("/p2.txt") + Get("/p3.txt"))),
                (false, A(string.Concat(new[] { "one", "two two", "three three three" }.Select(b => $"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {b.Length}\r\n\r\n{b}"))))], 1400, false),
            ("resent", [(true, A(Get("/r.txt"))), (false, A($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {text.Length}\r\n\r\n{text}"))], 300, true),
            ("range", [(true, A("GET /big.bin HTTP/1.1\r\nHost: files.example.com\r\nRange: bytes=100-199\r\n\r\n")),
                (false, A($"HTTP/1.1 206 Partial Content\r\nContent-Type: application/octet-stream\r\nContent-Range: bytes 100-199/4000\r\nContent-Length: 100\r\n\r\n{text[100..200]}"))], 1400, false),
            ("until-close", [(true, A("GET /old.txt HTTP/1.0\r\nHost: files.example.com\r\n\r\n")), (false, A($"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n{text}"))], 1400, false),
            ("post", [(true, A($"POST /upload HTTP/1.1\r\nHost: files.example.com\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nhello world")),
                (false, A("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 9\r\n\r\n{\"id\":42}"))], 1400, false),
            ("continue", [(true, A("POST /form HTTP/1.1\r\nHost: files.example.com\r\nContent-Type: text/plain\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n")),
                (false, A("HTTP/1.1 100 Continue\r\n\r\n")), (true, A("data")), (false, A("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"))], 1400, false),
            ("no-body", [(true, A("HEAD /h.txt HTTP/1.1\r\nHost: files.example.com\r\n\r\n")), (false, A("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 50\r\n\r\n")),
                (true, A(Get("/n.txt"))), (false, A("HTTP/1.1 304 Not Modified\r\n\r\n")), (true, A(Get("/z.txt"))), (false, A("HTTP/1.1 204 No Content\r\n\r\n"))], 1400, false),
        };
        return [.. cases.Select((c, i) => (c.Item1, Pcap(Connection((ushort)(52000 + i), 80, c.Item2, c.Item3, c.Item4))))];
    }

    [Permit("reference-tool")]
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_TSHARK")]
    public void Synthetic_captures_export_the_objects_tshark_exports()
    {
        var results = Synthetic().Select(c =>
        {
            var path = _dir.File(c.Name + ".pcap");
            File.WriteAllBytes(path, c.Capture);
            return Compare(path, null);
        }).ToList();
        Assert.True(results.All(r => r.Agrees), Report(results));
        output.WriteLine(Report(results));
    }

    [Permit("reference-tool")]
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_TSHARK", "CORVUS_CAPTURES")]
    public void Real_captures_export_every_object_tshark_exports()
    {
        var root = RealData.Path("CORVUS_CAPTURES");
        var results = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Where(IsCapture).Order().Select(path =>
        {
            var stem = Path.GetFileName(path).Split('.')[0];
            var keys = Directory.EnumerateFiles(Path.GetDirectoryName(path)!, stem + "*")
                .FirstOrDefault(f => f.EndsWith(".keys", StringComparison.OrdinalIgnoreCase) || Path.GetFileName(f).Contains("keylog", StringComparison.OrdinalIgnoreCase));
            return Compare(path, keys);
        }).Where(r => r.Theirs.Count + r.Ours.Count + r.Fragments > 0 || r.Unread != null).ToList();
        var report = Report(results);
        output.WriteLine(report);
        Assert.True(results.All(r => r.Match().OnlyTheirs.Count == 0), report);
    }

    private static Stream Open(string path)
    {
        var raw = File.OpenRead(path);
        return path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ? new GZipStream(raw, CompressionMode.Decompress) : raw;
    }

    private static bool IsCapture(string path)
    {
        var head = new byte[4];
        using var s = Open(path);
        try { return s.ReadAtLeast(head, 4, throwOnEndOfStream: false) == 4 && PcapReader.Looks(head); }
        catch (InvalidDataException) { return false; }
    }

    /// <summary>
    /// One capture's objects. Fragments: TShark's object&lt;frame&gt; files from frames that start no HTTP message (the bytes
    /// after a lost head, not a body); Unread: why TShark could not read the capture.
    /// </summary>
    private sealed record Result(string Capture, List<(string Name, string Sha)> Theirs, List<(string Name, string Sha)> Ours, int Fragments, string? Unread)
    {
        /// <summary>TShark's objects matched by content; the rest on either side.</summary>
        public (int Matched, int Named, List<string> OnlyTheirs, List<string> OnlyOurs) Match()
        {
            var ours = Ours.ToList();
            var onlyTheirs = new List<string>();
            int matched = 0, named = 0;
            foreach (var t in Theirs)
            {
                int at = ours.FindIndex(o => o.Sha == t.Sha && Stem(o.Name, true) == Stem(t.Name, false));
                if (at < 0) at = ours.FindIndex(o => o.Sha == t.Sha);
                else named++;
                if (at < 0) { onlyTheirs.Add($"{t.Name} {t.Sha[..12]}"); continue; }
                matched++;
                ours.RemoveAt(at);
            }
            return (matched, named, onlyTheirs, [.. ours.Select(o => $"{o.Name} {o.Sha[..12]}")]);
        }

        /// <summary>The URL's last segment without extension: ours drop the folded query, TShark's its "(n)" duplicate counter; "/" is index.</summary>
        private static string Stem(string name, bool ours)
        {
            if (ours) return Regex.Replace(Path.GetFileNameWithoutExtension(name.Split('/')[^1]), "_q[0-9a-f]{8}$", "");
            var file = Uri.UnescapeDataString(Regex.Replace(name, @"\(\d+\)(?=\.|$)", "")).Split('?')[0];
            return file is "\\" or "/" or "" ? "index" : Path.GetFileNameWithoutExtension(file);
        }

        public bool Agrees => Match() is var m && m.OnlyTheirs.Count == 0 && m.OnlyOurs.Count == 0;
    }

    private static string Report(List<Result> results)
    {
        var sb = new StringBuilder();
        int theirs = 0, matched = 0, named = 0, ours = 0;
        foreach (var r in results)
        {
            if (r.Unread != null) { sb.AppendLine($"{r.Capture}: not read by tshark ({r.Unread}); ours {r.Ours.Count}"); continue; }
            var (m, n, onlyTheirs, onlyOurs) = r.Match();
            (theirs, matched, named, ours) = (theirs + r.Theirs.Count, matched + m, named + n, ours + r.Ours.Count);
            sb.AppendLine($"{r.Capture}: tshark {r.Theirs.Count}, ours {r.Ours.Count}, {m} equal ({n} by name too)" + (r.Fragments > 0 ? $"; {r.Fragments} tshark fragment(s) after a lost head" : "") +
                          (onlyTheirs.Count > 0 ? "; only tshark: " + string.Join(", ", onlyTheirs) : "") + (onlyOurs.Count > 0 ? "; only ours: " + string.Join(", ", onlyOurs) : ""));
        }
        sb.AppendLine($"{matched} of {theirs} tshark objects equal byte for byte ({named} under the same name; {ours} ours); {results.Count(r => r.Unread == null && r.Agrees)} of {results.Count(r => r.Unread == null)} captures agree file by file");
        return sb.ToString();
    }

    private Result Compare(string capture, string? keyLog)
    {
        var tool = ExternalTools.TShark;
        var exe = ExternalTools.Locate(tool)!.Value.Path;
        var keyArgs = keyLog != null ? ExternalTools.Arguments(tool, "key-log", ("keys", keyLog)) : [];
        var outDir = Directory.CreateDirectory(_dir.File(Path.GetFileName(capture) + "_tshark")).FullName;
        var run = ExternalTools.Run(exe, [.. ExternalTools.Arguments(tool, "export-objects", ("file", capture), ("out", outDir)), .. keyArgs], TimeSpan.FromMinutes(5), 1 << 20, default);
        Assert.True(run.StartError == null && !run.TimedOut, $"{capture}: {run.StartError ?? run.Stderr}");
        string? unread = run.ExitCode != 0 ? run.Stderr.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.Length > 0) : null;
        var messages = ExternalTools.Run(exe, [.. ExternalTools.Arguments(tool, "http-messages", ("file", capture)), .. keyArgs], TimeSpan.FromMinutes(5), 16 << 20, default)
            .Text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet();
        var theirs = new List<(string, string)>();
        int fragments = 0;
        foreach (var file in Directory.EnumerateFiles(outDir))
        {
            var name = Path.GetFileName(file);
            if (Regex.Match(name, @"^object(\d+)") is { Success: true } m && !messages.Contains(m.Groups[1].Value)) fragments++;
            else theirs.Add((name, Sha(File.ReadAllBytes(file))));
        }

        TlsKeyLog? keys = null;
        if (keyLog != null) { keys = new TlsKeyLog(); keys.Add(File.ReadAllText(keyLog)); }
        using var stream = Open(capture);
        var contents = CaptureObjects.Read(stream, keys, AnalysisLimits.Default, default).Contents;
        var ours = contents.Items.Where(i => i.Origin.StartsWith("capture re", StringComparison.Ordinal)).Select(i => (i.Name, Sha(i.Bytes))).ToList();
        return new Result(Path.GetFileName(capture), theirs, ours, fragments, unread);
    }

    private static string Sha(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
}