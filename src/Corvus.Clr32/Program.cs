using System.Collections;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Diagnostics.Runtime;
using Corvus.Native.Dump.Managed;

namespace Corvus.Clr32;

/// <summary>
/// Decodes the CLR of a 32-bit dump for the 64-bit server: arguments are the dump, the DAC the server found and verified,
/// that file's SHA-256 (checked again here before the library is loaded) and the image folders. Then one request per
/// stdin line (facts, exception, frames, walk, object, exit), one JSON line per answer: {"ok":true,"value":...} or
/// {"ok":false,"error":"..."}. The first line answers the open.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        var stdout = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };
        var stdin = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false));
        if (args.Length < 3)
        {
            stdout.WriteLine(Error("usage: <dump> <dac> <sha256> [imageDirectories]"));
            return 2;
        }
        DataTarget target;
        ClrReads reads;
        try { (target, reads) = Open(args[0], args[1], args[2], args.Length > 3 ? args[3] : ""); }
        catch (Exception ex)
        {
            stdout.WriteLine(Error(ex.Message));
            return 1;
        }
        using (target)
        {
            stdout.WriteLine(Ok(new { Runtime = reads.Runtime.ClrInfo.Version.ToString() }));
            while (stdin.ReadLine() is { } line)
            {
                var f = line.Split('\t');
                if (f[0] == "exit") break;
                string answer;
                try { answer = Ok(Handle(reads, f)); }
                catch (Exception ex) { answer = Error(ex.Message); }
                stdout.WriteLine(answer);
            }
        }
        return 0;
    }

    private static (DataTarget, ClrReads) Open(string dump, string dac, string sha256, string imageDirectories)
    {
        var target = DataTarget.LoadDump(dump);
        try
        {
            target.FileLocator = new FolderLocator(imageDirectories.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries));
            var clr = target.ClrVersions.FirstOrDefault() ?? throw new InvalidOperationException("no CLR in the dump");
            // held open without write sharing from the hash check until the library is loaded
            using var file = new FileStream(dac, FileMode.Open, FileAccess.Read, FileShare.Read);
            using (var sha = SHA256.Create())
            {
                var hash = string.Concat(sha.ComputeHash(file).Select(b => b.ToString("x2", CultureInfo.InvariantCulture)));
                if (!hash.Equals(sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException($"the DAC file changed after it was verified (SHA-256 {hash})");
            }
            return (target, new ClrReads(clr.CreateRuntime(dac)));
        }
        catch
        {
            target.Dispose();
            throw;
        }
    }

    private static object? Handle(ClrReads reads, string[] f)
    {
        uint U32(int i) => uint.Parse(f[i], CultureInfo.InvariantCulture);
        int I32(int i) => int.Parse(f[i], CultureInfo.InvariantCulture);
        ulong U64(int i) => ulong.Parse(f[i], CultureInfo.InvariantCulture);
        return f[0] switch
        {
            "facts" => reads.Facts(),
            "exception" => reads.Exception(f[1] == "-" ? null : U32(1)),
            "frames" => reads.Frames(U32(1), I32(2)),
            "walk" => reads.Walk(f[1] == "-" ? null : f[1], U64(2), long.Parse(f[3], CultureInfo.InvariantCulture), I32(4), I32(5), CancellationToken.None),
            "object" => reads.Object(U64(1), I32(2), I32(3), I32(4)),
            _ => throw new InvalidOperationException($"unknown request '{f[0]}'"),
        };
    }

    private static string Ok(object? value)
    {
        var sb = new StringBuilder("{\"ok\":true,\"value\":");
        Write(sb, value);
        return sb.Append('}').ToString();
    }

    private static string Error(string message)
    {
        var sb = new StringBuilder("{\"ok\":false,\"error\":");
        Write(sb, message);
        return sb.Append('}').ToString();
    }

    /// <summary>JSON of the shared records: public properties in camel case, numbers exact, Guids as strings.</summary>
    private static void Write(StringBuilder sb, object? value)
    {
        switch (value)
        {
            case null: sb.Append("null"); return;
            case string s: String(sb, s); return;
            case bool b: sb.Append(b ? "true" : "false"); return;
            case Guid g: String(sb, g.ToString("D")); return;
            case IFormattable n when value.GetType().IsPrimitive: sb.Append(n.ToString(null, CultureInfo.InvariantCulture)); return;
            case IEnumerable list:
                sb.Append('[');
                bool firstItem = true;
                foreach (var item in list)
                {
                    if (!firstItem) sb.Append(',');
                    firstItem = false;
                    Write(sb, item);
                }
                sb.Append(']');
                return;
        }
        sb.Append('{');
        bool first = true;
        foreach (var p in value.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (p.GetIndexParameters().Length > 0) continue;
            if (!first) sb.Append(',');
            first = false;
            String(sb, char.ToLowerInvariant(p.Name[0]) + p.Name.Substring(1));
            sb.Append(':');
            Write(sb, p.GetValue(value));
        }
        sb.Append('}');
    }

    private static void String(StringBuilder sb, string s)
    {
        sb.Append('"');
        foreach (char c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20 || char.IsSurrogate(c)) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }

    /// <summary>Module images from the given folders, by name, timestamp and size; never the network.</summary>
    private sealed class FolderLocator(string[] directories) : IFileLocator
    {
        public string? FindPEImage(string fileName, int buildTimeStamp, int imageSize, bool checkProperties)
        {
            var name = Path.GetFileName(fileName);
            var candidates = new List<string>();
            if (Path.IsPathRooted(fileName)) candidates.Add(fileName);
            if (name.Length > 0 && name.IndexOfAny(Path.GetInvalidFileNameChars()) < 0) candidates.AddRange(directories.Select(d => Path.Combine(d, name)));
            foreach (var c in candidates)
                if (File.Exists(c) && Matches(c, buildTimeStamp, imageSize)) return c;
            return null;
        }

        private static bool Matches(string path, int stamp, int size)
        {
            try
            {
                using var s = File.OpenRead(path);
                var head = new byte[4096];
                int n = s.Read(head, 0, head.Length);
                if (n < 0x40 || head[0] != 'M' || head[1] != 'Z') return false;
                int pe = BitConverter.ToInt32(head, 0x3C);
                if (pe < 0 || pe + 24 + 60 > n) return false;
                return BitConverter.ToInt32(head, pe + 8) == stamp && BitConverter.ToInt32(head, pe + 24 + 56) == size;
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        }

        public string? FindPEImage(string fileName, SymbolProperties archivedUnder, System.Collections.Immutable.ImmutableArray<byte> buildIdOrUUID, OSPlatform originalPlatform, bool checkProperties) => null;
        public string? FindElfImage(string fileName, SymbolProperties archivedUnder, System.Collections.Immutable.ImmutableArray<byte> buildId, bool checkProperties) => null;
        public string? FindMachOImage(string fileName, SymbolProperties archivedUnder, System.Collections.Immutable.ImmutableArray<byte> uuid, bool checkProperties) => null;
    }
}
