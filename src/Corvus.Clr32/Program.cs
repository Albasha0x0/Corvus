using System.Collections;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Diagnostics.Runtime;
using Corvus.Native.Dump.Managed;

namespace Corvus.Clr32;

/// <summary>Decodes the CLR of a 32-bit dump or process for the 64-bit server: one JSON request and answer per line.</summary>
/// <remarks>Arguments: the dump (or --pid and the id), the verified DAC, its SHA-256 (checked again before loading) and the image folders. Answers are {"ok":true,"value":...} or {"ok":false,"error":"..."}; the first answers the open.</remarks>
internal static class Program
{
    private static int Main(string[] args)
    {
        var stdout = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };
        var stdin = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false));
        bool live = args.Length > 0 && args[0] == "--pid";
        if (live) args = args.Skip(1).ToArray();
        if (args.Length < 3)
        {
            stdout.WriteLine(Error("usage: <dump> | --pid <pid>, then <dac> <sha256> [imageDirectories]"));
            return 2;
        }
        DataTarget target;
        ClrReads reads;
        try { (target, reads) = Open(live, args[0], args[1], args[2], args.Length > 3 ? args[3] : ""); }
        catch (Exception ex)
        {
            stdout.WriteLine(Error(ex.Message));
            return 1;
        }
        using (target)
        {
            var process = target.DataReader as HeldThreadReader;
            var liveReads = process != null ? new ClrLiveReads(reads.Runtime) : null;
            stdout.WriteLine(Ok(new { Runtime = reads.Runtime.ClrInfo.Version.ToString() }));
            while (stdin.ReadLine() is { } line)
            {
                var f = line.Split('\t');
                if (f[0] == "exit") break;
                string answer;
                try { answer = Ok(liveReads != null && process != null && Live(liveReads, process, f, out var value) ? value : Handle(reads, f)); }
                catch (Exception ex) { answer = Error(ex.Message); }
                stdout.WriteLine(answer);
            }
        }
        return 0;
    }

    private static (DataTarget, ClrReads) Open(bool live, string source, string dac, string sha256, string imageDirectories)
    {
        // A running process's thread contexts are the ones the server sends.
        var target = live
            ? new DataTarget(new CustomDataTarget(new HeldThreadReader(DataTarget.AttachToProcess(int.Parse(source, CultureInfo.InvariantCulture), suspend: false))))
            : DataTarget.LoadDump(source);
        try
        {
            target.FileLocator = new FolderLocator(imageDirectories.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries));
            var clr = target.ClrVersions.FirstOrDefault() ?? throw new InvalidOperationException("no CLR in the dump");
            // Held open without write sharing from the hash check until the library is loaded.
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

    /// <summary>The requests about a running process; false for the others.</summary>
    private static bool Live(ClrLiveReads reads, HeldThreadReader process, string[] f, out object? value)
    {
        uint U32(int i) => uint.Parse(f[i], CultureInfo.InvariantCulture);
        int I32(int i) => int.Parse(f[i], CultureInfo.InvariantCulture);
        switch (f[0])
        {
            case "refresh":
                process.FlushCachedData();
                reads.Refresh();
                value = null;
                return true;
            case "method_at":
                value = reads.MethodAt(ulong.Parse(f[1], CultureInfo.InvariantCulture));
                return true;
            case "live_frames":
                var registers = f[3].Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries).Select(r => r.Split('='))
                    .Where(r => r.Length == 2).ToDictionary(r => r[0], r => r[1], StringComparer.OrdinalIgnoreCase);
                if (!process.SetContext(U32(1), registers)) value = new List<ulong>();
                else
                {
                    try { value = reads.Frames(U32(1), I32(2)); }
                    finally { process.ClearContext(U32(1)); }
                }
                return true;
            case "code_of":
                value = reads.CodeOf(f[1], I32(2), I32(3));
                return true;
            case "module_image":
                value = reads.ModuleImage(f[1]);
                return true;
            case "prepared":
                value = reads.Prepared(f[1]);
                return true;
            default:
                value = null;
                return false;
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

    /// <summary>ClrMD's process reader, except thread contexts come only from a stop's registers.</summary>
    private sealed class HeldThreadReader(DataTarget process) : IDataReader, IDisposable
    {
        private readonly IDataReader _inner = process.DataReader;
        private readonly Dictionary<uint, byte[]> _contexts = new();

        public bool SetContext(uint thread, IReadOnlyDictionary<string, string> registers)
        {
            if (StopContext.From(_inner.Architecture, registers) is not { } c) return false;
            _contexts[thread] = c;
            return true;
        }

        public void ClearContext(uint thread) => _contexts.Remove(thread);

        public string DisplayName => _inner.DisplayName;
        public bool IsThreadSafe => false;
        public OSPlatform TargetPlatform => _inner.TargetPlatform;
        public Architecture Architecture => _inner.Architecture;
        public int ProcessId => _inner.ProcessId;
        public int PointerSize => _inner.PointerSize;
        public IEnumerable<ModuleInfo> EnumerateModules() => _inner.EnumerateModules();

        public bool GetThreadContext(uint threadID, uint contextFlags, Span<byte> context)
        {
            if (!_contexts.TryGetValue(threadID, out var bytes)) return false;
            context.Clear();
            bytes.AsSpan(0, Math.Min(bytes.Length, context.Length)).CopyTo(context);
            return true;
        }

        public void FlushCachedData() => _inner.FlushCachedData();
        public int Read(ulong address, Span<byte> buffer) => _inner.Read(address, buffer);
        public bool Read<T>(ulong address, out T value) where T : unmanaged => _inner.Read(address, out value);
        public T Read<T>(ulong address) where T : unmanaged => _inner.Read<T>(address);
        public bool ReadPointer(ulong address, out ulong value) => _inner.ReadPointer(address, out value);
        public ulong ReadPointer(ulong address) => _inner.ReadPointer(address);
        public void Dispose() => process.Dispose();
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
