using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>WebGL builds: the version file and metadata from the WebPlayerData .data, unpacked to a cache folder laid out as Data/.</summary>
internal static class WebGlBuild
{
    /// <summary>A file in the extracted folder that marks it as a WebGL build.</summary>
    public const string Marker = ".webgl";
    // Bump when what is extracted changes.
    private const int Format = 2;
    private const int VersionHeaderBytes = 1 << 16;
    private const long MaxBytes = 2L << 30;

    public sealed record Build(string Data, string? Code);

    /// <summary>The build's data and code files when <paramref name="full"/> is a WebGL build, its Build folder or its .data file.</summary>
    public static Build? Find(string full)
    {
        if (File.Exists(full) && !IsData(full)) return null;
        var dir = File.Exists(full) ? Path.GetDirectoryName(full)! : full;
        foreach (var d in new[] { dir, Path.Combine(dir, "Build") }.Where(Directory.Exists))
        {
            var files = Directory.EnumerateFiles(d).Take(256).ToList();
            var data = File.Exists(full) && IsData(full) ? full : files.FirstOrDefault(IsData);
            if (data == null) continue;
            return new Build(data, files.FirstOrDefault(f => Path.GetFileName(f).Contains(".wasm", StringComparison.OrdinalIgnoreCase)));
        }
        return null;
    }

    private static bool IsData(string f)
    {
        var name = Path.GetFileName(f).ToLowerInvariant();
        return name.EndsWith(".data") || name.EndsWith(".data.gz") || name.EndsWith(".data.br") || name.EndsWith(".data.unityweb");
    }

    /// <summary>The extracted build folder; <paramref name="notes"/> gets the code's facts.</summary>
    public static string Extract(Build build, string cacheRoot, List<string> notes, CancellationToken ct)
    {
        var bytes = Decompress(File.ReadAllBytes(build.Data), build.Data);
        var sha = Convert.ToHexStringLower(SHA256.HashData(bytes));
        var root = Path.Combine(cacheRoot, "webgl", $"{sha[..16]}-{Format}", "app");
        if (!File.Exists(Path.Combine(root, Marker)))
        {
            var data = Path.Combine(root, "Data");
            Directory.CreateDirectory(Path.Combine(data, "Managed", "Metadata"));
            foreach (var (name, offset, size) in Entries(bytes, build.Data))
            {
                ct.ThrowIfCancellationRequested();
                var target = name switch
                {
                    "data.unity3d" or "globalgamemanagers" => Path.Combine(data, name),
                    _ when name.EndsWith("Metadata/global-metadata.dat", StringComparison.Ordinal) => Path.Combine(data, "Managed", "Metadata", "global-metadata.dat"),
                    _ => null,
                };
                if (target != null)
                    File.WriteAllBytes(target, bytes.AsSpan(offset, name == "data.unity3d" ? Math.Min(size, VersionHeaderBytes) : size).ToArray());
            }
            File.WriteAllText(Path.Combine(root, Marker), build.Data);
        }
        if (build.Code is { } code)
            try
            {
                var wasm = Decompress(File.ReadAllBytes(code), code);
                var module = WasmModule.Read(wasm);
                notes.Add($"WebGL code: {Path.GetFileName(code)}, WebAssembly, {wasm.Length:N0} bytes, {module.DefinedFunctions:N0} functions, {module.Imports.Count:N0} imports; summarize_file view=wasm lists them.");
            }
            catch (ToolError e) { notes.Add($"WebGL code {Path.GetFileName(code)}: {e.Message}"); }
        return root;
    }

    /// <summary>gzip by its magic, the plain table, else brotli (the build writes no brotli magic).</summary>
    private static byte[] Decompress(byte[] raw, string file)
    {
        if (raw.AsSpan().StartsWith("UnityWebData"u8) || WasmModule.IsWasm(raw)) return raw;
        try
        {
            using Stream inner = raw.Length > 2 && raw[0] == 0x1F && raw[1] == 0x8B
                ? new GZipStream(new MemoryStream(raw), CompressionMode.Decompress)
                : new BrotliStream(new MemoryStream(raw), CompressionMode.Decompress);
            using var output = new MemoryStream();
            var buffer = new byte[1 << 16];
            for (int n; (n = inner.Read(buffer)) > 0;)
            {
                if (output.Length + n > MaxBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{file} decompresses past {MaxBytes:N0} bytes.");
                output.Write(buffer, 0, n);
            }
            return output.ToArray();
        }
        catch (InvalidDataException e)
        {
            throw new ToolError(ErrorCode.MalformedInput, $"{file} is neither a WebPlayerData file nor gzip or brotli compressed: {e.Message}");
        }
    }

    /// <summary>"UnityWebData1.0\0", the header length, then (offset, size, name length, name) per file.</summary>
    internal static List<(string Name, int Offset, int Size)> Entries(byte[] d, string file)
    {
        if (!d.AsSpan().StartsWith("UnityWebData1.0\0"u8) || d.Length < 20)
            throw new ToolError(ErrorCode.MalformedInput, $"{file} is not a WebPlayerData file.");
        var entries = new List<(string, int, int)>();
        uint header = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(16));
        for (long p = 20; p + 12 <= Math.Min(header, (uint)d.Length);)
        {
            uint offset = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan((int)p)), size = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan((int)p + 4)),
                length = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan((int)p + 8));
            p += 12;
            if (length > 4096 || p + length > d.Length || (long)offset + size > d.Length) throw new ToolError(ErrorCode.MalformedInput, $"{file}: a file entry runs past the end.");
            entries.Add((Encoding.UTF8.GetString(d, (int)p, (int)length), (int)offset, (int)size));
            p += length;
        }
        return entries;
    }
}
