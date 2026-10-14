using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Corvus.Tests;

/// <summary>Builds ASAR archives in the @electron/asar layout.</summary>
public static class AsarWriter
{
    /// <summary>A file to pack: path with '/' separators; Unpacked files are only declared in the header.</summary>
    public sealed record File(string Path, byte[] Bytes, bool Unpacked = false, bool Executable = false, bool Integrity = true);

    public static File Text(string path, string text, bool unpacked = false) => new(path, Encoding.UTF8.GetBytes(text), unpacked);

    /// <summary>The archive bytes and its header JSON (whose SHA-256 is the header hash); editHeader rewrites the JSON text.</summary>
    public static (byte[] Archive, byte[] Header) Build(IEnumerable<File> files, IEnumerable<(string Path, string Target)>? links = null,
        int blockSize = 4 * 1024 * 1024, Func<string, string>? editHeader = null)
    {
        var root = new SortedDictionary<string, object>(StringComparer.Ordinal);
        using var data = new MemoryStream();
        foreach (var f in files)
        {
            var node = new Dictionary<string, object> { ["size"] = f.Bytes.Length };
            if (f.Unpacked) node["unpacked"] = true;
            else
            {
                node["offset"] = data.Length.ToString(CultureInfo.InvariantCulture);
                data.Write(f.Bytes);
            }
            if (f.Executable) node["executable"] = true;
            if (f.Integrity)
            {
                var blocks = new List<string>();
                int at = 0;
                do
                {
                    blocks.Add(Convert.ToHexStringLower(SHA256.HashData(f.Bytes.AsSpan(at, Math.Min(blockSize, f.Bytes.Length - at)))));
                    at += blockSize;
                } while (at < f.Bytes.Length);
                node["integrity"] = new Dictionary<string, object>
                {
                    ["algorithm"] = "SHA256", ["hash"] = Convert.ToHexStringLower(SHA256.HashData(f.Bytes)), ["blockSize"] = blockSize, ["blocks"] = blocks,
                };
            }
            Place(root, f.Path, node);
        }
        foreach (var (path, target) in links ?? []) Place(root, path, new Dictionary<string, object> { ["link"] = target });
        var json = JsonSerializer.Serialize(new Dictionary<string, object> { ["files"] = root });
        if (editHeader != null) json = editHeader(json);
        var header = Encoding.UTF8.GetBytes(json);
        int padded = (header.Length + 3) & ~3;
        var output = new byte[16 + padded + data.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(output, 4);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(4), (uint)(padded + 8));
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(8), (uint)(padded + 4));
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(12), (uint)header.Length);
        header.CopyTo(output, 16);
        data.ToArray().CopyTo(output, 16 + padded);
        return (output, header);
    }

    private static void Place(SortedDictionary<string, object> root, string path, Dictionary<string, object> node)
    {
        var parts = path.Split('/');
        var dir = root;
        foreach (var part in parts[..^1])
        {
            if (!dir.TryGetValue(part, out var sub))
                dir[part] = sub = new Dictionary<string, object> { ["files"] = new SortedDictionary<string, object>(StringComparer.Ordinal) };
            dir = (SortedDictionary<string, object>)((Dictionary<string, object>)sub)["files"];
        }
        dir[parts[^1]] = node;
    }
}
