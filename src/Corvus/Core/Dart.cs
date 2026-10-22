using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;

namespace Corvus.Core;

/// <summary>
/// A Dart snapshot header: file offset, kind, total length, the 32-character version hash the VM checks and the features
/// string (build mode, target architecture and OS, VM flags) it was compiled with.
/// </summary>
public sealed record DartSnapshot(long Offset, string Kind, long Length, string Hash, string Features)
{
    /// <summary>Set when a symbol (_kDartVmSnapshotData, _kDartIsolateSnapshotData) names the header's address.</summary>
    public string? Symbol { get; init; }

    private static readonly string[] Architectures = ["x64", "ia32", "arm", "arm64", "riscv32", "riscv64", "simarm", "simarm64"];
    private static readonly string[] Systems = ["android", "ios", "linux", "macos", "windows", "fuchsia"];

    public string? Mode => Tokens.FirstOrDefault(t => t is "product" or "release" or "debug" or "profile");
    /// <summary>The target architecture; older features strings add the ABI ("arm64-sysv").</summary>
    public string? Architecture => Tokens.Select(t => t.Split('-')[0]).FirstOrDefault(t => Architectures.Contains(t));
    public string? Os => Tokens.FirstOrDefault(t => Systems.Contains(t));
    private string[] Tokens => Features.Split(' ', StringSplitOptions.RemoveEmptyEntries);
}

/// <summary>
/// Dart and Flutter identification from bytes: AOT snapshot headers (libapp.so, App.framework/App) and the Dart VM version
/// string of an engine (libflutter.so, Flutter.framework). Scans only; nothing is decoded past the header.
/// </summary>
public static class DartScan
{
    private const int MaxSnapshots = 8, MaxFeatures = 1024;
    // kMagicValue 0xdcdcf5f5, little-endian on every target the AOT compiler emits.
    private static ReadOnlySpan<byte> Magic => [0xF5, 0xF5, 0xDC, 0xDC];
    // Snapshot::Kind as Dart 2.13+ numbers it.
    private static readonly string[] Kinds = ["full", "full-core", "full-jit", "full-aot", "none", "invalid"];

    /// <summary>Snapshot headers in file order: magic, int64 length, int64 kind, 32 hex characters, a NUL-terminated features string.</summary>
    public static List<DartSnapshot> Snapshots(ReadOnlySpan<byte> data, CancellationToken ct = default)
    {
        var found = new List<DartSnapshot>();
        int from = 0;
        while (found.Count < MaxSnapshots && from < data.Length)
        {
            ct.ThrowIfCancellationRequested();
            int i = data[from..].IndexOf(Magic);
            if (i < 0) break;
            int at = from + i;
            from = at + 4;
            if (Header(data, at) is { } s) { found.Add(s); from = at + 52; }
        }
        return found;
    }

    private static DartSnapshot? Header(ReadOnlySpan<byte> d, int at)
    {
        if (at + 53 > d.Length) return null;
        long length = BinaryPrimitives.ReadInt64LittleEndian(d[(at + 4)..]);
        long kind = BinaryPrimitives.ReadInt64LittleEndian(d[(at + 12)..]);
        if (length <= 0 || kind < 0 || kind >= Kinds.Length) return null;
        var hash = d.Slice(at + 20, 32);
        foreach (byte c in hash)
            if (!char.IsAsciiHexDigitLower((char)c)) return null;
        var rest = d[(at + 52)..];
        int end = rest[..Math.Min(rest.Length, MaxFeatures)].IndexOf((byte)0);
        if (end < 0) return null;
        foreach (byte c in rest[..end])
            if (c is < 0x20 or > 0x7E) return null;
        return new DartSnapshot(at, Kinds[kind], length, Encoding.ASCII.GetString(hash), Encoding.ASCII.GetString(rest[..end]));
    }

    /// <summary>The Dart VM version string, as `dart --version` prints it: "3.5.0 (stable) (date) on \"android_arm64\"".</summary>
    public static string? DartVersion(ReadOnlySpan<byte> data, CancellationToken ct = default)
    {
        ReadOnlySpan<byte> anchor = ") on \""u8;
        int from = 0;
        for (int n = 0; n < 10_000 && from < data.Length; n++)
        {
            ct.ThrowIfCancellationRequested();
            int i = data[from..].IndexOf(anchor);
            if (i < 0) break;
            int at = from + i;
            from = at + anchor.Length;
            int start = Math.Max(0, at - 160), stop = Math.Min(data.Length, at + 48);
            var m = Version.Match(Encoding.Latin1.GetString(data[start..stop]));
            if (m.Success) return m.Value;
        }
        return null;
    }

    /// <summary>The engine flavor: Flutter's embedder strings, else a plain Dart VM.</summary>
    public static bool IsFlutterEngine(ReadOnlySpan<byte> data) =>
        data.IndexOf("io/flutter/embedding/engine/FlutterJNI"u8) >= 0 || data.IndexOf("FlutterEngine"u8) >= 0 || data.IndexOf("flutter/shell/"u8) >= 0;

    private static readonly Regex Version = new(@"\b\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)? \((?:stable|beta|dev|main|be)\) \([^()\x00]{4,80}\) on ""[a-z0-9]+_[a-z0-9]+""",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
}
