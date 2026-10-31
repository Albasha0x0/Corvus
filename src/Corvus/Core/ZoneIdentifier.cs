using System.Text;

namespace Corvus.Core;

/// <summary>Where a file came from, read from its Zone.Identifier stream (the Mark of the Web): the zone and the download and referring URLs.</summary>
public sealed record ZoneIdentifier(int? ZoneId, string? HostUrl, string? ReferrerUrl)
{
    /// <summary>The most bytes read from the stream.</summary>
    public const int MaxBytes = 4096;

    private const string StreamName = ":Zone.Identifier";

    /// <summary>The keys present as "ZoneId=3 HostUrl=... ReferrerUrl=...".</summary>
    public override string ToString() =>
        string.Join(' ', new[] { ZoneId is { } id ? $"ZoneId={id}" : null, HostUrl != null ? $"HostUrl={HostUrl}" : null, ReferrerUrl != null ? $"ReferrerUrl={ReferrerUrl}" : null }.OfType<string>());

    /// <summary>The [ZoneTransfer] section of <paramref name="stream"/> (UTF-8 or UTF-16); null when it holds none of the three keys.</summary>
    public static ZoneIdentifier? Parse(ReadOnlySpan<byte> stream)
    {
        if (stream.Length > MaxBytes) stream = stream[..MaxBytes];
        var text = stream is [0xFF, 0xFE, ..] ? Encoding.Unicode.GetString(stream[2..]) : Encoding.UTF8.GetString(stream.StartsWith<byte>([0xEF, 0xBB, 0xBF]) ? stream[3..] : stream);
        int? zone = null;
        string? host = null, referrer = null;
        bool inSection = false;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith('[')) { inSection = line.Equals("[ZoneTransfer]", StringComparison.OrdinalIgnoreCase); continue; }
            if (!inSection || line.IndexOf('=') is not (> 0 and var eq)) continue;
            var key = line[..eq].Trim();
            var value = line[(eq + 1)..].Trim();
            if (value.Length == 0) continue;
            if (key.Equals("ZoneId", StringComparison.OrdinalIgnoreCase)) zone = int.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var id) ? id : zone;
            else if (key.Equals("HostUrl", StringComparison.OrdinalIgnoreCase)) host = value;
            else if (key.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase)) referrer = value;
        }
        return zone == null && host == null && referrer == null ? null : new ZoneIdentifier(zone, host, referrer);
    }

    /// <summary>The Zone.Identifier stream of <paramref name="path"/>; null off Windows, when the stream is absent or unreadable, or when its path is remote.</summary>
    /// <remarks>Reads at most <see cref="MaxBytes"/> bytes; the stream path passes the input's remote-path check.</remarks>
    public static ZoneIdentifier? Of(string path)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            var stream = Path.GetFullPath(path) + StreamName;
            if (InputFiles.RemoteProblem(stream, InputFiles.AllowRemote) != null) return null;
            using var file = new FileStream(stream, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var buffer = new byte[MaxBytes];
            int read = 0, n;
            while (read < buffer.Length && (n = file.Read(buffer, read, buffer.Length - read)) > 0) read += n;
            return Parse(buffer.AsSpan(0, read));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return null; }
    }
}
