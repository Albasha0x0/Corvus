using System.Text;
using Corvus.Services.Web.Packages;

namespace Corvus.Services.Analysis;

/// <summary>
/// An incident list: one <c>name@version</c>, SHA-256 or SHA-1 per line, <c>#</c>
/// comments; text after the first space is the label of a hash entry, and the
/// first label of a repeated hash wins.
/// </summary>
public sealed class IncidentList
{
    /// <summary>Lists larger than this are refused.</summary>
    public const int MaxBytes = 64 << 20;

    // Longest label kept, in characters.
    private const int MaxLabel = 80;

    private readonly HashSet<(string Name, string Version)> _packages = [];
    private readonly HashSet<(string Name, string Version)> _normalized = [];
    private readonly HashSet<string> _hashes = new(StringComparer.Ordinal);
    private readonly HashSet<string> _sha1 = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _labels = new(StringComparer.Ordinal);

    private IncidentList(string name) => Name = name;

    /// <summary>The file or pack name the list was read from.</summary>
    public string Name { get; }

    /// <summary>Lines that are neither a package, a SHA-256 nor a SHA-1; they are skipped.</summary>
    public int Unreadable { get; private set; }

    /// <summary>The number of listed packages and hashes.</summary>
    public int Count => _packages.Count + _hashes.Count + _sha1.Count;

    /// <summary>Whether any SHA-256 is listed.</summary>
    public bool HasHashes => _hashes.Count > 0;

    /// <summary>Whether any SHA-1 is listed.</summary>
    public bool HasSha1 => _sha1.Count > 0;

    /// <summary>Reads <paramref name="bytes"/> as a list named <paramref name="name"/>; bad lines are counted, never thrown.</summary>
    public static IncidentList Parse(byte[] bytes, string name)
    {
        var list = new IncidentList(name);
        if (bytes.Length > MaxBytes) return list;
        foreach (var raw in Encoding.UTF8.GetString(bytes).TrimStart('﻿').Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;
            var parts = line.Split([' ', '\t'], 2);
            var token = parts[0];
            int at = token.LastIndexOf('@');
            var isHash = (token.Length == 64 || token.Length == 40) && token.All(Uri.IsHexDigit);
            if (token.Length == 64 && isHash) { list._hashes.Add(token.ToLowerInvariant()); list.Label(token, parts); }
            else if (token.Length == 40 && isHash) { list._sha1.Add(token.ToLowerInvariant()); list.Label(token, parts); }
            else if (at > 0 && at < token.Length - 1 && token.IndexOfAny(['*', '?']) < 0)
            {
                var (n, v) = (token[..at], token[(at + 1)..]);
                list._packages.Add((n.ToLowerInvariant(), v));
                list._normalized.Add((Lockfiles.Normalize(n), v));
            }
            else list.Unreadable++;
        }
        return list;
    }

    private void Label(string hash, string[] parts)
    {
        if (parts.Length < 2) return;
        var label = string.Join(' ', parts[1].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        if (label.Length > MaxLabel)
            label = label[..(char.IsHighSurrogate(label[MaxLabel - 1]) ? MaxLabel - 1 : MaxLabel)];
        if (label.Length > 0) _labels.TryAdd(hash.ToLowerInvariant(), label);
    }

    /// <summary>Whether the exact version of a package is listed; python names compare in their normalized form.</summary>
    public bool Lists(string name, string version, bool python) =>
        python ? _normalized.Contains((Lockfiles.Normalize(name), version)) : _packages.Contains((name.ToLowerInvariant(), version));

    /// <summary>Whether <paramref name="sha256"/> (hex, any case) is listed.</summary>
    public bool Lists(string sha256) => _hashes.Contains(sha256.ToLowerInvariant());

    /// <summary>Whether <paramref name="sha1"/> (hex, any case) is listed.</summary>
    public bool ListsSha1(string sha1) => _sha1.Contains(sha1.ToLowerInvariant());

    /// <summary>The label after a listed hash (hex, any case); null when it has none.</summary>
    public string? LabelOf(string hash) => _labels.GetValueOrDefault(hash.ToLowerInvariant());
}
