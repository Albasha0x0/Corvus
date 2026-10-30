using System.Text;
using Corvus.Services.Web.Packages;

namespace Corvus.Services.Analysis;

/// <summary>
/// An incident list: one <c>name@version</c> or SHA-256 per line, <c>#</c>
/// comments; text after the first space is a label and is ignored.
/// </summary>
public sealed class IncidentList
{
    /// <summary>Lists larger than this are refused.</summary>
    public const int MaxBytes = 64 << 20;

    private readonly HashSet<(string Name, string Version)> _packages = [];
    private readonly HashSet<(string Name, string Version)> _normalized = [];
    private readonly HashSet<string> _hashes = new(StringComparer.Ordinal);

    private IncidentList(string name) => Name = name;

    /// <summary>The file or pack name the list was read from.</summary>
    public string Name { get; }

    /// <summary>Lines that are neither a package nor a SHA-256; they are skipped.</summary>
    public int Unreadable { get; private set; }

    /// <summary>The number of listed packages and hashes.</summary>
    public int Count => _packages.Count + _hashes.Count;

    /// <summary>Whether any SHA-256 is listed.</summary>
    public bool HasHashes => _hashes.Count > 0;

    /// <summary>Reads <paramref name="bytes"/> as a list named <paramref name="name"/>; bad lines are counted, never thrown.</summary>
    public static IncidentList Parse(byte[] bytes, string name)
    {
        var list = new IncidentList(name);
        if (bytes.Length > MaxBytes) return list;
        foreach (var raw in Encoding.UTF8.GetString(bytes).TrimStart('﻿').Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;
            var token = line.Split([' ', '\t'], 2)[0];
            int at = token.LastIndexOf('@');
            if (token.Length == 64 && token.All(Uri.IsHexDigit)) list._hashes.Add(token.ToLowerInvariant());
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

    /// <summary>Whether the exact version of a package is listed; python names compare in their normalized form.</summary>
    public bool Lists(string name, string version, bool python) =>
        python ? _normalized.Contains((Lockfiles.Normalize(name), version)) : _packages.Contains((name.ToLowerInvariant(), version));

    /// <summary>Whether <paramref name="sha256"/> (hex, any case) is listed.</summary>
    public bool Lists(string sha256) => _hashes.Contains(sha256.ToLowerInvariant());
}
