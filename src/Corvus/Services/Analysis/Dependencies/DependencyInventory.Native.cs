using System.Text;
using Corvus.Native;

namespace Corvus.Services.Analysis.Dependencies;

internal static partial class DependencyInventory
{
    /// <summary>Libraries a native image names by a version string in its sections; a string with no digits after the dot gives no version.</summary>
    private static void FromNativeVersionStrings(Builder b, INativeImage image, CancellationToken ct)
    {
        var seen = new HashSet<(string, string?)>();
        int before = b.Components.Count;
        foreach (var (section, size) in CryptoConstantRules.Plan(image))
        {
            var bytes = new byte[size];
            int read = image.Read(section.Rva, bytes);
            foreach (var (name, prefixes) in CryptoConstantRules.VersionStrings())
                foreach (var prefix in prefixes)
                {
                    var pattern = Encoding.ASCII.GetBytes(prefix);
                    for (int from = 0; from < read;)
                    {
                        ct.ThrowIfCancellationRequested();
                        int at = bytes.AsSpan(from, read - from).IndexOf(pattern);
                        if (at < 0) break;
                        int hit = from + at;
                        from = hit + pattern.Length;
                        // The prefix ends in the major version's digit and a dot.
                        int end = from;
                        while (end < read && bytes[end] is >= (byte)'0' and <= (byte)'9' or >= (byte)'a' and <= (byte)'z' or (byte)'.') end++;
                        var tail = Encoding.ASCII.GetString(bytes, from, end - from).TrimEnd('.');
                        var shown = prefix + tail;
                        var version = tail.Length > 0 && char.IsAsciiDigit(tail[0]) ? shown[(prefix.Length - 2)..] : null;
                        if (!seen.Add((name, version))) continue;
                        var location = $"{section.Name} @{NativeAddress.Va(image, section.Rva + (uint)hit)}";
                        b.Components.Add(new DependencyComponent(b.NewRef(version != null ? $"native:{name}@{version}" : $"native:{name}"), name, version,
                            "native", "library", null, EmbeddedVersion, "binary-analysis", $"version string \"{shown}\" in the native code")
                        { Locations = [location] });
                    }
                }
        }
        if (b.Components.Count > before) b.Sources.Add("version strings in the native image");
    }
}
