using System.Text;

namespace Corvus.Services.Analysis.Dependencies;

/// <summary>Package URLs (purl specification) for the ecosystems the inventory reads; every segment is percent-encoded.</summary>
public static class Purl
{
    /// <summary>pkg:nuget/Name@Version.</summary>
    public static string NuGet(string name, string version) => $"pkg:nuget/{Encode(name)}@{Encode(version)}";

    /// <summary>pkg:cargo/name@version.</summary>
    public static string Cargo(string name, string version) => $"pkg:cargo/{Encode(name)}@{Encode(version)}";

    /// <summary>pkg:golang/namespace/name@version: the module path's segments are the namespace and name; stdlib takes the bare toolchain version.</summary>
    public static string Golang(string modulePath, string version) =>
        $"pkg:golang/{string.Join('/', modulePath.Split('/', StringSplitOptions.RemoveEmptyEntries).Select(Encode))}@{Encode(version)}";

    /// <summary>The purl percent-encoding of one segment: unreserved characters stay, every other UTF-8 byte is %XX.</summary>
    public static string Encode(string segment)
    {
        var sb = new StringBuilder(segment.Length);
        foreach (var b in Encoding.UTF8.GetBytes(segment))
        {
            if (b is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' or >= (byte)'0' and <= (byte)'9' or (byte)'.' or (byte)'-' or (byte)'_' or (byte)'~')
                sb.Append((char)b);
            else sb.Append('%').Append(b.ToString("X2"));
        }
        return sb.ToString();
    }
}
