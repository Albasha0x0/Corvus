using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services.Analysis;

/// <summary>Detects ReadyToRun precompilation and assembly-merge traces. Never throws on malformed input.</summary>
public static class AssemblyTraits
{
    /// <summary>True when the image carries ReadyToRun native code alongside its IL.</summary>
    public static bool IsReadyToRun(ReadOnlySpan<byte> image)
    {
        var pe = PeImage.TryParse(image);
        return pe != null && pe.IsReadyToRun(image);
    }

    /// <summary>
    /// Describes a merged assembly, or null when there is no sign of merging.
    /// <list type="bullet">
    /// <item>ILRepack embeds an "ILRepack.List" resource naming the inputs.</item>
    /// <item>ILMerge renames clashing non-public types to "Input.Old" (compiler-generated) or "Input&lt;key&gt;.Old".
    /// C# type names cannot contain dots, so a dotted name beside its undotted twin indicates a merge. The count is a
    /// lower bound.</item>
    /// <item>Several distinct "&lt;PrivateImplementationDetails&gt;{MVID}" types (pre-Roslyn) indicate several modules.</item>
    /// </list>
    /// </summary>
    public static string? MergeNote(ModuleDef module)
    {
        try
        {
            var repack = module.Resources.FirstOrDefault(r => r.Name == "ILRepack.List");
            if (repack != null)
            {
                var names = repack is EmbeddedResource er ? ReadRepackList(er.CreateReader().ToArray()) : null;
                return names == null
                    ? "Merged by ILRepack (ILRepack.List resource present, but its list is unreadable)."
                    : $"Merged by ILRepack from {names.Count} assemblies: {string.Join(", ", names.Select(ShortName))}.";
            }

            var inputs = IlMergeInputs(module);
            var pidModules = module.Types.Select(t => PidGuid.Match(t.Name)).Where(m => m.Success).Select(m => m.Groups[1].Value.ToUpperInvariant()).Distinct().Count();
            if (inputs.Count == 0 && pidModules < 2) return null;
            int atLeast = Math.Max(inputs.Count + 1, pidModules); // +1 for the input that kept the original names
            var from = inputs.Count > 0 ? $" (renamed types from {string.Join(", ", inputs)})" : "";
            return $"Merged assembly (ILMerge-style): at least {atLeast} original modules{from}.";
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static readonly Regex PidGuid = new(@"^<PrivateImplementationDetails>\{([0-9A-Fa-f-]{36})\}$", RegexOptions.CultureInvariant);

    /// <summary>Input names recovered from ILMerge-renamed types ("Input.Old" / "Input123.Old").</summary>
    private static List<string> IlMergeInputs(ModuleDef module)
    {
        var names = new HashSet<(string Namespace, string Name)>();
        foreach (var t in module.Types) names.Add((t.Namespace.String, t.Name.String));
        var exact = new HashSet<string>(StringComparer.Ordinal); // compiler-generated renames: bare input name
        var keyed = new List<string>();                           // other renames: input name + numeric key
        foreach (var t in module.Types)
        {
            string name = t.Name.String;
            // Input names may contain dots; try every split, longest prefix first.
            for (int dot = name.LastIndexOf('.'); dot > 0; dot = name.LastIndexOf('.', dot - 1))
            {
                if (!names.Contains((t.Namespace.String, name[(dot + 1)..]))) continue;
                if (t.CustomAttributes.IsDefined("System.Runtime.CompilerServices.CompilerGeneratedAttribute")) exact.Add(name[..dot]);
                else keyed.Add(name[..dot]);
                break;
            }
        }
        var inputs = new SortedSet<string>(exact, StringComparer.Ordinal);
        foreach (var prefix in keyed)
        {
            // "Lib27" is "Lib2" + key 7 when "Lib2" is known; otherwise strip trailing digits.
            var known = exact.Where(e => prefix.Length > e.Length && prefix.StartsWith(e, StringComparison.Ordinal) && prefix[e.Length..].All(char.IsAsciiDigit))
                .MaxBy(e => e.Length);
            var trimmed = prefix.TrimEnd("0123456789".ToCharArray());
            inputs.Add(known ?? (trimmed.Length > 0 ? trimmed : prefix));
        }
        return [.. inputs];
    }

    private static string ShortName(string fullName) => fullName.Split(',')[0].Trim();

    /// <summary>
    /// Parses a BinaryFormatter string[]: 17-byte header, 0x11 + id + count, then per item 0x06 + id + 7-bit-length UTF-8.
    /// </summary>
    internal static List<string>? ReadRepackList(byte[] data)
    {
        const int header = 17;
        if (data.Length < header + 9 || data[header] != 0x11) return null;
        int count = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(header + 5));
        if (count < 0 || count > 10_000) return null;
        int pos = header + 9;
        var names = new List<string>(count);
        for (int i = 0; i < count; i++)
        {
            if (pos + 5 > data.Length || data[pos] != 0x06) return null;
            pos += 5;
            int len = 0, shift = 0;
            byte b;
            do
            {
                if (pos >= data.Length || shift > 28) return null;
                b = data[pos++];
                len |= (b & 0x7F) << shift;
                shift += 7;
            } while ((b & 0x80) != 0);
            if (len > data.Length - pos) return null;
            names.Add(Encoding.UTF8.GetString(data, pos, len));
            pos += len;
        }
        return names;
    }
}
