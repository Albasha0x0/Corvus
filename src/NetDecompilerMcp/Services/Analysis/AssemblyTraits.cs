using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;
using dnlib.DotNet;

namespace NetDecompilerMcp.Services.Analysis;

/// <summary>
/// How an assembly was built, read from its bytes and metadata: ReadyToRun precompilation, and the traces assembly
/// mergers leave behind. Detection and labelling only; never throws on malformed input.
/// </summary>
public static class AssemblyTraits
{
    /// <summary>True when the image carries ReadyToRun native code next to its IL (crossgen / PublishReadyToRun).</summary>
    public static bool IsReadyToRun(ReadOnlySpan<byte> image)
    {
        var pe = PeImage.TryParse(image);
        return pe != null && pe.IsReadyToRun(image);
    }

    /// <summary>
    /// A note when the assembly was produced by merging several assemblies, with the original count where it can be
    /// recovered; null when there is no sign of merging.
    /// <list type="bullet">
    /// <item>ILRepack embeds an "ILRepack.List" resource naming every merged assembly (unless run with /noRepackRes).</item>
    /// <item>ILMerge adds no marker, but renames a later input's non-public type whose name is taken: the type name
    /// (not its namespace) becomes "InputName.Old" for compiler-generated types and "InputName&lt;key&gt;.Old" for the
    /// rest, while the first input's type keeps "Old". C# cannot declare a type name containing a dot, so a dotted name
    /// next to its undotted twin is a merge. Inputs without clashing types leave no trace: the count is a lower bound.</item>
    /// <item>Pre-Roslyn compilers named the helper class "&lt;PrivateImplementationDetails&gt;{MVID}"; several distinct
    /// ones means several original modules (from either tool).</item>
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
            int atLeast = Math.Max(inputs.Count + 1, pidModules); // + 1: the input that kept the original names
            var from = inputs.Count > 0 ? $" (renamed types from {string.Join(", ", inputs)})" : "";
            return $"Merged assembly (ILMerge-style): at least {atLeast} original modules{from}.";
        }
        catch (Exception)
        {
            return null; // corrupt metadata: no label rather than a failure
        }
    }

    private static readonly Regex PidGuid = new(@"^<PrivateImplementationDetails>\{([0-9A-Fa-f-]{36})\}$", RegexOptions.CultureInvariant);

    /// <summary>Names of the inputs ILMerge renamed types from, recovered from "Input.Old" / "Input123.Old" type names.</summary>
    private static List<string> IlMergeInputs(ModuleDef module)
    {
        var names = new HashSet<(string Namespace, string Name)>();
        foreach (var t in module.Types) names.Add((t.Namespace.String, t.Name.String));
        var exact = new HashSet<string>(StringComparer.Ordinal); // from compiler-generated renames: the input name itself
        var keyed = new List<string>();                           // the rest: input name + numeric key
        foreach (var t in module.Types)
        {
            string name = t.Name.String;
            // The input name can contain dots itself ("Contoso.Utils.Old"): try every split, longest prefix first.
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
            // "Lib27" is "Lib2" + key 7 when "Lib2" is known; otherwise strip the trailing digits (the key)
            var known = exact.Where(e => prefix.Length > e.Length && prefix.StartsWith(e, StringComparison.Ordinal) && prefix[e.Length..].All(char.IsAsciiDigit))
                .MaxBy(e => e.Length);
            var trimmed = prefix.TrimEnd("0123456789".ToCharArray());
            inputs.Add(known ?? (trimmed.Length > 0 ? trimmed : prefix));
        }
        return [.. inputs];
    }

    private static string ShortName(string fullName) => fullName.Split(',')[0].Trim();

    /// <summary>
    /// ILRepack's list: a BinaryFormatter string[] (17-byte header, 0x11 + object id + count, then 0x06 + object id +
    /// 7-bit-length UTF-8 string per item). Null when the bytes do not follow that layout.
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
