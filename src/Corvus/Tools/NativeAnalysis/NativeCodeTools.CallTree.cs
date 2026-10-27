using System.ComponentModel;
using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Code;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>native_call_tree's record: the tree's nodes in tree order, paged by nodes.</summary>
public sealed record NativeCallTreeResult(
    string Image,
    [property: Description("Root function (or import) and its VA.")] string Root,
    [property: Description("callers, callees or both (one level: each node's site is its call instruction).")] string Direction,
    IReadOnlyList<NativeTreeNode> Items, int Offset, int Total,
    [property: Description("VAs of nodes cut by depth or maxNodes: pass one as function to continue there.")] IReadOnlyList<string>? Frontier,
    [property: Description(EngineDoc.Engine)] string Engine,
    [property: Description(EngineDoc.Note)] string? EngineNote);

/// <summary>A tree node with its text line (indented by depth).</summary>
internal sealed record TreeRow(NativeTreeNode Node, string Line);

public sealed partial class NativeCodeTools
{
    /// <summary>The page of <paramref name="rows"/> from <paramref name="offset"/>, as text lines and the record.</summary>
    private static string TreePage(int limit, LoadedNative native, string root, string direction, List<TreeRow> rows, int offset, string header, EngineChoice choice)
    {
        // The page's frontier: a whole tree's can hold thousands of nodes.
        static List<string>? Frontier(IEnumerable<TreeRow> page) =>
            page.Where(r => r.Node.Flags?.Contains("more") == true && r.Node.Address != null).Select(r => r.Node.Address!).Distinct().ToList() is { Count: > 0 } f ? f : null;
        return ToolOutput.List(rows, Math.Max(0, offset), ClampLimit(limit), r => r.Line,
            page => new NativeCallTreeResult(native.Id, root, direction, page.Select(r => r.Node).ToList(), Math.Max(0, offset), rows.Count,
                Frontier(page), choice.Engine, choice.Note), "node", choice.Line + "\n" + header);
    }

    /// <summary>Rows of a link-service tree: its text lines beside the rows it wrote.</summary>
    private static List<TreeRow> Zip(string text, List<NativeTreeNode> nodes)
    {
        var lines = text.Replace("\r\n", "\n").Split('\n', StringSplitOptions.RemoveEmptyEntries);
        return nodes.Select((n, i) => new TreeRow(n, i < lines.Length ? lines[i] : new string(' ', n.Depth * 2) + n.Name)).ToList();
    }

    /// <summary>Rows of the built-in index's tree (no link service).</summary>
    private static List<TreeRow> IndexTree(NativeCodeIndex index, CallTreeNode root, HashSet<CallTreeNode> dynamic)
    {
        var rows = new List<TreeRow>();
        void Walk(CallTreeNode node, int level, int? parent)
        {
            var name = node.Function?.Name ?? (node.Import != null ? NativeCodeIndex.ImportName(node.Import) : NativeAddress.Va(index.Image, node.Address));
            string? va = node.Function != null ? NativeAddress.Va(index.Image, node.Function.Start)
                : node.Import != null ? NativeAddress.Va(index.Image, node.Import.SlotRva) : NativeAddress.Va(index.Image, node.Address);
            var line = new StringBuilder(new string(' ', level * 2)).Append(name)
                .Append(dynamic.Contains(node) ? "  [dynamic]" : "")
                .Append(node.Via switch
                {
                    XrefKind.VirtualExact => "  [virtual]",
                    XrefKind.VirtualPossible => $"  [virtual?: one of {index.VirtualCalls.SiteAt(node.Site)?.TargetCount ?? 0}]",
                    _ => "",
                })
                .Append(node.Function != null ? $"  {NativeAddress.Va(index.Image, node.Function.Start)}" : "")
                .Append(node.Repeated ? "  (repeated)" : "").Append(node.Truncated ? "  (more not shown)" : "");
            var flags = new List<string>();
            if (node.Repeated) flags.Add("repeated");
            if (node.Truncated) flags.Add("more");
            if (node.Function == null && node.Import == null) flags.Add("unresolved");
            string? edge = parent == null ? null : dynamic.Contains(node) ? "dynamic" : node.Via switch
            {
                XrefKind.VirtualExact => "virtual",
                XrefKind.VirtualPossible => "virtual?",
                XrefKind.ImportCall or XrefKind.ImportJump => "import",
                XrefKind.TailCall => "jump",
                _ => node.Import != null ? "import" : "call",
            };
            int id = rows.Count;
            rows.Add(new TreeRow(new NativeTreeNode(id, parent, level, name, va, null, edge, flags.Count > 0 ? flags : null)
            {
                Note = node.Via == XrefKind.VirtualPossible ? $"one of {index.VirtualCalls.SiteAt(node.Site)?.TargetCount ?? 0}" : null,
            }, line.ToString()));
            foreach (var child in node.Children) Walk(child, level + 1, id);
        }
        Walk(root, 0, null);
        return rows;
    }

    /// <summary>Rows of an engine's indented tree text; a "(more not shown)" line marks its parent as not fully expanded.</summary>
    internal static List<TreeRow> ParseTree(string text)
    {
        var rows = new List<TreeRow>();
        var path = new List<int>();
        foreach (var raw in text.Replace("\r\n", "\n").Split('\n'))
        {
            if (raw.Trim().Length == 0 || raw.StartsWith(';')) continue;
            int level = (raw.Length - raw.TrimStart(' ').Length) / 2;
            var body = raw.Trim();
            if (path.Count > level) path.RemoveRange(level, path.Count - level);
            int? parent = path.Count > 0 ? path[^1] : null;
            if (body == "(more not shown)")
            {
                if (parent is { } p) rows[p] = rows[p] with { Node = rows[p].Node with { Flags = [.. rows[p].Node.Flags ?? [], "more"] } };
                continue;
            }
            var flags = new List<string>();
            if (body.EndsWith("(repeated)", StringComparison.Ordinal)) flags.Add("repeated");
            var m = TreeLine().Match(body);
            string name = m.Groups["name"].Value.Trim();
            string? va = m.Groups["va"].Success ? m.Groups["va"].Value : null;
            string tag = m.Groups["tag"].Value;
            string? edge = parent == null ? null
                : tag.StartsWith("[virtual?", StringComparison.Ordinal) ? "virtual?"
                : tag.StartsWith("[virtual", StringComparison.Ordinal) ? "virtual"
                : va == null && name.Contains('!') ? "import" : "call";
            int id = rows.Count;
            rows.Add(new TreeRow(new NativeTreeNode(id, parent, level, name, va, null, edge, flags.Count > 0 ? flags : null)
            {
                Note = tag.Length > 0 ? tag.Trim('[', ']') : null,
            }, raw));
            while (path.Count < level) path.Add(id);
            path.Add(id);
        }
        return rows;
    }

    [GeneratedRegex(@"^(?<name>.+?)(?:  (?<tag>\[[^\]]+\]))?(?:  (?<va>0x[0-9A-F]+))?(?:  \(repeated\))?$")]
    private static partial Regex TreeLine();

    /// <summary>direction=both rows: the root, then each caller and callee by call site ("callers (n):" / "callees (n):" sections).</summary>
    internal static List<TreeRow> ParseSites(string text, NativeCodeIndex index, string rootName, uint rootStart)
    {
        var rows = new List<TreeRow> { new(new NativeTreeNode(0, null, 0, rootName, NativeAddress.Va(index.Image, rootStart), null, null, null), $"{rootName}  {NativeAddress.Va(index.Image, rootStart)}") };
        string? role = null;
        foreach (var raw in text.Replace("\r\n", "\n").Split('\n'))
        {
            if (raw.StartsWith("callers (", StringComparison.Ordinal)) { role = "caller"; continue; }
            if (raw.StartsWith("callees (", StringComparison.Ordinal)) { role = "callee"; continue; }
            var m = SiteLine().Match(raw);
            if (role == null || !m.Success) continue;
            string flags = m.Groups["flags"].Value, rest = m.Groups["rest"].Value.Trim();
            string name;
            string? va;
            if (role == "callee")
            {
                var t = Regex.Match(rest, @"^-> (?<name>.+?)(?:  (?<va>0x[0-9A-F]+))?$");
                name = t.Groups["name"].Value;
                va = t.Groups["va"].Success ? t.Groups["va"].Value : null;
            }
            else
            {
                int plus = rest.LastIndexOf("+0x", StringComparison.Ordinal);
                name = plus > 0 ? rest[..plus] : rest;
                va = NativeAddress.Number(m.Groups["site"].Value) is { } site && site >= index.Image.ImageBase
                     && index.FunctionAt((uint)(site - index.Image.ImageBase)) is { } f && plus > 0 ? NativeAddress.Va(index.Image, f.Start) : null;
            }
            string edge = flags.Contains("virtual (one of", StringComparison.Ordinal) || flags.StartsWith("virtual?", StringComparison.Ordinal) ? "virtual?"
                : flags.Contains("virtual", StringComparison.Ordinal) ? "virtual"
                : flags.Contains("external", StringComparison.Ordinal) ? "import"
                : flags.StartsWith("jump", StringComparison.Ordinal) ? "jump" : "call";
            rows.Add(new TreeRow(new NativeTreeNode(rows.Count, 0, 1, name, va, null, edge, [role]) { Site = m.Groups["site"].Value, Note = flags },
                $"{role}  {raw.Trim()}"));
        }
        return rows;
    }

    [GeneratedRegex(@"^  (?<site>0x[0-9A-F]+)  (?<rest>.+?)  \[(?<flags>[^\]]+)\]$")]
    private static partial Regex SiteLine();
}
