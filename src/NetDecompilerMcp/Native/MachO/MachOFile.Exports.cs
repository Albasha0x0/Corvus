using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.MachO;

/// <summary>
/// An exports-trie entry. <see cref="Address"/> is the offset from the image base (an absolute value for
/// <see cref="IsAbsolute"/>); re-exports name a library ordinal and the symbol there (empty when it is the same name);
/// stub-and-resolver exports have the stub at <see cref="Address"/> and the resolver at <see cref="Resolver"/>.
/// </summary>
public sealed record MachOExport(string Name, ulong Flags, ulong Address, ulong Resolver, int ReexportOrdinal, string? ImportName)
{
    public bool IsReexport => (Flags & 0x08) != 0;
    public bool IsStubAndResolver => (Flags & 0x10) != 0;
    public bool IsWeakDefinition => (Flags & 0x04) != 0;
    public bool IsThreadLocal => (Flags & 0x03) == 1;
    public bool IsAbsolute => (Flags & 0x03) == 2;
}

public sealed partial class MachOFile
{
    private const int MaxTrieNodes = 1 << 22;

    private sealed record ExportInfo(List<MachOExport> All, List<NativeExport> Native)
    {
        public static readonly ExportInfo Empty = new([], []);
    }

    private ImageArea<ExportInfo> exportArea = null!;

    /// <summary>The exports trie (LC_DYLD_EXPORTS_TRIE or the dyld info export area), sorted by name.</summary>
    public IReadOnlyList<MachOExport> ExportTrie => exportArea.Value.All;

    /// <summary>Exports with image addresses; a re-export is forwarded as "library!symbol" with RVA 0; absolute symbols are left out.</summary>
    public IReadOnlyList<NativeExport> Exports => exportArea.Value.Native;

    private ExportInfo ParseExports(IssueLog log)
    {
        ByteView trie;
        if (commands.OfType<MachOLinkEditCommand>().FirstOrDefault(c => c.Command == 0x80000033) is { } lc) trie = FileWindow(lc.DataOffset, lc.DataSize);
        else if (commands.OfType<MachODyldInfoCommand>().FirstOrDefault() is { ExportSize: > 0 } info) trie = FileWindow(info.ExportOffset, info.ExportSize);
        else return ExportInfo.Empty;
        var result = new ExportInfo([], []);
        var budget = new WorkBudget(log);
        var visited = new HashSet<long>();
        var stack = new Stack<(long Node, string Prefix)>();
        stack.Push((0, ""));
        var dylibs = Dependencies;
        while (stack.Count > 0 && budget.Step())
        {
            var (node, prefix) = stack.Pop();
            if (!visited.Add(node) || visited.Count > MaxTrieNodes)
            {
                log.Add($"export trie node +0x{node:X} is reached twice or the trie is too large; that branch is not read");
                continue;
            }
            var r = new LebReader(trie.Span(0, trie.Length), (int)node);
            ulong terminalSize = r.Uleb();
            int childrenAt = r.Position + (int)Math.Min(terminalSize, int.MaxValue / 2);
            if (terminalSize > 0 && !r.Failed)
            {
                ulong flags = r.Uleb();
                ulong address = 0, resolver = 0;
                int ordinal = 0;
                string? importName = null;
                if ((flags & 0x08) != 0)
                {
                    ordinal = (int)Math.Min(r.Uleb(), int.MaxValue);
                    importName = r.CString();
                }
                else
                {
                    address = r.Uleb();
                    if ((flags & 0x10) != 0) resolver = r.Uleb();
                }
                if (r.Failed || r.Position > childrenAt) log.Add($"export {prefix}: terminal information at +0x{node:X} is malformed");
                else if (budget.Chars(prefix.Length)) result.All.Add(new MachOExport(prefix, flags, address, resolver, ordinal, importName is { Length: > 0 } ? importName : null));
            }
            r.Position = childrenAt;
            int count = r.Byte();
            for (int i = 0; i < count && !r.Failed; i++)
            {
                string? edge = r.CString();
                ulong child = r.Uleb();
                if (edge == null || r.Failed) break;
                if (child >= (ulong)trie.Length || prefix.Length + edge.Length > MaxNameLength)
                {
                    log.Add($"export trie edge '{prefix}{edge}' points outside the trie (+0x{child:X})");
                    continue;
                }
                stack.Push(((long)child, prefix + edge));
            }
            if (r.Failed) log.Add($"export trie node +0x{node:X} is truncated");
        }

        result.All.Sort((a, b) => string.CompareOrdinal(a.Name, b.Name));
        foreach (var e in result.All)
        {
            if (result.Native.Count >= PeLimits.MaxExports)
            {
                log.Add($"more than {PeLimits.MaxExports} exports; the rest are not listed");
                break;
            }
            if (e.IsReexport)
            {
                string library = MachONames.Library(e.ReexportOrdinal, dylibs) ?? $"ordinal {e.ReexportOrdinal}";
                result.Native.Add(new NativeExport(e.Name, 0, 0, $"{library}!{e.ImportName ?? e.Name}"));
            }
            else if (!e.IsAbsolute && e.Address <= uint.MaxValue && e.Address < SizeOfImage)
                result.Native.Add(new NativeExport(e.Name, 0, (uint)e.Address & (Arch == NativeArch.Arm ? ~1u : ~0u), null));
        }
        return result;
    }
}
