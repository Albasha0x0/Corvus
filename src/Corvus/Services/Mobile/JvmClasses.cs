using System.IO.Compression;
using Corvus.Core;
using Corvus.Core.Mobile;

namespace Corvus.Services.Mobile;

/// <summary>
/// Class files of a jar (without classes*.dex) or a single .class, read in-process: listings in javap's layout and the
/// class bytes the second Java decompiler is given.
/// </summary>
public static class JvmClasses
{
    private const long MaxClassBytes = 64L << 20;

    /// <summary>Whether <paramref name="path"/> holds class files and no DEX code: a .class, or a jar or zip of .class entries.</summary>
    public static bool IsClassInput(string path)
    {
        try
        {
            var full = InputFiles.RequireRegularFile(path, "file");
            if (IsClassFile(full)) return true;
            using var zip = ZipFile.OpenRead(full);
            return !zip.Entries.Any(e => !e.FullName.Contains('/') && e.FullName.StartsWith("classes", StringComparison.Ordinal) && e.FullName.EndsWith(".dex", StringComparison.Ordinal))
                   && zip.Entries.Any(e => e.FullName.EndsWith(".class", StringComparison.Ordinal));
        }
        catch (Exception e) when (e is IOException or InvalidDataException or UnauthorizedAccessException or ToolError) { return false; }
    }

    /// <summary>Whether the file itself is one class file (not a jar).</summary>
    public static bool IsClassFile(string full)
    {
        Span<byte> head = stackalloc byte[10];
        using var s = File.OpenRead(full);
        return s.ReadAtLeast(head, head.Length, throwOnEndOfStream: false) == head.Length && JvmClass.IsClassFile(head);
    }

    /// <summary>The <c>javap -c -p</c> listing of a class, or of one method (the block it has inside the class).</summary>
    public static string Listing(string path, string symbol, CancellationToken ct)
    {
        var (owner, member) = Split(symbol.Trim());
        var cls = Read(path, owner, ct);
        try { return member == null ? JvmListing.Class(cls) : JvmListing.Method(cls, FindMethod(cls, member)); }
        catch (InvalidDataException e) { throw new ToolError(ErrorCode.MalformedInput, $"{cls.Name.Replace('/', '.')}: {e.Message}"); }
    }

    /// <summary>A class symbol (pkg.C, pkg/C, Lpkg/C;) and its member text, if any (m, m(I)V, m(int, String)).</summary>
    internal static (string Owner, string? Member) Split(string symbol)
    {
        int sep = symbol.IndexOf("->", StringComparison.Ordinal) is var arrow and >= 0 ? arrow : symbol.IndexOf("::", StringComparison.Ordinal);
        string owner = symbol, member = "";
        if (sep >= 0) (owner, member) = (symbol[..sep], symbol[(sep + 2)..]);
        else if (symbol.IndexOf('(') is var paren and > 0 && symbol.LastIndexOf('.', paren) is var dot and > 0) (owner, member) = (symbol[..dot], symbol[(dot + 1)..]);
        owner = owner.Trim();
        if (owner.StartsWith('L') && owner.EndsWith(';')) owner = owner[1..^1];
        return (owner.Replace('.', '/'), member.Length > 0 ? member.Trim() : null);
    }

    /// <summary>The class <paramref name="internalName"/> of a jar, or the class of a .class file (which must be it).</summary>
    public static JvmClass Read(string path, string internalName, CancellationToken ct)
    {
        var full = InputFiles.RequireRegularFile(path, "class file or jar");
        var (bytes, single) = Bytes(full, internalName, ct);
        JvmClass cls;
        try { cls = JvmClass.Read(bytes); }
        catch (InvalidDataException e) { throw new ToolError(ErrorCode.MalformedInput, $"{internalName}: {e.Message}"); }
        if (!single || cls.Name == internalName) return cls;
        throw new ToolError(ErrorCode.NotFound, $"{full} holds {cls.Name.Replace('/', '.')}, not {internalName.Replace('/', '.')}.", $"symbol={cls.Name.Replace('/', '.')}");
    }

    /// <summary>The bytes of a class: the file itself, or the jar entry (a multi-release jar's base entry first, else its newest version).</summary>
    internal static (byte[] Bytes, bool Single) Bytes(string full, string internalName, CancellationToken ct)
    {
        var length = new FileInfo(full).Length;
        using (var s = File.OpenRead(full))
        {
            Span<byte> head = stackalloc byte[10];
            if (s.ReadAtLeast(head, head.Length, throwOnEndOfStream: false) == head.Length && JvmClass.IsClassFile(head))
            {
                if (length > MaxClassBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{full} is larger than {MaxClassBytes} bytes.");
                return (File.ReadAllBytes(full), true);
            }
        }
        ZipArchive zip;
        try { zip = ZipFile.OpenRead(full); }
        catch (InvalidDataException) { throw new ToolError(ErrorCode.Unsupported, $"{full} is neither a class file nor a jar.", "summarize_file names what it is"); }
        using (zip)
        {
            ct.ThrowIfCancellationRequested();
            var name = internalName + ".class";
            var entry = zip.GetEntry(name) ?? zip.Entries
                .Where(e => e.FullName.StartsWith("META-INF/versions/", StringComparison.Ordinal) && e.FullName.EndsWith("/" + name, StringComparison.Ordinal))
                .OrderByDescending(e => int.TryParse(e.FullName.Split('/')[2], out var v) ? v : 0).FirstOrDefault();
            if (entry == null)
            {
                var simple = internalName[(internalName.LastIndexOf('/') + 1)..] + ".class";
                var near = zip.Entries.Where(e => e.FullName.EndsWith("/" + simple, StringComparison.OrdinalIgnoreCase) || e.FullName.Equals(simple, StringComparison.OrdinalIgnoreCase))
                    .Take(5).Select(e => e.FullName[..^6].Replace('/', '.')).ToList();
                throw new ToolError(ErrorCode.NotFound, $"{full} has no class {internalName.Replace('/', '.')}.",
                    near.Count > 0 ? $"classes of that name: {string.Join(", ", near)}" : "decompile_java or summarize_file shows what the jar holds");
            }
            if (entry.Length > MaxClassBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{entry.FullName} is larger than {MaxClassBytes} bytes.");
            using var stream = entry.Open();
            return (Blob.ReadBounded(stream, MaxClassBytes) ?? throw new ToolError(ErrorCode.LimitExceeded, $"{entry.FullName} is larger than {MaxClassBytes} bytes."), false);
        }
    }

    /// <summary>
    /// One method by name, descriptor (m(I)V or m(I)) or Java parameter types (m(int, String), simple or full names);
    /// a name with several overloads is ambiguous.
    /// </summary>
    internal static JvmMember FindMethod(JvmClass cls, string member)
    {
        int open = member.IndexOf('(');
        var name = open >= 0 ? member[..open].Trim() : member;
        var candidates = cls.Methods.Where(m => m.Name == name).ToList();
        string Id(JvmMember m) => $"L{cls.Name};->{m.Name}{m.Descriptor}";
        if (candidates.Count == 0)
            throw new ToolError(ErrorCode.NotFound, $"{cls.Name.Replace('/', '.')} has no method {name}.", "the class listing (symbol=<class>) shows its methods");
        if (open < 0)
            return candidates.Count == 1 ? candidates[0] : throw new ToolError(ErrorCode.Ambiguous,
                $"{cls.Name.Replace('/', '.')}::{name} has {candidates.Count} overloads: {string.Join(", ", candidates.Select(Id))}.", "name one by its descriptor or parameter types");
        int close = member.IndexOf(')', open);
        var inner = member[(open + 1)..(close > open ? close : member.Length)].Trim();
        var returns = close > open ? member[(close + 1)..].Trim() : "";
        bool descriptor = !inner.Contains(',') && !inner.Contains(' ') && (inner.Length == 0 || inner.Contains(';') || inner.All(c => "ZBSCIJFD[".Contains(c)));
        List<JvmMember> found;
        if (descriptor)
            found = candidates.Where(m => m.Descriptor.StartsWith($"({inner})", StringComparison.Ordinal) && (returns.Length == 0 || m.Descriptor.EndsWith(")" + returns, StringComparison.Ordinal))).ToList();
        else
        {
            var wanted = inner.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Select(t => t.Replace("...", "[]", StringComparison.Ordinal)).ToList();
            found = candidates.Where(m =>
            {
                var args = JvmSignatures.Method(m.Descriptor).Arguments.Select(JvmSignatures.Print).ToList();
                return args.Count == wanted.Count && args.Zip(wanted).All(p => p.First == p.Second.Replace('/', '.') || Simple(p.First) == p.Second);
            }).ToList();
        }
        return found.Count switch
        {
            1 => found[0],
            0 => throw new ToolError(ErrorCode.NotFound, $"{cls.Name.Replace('/', '.')} has no method {member}; its {name} overloads: {string.Join(", ", candidates.Select(Id))}."),
            _ => throw new ToolError(ErrorCode.Ambiguous, $"{member} matches {found.Count} methods: {string.Join(", ", found.Select(Id))}.", "name one by its descriptor"),
        };
    }

    private static string Simple(string type)
    {
        int dims = type.IndexOf('[');
        var element = dims >= 0 ? type[..dims] : type;
        return element[(Math.Max(element.LastIndexOf('.'), element.LastIndexOf('$')) + 1)..] + (dims >= 0 ? type[dims..] : "");
    }

    /// <summary>The entries of a class and its nested classes (Outer$*), for a decompiler that reads class files.</summary>
    public static IReadOnlyList<(string Name, byte[] Bytes)> WithNested(string full, string internalName, CancellationToken ct)
    {
        var list = new List<(string, byte[])> { (internalName + ".class", Bytes(full, internalName, ct).Bytes) };
        try
        {
            using var zip = ZipFile.OpenRead(full);
            foreach (var e in zip.Entries.Where(e => e.FullName.StartsWith(internalName + "$", StringComparison.Ordinal) && e.FullName.EndsWith(".class", StringComparison.Ordinal)))
            {
                ct.ThrowIfCancellationRequested();
                using var s = e.Open();
                if (Blob.ReadBounded(s, MaxClassBytes) is { } b) list.Add((e.FullName, b));
            }
        }
        catch (InvalidDataException) { } // a single .class file
        return list;
    }
}
