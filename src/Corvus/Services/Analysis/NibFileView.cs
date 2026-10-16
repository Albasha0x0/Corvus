using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Native.MachO;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=nib: a compiled nib (NIBArchive or keyed archive): its classes, outlets and actions; inside an .app, each action's
/// selector is resolved to its implementation in the main executable through the Objective-C metadata: on the
/// destination's own class (and its superclasses), else on the one class that implements it, else the candidates.
/// </summary>
internal sealed class NibFileView : IFileSummaryView
{
    private const int MaxRows = 500;

    public sealed record Facts(string Format, int Objects, IReadOnlyList<string> Classes, IReadOnlyList<Connection> Outlets, IReadOnlyList<Connection> Actions,
        string? Executable, IReadOnlyList<string> Notes);

    /// <summary>A connection: its name (outlet or selector), the objects at each end, and for an action its implementation.</summary>
    public sealed record Connection(string Name, string Source, string Destination, string? Implementation);

    public string Name => "nib";

    private static readonly HashSet<string> OutletClasses = ["UIRuntimeOutletConnection", "UIRuntimeOutletCollectionConnection", "NSNibOutletConnector"];
    private static readonly HashSet<string> ActionClasses = ["UIRuntimeEventConnection", "NSNibControlConnector", "NSNibAuxiliaryActionConnector"];

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!NibArchive.IsNibArchive(file.Head) && !Plist.IsBinary(file.Head)) return null;
        NibArchive.Graph? read;
        if (!file.Streamed) read = NibArchive.Read(file.Bytes);
        else
            using (var stream = file.OpenRead()) read = NibArchive.Read(stream, 1 << 20); // a keyed archive's values kept to 1 MiB
        if (read is not { } graph) return null;
        var connectors = graph.Objects.Where(o => OutletClasses.Contains(o.Class) || ActionClasses.Contains(o.Class)).ToList();
        // a keyed archive that is not a nib (no connector, no UI or AppKit classes) belongs to view=plist
        if (graph.Format != "NIBArchive" && connectors.Count == 0 && !graph.Objects.Any(o => o.Class.StartsWith("UI", StringComparison.Ordinal) || o.Class.StartsWith("NSNib", StringComparison.Ordinal)))
            return null;
        var notes = new List<string>(graph.Issues);
        var (methods, executable) = Methods(file.Path, notes, ct);
        string Describe(object? value) => graph.Deref(value) is not { } o ? "nil" : o.Class switch
        {
            "UIProxyObject" => $"proxy {graph.Text(o["UIProxiedObjectIdentifier"]) ?? "?"}",
            "NSCustomObject" or "NSCustomView" => graph.Text(o["NSClassName"]) ?? o.Class,
            _ => o.Class,
        };
        string Label(NibObject c) => graph.Text(c["UILabel"] ?? c["NSLabel"]) ?? "?";
        var outlets = connectors.Where(c => OutletClasses.Contains(c.Class)).Take(MaxRows)
            .Select(c => new Connection(Label(c), Describe(c["UISource"] ?? c["NSSource"]), Describe(c["UIDestination"] ?? c["NSDestination"]), null)).ToList();
        var actions = connectors.Where(c => ActionClasses.Contains(c.Class)).Take(MaxRows).Select(c =>
        {
            var destination = Describe(c["UIDestination"] ?? c["NSDestination"]);
            var selector = Label(c);
            return new Connection(selector, Describe(c["UISource"] ?? c["NSSource"]), destination, methods != null ? Resolve(methods, destination, selector) : null);
        }).ToList();
        if (connectors.Count > 2 * MaxRows) notes.Add($"{connectors.Count} connections; the first {MaxRows} outlets and actions are listed");
        var classes = graph.Objects.GroupBy(o => o.Class).Where(g => g.Key.Length > 0).OrderByDescending(g => g.Count()).Select(g => $"{g.Key} ({g.Count()})").Take(60).ToList();
        var facts = new Facts(graph.Format, graph.Objects.Count, classes, outlets, actions, executable, notes);
        int resolved = actions.Count(a => a.Implementation?.StartsWith("0x", StringComparison.Ordinal) == true);
        return new FileView(facts, [$"Compiled nib ({graph.Format}): {graph.Objects.Count} objects, {outlets.Count} outlets, {actions.Count} actions" +
                                    (methods != null ? $", {resolved} resolved to their implementation in {Path.GetFileName(executable)}" : "") + "."]);
    }

    /// <summary>Instance methods by class and selector of the enclosing .app's main executable; null outside an app.</summary>
    private static (Dictionary<string, (string? Super, Dictionary<string, ulong> Selectors)>? Methods, string? Executable) Methods(string path, List<string> notes, CancellationToken ct)
    {
        for (var dir = Path.GetDirectoryName(Path.GetFullPath(path)); dir != null; dir = Path.GetDirectoryName(dir))
        {
            if (!dir.EndsWith(".app", StringComparison.OrdinalIgnoreCase)) continue;
            if (AppleFileView.MainExecutable(dir) is not { } exe) return (null, null);
            try
            {
                var metadata = AppleObjcMetadata.Read(MachOFile.Open(exe), ct);
                var map = new Dictionary<string, (string? Super, Dictionary<string, ulong> Selectors)>(StringComparer.Ordinal);
                foreach (var c in metadata.Classes)
                    map[c.Name] = (c.Superclass, c.Methods.Where(m => !m.IsClassMethod).GroupBy(m => m.Selector).ToDictionary(g => g.Key, g => g.First().Imp, StringComparer.Ordinal));
                foreach (var category in metadata.Categories.Where(c => map.ContainsKey(c.ClassName)))
                    foreach (var m in category.Methods.Where(m => !m.IsClassMethod)) map[category.ClassName].Selectors.TryAdd(m.Selector, m.Imp);
                return (map, exe);
            }
            catch (ToolError e)
            {
                notes.Add($"{Path.GetFileName(exe)}: {e.Message}");
                return (null, exe);
            }
        }
        return (null, null);
    }

    private static string? Resolve(Dictionary<string, (string? Super, Dictionary<string, ulong> Selectors)> methods, string destination, string selector)
    {
        for (string? c = destination; c != null && methods.TryGetValue(c, out var cls); c = cls.Super)
            if (cls.Selectors.TryGetValue(selector, out var imp)) return $"0x{imp:X} -[{c} {selector}]";
        var implementers = methods.Where(m => m.Value.Selectors.ContainsKey(selector)).Select(m => m.Key).ToList();
        return implementers.Count switch
        {
            0 => null,
            1 => $"0x{methods[implementers[0]].Selectors[selector]:X} -[{implementers[0]} {selector}] (the one class implementing it)",
            _ => $"one of {string.Join(", ", implementers.Take(5).Select(i => $"-[{i} {selector}]"))}{(implementers.Count > 5 ? ", ..." : "")}",
        };
    }
}
