using System.ComponentModel;
using System.Reflection.PortableExecutable;
using System.Xml.Linq;
using dnlib.DotNet;

namespace Corvus.Services.Analysis;

/// <summary>view=xbf: compiled XAML decoded to XAML, with event handlers resolved from a code-behind assembly within three folders, with tokens for decompile_member; pages by character offset.</summary>
internal sealed class XbfFileView : IFileSummaryView
{
    private const int Window = 24_000, MaxCandidates = 64;
    private const long MaxAssembly = 64 << 20;

    /// <summary>An event handler set on an element: the element, the event, the method it binds to and its token.</summary>
    public sealed record Handler(string Element, string Event, string Symbol, string Token);

    /// <summary>What view=xbf read: the XBF version, x:Class and its code-behind assembly, the handlers, the XAML page and notes.</summary>
    public sealed record Facts(string Version, string? Class,
        [property: Description("The assembly holding the code-behind class; null when none in reach is a .NET assembly with it.")] string? CodeBehind,
        IReadOnlyList<Handler> Handlers, int Elements, int XamlChars, long Offset, long? Next,
        [property: Description("The XAML from offset, with event handlers as attributes.")] string? Xaml,
        bool Complete, IReadOnlyList<string>? Notes);

    public string Name => "xbf";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!XbfReader.IsXbf(file.Head) || file.Streamed) return null;
        var bytes = file.Bytes;
        var first = XbfReader.Read(bytes);
        var notes = new List<string>(first.Notes);
        string? codeBehind = null;
        var handlers = new List<Handler>();
        var result = first;
        if (first.Xaml != null)
        {
            if (CodeBehind(file.Path, first.ClassName, ct) is { } found)
            {
                using var module = found.Module;
                codeBehind = found.Path;
                var className = found.ClassName;
                var connected = XamlEvents.ConnectedHandlers(module, className);
                result = XbfReader.Read(bytes, connected, className);
                var (resolved, _, _) = XamlEvents.Resolve(module, result.Xaml!);
                handlers.AddRange(resolved.Select(h => new Handler(h.Element, h.Event, h.Symbol, $"0x{h.Token:X8}")));
                int named = connected.Values.Sum(v => v.Count);
                if (named > handlers.Count) notes.Add($"{named - handlers.Count} of the {named} handlers Connect hooks up are not methods of {className} or its base types");
            }
            else notes.Add(first.ClassName != null
                ? $"the code-behind {first.ClassName} is in no .NET assembly within three folders; its event handlers are unknown"
                : "no .NET assembly within three folders loads it by an ms-appx:/// URI; its code-behind and event handlers are unknown");
        }
        var xaml = result.Xaml ?? "";
        long offset = Math.Clamp(file.Options.Offset, 0, xaml.Length);
        var window = xaml.Substring((int)offset, (int)Math.Min(Window, xaml.Length - offset));
        long? next = offset + window.Length < xaml.Length ? offset + window.Length : null;
        if (next != null) notes.Add($"{xaml.Length:N0} characters of XAML; offset={next} reads on");
        int elements = 0;
        try { elements = xaml.Length > 0 ? XDocument.Parse(xaml).Descendants().Count() + 1 : 0; }
        catch (System.Xml.XmlException e) { notes.Add($"the XAML is not well-formed: {e.Message}"); }
        var facts = new Facts($"{result.Major}.{result.Minor}", result.ClassName, codeBehind, handlers, elements, xaml.Length, offset, next,
            result.Xaml != null ? window : null, !result.Partial, notes.Count > 0 ? notes : null);
        var highlight = $"Compiled XAML (XBF {result.Major}.{result.Minor})" + (result.ClassName != null ? $" of {result.ClassName}" : "") +
                        (result.Xaml != null ? $": {elements} elements" : ": node stream not decoded") +
                        (codeBehind != null ? $", {handlers.Count} event handlers resolved in {Path.GetFileName(codeBehind)}" : "") + "; view=xbf shows the XAML.";
        return new FileView(facts, [highlight]);
    }

    /// <summary>The first nearby .NET assembly defining <paramref name="className"/>, or loading the file by URI when it is null; null when none.</summary>
    private static (string Path, ModuleDefMD Module, string ClassName)? CodeBehind(string path, string? className, CancellationToken ct)
    {
        int seen = 0;
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        for (int up = 0; up <= 3 && dir != null; up++, dir = Path.GetDirectoryName(dir))
        {
            IEnumerable<string> candidates;
            try { candidates = Directory.EnumerateFiles(dir).Where(f => f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)).Order(StringComparer.Ordinal).ToList(); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { continue; }
            foreach (var candidate in candidates)
            {
                ct.ThrowIfCancellationRequested();
                if (++seen > MaxCandidates) return null;
                if (!IsManaged(candidate)) continue;
                ModuleDefMD? module = null;
                try
                {
                    module = ModuleDefMD.Load(candidate);
                    if (className != null ? module.Find(className, isReflectionName: true) != null : (className = Loader(module, path)) != null)
                        return (candidate, module, className!);
                }
                catch (Exception e) when (e is BadImageFormatException or IOException or UnauthorizedAccessException) { }
                module?.Dispose();
            }
        }
        return null;
    }

    /// <summary>The class whose InitializeComponent loads the XAML compiled to <paramref name="xbf"/>; null when none.</summary>
    private static string? Loader(ModuleDefMD module, string xbf)
    {
        var source = Path.ChangeExtension(Path.GetFullPath(xbf), ".xaml").Replace('\\', '/');
        foreach (var type in module.GetTypes())
            foreach (var method in type.Methods.Where(m => m.Name == "InitializeComponent" && m.HasBody))
                foreach (var ins in method.Body.Instructions)
                    if (ins.Operand is string uri && uri.StartsWith("ms-appx:///", StringComparison.OrdinalIgnoreCase) &&
                        source.EndsWith("/" + uri["ms-appx:///".Length..].TrimStart('/'), StringComparison.OrdinalIgnoreCase))
                        return type.ReflectionFullName;
        return null;
    }

    private static bool IsManaged(string path)
    {
        try
        {
            if (new FileInfo(path).Length > MaxAssembly) return false;
            using var pe = new PEReader(File.OpenRead(path));
            return pe.PEHeaders.CorHeader != null;
        }
        catch (Exception e) when (e is BadImageFormatException or IOException or UnauthorizedAccessException) { return false; }
    }
}
