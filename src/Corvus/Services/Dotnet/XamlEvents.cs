using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using Corvus.Core;
using dnlib.DotNet;

namespace Corvus.Services;

/// <summary>
/// Event handlers named in decompiled XAML (Click="OnSave", EventSetter Handler="...") joined to the methods of the
/// x:Class code-behind type and its base types, with tokens for decompile_member.
/// </summary>
public static partial class XamlEvents
{
    private const string XamlNamespace = "http://schemas.microsoft.com/winfx/2006/xaml";

    public sealed record Handler(string Element, string Event, string Method, string Symbol, uint Token);

    /// <summary>The handlers found, or the parse error when the XAML is not well-formed.</summary>
    public static (List<Handler> Handlers, string? ParseError, string? ClassName) Resolve(ModuleDef module, string xaml)
    {
        XDocument doc;
        try { doc = XDocument.Parse(xaml); }
        catch (XmlException e) { return ([], e.Message, null); }
        if (doc.Root?.Attribute(XName.Get("Class", XamlNamespace))?.Value is not { Length: > 0 } className) return ([], null, null);
        var methods = new Dictionary<string, MethodDef>(StringComparer.Ordinal);
        for (var t = module.Find(className, isReflectionName: true); t != null; t = t.BaseType as TypeDef)
            foreach (var m in t.Methods)
                if (!m.IsConstructor && m.MethodSig?.Params.Count == 2) methods.TryAdd(m.Name, m);
        var found = new List<Handler>();
        if (methods.Count == 0) return (found, null, className);
        foreach (var e in doc.Root.DescendantsAndSelf())
        {
            var label = e.Attribute(XName.Get("Name", XamlNamespace))?.Value ?? e.Attribute("Name")?.Value ?? e.Name.LocalName;
            foreach (var a in e.Attributes())
            {
                if (a.IsNamespaceDeclaration || a.Name.NamespaceName.Length > 0 || a.Name.LocalName == "Name" || !Identifier().IsMatch(a.Value) || !methods.TryGetValue(a.Value, out var m)) continue;
                var evt = e.Name.LocalName == "EventSetter" && a.Name.LocalName == "Handler" ? e.Attribute("Event")?.Value ?? "Handler" : a.Name.LocalName;
                found.Add(new Handler(label, evt, a.Value, $"{m.DeclaringType.FullName}::{m.Name}({Format.ParameterTypes(m.MethodSig)})", m.MDToken.Raw));
            }
        }
        return (found, null, className);
    }

    /// <summary>A comment after the XAML naming each handler's method, or saying why the XAML does not parse.</summary>
    public static string Footer(ModuleDef module, string xaml)
    {
        var (handlers, error, className) = Resolve(module, xaml);
        if (error != null) return $"{Environment.NewLine}<!-- the XAML above is not well-formed: {error.Replace("--", "- -", StringComparison.Ordinal)} -->";
        if (handlers.Count == 0) return "";
        var sb = new StringBuilder($"{Environment.NewLine}<!-- event handlers: {handlers.Count}, methods of {className} or its base types (decompile_member symbol=<token>)");
        foreach (var h in handlers) sb.Append(Environment.NewLine).Append($"  {h.Element}.{h.Event} = {h.Symbol} 0x{h.Token:X8}");
        return sb.Append(Environment.NewLine).Append("-->").ToString();
    }

    [GeneratedRegex(@"^[\p{L}_][\p{L}\p{Nd}_]*$")]
    private static partial Regex Identifier();
}
