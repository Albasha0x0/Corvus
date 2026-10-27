using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using Corvus.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Corvus.Services;

/// <summary>Joins event handlers named in decompiled XAML to the x:Class code-behind methods, with their tokens.</summary>
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

    /// <summary>
    /// The handlers the generated Connect(int, object) methods hook up, by connection id; empty when the class is not in the module.
    /// </summary>
    public static Dictionary<int, IReadOnlyList<(string Event, string Method)>> ConnectedHandlers(ModuleDef module, string className)
    {
        var found = new Dictionary<int, List<(string Event, string Method)>>();
        if (module.Find(className, isReflectionName: true) is not { } type) return [];
        foreach (var connect in type.NestedTypes.Prepend(type).SelectMany(t => t.Methods)
                     .Where(m => m.Name.EndsWith("Connect", StringComparison.Ordinal) && m.HasBody && m.MethodSig?.Params is [{ ElementType: ElementType.I4 }, _]))
        {
            var code = connect.Body.Instructions;
            // Each case starts at a switch target or a branch taken on connectionId == constant.
            var starts = new SortedList<uint, int>();
            for (int i = 0; i < code.Count; i++)
            {
                var ins = code[i];
                if (ins.OpCode.Code == Code.Switch && ins.Operand is IList<Instruction> targets)
                {
                    int bias = i >= 2 && code[i - 1].OpCode.Code == Code.Sub && code[i - 2].IsLdcI4() ? code[i - 2].GetLdcI4Value() : 0;
                    for (int k = 0; k < targets.Count; k++) starts.TryAdd(targets[k].Offset, k + bias);
                }
                else if (ins.IsLdcI4() && i + 1 < code.Count && i > 0 && code[i - 1].IsLdarg() && code[i - 1].GetParameterIndex() == 1)
                {
                    var next = code[i + 1];
                    if (next.OpCode.Code is Code.Beq or Code.Beq_S && next.Operand is Instruction target) starts.TryAdd(target.Offset, ins.GetLdcI4Value());
                    else if (next.OpCode.Code is Code.Bne_Un or Code.Bne_Un_S && i + 2 < code.Count) starts.TryAdd(code[i + 2].Offset, ins.GetLdcI4Value());
                }
            }
            if (starts.Count == 0) continue;
            string? handler = null, adder = null;
            foreach (var ins in code)
            {
                if (ins.OpCode.Code is Code.Ldftn or Code.Ldvirtftn && ins.Operand is IMethod target)
                {
                    if (target.Name.StartsWith("add_", StringComparison.Ordinal)) adder = target.Name.String[4..];
                    else if (!target.Name.StartsWith("remove_", StringComparison.Ordinal)) handler = target.Name;
                    continue;
                }
                if (ins.OpCode.Code is not (Code.Call or Code.Callvirt) || ins.Operand is not IMethod callee || handler == null) continue;
                // A projected WinRT event goes through WindowsRuntimeMarshal.AddEventHandler(add, remove, handler).
                var evt = callee.Name.StartsWith("add_", StringComparison.Ordinal) ? callee.Name.String[4..] : callee.Name == "AddEventHandler" ? adder : null;
                if (evt == null) continue;
                int index = starts.Keys.Count(k => k <= ins.Offset) - 1;
                if (index >= 0)
                {
                    var id = starts.Values[index];
                    var list = found.TryGetValue(id, out var l) ? l : found[id] = [];
                    if (!list.Contains((evt, handler))) list.Add((evt, handler));
                }
                handler = adder = null;
            }
        }
        return found.ToDictionary(f => f.Key, f => (IReadOnlyList<(string, string)>)f.Value);
    }

    [GeneratedRegex(@"^[\p{L}_][\p{L}\p{Nd}_]*$")]
    private static partial Regex Identifier();
}
