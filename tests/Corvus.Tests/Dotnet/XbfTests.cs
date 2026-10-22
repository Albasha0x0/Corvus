using System.Xml.Linq;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Corvus.Tests;

/// <summary>Compiled XAML (XBF) of UWP and WinUI apps read back as XAML, with handlers joined to the code-behind.</summary>
public sealed class XbfTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    private static ushort K(string type) => XbfWriter.Known(type);
    private static ushort P(string property) => XbfWriter.KnownProperty(property);

    /// <summary>
    /// A page with a resource dictionary and a style read through their deferred streams, a template, a conditional
    /// element and constants of every kind; the Save button is connection 2.
    /// </summary>
    internal static byte[] Page()
    {
        var w = new XbfWriter();
        var (resources, resourcesIndex) = w.Stream();
        var (style, styleIndex) = w.Stream();
        var (template, templateIndex) = w.Stream();
        var badge = w.Type("App.Controls", "Badge", "App");
        var count = w.Property(badge, "Count");

        // The page's resources: a brush and a style, each found by its offset in the deferred stream.
        int brushAt = resources.Offset;
        resources.PushScopeCreateType(K("SolidColorBrush")).SetValueConstant(P("SolidColorBrush.Color")).Color(0xFF0078D4).EndInitPopScope();
        int styleAt = resources.Offset;
        resources.PushScopeCreateType(K("Style")).SetValueType(P("Style.TargetType"), K("Button")).CustomData(styleIndex, 11);
        // Style 3: setters with a container value, then with a resource value at its offset in the style's stream.
        int foregroundAt = style.Offset;
        style.StaticResource(P("Setter.Value"), "Accent");
        resources.UInt(2)
            .UInt(0x30).U16(P("FrameworkElement.Margin")).Thickness(1, 2, 1, 2)
            .UInt(0x12).U16(P("Control.Foreground")).UInt((uint)foregroundAt)
            .UInt(0);
        resources.EndInitPopScope();
        template.PushScopeCreateType(K("Border")).TemplateBinding(P("Border.Background"), P("Control.Background")).EndInitPopScope();

        w.Main.PushScopeAddNamespace(XbfWriter.Presentation, "").AddNamespace(XbfWriter.Xaml, "x").AddNamespace("using:App.Controls", "local")
            .CreateType(K("Page")).CheckPeerType("App.MainPage")
            // Resource dictionary 4: key, hash with the low bit clear for a string key, offset; then two empty lists.
            .GetValue(P("FrameworkElement.Resources")).CustomData(resourcesIndex, 12)
            .UInt(2).Shared("Accent").U64Fixed(0).UInt((uint)brushAt).Shared("Button").U64Fixed(1).UInt((uint)styleAt)
            .UInt(0).UInt(0).UInt(0).PopScope()
            .PushScopeCreateType(K("StackPanel")).SetValueConstant(P("StackPanel.Orientation")).Enum("Orientation", 1)
            .GetValue(P("Panel.Children"))
            .PushScopeCreateType(K("TextBlock")).Name("Title").SetValueConstant(P("TextBlock.Text")).Str("Hello, <world>")
            .SetValueConstant(P("TextBlock.FontSize")).Float(24).SetValueConstant(P("Grid.Row")).Int(1).EndInitPopScope().AddToCollection()
            .PushScopeCreateType(K("Button")).ConnectionId(2).Name("Save").SetValueConstant(P("ContentControl.Content")).Str("Save")
            .StaticResource(P("Control.Background"), "Accent").SetValueConstant(P("UIElement.IsTabStop")).Bool(false).EndInitPopScope().AddToCollection()
            .PushScopeCreateType(badge).SetValueConstant(count).Int(3).ThemeResource(P("Control.Foreground"), "SystemAccentColor").EndInitPopScope().AddToCollection()
            .BeginConditional(K("IsApiContractPresent"), "Windows.Foundation.UniversalApiContract,7")
            .PushScopeCreateType(K("ContentControl")).DeferredProperty(P("ContentControl.ContentTemplate"), templateIndex).EndInitPopScope().AddToCollection()
            .EndConditional()
            .PopScope().EndInitPopScope().SetValue(P("UserControl.Content"))
            .EndInitPopScope();
        return w.Build();
    }

    [Fact]
    public void A_page_decodes_to_xaml_with_its_deferred_resources_style_and_template()
    {
        var result = XbfReader.Read(Page());
        Assert.False(result.Partial, string.Join("; ", result.Notes));
        Assert.Equal((2, 1, "App.MainPage"), (result.Major, result.Minor, result.ClassName));
        var root = XDocument.Parse(result.Xaml!).Root!;
        XNamespace p = XbfWriter.Presentation, x = XbfWriter.Xaml, local = "using:App.Controls";
        Assert.Equal(p + "Page", root.Name);
        Assert.Equal("App.MainPage", (string?)root.Attribute(x + "Class"));
        var resources = Assert.Single(root.Elements(p + "Page.Resources")).Elements().ToList();
        Assert.Equal(["Accent", null], resources.Select(r => (string?)r.Attribute(x + "Key")));
        Assert.Equal("#FF0078D4", (string?)resources[0].Attribute("Color"));
        Assert.Equal("Button", (string?)resources[1].Attribute("TargetType"));
        Assert.Equal(["Margin=1,2", "Foreground={StaticResource Accent}"],
            resources[1].Elements(p + "Setter").Select(s => $"{s.Attribute("Property")?.Value}={s.Attribute("Value")?.Value}"));
        var panel = Assert.Single(root.Elements(p + "StackPanel"));
        Assert.Equal("Horizontal", (string?)panel.Attribute("Orientation"));
        var children = panel.Elements().ToList();
        Assert.Equal([p + "TextBlock", p + "Button", local + "Badge", p + "ContentControl"], children.Select(c => c.Name));
        Assert.Equal(("Title", "Hello, <world>", "24", "1"), ((string?)children[0].Attribute(x + "Name"), (string?)children[0].Attribute("Text"),
            (string?)children[0].Attribute("FontSize"), (string?)children[0].Attribute("Grid.Row")));
        Assert.Equal(("{StaticResource Accent}", "False"), ((string?)children[1].Attribute("Background"), (string?)children[1].Attribute("IsTabStop")));
        Assert.Equal(("3", "{ThemeResource SystemAccentColor}"), ((string?)children[2].Attribute("Count"), (string?)children[2].Attribute("Foreground")));
        Assert.Contains("IsApiContractPresent(Windows.Foundation.UniversalApiContract,7)", ((XComment)children[3].PreviousNode!).Value);
        var border = Assert.Single(children[3].Descendants(p + "Border"));
        Assert.Equal("{TemplateBinding Background}", (string?)border.Attribute("Background"));
        Assert.Equal(new XbfReader.Element("Button", "Save"), result.Connections[2]);
    }

    [Fact]
    public void Handlers_the_generated_Connect_method_hooks_up_are_written_and_resolved()
    {
        var xbf = _dir.File("MainPage.xbf");
        File.WriteAllBytes(xbf, Page());
        CodeBehind().Write(_dir.File("App.dll"));
        var facts = Assert.IsType<XbfFileView.Facts>(new InspectionService(_workspace).Summarize(null, xbf, default, new FileViewOptions("xbf")).Views["xbf"].Detail);
        Assert.EndsWith("App.dll", facts.CodeBehind);
        var handler = Assert.Single(facts.Handlers);
        Assert.Equal(("Save", "Click", "App.MainPage::Save_Click(object, RoutedEventArgs)"), (handler.Element, handler.Event, handler.Symbol));
        var button = XDocument.Parse(facts.Xaml!).Descendants().Single(e => e.Name.LocalName == "Button");
        Assert.Equal("Save_Click", (string?)button.Attribute("Click"));
        Assert.True(facts.Complete);
    }

    /// <summary>
    /// App.MainPage with the Connect(int, object) method the XAML compiler generates: a switch on the connection id whose
    /// case 2 adds Save_Click to the Button's Click event.
    /// </summary>
    private static ModuleDefUser CodeBehind()
    {
        var module = new ModuleDefUser("App.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("App", new Version(1, 0));
        assembly.Modules.Add(module);
        var obj = module.CorLibTypes.Object;
        var args = new TypeDefUser("App", "RoutedEventArgs", obj.TypeDefOrRef);
        var handlerType = new TypeDefUser("App", "RoutedEventHandler", module.CorLibTypes.Object.TypeDefOrRef);
        var buttonType = new TypeDefUser("App", "Button", obj.TypeDefOrRef);
        var page = new TypeDefUser("App", "MainPage", obj.TypeDefOrRef);
        foreach (var t in new[] { args, handlerType, buttonType, page }) module.Types.Add(t);
        var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, obj, module.CorLibTypes.IntPtr),
            MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { ImplAttributes = MethodImplAttributes.Runtime };
        handlerType.Methods.Add(ctor);
        var addClick = new MethodDefUser("add_Click", MethodSig.CreateInstance(module.CorLibTypes.Void, handlerType.ToTypeSig()), MethodAttributes.Public);
        addClick.Body = new CilBody { Instructions = { OpCodes.Ret.ToInstruction() } };
        buttonType.Methods.Add(addClick);
        var save = new MethodDefUser("Save_Click", MethodSig.CreateInstance(module.CorLibTypes.Void, obj, args.ToTypeSig()), MethodAttributes.Private);
        save.Body = new CilBody { Instructions = { OpCodes.Ret.ToInstruction() } };
        page.Methods.Add(save);
        var connect = new MethodDefUser("Connect", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Int32, obj), MethodAttributes.Public);
        var end = OpCodes.Ret.ToInstruction();
        var case2 = OpCodes.Ldarg_2.ToInstruction();
        connect.Body = new CilBody
        {
            Instructions =
            {
                OpCodes.Ldarg_1.ToInstruction(), OpCodes.Ldc_I4_2.ToInstruction(), OpCodes.Sub.ToInstruction(),
                OpCodes.Switch.ToInstruction(new[] { case2 }), OpCodes.Br.ToInstruction(end),
                case2, OpCodes.Castclass.ToInstruction(buttonType), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldftn.ToInstruction(save),
                OpCodes.Newobj.ToInstruction(ctor), OpCodes.Callvirt.ToInstruction(addClick), OpCodes.Br.ToInstruction(end),
                end,
            },
        };
        page.Methods.Add(connect);
        return module;
    }

    [Fact]
    public void An_xbf_1_file_is_partial_and_names_its_version()
    {
        var w = new XbfWriter { Major = 1, Minor = 0 };
        w.Type("App", "MainPage", "App");
        var result = XbfReader.Read(w.Build());
        Assert.True(result.Partial);
        Assert.Null(result.Xaml);
        Assert.Contains(result.Notes, n => n.StartsWith("XBF 1 (Windows 8.1)", StringComparison.Ordinal));
        Assert.Contains(result.Notes, n => n.Contains("MainPage", StringComparison.Ordinal));
    }

    [Fact]
    public void An_unknown_node_keeps_the_elements_read_before_it_and_names_its_offset()
    {
        var w = new XbfWriter();
        w.Main.PushScopeAddNamespace(XbfWriter.Presentation, "").CreateType(K("Grid"))
            .GetValue(P("Panel.Children")).PushScopeCreateType(K("TextBlock")).SetValueConstant(P("TextBlock.Text")).Str("kept").EndInitPopScope().AddToCollection()
            .Op(99);
        var result = XbfReader.Read(w.Build());
        Assert.True(result.Partial);
        var note = Assert.Single(result.Notes);
        Assert.Contains("node type 99", note);
        Assert.Contains("Text=\"kept\"", result.Xaml);
    }

    [Fact]
    [FuzzEntry(typeof(XbfReader), typeof(XbfFileView))]
    public void Damaged_xbf_files_read_as_partial_xaml_without_crashing()
    {
        var path = _dir.File("Page.xbf");
        var failures = FormatFuzz.Run(Page(), b =>
        {
            File.WriteAllBytes(path, b);
            new XbfFileView().Inspect(new FileInput(path, b, Blob.Identify(b)) { Options = new FileViewOptions("xbf") }, default);
        }, 500);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    [Fact]
    public void A_file_without_the_signature_is_rejected()
    {
        var e = Assert.Throws<InvalidDataException>(() => XbfReader.Read(new byte[32]));
        Assert.Contains("XBF", e.Message);
    }
}
