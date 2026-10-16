using System.Xml.Linq;
using Corvus.Services;
using Corvus.Tools;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Corvus.Tests;

/// <summary>Event handlers in decompiled XAML joined to the code-behind methods.</summary>
public class XamlEventsTests(Xunit.Abstractions.ITestOutputHelper output)
{
    [Fact]
    public void Handlers_resolve_to_methods_of_the_class_and_its_base()
    {
        var module = new ModuleDefUser("App.dll");
        var obj = module.CorLibTypes.Object;
        var basePage = new TypeDefUser("App", "PageBase", module.CorLibTypes.Object.TypeDefOrRef);
        var page = new TypeDefUser("App", "MainPage", basePage);
        module.Types.Add(basePage);
        module.Types.Add(page);
        MethodDef Handler(TypeDef t, string name)
        {
            var m = new MethodDefUser(name, MethodSig.CreateInstance(module.CorLibTypes.Void, obj, obj), MethodAttributes.Private);
            t.Methods.Add(m);
            return m;
        }
        Handler(page, "Save_Click");
        Handler(basePage, "OnHover");
        page.Methods.Add(new MethodDefUser("Helper", MethodSig.CreateInstance(module.CorLibTypes.Void, obj), MethodAttributes.Private));

        const string xaml = """
            <Page x:Class="App.MainPage" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
              <Page.Resources>
                <Style TargetType="Button"><EventSetter Event="MouseEnter" Handler="OnHover" /></Style>
              </Page.Resources>
              <StackPanel>
                <Button x:Name="Save" Content="Helper" Click="Save_Click" />
                <TextBlock Name="Save_Click" Text="Save_Click is a text, not a handler, here" />
              </StackPanel>
            </Page>
            """;
        var (handlers, error, className) = XamlEvents.Resolve(module, xaml);
        Assert.Null(error);
        Assert.Equal("App.MainPage", className);
        Assert.Equal(["EventSetter.MouseEnter = App.PageBase::OnHover(object, object)", "Save.Click = App.MainPage::Save_Click(object, object)"],
            handlers.Select(h => $"{h.Element}.{h.Event} = {h.Symbol}").Order(StringComparer.Ordinal));
        Assert.Contains("the XAML above is not well-formed", XamlEvents.Footer(module, "<Page><Button></Page>"));
    }

    public const string WpfApps = "CORVUS_WPF_APPS";

    /// <summary>
    /// Every BAML entry of the WPF programs under CORVUS_WPF_APPS (.exe, three levels deep) decompiles to XAML that parses,
    /// and every handler their generated Connect methods hook up (ldftn) is named in the XAML and resolved.
    /// </summary>
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact(WpfApps)]
    public async Task Wpf_apps_xaml_parses_and_every_connected_handler_resolves()
    {
        int apps = 0;
        var problems = new List<string>();
        foreach (var exe in Directory.EnumerateFiles(RealData.Get(WpfApps)!, "*.exe", new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 3 }))
        {
            ModuleDefMD module;
            try { module = ModuleDefMD.Load(exe); }
            catch (BadImageFormatException) { continue; }
            using (module)
            {
                var resource = module.Resources.FirstOrDefault(r => r.Name.EndsWith(".g.resources", StringComparison.Ordinal));
                if (resource == null) continue;
                // What the generated Connect methods hook up: (class, handler method token).
                var connected = module.GetTypes().SelectMany(t => t.Methods.Where(m => m.Name.EndsWith("Connect", StringComparison.Ordinal) && m.HasBody && m.Parameters.Count == 3)
                        .SelectMany(m => m.Body.Instructions.Where(i => i.OpCode == OpCodes.Ldftn && i.Operand is MethodDef { Name.String: var n } && !n.StartsWith('<'))
                            .Select(i => (Class: t.FullName, Token: ((MethodDef)i.Operand).MDToken.Raw))))
                    .ToHashSet();
                using var env = new Env(exe);
                using var dir = new TempDir();
                var tools = new ResourceTools(env.Workspace, env.Resources, env.Decompiler, env.Pager);
                var listing = await tools.GetResource(env.Fixture.Id, resource.Name);
                var entries = listing.Split('\n').Select(l => l.Trim()).Where(l => l.Contains(".baml  ", StringComparison.Ordinal)).Select(l => l.Split("  ")[0]).ToList();
                var resolved = new HashSet<(string, uint)>();
                int parsed = 0;
                foreach (var entry in entries)
                {
                    var saved = dir.File(Guid.NewGuid().ToString("N"));
                    await tools.GetResource(env.Fixture.Id, resource.Name, entry, saved);
                    var xaml = env.Workspace.Read(() => env.Decompiler.DecompileBaml(env.Fixture, File.ReadAllBytes(saved), default));
                    if (xaml == null) { problems.Add($"{Path.GetFileName(exe)} {entry}: not decompiled"); continue; }
                    try { XDocument.Parse(xaml); parsed++; }
                    catch (System.Xml.XmlException e) { problems.Add($"{Path.GetFileName(exe)} {entry}: {e.Message}"); continue; }
                    var (handlers, _, className) = XamlEvents.Resolve(env.Fixture.Module, xaml);
                    foreach (var h in handlers) resolved.Add((className!, h.Token));
                }
                var missing = connected.Where(c => !resolved.Contains(c)).ToList();
                foreach (var (cls, token) in missing) problems.Add($"{Path.GetFileName(exe)}: {cls} handler 0x{token:X8} hooked up in Connect but not resolved from the XAML");
                output.WriteLine($"{Path.GetFileName(exe)}: {entries.Count} BAML, {parsed} parse; {connected.Count} connected handlers, {connected.Count - missing.Count} resolved");
                apps++;
            }
        }
        Assert.True(apps >= 3, $"{apps} WPF programs under {WpfApps}");
        Assert.True(problems.Count == 0, string.Join("\n", problems.Take(30)));
    }
}
