using System.Text;
using Corvus.Core;
using Corvus.Core.Documents;
using Corvus.Core.Installers;

namespace Corvus.Services.Analysis;

/// <summary>view=installer: an MSI's product, files, code it runs, registry values, services, shortcuts and review findings, and the commands in an NSIS or Inno Setup script, without running it.</summary>
internal sealed class InstallerFileView : IFileSummaryView
{
    public sealed record Product(string? Name, string? Version, string? Manufacturer, string? ProductCode, string? UpgradeCode, string? Language);

    /// <summary>A step that runs code: its name, kind (DLL, EXE, JScript, ...), where the code comes from, when and how it runs.</summary>
    public sealed record CodeStep(string Name, string Kind, string Source, string? Target, string Execution, IReadOnlyList<string> When);

    public sealed record RegistryValue(string Key, string? Name, string? Value, int? Index = null, string? Kind = null);

    public sealed record Service(string Name, string? DisplayName, string? Start, string? Account, string? Arguments);

    public sealed record Facts(string Format, Product? Product, IReadOnlyDictionary<string, string>? Summary, int Files, long FilesSize, IReadOnlyList<string> Cabinets,
        IReadOnlyList<CodeStep> CustomActions, IReadOnlyList<RegistryValue> Registry, IReadOnlyList<Service> Services, IReadOnlyList<string> Shortcuts,
        IReadOnlyList<MacroFinding> Findings, IReadOnlyList<string> Notes, string? Builder = null, IReadOnlyList<ScriptCommand>? Commands = null, bool? CompiledCode = null, string? CommandsUnknown = null);

    /// <summary>A script command at its entry index: its kind (Exec, ExecWait, ExecShell, PluginCall, Run, ...) and text.</summary>
    public sealed record ScriptCommand(int Index, string Kind, string Text);

    public string Name => "installer";

    private const int MaxListed = 200;

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (MsiDatabase.Looks(file.Head) && file.Length <= 2L << 30) return Msi(MsiPackage.Read(file.Bytes, System.IO.Path.GetFileName(file.Path), ct));
        if (file.Head.AsSpan().StartsWith("MZ"u8) && file.Length <= 2L << 30) return Script(file);
        return null;
    }

    /// <summary>The builder a creating application or version string names; null when it names none of the two.</summary>
    internal static string? BuilderOf(string? text) =>
        text is null ? null : text.Contains("InstallShield", StringComparison.OrdinalIgnoreCase) ? "InstallShield"
        : text.Contains("Advanced Installer", StringComparison.OrdinalIgnoreCase) ? "Advanced Installer" : null;

    private static FileView? Script(FileInput file)
    {
        var name = System.IO.Path.GetFileName(file.Path);
        InstallerScript? script = null;
        string format = "";
        try
        {
            if (new NsisInstallerReader().Accepts(file.Head, name)) (format, script) = ("NSIS installer", NsisInstallerReader.ReadScript(new MemoryStream(file.Bytes, writable: false), name));
            else if (new InnoSetupReader().Accepts(file.Head, name)) (format, script) = ("Inno Setup installer", InnoSetupReader.ReadScript(new MemoryStream(file.Bytes, writable: false), name));
        }
        catch (ToolError e) { script = InstallerScript.Undecoded(format.Length > 0 ? format : "installer", e.Message); }
        if (script is null) return Builder(file);

        var commands = script.Commands.Select(c => new ScriptCommand(c.Index, c.Kind, c.Text)).ToList();
        var registry = script.Registry.Select(r => new RegistryValue(r.Key, r.Name, r.Value, r.Index, r.Kind)).ToList();
        var findings = new List<MacroFinding>();
        foreach (var r in script.Registry.Where(r => Autostart.Any(a => r.Key.Contains(a, StringComparison.OrdinalIgnoreCase))))
            findings.Add(new MacroFinding("Suspicious", $@"{r.Key}\{r.Name}", $"an autostart registry value: {r.Value}") { Location = "Registry" });
        var facts = new Facts(format, null, null, 0, 0, [], [], [.. registry.Take(MaxListed)], [], [], findings, script.Unknown is null ? [] : [script.Unknown],
            script.Builder, [.. commands.Take(MaxListed)], script.CompiledCode, script.Unknown);
        var h = new List<string> { script.Unknown is null ? $"{format}: {commands.Count} command(s) run, {registry.Count} registry value(s) written." : $"{format}: the script commands are unknown ({script.Unknown})" };
        if (script.CompiledCode == true) h.Add("The setup carries a compiled Pascal script.");
        h.AddRange(commands.Take(5).Select(c => $"Entry {c.Index} {c.Kind}: {c.Text}"));
        return new FileView(facts, h) { Findings = [.. FindingRules.FromMacros(findings, "installer"), .. FindingRules.FromLaunchers(Launchers.MatchAll(commands.Select(c => (string?)c.Text)), "installer")] };
    }

    /// <summary>InstallShield and Advanced Installer setups are named from their version resource; their scripts are not read.</summary>
    private static FileView? Builder(FileInput file)
    {
        if (file.Streamed) return null;
        string? builder;
        try
        {
            var info = Corvus.Native.Pe.PeFile.FromBytes(file.Bytes, file.Path).VersionInfo;
            builder = new[] { "ProductName", "FileDescription", "Comments", "InternalName" }.Select(k => BuilderOf(info?.Get(k))).FirstOrDefault(b => b != null);
        }
        catch (Exception e) when (e is not OperationCanceledException) { return null; }
        if (builder is null) return null;
        var notes = new List<string> { $"{builder} setup: the script is not read." };
        return new FileView(new Facts($"{builder} installer", null, null, 0, 0, [], [], [], [], [], [], notes, builder), [notes[0]]);
    }

    internal static readonly IReadOnlyList<string> Autostart =
        [@"\currentversion\run", @"\currentversion\runonce", @"\currentversion\winlogon", @"\currentversion\policies\explorer\run", @"\image file execution options",
         @"\currentcontrolset\services", @"\currentversion\explorer\shell folders", @"\active setup\installed components"];

    private static FileView Msi(MsiPackage p)
    {
        var db = p.Database;
        var props = p.Properties;
        var product = new Product(props.GetValueOrDefault("ProductName"), props.GetValueOrDefault("ProductVersion"), props.GetValueOrDefault("Manufacturer"),
            props.GetValueOrDefault("ProductCode"), props.GetValueOrDefault("UpgradeCode"), props.GetValueOrDefault("ProductLanguage"));
        var findings = new List<MacroFinding>();
        var commands = new List<string?>();
        var steps = new List<CodeStep>();
        foreach (var ca in p.CustomActions)
        {
            var target = ca.Target is { Length: > 300 } t ? t[..297] + "..." : ca.Target;
            steps.Add(new CodeStep(ca.Action, ca.Kind, ca.SourceKind == "inline" ? "inline" : $"{ca.SourceKind} {ca.Source}", target, ca.Execution, ca.Sequences));
            if (ca.Kind == "EXE") commands.Add($"{ca.Source} {ca.Target}");
            if (ca.Kind is "DLL" or "EXE" or "JScript" or "VBScript" or "nested install")
                findings.Add(new MacroFinding("Suspicious", ca.Action, $"runs {ca.Kind} from {(ca.SourceKind == "inline" ? "inline text" : $"{ca.SourceKind} {ca.Source}")}, {ca.Execution}") { Location = "CustomAction" });
            // Script text is inline, in the Binary table, or a property's value.
            string? script = ca.SourceKind == "inline" ? ca.Target
                : ca.SourceKind == "Binary" && ca.Kind is "JScript" or "VBScript" && ca.Source != null && p.Binary(ca.Source, 16 << 20) is { } b ? Encoding.UTF8.GetString(b)
                : ca.SourceKind == "Property" && ca.Kind is "JScript" or "VBScript" && ca.Source != null ? props.GetValueOrDefault(ca.Source) : null;
            if (script != null)
                findings.AddRange(MacroScan.Scan([(ca.Action, script)]).Where(f => f.Type is "Suspicious" or "IOC").Select(f => f with { Location = $"CustomAction {f.Location ?? ca.Action}" }));
        }
        var registry = new List<RegistryValue>();
        foreach (var r in db.Table("Registry")?.Records() ?? [])
        {
            var root = (r.GetValueOrDefault("Root") as int?) switch { 0 => "HKCR", 1 => "HKCU", 2 => "HKLM", 3 => "HKU", -1 => "HKCU or HKLM (per-user or per-machine)", var v => $"root {v}" };
            var key = $@"{root}\{r.GetValueOrDefault("Key")}";
            var value = new RegistryValue(key, r.GetValueOrDefault("Name") as string, r.GetValueOrDefault("Value") as string);
            registry.Add(value);
            if (Autostart.Any(a => key.Contains(a, StringComparison.OrdinalIgnoreCase)))
                findings.Add(new MacroFinding("Suspicious", $@"{key}\{value.Name}", $"an autostart registry value: {value.Value}") { Location = "Registry" });
        }
        var services = (db.Table("ServiceInstall")?.Records() ?? []).Select(r => new Service(r.GetValueOrDefault("Name") as string ?? "", r.GetValueOrDefault("DisplayName") as string,
            (r.GetValueOrDefault("StartType") as int?) switch { 2 => "automatic", 3 => "on demand", 4 => "disabled", 0 => "boot", 1 => "system", var v => v?.ToString() },
            r.GetValueOrDefault("StartName") as string, r.GetValueOrDefault("Arguments") as string)).ToList();
        foreach (var s in services.Where(s => s.Start is "automatic" or "boot" or "system"))
            findings.Add(new MacroFinding("Suspicious", s.Name, $"installs a service that starts {s.Start}{(s.Account != null ? $" as {s.Account}" : "")}") { Location = "ServiceInstall" });
        var shortcuts = (db.Table("Shortcut")?.Records() ?? []).Select(r => $"{MsiPackage.LongName(r.GetValueOrDefault("Name") as string)} -> {r.GetValueOrDefault("Target")}{(r.GetValueOrDefault("Arguments") is string a && a.Length > 0 ? " " + a : "")}").ToList();
        commands.AddRange(shortcuts);
        foreach (var f in p.Files.Where(f => f.Path.Contains("/Startup/", StringComparison.Ordinal)))
            findings.Add(new MacroFinding("Suspicious", f.Path, "a file installed in the Startup folder runs at every logon") { Location = "File" });
        var cabinets = p.Files.Select(f => f.Cabinet).Where(c => c != null).Distinct().Select(c => c!.StartsWith('#') ? $"{c[1..]} (embedded)" : $"{c} (external)").ToList();
        var notes = new List<string>(p.Notes);
        if (db.Table("Binary") is { Rows.Count: > 0 } binary)
            notes.Add($"Binary table: {string.Join(", ", binary.Rows.Select(r => r[0]).Take(20))}; unpack_container writes them under Binary/, where load_assembly reads a DLL or EXE.");
        var facts = new Facts($"Windows Installer {db.Kind}", product, p.Summary, p.Files.Count, p.Files.Sum(f => f.Size), cabinets,
            steps, [.. registry.Take(MaxListed)], services, [.. shortcuts.Take(MaxListed)], findings, notes, BuilderOf(p.Summary.GetValueOrDefault("application")));
        var h = new List<string> { $"Windows Installer package: {product.Name} {product.Version} by {product.Manufacturer}; {p.Files.Count} file(s), {steps.Count(s => s.Kind is "DLL" or "EXE" or "JScript" or "VBScript")} custom action(s) running code." };
        h.AddRange(p.CustomActions.Where(c => c.System && c.Kind is "DLL" or "EXE" or "JScript" or "VBScript").Take(5).Select(c => $"Custom action {c.Action} runs {c.Kind} as LocalSystem."));
        h.AddRange(findings.Where(f => f.Location is "Registry" or "ServiceInstall" or "File").Take(5).Select(f => $"Worth reviewing: {f.Description} ({f.Keyword})."));
        return new FileView(facts, h) { Findings = [.. FindingRules.FromMacros(findings, "installer"), .. FindingRules.FromLaunchers(Launchers.MatchAll(commands), "installer")] };
    }
}
