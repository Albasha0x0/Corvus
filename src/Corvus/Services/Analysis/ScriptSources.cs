using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>
/// A file whose commands sit inside a container format: the readable text, the
/// blocks a script reader can peel, the raw command lines, and what was bounded.
/// </summary>
internal sealed record SourceParts(string Kind, string Plain, IReadOnlyList<ScriptFileView.Block> Blocks, IReadOnlyList<string> Commands, IReadOnlyList<string> Notes);

/// <summary>Reads the actions, triggers and principal of a Task Scheduler definition (XML).</summary>
internal static class TaskDefinition
{
    private const int MaxActions = 256;

    // A path with spaces is quoted; a whole command line is kept as written.
    private static readonly Regex BarePath = new(@"\A[A-Za-z]:\\[^""]* [^""]*\.(?:exe|bat|cmd|com)\z", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking);

    /// <summary>The actions as blocks and commands; null for a non-task; a malformed task is reported as unknown.</summary>
    internal static SourceParts? Read(string text)
    {
        if (!Regex.IsMatch(text.Length > 4096 ? text[..4096] : text, @"<Task\b[^>]*schemas\.microsoft\.com/windows/\d{4}/\d{2}/mit/task", RegexOptions.NonBacktracking)) return null;
        XElement root;
        try { root = BoundedXml.Parse(text).Root!; }
        catch (XmlException) { return new SourceParts("scheduled task", "", [], [], ["Task XML could not be parsed; actions are unknown."]); }
        var plain = new StringBuilder();
        var blocks = new List<ScriptFileView.Block>();
        var commands = new List<string>();
        var notes = new List<string>();
        XElement? Section(string name) => root.Elements().FirstOrDefault(x => x.Name.LocalName == name);

        if (Section("Triggers") is { } triggers)
            foreach (var t in triggers.Elements())
                plain.Append("trigger: ").Append(t.Name.LocalName).Append(Child(t, "Enabled") == "false" ? " (disabled)" : "").Append('\n');
        if (Section("Principals")?.Elements().FirstOrDefault() is { } principal)
        {
            var who = new[] { Child(principal, "UserId"), Child(principal, "GroupId") }.FirstOrDefault(x => x.Length > 0);
            plain.Append("runs as: ").Append(who ?? "(unnamed)").Append(Child(principal, "RunLevel") is { Length: > 0 } level ? $", {level}" : "").Append('\n');
        }
        if (Child(Section("Settings"), "Hidden") == "true") plain.Append("hidden: true\n");
        if (Section("Actions") is { } actions)
        {
            var all = actions.Elements().ToList();
            foreach (var a in all.Take(MaxActions))
                switch (a.Name.LocalName)
                {
                    case "Exec":
                        var command = Child(a, "Command");
                        var line = (BarePath.IsMatch(command) ? $"\"{command}\"" : command) + (Child(a, "Arguments") is { Length: > 0 } args ? " " + args : "");
                        plain.Append("run: ").Append(line).Append('\n');
                        if (Child(a, "WorkingDirectory") is { Length: > 0 } cwd) plain.Append("in: ").Append(cwd).Append('\n');
                        commands.Add(line);
                        blocks.Add(new ScriptFileView.Block("batch", line));
                        break;
                    case "ComHandler":
                        plain.Append("com handler: ").Append(Child(a, "ClassId")).Append('\n');
                        break;
                    default:
                        plain.Append("action: ").Append(a.Name.LocalName).Append('\n');
                        break;
                }
            if (all.Count > MaxActions) notes.Add($"Read {MaxActions} of {all.Count} actions; the rest are not shown.");
        }
        return new SourceParts("scheduled task", plain.ToString(), blocks, commands, notes);
    }

    private static string Child(XElement? e, string name) => e?.Elements().FirstOrDefault(x => x.Name.LocalName == name)?.Value.Trim() ?? "";
}

/// <summary>Reads the code cells of a notebook (nbformat 4 JSON) and the shell commands inside them.</summary>
internal static class NotebookCells
{
    private const int MaxCommands = 1000;

    private static readonly Regex Subprocess = new(
        @"\b(?:os\.(?:system|popen)|subprocess\.(?:run|call|Popen|check_call|check_output|getoutput|getstatusoutput))\(\s*[rbf]?(?:""([^""\n]*)""|'([^'\n]*)')",
        RegexOptions.NonBacktracking);

    private static readonly Regex ProcessCall = new(@"\b(?:os\.(?:system|popen)|subprocess\.\w+)\(", RegexOptions.NonBacktracking);

    private static readonly Regex CellMagic = new(@"\A\s*%%(\w+)[^\n]*\n(.*)\z", RegexOptions.Singleline | RegexOptions.NonBacktracking);

    /// <summary>The code cells, shell blocks and commands; null for a non-notebook; malformed JSON is reported as unknown.</summary>
    internal static SourceParts? Read(string text)
    {
        JsonDocument doc;
        try { doc = InputJson.ParseDocument(text, new JsonDocumentOptions { MaxDepth = 64 }); }
        catch (JsonException) { return new SourceParts("notebook", "", [], [], ["Notebook JSON could not be parsed; cells are unknown."]); }
        using (doc)
        {
            if (doc.RootElement is not { ValueKind: JsonValueKind.Object } root || !root.TryGetProperty("cells", out var cells) || cells.ValueKind != JsonValueKind.Array) return null;
            var plain = new StringBuilder();
            var blocks = new List<ScriptFileView.Block>();
            var commands = new List<string>();
            int index = 0, code = 0, unreadable = 0, python = 0, all = 0, calls = 0, total = cells.GetArrayLength();
            foreach (var cell in cells.EnumerateArray())
            {
                index++;
                if (cell.ValueKind != JsonValueKind.Object || !cell.TryGetProperty("cell_type", out var type) || type.GetString() != "code") continue;
                if (!cell.TryGetProperty("source", out var source) || Source(source) is not { } body) { unreadable++; continue; }
                code++;
                plain.Append($"# cell {index}\n").Append(body).Append(body.EndsWith('\n') ? "" : "\n");
                var shell = Shell(body, out var block, out var isPython);
                if (isPython) python++;
                all += shell.Count;
                if (shell.Count == 0 && ProcessCall.IsMatch(body)) calls++;
                commands.AddRange(shell.Take(MaxCommands - commands.Count));
                if (block != null) blocks.Add(block);
            }
            var skipped = total - code - unreadable;
            var notes = new List<string> { $"Read {code} code cell(s) of {total} cell(s)" + (skipped > 0 ? $"; {skipped} markdown or raw cell(s) skipped." : ".") };
            if (python > 0) notes.Add("Python cells are listed, not peeled.");
            if (calls > 0) notes.Add($"{calls} cell(s) call a process with a non-literal or list-form argument; those commands are not read.");
            if (unreadable > 0) notes.Add($"{unreadable} code cell(s) have no readable source.");
            if (all > commands.Count) notes.Add($"Read {commands.Count:N0} of {all:N0} shell commands.");
            return new SourceParts("notebook", plain.ToString(), blocks, commands, notes);
        }
    }

    // A cell's source is one string or an array of lines.
    private static string? Source(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.String => e.GetString(),
        JsonValueKind.Array => string.Concat(e.EnumerateArray().Select(x => x.ValueKind == JsonValueKind.String ? x.GetString() : "")),
        _ => null,
    };

    // Shell lines (!cmd), shell cell magics (%%cmd, %%powershell) and string
    // commands of os.system and subprocess.
    private static List<string> Shell(string body, out ScriptFileView.Block? block, out bool python)
    {
        block = null;
        python = true;
        var found = new List<string>();
        var magic = CellMagic.Match(body);
        if (magic.Success)
        {
            var name = magic.Groups[1].Value.ToLowerInvariant();
            if (name == "writefile") { python = false; return found; }
            if (name is "cmd" or "bat" or "powershell" or "pwsh" or "bash" or "sh" or "script" or "system")
            {
                python = false;
                var cell = magic.Groups[2].Value;
                found.Add(cell.Trim());
                block = name switch { "powershell" or "pwsh" => new("powershell", cell), "cmd" or "bat" => new("batch", cell), _ => null };
                return found;
            }
            body = magic.Groups[2].Value;
        }
        foreach (var raw in body.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length > 1 && line[0] == '!') found.Add(line[1..].Trim());
            else if (Subprocess.Match(line) is { Success: true } m) found.Add(m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value);
        }
        return found;
    }
}
