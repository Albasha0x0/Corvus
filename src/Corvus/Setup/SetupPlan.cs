using System.Text.Json.Nodes;

namespace Corvus.Setup;

/// <summary>
/// What install would change, per client, computed before any write. Existing registrations are always refreshed (only
/// the command is re-pointed); named clients are added; other detected clients are new and need consent: --yes,
/// --all-detected or a confirmation. With refresh only (update) new clients are never added.
/// </summary>
internal static class SetupPlan
{
    public static List<ClientReport> Build(IReadOnlyList<McpClient> clients, ServerLaunch launch, IReadOnlyCollection<McpClient> named, bool refreshOnly)
    {
        var rows = new List<ClientReport>();
        foreach (var client in clients)
        {
            var current = client.Target.Current(ClientCatalog.ServerName);
            bool isNamed = named.Contains(client);
            var row = new ClientReport
            {
                Id = client.Id, Name = client.Name, Detected = client.Present, ConfigPath = client.Target.Path, Registered = current, Client = client,
            };
            rows.Add(row);
            if (!client.Present && current == null && !isNamed)
            {
                row.Message = "not detected";
                continue;
            }
            var preview = client.Target.Preview(ClientCatalog.ServerName, launch);
            row.Action = preview.Action;
            row.Before = preview.Before;
            row.After = preview.After;
            row.BackupPath = preview.BackupPath;
            row.PreservesComments = preview.Action is SetupAction.Add or SetupAction.Refresh && preview.BackupPath != null ? preview.PreservesComments : null;
            row.Message = Describe(row, preview.Reason);
            if (preview.Action != SetupAction.Add || isNamed) continue;
            if (refreshOnly)
            {
                row.Action = SetupAction.Skip;
                row.Message = "detected, not registered (update adds no clients)";
            }
            else
            {
                row.NeedsConsent = true;
            }
        }
        return rows;
    }

    /// <summary>Rows worth showing: everything except clients that are neither detected, registered nor named.</summary>
    public static IEnumerable<ClientReport> Shown(IEnumerable<ClientReport> rows) =>
        rows.Where(r => r.Action != SetupAction.Skip || r.NeedsConsent || r.Detected || r.Registered != null);

    /// <summary>Resolves the consent of new clients: added, or skipped with a note.</summary>
    public static void Decide(IEnumerable<ClientReport> rows, bool add)
    {
        foreach (var row in rows.Where(r => r.NeedsConsent))
        {
            row.NeedsConsent = false;
            if (add) continue;
            row.Action = SetupAction.Skip;
            row.Message = "detected, not registered";
            row.Before = row.After = null;
            row.BackupPath = null;
            row.PreservesComments = null;
        }
    }

    private static string Describe(ClientReport row, string? reason)
    {
        if (row.Action == SetupAction.Blocked) return $"left unchanged: {reason}";
        var notes = new List<string>();
        if (row.Action == SetupAction.Unchanged) notes.Add("already registered");
        if (row.Action == SetupAction.Add) notes.Add(row.BackupPath == null ? "new file" : $"backup {Path.GetFileName(row.BackupPath)}");
        if (row.Action == SetupAction.Refresh && row.Before is JsonObject before && row.After is JsonObject after)
        {
            var changed = after.Select(p => p.Key).Where(k => !JsonNode.DeepEquals(before[k], after[k])).ToList();
            notes.Add(changed.Count == 0 ? "updated" : $"updates {string.Join(", ", changed)}");
            if (row.Registered is { Args.Count: > 0 }) notes.Add("your args kept");
        }
        if (row.Action is SetupAction.Add or SetupAction.Refresh && row.BackupPath != null && row.PreservesComments == false) notes.Add("comments not kept");
        if (row.Disabled) notes.Add("disabled: kept disabled");
        return string.Join("; ", notes);
    }

    /// <summary>The plan as aligned text rows, paths shortened with ~.</summary>
    public static void Write(TextWriter output, SetupEnvironment env, IEnumerable<ClientReport> rows)
    {
        foreach (var row in Shown(rows))
        {
            var action = row.NeedsConsent ? "add (new)" : row.Action;
            output.WriteLine($"  {action,-10} {row.Name,-20} {Short(env, row.ConfigPath)}{(string.IsNullOrEmpty(row.Message) ? "" : "  " + row.Message)}");
        }
    }

    public static string Short(SetupEnvironment env, string path) =>
        path.StartsWith(env.Home, StringComparison.OrdinalIgnoreCase) ? "~" + path[env.Home.Length..] : path;
}
