using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Corvus.Core.Logs;

namespace Corvus.Setup;

/// <summary>batch --file log.evtx --evtx-jsonl: each recovered event as one JSON line.</summary>
internal static partial class ToolCli
{
    /// <summary>
    /// Runs --evtx-jsonl: writes the events and a count line. A usage error
    /// when the file or output is unusable.
    /// </summary>
    private static int EvtxJsonl(CliArgs a, CliIo io, CancellationToken ct)
    {
        if (a.Json || a.JsonLines || a.Recurse) throw new UsageException("--evtx-jsonl is a mode of its own: it does not go with --json, --jsonl or --recurse.");
        var path = Path.GetFullPath(a.BatchFile!);
        if (!File.Exists(path)) throw new UsageException($"No such file: {a.BatchFile}.");
        var output = OutputPath("--evtx-jsonl", a.EvtxJsonl);
        if (output != null && Directory.Exists(output)) throw new UsageException($"--evtx-jsonl names a file, not a folder: {a.EvtxJsonl}.");
        if (output != null && string.Equals(Path.GetFullPath(output), path, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new UsageException("--evtx-jsonl must not name the input log.");
        var (count, notes) = WriteEvtxLines(path, output!, ct);
        io.Out.WriteLine($"{count} event(s) written to {a.EvtxJsonl}.");
        if (count == 0 && notes.Count > 0) io.Out.WriteLine($"No event was readable; {notes.Count} note(s), first: {notes[0]}");
        return Exit.Ok;
    }

    /// <summary>
    /// Writes the events of the event log at <paramref name="path"/> to
    /// <paramref name="output"/>; returns the count and the reader's notes.
    /// A usage error when the file is not an event log or the output cannot
    /// be written.
    /// </summary>
    internal static (long Count, IReadOnlyList<string> Notes) WriteEvtxLines(string path, string output, CancellationToken ct)
    {
        long count = 0;
        // Write beside the output and move into place, so a refused file leaves none.
        var temp = output + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using var input = File.OpenRead(path);
            EvtxFile file;
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write))
            using (var writer = new StreamWriter(stream, new UTF8Encoding(false), 4096) { NewLine = "\n" })
            {
                try
                {
                    file = EvtxFile.Read(input, e =>
                    {
                        writer.Write(EvtxLine(e).ToJsonString(Compact));
                        writer.Write('\n');
                        count++;
                    }, ct);
                }
                catch (InvalidDataException ex) { throw new UsageException($"{Path.GetFileName(path)}: not a readable event log: {ex.Message}"); }
            }
            File.Move(temp, output, overwrite: true);
            return (count, file.Notes);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new UsageException($"{Path.GetFileName(path)}: cannot write {output}: {ex.Message}");
        }
        finally
        {
            try { File.Delete(temp); } catch (Exception) { }
        }
    }

    /// <summary>
    /// One event as a Timesketch record (message, datetime, timestamp_desc)
    /// holding the nested Event.System and Event.EventData shape of evtx_dump.
    /// </summary>
    internal static JsonObject EvtxLine(EvtxFile.Event e)
    {
        // The reader yields UTC for both times, so no conversion is needed.
        var time = e.Created ?? e.Written;
        var stamp = time.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'+00:00'", CultureInfo.InvariantCulture);
        var system = new JsonObject();
        if (e.Provider != null) system["Provider"] = Attributes(("Name", e.Provider));
        if (e.EventId != null) system["EventID"] = e.EventId;
        if (e.Level != null) system["Level"] = e.Level;
        system["TimeCreated"] = Attributes(("SystemTime", stamp));
        system["EventRecordID"] = e.EventRecordId ?? e.RecordId;
        if (e.Channel != null) system["Channel"] = e.Channel;
        if (e.Computer != null) system["Computer"] = e.Computer;
        if (e.ProcessId != null || e.ThreadId != null)
            system["Execution"] = Attributes(("ProcessID", e.ProcessId), ("ThreadID", e.ThreadId));
        if (e.UserId != null) system["Security"] = Attributes(("UserID", e.UserId));
        var data = new JsonObject();
        foreach (var (name, value) in e.Data)
        {
            var key = name;
            for (int n = 2; data.ContainsKey(key); n++) key = $"{name}_{n}";
            data[key] = value;
        }
        var values = string.Join("; ", e.Data.Where(d => d.Value.Length > 0).Take(8).Select(d => $"{d.Key}={Clip(d.Value)}"));
        var line = new JsonObject
        {
            ["message"] = $"{e.Provider ?? "?"} event {(e.EventId?.ToString(CultureInfo.InvariantCulture) ?? "?")}" + (values.Length > 0 ? $": {values}" : ""),
            ["datetime"] = stamp,
            ["timestamp_desc"] = e.Created != null ? "Event Created" : "Record Written",
            ["Event"] = new JsonObject { ["System"] = system, ["EventData"] = data },
        };
        if (e.Recovered) line["recovered"] = true;
        return line;
    }

    private static string Clip(string value) => value.Length > 200 ? value[..200] + "..." : value;

    private static JsonObject Attributes(params (string Name, object? Value)[] items)
    {
        var attributes = new JsonObject();
        foreach (var (name, value) in items)
            if (value != null) attributes[name] = value is int n ? JsonValue.Create(n) : JsonValue.Create(value.ToString());
        return new JsonObject { ["#attributes"] = attributes };
    }
}
