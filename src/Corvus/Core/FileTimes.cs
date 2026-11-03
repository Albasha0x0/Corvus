using System.Globalization;
using System.IO.Compression;
using System.Reflection.PortableExecutable;
using System.Text.Json.Nodes;
using Corvus.Core.Documents;
using Corvus.Core.Registry;

namespace Corvus.Core;

/// <summary>One stored time: the field it came from, where in the file, and the name it belongs to.</summary>
internal sealed record FileTimeEvent(DateTime Utc, string Desc, string Where, string Name);

/// <summary>The times of one file; a note names each time left out and each limit.</summary>
internal sealed record FileTimesResult(IReadOnlyList<FileTimeEvent> Events, IReadOnlyList<string> Notes);

/// <summary>Reads the times stored inside a file: PE header, shell link, compound file, registry hive and zip.</summary>
internal static class FileTimes
{
    /// <summary>Events one hive or archive yields before the walk stops.</summary>
    internal const int EventLimit = 100_000;

    private const long MaxBytes = 256L << 20;

    /// <summary>
    /// Every stored time of the file, detected by content. An unknown format
    /// gives one note and no events; an unreadable one gives a note.
    /// </summary>
    public static FileTimesResult Read(string path, CancellationToken ct)
    {
        var events = new List<FileTimeEvent>();
        var notes = new List<string>();
        var name = System.IO.Path.GetFileName(path);
        var head = new byte[4096];
        int n;
        long length;
        using (var s = File.OpenRead(path))
        {
            length = s.Length;
            n = s.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
        }
        var span = head.AsSpan(0, n);
        try
        {
            if (span.Length >= 2 && span[0] == 'M' && span[1] == 'Z') Pe(path, name, events, notes);
            else if (FileHeaders.Zip(span)) Zip(path, events, notes, ct);
            else if (ShellLink.Looks(span) || CompoundFile.Looks(span) || RegistryHive.Looks(span))
            {
                if (length > MaxBytes) notes.Add($"{name}: larger than {MaxBytes >> 20} MiB; times unknown");
                else Bytes(File.ReadAllBytes(path), name, events, notes, ct);
            }
            else notes.Add($"{name}: format not recognized; times unknown");
        }
        catch (Exception ex) when (ex is ToolError or InvalidDataException or BadImageFormatException or ArgumentException or IOException)
        {
            notes.Add($"{name}: unreadable ({ex.Message}); times unknown");
        }
        return new FileTimesResult(events, notes);
    }

    /// <summary>The Timesketch record of one event: message, datetime, timestamp_desc, data_type and source_file.</summary>
    public static JsonObject Line(FileTimeEvent e, string sourceFile) => new()
    {
        ["message"] = $"{e.Desc}: {e.Where}",
        ["datetime"] = e.Utc.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'+00:00'", CultureInfo.InvariantCulture),
        ["timestamp_desc"] = e.Desc,
        ["data_type"] = "corvus:file_times",
        ["source_file"] = sourceFile,
    };

    private static void Bytes(byte[] data, string name, List<FileTimeEvent> events, List<string> notes, CancellationToken ct)
    {
        if (ShellLink.Looks(data)) Link(ShellLink.Read(data, name), name, events, notes);
        else if (CompoundFile.Looks(data)) Compound(CompoundFile.Read(data, name), events, notes);
        else Hive(RegistryHive.Read(data), name, events, notes, ct);
    }

    private static void Pe(string path, string name, List<FileTimeEvent> events, List<string> notes)
    {
        using var s = File.OpenRead(path);
        using var pe = new PEReader(s);
        var stamp = pe.PEHeaders.CoffHeader.TimeDateStamp;
        var time = DateTime.UnixEpoch.AddSeconds(stamp);
        if (time.Year is < 1995 or > 2100) notes.Add($"{name}: deterministic stamp, not a time (0x{stamp:X8})");
        else events.Add(new(time, "COFF TimeDateStamp", "COFF header", name));
    }

    private static void Link(ShellLink link, string name, List<FileTimeEvent> events, List<string> notes)
    {
        int unknown = 0;
        foreach (var (time, desc) in new[] { (link.Created, "Link creation time"), (link.Accessed, "Link access time"), (link.Modified, "Link write time") })
        {
            if (time is { } t) events.Add(new(DateTime.SpecifyKind(t, DateTimeKind.Utc), desc, "Shell link header", link.Target ?? name));
            else unknown++;
        }
        if (unknown > 0) notes.Add($"{name}: {unknown} link time(s) zero or out of range; unknown");
        notes.AddRange(link.Notes);
    }

    private static void Compound(CompoundFile file, List<FileTimeEvent> events, List<string> notes)
    {
        int unknown = 0;
        foreach (var e in file.Entries)
        {
            if (events.Count >= EventLimit) { notes.Add($"{file.Name}: stopped at {EventLimit} events"); break; }
            if (e.Modified is { } t) events.Add(new(DateTime.SpecifyKind(t, DateTimeKind.Utc), "Directory entry modified", e.Path, e.Name));
            else unknown++;
        }
        if (unknown > 0) notes.Add($"{file.Name}: {unknown} entr(ies) without a modified time; unknown");
        notes.AddRange(file.Notes);
    }

    private static void Hive(RegistryHive hive, string name, List<FileTimeEvent> events, List<string> notes, CancellationToken ct)
    {
        int unknown = 0;
        void Add(DateTime? time, string where, string key, bool recovered)
        {
            if (time is { } t) events.Add(new(DateTime.SpecifyKind(t, DateTimeKind.Utc), "Key last written", recovered ? where + " (recovered)" : where, key));
            else unknown++;
        }
        if (hive.Header.LastWritten is { } w) events.Add(new(DateTime.SpecifyKind(w, DateTimeKind.Utc), "Hive last written", "Base block", name));
        else unknown++;
        bool full = false;
        foreach (var (p, key) in hive.Walk(ct))
        {
            if (events.Count >= EventLimit) { full = true; break; }
            Add(key.LastWritten, p.Length == 0 ? "\\" : p, key.Name, false);
        }
        if (!full)
            foreach (var key in hive.Recover(ct).Keys)
            {
                if (events.Count >= EventLimit) { full = true; break; }
                Add(key.LastWritten, key.Name, key.Name, true);
            }
        if (full) notes.Add($"{name}: stopped at {EventLimit} events; later keys unknown");
        if (unknown > 0) notes.Add($"{name}: {unknown} time(s) zero or out of range; unknown");
        notes.AddRange(hive.Notes);
    }

    private static void Zip(string path, List<FileTimeEvent> events, List<string> notes, CancellationToken ct)
    {
        using var zip = ZipFile.OpenRead(path);
        foreach (var e in zip.Entries)
        {
            ct.ThrowIfCancellationRequested();
            if (events.Count >= EventLimit) { notes.Add($"{System.IO.Path.GetFileName(path)}: stopped at {EventLimit} events"); break; }
            events.Add(new(DateTime.SpecifyKind(e.LastWriteTime.DateTime, DateTimeKind.Utc), "Zip entry modified", e.FullName, e.Name.Length > 0 ? e.Name : e.FullName));
        }
        if (events.Count > 0) notes.Add("zip times are stored without a zone; reported as stored, labelled UTC");
    }
}
