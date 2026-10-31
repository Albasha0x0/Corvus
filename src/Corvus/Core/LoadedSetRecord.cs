using System.Text.Json;

namespace Corvus.Core;

/// <summary>One recorded load: the id, the file it came from and the SHA-256 of its bytes.</summary>
public sealed record LoadedSetEntry(string Id, string Path, string Sha256);

/// <summary>
/// The ids a server loaded, kept in a file so a restarted server can name the path an unknown id referred to.
/// A null file disables the record; a failed read or write leaves it unchanged.
/// </summary>
public sealed class LoadedSetRecord(string? file)
{
    // Bounds the file; the oldest entries are dropped first.
    private const int MaxEntries = 500;

    private readonly object _gate = new();
    private List<LoadedSetEntry>? _list;
    private bool _dirty;

    /// <summary>The recorded entry for an id, or null for an unknown or blank id.</summary>
    public LoadedSetEntry? Find(string id)
    {
        var key = Key(id);
        if (key.Length == 0) return null;
        lock (_gate) return Load().FirstOrDefault(e => Key(e.Id).Equals(key, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Keeps the entry, replacing one with the same id; <see cref="Flush"/> writes the file.</summary>
    public void Add(LoadedSetEntry entry)
    {
        if (file == null) return;
        var key = Key(entry.Id);
        lock (_gate)
        {
            var list = Load();
            list.RemoveAll(e => Key(e.Id).Equals(key, StringComparison.OrdinalIgnoreCase));
            list.Add(entry);
            if (list.Count > MaxEntries) list.RemoveRange(0, list.Count - MaxEntries);
            _dirty = true;
        }
    }

    /// <summary>Drops the entry for an id so an unloaded id is not offered again; <see cref="Flush"/> writes the file.</summary>
    public void Remove(string id)
    {
        if (file == null) return;
        var key = Key(id);
        lock (_gate)
        {
            if (Load().RemoveAll(e => Key(e.Id).Equals(key, StringComparison.OrdinalIgnoreCase)) > 0) _dirty = true;
        }
    }

    /// <summary>Writes pending changes; a failed write leaves the file as it was and never throws.</summary>
    public void Flush()
    {
        if (file == null) return;
        lock (_gate)
        {
            if (!_dirty || _list == null) return;
            var full = System.IO.Path.GetFullPath(file);
            var temp = full + "." + Environment.ProcessId + ".tmp";
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
                File.WriteAllText(temp, JsonSerializer.Serialize(_list));
                File.Move(temp, full, overwrite: true);
                _dirty = false;
            }
            // Best effort: the record only improves a Next, so a write error must not fail a load.
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                try { File.Delete(temp); } catch (Exception) { }
            }
        }
    }

    private static string Key(string? id) => id?.Trim() ?? "";

    // Reads the file once; entries whose file is gone are dropped.
    private List<LoadedSetEntry> Load()
    {
        if (_list != null) return _list;
        _list = [];
        if (file == null || !File.Exists(file)) return _list;
        try
        {
            var read = JsonSerializer.Deserialize<List<LoadedSetEntry>>(File.ReadAllText(file)) ?? [];
            _list = read.Where(e => e?.Id != null && e.Path != null && File.Exists(e.Path)).ToList();
            _dirty = _list.Count != read.Count;
        }
        // An unreadable record is the same as an empty one.
        catch (Exception ex) when (ex is not OperationCanceledException) { }
        return _list;
    }
}
