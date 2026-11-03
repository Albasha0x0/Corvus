using System.Text;
using Corvus.Core;

namespace Corvus.Setup;

/// <summary>batch --file sample.lnk --times-jsonl: each stored time as one JSON line.</summary>
internal static partial class ToolCli
{
    /// <summary>
    /// Runs --times-jsonl: writes the stored times and a count line. A usage
    /// error when the file or output is unusable.
    /// </summary>
    private static int TimesJsonl(CliArgs a, CliIo io, CancellationToken ct)
    {
        if (a.EvtxJsonl != null) throw new UsageException("--times-jsonl and --evtx-jsonl are separate modes: use one.");
        if (a.Json || a.JsonLines || a.Recurse) throw new UsageException("--times-jsonl is a mode of its own: it does not go with --json, --jsonl or --recurse.");
        var path = Path.GetFullPath(a.BatchFile!);
        if (!File.Exists(path)) throw new UsageException($"No such file: {a.BatchFile}.");
        var output = OutputPath("--times-jsonl", a.TimesJsonl);
        if (output != null && Directory.Exists(output)) throw new UsageException($"--times-jsonl names a file, not a folder: {a.TimesJsonl}.");
        if (output != null && string.Equals(Path.GetFullPath(output), path, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new UsageException("--times-jsonl must not name the input file.");
        var (count, notes) = WriteTimesLines(path, output!, ct);
        io.Out.WriteLine($"{count} event(s) written to {a.TimesJsonl}.");
        if (count == 0 && notes.Count > 0) io.Out.WriteLine($"No time was read; {notes.Count} note(s), first: {notes[0]}");
        return Exit.Ok;
    }

    /// <summary>
    /// Writes the stored times of <paramref name="path"/> to
    /// <paramref name="output"/>, sorted by time then description; returns
    /// the count and the reader's notes. A usage error when the output
    /// cannot be written.
    /// </summary>
    internal static (long Count, IReadOnlyList<string> Notes) WriteTimesLines(string path, string output, CancellationToken ct)
    {
        var result = FileTimes.Read(path, ct);
        var source = Path.GetFileName(path);
        // Write beside the output and move into place, so a refused file leaves none.
        var temp = output + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write))
            using (var writer = new StreamWriter(stream, new UTF8Encoding(false), 4096) { NewLine = "\n" })
            {
                foreach (var e in result.Events.OrderBy(e => e.Utc).ThenBy(e => e.Desc, StringComparer.Ordinal))
                {
                    writer.Write(FileTimes.Line(e, source).ToJsonString(Compact));
                    writer.Write('\n');
                }
            }
            File.Move(temp, output, overwrite: true);
            return (result.Events.Count, result.Notes);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new UsageException($"{source}: cannot write {output}: {ex.Message}");
        }
        finally
        {
            try { File.Delete(temp); } catch (Exception) { }
        }
    }
}
