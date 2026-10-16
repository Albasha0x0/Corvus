// Notes 2.0: guide 3's new build of Notes 1.0 (two methods renamed, one moved, a note and a command added).
namespace Notes;

public sealed record Note(int Id, string Title, string Created);

public static class Program
{
    public static int Main(string[] args)
    {
        switch (args.Length > 0 ? args[0] : "list")
        {
            case "list":
                foreach (var note in NoteStore.All()) Console.WriteLine($"{note.Id}. {note.Title}");
                return 0;
            case "export":
                CsvExporter.Write(NoteStore.All(), Console.Out);
                return 0;
            case "preview":
                bool ok = args.Length > 1 && PreviewGate.Check(args[1]);
                Console.WriteLine(ok ? "preview enabled" : "preview unavailable");
                return ok ? 0 : 1;
            default:
                Console.Error.WriteLine("usage: Notes [list | export | preview <code>]");
                return 2;
        }
    }
}

public static class NoteStore
{
    public static IReadOnlyList<Note> All() =>
    [
        new(1, "Groceries", "2026-01-05"),
        new(2, "Hello, \"you\"", "2026-01-06"),
        new(3, "Plan", "2026-01-07"),
        new(4, "Ideas", "2026-02-01"),
    ];
}

public static class CsvExporter
{
    public static void Write(IEnumerable<Note> notes, TextWriter output)
    {
        output.WriteLine("id,title,created");
        foreach (var note in notes) output.WriteLine($"{note.Id},{Escape(note.Title)},{note.Created}");
    }

    public static string Escape(string field) =>
        field.IndexOfAny([',', '"', '\n', '\r']) < 0 ? field : "\"" + field.Replace("\"", "\"\"") + "\"";
}
