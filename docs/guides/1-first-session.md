# Guide 1: first session

Find the code behind a feature in a program without source, read it, predict its output, and check the prediction by
running the program. The program is Notes, a console app built from [samples/Notes](../../samples/Notes).

## Build the sample

From the repository root (needs the .NET 10 SDK):

<!-- check: setup -->
```sh
dotnet build samples/Notes/v1
dotnet build samples/Notes/v2
```

The program is `samples/Notes/v1/bin/Notes.dll`. Guide 3 uses the second build.

## Ask your agent

With Corvus registered in your MCP client ([installation](../installation.md)), paste:

> Load samples/Notes/v1/bin/Notes.dll. Find how Notes exports to CSV and predict the exported line for the note titled
> `Hello, "you"`.

From a terminal, as a [batch](../cli.md#batch) (save as `g1.jsonl`, run `corvus batch g1.jsonl`):

<!-- check: batch -->
```json
{"tool": "load_assembly", "args": {"path": "samples/Notes/v1/bin/Notes.dll"}}
{"tool": "search_symbols", "args": {"query": "Csv"}}
{"tool": "decompile_member", "args": {"member": "Notes.CsvExporter"}}
```

<!-- check: output -->
```text
=== [1/3] load_assembly
Loaded Notes: Notes, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
  samples/Notes/v1/bin/Notes.dll
  8 types, 2 namespaces
=== [2/3] search_symbols
1 match (showing 1-1):
  type     Notes.CsvExporter  [Notes] 0x02000008
[End: 1 match]
=== [3/3] decompile_member
// [Notes] Notes.CsvExporter
using System.Collections.Generic;
using System.IO;

namespace Notes;

public static class CsvExporter
{
	public static void Write(IEnumerable<Note> notes, TextWriter output)
	{
		output.WriteLine("id,title,created");
		foreach (Note note in notes)
		{
			output.WriteLine($"{note.Id},{Quote(note.Title)},{note.Created}");
		}
	}

	public static string Quote(string field)
	{
		if (field.IndexOfAny(new char[4] { ',', '"', '\n', '\r' }) >= 0)
		{
			return "\"" + field.Replace("\"", "\"\"") + "\"";
		}
		return field;
	}
}
```

## Predict, then check

`Quote` wraps a field with a comma, quote or line break in quotes, and doubles inner quotes. `Hello, "you"` has a comma
and quotes, so note 2 should export as `2,"Hello, ""you""",2026-01-06`:

<!-- check: run -->
```sh
dotnet samples/Notes/v1/bin/Notes.dll export
```

<!-- check: output -->
```text
id,title,created
1,Groceries,2026-01-05
2,"Hello, ""you""",2026-01-06
3,Plan,2026-01-07
exit code 0
```

Next: [guide 2](2-decode-and-patch.md) reads transformed code.
