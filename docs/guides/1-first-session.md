# Guide 1: first session

A first look at a program you have no source for: find the code behind a feature, read it, predict what it does, then
check the prediction by running the program. The program is Notes, a small console app built from
[samples/Notes](../../samples/Notes) in this repository, so every step here can be repeated and every output below is
what Corvus prints (a test runs these steps and compares).

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

The agent loads the file, searches for the export code and reads it. The same calls from the terminal, as a
[batch](../cli.md#batch) (save the lines as `g1.jsonl` and run `corvus batch g1.jsonl`):

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
1 match:
  type     Notes.CsvExporter  [Notes] 0x02000008
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

`Quote` leaves a field alone unless it holds a comma, a quote or a line break; otherwise it wraps the field in quotes
and doubles each quote inside. The title `Hello, "you"` has both, so the predicted line for note 2 is
`2,"Hello, ""you""",2026-01-06`. Run the program:

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

The second line of the export matches the prediction. Next: [guide 2](2-decode-and-patch.md) reads code that was
written to be hard to read.
