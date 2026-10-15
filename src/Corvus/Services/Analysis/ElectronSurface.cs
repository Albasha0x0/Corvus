namespace Corvus.Services.Analysis;

/// <summary>
/// One place where an Electron app's JavaScript crosses a boundary: a window and its preload script, a key or method exposed
/// through contextBridge, an IPC channel handled in main or used from a renderer, a sink (child_process, fs, shell), or a
/// native add-on loaded or called. <see cref="Value"/> is the channel, key or function when it resolves to a string, else
/// the expression; <see cref="Site"/> is file:line:column.
/// </summary>
public sealed record ElectronRow(string Kind, string Value, string Site)
{
    [System.ComponentModel.Description("ipcMain.handle, ipcRenderer.invoke via a wrapper, new BrowserWindow...")]
    public string? Call { get; init; }

    [System.ComponentModel.Description("IPC: the paired sites or unpaired; window: its preload; native-call: the add-on.")]
    public string? Link { get; init; }
}

/// <summary>The surface rows of one script, found by their call shapes (minified code keeps these property names).</summary>
internal static class ElectronSurface
{
    public const int MaxRows = 2000;

    // call shape -> row kind; the first argument is the value
    private static readonly (string Call, string Kind)[] Calls =
    [
        ("exposeInMainWorld(", "bridge-key"),
        ("ipcMain.handle(", "ipc-main"), ("ipcMain.handleOnce(", "ipc-main"), ("ipcMain.on(", "ipc-main"), ("ipcMain.once(", "ipc-main"),
        ("ipcRenderer.invoke(", "ipc-renderer"), ("ipcRenderer.send(", "ipc-renderer"), ("ipcRenderer.sendSync(", "ipc-renderer"),
        ("ipcRenderer.on(", "ipc-renderer"), ("ipcRenderer.once(", "ipc-renderer"), ("ipcRenderer.postMessage(", "ipc-renderer"),
        ("shell.openExternal(", "sink-shell"), ("shell.openPath(", "sink-shell"),
        ("require(\"child_process\")", "sink-child_process"), ("require('child_process')", "sink-child_process"),
        ("require(\"node:child_process\")", "sink-child_process"), ("require('node:child_process')", "sink-child_process"),
    ];

    public static void Scan(string text, string path, List<ElectronRow> rows)
    {
        int line = 1, lineStart = 0, counted = 0;
        string Site(int at)
        {
            for (; counted < at; counted++)
                if (text[counted] == '\n') { line++; lineStart = counted + 1; }
            return $"{path}:{line}:{at - lineStart + 1}";
        }
        // sites in text order, so the line counter only moves forward
        var found = new List<(int At, string Kind, string Value)>();
        foreach (var (call, kind) in Calls)
            for (int at = 0; (at = text.IndexOf(call, at, StringComparison.Ordinal)) >= 0; at += call.Length)
            {
                if (at > 0 && IsIdentifier(text[at - 1]) && call[0] != 'r') continue;
                found.Add((at, kind, call.EndsWith('(') ? Argument(text, at + call.Length) : call));
            }
        // native add-ons: a require of a .node file
        for (int at = 0; (at = text.IndexOf(".node", at, StringComparison.Ordinal)) >= 0; at += 5)
            if (at + 5 < text.Length && text[at + 5] is '"' or '\'' or '`' && Literal(text, at + 5) is { } module)
                found.Add((at, "native-require", module));
        foreach (var (at, kind, value) in found.OrderBy(f => f.At))
        {
            if (rows.Count >= MaxRows) return;
            rows.Add(new ElectronRow(kind, value, Site(at)));
        }
    }

    private static bool IsIdentifier(char c) => char.IsLetterOrDigit(c) || c is '_' or '$';

    /// <summary>The first argument at <paramref name="p"/>: a string literal's content, else the expression up to ',' or ')' (clipped).</summary>
    private static string Argument(string text, int p)
    {
        while (p < text.Length && char.IsWhiteSpace(text[p])) p++;
        if (p < text.Length && text[p] is '"' or '\'' or '`')
        {
            int end = text.IndexOf(text[p], p + 1);
            if (end > p && end - p < 200) return text[(p + 1)..end];
        }
        int depth = 0, start = p;
        for (; p < text.Length && p - start < 120; p++)
        {
            char c = text[p];
            if (c is '(' or '[' or '{') depth++;
            else if (c is ')' or ']' or '}') { if (depth == 0) break; depth--; }
            else if (c == ',' && depth == 0) break;
        }
        var expression = text[start..p].Trim();
        return p - start >= 120 ? expression + "..." : expression;
    }

    /// <summary>The string literal ending at <paramref name="close"/> (its quote), when it is short and on one line.</summary>
    private static string? Literal(string text, int close)
    {
        char quote = text[close];
        for (int p = close - 1; p >= 0 && close - p < 260; p--)
        {
            if (text[p] == '\n') return null;
            if (text[p] == quote) return text[(p + 1)..close];
        }
        return null;
    }
}
