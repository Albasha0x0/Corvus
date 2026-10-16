using System.Text.RegularExpressions;

namespace Corvus.Services.Web.Scripts;

/// <summary>
/// Reads PowerShell, batch, VBScript and JavaScript with their transformation layers peeled to plain text. Runs on a
/// thread of its own with a large stack, so deeply nested input ends at the evaluator's depth limits, not the stack's.
/// </summary>
public static class ScriptReader
{
    public static readonly string[] Languages = ["powershell", "batch", "vbscript", "javascript"];

    /// <summary>The language of a script by its extension, else by its text; null when it does not read as one.</summary>
    public static string? Detect(string path, string text)
    {
        switch (Path.GetExtension(path).ToLowerInvariant())
        {
            case ".ps1" or ".psm1" or ".psd1": return "powershell";
            case ".bat" or ".cmd": return "batch";
            case ".vbs" or ".vbe" or ".vba" or ".bas" or ".cls" or ".frm": return "vbscript";
            case ".js" or ".jse" or ".mjs" or ".cjs": return "javascript";
        }
        var head = text.Length > 8192 ? text[..8192] : text;
        if (Regex.IsMatch(head, @"(?im)^\s*@?echo\s+off\b|^\s*set\s+""?\w+=|%~dp0|^\s*goto\s+:?\w+")) return "batch";
        if (Regex.IsMatch(head, @"(?i)\$\w+\s*=|\b(?:invoke-expression|iex|new-object|write-host|foreach-object)\b|\[(?:system\.)?(?:convert|text\.encoding|char)\]::?")) return "powershell";
        if (Regex.IsMatch(head, @"(?im)^\s*(?:dim|set|sub|function|private sub|public sub)\s+\w+|createobject\s*\(|\bwscript\.\w+|\bexecute(?:global)?\s*[\(""]")
            && !Regex.IsMatch(head, @"\bvar\s+\w+\s*=|=>|\bconst\s+\w+\s*=")) return "vbscript";
        if (Regex.IsMatch(head, @"\b(?:var|let|const)\s+[\w$]+\s*=|\bfunction\s*[\w$]*\s*\(|=>")) return "javascript";
        return null;
    }

    /// <summary>Reads <paramref name="text"/> in <paramref name="language"/>; never runs it.</summary>
    public static ScriptReading Read(string text, string language, CancellationToken ct = default, int milliseconds = 4_000)
    {
        var ctx = new ScriptContext(new ScriptBudget(milliseconds: milliseconds, ct: ct));
        string? plain = null;
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try { plain = ReadLayer(language, text, ctx, 0); }
            catch (Exception ex) { failure = ex; }
        }, 64 << 20) { IsBackground = true, Name = "script reader" };
        thread.Start();
        thread.Join();
        if (failure is OperationCanceledException) throw failure;
        if (failure != null)
        {
            ctx.Note($"The {language} reader stopped: {failure.GetType().Name}.");
            ctx.Incomplete = true;
        }
        return new ScriptReading(language, plain ?? text, ctx.Layers, ctx.Folded, ctx.Calls.ToList(), ctx.Notes) { Complete = !ctx.Incomplete && !ctx.Budget.Exhausted, Recovered = ctx.Recovered.ToList() };
    }

    /// <summary>One layer's plain text in its language.</summary>
    internal static string ReadLayer(string language, string text, ScriptContext ctx, int depth) => language switch
    {
        "powershell" => PsInterpreter.Read(text, ctx, depth),
        "vbscript" => VbsInterpreter.Read(text, ctx, depth),
        "batch" => BatchReader.Read(text, ctx, depth),
        "javascript" => JsLayers.Read(text, ctx, depth),
        _ => text,
    };
}
