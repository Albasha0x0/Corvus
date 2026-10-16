using System.Diagnostics;
using System.Text;

namespace Corvus.Services.Web.Scripts;

/// <summary>One layer of a script: its depth (0 is the file), language, how it is reached (the call that runs it and the decoding chain) and its text.</summary>
public sealed record ScriptLayer(int Depth, string Language, string Via, string Text);

/// <summary>
/// A script read with its transformation layers peeled: <see cref="Plain"/> is the file with every peeled call replaced by
/// the layer it runs and constant expressions folded to literals. Nothing is executed: a bounded evaluator folds constants.
/// </summary>
public sealed record ScriptReading(string Language, string Plain, IReadOnlyList<ScriptLayer> Layers, int Folded,
    IReadOnlyList<string> Calls, IReadOnlyList<string> Notes)
{
    /// <summary>False when the budget ran out or a layer could not be decoded.</summary>
    public bool Complete { get; init; } = true;
}

/// <summary>The budget of one reading: evaluation steps, time and the largest string built.</summary>
internal sealed class ScriptBudget(long steps = 4_000_000, int milliseconds = 4_000, int maxChars = 8 << 20, CancellationToken ct = default)
{
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private long _steps;

    public int MaxChars { get; } = maxChars;
    public bool Exhausted { get; private set; }

    /// <summary>Counts a step; false (and <see cref="Exhausted"/>) once the steps or the time are used up.</summary>
    public bool Step(int n = 1)
    {
        if (Exhausted) return false;
        _steps += n;
        if ((_steps & 0xFFF) < n) ct.ThrowIfCancellationRequested();
        if (_steps > steps || (_steps & 0x3FF) < n && _clock.ElapsedMilliseconds > milliseconds) Exhausted = true;
        return !Exhausted;
    }

    public void ThrowIfCancelled() => ct.ThrowIfCancellationRequested();
}

/// <summary>What a reading collects across languages and layers.</summary>
internal sealed class ScriptContext(ScriptBudget budget)
{
    public const int MaxLayers = 64;

    public ScriptBudget Budget { get; } = budget;
    public List<ScriptLayer> Layers { get; } = [];
    public SortedSet<string> Calls { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Notes { get; } = [];
    public int Folded { get; set; }
    public bool Incomplete { get; set; }

    /// <summary>Environment variables a layer set (batch set, $env:), read by later layers in any language.</summary>
    public Dictionary<string, string> Environment { get; } = new(StringComparer.OrdinalIgnoreCase);

    public void Note(string note)
    {
        if (Notes.Count < 40 && !Notes.Contains(note)) Notes.Add(note);
    }

    private readonly Dictionary<(string, string), string?> _read = [];

    /// <summary>Records a layer and returns its plain text, read by the reader of its language; null past the layer limit. A layer met again is read once.</summary>
    public string? Peel(string language, string text, string via, int depth)
    {
        if (_read.TryGetValue((language, text), out var known)) return known;
        var plain = PeelOnce(language, text, via, depth);
        _read[(language, text)] = plain;
        return plain;
    }

    private string? PeelOnce(string language, string text, string via, int depth)
    {
        if (Layers.Count >= MaxLayers || depth > MaxLayers)
        {
            Note($"More than {MaxLayers} layers: the rest are left as they are.");
            Incomplete = true;
            return null;
        }
        Layers.Add(new ScriptLayer(depth, language, via, text));
        return ScriptReader.ReadLayer(language, text, this, depth);
    }
}

/// <summary>Text helpers shared by the script readers.</summary>
internal static class ScriptText
{
    /// <summary>The string as a single-quoted PowerShell / JavaScript literal.</summary>
    public static string SingleQuoted(string s) => "'" + s.Replace("'", "''") + "'";

    /// <summary>Bytes as text: UTF-16LE when every other byte is zero (an encoded command), else UTF-8 without a BOM.</summary>
    public static string Decode(byte[] bytes, out string encoding)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) { encoding = "utf-16le"; return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2); }
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) { encoding = "utf-8"; return Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3); }
        int zeros = 0, n = Math.Min(bytes.Length, 4096) & ~1;
        for (int i = 1; i < n; i += 2) if (bytes[i] == 0) zeros++;
        if (n >= 4 && zeros * 2 >= n * 9 / 10) { encoding = "utf-16le"; return Encoding.Unicode.GetString(bytes); }
        encoding = "utf-8";
        return Encoding.UTF8.GetString(bytes);
    }

    /// <summary>Whether the text reads as text: few control characters other than whitespace.</summary>
    public static bool Printable(string s)
    {
        if (s.Length == 0) return false;
        int bad = 0;
        foreach (var c in s.AsSpan(0, Math.Min(s.Length, 8192)))
            if (c < 0x20 && c is not ('\r' or '\n' or '\t') || c is '�' or '\u007F') bad++;
        return bad * 50 < Math.Min(s.Length, 8192);
    }

    /// <summary>Base64 (standard or URL alphabet, padding optional, whitespace ignored) to bytes, or null.</summary>
    public static byte[]? FromBase64(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
        {
            if (char.IsWhiteSpace(c)) continue;
            sb.Append(c switch { '-' => '+', '_' => '/', _ => c });
        }
        while (sb.Length % 4 != 0) sb.Append('=');
        try { return Convert.FromBase64String(sb.ToString()); }
        catch (FormatException) { return null; }
    }
}

/// <summary>Windows environment variables at their defaults, which scripts index to spell commands.</summary>
internal static class ScriptEnvironment
{
    public static readonly IReadOnlyDictionary<string, string> Defaults = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["ComSpec"] = @"C:\WINDOWS\system32\cmd.exe",
        ["windir"] = @"C:\WINDOWS",
        ["SystemRoot"] = @"C:\WINDOWS",
        ["SystemDrive"] = "C:",
        ["PUBLIC"] = @"C:\Users\Public",
        ["ProgramData"] = @"C:\ProgramData",
        ["ALLUSERSPROFILE"] = @"C:\ProgramData",
        ["ProgramFiles"] = @"C:\Program Files",
        ["ProgramFiles(x86)"] = @"C:\Program Files (x86)",
        ["ProgramW6432"] = @"C:\Program Files",
        ["CommonProgramFiles"] = @"C:\Program Files\Common Files",
        ["CommonProgramFiles(x86)"] = @"C:\Program Files (x86)\Common Files",
        ["OS"] = "Windows_NT",
        ["PROCESSOR_ARCHITECTURE"] = "AMD64",
        ["PATHEXT"] = ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
        ["PSModulePath"] = @"C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules",
    };
}
