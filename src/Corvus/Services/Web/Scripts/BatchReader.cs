using System.Text;
using System.Text.RegularExpressions;

namespace Corvus.Services.Web.Scripts;

/// <summary>
/// Batch files read as cmd.exe expands them: set (quoted, /a arithmetic), %var%, !var!, %var:~start,len% substrings,
/// %var:old=new% replacement, caret escapes, call's second expansion, goto and labels, if with string tests and for /l.
/// Every line is shown expanded; a line that starts PowerShell, cmd /c or mshta is read as a layer of that language.
/// Commands are never run.
/// </summary>
internal sealed partial class BatchReader
{
    private const int MaxLineSteps = 200_000;

    private readonly ScriptContext _ctx;
    private readonly int _depth;
    private readonly Dictionary<string, string> _vars;
    private readonly HashSet<int> _peeled = [];

    private BatchReader(ScriptContext ctx, int depth)
    {
        _ctx = ctx;
        _depth = depth;
        _vars = ctx.Environment; // shared with later layers in other languages
    }

    public static string Read(string text, ScriptContext ctx, int depth) => new BatchReader(ctx, depth).Run(text);

    private sealed record Line(int Start, int End, string Text);

    private string Run(string text)
    {
        var lines = Lines(text);
        var edits = new TextEdits(text);
        var labels = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < lines.Count; i++)
            if (lines[i].Text.TrimStart() is var t && t.StartsWith(':') && !t.StartsWith("::", StringComparison.Ordinal))
                labels.TryAdd(t[1..].Trim().Split(' ', '\t')[0], i);
        var seen = new Dictionary<int, string?>();
        int pc = 0, steps = 0;
        while (pc < lines.Count)
        {
            if (!_ctx.Budget.Step() || ++steps > MaxLineSteps)
            {
                _ctx.Incomplete = true;
                _ctx.Note("The evaluation budget ran out: later lines are shown as written.");
                break;
            }
            var line = lines[pc];
            var (shown, jump) = Execute(line.Text, labels, lines.Count);
            if (shown != null)
            {
                // a line run twice with different expansions is left as written
                if (seen.TryGetValue(pc, out var before)) { if (before != shown) seen[pc] = null; }
                else seen[pc] = shown;
            }
            if (jump == -2) break; // exit
            pc = jump >= 0 ? jump : pc + 1;
        }
        foreach (var (index, shown) in seen)
            if (shown != null && shown != lines[index].Text)
            {
                edits.Set(lines[index].Start, lines[index].End, shown);
                _ctx.Folded++;
            }
        return edits.Render();
    }

    /// <summary>Logical lines: a caret at the end of a line joins the next one.</summary>
    private static List<Line> Lines(string text)
    {
        var list = new List<Line>();
        int start = 0;
        var sb = new StringBuilder();
        int lineStart = 0;
        for (int i = 0; i <= text.Length; i++)
        {
            if (i < text.Length && text[i] != '\n') continue;
            int end = i > 0 && i <= text.Length && i - 1 >= start && text[i - 1] == '\r' ? i - 1 : i;
            var raw = text[start..Math.Max(start, end)];
            if (raw.EndsWith('^') && !raw.EndsWith("^^", StringComparison.Ordinal) && i < text.Length)
            {
                sb.Append(raw[..^1]);
                start = i + 1;
                continue;
            }
            sb.Append(raw);
            list.Add(new Line(lineStart, Math.Max(lineStart, end), sb.ToString()));
            sb.Clear();
            start = lineStart = i + 1;
        }
        return list;
    }

    /// <summary>Runs one line: its expanded text and the line to go to (-1 next, -2 exit).</summary>
    private (string? Shown, int Jump) Execute(string raw, Dictionary<string, int> labels, int count)
    {
        var trimmed = raw.TrimStart();
        if (trimmed.Length == 0 || trimmed.StartsWith(':') || Regex.IsMatch(trimmed, @"^@?rem(\s|$)", RegexOptions.IgnoreCase)) return (null, -1);
        var expanded = Expand(raw, delayed: false);
        if (expanded == null) return (null, -1);
        int jump = -1;
        var shown = Command(expanded, labels, ref jump);
        return (shown, jump);
    }

    /// <summary>One command line after %-expansion: runs set / goto / if / for / call, and reads launcher lines as layers.</summary>
    private string Command(string expanded, Dictionary<string, int> labels, ref int jump, int nesting = 0)
    {
        if (nesting > 8) return expanded;
        var line = expanded.TrimStart();
        var lead = expanded[..(expanded.Length - line.Length)];
        if (line.StartsWith('@')) { lead += "@"; line = line[1..]; }
        // a parenthesized block on one line, or commands joined by & / && / ||
        var parts = SplitCommands(line);
        if (parts.Count > 1)
        {
            var sb = new StringBuilder(lead);
            foreach (var (part, sep) in parts)
            {
                int j = -1;
                sb.Append(Command(part, labels, ref j, nesting + 1)).Append(sep);
                if (j != -1) { jump = j; break; }
            }
            return sb.ToString();
        }
        var unescaped = Unescape(line);
        var delayed = Expand(unescaped, delayed: true) ?? unescaped;
        var word = FirstWord(delayed, out var rest);
        switch (word.ToLowerInvariant())
        {
            case "set":
                Set(rest);
                return lead + delayed;
            case "goto":
            {
                var label = rest.Trim().TrimStart(':').Split(' ', '\t')[0];
                if (label.Equals("eof", StringComparison.OrdinalIgnoreCase)) jump = -2;
                else if (labels.TryGetValue(label, out var target)) jump = target;
                return lead + delayed;
            }
            case "exit":
                jump = -2;
                return lead + delayed;
            case "call":
                if (rest.TrimStart().StartsWith(':')) return lead + delayed;
                // call expands the line a second time
                var again = Expand(rest, delayed: false) ?? rest;
                return lead + "call " + Command(again, labels, ref jump, nesting + 1).TrimStart();
            case "if":
                return lead + If(rest, labels, ref jump, nesting);
            case "for":
                return lead + For(delayed, rest, labels, nesting);
            case "setlocal" or "endlocal" or "echo" or "title" or "color" or "cls" or "pause" or "chcp" or "mode" or "rem" or "timeout" or "ping":
                return lead + delayed;
        }
        return lead + Launch(word, rest, delayed);
    }

    /// <summary>cmd's command separators outside quotes and parentheses: &amp;, &amp;&amp;, ||.</summary>
    private static List<(string Part, string Sep)> SplitCommands(string line)
    {
        var list = new List<(string, string)>();
        bool quoted = false;
        int nest = 0, start = 0;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (c == '^') { i++; continue; }
            if (c == '"') quoted = !quoted;
            if (quoted) continue;
            if (c == '(') nest++;
            else if (c == ')' && nest > 0) nest--;
            else if (nest == 0 && (c == '&' || c == '|' && i + 1 < line.Length && line[i + 1] == '|'))
            {
                var sep = i + 1 < line.Length && line[i + 1] == c ? new string(c, 2) : c.ToString();
                list.Add((line[start..i], sep));
                i += sep.Length - 1;
                start = i + 1;
            }
        }
        list.Add((line[start..], ""));
        return list;
    }

    private static string FirstWord(string line, out string rest)
    {
        line = line.TrimStart();
        int i = 0;
        if (line.StartsWith('"'))
        {
            int close = line.IndexOf('"', 1);
            i = close < 0 ? line.Length : close + 1;
        }
        else
            while (i < line.Length && !char.IsWhiteSpace(line[i]) && line[i] is not ('(' or '/' or ',' or ';' or '=') || i == 0 && i < line.Length && line[i] == '/') i++;
        rest = line[i..];
        return line[..i].Trim('"');
    }

    private void Set(string rest)
    {
        rest = rest.TrimStart();
        if (rest.StartsWith("/a", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var assignment in rest[2..].Split(','))
            {
                var a = assignment.Trim().Trim('"');
                var m = Regex.Match(a, @"^([^=+\-*/%]+?)\s*([+\-*/%]?)=\s*(.+)$");
                if (!m.Success) continue;
                var name = m.Groups[1].Value.Trim();
                if (Arithmetic(m.Groups[3].Value) is not { } value) { _vars.Remove(name); continue; }
                if (m.Groups[2].Value.Length > 0)
                {
                    long old = long.TryParse(Get(name), out var o) ? o : 0;
                    value = m.Groups[2].Value switch { "+" => old + value, "-" => old - value, "*" => old * value, "/" => value == 0 ? 0 : old / value, _ => value == 0 ? 0 : old % value };
                }
                _vars[name] = value.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }
            return;
        }
        if (rest.StartsWith("/p", StringComparison.OrdinalIgnoreCase))
        {
            var name = rest[2..].Trim().Split('=')[0].Trim().Trim('"');
            _vars.Remove(name);
            return;
        }
        string body = rest;
        if (body.StartsWith('"'))
        {
            int close = body.LastIndexOf('"');
            body = close > 0 ? body[1..close] : body[1..];
        }
        int eq = body.IndexOf('=');
        if (eq <= 0) return;
        var key = body[..eq].Trim();
        var v = body[(eq + 1)..];
        if (v.Length == 0) _vars.Remove(key);
        else _vars[key] = v;
    }

    private string? Get(string name) =>
        _vars.TryGetValue(name, out var v) ? v : ScriptEnvironment.Defaults.TryGetValue(name, out var d) ? d : null;

    /// <summary>set /a: integers with + - * / % and parentheses, variables by name.</summary>
    private long? Arithmetic(string expr)
    {
        var tokens = Regex.Matches(expr, @"0x[0-9a-fA-F]+|\d+|[A-Za-z_][\w.]*|[-+*/%()]").Select(m => m.Value).ToList();
        int i = 0;
        long? Atom()
        {
            if (i >= tokens.Count) return null;
            var t = tokens[i++];
            if (t == "(") { var v = Sum(); if (i < tokens.Count && tokens[i] == ")") i++; return v; }
            if (t == "-") return -Atom();
            if (t == "+") return Atom();
            if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) return Convert.ToInt64(t[2..], 16);
            if (char.IsDigit(t[0])) return long.TryParse(t, out var n) ? n : null;
            return long.TryParse(Get(t), out var vv) ? vv : 0;
        }
        long? Product()
        {
            var l = Atom();
            while (l != null && i < tokens.Count && tokens[i] is "*" or "/" or "%")
            {
                var op = tokens[i++];
                var r = Atom();
                if (r == null) return null;
                l = op == "*" ? l * r : r == 0 ? null : op == "/" ? l / r : l % r;
            }
            return l;
        }
        long? Sum()
        {
            var l = Product();
            while (l != null && i < tokens.Count && tokens[i] is "+" or "-")
            {
                var op = tokens[i++];
                var r = Product();
                if (r == null) return null;
                l = op == "+" ? l + r : l - r;
            }
            return l;
        }
        try { return Sum(); }
        catch (Exception ex) when (ex is FormatException or OverflowException) { return null; }
    }

    private string If(string rest, Dictionary<string, int> labels, ref int jump, int nesting)
    {
        var m = Regex.Match(rest, @"^\s*(?:/i\s+)?(not\s+)?(?:(defined)\s+(\S+)|(""[^""]*""|\S+)\s*(==|\s(?:equ|neq|lss|leq|gtr|geq)\s)\s*(""[^""]*""|\S+))\s+(.*)$", RegexOptions.IgnoreCase);
        if (!m.Success) return "if" + rest;
        bool? result;
        if (m.Groups[2].Success) result = Get(m.Groups[3].Value) != null;
        else
        {
            string a = m.Groups[4].Value.Trim('"'), b = m.Groups[6].Value.Trim('"');
            bool ci = rest.TrimStart().StartsWith("/i", StringComparison.OrdinalIgnoreCase);
            var op = m.Groups[5].Value.Trim().ToLowerInvariant();
            int c = long.TryParse(a, out var x) && long.TryParse(b, out var y) ? x.CompareTo(y) : string.Compare(a, b, ci ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
            result = op switch { "==" or "equ" => c == 0, "neq" => c != 0, "lss" => c < 0, "leq" => c <= 0, "gtr" => c > 0, _ => c >= 0 };
        }
        if (m.Groups[1].Success) result = !result;
        var command = m.Groups[7].Value;
        int elseAt = command.IndexOf(") else (", StringComparison.OrdinalIgnoreCase);
        string then = command, otherwise = "";
        if (elseAt >= 0) { then = command[..(elseAt + 1)]; otherwise = command[(elseAt + 7)..]; }
        var chosen = result == true ? then : otherwise;
        chosen = chosen.Trim();
        if (chosen.StartsWith('(') && chosen.EndsWith(')')) chosen = chosen[1..^1];
        if (chosen.Length > 0) Command(chosen, labels, ref jump, nesting + 1);
        return "if" + rest;
    }

    /// <summary>for /l %%i in (start,step,end) do command, run with the variable replaced; other loops are shown as written.</summary>
    private string For(string line, string rest, Dictionary<string, int> labels, int nesting)
    {
        var m = Regex.Match(rest, @"^\s*/l\s+%%?(\w)\s+in\s*\(\s*(-?\d+)\s*,\s*(-?\d+)\s*,\s*(-?\d+)\s*\)\s*do\s+(.+)$", RegexOptions.IgnoreCase);
        if (!m.Success) return line;
        long from = long.Parse(m.Groups[2].Value), step = long.Parse(m.Groups[3].Value), to = long.Parse(m.Groups[4].Value);
        if (step == 0) return line;
        var body = m.Groups[5].Value.Trim();
        if (body.StartsWith('(') && body.EndsWith(')')) body = body[1..^1];
        var name = m.Groups[1].Value;
        for (long i = from; step > 0 ? i <= to : i >= to; i += step)
        {
            if (!_ctx.Budget.Step(16)) break;
            int j = -1;
            var text = Regex.Replace(body, "%%?" + Regex.Escape(name) + @"\b", i.ToString(System.Globalization.CultureInfo.InvariantCulture));
            Command(Expand(text, delayed: true) ?? text, labels, ref j, nesting + 1);
        }
        return line;
    }

    /// <summary>A command that starts another reader: PowerShell, cmd /c, mshta vbscript: / javascript:.</summary>
    private string Launch(string word, string rest, string line)
    {
        var name = Path.GetFileNameWithoutExtension(word.Replace('\\', '/').Split('/')[^1]).ToLowerInvariant();
        if (name.Length > 0) Record(name, rest);
        switch (name)
        {
            case "powershell" or "pwsh":
                return PowerShell(rest) ?? line;
            case "cmd":
            {
                var m = Regex.Match(rest, @"^\s*(?:/[a-bd-jl-qs-z]\S*\s+)*/[ckr]\s+(.+)$", RegexOptions.IgnoreCase);
                if (!m.Success) return line;
                var inner = m.Groups[1].Value.Trim();
                if (inner.Length > 1 && inner[0] == '"' && inner[^1] == '"') inner = inner[1..^1];
                var plain = _ctx.Peel("batch", inner, "cmd /c", _depth + 1);
                return plain == null ? line : "cmd /c " + plain;
            }
            case "mshta":
            {
                var arg = rest.Trim().Trim('"');
                var m = Regex.Match(arg, @"^(vbscript|javascript):(.+)$", RegexOptions.IgnoreCase | RegexOptions.Singleline);
                if (!m.Success) return line;
                var language = m.Groups[1].Value.Equals("vbscript", StringComparison.OrdinalIgnoreCase) ? "vbscript" : "javascript";
                var code = m.Groups[2].Value;
                var plain = _ctx.Peel(language, code, "mshta " + m.Groups[1].Value.ToLowerInvariant() + ":", _depth + 1);
                return plain == null ? line : $"mshta {language}: {plain}";
            }
        }
        return line;
    }

    /// <summary>powershell.exe arguments as cmd passes them: -EncodedCommand (base64 of UTF-16LE), -Command or a command line.</summary>
    private string? PowerShell(string rest)
    {
        var args = Arguments(rest);
        for (int i = 0; i < args.Count; i++)
        {
            var a = args[i];
            if (a.Length < 2 || a[0] is not ('-' or '/')) break;
            var p = a[1..].ToLowerInvariant();
            if (p is "e" or "ec" || p.Length >= 2 && "encodedcommand".StartsWith(p, StringComparison.Ordinal))
            {
                if (i + 1 >= args.Count || ScriptText.FromBase64(args[i + 1]) is not { } bytes) return null;
                return _ctx.Peel("powershell", Encoding.Unicode.GetString(bytes), "powershell -EncodedCommand of base64 > utf-16le", _depth + 1);
            }
            if (p is "c" or "co" or "com" or "comm" or "comma" or "comman" or "command")
                return i + 1 < args.Count ? _ctx.Peel("powershell", string.Join(" ", args.Skip(i + 1)), "powershell -Command", _depth + 1) : null;
            if (p is "f" or "file" or "ex" or "exec" or "executionpolicy" or "w" or "windowstyle" or "ep" or "v" or "version" or "configurationname" or "inputformat" or "outputformat")
                i++; // the option's value
        }
        int first = args.FindIndex(a => a.Length > 0 && a[0] is not ('-' or '/'));
        if (first < 0) return null;
        // an option's value is not the command
        while (first > 0 && args[first - 1].ToLowerInvariant() is "-w" or "-windowstyle" or "-ep" or "-ex" or "-exec" or "-executionpolicy" or "-v" or "-version" or "-file" or "-f")
        {
            int next = args.FindIndex(first + 1, a => a.Length > 0 && a[0] is not ('-' or '/'));
            if (next < 0) return null;
            first = next;
        }
        return _ctx.Peel("powershell", string.Join(" ", args.Skip(first)), "powershell", _depth + 1);
    }

    /// <summary>Command-line arguments: whitespace-separated, double quotes grouping and removed, \" a literal quote.</summary>
    private static List<string> Arguments(string s)
    {
        var list = new List<string>();
        var sb = new StringBuilder();
        bool quoted = false, any = false;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c == '\\' && i + 1 < s.Length && s[i + 1] == '"') { sb.Append('"'); i++; any = true; continue; }
            if (c == '"') { quoted = !quoted; any = true; continue; }
            if (char.IsWhiteSpace(c) && !quoted)
            {
                if (any) { list.Add(sb.ToString()); sb.Clear(); any = false; }
                continue;
            }
            sb.Append(c);
            any = true;
        }
        if (any) list.Add(sb.ToString());
        return list;
    }

    private static readonly HashSet<string> Plumbing = new(StringComparer.OrdinalIgnoreCase)
    {
        "echo", "set", "setlocal", "endlocal", "goto", "call", "if", "for", "exit", "title", "color", "cls", "pause", "chcp", "mode", "rem", "cd", "pushd", "popd",
    };

    private void Record(string name, string rest)
    {
        if (Plumbing.Contains(name) || !Regex.IsMatch(name, @"^[\w.\-]+$")) return;
        var args = rest.Trim();
        var call = args.Length == 0 ? name : $"{name} {(args.Length > 160 ? args[..160] + "…" : args)}";
        if (_ctx.Calls.Count < 200) _ctx.Calls.Add(call);
    }

    /// <summary>Caret escapes removed outside double quotes.</summary>
    private static string Unescape(string s)
    {
        if (!s.Contains('^')) return s;
        var sb = new StringBuilder(s.Length);
        bool quoted = false;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c == '"') quoted = !quoted;
            if (c == '^' && !quoted && i + 1 < s.Length) { sb.Append(s[++i]); continue; }
            sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>%var% (or !var! when <paramref name="delayed"/>) with substring and replacement forms; undefined names expand to nothing.</summary>
    private string? Expand(string s, bool delayed)
    {
        char mark = delayed ? '!' : '%';
        if (!s.Contains(mark)) return s;
        var sb = new StringBuilder(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c != mark) { sb.Append(c); continue; }
            if (!delayed && i + 1 < s.Length && s[i + 1] == '%') { sb.Append('%'); i++; continue; } // %% is a literal %
            if (!delayed && i + 1 < s.Length && (char.IsDigit(s[i + 1]) || s[i + 1] == '*')) { sb.Append(c).Append(s[++i]); continue; } // %1, %*
            if (!delayed && i + 1 < s.Length && s[i + 1] == '~') // %~dp0 and friends
            {
                int q = i + 2;
                while (q < s.Length && char.IsLetter(s[q])) q++;
                if (q < s.Length && char.IsDigit(s[q])) { sb.Append(s, i, q - i + 1); i = q; continue; }
            }
            int close = s.IndexOf(mark, i + 1);
            if (close < 0) { sb.Append(s, i, s.Length - i); break; }
            var body = s[(i + 1)..close];
            if (body.Length == 0 || body.Contains(' ') && !body.Contains(':')) { sb.Append(c); continue; }
            var value = Variable(body);
            if (value == null)
            {
                if (delayed) { sb.Append(c); continue; } // !x! of an unknown name stays (it may be text)
                i = close; // an undefined %var% in a batch file expands to nothing
                continue;
            }
            sb.Append(value);
            i = close;
            if (sb.Length > _ctx.Budget.MaxChars) return null;
        }
        return sb.ToString();
    }

    private string? Variable(string body)
    {
        int colon = body.IndexOf(':');
        if (colon < 0) return Get(body);
        var name = body[..colon];
        var op = body[(colon + 1)..];
        var value = Get(name);
        if (value == null) return null;
        if (op.StartsWith('~'))
        {
            var parts = op[1..].Split(',');
            if (!int.TryParse(parts[0].Trim(), out var start)) return null;
            int len = value.Length;
            if (start < 0) start = Math.Max(0, len + start);
            start = Math.Min(start, len);
            int take = len - start;
            if (parts.Length > 1 && int.TryParse(parts[1].Trim(), out var n)) take = n < 0 ? Math.Max(0, len + n - start) : Math.Min(n, len - start);
            return value.Substring(start, Math.Max(0, take));
        }
        int eq = op.IndexOf('=');
        if (eq < 0) return null;
        var find = op[..eq];
        var replace = op[(eq + 1)..];
        if (find.Length == 0) return value;
        if (find.StartsWith('*'))
        {
            int at = value.IndexOf(find[1..], StringComparison.OrdinalIgnoreCase);
            return at < 0 ? value : replace + value[(at + find.Length - 1)..];
        }
        return Regex.Replace(value, Regex.Escape(find), replace.Replace("$", "$$"), RegexOptions.IgnoreCase);
    }
}
