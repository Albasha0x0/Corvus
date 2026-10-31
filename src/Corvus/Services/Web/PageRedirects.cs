using System.Text.RegularExpressions;
using Corvus.Services.Analysis;

namespace Corvus.Services.Web;

/// <summary>Forms that post to another origin, password inputs in them, meta refresh redirects and script that assigns location, each named at its element and line.</summary>
internal static partial class PageRedirects
{
    private const int MaxFindings = 200;

    /// <summary>The page/* findings of <paramref name="html"/>; empty when none. A file has no origin, so an absolute http(s) action is another origin.</summary>
    public static List<Finding> Find(string html, CancellationToken ct)
    {
        var found = new List<Finding>();
        // Comments are blanked to spaces, keeping newlines, so line numbers hold.
        var text = CommentOrScript().Replace(html, m => m.Value.StartsWith("<!--", StringComparison.Ordinal) ? Blank(m.Value) : m.Value);
        var starts = LineStarts(text);
        void Add(string rule, string category, string evidence, string tag, int index)
        {
            if (found.Count < MaxFindings) found.Add(new Finding(FindingRules.Check(rule, FindingLevel.Review), rule, category, evidence, $"{tag} line {Line(starts, index)}", "page"));
        }
        foreach (Match m in Form().Matches(text))
        {
            ct.ThrowIfCancellationRequested();
            var form = SavedPage.Attributes(m.Groups[1].Value);
            if (!form.TryGetValue("action", out var action) || !OtherOrigin(action) || !form.GetValueOrDefault("method", "").Trim().Equals("post", StringComparison.OrdinalIgnoreCase)) continue;
            Add("page/foreign-form", "form", $"posts to {Clip(action.Trim())}", "<form>", m.Index);
            foreach (Match i in Input().Matches(m.Groups[2].Value))
                if (SavedPage.Attributes(i.Groups[1].Value).TryGetValue("type", out var type) && type.Trim().Equals("password", StringComparison.OrdinalIgnoreCase))
                    Add("page/password-foreign-form", "form", $"a password input in a form that posts to {Clip(action.Trim())}", "<input>", m.Groups[2].Index + i.Index);
        }
        foreach (Match m in Meta().Matches(text))
        {
            var a = SavedPage.Attributes(m.Groups[1].Value);
            if (a.TryGetValue("http-equiv", out var equiv) && equiv.Trim().Equals("refresh", StringComparison.OrdinalIgnoreCase)
                && a.TryGetValue("content", out var content) && RefreshUrl().Match(content) is { Success: true } u)
                Add("page/meta-refresh", "redirect", $"redirects to {Clip(u.Groups[1].Value.Trim())}", "<meta>", m.Index);
        }
        foreach (Match m in ScriptElement().Matches(text))
        {
            ct.ThrowIfCancellationRequested();
            var body = m.Groups[1].Value;
            foreach (Match r in LocationCall().Matches(body))
                Add("page/script-redirect", "redirect", $"sends the browser to {Clip(r.Groups[1].Value)}", "<script>", m.Groups[1].Index + r.Index);
        }
        return found;
    }

    private static bool OtherOrigin(string action) =>
        action.Trim().StartsWith("http://", StringComparison.OrdinalIgnoreCase) || action.Trim().StartsWith("https://", StringComparison.OrdinalIgnoreCase);

    private static List<int> LineStarts(string text)
    {
        var starts = new List<int> { 0 };
        for (int i = 0; i < text.Length; i++)
            if (text[i] == '\n') starts.Add(i + 1);
        return starts;
    }

    // Binary search keeps a file of many findings linear.
    private static int Line(List<int> starts, int index)
    {
        int at = starts.BinarySearch(index);
        return at >= 0 ? at + 1 : ~at;
    }

    private static string Blank(string s) => string.Create(s.Length, s, (span, src) =>
    {
        for (int i = 0; i < src.Length; i++) span[i] = src[i] is '\n' or '\r' ? src[i] : ' ';
    });

    private static string Clip(string s) => s.Length <= 120 ? s : s[..117] + "...";

    [GeneratedRegex(@"<!--.*?-->|<script\b[^>]*>.*?</script\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.NonBacktracking)]
    private static partial Regex CommentOrScript();

    [GeneratedRegex(@"<form\b([^>]*)>(.*?)</form\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.NonBacktracking)]
    private static partial Regex Form();

    [GeneratedRegex(@"<input\b([^>]*)>", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)]
    private static partial Regex Input();

    [GeneratedRegex(@"<meta\b([^>]*)>", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)]
    private static partial Regex Meta();

    [GeneratedRegex(@"url\s*=\s*['""]?([^'""\s;][^'"";]*)", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)]
    private static partial Regex RefreshUrl();

    [GeneratedRegex(@"<script\b[^>]*>(.*?)</script\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.NonBacktracking)]
    private static partial Regex ScriptElement();

    [GeneratedRegex(@"\blocation(?:\s*\.\s*(?:href\s*=|replace\s*\(|assign\s*\()|\s*=)\s*['""]([^'""]+)['""]", RegexOptions.NonBacktracking)]
    private static partial Regex LocationCall();
}
