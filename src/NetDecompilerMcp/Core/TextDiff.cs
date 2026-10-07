using System.Text;

namespace NetDecompilerMcp.Core;

/// <summary>Line-based unified diff (LCS), sized for decompiled members and types.</summary>
public static class TextDiff
{
    private const long MaxCells = 16_000_000;

    public static string Unified(string before, string after, string beforeLabel, string afterLabel, int context = 3)
    {
        var a = Split(before);
        var b = Split(after);
        var sb = new StringBuilder($"--- {beforeLabel}\n+++ {afterLabel}\n");
        if ((long)a.Length * b.Length > MaxCells)
        {
            // Too large for a line-level diff: show it as a full replacement.
            sb.AppendLine($"@@ -1,{a.Length} +1,{b.Length} @@");
            foreach (var l in a) sb.Append('-').AppendLine(l);
            foreach (var l in b) sb.Append('+').AppendLine(l);
            return sb.ToString();
        }

        var ops = Diff(a, b);
        if (ops.All(o => o.Kind == ' '))
            return sb.AppendLine("(no textual change)").ToString();

        // Group into hunks with `context` unchanged lines around each change.
        int i = 0;
        while (i < ops.Count)
        {
            while (i < ops.Count && ops[i].Kind == ' ') i++;
            if (i >= ops.Count) break;
            int start = Math.Max(0, i - context);
            int end = i;
            int quiet = 0;
            while (end < ops.Count && quiet <= context * 2)
            {
                quiet = ops[end].Kind == ' ' ? quiet + 1 : 0;
                end++;
            }
            end = Math.Min(ops.Count, end - Math.Max(0, quiet - context));
            var hunk = ops.GetRange(start, end - start);
            int aStart = hunk[0].A + 1, bStart = hunk[0].B + 1;
            sb.AppendLine($"@@ -{aStart},{hunk.Count(o => o.Kind != '+')} +{bStart},{hunk.Count(o => o.Kind != '-')} @@");
            foreach (var o in hunk) sb.Append(o.Kind).AppendLine(o.Text);
            i = end;
        }
        return sb.ToString();
    }

    private record struct Op(char Kind, string Text, int A, int B);

    private static List<Op> Diff(string[] a, string[] b)
    {
        int n = a.Length, m = b.Length;
        var lcs = new int[n + 1, m + 1];
        for (int x = n - 1; x >= 0; x--)
            for (int y = m - 1; y >= 0; y--)
                lcs[x, y] = a[x] == b[y] ? lcs[x + 1, y + 1] + 1 : Math.Max(lcs[x + 1, y], lcs[x, y + 1]);

        var ops = new List<Op>();
        int i = 0, j = 0;
        while (i < n && j < m)
        {
            if (a[i] == b[j]) { ops.Add(new Op(' ', a[i], i, j)); i++; j++; }
            else if (lcs[i + 1, j] >= lcs[i, j + 1]) { ops.Add(new Op('-', a[i], i, j)); i++; }
            else { ops.Add(new Op('+', b[j], i, j)); j++; }
        }
        while (i < n) { ops.Add(new Op('-', a[i], i, j)); i++; }
        while (j < m) { ops.Add(new Op('+', b[j], i, j)); j++; }
        return ops;
    }

    private static string[] Split(string s) => s.Length == 0 ? [] : s.Replace("\r\n", "\n").TrimEnd('\n').Split('\n');
}
